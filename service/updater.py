"""Automatic-update engine (current **testing channel**).

Workflow implemented here::

    test -> patch -> improve -> build new version -> publish testing release
         -> existing ProShield detects update
         -> verify package (signature + hash)
         -> upgrade (detached helper)
         -> restart service
         -> health check
         -> continue testing

Modes (``update_mode`` in ``proshield.json`` / ``PROSHIELD_UPDATE_MODE``):

``automatic``    check, verify and apply without asking (current testing phase)
``notify-only``  check and record the available version, never apply
``manual``       never check on its own; an operator or the GUI triggers a check

Hard guarantees:

* The core ProShield system keeps working when the update server or the
  internet is unavailable - every failure is contained and logged.
* Nothing is installed before signature **and** hash verification succeed.
* The service never applies an update while its own planes are unhealthy.
* Applying happens in a **detached helper process outside the install tree**,
  because the installer must be free to replace ``ProShieldService.exe`` while
  this service stops.
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import sys
import threading
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from service import update_client, update_manifest
from service.paths import ProShieldPaths, resolve_paths
from service.settings import ServiceSettings, load_settings
from service.version import is_newer

LOGGER = logging.getLogger("proshield.updater")

STATE_IDLE = "idle"
STATE_DISABLED = "disabled"
STATE_CHECKING = "checking"
STATE_UP_TO_DATE = "up-to-date"
STATE_AVAILABLE = "available"
STATE_DOWNLOADING = "downloading"
STATE_VERIFIED = "verified"
STATE_APPLYING = "applying"
STATE_SUCCESS = "success"
STATE_FAILED = "failed"
STATE_ROLLED_BACK = "rolled-back"
STATE_ERROR = "error"

HELPER_DIRNAME = "helper"
MAX_HISTORY = 25


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class UpdateState:
    """Durable update state - survives service restarts and upgrades."""

    mode: str = "automatic"
    channel: str = "testing"
    current_version: str = "0.0.0"
    manifest_url: str = ""
    status: str = STATE_IDLE
    message: str = ""
    available_version: str = ""
    last_check_at: str = ""
    last_check_result: str = ""
    last_check_message: str = ""
    staged_artifact: str = ""
    staged_manifest: str = ""
    last_applied_version: str = ""
    last_apply_at: str = ""
    last_apply_result: str = ""
    pending_apply: bool = False
    history: List[Dict[str, Any]] = field(default_factory=list)

    def as_dict(self) -> Dict[str, Any]:
        return asdict(self)


class UpdateEngine:
    """Periodic, non-fatal update checking and application."""

    def __init__(
        self,
        paths: Optional[ProShieldPaths] = None,
        settings: Optional[ServiceSettings] = None,
    ) -> None:
        self.paths = (paths or resolve_paths()).ensure_layout()
        self.settings = settings or load_settings(self.paths)
        self.state = self._load_state()
        self._thread: Optional[threading.Thread] = None
        self._stop_event: Optional[threading.Event] = None
        self._lock = threading.RLock()
        self._next_check_at = 0.0
        self._next_apply_attempt = 0.0
        self._last_public_key = None

    # ----------------------------------------------------------------- state
    def _load_state(self) -> UpdateState:
        state = UpdateState(
            mode=self.settings.update_mode,
            channel=self.settings.channel,
            current_version=self.settings.version,
            manifest_url=self.settings.update_manifest_url,
        )
        path = self.paths.update_state_file
        if path.is_file():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                for key, value in data.items():
                    if hasattr(state, key):
                        setattr(state, key, value)
            except (OSError, ValueError) as exc:
                LOGGER.warning("update state file unreadable (%s); starting fresh", exc)
        # Config always wins over stale persisted values.
        state.mode = self.settings.update_mode
        state.channel = self.settings.channel
        state.current_version = self.settings.version
        state.manifest_url = self.settings.update_manifest_url
        return state

    def save_state(self) -> None:
        try:
            self.paths.update_state_file.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.paths.update_state_file.with_suffix(".json.tmp")
            tmp.write_text(
                json.dumps(self.state.as_dict(), indent=2, sort_keys=True),
                encoding="utf-8",
            )
            os.replace(tmp, self.paths.update_state_file)
        except OSError as exc:  # pragma: no cover
            LOGGER.warning("could not persist update state: %s", exc)

    def _record(self, event: str, detail: str = "", version: str = "") -> None:
        self.state.history.append(
            {"at": _utc_now(), "event": event, "detail": detail, "version": version}
        )
        del self.state.history[:-MAX_HISTORY]

    # ------------------------------------------------------------ public key
    def _public_key(self):
        if self._last_public_key is None:
            self._last_public_key = update_manifest.load_public_key(
                self.paths.update_public_key_file
            )
        return self._last_public_key

    # ----------------------------------------------------------------- check
    def check_now(self) -> Dict[str, Any]:
        """Fetch, parse and verify the manifest. Never raises."""
        url = (self.settings.update_manifest_url or "").strip()
        self.state.last_check_at = _utc_now()

        # Accept either a manifest URL or the channel's *base* URL.  The
        # installer records the channel base (PROSHIELD_UPDATE_URL), and asking
        # an operator to remember the trailing "/manifest.json" is a needless
        # footgun - without this, fetching the base URL returns a directory
        # listing and the check fails with "manifest is not valid JSON".
        if url and not url.lower().endswith((".json", ".json.txt")):
            url = url.rstrip("/") + "/manifest.json"
            LOGGER.info("update endpoint resolved to %s", url)

        if not url:
            self.state.status = STATE_DISABLED
            self.state.last_check_result = "no-endpoint"
            self.state.last_check_message = (
                "no update endpoint configured (update_manifest_url / "
                "PROSHIELD_UPDATE_URL); the update channel is inactive"
            )
            self.save_state()
            return {"ok": True, "result": "no-endpoint", "message": self.state.last_check_message}

        self.state.status = STATE_CHECKING
        self.save_state()

        try:
            raw = update_client.fetch_bytes(url, timeout=30.0)
        except update_client.UpdateClientError as exc:
            self.state.status = STATE_ERROR
            self.state.last_check_result = "server-unavailable"
            self.state.last_check_message = f"update server unavailable: {exc}"
            LOGGER.warning("update check failed: %s", exc)
            self.save_state()
            return {"ok": False, "result": "server-unavailable", "message": str(exc)}

        try:
            manifest = update_manifest.parse_manifest(raw)
        except update_manifest.ManifestError as exc:
            self.state.status = STATE_ERROR
            self.state.last_check_result = "invalid-manifest"
            self.state.last_check_message = str(exc)
            LOGGER.error("update manifest rejected: %s", exc)
            self.save_state()
            return {"ok": False, "result": "invalid-manifest", "message": str(exc)}

        try:
            manifest = update_manifest.verify_manifest(
                manifest,
                self._public_key(),
                allow_unsigned=self.settings.update_allow_unsigned,
                expected_channel=self.settings.channel,
            )
        except update_manifest.ManifestError as exc:
            self.state.status = STATE_ERROR
            self.state.last_check_result = "untrusted-manifest"
            self.state.last_check_message = str(exc)
            LOGGER.error("update manifest rejected: %s", exc)
            self._record("rejected", str(exc), manifest.version)
            self.save_state()
            return {"ok": False, "result": "untrusted-manifest", "message": str(exc)}

        if not is_newer(manifest.version, self.settings.version):
            self.state.status = STATE_UP_TO_DATE
            self.state.available_version = ""
            self.state.pending_apply = False
            self.state.last_check_result = "up-to-date"
            self.state.last_check_message = (
                f"{self.settings.version} is current (channel={manifest.channel})"
            )
            self.save_state()
            return {"ok": True, "result": "up-to-date", "message": self.state.last_check_message}

        artifact = manifest.artifact_for(update_manifest.WINDOWS_PLATFORM)
        if artifact is None:
            self.state.status = STATE_ERROR
            self.state.last_check_result = "no-artifact"
            self.state.last_check_message = (
                f"manifest {manifest.version} has no "
                f"{update_manifest.WINDOWS_PLATFORM} artefact"
            )
            self.save_state()
            return {"ok": False, "result": "no-artifact", "message": self.state.last_check_message}

        if manifest.min_version and is_newer(manifest.min_version, self.settings.version):
            self.state.status = STATE_ERROR
            self.state.last_check_result = "below-min-version"
            self.state.last_check_message = (
                f"version {manifest.version} requires at least "
                f"{manifest.min_version}; this install is {self.settings.version} "
                "and needs a full reinstall"
            )
            self.save_state()
            return {"ok": False, "result": "below-min-version", "message": self.state.last_check_message}

        self.state.available_version = manifest.version
        self.state.last_check_result = "update-available"
        self.state.last_check_message = (
            f"{manifest.version} available on channel {manifest.channel} "
            f"({manifest.verify_detail})"
        )
        LOGGER.info("update available: %s (%s)", manifest.version, manifest.verify_detail)

        staged = self._stage(manifest, artifact)
        if staged is None:
            return {"ok": False, "result": "stage-failed", "message": self.state.last_check_message}

        self.state.pending_apply = self.settings.update_mode == "automatic"
        self.state.status = STATE_VERIFIED if self.state.pending_apply else STATE_AVAILABLE
        self._record(
            "verified",
            f"{manifest.verify_detail}; staged {artifact.name}",
            manifest.version,
        )
        self.save_state()
        return {
            "ok": True,
            "result": "update-available",
            "message": self.state.last_check_message,
            "version": manifest.version,
            "will_apply": self.state.pending_apply,
        }

    # -------------------------------------------------------------- staging
    def _stage_dir(self, version: str) -> Path:
        return self.paths.updates_dir / version

    def _stage(self, manifest, artifact) -> Optional[Path]:
        """Download + verify the artefact. Returns the staged path on success."""
        stage_dir = self._stage_dir(manifest.version)
        stage_dir.mkdir(parents=True, exist_ok=True)
        target = stage_dir / artifact.name

        self.state.status = STATE_DOWNLOADING
        self.state.message = f"downloading {artifact.name}"
        self.save_state()

        try:
            update_client.download_artifact(
                artifact.url,
                target,
                timeout=float(self.settings.update_download_timeout_seconds),
                expected_size=artifact.size,
            )
        except update_client.UpdateClientError as exc:
            self.state.status = STATE_FAILED
            self.state.message = f"download failed: {exc}"
            self._record("download-failed", str(exc), manifest.version)
            self.save_state()
            LOGGER.error("update download failed: %s", exc)
            return None

        ok, detail = update_manifest.verify_artifact(artifact, target)
        if not ok:
            self.state.status = STATE_FAILED
            self.state.message = f"package verification failed: {detail}"
            self._record("hash-mismatch", detail, manifest.version)
            self.save_state()
            LOGGER.error("update package rejected: %s", detail)
            try:
                target.unlink()
            except OSError:
                pass
            return None

        manifest_path = stage_dir / "manifest.json"
        try:
            manifest_path.write_text(
                json.dumps(manifest.raw, indent=2, sort_keys=True), encoding="utf-8"
            )
        except OSError as exc:  # pragma: no cover
            LOGGER.warning("could not persist staged manifest: %s", exc)

        self.state.staged_artifact = str(target)
        self.state.staged_manifest = str(manifest_path)
        self.state.message = f"{artifact.name} verified ({detail})"
        LOGGER.info("update staged: %s", target)
        return target

    # ---------------------------------------------------------------- apply
    def spawn_apply_helper(self, wait: bool = False) -> Dict[str, Any]:
        """Launch the detached apply helper.

        The helper must live **outside** the install tree: the installer has to
        be able to overwrite ``ProShieldService.exe``, which is impossible while
        that image is the running process.
        """
        artifact = self.state.staged_artifact
        manifest_path = self.state.staged_manifest
        if not artifact or not Path(artifact).is_file():
            return {"ok": False, "message": "no verified package is staged"}

        helper_dir = self.paths.updates_dir / HELPER_DIRNAME
        helper_dir.mkdir(parents=True, exist_ok=True)

        frozen = bool(getattr(sys, "frozen", False))
        if frozen:
            # A frozen service must stage its OWN image: the installer will
            # replace <install>\service\ProShieldService.exe, and Windows locks a
            # running executable, so the helper has to run from outside the
            # install tree.
            helper_exe = helper_dir / "ProShieldUpdateHelper.exe"
            try:
                shutil.copy2(sys.executable, helper_exe)
            except OSError as exc:
                return {"ok": False, "message": f"could not stage update helper: {exc}"}
            command = [
                str(helper_exe),
                "update-apply",
                "--artifact",
                artifact,
                "--manifest",
                manifest_path,
                "--expected-version",
                self.state.available_version,
            ]
        else:
            command = [
                str(sys.executable),
                "-m",
                "service.update_apply",
                "--artifact",
                artifact,
                "--manifest",
                manifest_path,
                "--expected-version",
                self.state.available_version,
            ]

        # The post-update restart step differs between the machine-wide install
        # (a Windows Service) and a per-user testing install (no service), so it
        # is configurable rather than hard-coded.  Passed as a JSON array so
        # paths with spaces survive the command line intact.
        if self.settings.update_restart_command:
            command += [
                "--restart-command",
                json.dumps(list(self.settings.update_restart_command)),
            ]

        log_path = self.paths.logs_dir / "updater.log"
        log_handle = open(log_path, "a", encoding="utf-8", errors="replace")
        flags = 0
        if os.name == "nt":
            flags = (
                getattr(subprocess, "DETACHED_PROCESS", 0)
                | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
                | getattr(subprocess, "CREATE_NO_WINDOW", 0)
            )
        env = dict(os.environ)
        env["PROSHIELD_INSTALL_DIR"] = str(self.paths.install_root)
        env["PROSHIELD_DATA_DIR"] = str(self.paths.data_root)
        env.setdefault("PYTHONPATH", str(self.paths.install_root))

        try:
            process = subprocess.Popen(
                command,
                cwd=str(self.paths.install_root),
                env=env,
                stdout=log_handle,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                creationflags=flags,
                close_fds=True,
            )
        except OSError as exc:
            log_handle.close()
            return {"ok": False, "message": f"could not start update helper: {exc}"}

        self.state.status = STATE_APPLYING
        self.state.message = (
            f"applying {self.state.available_version} via detached helper "
            f"(pid={process.pid})"
        )
        self.state.pending_apply = False
        self._record("apply-started", self.state.message, self.state.available_version)
        self.save_state()
        LOGGER.info("update helper started (pid=%s)", process.pid)

        if wait:
            try:
                process.wait(timeout=float(self.settings.update_apply_timeout_seconds))
            except subprocess.TimeoutExpired:  # pragma: no cover
                return {"ok": False, "message": "update helper timed out"}
        return {"ok": True, "pid": process.pid, "message": self.state.message}

    # ------------------------------------------------------------------ tick
    def on_tick(self, supervisor, stop_event: threading.Event) -> None:
        """Fast hook called from the supervisor loop (must never block).

        Only applies a staged update when the current stack is *healthy*, so a
        broken install never gets replaced mid-failure.
        """
        if not (self.state.pending_apply and self.settings.update_mode == "automatic"):
            return
        if not supervisor.mongo_ready:
            return
        if not all(child.running and child.healthy for child in supervisor.children):
            return
        # Retry at a bounded rate: a failure here (helper cannot be staged,
        # permissions, disk) must be visible without flooding the log every
        # supervisor tick.
        now = time.time()
        if now < self._next_apply_attempt:
            return
        self._next_apply_attempt = now + 60.0

        result = self.spawn_apply_helper()
        if not result.get("ok"):
            LOGGER.error(
                "could not start the update helper: %s", result.get("message")
            )
            self.state.message = (
                f"update helper could not be started: {result.get('message')}"
            )
            self.save_state()

    # ---------------------------------------------------------------- thread
    def start(self, stop_event: threading.Event) -> None:
        if self._thread is not None:
            return
        self._stop_event = stop_event
        self._next_check_at = time.time() + max(5, self.settings.update_initial_delay_seconds)
        self._thread = threading.Thread(
            target=self._loop, name="proshield-update-engine", daemon=True
        )
        self._thread.start()
        LOGGER.info(
            "update engine started (mode=%s channel=%s endpoint=%s interval=%ss)",
            self.settings.update_mode,
            self.settings.channel,
            self.settings.update_manifest_url or "<unset>",
            self.settings.update_check_interval_seconds,
        )

    def stop(self) -> None:
        if self._stop_event is not None:
            self._stop_event.set()
        thread = self._thread
        if thread is not None:
            thread.join(timeout=5.0)
        self._thread = None

    def _loop(self) -> None:
        stop_event = self._stop_event
        assert stop_event is not None
        while not stop_event.is_set():
            if self.settings.update_mode == "manual":
                if stop_event.wait(30.0):
                    break
                continue
            delay = max(0.0, self._next_check_at - time.time())
            if delay > 0:
                if stop_event.wait(min(delay, 30.0)):
                    break
                continue
            try:
                with self._lock:
                    self.check_now()
            except Exception as exc:  # pragma: no cover - never fatal
                LOGGER.exception("update check crashed: %s", exc)
            self._next_check_at = time.time() + max(
                60, self.settings.update_check_interval_seconds
            )

    # -------------------------------------------------------------- summary
    def summary(self) -> Dict[str, Any]:
        return {
            "mode": self.state.mode,
            "channel": self.state.channel,
            "current_version": self.state.current_version,
            "status": self.state.status,
            "message": self.state.message,
            "available_version": self.state.available_version,
            "last_check_at": self.state.last_check_at,
            "last_check_result": self.state.last_check_result,
            "last_applied_version": self.state.last_applied_version,
            "endpoint_configured": bool(self.settings.update_manifest_url),
        }
