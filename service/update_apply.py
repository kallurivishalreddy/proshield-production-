"""Detached update applier: verify -> backup -> apply -> health check -> rollback.

Why a *detached helper* rather than updating in place from the service?

The installer must replace ``ProShieldService.exe``.  Windows locks the image of
a running executable, and the installer's first action is to stop the service -
which would kill the process performing the update.  The helper is therefore:

* staged into ``<data_root>\\updates\\helper\\`` - **outside** the install tree,
  so the installer never needs to overwrite a running image;
* launched ``DETACHED_PROCESS`` from the service, so it survives the service
  stop;
* responsible for its own verification (it re-verifies the manifest signature
  and the package hash independently of the service that staged it).

Failure containment (requirement 10)::

    invalid signature      -> rejected before anything is downloaded/applied
    invalid hash           -> rejected before anything is applied
    corrupted package      -> rejected by size + SHA-256 verification
    interrupted download   -> partial file discarded, bounded retry
    unavailable server     -> check fails, zero state change
    failed service restart -> previous install tree restored, service restarted
    failed health check    -> previous install tree restored, service restarted

Data safety: MongoDB is never touched (it is an independent Windows service),
and ``<data_root>`` is outside the install tree, so configuration, security
events, detections, correlations, cases and history all survive an update.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

from service import probes, update_manifest
from service.logging_setup import configure_logging
from service.paths import ProShieldPaths, resolve_paths
from service.settings import ServiceSettings, load_settings

LOGGER = logging.getLogger("proshield.update_apply")

SERVICE_NAME = "ProShieldService"

#: Top-level entries of the install tree that an upgrade replaces.
INSTALL_TREE_DIRS: Tuple[str, ...] = (
    "app",
    "scripts",
    "frontend",
    "service",
    "desktop",
    "deploy",
    "runtime",
)

BACKUP_KEEP = 3

#: Inno Setup exit codes -> operator-facing meaning.
INNO_EXIT_CODES: Dict[int, str] = {
    0: "success",
    1: "setup failed to initialise",
    2: "installation cancelled before it started",
    3: "fatal error during setup",
    4: "fatal error during installation",
    5: "installation cancelled (or elevation was declined)",
    6: "setup was terminated by a debugger",
    7: "setup determined it cannot install (already running / unsupported)",
    8: "preparation to install failed",
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


@dataclass
class ApplyResult:
    ok: bool
    status: str
    message: str
    detail: str = ""
    from_version: str = ""
    to_version: str = ""
    rolled_back: bool = False

    def as_dict(self) -> Dict[str, object]:
        return {
            "ok": self.ok,
            "status": self.status,
            "message": self.message,
            "detail": self.detail,
            "from_version": self.from_version,
            "to_version": self.to_version,
            "rolled_back": self.rolled_back,
        }


class UpdateApplier:
    """Applies one verified update package with rollback safety."""

    def __init__(
        self,
        paths: Optional[ProShieldPaths] = None,
        settings: Optional[ServiceSettings] = None,
        installer_command: Optional[Sequence[str]] = None,
        restart_command: Optional[Sequence[str]] = None,
        health_timeout: Optional[float] = None,
        keep_backups: int = BACKUP_KEEP,
        allow_unsigned: bool = False,
    ) -> None:
        self.paths = (paths or resolve_paths()).ensure_layout()
        self.settings = settings or load_settings(self.paths)
        self.installer_command = list(installer_command) if installer_command else None
        if restart_command:
            self.restart_command = list(restart_command)
        elif self.settings.update_restart_command:
            # Operator-configured restart step (see ServiceSettings).
            self.restart_command = list(self.settings.update_restart_command)
        else:
            self.restart_command = ["sc", "start", SERVICE_NAME]
        self.health_timeout = float(
            health_timeout
            if health_timeout is not None
            else self.settings.update_apply_timeout_seconds
        )
        self.keep_backups = max(1, int(keep_backups))
        self.allow_unsigned = allow_unsigned

    # ---------------------------------------------------------------- verify
    def verify(self, manifest_path: Path, artifact_path: Path) -> Tuple[bool, str, Optional[object]]:
        """Independent re-verification of signature + hash before any change."""
        if not manifest_path.is_file():
            return False, f"staged manifest {manifest_path} is missing", None
        if not artifact_path.is_file():
            return False, f"staged package {artifact_path} is missing", None

        try:
            raw = manifest_path.read_bytes()
        except OSError as exc:
            return False, f"staged manifest unreadable: {exc}", None

        try:
            manifest = update_manifest.parse_manifest(raw)
            manifest = update_manifest.verify_manifest(
                manifest,
                update_manifest.load_public_key(self.paths.update_public_key_file),
                allow_unsigned=self.allow_unsigned,
                expected_channel=self.settings.channel,
            )
        except update_manifest.ManifestError as exc:
            return False, f"manifest rejected: {exc}", None

        artifact = manifest.artifact_for(update_manifest.WINDOWS_PLATFORM)
        if artifact is None:
            return False, "manifest has no windows-x64 artefact", None

        ok, detail = update_manifest.verify_artifact(artifact, artifact_path)
        if not ok:
            return False, f"package rejected: {detail}", None

        return True, detail, manifest

    # ---------------------------------------------------------------- backup
    def backup_dir_for(self, version: str) -> Path:
        return self.paths.backup_dir / f"{version}-{_stamp()}"

    def backup_install_tree(self, version: str) -> Optional[Path]:
        """Snapshot the current install tree so a failed update can be undone."""
        target = self.backup_dir_for(version)
        target.mkdir(parents=True, exist_ok=True)
        copied: List[str] = []
        for name in INSTALL_TREE_DIRS:
            source = self.paths.install_root / name
            if not source.is_dir():
                continue
            try:
                shutil.copytree(
                    source,
                    target / name,
                    dirs_exist_ok=True,
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"),
                )
                copied.append(name)
            except OSError as exc:
                LOGGER.error("backup of %s failed: %s", name, exc)
                return None
        try:
            (target / "backup-info.json").write_text(
                json.dumps(
                    {
                        "from_version": version,
                        "created_at": _utc_now(),
                        "copied": copied,
                        "install_root": str(self.paths.install_root),
                    },
                    indent=2,
                    sort_keys=True,
                ),
                encoding="utf-8",
            )
        except OSError:  # pragma: no cover
            pass
        LOGGER.info("install tree backed up to %s (%s)", target, ", ".join(copied))
        return target

    def restore_install_tree(self, backup: Path) -> bool:
        """Restore a snapshot taken by :meth:`backup_install_tree`.

        The install tree is first quiesced: the backend planes run from this
        directory (and share the bundled ``runtime\\python.exe``), so replacing
        files underneath them either fails on locked images or leaves a
        half-written tree.  The caller restarts the service afterwards.
        """
        if not backup.is_dir():
            LOGGER.error("rollback impossible: backup %s does not exist", backup)
            return False

        cleanup = self.quiesce_install_tree()
        if cleanup.get("remaining"):
            LOGGER.warning(
                "rollback proceeding with %s process(es) still running from %s",
                cleanup["remaining"],
                self.paths.install_root,
            )

        restored: List[str] = []
        for name in INSTALL_TREE_DIRS:
            source = backup / name
            if not source.is_dir():
                continue
            target = self.paths.install_root / name
            try:
                if target.exists():
                    shutil.rmtree(target, ignore_errors=True)
                shutil.copytree(source, target, dirs_exist_ok=True)
                restored.append(name)
            except OSError as exc:
                LOGGER.error("rollback of %s failed: %s", name, exc)
                return False
        LOGGER.warning("rolled back install tree from %s (%s)", backup, ", ".join(restored))
        return True

    def prune_backups(self) -> None:
        try:
            entries = sorted(
                (p for p in self.paths.backup_dir.iterdir() if p.is_dir()),
                key=lambda p: p.stat().st_mtime,
                reverse=True,
            )
        except OSError:
            return
        for stale in entries[self.keep_backups :]:
            shutil.rmtree(stale, ignore_errors=True)

    # ------------------------------------------------------------- installer
    def build_installer_command(self, artifact: Path) -> List[str]:
        if self.installer_command:
            return list(self.installer_command)
        log_file = self.paths.logs_dir / "installer-update.log"
        return [
            str(artifact),
            "/VERYSILENT",
            "/SUPPRESSMSGBOXES",
            "/NORESTART",
            "/NOCANCEL",
            "/SP-",
            "/UPDATE=1",
            f"/LOG={log_file}",
        ]

    def quiesce_install_tree(self) -> dict:
        """Terminate ProShield processes still running from the install tree.

        The installer must replace ``runtime\\python.exe``, which Windows locks
        while a backend plane is running.  Without this, an upgrade fails with
        ``DeleteFile failed; code 5`` and the installer aborts mid-way.  The
        applier's own process lives outside the install tree (the detached
        helper is staged in ``<data_root>\\updates\\helper``), so it is never a
        target.
        """
        try:
            from service.proc_cleanup import terminate_processes_in

            summary = terminate_processes_in(self.paths.install_root, timeout=20.0)
        except Exception as exc:  # pragma: no cover - never fatal
            LOGGER.warning("process cleanup before update failed: %s", exc)
            return {"error": str(exc)}
        LOGGER.info(
            "pre-update cleanup: found=%s terminated=%s remaining=%s",
            summary.get("found"),
            summary.get("terminated"),
            summary.get("remaining"),
        )
        return summary

    def run_installer(self, artifact: Path) -> Tuple[int, str]:
        command = self.build_installer_command(artifact)
        cleanup = self.quiesce_install_tree()
        LOGGER.info("running installer: %s", " ".join(command))
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=self.health_timeout,
                creationflags=flags,
            )
        except subprocess.TimeoutExpired:
            return -1, "installer timed out"
        except OSError as exc:
            return -2, f"installer could not be started: {exc}"
        tail = ((completed.stdout or "") + (completed.stderr or "")).strip()
        meaning = INNO_EXIT_CODES.get(completed.returncode, "unknown exit code")
        if cleanup.get("remaining"):
            meaning += (
                f" | WARNING: {cleanup['remaining']} ProShield process(es) were "
                "still running from the install directory"
            )
        LOGGER.info("installer exit=%s (%s)", completed.returncode, meaning)
        return completed.returncode, meaning + (f" | {tail[-500:]}" if tail else "")

    # ---------------------------------------------------------------- health
    def installed_version(self) -> str:
        path = self.paths.build_info_file
        if not path.is_file():
            return ""
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return str(data.get("version") or "")
        except (OSError, ValueError):
            return ""

    def restart_backend(self) -> bool:
        """Start the Windows service (the installer normally already did)."""
        if not self.restart_command:
            return True
        try:
            completed = subprocess.run(
                self.restart_command,
                capture_output=True,
                text=True,
                timeout=120,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            LOGGER.error("restart command failed: %s", exc)
            return False
        LOGGER.info(
            "restart command %s -> exit %s",
            " ".join(self.restart_command),
            completed.returncode,
        )
        return completed.returncode == 0

    def wait_for_health(
        self,
        expected_version: str,
        timeout: Optional[float] = None,
    ) -> Tuple[bool, str]:
        """Wait until the new build is installed *and* both planes answer."""
        budget = float(timeout if timeout is not None else self.health_timeout)
        deadline = time.time() + max(5.0, budget)
        last = "no probe completed"
        while time.time() < deadline:
            installed = self.installed_version()
            if expected_version and installed and installed != expected_version:
                last = f"installed version is {installed}, expected {expected_version}"
                time.sleep(2.0)
                continue
            analyst = probes.http_probe(
                f"{self.settings.analyst_base_url}/health", timeout=5.0
            )
            if not analyst.ok:
                last = f"analyst plane not healthy ({analyst.detail})"
                time.sleep(2.0)
                continue
            ingress = probes.http_probe(
                f"{self.settings.ingress_base_url}/api/ingress/health", timeout=5.0
            )
            if not ingress.ok:
                last = f"ingress plane not healthy ({ingress.detail})"
                time.sleep(2.0)
                continue
            return True, (
                f"health ok (installed={installed or 'unknown'}, "
                f"analyst={analyst.detail}, ingress={ingress.detail})"
            )
        return False, f"post-update health check failed: {last}"

    # ------------------------------------------------------------------ state
    def _write_state(self, result: ApplyResult) -> None:
        path = self.paths.update_state_file
        data: Dict[str, object] = {}
        if path.is_file():
            try:
                loaded = json.loads(path.read_text(encoding="utf-8"))
                if isinstance(loaded, dict):
                    data = loaded
            except (OSError, ValueError):
                data = {}
        data.update(
            {
                "status": result.status,
                "message": result.message,
                "pending_apply": False,
                "last_apply_at": _utc_now(),
                "last_apply_result": result.status,
                "last_applied_version": result.to_version if result.ok else data.get("last_applied_version", ""),
                "available_version": "" if result.ok else data.get("available_version", ""),
                "staged_artifact": "" if result.ok else data.get("staged_artifact", ""),
                "staged_manifest": "" if result.ok else data.get("staged_manifest", ""),
            }
        )
        history = data.get("history")
        if not isinstance(history, list):
            history = []
        history.append(
            {
                "at": _utc_now(),
                "event": result.status,
                "detail": result.message,
                "version": result.to_version,
            }
        )
        data["history"] = history[-25:]
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(".json.tmp")
            tmp.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
            os.replace(tmp, path)
        except OSError as exc:  # pragma: no cover
            LOGGER.warning("could not persist apply state: %s", exc)

    # ------------------------------------------------------------------ apply
    def apply(
        self,
        artifact_path: Path,
        manifest_path: Path,
        expected_version: str = "",
        rollback_on_failure: bool = True,
    ) -> ApplyResult:
        from_version = self.installed_version() or self.settings.version

        ok, detail, manifest = self.verify(manifest_path, artifact_path)
        if not ok:
            result = ApplyResult(
                ok=False,
                status="rejected",
                message=detail,
                from_version=from_version,
                to_version=expected_version,
            )
            self._write_state(result)
            return result

        to_version = getattr(manifest, "version", "") or expected_version
        LOGGER.info(
            "applying update %s -> %s (%s)", from_version, to_version, detail
        )

        backup = self.backup_install_tree(from_version)
        if backup is None and rollback_on_failure:
            result = ApplyResult(
                ok=False,
                status="failed",
                message="could not back up the current installation; aborting to avoid "
                "an unrecoverable partial update",
                from_version=from_version,
                to_version=to_version,
            )
            self._write_state(result)
            return result

        exit_code, meaning = self.run_installer(artifact_path)
        if exit_code != 0:
            message = f"installer failed (exit {exit_code}: {meaning})"
            if rollback_on_failure and backup is not None:
                restored = self.restore_install_tree(backup)
                self.restart_backend()
                result = ApplyResult(
                    ok=False,
                    status="rolled-back" if restored else "failed",
                    message=message + ("; previous version restored" if restored else "; rollback failed"),
                    detail=meaning,
                    from_version=from_version,
                    to_version=to_version,
                    rolled_back=restored,
                )
            else:
                result = ApplyResult(
                    ok=False,
                    status="failed",
                    message=message,
                    detail=meaning,
                    from_version=from_version,
                    to_version=to_version,
                )
            self._write_state(result)
            return result

        healthy, health_detail = self.wait_for_health(
            to_version, timeout=min(45.0, self.health_timeout)
        )
        if not healthy:
            # The machine-wide installer restarts the Windows Service itself.
            # If that did not happen (per-user install, no service registered,
            # or an operator stopped it) bring the backend back once and keep
            # waiting - a healthy stack is part of "the update succeeded".
            LOGGER.info(
                "backend not healthy after the installer (%s); restarting it",
                health_detail,
            )
            self.restart_backend()
            healthy, health_detail = self.wait_for_health(to_version)

        if not healthy:
            if rollback_on_failure and backup is not None:
                restored = self.restore_install_tree(backup)
                self.restart_backend()
                result = ApplyResult(
                    ok=False,
                    status="rolled-back" if restored else "failed",
                    message=health_detail + ("; previous version restored" if restored else "; rollback failed"),
                    from_version=from_version,
                    to_version=to_version,
                    rolled_back=restored,
                )
            else:
                result = ApplyResult(
                    ok=False,
                    status="failed",
                    message=health_detail,
                    from_version=from_version,
                    to_version=to_version,
                )
            self._write_state(result)
            return result

        self.prune_backups()
        result = ApplyResult(
            ok=True,
            status="success",
            message=f"updated {from_version} -> {to_version}; {health_detail}",
            detail=detail,
            from_version=from_version,
            to_version=to_version,
        )
        self._write_state(result)
        return result

    def rollback(self, backup: Optional[Path] = None) -> ApplyResult:
        """Manually restore the newest (or a named) backup and restart."""
        chosen = backup
        if chosen is None:
            try:
                candidates = sorted(
                    (p for p in self.paths.backup_dir.iterdir() if p.is_dir()),
                    key=lambda p: p.stat().st_mtime,
                    reverse=True,
                )
            except OSError:
                candidates = []
            chosen = candidates[0] if candidates else None
        if chosen is None:
            return ApplyResult(False, "failed", "no backup available to roll back to")
        restored = self.restore_install_tree(chosen)
        self.restart_backend()
        return ApplyResult(
            ok=restored,
            status="rolled-back" if restored else "failed",
            message=f"manual rollback from {chosen}",
            rolled_back=restored,
        )


# =============================================================== helper CLI


def _parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="ProShieldUpdateHelper",
        description="Detached ProShield update applier (internal).",
    )
    parser.add_argument("--artifact", required=False)
    parser.add_argument("--manifest", required=False)
    parser.add_argument("--expected-version", default="")
    parser.add_argument("--health-timeout", type=float, default=None)
    parser.add_argument(
        "--restart-command",
        default="",
        help=(
            "JSON array of the command used to bring the backend back after the "
            'update, e.g. \'["sc","start","ProShieldService"]\'. Defaults to '
            "the configured update_restart_command, else 'sc start "
            "ProShieldService'."
        ),
    )
    parser.add_argument("--rollback-only", action="store_true")
    parser.add_argument("--no-rollback", action="store_true")
    parser.add_argument("--allow-unsigned", action="store_true")
    return parser.parse_args(list(argv))


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv if argv is not None else sys.argv[1:])
    paths = resolve_paths()
    configure_logging(paths.logs_dir, "INFO", "updater.log", console=True)
    settings = load_settings(paths)

    applier = UpdateApplier(
        paths=paths,
        settings=settings,
        health_timeout=args.health_timeout,
        allow_unsigned=args.allow_unsigned,
    )

    if args.restart_command:
        try:
            parsed = json.loads(args.restart_command)
        except ValueError as exc:
            LOGGER.error("--restart-command is not valid JSON: %s", exc)
            return 2
        if not isinstance(parsed, list) or not all(
            isinstance(item, str) for item in parsed
        ):
            LOGGER.error("--restart-command must be a JSON array of strings")
            return 2
        applier.restart_command = [str(item) for item in parsed]
        LOGGER.info("post-update restart command: %s", " ".join(applier.restart_command))

    if args.rollback_only:
        result = applier.rollback()
    else:
        if not args.artifact or not args.manifest:
            LOGGER.error("--artifact and --manifest are required")
            return 2
        result = applier.apply(
            Path(args.artifact),
            Path(args.manifest),
            expected_version=args.expected_version,
            rollback_on_failure=not args.no_rollback,
        )

    LOGGER.info("apply result: %s", json.dumps(result.as_dict(), sort_keys=True))
    print(json.dumps(result.as_dict(), indent=2, sort_keys=True))
    return 0 if result.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
