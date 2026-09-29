"""Supervisor: owns, monitors and recovers the two ProShield backend planes.

This is the *only* thing the Windows Service does.  It adds process lifecycle
management around the **existing, unmodified** entry points:

    Analyst / SecureProxy plane   ``python -m scripts.proxy_server``   :8088
    Ingress / trust boundary      ``python -m scripts.ingress_server`` :8089

Architectural guarantees enforced here (not weakened by packaging):

* The security planes stay **separate processes** on separate ports - the
  plane separation documented in ``scripts/ingress_server.py`` is preserved.
* The supervisor never inspects, rewrites or short-circuits a security
  decision; it only starts, watches and restarts OS processes.
* MongoDB connectivity belongs to the planes (via ``PROSHIELD_MONGO_*``); the
  supervisor merely *waits* until ``mongod`` is ready before starting them.
* If MongoDB is still starting (typical after a reboot), the service waits and
  retries instead of failing - and the core system keeps working if the update
  server or the internet is unavailable.
"""
from __future__ import annotations

import json
import os
import subprocess
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from service import probes
from service.logging_setup import child_log_path
from service.paths import ProShieldPaths, resolve_paths
from service.settings import ServiceSettings, ensure_bootstrap

LOGGER_NAME = "proshield.supervisor"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# --------------------------------------------------------------------- logging


class _RotatingSink:
    """Minimal size-rotating text sink for captured child output."""

    def __init__(self, path: Path, max_bytes: int, keep: int) -> None:
        self.path = path
        self.max_bytes = max(64 * 1024, int(max_bytes))
        self.keep = max(1, int(keep))
        self._lock = threading.Lock()
        self._handle = None
        self._size = 0
        self._open()

    def _open(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._handle = open(self.path, "a", encoding="utf-8", errors="replace")
        try:
            self._size = self.path.stat().st_size
        except OSError:
            self._size = 0

    def _rotate(self) -> None:
        assert self._handle is not None
        self._handle.close()
        self._handle = None
        for index in range(self.keep - 1, 0, -1):
            older = self.path.with_suffix(self.path.suffix + f".{index}")
            newer = self.path.with_suffix(self.path.suffix + f".{index + 1}")
            if older.is_file():
                try:
                    os.replace(older, newer)
                except OSError:
                    pass
        try:
            os.replace(self.path, self.path.with_suffix(self.path.suffix + ".1"))
        except OSError:
            pass
        self._open()

    def write(self, text: str) -> None:
        if not text:
            return
        payload = text if text.endswith("\n") else text + "\n"
        data = payload.encode("utf-8", errors="replace")
        with self._lock:
            if self._handle is None:
                return
            if self._size + len(data) > self.max_bytes:
                self._rotate()
            try:
                self._handle.write(payload)
                self._handle.flush()
                self._size += len(data)
            except (OSError, ValueError):  # pragma: no cover - log sink failures
                pass

    def close(self) -> None:
        with self._lock:
            if self._handle is not None:
                try:
                    self._handle.close()
                finally:
                    self._handle = None


class _PipePump(threading.Thread):
    """Drains a child's stdout/stderr into its rotating log file."""

    daemon = True

    def __init__(self, stream, sink: _RotatingSink, name: str) -> None:
        super().__init__(name=f"proshield-pump-{name}", daemon=True)
        self._stream = stream
        self._sink = sink

    def run(self) -> None:
        try:
            for line in iter(self._stream.readline, ""):
                self._sink.write(line.rstrip("\r\n"))
        except (ValueError, OSError):
            pass
        finally:
            try:
                self._stream.close()
            except Exception:  # pragma: no cover
                pass


# ----------------------------------------------------------------- child spec


@dataclass(frozen=True)
class ChildSpec:
    """One supervised ProShield backend plane."""

    name: str
    module: str
    port: int
    health_path: str
    display_name: str = ""

    def health_url(self, host: str) -> str:
        return f"http://{host}:{self.port}{self.health_path}"


#: Analyst plane first (it serves the UI + the SecureProxy wire boundary),
#: ingress plane second - matching the documented startup order.
def default_child_specs(settings: ServiceSettings) -> List[ChildSpec]:
    return [
        ChildSpec(
            name="analyst",
            module="scripts.proxy_server",
            port=settings.analyst_port,
            health_path="/health",
            display_name="Analyst / SecureProxy plane",
        ),
        ChildSpec(
            name="ingress",
            module="scripts.ingress_server",
            port=settings.ingress_port,
            health_path="/api/ingress/health",
            display_name="Ingress / trust boundary plane",
        ),
    ]


@dataclass
class ChildProcess:
    spec: ChildSpec
    process: Optional[subprocess.Popen] = None
    sink: Optional[_RotatingSink] = None
    pumps: List[_PipePump] = field(default_factory=list)
    started_at: float = 0.0
    restarts: int = 0
    consecutive_unhealthy: int = 0
    last_exit_code: Optional[int] = None
    healthy: bool = False
    next_start_after: float = 0.0
    last_health_detail: str = ""

    # ------------------------------------------------------------------ api
    @property
    def running(self) -> bool:
        return self.process is not None and self.process.poll() is None

    @property
    def pid(self) -> Optional[int]:
        return self.process.pid if self.process is not None else None

    def uptime_seconds(self) -> float:
        if not self.running or not self.started_at:
            return 0.0
        return max(0.0, time.time() - self.started_at)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "name": self.spec.name,
            "display_name": self.spec.display_name or self.spec.name,
            "module": self.spec.module,
            "port": self.spec.port,
            "pid": self.pid,
            "running": self.running,
            "healthy": bool(self.healthy),
            "health_detail": self.last_health_detail,
            "restarts": self.restarts,
            "uptime_seconds": round(self.uptime_seconds(), 1),
            "last_exit_code": self.last_exit_code,
        }


# ------------------------------------------------------------------- events


@dataclass(frozen=True)
class SupervisorEvent:
    kind: str
    child: str
    detail: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return {"kind": self.kind, "child": self.child, "detail": self.detail}


# --------------------------------------------------------------- supervisor


class Supervisor:
    """Start, watch and recover the ProShield backend planes."""

    def __init__(
        self,
        paths: Optional[ProShieldPaths] = None,
        settings: Optional[ServiceSettings] = None,
        python_exe: Optional[Path] = None,
        children: Optional[List[ChildSpec]] = None,
    ) -> None:
        if paths is None or settings is None:
            resolved_settings, resolved_paths = ensure_bootstrap(paths)
            settings = settings or resolved_settings
            paths = paths or resolved_paths
        self.paths = paths.ensure_layout()
        self.settings = settings
        self.python_exe = Path(python_exe) if python_exe else paths.runtime_python
        self.children: List[ChildProcess] = [
            ChildProcess(spec=spec)
            for spec in (children or default_child_specs(settings))
        ]
        self.started_at = time.time()
        self._lock = threading.RLock()
        self._mongo_ready = False
        self._log_dir = self.paths.logs_dir

    # ------------------------------------------------------------------ log
    @staticmethod
    def _logger():
        import logging

        return logging.getLogger(LOGGER_NAME)

    def _child(self, name: str) -> Optional[ChildProcess]:
        for child in self.children:
            if child.spec.name == name:
                return child
        return None

    # -------------------------------------------------------- mongo readiness
    def wait_for_mongo(
        self,
        stop_event: Optional[threading.Event] = None,
        timeout: Optional[float] = None,
    ) -> bool:
        """Block until MongoDB answers, or the timeout / stop event fires.

        Cold-boot ordering is Windows -> MongoDB -> ProShield Service, so on a
        reboot the service will typically arrive before ``mongod`` is serving.
        Waiting here (rather than crashing) is what makes automatic startup
        reliable.
        """
        budget = float(timeout if timeout is not None else self.settings.mongo_wait_seconds)
        deadline = time.time() + max(0.0, budget)
        attempt = 0
        while True:
            attempt += 1
            result = probes.mongo_ready(self.settings.mongo_uri)
            if result.ok:
                self._mongo_ready = True
                self._logger().info(
                    "MongoDB ready after %d probe(s): %s", attempt, result.detail
                )
                return True
            if stop_event is not None and stop_event.is_set():
                self._logger().info("MongoDB wait aborted by stop request")
                return False
            if time.time() >= deadline:
                self._logger().error(
                    "MongoDB not ready after %.0fs (%s); starting planes anyway "
                    "- they will retry their own connections",
                    budget,
                    result.detail,
                )
                self._mongo_ready = False
                return False
            if attempt == 1 or attempt % 15 == 0:
                self._logger().info(
                    "waiting for MongoDB (%s): %s", self.settings.mongo_uri, result.detail
                )
            if stop_event is not None:
                if stop_event.wait(self.settings.mongo_poll_seconds):
                    return False
            else:
                time.sleep(self.settings.mongo_poll_seconds)

    @property
    def mongo_ready(self) -> bool:
        return self._mongo_ready

    # ------------------------------------------------------------- lifecycle
    def _child_env(self) -> Dict[str, str]:
        env = dict(os.environ)
        env.update(self.settings.to_child_env())
        env["PROSHIELD_INSTALL_DIR"] = str(self.paths.install_root)
        env["PROSHIELD_DATA_DIR"] = str(self.paths.data_root)
        env.setdefault("PYTHONPATH", str(self.paths.install_root))
        return env

    def _creation_flags(self) -> int:
        """A service child must never allocate a console window."""
        if os.name != "nt":  # pragma: no cover - Windows-only product
            return 0
        return getattr(subprocess, "CREATE_NO_WINDOW", 0) | getattr(
            subprocess, "CREATE_NEW_PROCESS_GROUP", 0
        )

    def _command(self, spec: ChildSpec) -> List[str]:
        host = (
            self.settings.analyst_host
            if spec.name == "analyst"
            else self.settings.ingress_host
        )
        return [
            str(self.python_exe),
            "-m",
            spec.module,
            "--host",
            host,
            "--port",
            str(spec.port),
            "--backend",
            "mongo",
        ]

    def start_child(self, child: ChildProcess) -> SupervisorEvent:
        """Spawn one plane. Never raises; returns an event describing the outcome."""
        spec = child.spec
        logger = self._logger()
        with self._lock:
            if child.running:
                return SupervisorEvent("already_running", spec.name, f"pid={child.pid}")
            if child.sink is None:
                child.sink = _RotatingSink(
                    child_log_path(self._log_dir, spec.name),
                    self.settings.log_rotate_bytes,
                    self.settings.log_rotate_keep,
                )
            child.sink.write(
                f"=== {_utc_now()} starting {spec.module} "
                f"(port={spec.port}, python={self.python_exe}) ==="
            )
            try:
                process = subprocess.Popen(
                    self._command(spec),
                    cwd=str(self.paths.install_root),
                    env=self._child_env(),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    stdin=subprocess.DEVNULL,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    bufsize=1,
                    creationflags=self._creation_flags(),
                )
            except OSError as exc:
                child.last_exit_code = None
                logger.error("failed to launch %s: %s", spec.module, exc)
                child.sink.write(f"!!! launch failed: {exc}")
                return SupervisorEvent("launch_failed", spec.name, str(exc))

            child.process = process
            child.started_at = time.time()
            child.healthy = False
            child.consecutive_unhealthy = 0
            assert process.stdout is not None
            pump = _PipePump(process.stdout, child.sink, spec.name)
            pump.start()
            child.pumps.append(pump)
            logger.info(
                "%s plane launched (%s) pid=%s port=%s",
                spec.name,
                spec.module,
                process.pid,
                spec.port,
            )
            return SupervisorEvent("started", spec.name, f"pid={process.pid}")

    def stop_child(self, child: ChildProcess, timeout: float = 15.0) -> None:
        """Terminate one plane, escalating to a hard kill if it will not exit."""
        spec = child.spec
        logger = self._logger()
        with self._lock:
            process = child.process
            if process is None:
                return
            if process.poll() is not None:
                child.last_exit_code = process.returncode
                child.process = None
                child.healthy = False
                return
            logger.info("stopping %s plane (pid=%s)", spec.name, process.pid)
            if child.sink is not None:
                child.sink.write(f"=== {_utc_now()} stopping (pid={process.pid}) ===")
            try:
                process.terminate()
            except OSError:  # pragma: no cover
                pass
            deadline = time.time() + max(0.0, timeout)
            while process.poll() is None and time.time() < deadline:
                time.sleep(0.2)
            if process.poll() is None:
                logger.warning("%s plane ignored terminate; killing", spec.name)
                try:
                    process.kill()
                except OSError:  # pragma: no cover
                    pass
                try:
                    process.wait(timeout=5)
                except Exception:  # pragma: no cover
                    pass
            child.last_exit_code = process.returncode
            child.process = None
            child.healthy = False

    # ---------------------------------------------------------------- health
    def check_health(self, child: ChildProcess, timeout: Optional[float] = None) -> bool:
        result = probes.http_probe(
            child.spec.health_url(
                self.settings.analyst_host
                if child.spec.name == "analyst"
                else self.settings.ingress_host
            ),
            timeout=timeout or min(5.0, self.settings.health_poll_seconds + 3.0),
        )
        child.healthy = result.ok
        child.last_health_detail = result.detail
        return result.ok

    def wait_until_ready(
        self,
        timeout: Optional[float] = None,
        stop_event: Optional[threading.Event] = None,
    ) -> bool:
        """Wait for every plane to answer its health endpoint."""
        budget = float(timeout if timeout is not None else self.settings.health_timeout_seconds)
        deadline = time.time() + max(0.0, budget)
        while time.time() < deadline:
            if stop_event is not None and stop_event.is_set():
                return False
            if all(
                child.running and self.check_health(child)
                for child in self.children
            ):
                return True
            time.sleep(self.settings.health_poll_seconds)
        return all(child.running and self.check_health(child) for child in self.children)

    # ------------------------------------------------------------------ poll
    def _backoff_delay(self, child: ChildProcess) -> float:
        attempt = max(1, child.restarts)
        delay = self.settings.restart_backoff_seconds * (2 ** (attempt - 1))
        return min(delay, self.settings.restart_backoff_max_seconds)

    def _restart_due(self, child: ChildProcess) -> bool:
        delay = self._backoff_delay(child)
        child.next_start_after = time.time() + delay
        return True

    def poll_once(self) -> List[SupervisorEvent]:
        """Reap, restart and health-check every plane exactly once."""
        events: List[SupervisorEvent] = []
        logger = self._logger()
        with self._lock:
            children = list(self.children)

        for child in children:
            spec = child.spec
            process = child.process

            # ---- crashed or never started -----------------------------
            if process is None or process.poll() is not None:
                if process is not None:
                    code = process.poll()
                    if child.last_exit_code != code:
                        logger.error(
                            "%s plane exited with code %s", spec.name, code
                        )
                        if child.sink is not None:
                            child.sink.write(
                                f"!!! {_utc_now()} exited with code {code}"
                            )
                    child.last_exit_code = code
                    child.process = None
                    child.healthy = False
                    if (
                        child.started_at
                        and time.time() - child.started_at
                        >= self.settings.restart_stable_seconds
                    ):
                        # It ran healthily for a while: treat as a fresh fault.
                        child.restarts = 0
                if self.settings.max_restart_attempts:
                    if child.restarts >= self.settings.max_restart_attempts:
                        continue
                now = time.time()
                if child.next_start_after and now < child.next_start_after:
                    continue
                if child.next_start_after:
                    logger.info(
                        "backoff elapsed for %s plane; restarting (attempt %d)",
                        spec.name,
                        child.restarts + 1,
                    )
                child.restarts += 1
                events.append(self.start_child(child))
                self._restart_due(child)
                continue

            # ---- running: health-check, restart if hung ----------------
            healthy = self.check_health(child)
            if healthy:
                child.consecutive_unhealthy = 0
                if (
                    child.started_at
                    and time.time() - child.started_at
                    >= self.settings.restart_stable_seconds
                ):
                    child.restarts = 0
                continue

            child.consecutive_unhealthy += 1
            grace = max(self.settings.restart_stable_seconds, 30.0)
            if (
                child.uptime_seconds() >= grace
                and child.consecutive_unhealthy >= 3
            ):
                logger.error(
                    "%s plane unhealthy for %d consecutive probes (%s); restarting",
                    spec.name,
                    child.consecutive_unhealthy,
                    child.last_health_detail,
                )
                if child.sink is not None:
                    child.sink.write(
                        f"!!! {_utc_now()} unhealthy; restarting "
                        f"({child.last_health_detail})"
                    )
                events.append(SupervisorEvent("unhealthy_restart", spec.name, child.last_health_detail))
                self.stop_child(child, timeout=10.0)
                child.restarts += 1
                events.append(self.start_child(child))
                self._restart_due(child)
        return events

    def ensure_all_started(self) -> List[SupervisorEvent]:
        events: List[SupervisorEvent] = []
        for child in self.children:
            if not child.running:
                child.restarts += 1
                events.append(self.start_child(child))
        return events

    # ----------------------------------------------------------------- status
    def status(self) -> Dict[str, Any]:
        children = [child.as_dict() for child in self.children]
        return {
            "supervisor_pid": os.getpid(),
            "started_at": datetime.fromtimestamp(self.started_at, timezone.utc).isoformat(
                timespec="seconds"
            ),
            "version": self.settings.version,
            "channel": self.settings.channel,
            "mongo": {
                "uri": self.settings.mongo_uri,
                "db": self.settings.mongo_db,
                "ready": self._mongo_ready,
            },
            "children": children,
            "all_healthy": bool(children)
            and all(item["running"] and item["healthy"] for item in children),
            "install_root": str(self.paths.install_root),
            "data_root": str(self.paths.data_root),
        }

    def write_status_file(self) -> None:
        """Persist a status snapshot for diagnostics / installer / tray UI.

        Contains no security events, no evidence and no MongoDB credentials -
        it is a process-status readout only, so it does not create a path
        around SecureProxy.
        """
        try:
            payload = self.status()
            payload["generated_at"] = _utc_now()
            tmp = self.paths.health_state_file.with_suffix(".json.tmp")
            tmp.parent.mkdir(parents=True, exist_ok=True)
            tmp.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
            os.replace(tmp, self.paths.health_state_file)
        except OSError as exc:  # pragma: no cover
            self._logger().warning("could not write status file: %s", exc)

    # ------------------------------------------------------------------- run
    def run_forever(
        self,
        stop_event: threading.Event,
        on_tick=None,
        tick_seconds: float = 1.0,
        status_seconds: float = 10.0,
    ) -> None:
        """Main service loop.

        ``on_tick`` is invoked each cycle (the update engine hooks in here) and
        receives ``(supervisor, stop_event)``.  Any exception it raises is
        logged and swallowed: a broken update channel must never stop the
        security planes.
        """
        logger = self._logger()
        logger.info(
            "supervisor starting (version=%s channel=%s install=%s data=%s)",
            self.settings.version,
            self.settings.channel,
            self.paths.install_root,
            self.paths.data_root,
        )
        self.wait_for_mongo(stop_event)
        self.ensure_all_started()
        self.write_status_file()

        next_status = time.time() + max(1.0, status_seconds)
        while not stop_event.is_set():
            try:
                for event in self.poll_once():
                    logger.info("supervisor event: %s", event.as_dict())
            except Exception as exc:  # pragma: no cover - defensive
                logger.exception("poll_once failed: %s", exc)

            if on_tick is not None:
                try:
                    on_tick(self, stop_event)
                except Exception as exc:  # pragma: no cover - never fatal
                    logger.warning("on_tick failed: %s", exc)

            if time.time() >= next_status:
                self.write_status_file()
                next_status = time.time() + max(1.0, status_seconds)

            if stop_event.wait(max(0.05, tick_seconds)):
                break

        logger.info("supervisor stopping; terminating planes")
        self.shutdown()
        self.write_status_file()
        logger.info("supervisor stopped")

    def shutdown(self) -> None:
        """Stop every plane and close log sinks. Safe to call twice."""
        for child in self.children:
            try:
                self.stop_child(child)
            except Exception as exc:  # pragma: no cover
                self._logger().warning("stop_child(%s) failed: %s", child.spec.name, exc)
        for child in self.children:
            for pump in child.pumps:
                try:
                    pump.join(timeout=2.0)
                except Exception:  # pragma: no cover
                    pass
            child.pumps.clear()
            if child.sink is not None:
                try:
                    child.sink.write(f"=== {_utc_now()} plane stopped by supervisor ===")
                    child.sink.close()
                finally:
                    child.sink = None