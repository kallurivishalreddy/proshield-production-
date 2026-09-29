"""ProShield Service - a real Windows Service managed by the SCM.

    Windows SCM
        -> ProShieldService.exe   (this module)
             -> Supervisor
                  |- Analyst / SecureProxy plane   python -m scripts.proxy_server :8088
                  '- Ingress / trust boundary      python -m scripts.ingress_server :8089
                                                          |
                                                      MongoDB :27017  (existing service)

Design constraints honoured here:

* The service is **separate from the GUI**.  ``ProShield.exe`` is an ordinary
  process; closing it has no effect on this service, and this service keeps
  running when the user logs out.
* Auto-start + recovery are registered by the installer
  (``packaging/scripts/install_service.ps1`` / the Inno ``[Run]`` section) and
  are also available from this executable for repair:
  ``ProShieldService.exe install``.
* Shutdown is graceful: on stop *or* machine shutdown the supervised planes are
  terminated and the log sinks flushed, so the status file is never left
  describing a half-dead stack.

Commands (all of them also work in development via ``python -m service``):

    install      register the service (auto-start + MongoDB dependency + recovery)
    uninstall    stop and delete the service (data is preserved)
    start|stop|restart
    status       print SCM + supervisor status as JSON
    console      run the supervisor in the foreground (development / verification)
    debug        run the service class in console mode (pywin32)

The frozen executable is also the detached update helper.  When it is invoked
as ``ProShieldUpdateHelper.exe update-apply ...`` (a copy of this image staged
outside the install tree, see ``service/updater.py``) the ``update-apply``
subcommand is dispatched to :mod:`service.update_apply`.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import threading
import time
from typing import List, Optional, Sequence

from service.logging_setup import configure_logging
from service.paths import ProShieldPaths, is_installed, resolve_paths
from service.settings import ServiceSettings, ensure_bootstrap
from service.supervisor import Supervisor

SERVICE_NAME = "ProShieldService"
SERVICE_DISPLAY_NAME = "ProShield Service"
SERVICE_DESCRIPTION = (
    "ProShield security platform. Supervises the analyst/SecureProxy plane "
    "(127.0.0.1:8088) and the ingress/trust-boundary plane (127.0.0.1:8089), "
    "waits for MongoDB to become ready at boot, and recovers failed backend "
    "processes. Closing the ProShield desktop application does not stop this "
    "service."
)
SERVICE_CLASS_STRING = "service.windows_service.ProShieldService"

#: Windows service that MongoDB Community Server installs.  Used as a *soft*
#: dependency so the SCM starts MongoDB first on a reboot; the supervisor
#: additionally waits for real query readiness, so a missing/renamed MongoDB
#: service degrades gracefully instead of blocking startup.
MONGO_SERVICE_CANDIDATES = ("MongoDB", "mongodb", "MongoDB Server")

RECOVERY_RESET_SECONDS = 86400
RECOVERY_ACTIONS = "restart/5000/restart/10000/restart/30000"


def _log_paths() -> ProShieldPaths:
    return resolve_paths()


# ============================================================== SCM helpers


def _run_sc(args: Sequence[str]) -> tuple[int, str]:
    """Run ``sc.exe`` without flashing a console window."""
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        completed = subprocess.run(
            ["sc"] + list(args),
            capture_output=True,
            text=True,
            creationflags=flags,
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return 1, str(exc)
    output = (completed.stdout or "") + (completed.stderr or "")
    return completed.returncode, output.strip()


def detect_mongo_service() -> Optional[str]:
    """Return the installed MongoDB service name, if any."""
    for candidate in MONGO_SERVICE_CANDIDATES:
        code, _ = _run_sc(["query", candidate])
        if code == 0:
            return candidate
    return None


def service_is_installed() -> bool:
    code, _ = _run_sc(["query", SERVICE_NAME])
    return code == 0


def service_state() -> str:
    code, output = _run_sc(["query", SERVICE_NAME])
    if code != 0:
        return "not-installed"
    for token in ("RUNNING", "STOPPED", "START_PENDING", "STOP_PENDING", "PAUSED"):
        if token in output:
            return token.lower()
    return "unknown"


def configure_recovery() -> List[str]:
    """Configure SCM failure recovery: restart 5s / 10s / 30s, reset daily."""
    steps: List[str] = []
    code, _ = _run_sc(
        ["failure", SERVICE_NAME, "reset=", str(RECOVERY_RESET_SECONDS), "actions=", RECOVERY_ACTIONS]
    )
    steps.append(f"sc failure -> exit {code}")
    code, _ = _run_sc(["failureflag", SERVICE_NAME, "1"])
    steps.append(f"sc failureflag -> exit {code}")
    return steps


def _require_admin() -> None:
    if os.name != "nt":  # pragma: no cover
        raise SystemExit("ProShield Service can only be installed on Windows.")
    try:
        import win32security  # type: ignore
    except Exception:  # pragma: no cover
        return
    try:
        if not win32security.IsUserAnAdmin():
            raise SystemExit(
                "Administrator privileges are required to register the "
                "ProShield Service. Re-run from an elevated prompt."
            )
    except SystemExit:
        raise
    except Exception:  # pragma: no cover
        pass


def install_service(start_now: bool = True, wait_seconds: int = 90) -> int:
    """Register the Windows Service: auto-start, dependency, recovery."""
    _require_admin()
    import win32service  # type: ignore
    import win32serviceutil  # type: ignore

    paths = _log_paths()
    logger = configure_logging(paths.logs_dir, "INFO", "service.log", console=True)
    logger.info("registering service %s (exe=%s)", SERVICE_NAME, sys.executable)

    if service_is_installed():
        logger.info("service already registered; reconfiguring in place (repair)")

    mongo_service = detect_mongo_service()
    dependencies = [mongo_service] if mongo_service else None
    logger.info("MongoDB service dependency: %s", mongo_service or "none detected")

    exe_name = sys.executable if getattr(sys, "frozen", False) else None

    if service_is_installed():
        win32serviceutil.ChangeServiceConfig(
            SERVICE_CLASS_STRING,
            SERVICE_NAME,
            startType=win32service.SERVICE_AUTO_START,
            exeName=exe_name,
            displayName=SERVICE_DISPLAY_NAME,
            serviceDeps=dependencies,
            description=SERVICE_DESCRIPTION,
        )
    else:
        win32serviceutil.InstallService(
            SERVICE_CLASS_STRING,
            SERVICE_NAME,
            SERVICE_DISPLAY_NAME,
            startType=win32service.SERVICE_AUTO_START,
            exeName=exe_name,
            serviceDeps=dependencies,
            description=SERVICE_DESCRIPTION,
        )

    for step in configure_recovery():
        logger.info("recovery: %s", step)

    # Failures after start should not be treated as "service did not report".
    _run_sc(["config", SERVICE_NAME, "start=", "auto"])

    logger.info("service registered (start=auto, recovery=%s)", RECOVERY_ACTIONS)

    if start_now and service_state() != "running":
        code, output = _run_sc(["start", SERVICE_NAME])
        logger.info("sc start -> exit %s", code)
        deadline = time.time() + max(5, wait_seconds)
        while time.time() < deadline:
            if service_state() == "running":
                logger.info("service is RUNNING")
                return 0
            time.sleep(1.0)
        logger.error("service did not reach RUNNING within %ss (%s)", wait_seconds, output)
        return 3
    return 0


def uninstall_service(purge_data: bool = False) -> int:
    """Stop and delete the service. ProShield data and MongoDB are preserved."""
    _require_admin()
    paths = _log_paths()
    logger = configure_logging(paths.logs_dir, "INFO", "service.log", console=True)

    if service_is_installed():
        if service_state() in ("running", "start_pending"):
            _run_sc(["stop", SERVICE_NAME])
            deadline = time.time() + 60
            while time.time() < deadline and service_state() not in ("stopped", "not-installed"):
                time.sleep(1.0)
        code, output = _run_sc(["delete", SERVICE_NAME])
        logger.info("sc delete -> exit %s %s", code, output)
    else:
        logger.info("service was not registered")

    if purge_data:
        logger.info(
            "purge-data requested: ProShield runtime data under %s was left "
            "untouched by design (MongoDB database is never deleted)",
            paths.data_root,
        )
    return 0


def service_status_payload() -> dict:
    paths = _log_paths()
    payload = {
        "service_name": SERVICE_NAME,
        "display_name": SERVICE_DISPLAY_NAME,
        "scm_state": service_state(),
        "installed": service_is_installed(),
        "mongo_service": detect_mongo_service(),
        "mongo_ready": False,
        "supervisor": None,
    }
    if paths.health_state_file.is_file():
        try:
            payload["supervisor"] = json.loads(
                paths.health_state_file.read_text(encoding="utf-8")
            )
            payload["mongo_ready"] = bool(
                payload["supervisor"].get("mongo", {}).get("ready")
            )
        except (OSError, ValueError):
            pass
    return payload


# ============================================================== service class


def _build_service_class():
    """Import pywin32 lazily so development/console mode works without SCM."""
    import servicemanager  # type: ignore
    import win32event  # type: ignore
    import win32service  # type: ignore
    import win32serviceutil  # type: ignore

    class ProShieldService(win32serviceutil.ServiceFramework):
        _svc_name_ = SERVICE_NAME
        _svc_display_name_ = SERVICE_DISPLAY_NAME
        _svc_description_ = SERVICE_DESCRIPTION

        def __init__(self, args):
            win32serviceutil.ServiceFramework.__init__(self, args)
            self._stop_handle = win32event.CreateEvent(None, 0, 0, None)
            self._stop_event = threading.Event()
            self._supervisor: Optional[Supervisor] = None
            self._logger = None

        # -------------------------------------------------------- SCM control
        def GetAcceptedControls(self):
            controls = win32serviceutil.ServiceFramework.GetAcceptedControls(self)
            controls |= win32service.SERVICE_ACCEPT_PRESHUTDOWN
            return controls

        def SvcStop(self):
            """Stop request (service manager, or machine shutdown)."""
            self.ReportServiceStatus(
                win32service.SERVICE_STOP_PENDING, waitHint=45000
            )
            if self._logger:
                self._logger.info("stop requested by SCM")
            self._stop_event.set()
            win32event.SetEvent(self._stop_handle)

        def SvcShutdown(self):
            """Machine is shutting down - identical graceful path."""
            if self._logger:
                self._logger.info("machine shutdown notification received")
            self.SvcStop()

        def SvcOtherEx(self, control):
            """Pre-shutdown gives us a longer grace period than shutdown."""
            if control == win32service.SERVICE_CONTROL_PRESHUTDOWN:
                if self._logger:
                    self._logger.info("pre-shutdown notification received")
                self.SvcStop()
            else:  # pragma: no cover
                win32serviceutil.ServiceFramework.SvcOtherEx(self, control)

        # ------------------------------------------------------------ run
        def SvcDoRun(self):
            servicemanager.LogInfoMsg(
                f"{SERVICE_NAME} starting (version={_version_string()})"
            )
            paths = _log_paths()
            self._logger = configure_logging(
                paths.logs_dir, "INFO", "service.log", console=False
            )
            try:
                settings, paths = ensure_bootstrap(paths)
                self._supervisor = Supervisor(paths=paths, settings=settings)
                self._supervisor.run_forever(self._stop_event)
            except Exception as exc:  # pragma: no cover - last-resort guard
                if self._logger:
                    self._logger.exception("service loop crashed: %s", exc)
                servicemanager.LogErrorMsg(f"{SERVICE_NAME} crashed: {exc}")
                self.ReportServiceStatus(win32service.SERVICE_STOPPED, win32ExitCode=1)
                return
            servicemanager.LogInfoMsg(f"{SERVICE_NAME} stopped")

    return ProShieldService


def _version_string() -> str:
    from service.version import VERSION_INFO

    return VERSION_INFO.display_version


# ============================================================== console mode


def run_console(
    dev_credentials: bool = False,
    duration: Optional[float] = None,
    verbose: bool = True,
) -> int:
    """Run the supervisor in the foreground - the *same* code path the SCM runs.

    Used by development mode, by the installer's post-install health check and
    by the acceptance tests, so an installed ProShield can be exercised without
    an elevated SCM registration.
    """
    paths = _log_paths()
    logger = configure_logging(
        paths.logs_dir, "INFO", "service.log", console=verbose
    )
    settings, paths = ensure_bootstrap(paths, dev_credentials=dev_credentials)
    logger.info(
        "console mode: version=%s install=%s data=%s",
        settings.version,
        paths.install_root,
        paths.data_root,
    )
    supervisor = Supervisor(paths=paths, settings=settings)
    stop_event = threading.Event()

    from service.updater import UpdateEngine

    engine = UpdateEngine(paths=paths, settings=settings)
    engine.start(stop_event)

    if duration:
        timer = threading.Timer(duration, stop_event.set)
        timer.daemon = True
        timer.start()

    try:
        supervisor.run_forever(stop_event, on_tick=engine.on_tick)
    except KeyboardInterrupt:  # pragma: no cover
        logger.info("interrupted; shutting down")
        stop_event.set()
        supervisor.shutdown()
    finally:
        engine.stop()
    return 0


# ==================================================================== main


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="ProShieldService",
        description="ProShield Windows Service host.",
    )
    parser.add_argument(
        "command",
        nargs="?",
        default="",
        choices=[
            "",
            "install",
            "uninstall",
            "start",
            "stop",
            "restart",
            "status",
            "console",
            "debug",
            "stop-planes",
        ],
        help="service command (no command = run under SCM control)",
    )
    parser.add_argument(
        "--dev-credentials",
        action="store_true",
        help="seed the documented development credentials (development parity)",
    )
    parser.add_argument(
        "--duration",
        type=float,
        default=None,
        help="console mode only: stop automatically after N seconds",
    )
    parser.add_argument(
        "--wait",
        type=int,
        default=90,
        help="install: seconds to wait for RUNNING",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=None,
        help=(
            "stop-planes: seconds to wait for the planes to exit. Alias of "
            "--wait, accepted because the installer, the detached update "
            "helper and the deployment docs all spell it --timeout; rejecting "
            "it silently skipped the cleanup that lets an upgrade replace "
            "runtime\\python.exe."
        ),
    )
    parser.add_argument(
        "--no-start",
        action="store_true",
        help="install: register but do not start",
    )
    parser.add_argument(
        "--purge-data",
        action="store_true",
        help="uninstall: acknowledge that MongoDB data is still never deleted",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="stop-planes: emit a JSON summary",
    )
    return parser.parse_args(list(argv) if argv is not None else None)


def main(argv: Optional[Sequence[str]] = None) -> int:
    if argv is None:
        argv = sys.argv[1:]

    # ``update-apply`` is the detached update helper's subcommand.  A frozen
    # ProShield stages the update helper as a COPY of this executable (see
    # service.updater.spawn_apply_helper - the installer must be able to replace
    # the running ProShieldService.exe image, so the helper runs from outside the
    # install tree).  Its options differ from the service host's, so it is
    # dispatched before argparse instead of being squeezed into the service
    # parser: forgetting that made every frozen helper exit with
    # "invalid choice: 'update-apply'", i.e. a verified update was never applied.
    if argv and str(argv[0]) == "update-apply":
        from service.update_apply import main as update_apply_main

        return update_apply_main(list(argv[1:]))

    args = _parse_args(argv)
    command = args.command

    if command == "console":
        return run_console(
            dev_credentials=args.dev_credentials, duration=args.duration
        )
    if command == "status":
        print(json.dumps(service_status_payload(), indent=2, sort_keys=True))
        return 0
    if command == "stop-planes":
        # Used by the installer and the update helper: terminate every ProShield
        # process running from the install directory so the bundled
        # runtime\python.exe is not locked while an upgrade replaces it.
        from service.proc_cleanup import main as stop_planes_main

        # ``--timeout`` is the spelling used by the installer, the update helper
        # and the deployment docs; ``--wait`` is the service-host spelling.
        # Accepting only the latter meant argparse rejected the documented call
        # and the cleanup never ran.
        timeout_seconds = args.timeout if args.timeout is not None else args.wait
        forwarded = ["--timeout", str(timeout_seconds)]
        if args.json:
            forwarded.append("--json")
        return stop_planes_main(forwarded)
    if command == "install":
        return install_service(start_now=not args.no_start, wait_seconds=args.wait)
    if command == "uninstall":
        return uninstall_service(purge_data=args.purge_data)
    if command in ("start", "stop", "restart"):
        _require_admin()
        code, output = _run_sc([command, SERVICE_NAME])
        print(output)
        return code

    # ---- SCM dispatch -------------------------------------------------
    if is_installed() or os.name == "nt":
        try:
            service_class = _build_service_class()
        except ImportError as exc:  # pragma: no cover
            print(f"pywin32 is required to run as a Windows Service: {exc}")
            return 2

        if command == "debug":
            import win32serviceutil  # type: ignore

            win32serviceutil.HandleCommandLine(
                service_class, serviceClassString=SERVICE_CLASS_STRING, argv=["", "debug"]
            )
            return 0

        if not argv:
            import servicemanager  # type: ignore

            servicemanager.Initialize()
            servicemanager.PrepareToHostSingle(service_class)
            servicemanager.StartServiceCtrlDispatcher()
            return 0

        import win32serviceutil  # type: ignore

        win32serviceutil.HandleCommandLine(
            service_class, serviceClassString=SERVICE_CLASS_STRING, argv=[""] + list(argv)
        )
        return 0

    print("Unsupported platform for Windows service mode.")  # pragma: no cover
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
