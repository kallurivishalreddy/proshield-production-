"""ProShield desktop shell entry point.

Technology choice (documented, repository-driven):

    pywebview 6 (WinForms host + Microsoft Edge WebView2) frozen with
    PyInstaller -> single native ``ProShield.exe``.

Why not Tauri / Electron:

* The authoritative UI is already a **single-file** Vite bundle
  (``vite-plugin-singlefile``) served same-origin by the analyst plane; the
  shell therefore needs an embedded browser *control*, not an application
  framework.
* WebView2 Runtime ships with Windows 10/11 (verified present on the build
  host: 153.0.4234.32), so no ~150 MB Chromium bundle has to be installed or
  shipped, and there is no Electron/Node runtime dependency for the shell.
* It keeps the whole product in one language (Python), so one toolchain and
  one test framework (pytest) cover the service, the updater and the shell.
* Tauri would require a Rust + MSVC Build Tools toolchain (~2 GB) that is
  absent here and unused by every other part of ProShield.

Command line (development / diagnostics)::

    ProShield.exe                         normal launch
    ProShield.exe --backend-url http://127.0.0.1:8088
    ProShield.exe --status                print the status payload as JSON
    ProShield.exe --version               print version information
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from service import probes
from service.logging_setup import configure_logging
from service.paths import ProShieldPaths, is_installed, resolve_paths
from service.settings import ServiceSettings, load_settings
from service.version import VERSION_INFO

APP_TITLE = "ProShield"
WINDOW_MIN_SIZE = (1024, 700)
DEFAULT_WINDOW_SIZE = (1440, 920)

WV2_CLIENTS_KEY = r"SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _status_html_path() -> Path:
    if getattr(sys, "frozen", False):
        base = Path(getattr(sys, "_MEIPASS", Path(sys.executable).parent))
        return base / "status.html"
    return Path(__file__).resolve().parent / "status.html"


def webview2_available() -> bool:
    """True when the Evergreen WebView2 runtime is installed on this machine."""
    if os.name != "nt":  # pragma: no cover
        return False
    try:
        import winreg  # type: ignore
    except ImportError:  # pragma: no cover
        return False
    for hive, key in (
        (winreg.HKEY_LOCAL_MACHINE, WV2_CLIENTS_KEY),
        (winreg.HKEY_CURRENT_USER, WV2_CLIENTS_KEY.replace("WOW6432Node\\", "")),
    ):
        try:
            with winreg.OpenKey(hive, key) as handle:
                value, _ = winreg.QueryValueEx(handle, "pv")
                if value:
                    return True
        except OSError:
            continue
    return False


def _port_open(host: str, port: int, timeout: float = 0.6) -> bool:
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True
    except OSError:
        return False


# ------------------------------------------------------------------- JS API


class DesktopApi:
    """Bridge between the local status page and this shell.

    Exposed only to the bundled ``status.html``; it can report *process* state
    and open folders.  It offers no access to security data, no proxy call and
    no database handle.
    """

    def __init__(self, shell: "ProShieldDesktop") -> None:
        self._shell = shell

    def status(self) -> Dict[str, Any]:
        return self._shell.status_payload()

    def version(self) -> Dict[str, Any]:
        return VERSION_INFO.as_dict()

    def open_logs_folder(self) -> Dict[str, Any]:
        return self._open(self._shell.paths.logs_dir)

    def open_data_folder(self) -> Dict[str, Any]:
        return self._open(self._shell.paths.data_root)

    def retry(self) -> Dict[str, Any]:
        self._shell.request_reconnect()
        return {"ok": True}

    def _open(self, folder: Path) -> Dict[str, Any]:
        try:
            folder.mkdir(parents=True, exist_ok=True)
            os.startfile(str(folder))  # type: ignore[attr-defined]
            return {"ok": True, "path": str(folder)}
        except Exception as exc:
            return {"ok": False, "path": str(folder), "message": str(exc)}


# --------------------------------------------------------------------- shell


class ProShieldDesktop:
    """Owns the native window and the connection to the local backend."""

    def __init__(
        self,
        backend_url: Optional[str] = None,
        paths: Optional[ProShieldPaths] = None,
    ) -> None:
        self.paths = (paths or resolve_paths()).ensure_layout()
        # The GUI never reads the secrets file (see service.settings).
        self.settings: ServiceSettings = load_settings(
            self.paths, include_secrets=False
        )
        if backend_url:
            host, _, port = backend_url.replace("http://", "").partition(":")
            self.settings = type(self.settings)(
                **{
                    **self.settings.__dict__,
                    "analyst_host": host or self.settings.analyst_host,
                    "analyst_port": int(port) if port.isdigit() else self.settings.analyst_port,
                }
            )
        self.window = None
        self._stop_event = threading.Event()
        self._navigated = False
        self._reconnect_requested = threading.Event()
        self._webview_ready = threading.Event()
        self.logger = configure_logging(
            self.paths.logs_dir, "INFO", "desktop.log", console=False
        )

    # ------------------------------------------------------------- status
    def _read_json(self, path: Path) -> Optional[Dict[str, Any]]:
        if not path.is_file():
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else None
        except (OSError, ValueError):
            return None

    def service_state(self) -> Dict[str, Any]:
        """SCM state of the ProShield Service (best effort, no admin needed)."""
        state: Dict[str, Any] = {
            "name": "ProShieldService",
            "installed": False,
            "state": "unknown",
        }
        if os.name != "nt":
            return state
        try:
            import win32service  # type: ignore
            import win32serviceutil  # type: ignore

            status = win32serviceutil.QueryServiceStatus("ProShieldService")
            state["installed"] = True
            mapping = {
                win32service.SERVICE_RUNNING: "running",
                win32service.SERVICE_STOPPED: "stopped",
                win32service.SERVICE_START_PENDING: "starting",
                win32service.SERVICE_STOP_PENDING: "stopping",
            }
            state["state"] = mapping.get(status[1], "unknown")
        except Exception:
            state["state"] = "not-installed"
        return state

    def backend_status(self) -> Dict[str, Any]:
        analyst_url = f"{self.settings.analyst_base_url}/health"
        ingress_url = f"{self.settings.ingress_base_url}/api/ingress/health"
        analyst = probes.http_probe(analyst_url, timeout=2.5)
        ingress = probes.http_probe(ingress_url, timeout=2.5)
        return {
            "ui_url": self.settings.ui_url,
            "analyst": {
                "url": analyst_url,
                "port": self.settings.analyst_port,
                "reachable": analyst.ok,
                "detail": analyst.detail,
                "port_open": _port_open(self.settings.analyst_host, self.settings.analyst_port),
            },
            "ingress": {
                "url": ingress_url,
                "port": self.settings.ingress_port,
                "reachable": ingress.ok,
                "detail": ingress.detail,
                "port_open": _port_open(self.settings.ingress_host, self.settings.ingress_port),
            },
            "mongo": self._read_json(self.paths.health_state_file) or {},
        }

    def status_payload(self) -> Dict[str, Any]:
        backend = self.backend_status()
        supervisor = self._read_json(self.paths.health_state_file) or {}
        update_state = self._read_json(self.paths.update_state_file) or {}
        ready = bool(backend["analyst"]["reachable"])
        return {
            "shell": {
                **VERSION_INFO.as_dict(),
                "frozen": is_installed(),
                "pid": os.getpid(),
                "generated_at": _utc_now(),
            },
            "paths": {
                "install_root": str(self.paths.install_root),
                "data_root": str(self.paths.data_root),
                "logs_dir": str(self.paths.logs_dir),
                "ui_file": str(self.paths.frontend_ui),
                "ui_file_exists": self.paths.frontend_ui.is_file(),
            },
            "backend": backend,
            "service": self.service_state(),
            "supervisor": supervisor,
            "update": {
                "mode": update_state.get("mode", self.settings.update_mode),
                "channel": update_state.get("channel", self.settings.channel),
                "status": update_state.get("status", "idle"),
                "message": update_state.get("message", ""),
                "available_version": update_state.get("available_version", ""),
                "current_version": update_state.get("current_version", VERSION_INFO.version),
                "last_check_at": update_state.get("last_check_at", ""),
            },
            "ready": ready,
        }

    # ------------------------------------------------------- connection
    def request_reconnect(self) -> None:
        self._reconnect_requested.set()

    def _wait_for_backend(self, timeout: float = 900.0) -> bool:
        """Wait until the analyst plane answers, then load the SOC UI."""
        deadline = time.time() + timeout
        announced = False
        while not self._stop_event.is_set() and time.time() < deadline:
            if self._reconnect_requested.is_set():
                self._reconnect_requested.clear()
                deadline = time.time() + timeout
            result = probes.http_probe(
                f"{self.settings.analyst_base_url}/health", timeout=3.0
            )
            if result.ok:
                return True
            if not announced:
                self.logger.info(
                    "waiting for the ProShield backend at %s (%s)",
                    self.settings.analyst_base_url,
                    result.detail,
                )
                announced = True
            self._stop_event.wait(1.5)
        return False

    def _monitor(self) -> None:
        if not self._wait_for_backend():
            self.logger.warning("backend did not become ready within the timeout")
            return
        if self._navigated or self._stop_event.is_set():
            return
        # The UI is served by the analyst plane, same-origin with /api/proxy.
        if not self.paths.frontend_ui.is_file():
            self.logger.error(
                "authoritative UI missing at %s - the installed bundle is "
                "incomplete",
                self.paths.frontend_ui,
            )
        self.logger.info("backend ready; loading %s", self.settings.ui_url)
        try:
            self.window.load_url(self.settings.ui_url)
            self._navigated = True
        except Exception as exc:  # pragma: no cover
            self.logger.error("could not load the SOC UI: %s", exc)

    # ------------------------------------------------------------- launch
    def single_instance_guard(self) -> bool:
        """Best-effort single-instance guard using a named mutex."""
        if os.name != "nt":
            return True
        try:
            import win32event  # type: ignore
            import win32api  # type: ignore

            self._mutex = win32event.CreateMutex(
                None, False, "Global\\ProShieldDesktopShell"
            )
            if win32api.GetLastError() == 183:  # ERROR_ALREADY_EXISTS
                return False
            return True
        except Exception:
            return True

    def run(self) -> int:
        try:
            import webview  # type: ignore
        except ImportError as exc:  # pragma: no cover
            print(
                "The ProShield desktop shell requires the 'pywebview' package "
                f"(bundled with the installer): {exc}"
            )
            return 2

        if not webview2_available():
            self.logger.error("Microsoft Edge WebView2 Runtime is not installed")
            print(
                "ProShield needs the Microsoft Edge WebView2 Runtime, which "
                "ships with Windows 10/11. Install it from "
                "https://developer.microsoft.com/microsoft-edge/webview2/ and "
                "start ProShield again."
            )
            return 3

        status_page = _status_html_path()
        start_url = (
            status_page.as_uri() if status_page.is_file() else "about:blank"
        )

        api = DesktopApi(self)
        self.window = webview.create_window(
            f"{APP_TITLE} {VERSION_INFO.display_version}",
            url=start_url,
            width=DEFAULT_WINDOW_SIZE[0],
            height=DEFAULT_WINDOW_SIZE[1],
            min_size=WINDOW_MIN_SIZE,
            js_api=api,
            background_color="#0B1220",
            text_select=True,
        )

        monitor = threading.Thread(
            target=self._monitor, name="proshield-desktop-monitor", daemon=True
        )
        monitor.start()

        storage_path = self.paths.state_dir / "webview"
        storage_path.mkdir(parents=True, exist_ok=True)
        self.logger.info(
            "desktop shell starting (version=%s install=%s)",
            VERSION_INFO.display_version,
            self.paths.install_root,
        )
        try:
            webview.start(
                gui="edgechromium",
                # private_mode=False keeps localStorage (the browser-internal
                # session token) across launches; storage lives in ProgramData,
                # never in the repository or the install tree.
                private_mode=False,
                storage_path=str(storage_path),
                debug=False,
            )
        except Exception as exc:  # pragma: no cover
            self.logger.exception("desktop shell failed: %s", exc)
            print(f"ProShield desktop shell failed to start: {exc}")
            return 1
        finally:
            self._stop_event.set()
        return 0


# ==================================================================== main


def _parse_args(argv: Optional[Sequence[str]]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="ProShield", description="ProShield desktop application."
    )
    parser.add_argument("--backend-url", default="", help="override the analyst plane URL")
    parser.add_argument("--status", action="store_true", help="print status JSON and exit")
    parser.add_argument("--version", action="store_true", help="print version and exit")
    return parser.parse_args(list(argv) if argv is not None else None)


def main(argv: Optional[Sequence[str]] = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    args = _parse_args(argv)

    if args.version:
        print(json.dumps(VERSION_INFO.as_dict(), indent=2, sort_keys=True))
        return 0

    shell = ProShieldDesktop(backend_url=args.backend_url or None)

    if args.status:
        print(json.dumps(shell.status_payload(), indent=2, sort_keys=True))
        return 0

    if not shell.single_instance_guard():
        print("ProShield is already running.")
        return 0

    return shell.run()


if __name__ == "__main__":
    raise SystemExit(main())
