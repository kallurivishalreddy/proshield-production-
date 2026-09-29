"""Verify the automatic testing-channel update flow end to end.

Runs the real workflow against a real installation:

    publish release  ->  existing install detects update
                     ->  verifies package (Ed25519 signature + SHA-256)
                     ->  applies it (detached helper runs the installer)
                     ->  restarts the backend
                     ->  health check
                     ->  continue running on the new version

and then the negative cases against the *installed* updater:

    untrusted signature  ->  refused, nothing staged
    hash mismatch        ->  refused, nothing applied

Usage::

    python -m scripts.verify_update_flow \
        --install-dir "%LOCALAPPDATA%\\ProShield" \
        --data-dir    "%LOCALAPPDATA%\\ProShield" \
        --release-version 1.0.1 --expect-version 1.0.1

The release being published must already exist under ``dist/windows/<version>/``
with a signed ``manifest.json`` (see ``deploy/build_windows.py``).
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import threading
import time
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from service.paths import resolve_paths  # noqa: E402
from service.settings import load_settings  # noqa: E402

RESULTS: List[tuple] = []


def record(name: str, ok: bool, detail: str = "") -> None:
    RESULTS.append((name, ok, detail))
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f" - {detail}" if detail else ""))


def section(title: str) -> None:
    print()
    print("=" * 72)
    print(title)
    print("=" * 72)


class Channel:
    """In-process HTTP server exposing a release directory."""

    def __init__(self, directory: Path, host: str = "127.0.0.1", port: int = 8099) -> None:
        outer = self

        class Handler(SimpleHTTPRequestHandler):
            def log_message(self, fmt, *args):  # noqa: D102
                print(f"  [channel] {fmt % args}")

            def translate_path(self, path):  # noqa: D102
                return str(directory / path.lstrip("/").split("?")[0])

        self.directory = directory
        self.server = ThreadingHTTPServer((host, port), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://{host}:{port}"

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


def read_json(path: Path) -> Dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def reset_update_state(paths) -> None:
    """Clear the durable update state before a phase.

    The updater persists its state in ``state/update-state.json`` and that file
    is shared with every other ProShield tool (the acceptance harness writes to
    it too).  Without a reset, a phase can observe a *previous* run's
    ``status``/``last_apply_at`` and conclude the update already finished.  The
    file is archived rather than deleted so the evidence is not lost.
    """
    state_file = paths.update_state_file
    if not state_file.is_file():
        return
    archive = state_file.with_name(
        f"update-state.archive-{int(time.time())}.json"
    )
    try:
        os.replace(state_file, archive)
        print(f"  (previous update state archived as {archive.name})")
    except OSError:
        try:
            state_file.unlink()
        except OSError:
            pass


def wait_for_transition(
    state_path: Path,
    baseline: Dict[str, Any],
    accept,
    timeout: float,
    interval: float = 3.0,
) -> Dict[str, Any]:
    """Wait until the persisted state changes and satisfies ``accept``."""
    deadline = time.time() + timeout
    last: Dict[str, Any] = {}
    while time.time() < deadline:
        last = read_json(state_path)
        changed = (
            last.get("last_check_at") != baseline.get("last_check_at")
            or last.get("last_apply_at") != baseline.get("last_apply_at")
            or last.get("status") != baseline.get("status")
        )
        if changed and accept(last):
            return last
        time.sleep(interval)
    return last


def wait_for(predicate, timeout: float, interval: float = 2.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if predicate():
                return True
        except Exception:
            pass
        time.sleep(interval)
    return False


def write_settings(paths, updates: Dict[str, Any]) -> None:
    """Merge the update-channel configuration into the installed settings."""
    current = read_json(paths.settings_file)
    current.update(updates)
    paths.settings_file.parent.mkdir(parents=True, exist_ok=True)
    paths.settings_file.write_text(
        json.dumps(current, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def channel_env(env: Dict[str, str], endpoint: str) -> Dict[str, str]:
    """Return ``env`` with the update endpoint pinned for the child process.

    ``PROSHIELD_UPDATE_URL`` takes precedence over the settings file, and the
    installer records the channel base there.  A verification run that only
    patched the settings file would therefore test the *installer's* endpoint,
    not the one under test - so the endpoint is set explicitly for every phase.
    """
    updated = dict(env)
    updated["PROSHIELD_UPDATE_URL"] = endpoint
    return updated


def write_restart_launcher(paths) -> Path:
    """A launcher that brings the backend back for a per-user install.

    The machine-wide install uses ``sc start ProShieldService``; a per-user
    testing install has no service, so the supervisor is started directly.
    """
    launcher = paths.state_dir / "restart-backend.cmd"
    launcher.parent.mkdir(parents=True, exist_ok=True)
    service_exe = paths.service_exe
    launcher.write_text(
        "@echo off\r\n"
        f'start "ProShieldService" /min "{service_exe}" console\r\n',
        encoding="utf-8",
    )
    return launcher


def start_service(paths, env: Dict[str, str]) -> subprocess.Popen:
    log_path = paths.logs_dir / "verify-update-service.log"
    handle = open(log_path, "w", encoding="utf-8", errors="replace")
    return subprocess.Popen(
        [str(paths.service_exe), "console"],
        cwd=str(paths.install_root),
        env=env,
        stdout=handle,
        stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)
        | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0),
    )


def stop_service(process: Optional[subprocess.Popen], paths) -> None:
    # Terminate only what belongs to THIS install tree.
    #
    # This used to begin with ``taskkill /IM ProShieldService.exe /F``, which is
    # machine-wide: running the verifier against a per-user testing install also
    # killed the machine-wide Windows service, leaving the real deployment down
    # (and, on the service side, looking like a crash loop).  A verification run
    # must be isolated, so the cleanup is scoped to ``paths.install_root``.
    if process is not None and process.poll() is None:
        try:
            process.terminate()
            process.wait(timeout=15)
        except Exception:
            process.kill()
    subprocess.run(
        [str(paths.service_exe), "stop-planes", "--timeout", "20"],
        capture_output=True,
        text=True,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )


def ensure_clean_start(paths) -> None:
    """Kill any ProShield process left over from a previous phase or run.

    Without this, a leftover supervisor keeps the analyst/ingress ports bound and
    keeps checking the *installer's* endpoint.  The supervisor started by this
    run then cannot bring its planes up, health never becomes true, and the run
    fails for the wrong reason.

    Scoped to ``paths.install_root`` on purpose: an unscoped
    ``taskkill /IM ProShieldService.exe`` also killed the machine-wide Windows
    service, so verifying a per-user testing install took the real deployment
    down with it.
    """
    try:
        from service.proc_cleanup import terminate_processes_in

        summary = terminate_processes_in(paths.install_root, timeout=20.0)
        if summary.get("terminated"):
            print(f"  (stopped {summary['terminated']} leftover ProShield process(es))")
    except Exception:  # pragma: no cover - best effort
        pass
    time.sleep(2.0)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Verify the ProShield update flow.")
    parser.add_argument("--install-dir", required=True)
    parser.add_argument("--data-dir", required=True)
    parser.add_argument("--release-version", default="")
    parser.add_argument(
        "--release-dir",
        default="",
        help=(
            "directory holding the signed manifest.json + artifact to serve. "
            "Defaults to dist/windows/<--release-version>. Pointing it at a "
            "temporary directory lets the whole flow run against an isolated "
            "channel and artifact, instead of the published release, so a "
            "verification run cannot disturb a real installation or its data."
        ),
    )
    parser.add_argument("--expect-version", required=True)
    parser.add_argument("--port", type=int, default=8099)
    parser.add_argument("--apply-timeout", type=float, default=420.0)
    parser.add_argument("--skip-negative", action="store_true")
    args = parser.parse_args(argv if argv is not None else sys.argv[1:])

    install_root = Path(args.install_dir).resolve()
    data_root = Path(args.data_dir).resolve()
    if args.release_dir:
        release_dir = Path(args.release_dir).resolve()
    elif args.release_version:
        release_dir = ROOT / "dist" / "windows" / args.release_version
    else:
        parser.error("one of --release-version or --release-dir is required")

    os.environ["PROSHIELD_INSTALL_DIR"] = str(install_root)
    os.environ["PROSHIELD_DATA_DIR"] = str(data_root)
    paths = resolve_paths(install=install_root, data=data_root).ensure_layout()

    print("=" * 72)
    print("ProShield automatic testing-channel update verification")
    print("=" * 72)
    print(f"  install      : {install_root}")
    print(f"  data         : {data_root}")
    print(f"  release      : {release_dir}")
    print(f"  expect       : {args.expect_version}")

    if not (release_dir / "manifest.json").is_file():
        record("release manifest exists", False, f"{release_dir}/manifest.json missing")
        return 1

    manifest = json.loads((release_dir / "manifest.json").read_text(encoding="utf-8"))
    record(
        "release manifest is signed",
        bool(manifest.get("signature")),
        f"channel={manifest.get('channel')} version={manifest.get('version')} "
        f"artifact={manifest.get('artifacts', {}).get('windows-x64', {}).get('filename')}",
    )

    channel = Channel(release_dir, port=args.port)
    print(f"  channel      : {channel.base}")

    service_process: Optional[subprocess.Popen] = None
    try:
        ensure_clean_start(paths)
        launcher = write_restart_launcher(paths)
        write_settings(
            paths,
            {
                "update_manifest_url": f"{channel.base}/manifest.json",
                "update_mode": "automatic",
                "update_initial_delay_seconds": 5,
                "update_check_interval_seconds": 60,
                "update_restart_command": ["cmd", "/c", str(launcher)],
            },
        )
        record(
            "update channel configured on the installation",
            True,
            f"automatic @ {channel.base}/manifest.json (restart via {launcher.name})",
        )

        before = read_json(paths.build_info_file).get("version", "unknown")
        env = channel_env(dict(os.environ), f"{channel.base}/manifest.json")
        env["PROSHIELD_INSTALL_DIR"] = str(install_root)
        env["PROSHIELD_DATA_DIR"] = str(data_root)
        reset_update_state(paths)
        baseline: Dict[str, Any] = {}
        service_process = start_service(paths, env)
        print(f"  supervisor   : pid {service_process.pid}")

        started = wait_for(
            lambda: read_json(paths.health_state_file).get("all_healthy") is True, 180
        )
        record("installed backend healthy before the update", started, f"version {before}")
        if not started:
            return 1

        section("Automatic update: detect -> verify -> apply -> restart -> health")

        settled = wait_for_transition(
            paths.update_state_file,
            baseline,
            lambda s: s.get("status")
            in ("success", "failed", "rolled-back", "rejected"),
            args.apply_timeout,
        )
        state = settled or read_json(paths.update_state_file)
        if state.get("status") not in ("success", "failed", "rolled-back", "rejected"):
            record(
                "update applied",
                False,
                f"timed out after {args.apply_timeout}s; state="
                f"{state.get('status')} :: {state.get('message')}",
            )
            return 1

        record(
            "update detected and verified",
            state.get("last_check_result") == "update-available"
            or state.get("status") == "success",
            f"check={state.get('last_check_result')} "
            f"available={state.get('available_version')} "
            f"verified={state.get('status')}",
        )
        record(
            "update applied and health-checked",
            state.get("status") == "success",
            f"status={state.get('status')} :: {state.get('message')}",
        )

        installed = read_json(paths.build_info_file).get("version", "")
        record(
            f"installed version is now {args.expect_version}",
            installed == args.expect_version,
            f"build_info version={installed} (was {before})",
        )

        healthy = wait_for(
            lambda: read_json(paths.health_state_file).get("all_healthy") is True, 240
        )
        health = read_json(paths.health_state_file)
        record(
            "backend healthy on the new version after the update",
            healthy,
            f"version={health.get('version')} "
            + ", ".join(
                f"{c['name']}={c.get('health_detail')}" for c in health.get("children", [])
            ),
        )

        # --------------------------------------------------- negative cases
        if not args.skip_negative:
            section("Negative cases against the installed updater")
            forged = release_dir / "manifest-forged.json"
            badhash = release_dir / "manifest-badhash.json"

            def restart_supervisor() -> subprocess.Popen:
                subprocess.run(
                    ["taskkill", "/IM", "ProShieldService.exe", "/F"],
                    capture_output=True,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
                time.sleep(3.0)
                subprocess.run(
                    [str(paths.service_exe), "stop-planes", "--timeout", "15"],
                    capture_output=True,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
                reset_update_state(paths)
                return start_service(paths, env)

            if forged.is_file():
                env = channel_env(env, f"{channel.base}/manifest-forged.json")
                write_settings(
                    paths, {"update_manifest_url": f"{channel.base}/manifest-forged.json"}
                )
                service_process = restart_supervisor()
                state = wait_for_transition(
                    paths.update_state_file,
                    {},
                    lambda s: s.get("last_check_result") == "untrusted-manifest",
                    180,
                )
                record(
                    "untrusted signature refused live (nothing staged)",
                    state.get("last_check_result") == "untrusted-manifest"
                    and not state.get("pending_apply"),
                    f"result={state.get('last_check_result')} :: "
                    f"{(state.get('last_check_message') or '')[:90]}",
                )
                record(
                    "version unchanged after the refused update",
                    read_json(paths.build_info_file).get("version") == args.expect_version,
                    f"installed={read_json(paths.build_info_file).get('version')}",
                )
            else:
                record(
                    "untrusted-signature manifest available",
                    False,
                    "run scripts.publish_update_channel --forge first",
                )

            if badhash.is_file():
                env = channel_env(env, f"{channel.base}/manifest-badhash.json")
                write_settings(
                    paths, {"update_manifest_url": f"{channel.base}/manifest-badhash.json"}
                )
                service_process = restart_supervisor()
                state = wait_for_transition(
                    paths.update_state_file,
                    {},
                    lambda s: s.get("status") in ("failed", "error")
                    and s.get("last_check_result") == "update-available",
                    180,
                )
                refused = state.get("status") in ("failed", "error") and (
                    "hash" in (state.get("message") or "").lower()
                    or "verification" in (state.get("message") or "").lower()
                    or "size" in (state.get("message") or "").lower()
                )
                record(
                    "hash mismatch refused live (nothing applied)",
                    refused,
                    f"status={state.get('status')} :: {(state.get('message') or '')[:110]}",
                )
                record(
                    "version still unchanged after the refused hash",
                    read_json(paths.build_info_file).get("version") == args.expect_version,
                    f"installed={read_json(paths.build_info_file).get('version')}",
                )
    finally:
        section("Stopping the installed supervisor")
        stop_service(service_process, paths)
        channel.close()
        print("  stopped")

    section("SUMMARY")
    failed = 0
    for name, ok, _detail in RESULTS:
        print(f"  {'PASS' if ok else 'FAIL'}  {name}")
        if not ok:
            failed += 1
    print()
    print(f"  {len(RESULTS) - failed} passed, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
