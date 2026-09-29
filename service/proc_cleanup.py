"""Terminate ProShield processes that run from inside the install directory.

Why this exists
---------------
An upgrade must replace ``runtime\\python.exe``, and Windows locks a running
image.  The bundled interpreter is shared by **both** backend planes, so any
plane still alive during an upgrade makes the installer fail on that file with
``DeleteFile failed; code 5`` — which is exactly what happened before this
module existed (the installer then aborted and rolled back).

``net stop ProShieldService`` is the primary mechanism (the supervisor
terminates its children on stop), but it is not sufficient on its own:

* a *test-mode* install has no Windows Service to stop;
* a plane can outlive its supervisor if the supervisor was killed;
* an operator may be running ``ProShieldService.exe console`` by hand.

Matching on the **executable path** rather than the image name is deliberate:
``python.exe`` is a generic name, and killing every ``python.exe`` on the machine
would destroy unrelated user work.  Only processes whose image lives inside the
given install directory are touched.

Implemented with ``ctypes`` (Toolhelp snapshots + ``QueryFullProcessImageName``)
so the frozen service and helper carry no extra dependency.
"""
from __future__ import annotations

import ctypes
import json
import logging
import os
import time
from ctypes import wintypes
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Sequence, Tuple

LOGGER = logging.getLogger("proshield.proc_cleanup")

TH32CS_SNAPPROCESS = 0x00000002
PROCESS_TERMINATE = 0x0001
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value
MAX_PATH_LONG = 32768

#: Images that must NEVER be terminated by this module.
#:
#: The detached update helper is a copy of ``ProShieldService.exe`` staged under
#: ``<data_root>\updates\helper``.  For a machine-wide install that directory is
#: outside ``C:\Program Files\ProShield``, so it is already safe.  For a
#: *per-user* install the data root and the install root are the same directory,
#: and the helper sits inside the kill set - it would terminate itself part-way
#: through applying an update.  Excluding it by name fixes that without weakening
#: the cleanup: the helper is the one process that must survive the quiesce step
#: it is performing.
NEVER_TERMINATE_NAMES = ("proshieldupdatehelper.exe",)


@dataclass(frozen=True)
class ProcessInfo:
    pid: int
    name: str
    exe_path: str


class _PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", ctypes.c_long),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", wintypes.WCHAR * 260),
    ]


def _kernel32():
    return ctypes.WinDLL("kernel32", use_last_error=True)


def enumerate_processes() -> List[ProcessInfo]:
    """Every process the current user can query, with its image path."""
    if os.name != "nt":  # pragma: no cover - Windows-only product
        return []

    kernel32 = _kernel32()
    create_snapshot = kernel32.CreateToolhelp32Snapshot
    create_snapshot.restype = wintypes.HANDLE
    create_snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]

    first = kernel32.Process32FirstW
    next_ = kernel32.Process32NextW
    first.argtypes = [wintypes.HANDLE, ctypes.POINTER(_PROCESSENTRY32W)]
    next_.argtypes = [wintypes.HANDLE, ctypes.POINTER(_PROCESSENTRY32W)]

    open_process = kernel32.OpenProcess
    open_process.restype = wintypes.HANDLE
    open_process.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]

    query_path = kernel32.QueryFullProcessImageNameW
    query_path.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.LPWSTR,
        ctypes.POINTER(wintypes.DWORD),
    ]
    close_handle = kernel32.CloseHandle

    snapshot = create_snapshot(TH32CS_SNAPPROCESS, 0)
    if snapshot == INVALID_HANDLE_VALUE:
        return []

    results: List[ProcessInfo] = []
    try:
        entry = _PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(_PROCESSENTRY32W)
        if not first(snapshot, ctypes.byref(entry)):
            return []
        while True:
            pid = int(entry.th32ProcessID)
            if pid:
                exe_path = ""
                handle = open_process(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
                if handle:
                    try:
                        buffer = ctypes.create_unicode_buffer(MAX_PATH_LONG)
                        size = wintypes.DWORD(MAX_PATH_LONG)
                        if query_path(handle, 0, buffer, ctypes.byref(size)):
                            exe_path = buffer.value
                    finally:
                        close_handle(handle)
                results.append(
                    ProcessInfo(pid=pid, name=str(entry.szExeFile), exe_path=exe_path)
                )
            if not next_(snapshot, ctypes.byref(entry)):
                break
    finally:
        close_handle(snapshot)
    return results


def processes_under(
    prefix: Path, exclude_pids: Tuple[int, ...] = ()
) -> List[ProcessInfo]:
    """Processes whose image lives inside ``prefix`` (case-insensitive)."""
    try:
        root = str(Path(prefix).resolve()).rstrip("\\").lower() + "\\"
    except OSError:  # pragma: no cover
        root = str(prefix).rstrip("\\").lower() + "\\"

    excluded = set(exclude_pids)
    matches: List[ProcessInfo] = []
    for item in enumerate_processes():
        if item.pid in excluded or not item.exe_path:
            continue
        if item.name.lower() in NEVER_TERMINATE_NAMES:
            continue
        if item.exe_path.lower().startswith(root):
            matches.append(item)
    return matches


def _self_and_ancestors() -> set:
    """PIDs that must never be terminated: us and our parent chain."""
    skip = {os.getpid()}
    parent = os.getppid() if hasattr(os, "getppid") else 0
    if parent:
        skip.add(parent)
    return skip


def terminate_processes_in(
    prefix: Path,
    timeout: float = 20.0,
    poll_seconds: float = 0.5,
    exclude_pids: Optional[Sequence[int]] = None,
) -> dict:
    """Force-terminate every ProShield process running from ``prefix``.

    Returns a secret-free summary suitable for logging or JSON output.  Never
    raises: an upgrade must be able to proceed (and fail cleanly) even if this
    cleanup cannot run.
    """
    skip = _self_and_ancestors()
    if exclude_pids:
        skip.update(int(pid) for pid in exclude_pids)

    summary = {
        "prefix": str(prefix),
        "found": 0,
        "terminated": 0,
        "remaining": 0,
        "skipped_self": sorted(skip),
        "targets": [],
    }

    if os.name != "nt":  # pragma: no cover
        summary["note"] = "not Windows"
        return summary

    try:
        targets = processes_under(prefix, exclude_pids=tuple(skip))
    except Exception as exc:  # pragma: no cover - defensive
        LOGGER.warning("could not enumerate processes: %s", exc)
        summary["error"] = str(exc)
        return summary

    summary["found"] = len(targets)
    summary["targets"] = [
        {"pid": item.pid, "name": item.name, "path": item.exe_path} for item in targets
    ]

    kernel32 = _kernel32()
    open_process = kernel32.OpenProcess
    open_process.restype = wintypes.HANDLE
    open_process.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    terminate = kernel32.TerminateProcess
    terminate.argtypes = [wintypes.HANDLE, wintypes.UINT]
    close_handle = kernel32.CloseHandle

    for item in targets:
        handle = open_process(PROCESS_TERMINATE, False, item.pid)
        if not handle:
            LOGGER.warning(
                "cannot open pid %s (%s) for termination", item.pid, item.name
            )
            continue
        try:
            if terminate(handle, 1):
                summary["terminated"] += 1
                LOGGER.info("terminated %s (pid=%s)", item.name, item.pid)
            else:
                LOGGER.warning("TerminateProcess failed for pid %s", item.pid)
        finally:
            close_handle(handle)

    # Wait for the images to actually be released so the installer can replace
    # them instead of failing on a still-locked file.
    deadline = time.time() + max(0.0, timeout)
    while time.time() < deadline:
        try:
            if not processes_under(prefix, exclude_pids=tuple(skip)):
                break
        except Exception:  # pragma: no cover
            break
        time.sleep(max(0.05, poll_seconds))

    try:
        summary["remaining"] = len(processes_under(prefix, exclude_pids=tuple(skip)))
    except Exception:  # pragma: no cover
        summary["remaining"] = -1

    if summary["remaining"]:
        LOGGER.warning(
            "%d process(es) are still running from %s after cleanup",
            summary["remaining"],
            prefix,
        )
    return summary


def main(argv: Optional[List[str]] = None) -> int:
    """``stop-planes [--install-dir DIR] [--json]`` (internal helper command)."""
    import argparse

    parser = argparse.ArgumentParser(
        prog="ProShield stop-planes",
        description=(
            "Terminate ProShield backend processes running from the install "
            "directory so an upgrade can replace runtime\\python.exe."
        ),
    )
    parser.add_argument("--install-dir", default="")
    parser.add_argument("--timeout", type=float, default=20.0)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(list(argv) if argv is not None else None)

    if args.install_dir:
        prefix = Path(args.install_dir)
    else:
        from service.paths import install_root

        prefix = install_root()

    summary = terminate_processes_in(prefix, timeout=args.timeout)
    if args.json:
        print(json.dumps(summary, indent=2, sort_keys=True))
    else:
        print(
            f"proshield processes under {summary['prefix']}: "
            f"found={summary['found']} terminated={summary['terminated']} "
            f"remaining={summary['remaining']}"
        )
    return 0 if not summary.get("remaining") else 1


if __name__ == "__main__":
    raise SystemExit(main())