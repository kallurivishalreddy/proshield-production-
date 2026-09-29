"""Unit tests for the install-tree process cleanup.

This is the fix for a real upgrade failure: the installer could not replace
``runtime\\python.exe`` because a backend plane was still running from the
install directory (``DeleteFile failed; code 5``), which aborted the upgrade.

The tests are hermetic - they exercise enumeration and path matching against
this interpreter's own process, and assert the safety properties that matter
(never touch a process outside the prefix; never touch ourselves).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from service import proc_cleanup

WINDOWS_ONLY = pytest.mark.skipif(
    sys.platform != "win32", reason="Windows process APIs"
)


@WINDOWS_ONLY
def test_enumerate_processes_includes_the_current_process() -> None:
    processes = proc_cleanup.enumerate_processes()
    assert processes, "process enumeration returned nothing"
    pids = {item.pid for item in processes}
    assert proc_cleanup.os.getpid() in pids


@WINDOWS_ONLY
def test_enumerate_processes_resolves_image_paths() -> None:
    processes = proc_cleanup.enumerate_processes()
    resolved = [item for item in processes if item.exe_path]
    assert resolved, "no process image paths could be resolved"
    # This interpreter's own image must be resolvable and be the running python.
    mine = next(
        (item for item in processes if item.pid == proc_cleanup.os.getpid()), None
    )
    assert mine is not None
    assert mine.exe_path.lower().endswith("python.exe")


@WINDOWS_ONLY
def test_processes_under_finds_the_current_interpreter_directory() -> None:
    """Path matching must recognise processes running from a given directory."""
    interpreter_dir = Path(sys.executable).resolve().parent
    found = proc_cleanup.processes_under(interpreter_dir)
    assert any(item.pid == proc_cleanup.os.getpid() for item in found), (
        "the current interpreter was not matched by its own directory"
    )


@WINDOWS_ONLY
def test_processes_under_excludes_requested_pids() -> None:
    """The safety property: we must never target ourselves."""
    interpreter_dir = Path(sys.executable).resolve().parent
    found = proc_cleanup.processes_under(
        interpreter_dir, exclude_pids=(proc_cleanup.os.getpid(),)
    )
    assert all(item.pid != proc_cleanup.os.getpid() for item in found)


@WINDOWS_ONLY
def test_processes_under_matches_nothing_for_an_unrelated_directory(tmp_path: Path) -> None:
    empty = tmp_path / "no-such-install"
    empty.mkdir()
    assert proc_cleanup.processes_under(empty) == []


@WINDOWS_ONLY
def test_terminate_processes_in_is_safe_for_an_unrelated_directory(tmp_path: Path) -> None:
    empty = tmp_path / "nothing-here"
    empty.mkdir()
    summary = proc_cleanup.terminate_processes_in(empty, timeout=1.0)
    assert summary["found"] == 0
    assert summary["terminated"] == 0
    assert summary["remaining"] == 0
    assert summary["prefix"] == str(empty)
    # It must still be running after a cleanup pass over an unrelated directory.
    assert proc_cleanup.os.getpid() in summary["skipped_self"]


@WINDOWS_ONLY
def test_terminate_processes_never_kills_the_caller() -> None:
    """Pointing cleanup at our own directory must not terminate this test run."""
    interpreter_dir = Path(sys.executable).resolve().parent
    summary = proc_cleanup.terminate_processes_in(interpreter_dir, timeout=1.0)
    assert proc_cleanup.os.getpid() in summary["skipped_self"]
    assert all(
        target["pid"] != proc_cleanup.os.getpid() for target in summary["targets"]
    )


@WINDOWS_ONLY
def test_self_and_ancestors_includes_this_process() -> None:
    skip = proc_cleanup._self_and_ancestors()
    assert proc_cleanup.os.getpid() in skip


@WINDOWS_ONLY
def test_main_emits_json_and_succeeds_for_an_unrelated_directory(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    empty = tmp_path / "target"
    empty.mkdir()
    code = proc_cleanup.main(["--install-dir", str(empty), "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert code == 0
    assert payload["found"] == 0
    assert payload["remaining"] == 0


@WINDOWS_ONLY
def test_update_helper_is_never_a_cleanup_target(tmp_path: Path, monkeypatch) -> None:
    """The detached helper must survive the quiesce step it triggers.

    In a per-user install the data root and install root are the same directory,
    so the helper (<data>\\updates\\helper\\ProShieldUpdateHelper.exe) would fall
    inside the kill set and terminate itself part-way through applying an update.
    """
    fake_processes = [
        proc_cleanup.ProcessInfo(
            pid=1111,
            name="ProShieldService.exe",
            exe_path=str(tmp_path / "install" / "service" / "ProShieldService.exe"),
        ),
        proc_cleanup.ProcessInfo(
            pid=2222,
            name="python.exe",
            exe_path=str(tmp_path / "install" / "runtime" / "python.exe"),
        ),
        proc_cleanup.ProcessInfo(
            pid=3333,
            name="ProShieldUpdateHelper.exe",
            exe_path=str(
                tmp_path / "install" / "updates" / "helper" / "ProShieldUpdateHelper.exe"
            ),
        ),
    ]
    monkeypatch.setattr(proc_cleanup, "enumerate_processes", lambda: fake_processes)

    found = proc_cleanup.processes_under(tmp_path / "install")
    names = {item.name for item in found}
    assert "ProShieldService.exe" in names
    assert "python.exe" in names
    assert "ProShieldUpdateHelper.exe" not in names, (
        "the update helper must never be terminated by install-tree cleanup"
    )


@WINDOWS_ONLY
def test_service_host_accepts_the_documented_stop_planes_timeout_alias(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    """``stop-planes --timeout N`` must be accepted and forwarded.

    Regression: the installer's ``PrepareToInstall``, the detached update
    helper's quiesce step and docs/WINDOWS_DEPLOYMENT.md all spell the wait as
    ``--timeout``, but the service host only defined ``--wait``.  argparse then
    exited 2 with "unrecognized arguments", the installer logged that exit code
    and believed it had quiesced the install tree - so a backend plane kept
    ``runtime\\python.exe`` locked and the upgrade died with
    ``DeleteFile failed; code 5``.
    """
    from service import windows_service

    empty = tmp_path / "install-tree"
    empty.mkdir()

    captured: dict[str, list] = {}

    def fake_main(argv):  # type: ignore[no-untyped-def]
        captured["argv"] = list(argv)
        return 0

    monkeypatch.setattr("service.proc_cleanup.main", fake_main)

    # The documented spelling must parse and reach the cleanup helper.
    assert windows_service.main(["stop-planes", "--timeout", "17"]) == 0
    assert captured["argv"] == ["--timeout", "17"]

    # ``--json`` still rides along.
    assert windows_service.main(["stop-planes", "--timeout", "5", "--json"]) == 0
    assert captured["argv"] == ["--timeout", "5", "--json"]

    # The service-host spelling keeps working unchanged.
    assert windows_service.main(["stop-planes", "--wait", "8"]) == 0
    assert captured["argv"] == ["--timeout", "8"]

    # An explicit ``--timeout`` wins over the ``--wait`` default rather than
    # silently falling back to 90 s.
    assert windows_service.main(["stop-planes", "--timeout", "3", "--wait", "40"]) == 0
    assert captured["argv"] == ["--timeout", "3"]

    capsys.readouterr()


@WINDOWS_ONLY
def test_summary_contains_no_secrets() -> None:
    summary = proc_cleanup.terminate_processes_in(Path("C:/definitely/not/here"), timeout=0.5)
    blob = json.dumps(summary)
    assert "PROSHIELD_" not in blob
    assert "credential" not in blob.lower()
