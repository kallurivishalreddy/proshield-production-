"""Integration tests over a real ProShield Windows release build.

These verify requirement 13 (build deliverables) against artefacts produced by
``python -m deploy.build_windows``.  They are skipped when no release has been
built, so a clean checkout, a CI job without Inno Setup, or a development
machine is unaffected.

Build a release first:

    python -m deploy.build_windows --with-testmode-installer
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from deploy import build_windows
from service import update_manifest
from service.paths import resolve_paths

ROOT = Path(__file__).resolve().parents[2]
RELEASE_ROOT = ROOT / "dist" / "windows"


def _latest_release() -> Path | None:
    if not RELEASE_ROOT.is_dir():
        return None
    candidates = sorted(
        (p for p in RELEASE_ROOT.iterdir() if p.is_dir() and p.name[0].isdigit()),
        key=lambda p: p.name,
    )
    return candidates[-1] if candidates else None


RELEASE = _latest_release()

pytestmark = pytest.mark.skipif(
    RELEASE is None,
    reason="no Windows release has been built (run: python -m deploy.build_windows)",
)


def test_required_deliverables_exist() -> None:
    assert RELEASE is not None
    version = json.loads((ROOT / "deploy" / "version.json").read_text(encoding="utf-8"))[
        "version"
    ]
    for name in (
        "ProShield.exe",
        "ProShieldService.exe",
        f"ProShieldSetup-v{version}.exe",
        "ProShieldSetup.exe",
        "manifest.json",
        "checksums.txt",
    ):
        path = RELEASE / name
        assert path.is_file(), f"missing deliverable {name}"
        assert path.stat().st_size > 0, f"empty deliverable {name}"


def test_deliverables_are_confined_to_the_release_directory() -> None:
    """Generated binaries must never appear inside a source directory.

    Dependency directories are excluded on purpose: ``node_modules`` contains
    third-party prebuilt binaries (``@esbuild/win32-x64/esbuild.exe``), which
    are a build *input* fetched by npm, not a ProShield artefact the build
    produced.  Flagging them made this guard fail as soon as ``npm install``
    had run, i.e. it punished a normal development machine.
    """
    assert RELEASE is not None
    ignored = {
        "node_modules",
        "__pycache__",
        ".pytest_cache",
        ".venv",
        "venv",
        ".mypy_cache",
        ".ruff_cache",
    }
    for source_dir in ("app", "scripts", "frontend", "service", "desktop", "deploy"):
        offenders = sorted(
            str(p.relative_to(ROOT))
            for p in (ROOT / source_dir).rglob("*")
            if p.is_file()
            and p.suffix.lower() in (".exe", ".msi", ".dll")
            and not ignored.intersection(p.relative_to(ROOT / source_dir).parts)
        )
        assert not offenders, (
            f"build artefacts found inside the source tree under {source_dir}/: {offenders}"
        )


def test_checksums_match_the_artefacts() -> None:
    assert RELEASE is not None
    checksums = RELEASE / "checksums.txt"
    lines = [
        line.split()
        for line in checksums.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert lines, "checksums.txt is empty"
    for digest, name in lines:
        target = RELEASE / name
        assert target.is_file(), f"checksum entry {name} has no matching file"
        assert build_windows.sha256_file(target) == digest, f"checksum mismatch for {name}"


def test_signed_manifest_verifies_against_the_shipped_public_key() -> None:
    """The published manifest must chain back to the public key that ships."""
    assert RELEASE is not None
    public_key_path = ROOT / "deploy" / "proshield-update.pub.pem"
    assert public_key_path.is_file(), "the update public key must be tracked in Git"

    document = json.loads((RELEASE / "manifest.json").read_text(encoding="utf-8"))
    manifest = update_manifest.parse_manifest(json.dumps(document).encode())
    verified = update_manifest.verify_manifest(
        manifest,
        update_manifest.load_public_key(public_key_path),
        expected_channel=manifest.channel,
    )
    assert verified.verified is True
    assert "signature ok" in verified.verify_detail


def test_manifest_hashes_the_installer_it_publishes() -> None:
    assert RELEASE is not None
    document = json.loads((RELEASE / "manifest.json").read_text(encoding="utf-8"))
    artifact = document["artifacts"]["windows-x64"]
    installer = RELEASE / artifact["filename"]
    assert installer.is_file(), f"manifest points at a missing installer {artifact['filename']}"
    assert build_windows.sha256_file(installer) == artifact["sha256"]
    assert installer.stat().st_size == artifact["size"]


def test_build_report_records_toolchain_and_payload_audit() -> None:
    assert RELEASE is not None
    report = json.loads((RELEASE / "build-report.json").read_text(encoding="utf-8"))
    for key in ("version", "channel", "git_commit", "tools", "installers"):
        assert key in report, f"build-report.json is missing {key}"
    tools = report["tools"]
    assert tools.get("python") and tools.get("pyinstaller")

    # The payload gate must have run and passed.
    assert report.get("payload_audit", {}).get("ok") is True
    pruned = report.get("pruned", {})
    assert "removed_dirs" in pruned and "removed_files" in pruned


def test_staged_payload_contains_no_forbidden_content() -> None:
    """Requirement 11, asserted directly against the staged payload."""
    assert RELEASE is not None
    stage = RELEASE / "_stage"
    if not stage.is_dir():
        pytest.skip("staging directory was cleaned up")
    # audit_stage raises SystemExit when anything forbidden is present.
    result = build_windows.audit_stage(stage)
    assert result["ok"] is True


def test_staged_payload_only_ships_the_authoritative_ui() -> None:
    assert RELEASE is not None
    stage = RELEASE / "_stage"
    if not stage.is_dir():
        pytest.skip("staging directory was cleaned up")

    ui = stage / "frontend" / "soc" / "index.html"
    assert ui.is_file(), "the authoritative React UI was not staged"

    legacy = [
        p.name
        for p in (stage / "frontend").iterdir()
        if p.name != "soc" and p.name != "login.html"
    ]
    assert legacy == [], f"legacy frontend content was staged: {legacy}"

    scripts = sorted(p.name for p in (stage / "scripts").iterdir())
    assert scripts == ["__init__.py", "ingress_server.py", "proxy_server.py"]


def test_staged_payload_ships_the_implementation_and_runtime() -> None:
    assert RELEASE is not None
    stage = RELEASE / "_stage"
    if not stage.is_dir():
        pytest.skip("staging directory was cleaned up")

    assert (stage / "app" / "config.py").is_file()
    assert (stage / "app" / "proxy" / "proxy.py").is_file()
    assert (stage / "runtime" / "python.exe").is_file()
    assert (stage / "service" / "ProShieldService.exe").is_file()
    assert (stage / "desktop" / "ProShield.exe").is_file()
    assert (stage / "deploy" / "build_info.json").is_file()

    build_info = json.loads(
        (stage / "deploy" / "build_info.json").read_text(encoding="utf-8")
    )
    version_file = json.loads((ROOT / "deploy" / "version.json").read_text(encoding="utf-8"))
    assert build_info["version"] == version_file["version"]
    assert build_info["channel"] == version_file["channel"]


def test_build_report_records_the_freshness_gate() -> None:
    """The build must prove its frozen binaries are not stale."""
    assert RELEASE is not None
    report = json.loads((RELEASE / "build-report.json").read_text(encoding="utf-8"))
    freshness = report.get("frozen_freshness")
    assert freshness is not None, "build-report.json is missing frozen_freshness"
    assert freshness.get("ok") is True
    assert freshness.get("checked"), "no frozen executable was checked"


def test_verify_frozen_freshness_flags_a_stale_binary(tmp_path) -> None:
    """A frozen exe older than its own sources must fail the build gate.

    This is the guard for a real incident: a build step replaced a freshly
    frozen (fixed) service with an older copy and the packaged installer then
    carried the bug.
    """
    import os
    import time

    from deploy import build_windows

    stage = tmp_path / "_stage"
    (stage / "service").mkdir(parents=True)
    (stage / "desktop").mkdir(parents=True)
    stale_exe = stage / "service" / "ProShieldService.exe"
    stale_exe.write_bytes(b"MZ-stale")

    # Make the frozen image look old, then make a service source look new.
    old = time.time() - 3600
    os.utime(stale_exe, (old, old))

    # A dedicated source directory keeps the test independent of the real tree.
    source_dir = tmp_path / "service"
    source_dir.mkdir()
    fresh_source = source_dir / "windows_service.py"
    fresh_source.write_text("# changed after the freeze\n", encoding="utf-8")
    os.utime(fresh_source, (time.time(), time.time()))

    original_pairs = build_windows.FROZEN_SOURCE_PAIRS
    original_root = build_windows.ROOT
    try:
        build_windows.FROZEN_SOURCE_PAIRS = (
            ("service/ProShieldService.exe", str(source_dir)),
        )
        build_windows.ROOT = tmp_path
        with pytest.raises(SystemExit) as excinfo:
            build_windows.verify_frozen_freshness(stage)
        assert "freshness check FAILED" in str(excinfo.value)

        # Refreshing the frozen image clears the failure.
        os.utime(stale_exe, (time.time(), time.time()))
        result = build_windows.verify_frozen_freshness(stage)
        assert result["ok"] is True
    finally:
        build_windows.FROZEN_SOURCE_PAIRS = original_pairs
        build_windows.ROOT = original_root


def test_private_signing_key_is_never_packaged() -> None:
    assert RELEASE is not None
    private = ROOT / "deploy" / "signing" / "proshield-update-private.pem"
    if private.is_file():
        # It exists on this machine (it is the signing key) but must not be shipped.
        for base in (RELEASE, RELEASE / "_stage"):
            if not base.is_dir():
                continue
            leaked = [str(p) for p in base.rglob("*private*.pem")]
            assert leaked == [], f"private signing key leaked into {base}: {leaked}"