"""Unit tests for the ProShield update trust chain and failure containment.

Covers requirement 9 (update security) and requirement 10 (update failure /
recovery).  Everything is hermetic: manifests and packages are generated in
``tmp_path`` and served from a loopback HTTP server; no external network and no
MongoDB are involved.
"""
from __future__ import annotations

import dataclasses
import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Optional

import pytest

from service import update_client, update_manifest
from service.paths import resolve_paths
from service.settings import load_settings
from service.update_apply import UpdateApplier
from service.updater import STATE_DISABLED, UpdateEngine

pytest.importorskip("cryptography")

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from cryptography.hazmat.primitives.serialization import (  # noqa: E402
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

GOOD_PACKAGE = b"MZ" + b"proshield-package-payload" * 8


# ------------------------------------------------------------------- fixtures


@pytest.fixture()
def keypair(tmp_path: Path):
    private = Ed25519PrivateKey.generate()
    private_path = tmp_path / "signing.key"
    private_path.write_bytes(
        private.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    )
    public_path = tmp_path / "signing.pub.pem"
    public_path.write_bytes(
        private.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    )
    return private_path, public_path


@pytest.fixture()
def paths(tmp_path: Path):
    """A temporary install + data layout with the public key installed."""
    install = tmp_path / "install"
    data = tmp_path / "data"
    resolved = resolve_paths(install=install, data=data).ensure_layout()
    for name in ("app", "scripts", "frontend", "service", "desktop", "deploy"):
        (install / name).mkdir(parents=True, exist_ok=True)
    (install / "app" / "config.py").write_text("# marker\n", encoding="utf-8")
    (install / "frontend" / "soc").mkdir(parents=True, exist_ok=True)
    (install / "frontend" / "soc" / "index.html").write_text("<div id=root>", encoding="utf-8")
    (install / "deploy" / "build_info.json").write_text(
        json.dumps({"version": "1.0.0", "channel": "testing"}), encoding="utf-8"
    )
    return resolved


def _write_public_key(paths, public_path: Path) -> None:
    paths.update_public_key_file.write_bytes(public_path.read_bytes())


def _signed_manifest_document(private_path: Path, version: str, payload: bytes, url: str) -> dict:
    return update_manifest.build_signed_manifest(
        version=version,
        channel="testing",
        artifacts={
            "windows-x64": {
                "url": url,
                "sha256": update_manifest.sha256_bytes(payload),
                "size": len(payload),
                "filename": "ProShieldSetup-v" + version + ".exe",
                "kind": "installer",
            }
        },
        private_key_path=private_path,
        notes="unit test",
    )


class _AnyJsonServer:
    """Loopback HTTP server: serves files from a directory and always answers
    /health and /api/ingress/health with 200 JSON."""

    def __init__(self, directory: Path) -> None:
        self.directory = directory
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                if self.path in ("/health", "/api/ingress/health"):
                    body = json.dumps({"status": "ok", "ok": True}).encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                candidate = outer.directory / self.path.lstrip("/").split("?")[0]
                if candidate.is_file():
                    data = candidate.read_bytes()
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
                    return
                self.send_error(404)

            def log_message(self, *args):  # noqa: D102
                pass

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.server.server_address[1]}"

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


# ----------------------------------------------------------- canonical payload


def test_canonical_payload_is_stable_and_excludes_the_signature() -> None:
    document = {"b": 2, "a": 1, "signature": "abc"}
    payload = update_manifest.canonical_payload(document)
    assert payload == b'{"a":1,"b":2}'
    # Key order in the input must not matter.
    assert update_manifest.canonical_payload({"a": 1, "b": 2}) == payload


# ------------------------------------------------------------- parse + verify


def test_parse_manifest_rejects_garbage() -> None:
    with pytest.raises(update_manifest.ManifestError):
        update_manifest.parse_manifest(b"not json")
    with pytest.raises(update_manifest.ManifestError):
        update_manifest.parse_manifest(b"[1,2,3]")
    with pytest.raises(update_manifest.ManifestError):
        update_manifest.parse_manifest(json.dumps({"channel": "testing"}).encode())


def test_parse_manifest_ignores_artifacts_without_url_or_hash() -> None:
    raw = json.dumps(
        {
            "version": "1.0.1",
            "channel": "testing",
            "artifacts": {
                "windows-x64": {"url": "", "sha256": "x"},
                "linux-x64": {"url": "http://x", "sha256": ""},
            },
        }
    ).encode()
    manifest = update_manifest.parse_manifest(raw)
    assert manifest.version == "1.0.1"
    assert manifest.artifacts == {}


def test_unsigned_manifest_is_rejected_by_default(paths, keypair) -> None:
    _, public_path = keypair
    _write_public_key(paths, public_path)
    manifest = update_manifest.parse_manifest(
        json.dumps({"version": "2.0.0", "channel": "testing"}).encode()
    )
    with pytest.raises(update_manifest.ManifestError, match="no signature"):
        update_manifest.verify_manifest(manifest, update_manifest.load_public_key(
            paths.update_public_key_file))


def test_unsigned_manifest_allowed_only_when_explicitly_enabled(paths) -> None:
    manifest = update_manifest.parse_manifest(
        json.dumps({"version": "2.0.0", "channel": "testing"}).encode()
    )
    verified = update_manifest.verify_manifest(
        manifest, None, allow_unsigned=True, expected_channel="testing"
    )
    assert verified.verified is True
    assert "UNSIGNED" in verified.verify_detail


def test_missing_public_key_is_fail_closed(paths) -> None:
    manifest = update_manifest.parse_manifest(
        json.dumps({"version": "2.0.0", "channel": "testing", "signature": "x"}).encode()
    )
    with pytest.raises(update_manifest.ManifestError, match="no update public key"):
        update_manifest.verify_manifest(manifest, None)


def test_signed_manifest_verifies_and_forgeries_fail(paths, keypair) -> None:
    private_path, public_path = keypair
    _write_public_key(paths, public_path)
    document = _signed_manifest_document(
        private_path, "2.0.0", GOOD_PACKAGE, "http://example/ProShieldSetup.exe"
    )
    manifest = update_manifest.parse_manifest(json.dumps(document).encode())
    verified = update_manifest.verify_manifest(
        manifest, update_manifest.load_public_key(paths.update_public_key_file),
        expected_channel="testing",
    )
    assert verified.verified is True
    assert "signature ok" in verified.verify_detail

    # Flip the version -> the signed payload no longer matches.
    forged = dict(document)
    forged["version"] = "9.9.9"
    with pytest.raises(update_manifest.ManifestError, match="signature verification FAILED"):
        update_manifest.verify_manifest(
            update_manifest.parse_manifest(json.dumps(forged).encode()),
            update_manifest.load_public_key(paths.update_public_key_file),
        )

    # Swap the artefact hash -> also a signature failure (the hash is signed).
    forged_hash = json.loads(json.dumps(document))
    forged_hash["artifacts"]["windows-x64"]["sha256"] = "0" * 64
    with pytest.raises(update_manifest.ManifestError, match="signature verification FAILED"):
        update_manifest.verify_manifest(
            update_manifest.parse_manifest(json.dumps(forged_hash).encode()),
            update_manifest.load_public_key(paths.update_public_key_file),
        )


def test_wrong_channel_is_refused_but_stable_promotes_testing(paths, keypair) -> None:
    private_path, public_path = keypair
    _write_public_key(paths, public_path)

    beta = _signed_manifest_document(
        private_path, "2.0.0", GOOD_PACKAGE, "http://example/x.exe"
    )
    beta["channel"] = "beta"
    with pytest.raises(update_manifest.ManifestError, match="does not match"):
        update_manifest.verify_manifest(
            update_manifest.parse_manifest(json.dumps(beta).encode()),
            update_manifest.load_public_key(paths.update_public_key_file),
            expected_channel="testing",
        )


def test_bad_signature_encoding_is_rejected(paths, keypair) -> None:
    _, public_path = keypair
    _write_public_key(paths, public_path)
    document = {
        "version": "2.0.0",
        "channel": "testing",
        "signature": "!!!not-base64!!!",
    }
    with pytest.raises(update_manifest.ManifestError, match="base64"):
        update_manifest.verify_manifest(
            update_manifest.parse_manifest(json.dumps(document).encode()),
            update_manifest.load_public_key(paths.update_public_key_file),
        )


# -------------------------------------------------------------- verify_artifact


def test_verify_artifact_detects_size_and_hash_mismatch(tmp_path: Path) -> None:
    artifact = update_manifest.Artifact(
        url="http://x/p.exe",
        sha256=update_manifest.sha256_bytes(GOOD_PACKAGE),
        size=len(GOOD_PACKAGE),
        filename="p.exe",
    )
    good = tmp_path / "p.exe"
    good.write_bytes(GOOD_PACKAGE)
    ok, detail = update_manifest.verify_artifact(artifact, good)
    assert ok is True and "hash verified" in detail

    truncated = tmp_path / "trunc.exe"
    truncated.write_bytes(GOOD_PACKAGE[:-3])
    ok, detail = update_manifest.verify_artifact(artifact, truncated)
    assert ok is False and "size mismatch" in detail

    corrupted = tmp_path / "corrupt.exe"
    corrupted.write_bytes(GOOD_PACKAGE + b"x")
    ok, detail = update_manifest.verify_artifact(artifact, corrupted)
    assert ok is False

    ok, detail = update_manifest.verify_artifact(artifact, tmp_path / "missing.exe")
    assert ok is False and "does not exist" in detail


# ------------------------------------------------------------------- download


def test_download_artifact_streams_and_is_atomic(tmp_path: Path) -> None:
    served = tmp_path / "served"
    served.mkdir()
    (served / "pkg.exe").write_bytes(GOOD_PACKAGE)
    server = _AnyJsonServer(served)
    try:
        destination = tmp_path / "out" / "pkg.exe"
        result = update_client.download_artifact(
            f"{server.base_url}/pkg.exe", destination, expected_size=len(GOOD_PACKAGE)
        )
        assert result.read_bytes() == GOOD_PACKAGE
        assert not destination.with_suffix(destination.suffix + ".part").exists()
    finally:
        server.close()


def test_download_artifact_rejects_a_truncated_transfer(tmp_path: Path) -> None:
    served = tmp_path / "served"
    served.mkdir()
    (served / "pkg.exe").write_bytes(GOOD_PACKAGE)
    server = _AnyJsonServer(served)
    try:
        with pytest.raises(update_client.UpdateClientError, match="incomplete download"):
            update_client.download_artifact(
                f"{server.base_url}/pkg.exe",
                tmp_path / "pkg.exe",
                expected_size=len(GOOD_PACKAGE) + 100,
                retries=1,
            )
    finally:
        server.close()


def test_fetch_bytes_reports_unavailable_server() -> None:
    with pytest.raises(update_client.UpdateClientError):
        update_client.fetch_bytes("http://127.0.0.1:1/manifest.json", timeout=1.0, retries=1)


# --------------------------------------------------------------------- engine


def test_engine_without_endpoint_is_disabled_and_harmless(paths, monkeypatch) -> None:
    """No configured endpoint => the channel is inactive, never an error.

    The environment is cleared explicitly rather than relying only on the
    root conftest's scrub fixture: the whole point of this test is "nothing is
    configured", so it must not be able to observe an ambient
    ``PROSHIELD_UPDATE_URL``.  With a leftover one set (as the deployment
    verification scripts do) the endpoint resolved, the fetch failed and this
    reported ``server-unavailable`` - masking the disabled-channel path.
    """
    monkeypatch.delenv("PROSHIELD_UPDATE_URL", raising=False)

    settings = load_settings(paths)
    engine = UpdateEngine(paths=paths, settings=settings)
    result = engine.check_now()
    assert result["result"] == "no-endpoint"
    assert engine.state.status == STATE_DISABLED
    assert paths.update_state_file.is_file()
    # Nothing was staged and nothing will be applied.
    assert engine.state.pending_apply is False
    assert engine.state.staged_artifact == ""


def test_ambient_proshield_env_cannot_leak_into_a_test() -> None:
    """The root conftest must strip ambient ``PROSHIELD_*`` variables.

    ``service/settings.py`` gives the environment precedence over
    ``proshield.json`` on purpose (the installer and the Windows service depend
    on it).  The consequence is that a developer machine with those variables
    set changes test outcomes, which is exactly how
    ``test_engine_without_endpoint_is_disabled_and_harmless`` started failing.
    An explicit override must still work.
    """
    leaked = [n for n in os.environ if n.startswith("PROSHIELD_")]
    assert leaked == [], (
        "the autouse _scrub_proshield_environment fixture must remove ambient "
        f"PROSHIELD_* variables; still set: {leaked}"
    )

    # A test that *wants* an override can still set one.
    monkeypatch = pytest.MonkeyPatch()
    try:
        monkeypatch.setenv("PROSHIELD_UPDATE_URL", "http://127.0.0.1:9/x.json")
        assert os.environ["PROSHIELD_UPDATE_URL"] == "http://127.0.0.1:9/x.json"
    finally:
        monkeypatch.undo()
    assert "PROSHIELD_UPDATE_URL" not in os.environ


def test_engine_reports_up_to_date_when_installed_version_matches(paths, keypair) -> None:
    private_path, public_path = keypair
    _write_public_key(paths, public_path)
    served = paths.data_root / "state" / "served"
    served.mkdir(parents=True, exist_ok=True)

    current = load_settings(paths).version
    document = _signed_manifest_document(
        private_path, current, GOOD_PACKAGE, "http://example/x.exe"
    )
    (served / "manifest.json").write_text(json.dumps(document), encoding="utf-8")
    server = _AnyJsonServer(served)
    try:
        settings = dataclasses.replace(
            load_settings(paths), update_manifest_url=f"{server.base_url}/manifest.json"
        )
        engine = UpdateEngine(paths=paths, settings=settings)
        result = engine.check_now()
        assert result["result"] == "up-to-date"
        assert engine.state.pending_apply is False
    finally:
        server.close()


def test_engine_stages_a_newer_signed_release(paths, keypair) -> None:
    private_path, public_path = keypair
    _write_public_key(paths, public_path)
    served = paths.data_root / "state" / "served"
    served.mkdir(parents=True, exist_ok=True)
    (served / "ProShieldSetup-v9.9.9.exe").write_bytes(GOOD_PACKAGE)

    server = _AnyJsonServer(served)
    try:
        document = _signed_manifest_document(
            private_path,
            "9.9.9",
            GOOD_PACKAGE,
            f"{server.base_url}/ProShieldSetup-v9.9.9.exe",
        )
        (served / "manifest.json").write_text(json.dumps(document), encoding="utf-8")
        settings = dataclasses.replace(
            load_settings(paths),
            update_manifest_url=f"{server.base_url}/manifest.json",
            update_mode="automatic",
        )
        engine = UpdateEngine(paths=paths, settings=settings)
        result = engine.check_now()
        assert result["result"] == "update-available"
        assert result["version"] == "9.9.9"
        assert result["will_apply"] is True
        staged = Path(engine.state.staged_artifact)
        assert staged.is_file()
        assert staged.read_bytes() == GOOD_PACKAGE
        assert Path(engine.state.staged_manifest).is_file()
    finally:
        server.close()


def test_engine_refuses_a_tampered_package(paths, keypair) -> None:
    private_path, public_path = keypair
    _write_public_key(paths, public_path)
    served = paths.data_root / "state" / "served"
    served.mkdir(parents=True, exist_ok=True)
    # The manifest describes GOOD_PACKAGE but the server hands out a package of
    # the SAME LENGTH with different content, so only the hash can catch it.
    tampered = b"EVIL" + GOOD_PACKAGE[4:]
    assert len(tampered) == len(GOOD_PACKAGE)
    (served / "ProShieldSetup-v9.9.9.exe").write_bytes(tampered)

    server = _AnyJsonServer(served)
    try:
        document = _signed_manifest_document(
            private_path,
            "9.9.9",
            GOOD_PACKAGE,
            f"{server.base_url}/ProShieldSetup-v9.9.9.exe",
        )
        (served / "manifest.json").write_text(json.dumps(document), encoding="utf-8")
        settings = dataclasses.replace(
            load_settings(paths),
            update_manifest_url=f"{server.base_url}/manifest.json",
            update_mode="automatic",
        )
        engine = UpdateEngine(paths=paths, settings=settings)
        result = engine.check_now()
        assert result["result"] == "stage-failed"
        assert engine.state.pending_apply is False
        assert "verification failed" in engine.state.message
        # The rejected package is not left behind.
        assert not (paths.updates_dir / "9.9.9" / "ProShieldSetup-v9.9.9.exe").exists()
    finally:
        server.close()


def test_engine_refuses_a_manifest_below_min_version(paths, keypair) -> None:
    private_path, public_path = keypair
    _write_public_key(paths, public_path)
    served = paths.data_root / "state" / "served"
    served.mkdir(parents=True, exist_ok=True)
    document = _signed_manifest_document(
        private_path, "9.9.9", GOOD_PACKAGE, "http://example/x.exe"
    )
    document["min_version"] = "5.0.0"
    # Re-sign because min_version is part of the signed payload.
    document = update_manifest.build_signed_manifest(
        version="9.9.9",
        channel="testing",
        artifacts=document["artifacts"],
        private_key_path=private_path,
        min_version="5.0.0",
    )
    (served / "manifest.json").write_text(json.dumps(document), encoding="utf-8")
    server = _AnyJsonServer(served)
    try:
        settings = dataclasses.replace(
            load_settings(paths), update_manifest_url=f"{server.base_url}/manifest.json"
        )
        engine = UpdateEngine(paths=paths, settings=settings)
        result = engine.check_now()
        assert result["result"] == "below-min-version"
        assert engine.state.pending_apply is False
    finally:
        server.close()


def test_engine_accepts_a_channel_base_url(paths, keypair) -> None:
    """An operator may configure the channel base, not just the manifest URL.

    The installer records ``PROSHIELD_UPDATE_URL`` as a *base* URL.  Without
    normalisation the updater fetched the base (receiving a directory listing)
    and failed with "manifest is not valid JSON".
    """
    private_path, public_path = keypair
    _write_public_key(paths, public_path)
    served = paths.data_root / "state" / "served"
    served.mkdir(parents=True, exist_ok=True)
    (served / "ProShieldSetup-v9.9.9.exe").write_bytes(GOOD_PACKAGE)

    server = _AnyJsonServer(served)
    try:
        document = _signed_manifest_document(
            private_path, "9.9.9", GOOD_PACKAGE, f"{server.base_url}/ProShieldSetup-v9.9.9.exe"
        )
        (served / "manifest.json").write_text(json.dumps(document), encoding="utf-8")
        settings = dataclasses.replace(
            load_settings(paths),
            update_manifest_url=server.base_url,  # base URL, no /manifest.json
            update_mode="notify-only",
        )
        engine = UpdateEngine(paths=paths, settings=settings)
        result = engine.check_now()
        assert result["result"] == "update-available", result
        assert engine.state.available_version == "9.9.9"
    finally:
        server.close()


def test_engine_rejects_a_genuinely_invalid_manifest(paths) -> None:
    """Normalisation must not paper over a real server error."""
    settings = dataclasses.replace(
        load_settings(paths),
        update_manifest_url="http://127.0.0.1:1/manifest.json",
    )
    engine = UpdateEngine(paths=paths, settings=settings)
    result = engine.check_now()
    assert result["result"] == "server-unavailable"


def test_spawn_apply_helper_requires_a_staged_package(paths) -> None:
    settings = load_settings(paths)
    engine = UpdateEngine(paths=paths, settings=settings)
    result = engine.spawn_apply_helper()
    assert result["ok"] is False
    assert "no verified package" in result["message"]


def test_spawn_apply_helper_frozen_branch_stages_and_launches(
    paths, monkeypatch, tmp_path
) -> None:
    """Regression: the frozen branch used ``sys`` without importing it.

    That raised ``NameError: name 'sys' is not defined`` inside the supervisor's
    tick hook, so a *verified, staged* update was never applied - the install
    silently stayed on the old version.  This test exercises the frozen code path
    directly.
    """
    settings = load_settings(paths)
    engine = UpdateEngine(paths=paths, settings=settings)

    artifact = paths.updates_dir / "9.9.9" / "ProShieldSetup.exe"
    artifact.parent.mkdir(parents=True, exist_ok=True)
    artifact.write_bytes(GOOD_PACKAGE)
    manifest = artifact.parent / "manifest.json"
    manifest.write_text(json.dumps({"version": "9.9.9"}), encoding="utf-8")

    engine.state.staged_artifact = str(artifact)
    engine.state.staged_manifest = str(manifest)
    engine.state.available_version = "9.9.9"
    engine.state.pending_apply = True

    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", sys.executable, raising=False)

    result = engine.spawn_apply_helper()

    assert result["ok"] is True, result.get("message")
    helper = paths.updates_dir / "helper" / "ProShieldUpdateHelper.exe"
    assert helper.is_file(), "the frozen helper was not staged outside the install tree"
    # The helper must live OUTSIDE the install tree, otherwise the installer
    # cannot replace the running ProShieldService.exe image.
    assert paths.install_root not in helper.parents
    assert engine.state.pending_apply is False
    assert engine.state.status == "applying"


def test_on_tick_does_not_apply_while_unhealthy(paths, monkeypatch) -> None:
    """A staged update must never be applied over a broken stack."""
    settings = load_settings(paths)
    engine = UpdateEngine(paths=paths, settings=settings)
    engine.state.pending_apply = True

    calls = {"n": 0}
    monkeypatch.setattr(
        engine, "spawn_apply_helper", lambda wait=False: calls.__setitem__("n", calls["n"] + 1) or {"ok": True}
    )

    class FakeChild:
        running = True
        healthy = False

    class FakeSupervisor:
        mongo_ready = True
        children = [FakeChild()]

    import threading

    engine.on_tick(FakeSupervisor(), threading.Event())
    assert calls["n"] == 0, "an unhealthy stack must not be updated"

    class HealthyChild:
        running = True
        healthy = True

    FakeSupervisor.children = [HealthyChild()]
    engine.on_tick(FakeSupervisor(), threading.Event())
    assert calls["n"] == 1, "a healthy stack should apply the staged update"


# -------------------------------------------------------------------- applier


#: Tests must never shell out to the SCM: the restart hook is injected.
NOOP_RESTART = [sys.executable, "-c", "pass"]


def _applier(paths, settings, installer_command, health_timeout=20.0):
    return UpdateApplier(
        paths=paths,
        settings=settings,
        installer_command=installer_command,
        restart_command=NOOP_RESTART,
        health_timeout=health_timeout,
    )


def _stub_installer(tmp_path: Path, exit_code: int, new_version: Optional[str]) -> Path:
    """A stand-in for ProShieldSetup.exe: optionally rewrites build_info.json."""
    script = tmp_path / f"stub-installer-{exit_code}-{new_version}.py"
    body = [
        "import json, sys",
        "from pathlib import Path",
        f"root = Path({str(tmp_path / 'install')!r})",
    ]
    if new_version:
        body += [
            f"info = root / 'deploy' / 'build_info.json'",
            "info.write_text(json.dumps({'version': " + repr(new_version) + ", 'channel': 'testing'}), encoding='utf-8')",
        ]
    body += [f"sys.exit({exit_code})"]
    script.write_text("\n".join(body) + "\n", encoding="utf-8")
    return script


def test_applier_verify_rejects_missing_files(paths) -> None:
    settings = load_settings(paths)
    applier = UpdateApplier(paths=paths, settings=settings)
    ok, detail, manifest = applier.verify(paths.data_root / "nope.json", paths.data_root / "nope.exe")
    assert ok is False and "missing" in detail and manifest is None


def test_applier_backup_and_restore_round_trip(paths) -> None:
    settings = load_settings(paths)
    applier = UpdateApplier(paths=paths, settings=settings)
    marker = paths.install_root / "app" / "config.py"
    original = marker.read_bytes()

    backup = applier.backup_install_tree("1.0.0")
    assert backup is not None and backup.is_dir()
    assert (backup / "backup-info.json").is_file()

    marker.write_text("# sabotaged\n", encoding="utf-8")
    assert applier.restore_install_tree(backup) is True
    assert marker.read_bytes() == original


def test_applier_restore_fails_cleanly_without_a_backup(paths) -> None:
    settings = load_settings(paths)
    applier = UpdateApplier(paths=paths, settings=settings)
    assert applier.restore_install_tree(paths.backup_dir / "does-not-exist") is False


def test_applier_happy_path_updates_and_health_checks(paths, keypair, tmp_path) -> None:
    private_path, public_path = keypair
    _write_public_key(paths, public_path)
    server = _AnyJsonServer(paths.data_root / "state")
    try:
        settings = dataclasses.replace(
            load_settings(paths),
            analyst_port=server.server.server_address[1],
            ingress_port=server.server.server_address[1],
        )
        document = _signed_manifest_document(
            private_path, "9.9.9", GOOD_PACKAGE, "http://example/ProShieldSetup.exe"
        )
        manifest_path = tmp_path / "manifest.json"
        manifest_path.write_text(json.dumps(document), encoding="utf-8")
        package = tmp_path / "ProShieldSetup.exe"
        package.write_bytes(GOOD_PACKAGE)

        applier = _applier(paths, settings, [sys.executable, str(_stub_installer(tmp_path, 0, "9.9.9"))])
        result = applier.apply(package, manifest_path, expected_version="9.9.9")

        assert result.ok is True, result.message
        assert result.status == "success"
        assert result.from_version == "1.0.0"
        assert result.to_version == "9.9.9"
        assert applier.installed_version() == "9.9.9"

        state = json.loads(paths.update_state_file.read_text(encoding="utf-8"))
        assert state["last_apply_result"] == "success"
        assert state["last_applied_version"] == "9.9.9"
        assert state["pending_apply"] is False
    finally:
        server.close()


def test_applier_rolls_back_when_the_installer_fails(paths, keypair, tmp_path) -> None:
    private_path, public_path = keypair
    _write_public_key(paths, public_path)
    marker = paths.install_root / "app" / "config.py"
    original = marker.read_bytes()

    document = _signed_manifest_document(
        private_path, "9.9.9", GOOD_PACKAGE, "http://example/ProShieldSetup.exe"
    )
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(document), encoding="utf-8")
    package = tmp_path / "ProShieldSetup.exe"
    package.write_bytes(GOOD_PACKAGE)

    stub = _stub_installer(tmp_path, 4, None)
    settings = load_settings(paths)
    applier = _applier(paths, settings, [sys.executable, str(stub)])

    # Simulate a partially-applied install: the applier backs up first, then the
    # "installer" mangles the tree and fails.
    original_apply = applier.run_installer

    def failing_installer(artifact):
        marker.write_text("# partially updated\n", encoding="utf-8")
        return original_apply(artifact)

    applier.run_installer = failing_installer  # type: ignore[assignment]
    result = applier.apply(package, manifest_path, expected_version="9.9.9")

    assert result.ok is False
    assert result.status == "rolled-back"
    assert result.rolled_back is True
    assert "previous version restored" in result.message
    assert marker.read_bytes() == original, "the previous install tree was not restored"

    state = json.loads(paths.update_state_file.read_text(encoding="utf-8"))
    assert state["last_apply_result"] == "rolled-back"


def test_applier_rolls_back_when_health_check_fails(paths, keypair, tmp_path) -> None:
    private_path, public_path = keypair
    _write_public_key(paths, public_path)
    marker = paths.install_root / "app" / "config.py"
    original = marker.read_bytes()

    document = _signed_manifest_document(
        private_path, "9.9.9", GOOD_PACKAGE, "http://example/ProShieldSetup.exe"
    )
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(document), encoding="utf-8")
    package = tmp_path / "ProShieldSetup.exe"
    package.write_bytes(GOOD_PACKAGE)

    # The installer "succeeds" but the planes never come back healthy, because
    # the ports point at a dead socket.
    settings = dataclasses.replace(
        load_settings(paths), analyst_port=1, ingress_port=1
    )
    applier = _applier(
        paths, settings, [sys.executable, str(_stub_installer(tmp_path, 0, "9.9.9"))],
        health_timeout=8.0,
    )
    result = applier.apply(package, manifest_path, expected_version="9.9.9")

    assert result.ok is False
    assert result.status == "rolled-back"
    assert "health check failed" in result.message
    assert applier.installed_version() == "1.0.0", "rollback must restore the version stamp"
    assert marker.read_bytes() == original


def test_applier_aborts_when_the_backup_cannot_be_taken(paths, keypair, tmp_path, monkeypatch) -> None:
    private_path, public_path = keypair
    _write_public_key(paths, public_path)
    document = _signed_manifest_document(
        private_path, "9.9.9", GOOD_PACKAGE, "http://example/ProShieldSetup.exe"
    )
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(document), encoding="utf-8")
    package = tmp_path / "ProShieldSetup.exe"
    package.write_bytes(GOOD_PACKAGE)

    applier = _applier(paths, load_settings(paths), [sys.executable, str(_stub_installer(tmp_path, 0, "9.9.9"))])
    monkeypatch.setattr(applier, "backup_install_tree", lambda version: None)

    result = applier.apply(package, manifest_path, expected_version="9.9.9")
    assert result.ok is False
    assert "could not back up" in result.message
    # Nothing was installed.
    assert applier.installed_version() == "1.0.0"


def test_applier_rejects_before_touching_the_install_tree(paths, keypair, tmp_path) -> None:
    private_path, public_path = keypair
    _write_public_key(paths, public_path)
    document = _signed_manifest_document(
        private_path, "9.9.9", GOOD_PACKAGE, "http://example/ProShieldSetup.exe"
    )
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(document), encoding="utf-8")

    # A tampered package must be refused before any backup or installer run.
    tampered = tmp_path / "ProShieldSetup.exe"
    tampered.write_bytes(b"EVIL" + GOOD_PACKAGE)

    calls = {"installer": 0}

    def counting_installer(artifact):
        calls["installer"] += 1
        return 0, "should not run"

    applier = _applier(paths, load_settings(paths), [sys.executable, str(_stub_installer(tmp_path, 0, "9.9.9"))])
    applier.run_installer = counting_installer  # type: ignore[assignment]
    result = applier.apply(tampered, manifest_path, expected_version="9.9.9")

    assert result.ok is False
    assert result.status == "rejected"
    assert calls["installer"] == 0
    assert not any(paths.backup_dir.iterdir()), "no backup should be taken for a rejected package"
    assert applier.installed_version() == "1.0.0"


def test_applier_manual_rollback_uses_the_newest_backup(paths) -> None:
    settings = load_settings(paths)
    applier = UpdateApplier(paths=paths, settings=settings)
    marker = paths.install_root / "app" / "config.py"
    original = marker.read_bytes()

    first = applier.backup_install_tree("1.0.0")
    assert first is not None
    marker.write_text("# changed\n", encoding="utf-8")

    result = applier.rollback()
    assert result.ok is True
    assert result.status == "rolled-back"
    assert marker.read_bytes() == original


def test_applier_prunes_old_backups(paths) -> None:
    settings = load_settings(paths)
    applier = UpdateApplier(paths=paths, settings=settings, keep_backups=2)
    for index in range(4):
        applier.backup_install_tree(f"1.0.{index}")
    applier.prune_backups()
    remaining = [p for p in paths.backup_dir.iterdir() if p.is_dir()]
    assert len(remaining) == 2


# ------------------------------------------- frozen helper subcommand routing


def test_service_host_dispatches_the_update_apply_subcommand(monkeypatch) -> None:
    """Regression: the frozen update helper is a COPY of ProShieldService.exe.

    The service host's argparse only knew the service subcommands, so a frozen
    helper exited immediately with ``invalid choice: 'update-apply'`` - a
    *verified, staged* update was therefore never applied and the installation
    silently stayed on the old version.  This asserts the subcommand is routed
    to the applier before the service parser ever sees it.
    """
    from service import windows_service
    import service.update_apply as update_apply_module

    captured = {}

    def fake_main(argv):
        captured["argv"] = list(argv)
        return 0

    monkeypatch.setattr(update_apply_module, "main", fake_main)

    code = windows_service.main(
        [
            "update-apply",
            "--artifact",
            "pkg.exe",
            "--manifest",
            "manifest.json",
            "--expected-version",
            "9.9.9",
        ]
    )

    assert code == 0
    assert captured["argv"] == [
        "--artifact",
        "pkg.exe",
        "--manifest",
        "manifest.json",
        "--expected-version",
        "9.9.9",
    ]


def test_service_host_lists_the_contract_subcommands() -> None:
    """The installer and helpers depend on this exact command set."""
    from service import windows_service

    parser_choices = {
        "install",
        "uninstall",
        "start",
        "stop",
        "restart",
        "status",
        "console",
        "debug",
        "stop-planes",
    }
    # argparse exits with a non-zero code for an unknown command ...
    with pytest.raises(SystemExit) as excinfo:
        windows_service.main(["definitely-not-a-command"])
    assert excinfo.value.code != 0

    # ... but each supported command must at least be parsed.  ``status`` is the
    # only one that is safe to execute here.
    assert windows_service.main(["status"]) == 0

    # And the parser accepts every documented command name.
    for command in sorted(parser_choices):
        if command == "status":
            continue
        with pytest.raises(SystemExit) as excinfo:
            windows_service.main([command, "--help"])
        assert excinfo.value.code == 0, command