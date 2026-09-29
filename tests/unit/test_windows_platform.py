"""Unit tests for the ProShield Windows platform layer.

Zero infrastructure: no MongoDB, no SCM, no network beyond loopback.
These cover the deployment/productization code only - the security
implementation keeps its own existing test suite untouched.
"""
from __future__ import annotations

import json
import socket
import threading
from pathlib import Path

import pytest

from service import probes
from service.logging_setup import configure_logging
from service.paths import is_installed, resolve_paths, runtime_python
from service.settings import (
    ENV_AUTH_SIGNING_KEY,
    ENV_SOURCE_SIGNING_KEY,
    ENV_SUBJECT_CREDENTIALS,
    SEED_SUBJECTS,
    bootstrap_secrets,
    ensure_bootstrap,
    load_secrets,
    load_settings,
    write_default_settings,
)
from service.supervisor import ChildProcess, ChildSpec, _RotatingSink, default_child_specs
from service.version import is_newer, load_version_info, parse_version


def _paths(tmp_path: Path):
    return resolve_paths(install=tmp_path / "install", data=tmp_path / "data")


# ---------------------------------------------------------------------- paths


def test_resolve_paths_uses_explicit_roots(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    assert paths.install_root == (tmp_path / "install").resolve()
    assert paths.data_root == (tmp_path / "data").resolve()
    assert paths.app_dir == paths.install_root / "app"
    assert paths.frontend_ui == paths.install_root / "frontend" / "soc" / "index.html"
    assert paths.service_exe.name == "ProShieldService.exe"
    assert paths.desktop_exe.name == "ProShield.exe"


def test_ensure_layout_creates_only_data_directories(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    paths.ensure_layout()
    for directory in (
        paths.config_dir,
        paths.secrets_dir,
        paths.logs_dir,
        paths.state_dir,
        paths.updates_dir,
        paths.backup_dir,
    ):
        assert directory.is_dir(), directory
    # The install tree must never be created as a side effect.
    assert not paths.install_root.exists()


def test_secrets_are_not_inside_the_readable_config_dir(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    assert paths.secrets_file.parent == paths.secrets_dir
    assert paths.secrets_dir != paths.config_dir
    assert paths.settings_file.parent == paths.config_dir


def test_install_tree_and_data_root_are_separate(tmp_path: Path) -> None:
    """An upgrade replaces the install tree; runtime data must live outside it."""
    paths = _paths(tmp_path)
    assert paths.data_root not in paths.install_root.parents
    assert paths.install_root not in paths.data_root.parents


def test_runtime_python_falls_back_to_current_interpreter(tmp_path: Path) -> None:
    import sys

    assert runtime_python(tmp_path / "install") == Path(sys.executable).resolve()


def test_runtime_python_prefers_bundled_runtime(tmp_path: Path) -> None:
    install = tmp_path / "install"
    bundled = install / "runtime" / "python.exe"
    bundled.parent.mkdir(parents=True)
    bundled.write_bytes(b"MZ")
    assert runtime_python(install) == bundled


def test_is_installed_is_false_in_development() -> None:
    assert is_installed() is False


# -------------------------------------------------------------------- version


@pytest.mark.parametrize(
    "text,expected",
    [
        ("1.0.0", (1, 0, 0)),
        ("0.1.1", (0, 1, 1)),
        ("1.2.3-rc1", (1, 2, 3)),
        ("2.0", (2, 0, 0)),
        ("", (0, 0, 0)),
        ("garbage", (0, 0, 0)),
    ],
)
def test_parse_version(text: str, expected: tuple) -> None:
    assert parse_version(text) == expected


@pytest.mark.parametrize(
    "candidate,current,newer",
    [
        ("1.0.1", "1.0.0", True),
        ("1.0.0", "1.0.0", False),
        ("0.9.9", "1.0.0", False),
        ("1.1.0", "1.0.9", True),
        ("2.0.0", "1.99.99", True),
    ],
)
def test_is_newer(candidate: str, current: str, newer: bool) -> None:
    assert is_newer(candidate, current) is newer


def test_version_info_reads_the_repository_version_file() -> None:
    info = load_version_info()
    assert info.version != "0.0.0"
    assert info.source in ("repository", "install", "fallback")
    assert info.display_version.startswith(info.version)
    assert info.setup_filename == f"ProShieldSetup-v{info.version}.exe"
    payload = info.as_dict()
    assert payload["version"] == info.version
    assert "build_id" in payload and "git_commit" in payload


def test_version_info_reads_build_info_from_the_install_deploy_dir(tmp_path: Path) -> None:
    """Regression: the installed version stamp lives in <install>/deploy/.

    A stale 'packaging' path here makes an installed ProShield report 0.0.0
    (fallback) instead of its real version, which would also break
    update version comparison.
    """
    install = tmp_path / "install"
    (install / "deploy").mkdir(parents=True)
    (install / "deploy" / "build_info.json").write_text(
        json.dumps(
            {
                "version": "7.7.7",
                "channel": "testing",
                "product_name": "ProShield",
                "build_id": "7.7.7+20260101000000",
                "git_commit": "deadbeef",
            }
        ),
        encoding="utf-8",
    )
    info = load_version_info(install)
    assert info.version == "7.7.7"
    assert info.source == "install"
    assert info.build_id == "7.7.7+20260101000000"
    assert info.git_commit == "deadbeef"
    assert info.display_version == "7.7.7-testing"


def test_paths_resolve_the_install_deploy_dir(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    assert paths.deploy_dir == paths.install_root / "deploy"
    assert paths.build_info_file == paths.install_root / "deploy" / "build_info.json"
    assert paths.update_public_key_file == (
        paths.install_root / "deploy" / "proshield-update.pub.pem"
    )


# ------------------------------------------------------------------- settings


def test_bootstrap_secrets_creates_signing_keys_and_credentials(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    secrets = bootstrap_secrets(paths)
    assert secrets[ENV_AUTH_SIGNING_KEY]
    assert secrets[ENV_SOURCE_SIGNING_KEY]
    assert secrets[ENV_AUTH_SIGNING_KEY] != secrets[ENV_SOURCE_SIGNING_KEY]
    credentials = dict(
        pair.split(":", 1) for pair in secrets[ENV_SUBJECT_CREDENTIALS].split(",")
    )
    assert set(credentials) == set(SEED_SUBJECTS)
    assert all(len(value) >= 12 for value in credentials.values())
    assert paths.initial_credentials_file.is_file()


def test_bootstrap_secrets_never_rotates_existing_keys(tmp_path: Path) -> None:
    """A restart or an upgrade must not invalidate live sessions/tokens."""
    paths = _paths(tmp_path)
    first = bootstrap_secrets(paths)
    second = bootstrap_secrets(paths)
    assert first == second
    third = bootstrap_secrets(paths)
    assert third[ENV_AUTH_SIGNING_KEY] == first[ENV_AUTH_SIGNING_KEY]


def test_load_settings_include_secrets_false_hides_secrets(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    bootstrap_secrets(paths)
    with_secrets = load_settings(paths)
    assert with_secrets.auth_signing_key
    assert with_secrets.subject_credentials()

    # The desktop shell uses this form: it must never hold the keys.
    without = load_settings(paths, include_secrets=False)
    assert without.secrets == {}
    assert without.auth_signing_key == ""
    assert without.source_signing_key == ""
    assert without.subject_credentials() == {}


def test_load_secrets_supports_the_legacy_config_location(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    paths.ensure_layout()
    legacy = paths.legacy_secrets_file
    legacy.write_text(f"{ENV_AUTH_SIGNING_KEY}=legacy-key\n", encoding="utf-8")
    assert load_secrets(paths)[ENV_AUTH_SIGNING_KEY] == "legacy-key"

    # The new location wins once it exists.
    paths.secrets_file.write_text(f"{ENV_AUTH_SIGNING_KEY}=new-key\n", encoding="utf-8")
    assert load_secrets(paths)[ENV_AUTH_SIGNING_KEY] == "new-key"


def test_child_env_carries_plane_configuration_and_secrets(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    bootstrap_secrets(paths)
    settings = load_settings(paths)

    env = settings.to_child_env()
    assert env["PROSHIELD_MONGO_URI"] == settings.mongo_uri
    assert env["PROSHIELD_MONGO_DB"] == settings.mongo_db
    assert env["PROSHIELD_INGRESS_BACKEND"] == "mongo"
    assert env["PROSHIELD_INGRESS_REPLAY_STORE_REQUIRED"] == "1"
    assert env[ENV_AUTH_SIGNING_KEY] == settings.auth_signing_key
    assert env[ENV_SOURCE_SIGNING_KEY] == settings.source_signing_key
    assert ENV_SUBJECT_CREDENTIALS in env


def test_settings_json_never_contains_secrets(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    settings, paths = ensure_bootstrap(paths)
    write_default_settings(paths, settings)
    blob = paths.settings_file.read_text(encoding="utf-8")
    assert settings.auth_signing_key not in blob
    assert settings.source_signing_key not in blob

    summary = json.dumps(settings.as_dict())
    assert settings.auth_signing_key not in summary
    assert settings.source_signing_key not in summary
    assert "PROSHIELD_DEFAULT_SUBJECT_CREDENTIALS" in summary  # names only


def test_settings_file_survives_and_is_reused(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    settings, paths = ensure_bootstrap(paths)
    paths.settings_file.write_text(
        json.dumps({"analyst_port": 18088, "update_mode": "notify-only"}),
        encoding="utf-8",
    )
    reloaded = load_settings(paths)
    assert reloaded.analyst_port == 18088
    assert reloaded.update_mode == "notify-only"


def test_unknown_update_mode_degrades_to_notify_only(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    paths.ensure_layout()
    paths.settings_file.write_text(json.dumps({"update_mode": "yolo"}), encoding="utf-8")
    assert load_settings(paths).update_mode == "notify-only"


def test_ports_and_endpoints_derive_consistent_urls(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    settings = load_settings(paths)
    assert settings.analyst_base_url == f"http://127.0.0.1:{settings.analyst_port}"
    assert settings.ingress_base_url == f"http://127.0.0.1:{settings.ingress_port}"
    # The GUI origin is the analyst plane: same-origin with /api/proxy.
    assert settings.ui_url == (
        f"http://127.0.0.1:{settings.analyst_port}/static/soc/index.html"
    )


# --------------------------------------------------------------------- probes


@pytest.mark.parametrize(
    "uri,host,port",
    [
        ("mongodb://127.0.0.1:27017", "127.0.0.1", 27017),
        ("mongodb://localhost", "localhost", 27017),
        ("mongodb://user:pw@10.0.0.5:27018/proshield", "10.0.0.5", 27018),
        ("mongodb://host1:27017,host2:27017/db", "host1", 27017),
        ("", "127.0.0.1", 27017),
    ],
)
def test_split_mongo_uri(uri: str, host: str, port: int) -> None:
    assert probes.split_mongo_uri(uri) == (host, port)


def test_mongo_ready_reports_failure_on_a_dead_port() -> None:
    result = probes.mongo_ready("mongodb://127.0.0.1:1", timeout_ms=300)
    assert result.ok is False


def test_tcp_reachable_detects_a_listening_socket() -> None:
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]
    try:
        assert probes.tcp_reachable("127.0.0.1", port) is True
    finally:
        server.close()
    assert probes.tcp_reachable("127.0.0.1", port, timeout=0.2) is False


def test_http_probe_reports_failure_for_a_dead_port() -> None:
    result = probes.http_probe("http://127.0.0.1:1/health", timeout=1.0)
    assert result.ok is False


def test_http_probe_parses_json_from_a_loopback_server() -> None:
    from http.server import BaseHTTPRequestHandler, HTTPServer

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            body = json.dumps({"status": "ok"}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):  # noqa: D102
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = server.server_address[1]
        result = probes.http_probe(f"http://127.0.0.1:{port}/health")
        assert result.ok is True
        assert result.payload == {"status": "ok"}
    finally:
        server.shutdown()
        server.server_close()


# ----------------------------------------------------------------- supervisor


def test_default_child_specs_match_the_documented_topology(tmp_path) -> None:
    """The default topology must not depend on the machine it runs on.

    This used to call ``resolve_paths()`` with no arguments, which resolves the
    **real machine-wide** data root.  ``load_settings`` then read
    ``C:\\ProgramData\\ProShield\\secrets\\proshield.env``, which the installer
    ACLs to Administrators + SYSTEM - so a non-elevated ``pytest`` died with
    ``PermissionError: [WinError 5]``.  A unit test must never read a live
    installation.
    """
    paths = resolve_paths(install=tmp_path / "install", data=tmp_path / "data")
    settings = load_settings(paths)
    specs = default_child_specs(settings)
    assert [spec.name for spec in specs] == ["analyst", "ingress"]
    assert specs[0].module == "scripts.proxy_server"
    assert specs[0].port == settings.analyst_port
    assert specs[0].health_path == "/health"
    assert specs[1].module == "scripts.ingress_server"
    assert specs[1].port == settings.ingress_port
    assert specs[1].health_path == "/api/ingress/health"


def test_child_process_status_dict_shape() -> None:
    spec = ChildSpec(
        name="analyst",
        module="scripts.proxy_server",
        port=8088,
        health_path="/health",
        display_name="Analyst",
    )
    child = ChildProcess(spec=spec)
    payload = child.as_dict()
    assert payload["name"] == "analyst"
    assert payload["running"] is False
    assert payload["healthy"] is False
    assert payload["restarts"] == 0
    assert payload["pid"] is None


def test_rotating_sink_rotates_and_keeps_history(tmp_path: Path) -> None:
    path = tmp_path / "analyst.log"
    sink = _RotatingSink(path, max_bytes=64 * 1024, keep=3)
    line = "x" * 1023
    for _ in range(80):
        sink.write(line)
    sink.close()
    assert path.is_file()
    rotated = path.with_suffix(path.suffix + ".1")
    assert rotated.is_file(), "expected the sink to rotate at the size limit"


def test_logging_setup_is_idempotent(tmp_path: Path) -> None:
    import logging

    configure_logging(tmp_path / "logs", "INFO", "service.log")
    first = [
        handler
        for handler in logging.getLogger().handlers
        if getattr(handler, "_proshield", False)
    ]
    configure_logging(tmp_path / "logs", "INFO", "service.log")
    second = [
        handler
        for handler in logging.getLogger().handlers
        if getattr(handler, "_proshield", False)
    ]
    assert len(first) == len(second) == 1
    assert (tmp_path / "logs" / "service.log").is_file()
