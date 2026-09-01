"""Unit tests for runtime configuration loading.

Reference: docs/PHASE 3/SECURITY_CONFIGURATION.md.
"""
from __future__ import annotations

import os

import pytest

from app.config import ProShieldConfig


def test_from_env_uses_defaults_when_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in (
        "PROSHIELD_ENV",
        "PROSHIELD_LOG_LEVEL",
        "PROSHIELD_MONGO_URI",
        "PROSHIELD_MONGO_DB",
        "PROSHIELD_MONGO_COLLECTION_EVENTS",
        "PROSHIELD_INGEST_MAX_BODY_BYTES",
        "PROSHIELD_INGEST_MAX_DETAILS_BYTES",
        "PROSHIELD_INGEST_RATE_LIMIT_PER_MINUTE",
        "PROSHIELD_CONNECTORS",
    ):
        monkeypatch.delenv(var, raising=False)
    cfg = ProShieldConfig.from_env()
    assert cfg.env_name == "development"
    assert cfg.mongo_uri == "mongodb://127.0.0.1:27017"
    assert cfg.mongo_db == "proshield"
    assert cfg.ingest_max_body_bytes == 16_384


def test_from_env_reads_overrides(monkeypatch: pytest.MonkeyPatch) -> None:
    # ST-03 hardening: a production-like ``env_name``
    # (``production`` / ``staging`` / ``preview`` / ``prod``)
    # requires both signing keys to be present (fail-fast).
    monkeypatch.setenv("PROSHIELD_ENV", "production")
    monkeypatch.setenv("PROSHIELD_AUTH_SIGNING_KEY", "test-auth-key-123")
    monkeypatch.setenv("PROSHIELD_SOURCE_SIGNING_KEY", "test-source-key-456")
    monkeypatch.setenv("PROSHIELD_MONGO_DB", "proshield_prod")
    monkeypatch.setenv("PROSHIELD_INGEST_MAX_BODY_BYTES", "8192")
    cfg = ProShieldConfig.from_env()
    assert cfg.env_name == "production"
    assert cfg.mongo_db == "proshield_prod"
    assert cfg.ingest_max_body_bytes == 8192
    assert bool(cfg.auth_signing_key) is True
    assert bool(cfg.source_signing_key) is True


def test_production_env_rejects_empty_keys(monkeypatch: pytest.MonkeyPatch) -> None:
    """ST-03 / ST-02 startup hardening: a production-like
    ``env_name`` with an empty signing key MUST fail at
    construction time so misconfigured production startups
    cannot accidentally boot with an empty key.
    """
    monkeypatch.setenv("PROSHIELD_ENV", "production")
    monkeypatch.setenv("PROSHIELD_AUTH_SIGNING_KEY", "")
    monkeypatch.setenv("PROSHIELD_SOURCE_SIGNING_KEY", "")
    with pytest.raises(ValueError):
        ProShieldConfig.from_env()


def test_development_env_allows_empty_keys() -> None:
    """``development`` / ``test`` env-names keep the
    empty-key fallback so tests and demo scripts can
    construct an isolated config without a real key.
    """
    cfg = ProShieldConfig(env_name="development")
    assert cfg.auth_signing_key == ""
    assert cfg.source_signing_key == ""


def test_ingress_replay_store_required_enforced() -> None:
    """ST-02: ``ingress_replay_store_required`` defaults to True."""
    cfg = ProShieldConfig(env_name="development")
    assert cfg.ingress_replay_store_required is True


def test_credentials_parsed() -> None:
    cfg = ProShieldConfig(
        env_name="development",
        default_subject_credentials={
            "user-analyst-001": "pw-a",
            "user-admin-001": "pw-b",
        },
    )
    assert cfg.default_subject_credentials["user-admin-001"] == "pw-b"


def test_invalid_int_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PROSHIELD_INGEST_MAX_BODY_BYTES", "not-an-int")
    with pytest.raises(ValueError):
        ProShieldConfig.from_env()


def test_safe_summary_strips_credentials() -> None:
    cfg = ProShieldConfig(mongo_uri="mongodb://user:pass@host:27017/db")
    s = cfg.safe_summary()
    # Credentials must be redacted.
    assert "user:pass" not in s["mongo_uri"]
    assert "***" in s["mongo_uri"]


def test_safe_summary_includes_no_secrets() -> None:
    cfg = ProShieldConfig()
    s = cfg.safe_summary()
    for needle in ("JWT_SECRET", "password", "secret"):
        for v in s.values():
            if isinstance(v, str):
                assert needle.lower() not in v.lower()
