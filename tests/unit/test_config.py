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
    monkeypatch.setenv("PROSHIELD_ENV", "production")
    monkeypatch.setenv("PROSHIELD_MONGO_DB", "proshield_prod")
    monkeypatch.setenv("PROSHIELD_INGEST_MAX_BODY_BYTES", "8192")
    cfg = ProShieldConfig.from_env()
    assert cfg.env_name == "production"
    assert cfg.mongo_db == "proshield_prod"
    assert cfg.ingest_max_body_bytes == 8192


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
