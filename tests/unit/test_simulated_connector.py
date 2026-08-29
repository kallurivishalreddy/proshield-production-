"""Unit tests for the simulated source connector.

The simulator is the first MVP validation source
(docs/PHASE 0/INITIAL_SECURITY_EVENTS.md).  It must:

* yield events that already conform to the canonical SecurityEvent,
* never bypass validation, normalization, persistence,
* preserve provenance (collector + source_event_id).
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError as PydanticValidationError

from app.connectors.simulated import SimulatedConnector
from app.domain.security_event import (
    SecurityEvent,
    SecurityEventProvenance,
)


def test_connector_declares_canonical_source() -> None:
    assert SimulatedConnector.source == "simulator"


def test_collect_yields_only_canonical_events() -> None:
    events = list(SimulatedConnector().collect())
    assert len(events) == 5  # 1 + 4
    for e in events:
        assert isinstance(e, SecurityEvent)
        assert e.source == "simulator"
        assert e.event_id  # UUIDv7 string
        assert e.provenance.collector == "simulated"
        assert e.provenance.source_event_id


def test_health_does_not_leak_secrets() -> None:
    h = SimulatedConnector().health()
    assert h["status"] == "ok"
    # No paths, no env values, no event payloads.
    forbidden_substrings = (
        "password", "secret", "token", "mongodb://",
    )
    for v in h.values():
        if isinstance(v, str):
            for needle in forbidden_substrings:
                assert needle not in v.lower()


def test_safe_str_truncates_to_max_length() -> None:
    c = SimulatedConnector()
    out = c.safe_str("x" * 1000, max_length=10)
    assert out == "x" * 10


def test_safe_str_preserves_none() -> None:
    assert SimulatedConnector.safe_str(None) is None


def test_collected_events_use_only_allowed_event_types() -> None:
    events = list(SimulatedConnector().collect())
    allowed = {
        "waf_attack_detected",
        "request_blocked",
        "rate_limit_exceeded",
        "suspicious_request",
        "authentication_failure",
        "authentication_success",
        "tls_anomaly",
        "network_anomaly",
        "security_control_alert",
    }
    for e in events:
        assert e.event_type in allowed
