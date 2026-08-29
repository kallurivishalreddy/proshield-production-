"""Unit tests for the canonical SecurityEvent model.

Reference: docs/PHASE 2/SECURITY_EVENT_SCHEMA.md.
"""
from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

import pytest
from pydantic import ValidationError as PydanticValidationError

from app.domain.errors import ValidationError as DomainValidationError
from app.domain.security_event import (
    ALLOWED_EVENT_TYPES,
    ALLOWED_SOURCES,
    MAX_BODY_BYTES_DEFAULT,
    SecurityEvent,
    SecurityEventAccount,
    SecurityEventDevice,
    SecurityEventProvenance,
    to_canonical_dict,
    validate_size_constraints,
)
from app.domain.uuid7 import uuid7


def _make_event(**overrides) -> SecurityEvent:
    eid = overrides.pop("event_id", str(uuid7()))
    et = overrides.pop("event_time", datetime(2026, 1, 1, tzinfo=timezone.utc))
    base = SecurityEvent(
        event_id=eid,
        event_time=et,
        ingested_at=et,
        source="simulator",
        event_type="request_blocked",
        source_ip="203.0.113.10",
        destination="app.example.internal",
        endpoint="/api/login",
        asset="web-api-01",
        account=SecurityEventAccount(id="user-123"),
        device=SecurityEventDevice(id="device-1"),
        details={"http_method": "POST", "status_code": 403},
        provenance=SecurityEventProvenance(
            collector="simulated", source_event_id="test-1"
        ),
    )
    if overrides:
        return base.model_copy(update=overrides)
    return base


# ---------------------------------------------------------------------------
# Required fields and basic construction
# ---------------------------------------------------------------------------
def test_canonical_event_constructs_with_minimum_fields() -> None:
    et = datetime(2026, 1, 1, tzinfo=timezone.utc)
    e = SecurityEvent(
        event_id=str(uuid7()),
        event_time=et,
        ingested_at=et,
        source="simulator",
        event_type="request_blocked",
        provenance=SecurityEventProvenance(
            collector="simulated", source_event_id="x"
        ),
    )
    assert e.source == "simulator"
    assert e.event_type == "request_blocked"


def test_missing_required_field_raises() -> None:
    et = datetime(2026, 1, 1, tzinfo=timezone.utc)
    with pytest.raises(PydanticValidationError):
        SecurityEvent(
            event_time=et,
            ingested_at=et,
            source="simulator",
            event_type="request_blocked",
            provenance=SecurityEventProvenance(
                collector="simulated", source_event_id="x"
            ),
        )


def test_extra_field_is_rejected() -> None:
    et = datetime(2026, 1, 1, tzinfo=timezone.utc)
    with pytest.raises(PydanticValidationError):
        SecurityEvent(
            event_id=str(uuid7()),
            event_time=et,
            ingested_at=et,
            source="simulator",
            event_type="request_blocked",
            provenance=SecurityEventProvenance(
                collector="simulated", source_event_id="x"
            ),
            unknown_field="boom",  # type: ignore[call-arg]
        )


# ---------------------------------------------------------------------------
# Timestamps
# ---------------------------------------------------------------------------
def test_naive_timestamp_is_rejected() -> None:
    with pytest.raises(PydanticValidationError):
        _make_event(event_time=datetime(2026, 1, 1))  # no tzinfo


def test_ingested_at_60s_before_event_time_is_rejected() -> None:
    from datetime import timedelta
    et = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    with pytest.raises(PydanticValidationError):
        SecurityEvent(
            event_id=str(uuid7()),
            event_time=et,
            ingested_at=et - timedelta(minutes=5),
            source="simulator",
            event_type="request_blocked",
            provenance=SecurityEventProvenance(
                collector="simulated", source_event_id="x"
            ),
        )


def test_ingested_at_close_after_event_time_is_accepted() -> None:
    et = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    e = _make_event(event_time=et, ingested_at=et.replace(second=1))
    assert e.ingested_at.second == 1


# ---------------------------------------------------------------------------
# Catalogues
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("source", sorted(ALLOWED_SOURCES))
def test_each_allowed_source_is_accepted(source: str) -> None:
    e = _make_event(source=source)
    assert e.source == source


@pytest.mark.parametrize("event_type", sorted(ALLOWED_EVENT_TYPES))
def test_each_allowed_event_type_is_accepted(event_type: str) -> None:
    e = _make_event(event_type=event_type)
    assert e.event_type == event_type


def test_unknown_source_is_rejected() -> None:
    et = datetime(2026, 1, 1, tzinfo=timezone.utc)
    with pytest.raises(PydanticValidationError):
        SecurityEvent(
            event_id=str(uuid7()),
            event_time=et,
            ingested_at=et,
            source="acme-proprietary",
            event_type="request_blocked",
            provenance=SecurityEventProvenance(
                collector="simulated", source_event_id="x"
            ),
        )


def test_unknown_event_type_is_rejected() -> None:
    et = datetime(2026, 1, 1, tzinfo=timezone.utc)
    with pytest.raises(PydanticValidationError):
        SecurityEvent(
            event_id=str(uuid7()),
            event_time=et,
            ingested_at=et,
            source="simulator",
            event_type="rocket_launch",
            provenance=SecurityEventProvenance(
                collector="simulated", source_event_id="x"
            ),
        )


# ---------------------------------------------------------------------------
# event_id: UUIDv7
# ---------------------------------------------------------------------------
def test_event_id_must_be_uuid7() -> None:
    with pytest.raises(PydanticValidationError):
        _make_event(event_id=str(UUID(int=42)))  # not UUIDv7


def test_event_id_must_be_uuid_string() -> None:
    with pytest.raises(PydanticValidationError):
        _make_event(event_id="not-a-uuid")


# ---------------------------------------------------------------------------
# Sensitive-data rejection (schema Section 20)
# ---------------------------------------------------------------------------
def test_sensitive_key_in_details_is_rejected() -> None:
    et = datetime(2026, 1, 1, tzinfo=timezone.utc)
    with pytest.raises(PydanticValidationError):
        SecurityEvent(
            event_id=str(uuid7()),
            event_time=et,
            ingested_at=et,
            source="simulator",
            event_type="request_blocked",
            provenance=SecurityEventProvenance(
                collector="simulated", source_event_id="x"
            ),
            details={"password": "hunter2"},
        )


def test_sensitive_substring_in_details_key_is_rejected() -> None:
    et = datetime(2026, 1, 1, tzinfo=timezone.utc)
    with pytest.raises(PydanticValidationError):
        SecurityEvent(
            event_id=str(uuid7()),
            event_time=et,
            ingested_at=et,
            source="simulator",
            event_type="request_blocked",
            provenance=SecurityEventProvenance(
                collector="simulated", source_event_id="x"
            ),
            details={"auth_token": "abc"},
        )


def test_sensitive_value_in_account_id_is_rejected() -> None:
    et = datetime(2026, 1, 1, tzinfo=timezone.utc)
    with pytest.raises(PydanticValidationError):
        SecurityEvent(
            event_id=str(uuid7()),
            event_time=et,
            ingested_at=et,
            source="simulator",
            event_type="request_blocked",
            provenance=SecurityEventProvenance(
                collector="simulated", source_event_id="x"
            ),
            account=SecurityEventAccount(id="user-with-bearer-in-it"),
        )


def test_sensitive_value_in_nested_details_is_rejected() -> None:
    et = datetime(2026, 1, 1, tzinfo=timezone.utc)
    with pytest.raises(PydanticValidationError):
        SecurityEvent(
            event_id=str(uuid7()),
            event_time=et,
            ingested_at=et,
            source="simulator",
            event_type="request_blocked",
            provenance=SecurityEventProvenance(
                collector="simulated", source_event_id="x"
            ),
            details={"outer": {"session_cookie": "abc"}},
        )


# ---------------------------------------------------------------------------
# IP / size / canonicalisation
# ---------------------------------------------------------------------------
def test_invalid_source_ip_is_rejected() -> None:
    et = datetime(2026, 1, 1, tzinfo=timezone.utc)
    with pytest.raises(PydanticValidationError):
        SecurityEvent(
            event_id=str(uuid7()),
            event_time=et,
            ingested_at=et,
            source="simulator",
            event_type="request_blocked",
            provenance=SecurityEventProvenance(
                collector="simulated", source_event_id="x"
            ),
            source_ip="not-an-ip",
        )


def test_valid_ipv6_source_ip_is_accepted() -> None:
    et = datetime(2026, 1, 1, tzinfo=timezone.utc)
    e = SecurityEvent(
        event_id=str(uuid7()),
        event_time=et,
        ingested_at=et,
        source="simulator",
        event_type="request_blocked",
        provenance=SecurityEventProvenance(
            collector="simulated", source_event_id="x"
        ),
        source_ip="2001:db8::1",
    )
    assert e.source_ip == "2001:db8::1"


def test_size_validator_rejects_oversized_body() -> None:
    e = _make_event()
    payload = to_canonical_dict(e)
    payload["details"] = {"x": "y" * (MAX_BODY_BYTES_DEFAULT + 100)}
    with pytest.raises(DomainValidationError):
        validate_size_constraints(payload)


def test_size_validator_rejects_oversized_details() -> None:
    e = _make_event()
    payload = to_canonical_dict(e)
    payload["details"] = {"x": "y" * 10_000}
    with pytest.raises(DomainValidationError):
        validate_size_constraints(payload, max_details_bytes=1024)


def test_canonical_dict_contains_only_canonical_fields() -> None:
    e = _make_event()
    d = to_canonical_dict(e)
    assert "_id" not in d
    assert set(d.keys()) >= {
        "event_id",
        "event_time",
        "ingested_at",
        "source",
        "event_type",
        "provenance",
        "source_ip",
        "destination",
        "endpoint",
        "asset",
        "account",
        "device",
        "details",
        "schema_version",
    }

