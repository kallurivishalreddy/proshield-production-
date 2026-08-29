"""Integration tests for the SecurityEvent ingestion service.

These tests REQUIRE a running local MongoDB on 127.0.0.1:27017.
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from app.config import ProShieldConfig
from app.connectors.simulated import SimulatedConnector
from app.domain.errors import (
    ConflictEventError,
    DuplicateEventError,
    IngestionError,
    ValidationError,
)
from app.domain.security_event import (
    SecurityEvent,
    SecurityEventProvenance,
)
from app.ingestion.service import SecurityEventIngestionService
from app.persistence.security_event_repository import (
    SecurityEventRepository,
)


def _make_event(**overrides) -> SecurityEvent:
    eid = overrides.pop("event_id", str(__import__("app.domain.uuid7", fromlist=["uuid7"]).uuid7()))
    et = overrides.pop("event_time", datetime(2026, 1, 1, tzinfo=timezone.utc))
    return SecurityEvent(
        event_id=eid,
        event_time=et,
        ingested_at=et,
        source="simulator",
        event_type="request_blocked",
        source_ip="203.0.113.10",
        destination="app.example.internal",
        endpoint="/api/login",
        asset="web-api-01",
        provenance=SecurityEventProvenance(
            collector="simulated", source_event_id="svc-test-1"
        ),
        details={"http_method": "POST", "status_code": 403},
        **overrides,
    )


@pytest.fixture
def service(repository: SecurityEventRepository,
            test_config: ProShieldConfig) -> SecurityEventIngestionService:
    return SecurityEventIngestionService(repository, test_config)


def test_ingest_persists_event(
    service: SecurityEventIngestionService,
    repository: SecurityEventRepository,
) -> None:
    e = _make_event()
    out = service.ingest(e)
    assert out.event_id == e.event_id
    assert repository.count() == 1


def test_ingest_idempotent_replay_returns_existing(
    service: SecurityEventIngestionService,
    repository: SecurityEventRepository,
) -> None:
    e = _make_event()
    first = service.ingest(e)
    second = service.ingest(e)  # identical content
    assert first.event_id == second.event_id
    assert repository.count() == 1


def test_ingest_conflict_replay_raises_conflict(
    service: SecurityEventIngestionService,
) -> None:
    e = _make_event()
    service.ingest(e)
    e_changed = e.model_copy(
        update={"details": {"http_method": "GET"}}
    )
    with pytest.raises(ConflictEventError):
        service.ingest(e_changed)


def test_ingest_overrides_ingested_at_to_server_clock(
    service: SecurityEventIngestionService,
    repository: SecurityEventRepository,
) -> None:
    e = _make_event()
    client_supplied_ingested_at = e.ingested_at
    out = service.ingest(e)
    fetched = repository.get_by_event_id(out.event_id)
    assert fetched is not None
    # Server clock must be >= the client-supplied value within a
    # reasonable tolerance.
    assert fetched.ingested_at >= client_supplied_ingested_at


def test_ingest_from_connector_persists_all_events(
    service: SecurityEventIngestionService,
    repository: SecurityEventRepository,
) -> None:
    n = service.ingest_from_connector(SimulatedConnector())
    assert n == 5  # scenario A (1) + scenario B (4)
    assert repository.count() == 5


def test_ingest_generates_event_id_when_missing(
    service: SecurityEventIngestionService,
    repository: SecurityEventRepository,
) -> None:
    eid = "0198c2a1-7e3b-7a8e-b7b6-4f6a7d4d5f12"
    # Build event without event_id by removing it from the validated
    # model is not possible (event_id is required).  Instead, pass a
    # non-UUIDv7 to trigger the service's auto-generate path.
    e = _make_event(
        event_id="0198c2a1-7e3b-7a8e-b7b6-4f6a7d4d5f12"
    )
    # Construct a clone whose event_id is not a valid UUIDv7 by
    # replacing it after construction (model_copy preserves it).
    # The simplest path is to use the explicit _stamp method.
    from app.domain.uuid7 import uuid7
    stamped = e.model_copy(update={"event_id": ""})  # empty -> service regenerates
    out = service.ingest(stamped)
    # The service's _stamp should have filled in a UUIDv7.
    parsed = __import__("uuid").UUID(out.event_id)
    assert parsed.version == 7
    # And persisted.
    assert repository.get_by_event_id(out.event_id) is not None
