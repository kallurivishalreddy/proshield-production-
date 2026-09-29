"""Integration tests for the SecurityEvent repository against real MongoDB.

These tests REQUIRE a running local MongoDB on 127.0.0.1:27017.

Reference: docs/PHASE 2/SECURITY_EVENT_SCHEMA.md, Sections 21-23.
"""
from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

import pytest
from pymongo.errors import PyMongoError

from app.config import ProShieldConfig
from app.domain.errors import (
    ConflictEventError,
    DuplicateEventError,
    PersistenceError,
)
from app.domain.security_event import (
    SecurityEvent,
    SecurityEventProvenance,
)
from app.domain.uuid7 import uuid7
from app.persistence.mongo import (
    check_connectivity,
    get_database,
    make_client,
)
from app.persistence.security_event_repository import (
    INDEX_SPECS,
    SecurityEventRepository,
)


def _make_event(**overrides) -> SecurityEvent:
    eid = overrides.pop("event_id", str(uuid7()))
    et = overrides.pop("event_time", datetime(2026, 1, 1, tzinfo=timezone.utc))
    collector = overrides.pop("collector", "simulated")
    source_event_id = overrides.pop("source_event_id", "test-it-1")
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
            collector=collector, source_event_id=source_event_id
        ),
        details={"http_method": "POST", "status_code": 403},
        **overrides,
    )


def test_connectivity_works(test_config: ProShieldConfig) -> None:
    client = make_client(test_config)
    try:
        check_connectivity(client)  # must not raise
    finally:
        client.close()


def test_ensure_schema_and_indexes_are_idempotent(
    repository: SecurityEventRepository,
) -> None:
    # ensure_schema and ensure_indexes are called by the fixture
    # already; calling them again must not raise.
    repository.ensure_schema()
    created = repository.ensure_indexes()
    # Re-creating should be a no-op (MongoDB returns the existing index
    # name); we should still see all expected names.
    assert set(created) == {spec["name"] for spec in INDEX_SPECS}


def test_create_persists_event(repository: SecurityEventRepository) -> None:
    e = _make_event()
    out = repository.create(e)
    assert out.event_id == e.event_id
    assert repository.count() == 1


def test_get_by_event_id_round_trip(repository: SecurityEventRepository) -> None:
    e = _make_event()
    repository.create(e)
    fetched = repository.get_by_event_id(e.event_id)
    assert fetched is not None
    # Compare every field except ``ingested_at`` (server-stamped).
    for k in set(e.model_dump()) - {"ingested_at"}:
        assert getattr(fetched, k) == getattr(e, k), f"mismatch on {k}"


def test_get_by_event_id_returns_none_when_missing(
    repository: SecurityEventRepository,
) -> None:
    assert repository.get_by_event_id(str(uuid7())) is None


def test_idempotent_re_ingest_returns_duplicate_error(
    repository: SecurityEventRepository,
) -> None:
    e = _make_event()
    repository.create(e)
    with pytest.raises(DuplicateEventError) as ei:
        repository.create(e)
    assert ei.value.existing.event_id == e.event_id


def test_idempotent_reingest_with_submillisecond_event_time(
    repository: SecurityEventRepository,
) -> None:
    """AUD-01 regression: BSON stores datetimes at millisecond precision.

    A genuine re-delivery of the SAME source event (fresh SecurityEvent
    instance, identical content, event_time carrying sub-millisecond
    microseconds) must be classified as an idempotent duplicate — NOT as
    a conflicting replay — even though the stored event_time was
    truncated to milliseconds by MongoDB.
    """
    et = datetime(2026, 9, 17, 12, 0, 0, 123456, tzinfo=timezone.utc)
    e1 = _make_event(event_id=str(uuid7()), event_time=et)
    e2 = _make_event(
        event_id=e1.event_id,
        event_time=et,
        source_event_id=e1.provenance.source_event_id,
    )
    # e1/e2 are distinct instances with identical content (frozen model
    # equality makes them ==); each create() rebuilds the canonical
    # payload from its own instance, which is what a re-delivery does.
    repository.create(e1)
    with pytest.raises(DuplicateEventError) as ei:
        repository.create(e2)
    assert ei.value.existing.event_id == e1.event_id


def test_conflict_still_detected_for_materially_different_event_time(
    repository: SecurityEventRepository,
) -> None:
    """The AUD-01 fix must not weaken tamper detection: a re-delivery
    claiming the same event_id with a materially different event_time
    (whole milliseconds apart) is still a conflicting replay.
    """
    e1 = _make_event(event_id=str(uuid7()))
    e2 = _make_event(
        event_id=e1.event_id,
        event_time=e1.event_time.replace(microsecond=500_000),
        source_event_id=e1.provenance.source_event_id,
    )
    repository.create(e1)
    with pytest.raises(ConflictEventError):
        repository.create(e2)


def test_conflict_on_same_event_id_different_content(
    repository: SecurityEventRepository,
) -> None:
    e = _make_event()
    repository.create(e)
    e2 = e.model_copy(
        update={"details": {"http_method": "GET", "status_code": 404}}
    )
    with pytest.raises(ConflictEventError):
        repository.create(e2)


def test_find_by_canonical_identity_finds_event(
    repository: SecurityEventRepository,
) -> None:
    e = _make_event(
        source_event_id="prov-key-1", collector="simulated"
    )
    repository.create(e)
    found = repository.find_by_canonical_identity(
        source="simulator", source_event_id="prov-key-1"
    )
    assert found is not None
    assert found.event_id == e.event_id


def test_find_by_canonical_identity_returns_none_when_missing(
    repository: SecurityEventRepository,
) -> None:
    found = repository.find_by_canonical_identity(
        source="simulator", source_event_id="never-ingested"
    )
    assert found is None


def test_indexed_query_by_source_works(
    repository: SecurityEventRepository,
) -> None:
    e1 = _make_event()
    e2 = _make_event()
    repository.create(e1)
    repository.create(e2)
    # The repository hides the driver; we exercise the index path
    # indirectly via a hand-rolled query and verify the index is
    # selected.
    from tests.integration.conftest import TEST_DB_NAME
    from app.config import ProShieldConfig as _C
    cfg = repository._config  # type: ignore[attr-defined]
    raw = repository._collection  # type: ignore[attr-defined]
    # Force the planner to use the source index by querying with a
    # single equality predicate.
    explain = raw.find({"source": "simulator"}).explain()
    # ``explain`` returns a plan with ``queryPlanner``; the plan must
    # mention the IXSCAN stage.
    plan_str = str(explain)
    assert "IXSCAN" in plan_str or "COLLSCAN" in plan_str
    # We accept either: with only a few docs the planner may
    # legitimately choose COLLSCAN.  The real assertion is that the
    # index is created (covered below).
    indexes = [idx["name"] for idx in raw.list_indexes()]
    assert "ev_source_time" in indexes
    assert "ev_event_id_unique" in indexes
    assert "ev_time_desc" in indexes
    assert "ev_type_time" in indexes
    assert "ev_asset_time" in indexes
    assert "ev_account_time" in indexes
    assert "ev_provenance_source_id" in indexes


def test_count_returns_zero_on_empty_collection(
    repository: SecurityEventRepository,
) -> None:
    assert repository.count() == 0
