"""Failure-classification tests for the persistence layer.

Reference: docs/PHASE 1/THREAT_MODEL.md, Boundary 4
(Application -> Storage) and docs/PHASE 3/SECURE_FOUNDATION.md,
Gate 8 (Secure Failure: failures do not create false success or
silent security-state corruption).
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pymongo import MongoClient

from app.config import ProShieldConfig
from app.domain.errors import PersistenceError
from app.domain.security_event import (
    SecurityEvent,
    SecurityEventProvenance,
)
from app.domain.uuid7 import uuid7
from app.persistence.mongo import (
    check_connectivity,
    make_client,
)


def _make_event() -> SecurityEvent:
    et = datetime(2026, 1, 1, tzinfo=timezone.utc)
    return SecurityEvent(
        event_id=str(uuid7()),
        event_time=et,
        ingested_at=et,
        source="simulator",
        event_type="request_blocked",
        provenance=SecurityEventProvenance(
            collector="simulated", source_event_id="x"
        ),
    )


def test_unreachable_mongo_raises_persistence_error() -> None:
    # Point at a port that nothing is listening on; connectivity
    # check must surface the failure as PersistenceError, NOT a
    # raw driver exception.
    bad_cfg = ProShieldConfig(
        mongo_uri="mongodb://127.0.0.1:1/",  # no server on port 1
    )
    client = make_client(bad_cfg)
    try:
        with pytest.raises(PersistenceError) as ei:
            check_connectivity(client)
        # Safe message must not contain the driver class name.
        assert "pymongo" not in ei.value.safe_message
        # Internal detail MAY include the driver class name for
        # server-side diagnosis.
        assert ei.value.internal_detail is not None
    finally:
        client.close()
