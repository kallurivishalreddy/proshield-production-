"""Live smoke: drop the collection, run init, ingest a small scenario,
verify counts, prove the events are queryable by every documented
index path.  This is the script that produced the
'Runtime Verification' numbers in the Phase 4.1 final report.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.config import ProShieldConfig
from app.connectors.simulated import SimulatedConnector
from app.domain.errors import ConflictEventError, DuplicateEventError
from app.domain.security_event import (
    SecurityEvent,
    SecurityEventProvenance,
)
from app.ingestion.service import SecurityEventIngestionService
from app.observability.logging import configure_logging
from app.persistence.mongo import mongo_session
from app.persistence.security_event_repository import (
    SecurityEventRepository,
)


def _build_fixed_event(seq: int) -> SecurityEvent:
    """Build an event with a stable event_id for the replay test."""
    base = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    et = base + timedelta(seconds=seq)
    return SecurityEvent(
        event_id="0198c2a1-7e3b-7a8e-b7b6-4f6a7d4d5f12",
        event_time=et,
        ingested_at=et + timedelta(milliseconds=1),
        source="simulator",
        event_type="request_blocked",
        source_ip="203.0.113.42",
        destination="app.example.internal",
        endpoint="/api/login",
        asset="web-api-01",
        provenance=SecurityEventProvenance(
            collector="simulated", source_event_id="smoke-fixed-1"
        ),
        details={"http_method": "POST", "status_code": 403},
    )


def main() -> int:
    configure_logging("INFO")
    cfg = ProShieldConfig.from_env()
    with mongo_session(cfg) as (_client, db):
        # Wipe for a deterministic count.
        db[cfg.mongo_collection_events].drop()
        repo = SecurityEventRepository(db, cfg)
        repo.ensure_schema()
        repo.ensure_indexes()
        svc = SecurityEventIngestionService(repo, cfg)
        n_before = repo.count()
        n_ingested = svc.ingest_from_connector(SimulatedConnector())
        n_after = repo.count()

        # True idempotency: re-ingest the SAME event with the SAME
        # event_id.  The repository should report DuplicateEventError
        # which the service treats as a successful no-op.
        fixed1 = _build_fixed_event(0)
        result1 = svc.ingest(fixed1)
        result2 = svc.ingest(fixed1)  # same event_id, same content
        n_after_idem = repo.count()
        ids_match = result1.event_id == result2.event_id

        # Conflict path: same event_id, DIFFERENT content -> ConflictEventError.
        fixed_changed = fixed1.model_copy(
            update={"details": {"http_method": "GET", "status_code": 404}}
        )
        conflict_raised = False
        try:
            svc.ingest(fixed_changed)
        except ConflictEventError:
            conflict_raised = True

        # Provenance lookup.
        e1 = repo.find_by_canonical_identity(
            source="simulator", source_event_id="sim-A-001"
        )
        # Sample a document straight from MongoDB to confirm shape.
        sample = db[cfg.mongo_collection_events].find_one({})

        # Query paths covered by indexes.
        by_time = list(
            db[cfg.mongo_collection_events]
            .find()
            .sort("event_time", -1)
            .limit(3)
        )
        by_source = list(
            db[cfg.mongo_collection_events]
            .find({"source": "simulator"})
            .limit(3)
        )
        by_type = list(
            db[cfg.mongo_collection_events]
            .find({"event_type": "authentication_failure"})
            .limit(3)
        )
        by_prov = list(
            db[cfg.mongo_collection_events]
            .find({"provenance.source_event_id": "sim-A-001"})
            .limit(1)
        )

        indexes = list(db[cfg.mongo_collection_events].list_indexes())

    print(f"before                       : {n_before}")
    print(f"ingested                     : {n_ingested}")
    print(f"after_first_ingest           : {n_after}")
    print(f"idempotent_kept_count        : {n_after_idem - n_after}")
    print(f"idempotent_same_event_id     : {ids_match}")
    print(f"conflict_raised_on_change    : {conflict_raised}")
    print(f"provenance_lookup_event_id   : {e1.event_id if e1 else None}")
    print(f"sample_source                : {sample.get('source') if sample else None}")
    print(f"sample_event_type            : {sample.get('event_type') if sample else None}")
    print(f"sample_keys                  : {sorted(sample.keys()) if sample else None}")
    print(f"by_time_count                : {len(by_time)}")
    print(f"by_source_count              : {len(by_source)}")
    print(f"by_type_count                : {len(by_type)}")
    print(f"by_provenance_count          : {len(by_prov)}")
    print(f"indexes                      : {[i['name'] for i in indexes]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
