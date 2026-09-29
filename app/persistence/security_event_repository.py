"""SecurityEvent repository: the documented boundary for SecurityEvent persistence.

Routes and services MUST NOT import pymongo directly.  All MongoDB
access goes through this module.  This isolates:

* the collection name and database binding,
* the index set,
* the document validators,
* driver error translation to safe domain errors,
* the documented idempotency / duplicate-handling policy.

Reference: docs/PHASE 2/CONTRACT_DECISIONS.md (ADR-001, ADR-002),
           docs/PHASE 2/SECURITY_EVENT_SCHEMA.md, Sections 15 / 16 / 21-23.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from pydantic import ValidationError as PydanticValidationError
from pymongo import ASCENDING, DESCENDING
from pymongo.collection import Collection
from pymongo.database import Database
from pymongo.errors import (
    BulkWriteError,
    DuplicateKeyError,
    PyMongoError,
)

from ..config import ProShieldConfig
from ..domain.errors import (
    ConflictEventError,
    DuplicateEventError,
    PersistenceError,
    ValidationError,
)
from ..domain.security_event import (
    MAX_EVENT_ID,
    SecurityEvent,
    to_canonical_dict,
    validate_size_constraints,
)
from .schema import SECURITY_EVENTS_VALIDATOR

_log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Index definitions
#
# Each index corresponds to a documented query pattern from
# docs/PHASE 2/SECURITY_EVENT_SCHEMA.md, Section 23:
#
#   - by time range (event_time)              -> ev_time_desc
#   - by source (source, event_time)          -> ev_source_time
#   - by event_type (event_type, event_time)  -> ev_type_time
#   - by asset (asset, event_time)            -> ev_asset_time
#   - by account (account.id, event_time)     -> ev_account_time
#   - by provenance (provenance.source_event_id) -> ev_provenance_source_id
#   - unique on event_id                      -> ev_event_id_unique
#
# ADR-043 leaves exact index sets query-driven; the list below covers
# every access pattern called out in the schema and is the MVP minimum.
# ---------------------------------------------------------------------------
INDEX_SPECS: List[Dict[str, Any]] = [
    {"name": "ev_event_id_unique", "key": [("event_id", ASCENDING)], "unique": True},
    {"name": "ev_time_desc", "key": [("event_time", DESCENDING)]},
    {"name": "ev_source_time", "key": [("source", ASCENDING), ("event_time", DESCENDING)]},
    {"name": "ev_type_time", "key": [("event_type", ASCENDING), ("event_time", DESCENDING)]},
    {"name": "ev_asset_time", "key": [("asset", ASCENDING), ("event_time", DESCENDING)]},
    {
        "name": "ev_account_time",
        "key": [
            ("account.id", ASCENDING),
            ("event_time", DESCENDING),
        ],
        "sparse": True,
    },
    {
        "name": "ev_provenance_source_id",
        "key": [
            ("provenance.collector", ASCENDING),
            ("provenance.source_event_id", ASCENDING),
        ],
    },
    {
        # Phase 4.9: source-instance lookups. Sparse so
        # Phase 4.1-4.8 events (no ``provenance.source_instance_id``)
        # do not consume index slots.
        "name": "ev_provenance_source_instance_id",
        "key": [
            ("provenance.source_instance_id", ASCENDING),
            ("event_time", DESCENDING),
        ],
        "sparse": True,
    },
]


class SecurityEventRepository:
    """Repository for the ``security_events`` collection.

    The repository speaks one and only one domain type
    (:class:`SecurityEvent`); it never returns raw documents.  It
    raises :class:`DomainError` subclasses on failure so the upper
    layers can use a single error contract.
    """

    def __init__(self, db: Database, config: ProShieldConfig) -> None:
        self._db = db
        self._config = config
        self._collection: Collection = db[config.mongo_collection_events]

    # ------------------------------------------------------------------ setup
    def ensure_schema(self) -> None:
        """Apply the $jsonSchema validator to the collection.

        Safe to call repeatedly.  Existing documents that fail the new
        validator are NOT modified; this slice assumes we are
        bootstrapping an empty database.  Future slices should add
        explicit migration steps if a schema change must be enforced
        on existing data.
        """
        try:
            self._db.command(
                "collMod",
                self._config.mongo_collection_events,
                validator=SECURITY_EVENTS_VALIDATOR,
                validationLevel="strict",
                validationAction="error",
            )
        except PyMongoError as exc:
            # MongoDB signals a missing namespace either as
            # "ns not found" (older server messages) or as
            # "ns does not exist" (current MongoDB 6+).  We accept
            # either form.
            msg = str(exc).lower()
            if "ns not found" in msg or "ns does not exist" in msg:
                self._db.create_collection(
                    self._config.mongo_collection_events,
                    validator=SECURITY_EVENTS_VALIDATOR,
                    validationLevel="strict",
                    validationAction="error",
                )
                return
            raise PersistenceError(
                safe_message="could not configure schema validator",
                internal_detail=f"collMod failed: {type(exc).__name__}",
            ) from exc

    def ensure_indexes(self) -> List[str]:
        """Create the documented indexes.  Returns the names of created indexes.

        If an index already exists with the same spec, this is a no-op.
        If a conflicting index exists, that is a configuration problem
        and is surfaced as a ``PersistenceError`` for the operator to
        resolve.
        """
        created: List[str] = []
        try:
            for spec in INDEX_SPECS:
                keys = spec["key"]
                opts = {k: v for k, v in spec.items() if k not in {"name", "key"}}
                self._collection.create_index(keys, name=spec["name"], **opts)
                created.append(spec["name"])
            return created
        except PyMongoError as exc:
            raise PersistenceError(
                safe_message="could not create indexes",
                internal_detail=f"create_index failed: {type(exc).__name__}",
            ) from exc

    # ------------------------------------------------------------------ write
    def create(self, event: SecurityEvent) -> SecurityEvent:
        """Insert a new event.  Idempotent: if an event with the same
        ``event_id`` already exists with identical content, the
        existing document is returned and ``DuplicateEventError`` is
        raised with the existing instance attached (so callers can
        choose to treat it as success).  If the existing content
        differs, :class:`ConflictEventError` is raised.
        """
        payload = to_canonical_dict(event)
        validate_size_constraints(
            payload,
            max_body_bytes=self._config.ingest_max_body_bytes,
            max_details_bytes=self._config.ingest_max_details_bytes,
        )
        # Defence in depth: the application has already validated, but
        # we re-check the documented character cap on event_id before
        # sending it to the driver.
        if len(payload["event_id"]) > MAX_EVENT_ID:
            raise ValidationError(
                safe_message="event_id exceeds documented length",
                internal_detail=f"event_id length {len(payload['event_id'])}",
                field="event_id",
            )

        try:
            self._collection.insert_one(payload)
            return event
        except DuplicateKeyError as exc:
            existing = self.get_by_event_id(event.event_id)
            if existing is None:
                raise PersistenceError(
                    safe_message="duplicate-key conflict without existing record",
                    internal_detail="insert_one raised DuplicateKeyError "
                    "but get_by_event_id returned None",
                ) from exc
            # Strip pymongo's mutated ``_id`` from the failed-insert
            # payload so the comparison is on the canonical event
            # content only.
            payload_for_compare = {k: v for k, v in payload.items() if k != "_id"}
            new_p = to_canonical_dict(existing)
            if _canonical_equal(payload_for_compare, new_p):
                err = DuplicateEventError(
                    safe_message="event already accepted (idempotent)",
                    internal_detail=f"event_id={event.event_id}",
                )
                err.existing = existing  # type: ignore[attr-defined]
                raise err
            raise ConflictEventError(
                safe_message="event_id already exists with different content",
                internal_detail=f"event_id={event.event_id}",
            ) from exc
        except BulkWriteError as exc:
            raise PersistenceError(
                safe_message="bulk write failure",
                internal_detail=str(exc.details.get("writeErrors", [])),
            ) from exc
        except PyMongoError as exc:
            raise PersistenceError(
                safe_message="could not persist event",
                internal_detail=f"insert_one failed: {type(exc).__name__}",
            ) from exc

    # ------------------------------------------------------------------ read
    def get_by_event_id(self, event_id: str) -> Optional[SecurityEvent]:
        """Look up a single event by its canonical event_id.

        Returns ``None`` if not present.  Translates driver errors to
        the safe domain error class.
        """
        try:
            doc = self._collection.find_one({"event_id": event_id})
        except PyMongoError as exc:
            raise PersistenceError(
                safe_message="could not read event",
                internal_detail=f"find_one failed: {type(exc).__name__}",
            ) from exc
        if doc is None:
            return None
        return _document_to_event(doc)

    def find_by_canonical_identity(
        self,
        *,
        source: str,
        source_event_id: str,
        collector: Optional[str] = None,
    ) -> Optional[SecurityEvent]:
        """Look up an event by its provenance (source-side identity).

        Used by ingestion for idempotency checks on connectors that
        supply their own source_event_id.  This is the documented
        Boundary 2 (Collector -> Trusted Processing) dedup path.
        """
        query: Dict[str, Any] = {
            "source": source,
            "provenance.source_event_id": source_event_id,
        }
        if collector is not None:
            query["provenance.collector"] = collector
        try:
            doc = self._collection.find_one(query)
        except PyMongoError as exc:
            raise PersistenceError(
                safe_message="could not read event by canonical identity",
                internal_detail=f"find_one failed: {type(exc).__name__}",
            ) from exc
        if doc is None:
            return None
        return _document_to_event(doc)

    def find_by_source_instance(
        self,
        source_instance_id: str,
        *,
        limit: int = 256,
    ) -> List[SecurityEvent]:
        """Return recent events ingested from the given source instance.

        Used by the Phase 4.9 centralised-investigation path to
        enumerate evidence attached to a specific source instance.
        """
        if not isinstance(source_instance_id, str) or not source_instance_id:
            return []
        try:
            cursor = (
                self._collection
                .find({"provenance.source_instance_id": source_instance_id})
                .sort("event_time", -1)
                .limit(max(1, int(limit)))
            )
        except PyMongoError as exc:
            raise PersistenceError(
                safe_message="could not list events by source instance",
                internal_detail=f"find failed: {type(exc).__name__}",
            ) from exc
        return [
            d for d in (_document_to_event(c) for c in cursor) if d
        ]

    def find_recent(
        self,
        *,
        limit: int = 200,
        source_instance_id: Optional[str] = None,
    ) -> List[SecurityEvent]:
        """Return the most recent events, newest first (V2-06).

        The documented ``ev_time_desc`` index serves this read
        pattern. ``limit`` is hard-bounded to 200 so the unfiltered
        read can never stream the whole event store. This is the
        analyst visibility surface for events that matched **no**
        rule: a valid, trusted, persisted event must be reachable by
        the analyst even when it produced zero detections (V2-06).
        """
        bounded = max(1, min(int(limit), 200))
        query: Dict[str, Any] = {}
        if source_instance_id:
            query["provenance.source_instance_id"] = source_instance_id
        try:
            cursor = (
                self._collection.find(query)
                .sort("event_time", -1)
                .limit(bounded)
            )
        except PyMongoError as exc:
            raise PersistenceError(
                safe_message="could not list recent events",
                internal_detail=f"find failed: {type(exc).__name__}",
            ) from exc
        # Quarantine policy (matches the incident / correlation
        # repositories): a poisoned legacy document is logged and
        # skipped — it must never crash a bounded read path.
        out: List[SecurityEvent] = []
        for doc in cursor:
            try:
                event = _document_to_event(doc)
            except (PydanticValidationError, ValueError, TypeError) as exc:
                _log.warning(
                    "security_event.document_quarantined",
                    extra={
                        "event_id": doc.get("event_id"),
                        "error_type": type(exc).__name__,
                        "error": str(exc)[:512],
                    },
                )
                continue
            if event is not None:
                out.append(event)
        return out

    def count(self) -> int:
        try:
            return int(self._collection.count_documents({}))
        except PyMongoError as exc:
            raise PersistenceError(
                safe_message="could not count events",
                internal_detail=f"count_documents failed: {type(exc).__name__}",
            ) from exc


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _document_to_event(doc: Dict[str, Any]) -> SecurityEvent:
    """Convert a MongoDB document back into a SecurityEvent.

    The document is a dict that Pydantic can validate directly.  We
    strip the MongoDB-managed ``_id`` field first because the
    canonical Pydantic model uses ``extra='forbid'`` and would
    otherwise reject it.  We also re-attach UTC tzinfo to any
    ``datetime`` fields, because BSON Date round-trips as a naive
    Python ``datetime`` whereas the Pydantic model requires an
    aware datetime in UTC.
    """
    from datetime import timezone
    cleaned = {k: v for k, v in doc.items() if k != "_id"}
    for ts_field in ("event_time", "ingested_at"):
        v = cleaned.get(ts_field)
        if isinstance(v, datetime) and v.tzinfo is None:
            cleaned[ts_field] = v.replace(tzinfo=timezone.utc)
    return SecurityEvent.model_validate(cleaned)


# Local datetime import for the helper above; kept here rather than
# at module top to avoid a circular import surprise.
from datetime import datetime, timezone  # noqa: E402


def _ms_precision(value: Any) -> Any:
    """Normalize a datetime to millisecond precision (BSON storage precision).

    MongoDB stores BSON datetimes at millisecond precision, so a value
    round-tripped through the database loses any sub-millisecond digits.
    An idempotent re-delivery of the SAME source event must not be
    classified as a conflicting replay just because the freshly built
    payload still carries microseconds.  Non-datetime values compare
    unchanged.
    """
    if isinstance(value, datetime):
        if value.tzinfo is not None:
            value = value.astimezone(timezone.utc).replace(tzinfo=None)
        ms = (value.microsecond // 1000) * 1000
        return value.replace(microsecond=ms)
    return value


def _canonical_equal(a: Dict[str, Any], b: Dict[str, Any]) -> bool:
    """Equality check on the canonical dict form of an event.

    Used to detect the documented idempotency case
    (same event_id, same SOURCE content).

    Two storage artifacts are normalized so a genuine re-delivery of the
    same event is not misclassified as a conflicting replay (T02):

    * ``ingested_at`` — server-side bookkeeping that the ingestion
      service stamps per-call, so it is excluded entirely;
    * ``event_time`` — compared at BSON (millisecond) precision,
      because MongoDB truncates sub-millisecond digits on write.

    Any other difference (including a materially different event_time)
    still raises :class:`ConflictEventError`.
    """
    excluded = {"ingested_at"}
    keys = (set(a) | set(b)) - excluded
    for k in keys:
        if k == "event_time":
            if _ms_precision(a.get(k)) != _ms_precision(b.get(k)):
                return False
            continue
        if a.get(k) != b.get(k):
            return False
    return True
