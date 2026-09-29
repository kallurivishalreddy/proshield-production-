"""Correlation repository: the documented boundary for Correlation persistence.

Reference: docs/PHASE 4/DETECTION_ENGINEERING_AND_FUTURE_AI.md
           (Sections 14-17, 87-91) and
           docs/PHASE 2/CONTRACT_DECISIONS.md (ADR-001, ADR-002).

The :class:`CorrelationRepository` is the only place in the
codebase that talks to pymongo about correlation documents. It
mirrors the documented :class:`SecurityEventRepository` and
:class:`DetectionRepository` policies:

* Translates driver errors to safe :class:`DomainError`
  subclasses so callers have a single error contract.
* Maintains the documented index set and the idempotency /
  duplicate-handling policy for the ``correlations``
  collection.

The contract
------------

A :class:`app.correlation.models.Correlation` is a frozen,
BSON-safe Pydantic model with a deterministic
``corr-<uuidv7>`` id (matching the per-event ``detection_id``
derivation in ``app.detection.engine``). The repository
persists it via its :meth:`Correlation.to_dict`
representation. A document is uniquely identified by its
``correlation_id``; the repository refuses to insert a document
whose id already exists (idempotent re-delivery, matching the
other repositories).
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from pymongo import ASCENDING, DESCENDING
from pymongo.collection import Collection
from pymongo.database import Database
from pymongo.errors import (
    DuplicateKeyError,
    PyMongoError,
)

from ..config import ProShieldConfig
from ..correlation.models import Correlation, CorrelationKey
from ..domain.errors import (
    DuplicateEventError,
    PersistenceError,
    ValidationError,
)
from .human_ids import COUNTERS_COLLECTION, HumanIdAllocator


# ----------------------------------------------------------------- index specs
INDEX_SPECS: List[Dict[str, Any]] = [
    {
        "name": "corr_correlation_id_unique",
        "key": [("correlation_id", ASCENDING)],
        "unique": True,
    },
    {
        "name": "corr_pattern_id",
        "key": [("pattern_id", ASCENDING), ("pattern_version", ASCENDING)],
    },
    {"name": "corr_window", "key": [("window_start", DESCENDING)]},
    {"name": "corr_key", "key": [("key", ASCENDING)]},
    # Phase 5.2 (§12): capability-scoped correlation lookup.
    {"name": "corr_capability_ids", "key": [("capability_ids", ASCENDING)]},
]


def correlation_collection_name(config: ProShieldConfig) -> str:
    """The collection name for the ``correlations`` collection."""
    return getattr(
        config,
        "mongo_collection_correlations",
        "correlations",
    )


# ----------------------------------------------------------------- validator
CORRELATIONS_VALIDATOR: Dict[str, Any] = {
    "$jsonSchema": {
        "bsonType": "object",
        # Defense-in-depth (D-3 fix): reject documents that contain
        # any top-level field not in the documented ``properties``
        # below.  The Pydantic ``Correlation`` model is also
        # ``extra="forbid"`` so a read path would reject the same
        # documents; this validator blocks them at write time so
        # that direct MongoDB writes (migrations, a future HTTP
        # API, an attacker with direct DB access) cannot bypass
        # the Pydantic contract.
        "additionalProperties": False,
        "required": [
            "correlation_id",
            "pattern_id",
            "pattern_version",
            "trigger",
            "key",
            "detection_ids",
            "event_ids",
            "window_start",
            "window_end",
            "count",
            "reasoning",
            "correlated_at",
        ],
        "properties": {
            "_id": {"bsonType": "objectId"},
            "correlation_id": {
                "bsonType": "string",
                "minLength": 36,
                "maxLength": 64,
                "pattern": r"^corr-[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
            },
            "pattern_id": {"bsonType": "string", "minLength": 3, "maxLength": 64},
            "pattern_version": {"bsonType": "int", "minimum": 1, "maximum": 999_999},
            "trigger": {"bsonType": "string", "minLength": 3, "maxLength": 64},
            "key": {
                "bsonType": "array",
                "items": {"bsonType": "string", "minLength": 1, "maxLength": 64},
            },
            # Capability patch gaps 2+6: human id + composed confidence
            # band. Optional (null for legacy rows) — never fabricated.
            "confidence": {
                "bsonType": ["string", "null"], "maxLength": 32,
            },
            "human_id": {
                "bsonType": ["string", "null"], "maxLength": 32,
            },
            "detection_ids": {
                "bsonType": "array",
                "items": {"bsonType": "string"},
            },
            "event_ids": {
                "bsonType": "array",
                "items": {"bsonType": "string"},
            },
            "window_start": {"bsonType": "date"},
            "window_end": {"bsonType": "date"},
            "count": {"bsonType": "int", "minimum": 1, "maximum": 256},
            "reasoning": {"bsonType": "string", "maxLength": 2048},
            "correlated_at": {"bsonType": "date"},
            "extra": {"bsonType": "object"},
            # Phase 5.2 (§8/§12): capabilities derived from the member
            # detections (sorted + de-duplicated by the model validator).
            # Optional; an empty/absent list means no member detection
            # carried a derived capability — never fabricated.
            "capability_ids": {
                "bsonType": "array",
                "maxItems": 16,
                "items": {
                    "bsonType": "string",
                    "maxLength": 64,
                    "pattern": r"^cap-[a-z][a-z0-9-]{1,47}$",
                },
            },
        },
    }
}


# ----------------------------------------------------------------- repository
class CorrelationRepository:
    """Repository for the ``correlations`` collection."""

    def __init__(self, db: Database, config: ProShieldConfig) -> None:
        self._db = db
        self._config = config
        self._collection_name: str = correlation_collection_name(config)
        self._collection: Collection = db[self._collection_name]
        # Capability patch gaps 2+6: human-id assignment and
        # confidence composition at the persistence boundary (every
        # creation path — pipeline, centralized analysis, seeding —
        # gets the composed band exactly once, deterministically).
        counters = db[COUNTERS_COLLECTION]
        if not hasattr(counters, "find_one_and_update"):
            counters = None
        self._human_ids = HumanIdAllocator(counters, "correlation")

    def ensure_schema(self) -> None:
        if self._collection_name in self._db.list_collection_names():
            return
        try:
            self._db.create_collection(
                self._collection_name,
                validator=CORRELATIONS_VALIDATOR,
            )
        except PyMongoError as exc:
            raise PersistenceError(
                safe_message="could not create correlations collection",
                internal_detail=(
                    f"create_collection failed: {type(exc).__name__}"
                ),
            ) from exc
        self._collection = self._db[self._collection_name]

    def ensure_indexes(self) -> None:
        try:
            existing = {ix["name"] for ix in self._collection.list_indexes()}
        except PyMongoError as exc:
            raise PersistenceError(
                safe_message="could not list correlation indexes",
                internal_detail=(
                    f"list_indexes failed: {type(exc).__name__}"
                ),
            ) from exc
        for spec in INDEX_SPECS:
            if spec["name"] in existing:
                continue
            try:
                kwargs: Dict[str, Any] = {"name": spec["name"]}
                if "unique" in spec:
                    kwargs["unique"] = spec["unique"]
                if "sparse" in spec:
                    kwargs["sparse"] = spec["sparse"]
                self._collection.create_index(spec["key"], **kwargs)
            except PyMongoError as exc:
                raise PersistenceError(
                    safe_message=(
                        f"could not create correlation index {spec['name']!r}"
                    ),
                    internal_detail=(
                        f"create_index failed: {type(exc).__name__}"
                    ),
                ) from exc

    def create(self, correlation: Correlation) -> Correlation:
        """Persist a single correlation.

        Raises :class:`DuplicateEventError` when a correlation
        with the same ``correlation_id`` already exists.
        """
        if not isinstance(correlation, Correlation):
            raise ValidationError(
                safe_message="create() requires a Correlation",
                internal_detail=f"got {type(correlation).__name__}",
            )
        if not correlation.human_id:
            correlation = correlation.model_copy(
                update={"human_id": self._human_ids.allocate()},
            )
        if not correlation.confidence:
            # Compose the documented confidence band once, at
            # persistence (gap 6). Failure leaves the band empty —
            # never a fabricated value, never a blocked write.
            from ..severity.enrichment import enrich_correlation

            correlation = enrich_correlation(correlation)
        try:
            payload = correlation.to_dict()
            from datetime import datetime
            for ts_field in ("window_start", "window_end", "correlated_at"):
                if isinstance(payload[ts_field], str):
                    payload[ts_field] = datetime.fromisoformat(
                        payload[ts_field]
                    )
            self._collection.insert_one(payload)
        except DuplicateKeyError as exc:
            raise DuplicateEventError(
                safe_message=(
                    f"correlation {correlation.correlation_id!r} "
                    "already exists"
                ),
                internal_detail=(
                    f"insert_one duplicate: {type(exc).__name__}"
                ),
            ) from exc
        except PyMongoError as exc:
            raise PersistenceError(
                safe_message="could not persist correlation",
                internal_detail=(
                    f"insert_one failed: {type(exc).__name__}"
                ),
            ) from exc
        return correlation

    def get_by_correlation_id(
        self, correlation_id: str
    ) -> Optional[Correlation]:
        try:
            doc = self._collection.find_one(
                {"correlation_id": correlation_id}
            )
        except PyMongoError as exc:
            raise PersistenceError(
                safe_message="could not read correlation",
                internal_detail=(
                    f"find_one failed: {type(exc).__name__}"
                ),
            ) from exc
        if doc is None:
            return None
        return _document_to_correlation(doc)

    def upsert_growth(self, correlation: Correlation) -> Correlation:
        """Grow the stored cluster row to the newest evidence (V2-08).

        The correlation_id now identifies the *logical cluster*
        (signature-derived, stable as the cluster grows). When a
        freshly evaluated correlation for the same signature carries a
        wider window / larger detection-event set than the stored row,
        this method replaces the moving fields in place — **without
        changing the row's identity** and without touching the
        original ``correlated_at`` (first-observed bookkeeping).

        Returns the merged :class:`Correlation`. Insert-new when no
        row exists yet (same guarantee as :meth:`create`).
        """
        if not isinstance(correlation, Correlation):
            raise ValidationError(
                safe_message="upsert_growth() requires a Correlation",
                internal_detail=f"got {type(correlation).__name__}",
            )
        existing = self.get_by_correlation_id(correlation.correlation_id)
        if existing is None:
            return self.create(correlation)
        merged_ids = sorted(
            set(existing.detection_ids) | set(correlation.detection_ids)
        )
        merged_events = sorted(
            set(existing.event_ids) | set(correlation.event_ids)
        )
        window_start = min(existing.window_start, correlation.window_start)
        window_end = max(existing.window_end, correlation.window_end)
        # The count is the number of distinct events in the merged set.
        count = max(existing.count, correlation.count, len(merged_events))
        update: Dict[str, Any] = {
            "detection_ids": merged_ids,
            "event_ids": merged_events,
            "window_start": window_start,
            "window_end": window_end,
            "count": count,
            "reasoning": correlation.reasoning or existing.reasoning,
        }
        try:
            self._collection.update_one(
                {"correlation_id": correlation.correlation_id},
                {"$set": update},
            )
        except PyMongoError as exc:
            raise PersistenceError(
                safe_message="could not update correlation evidence",
                internal_detail=(
                    f"update_one failed: {type(exc).__name__}"
                ),
            ) from exc
        # Best-effort: keep the in-memory instance consistent with the
        # persisted row for the caller (case evidence merge).
        try:
            from .models import MAX_CORRELATION_DETECTIONS as _MAX

            return correlation.model_copy(update={
                "detection_ids": tuple(merged_ids),
                "event_ids": tuple(merged_events),
                "window_start": window_start,
                "window_end": window_end,
                "count": min(count, _MAX),
                "reasoning": update["reasoning"],
            })
        except Exception:  # noqa: BLE001 - merged view is best-effort
            return existing

    def find_by_pattern(
        self, pattern_id: str, *, pattern_version: Optional[int] = None
    ) -> List[Correlation]:
        """Return correlations produced by a given pattern.

        ``pattern_id`` MUST be a ``str``. A non-``str`` input is
        rejected up-front with a :class:`ValidationError` to
        prevent NoSQL-injection-shaped queries from reaching
        pymongo.
        """
        if not isinstance(pattern_id, str):
            raise ValidationError(
                safe_message="invalid pattern_id",
                internal_detail=(
                    f"pattern_id must be a str, got "
                    f"{type(pattern_id).__name__}"
                ),
            )
        query: Dict[str, Any] = {"pattern_id": pattern_id}
        if pattern_version is not None:
            query["pattern_version"] = pattern_version
        try:
            cursor = self._collection.find(query).sort(
                "window_start", ASCENDING
            )
            docs = list(cursor)
        except PyMongoError as exc:
            raise PersistenceError(
                safe_message="could not read correlations by pattern",
                internal_detail=f"find failed: {type(exc).__name__}",
            ) from exc
        return [_document_to_correlation(d) for d in docs]

    def find_recent(self, *, limit: int = 50) -> List[Correlation]:
        """Return the most recent correlations ordered by
        ``window_start`` descending.

        Used by the unfiltered ``correlation.list`` path so an analyst
        can see the latest correlation clusters without specifying a
        ``pattern_id`` (F-3). The collection is indexed on
        ``window_start`` for this read pattern.
        """
        if not isinstance(limit, int) or limit < 1 or limit > 1000:
            raise ValidationError(
                safe_message="invalid limit",
                internal_detail=(
                    f"limit must be int in [1, 1000], got {limit!r}"
                ),
                field="limit",
            )
        try:
            cursor = self._collection.find({}).sort(
                "window_start", DESCENDING
            ).limit(limit)
            docs = list(cursor)
        except PyMongoError as exc:
            raise PersistenceError(
                safe_message="could not read correlations",
                internal_detail=f"find_recent failed: {type(exc).__name__}",
            ) from exc
        return [_document_to_correlation(d) for d in docs]

    def count(self) -> int:
        try:
            return int(self._collection.count_documents({}))
        except PyMongoError as exc:
            raise PersistenceError(
                safe_message="could not count correlations",
                internal_detail=(
                    f"count_documents failed: {type(exc).__name__}"
                ),
            ) from exc


# ----------------------------------------------------------------- helpers
def _document_to_correlation(doc: Dict[str, Any]) -> Correlation:
    """Convert a MongoDB document back into a Correlation.

    The Correlation model is ``frozen=True, extra="forbid"`` so
    we MUST strip the MongoDB-managed ``_id`` field. The ``key``
    field is stored as a list of strings and must be
    re-wrapped as a :class:`CorrelationKey`; the ``extra``
    field is stored as a dict and must be converted back to a
    tuple of (key, value) pairs. BSON Date fields
    (``window_start``, ``window_end``, ``correlated_at``) are
    re-attached UTC tzinfo because they round-trip as naive
    Python ``datetime`` objects.
    """
    from datetime import datetime, timezone
    cleaned = {k: v for k, v in doc.items() if k != "_id"}
    # Capability patch gaps 2+6: wire-friendly None round-trips back
    # to the model's "" default.
    for blank_field in ("confidence", "human_id"):
        if cleaned.get(blank_field) is None:
            cleaned[blank_field] = ""
    if "key" in cleaned and isinstance(cleaned["key"], list):
        cleaned["key"] = CorrelationKey(parts=tuple(cleaned["key"]))
    if "extra" in cleaned and isinstance(cleaned["extra"], dict):
        cleaned["extra"] = tuple(sorted(cleaned["extra"].items()))
    # Convert list to tuple for tuple-typed fields (Pydantic
    # accepts both, but be explicit).
    for f in ("detection_ids", "event_ids", "capability_ids"):
        if f in cleaned and isinstance(cleaned[f], list):
            cleaned[f] = tuple(cleaned[f])
    # Re-attach UTC tzinfo to all timestamp fields.
    for f in ("window_start", "window_end", "correlated_at"):
        if (
            f in cleaned
            and isinstance(cleaned[f], datetime)
            and cleaned[f].tzinfo is None
        ):
            cleaned[f] = cleaned[f].replace(tzinfo=timezone.utc)
    return Correlation.model_validate(cleaned)