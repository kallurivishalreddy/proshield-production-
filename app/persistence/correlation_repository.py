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
    if "key" in cleaned and isinstance(cleaned["key"], list):
        cleaned["key"] = CorrelationKey(parts=tuple(cleaned["key"]))
    if "extra" in cleaned and isinstance(cleaned["extra"], dict):
        cleaned["extra"] = tuple(sorted(cleaned["extra"].items()))
    # Convert list to tuple for tuple-typed fields (Pydantic
    # accepts both, but be explicit).
    for f in ("detection_ids", "event_ids"):
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