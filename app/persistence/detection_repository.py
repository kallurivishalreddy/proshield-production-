"""Detection repository: the documented boundary for Detection persistence.

Reference: docs/PHASE 4/DETECTION_ENGINEERING_AND_FUTURE_AI.md
           (Sections 8, 9, 12, 13, 87-91) and
           docs/PHASE 2/CONTRACT_DECISIONS.md (ADR-001, ADR-002).

The :class:`DetectionRepository` is to detections what the
:class:`SecurityEventRepository` is to security events:

* The only place in the codebase that talks to pymongo about
  detection documents.
* Translates driver errors to safe domain errors so callers
  have a single error contract.
* Maintains the documented index set and the idempotency /
  duplicate-handling policy for the ``detections`` collection.

The contract
------------

A :class:`app.detection.models.Detection` is already a frozen,
BSON-safe Pydantic model with a deterministic
``det-<uuidv7>`` id (Phase 4.4 D-2 fix). The repository
persists it via its :meth:`Detection.to_dict` representation
(deterministic, ISO-stringified timestamps, frozen ``extra``
as a dict). A document is uniquely identified by its
``detection_id``; the repository refuses to insert a document
whose id already exists (idempotent re-delivery, matching the
:class:`SecurityEventRepository` policy).

Document shape
--------------

::

    {
      "_id": <ObjectId>,             # server-managed
      "detection_id": "det-<uuidv7>",
      "rule_id": "NGINX-AUTH-FAILURE-001",
      "rule_version": 1,
      "category": "source_specific",
      "event_id": "<uuidv7>",
      "evidence_refs": ["<uuidv7>", ...],
      "reasoning": "...",
      "detected_at": <BSON Date>,
      "extra": { ... },
      "correlated": false            # documented forward-compat flag
    }

The ``correlated`` field is a boolean defaulting to ``False``.
A future correlation-persistence slice can flip it to ``True``
on a detection that participated in a correlation, without
changing the detection contract. The detection engine does
NOT set it; the correlation persistence layer will.

Index set
---------

The Phase 4.5 index set is the documented minimum:

* ``det_detection_id_unique`` — unique on ``detection_id``
  (idempotency key, also the primary lookup),
* ``det_rule_id`` — by rule (research / catalog / lineage),
* ``det_event_id`` — by underlying event (analyst investigation
  path: "show me every detection that came from this event"),
* ``det_detected_at_desc`` — by time (audit / replay / timeline
  construction).
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import ValidationError as PydanticValidationError
from pymongo import ASCENDING, DESCENDING
from pymongo.collection import Collection
from pymongo.database import Database
from pymongo.errors import (
    DuplicateKeyError,
    PyMongoError,
)

from ..config import ProShieldConfig
from ..detection.models import Detection
from ..domain.errors import (
    DuplicateEventError,
    PersistenceError,
    ValidationError,
)


# ----------------------------------------------------------------- index specs
INDEX_SPECS: List[Dict[str, Any]] = [
    {
        "name": "det_detection_id_unique",
        "key": [("detection_id", ASCENDING)],
        "unique": True,
    },
    {"name": "det_rule_id", "key": [("rule_id", ASCENDING), ("rule_version", ASCENDING)]},
    {"name": "det_event_id", "key": [("event_id", ASCENDING)]},
    {"name": "det_detected_at_desc", "key": [("detected_at", DESCENDING)]},
]


def detection_collection_name(config: ProShieldConfig) -> str:
    """The collection name for the ``detections`` collection."""
    return getattr(
        config,
        "mongo_collection_detections",
        "detections",
    )


# ----------------------------------------------------------------- validator
DETECTIONS_VALIDATOR: Dict[str, Any] = {
    "$jsonSchema": {
        "bsonType": "object",
        # Defense-in-depth (D-3 fix): reject documents that contain
        # any top-level field not in the documented ``properties``
        # below.  The Pydantic ``Detection`` model is also
        # ``extra="forbid"`` so a read path would reject the same
        # documents; this validator blocks them at write time so
        # that direct MongoDB writes (migrations, a future HTTP
        # API, an attacker with direct DB access) cannot bypass
        # the Pydantic contract.
        "additionalProperties": False,
        "required": [
            "detection_id",
            "rule_id",
            "rule_version",
            "category",
            "event_id",
            "evidence_refs",
            "reasoning",
            "detected_at",
        ],
        "properties": {
            "_id": {"bsonType": "objectId"},
            "detection_id": {
                "bsonType": "string",
                "minLength": 36,
                "maxLength": 64,
                "pattern": r"^det-[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
            },
            "rule_id": {"bsonType": "string", "minLength": 3, "maxLength": 64},
            "rule_version": {"bsonType": "int", "minimum": 1, "maximum": 999_999},
            "category": {"bsonType": "string", "minLength": 1, "maxLength": 32},
            "event_id": {"bsonType": "string", "minLength": 1, "maxLength": 64},
            "evidence_refs": {
                "bsonType": "array",
                "items": {"bsonType": "string"},
            },
            "reasoning": {"bsonType": "string", "maxLength": 2048},
            "detected_at": {"bsonType": "date"},
            "extra": {"bsonType": "object"},
            "correlated": {"bsonType": "bool"},
        },
    }
}


# ----------------------------------------------------------------- repository
class DetectionRepository:
    """Repository for the ``detections`` collection.

    The repository speaks one and only one domain type
    (:class:`Detection`); it never returns raw documents. It
    raises :class:`DomainError` subclasses on failure so the
    upper layers can use a single error contract.

    The collection is created lazily on the first
    :meth:`ensure_schema` / :meth:`ensure_indexes` call. The
    repository does NOT perform detection — it only persists
    detections produced by the detection engine.
    """

    def __init__(self, db: Database, config: ProShieldConfig) -> None:
        self._db = db
        self._config = config
        self._collection_name: str = detection_collection_name(config)
        self._collection: Collection = db[self._collection_name]

    # ------------------------------------------------------------- infrastructure
    def ensure_schema(self) -> None:
        """Create the collection with the $jsonSchema validator.

        Mirrors :meth:`SecurityEventRepository.ensure_schema`.
        The validator is the documented defense-in-depth: the
        application is the primary gate (Pydantic), the
        database is the secondary gate.
        """
        if self._collection_name in self._db.list_collection_names():
            return
        try:
            self._db.create_collection(
                self._collection_name,
                validator=DETECTIONS_VALIDATOR,
            )
        except PyMongoError as exc:
            raise PersistenceError(
                safe_message="could not create detections collection",
                internal_detail=f"create_collection failed: {type(exc).__name__}",
            ) from exc
        self._collection = self._db[self._collection_name]

    def ensure_indexes(self) -> None:
        """Create the documented index set. Idempotent."""
        try:
            existing = {ix["name"] for ix in self._collection.list_indexes()}
        except PyMongoError as exc:
            raise PersistenceError(
                safe_message="could not list detection indexes",
                internal_detail=f"list_indexes failed: {type(exc).__name__}",
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
                        f"could not create detection index {spec['name']!r}"
                    ),
                    internal_detail=(
                        f"create_index failed: {type(exc).__name__}"
                    ),
                ) from exc

    # ------------------------------------------------------------- public API
    def create(self, detection: Detection) -> Detection:
        """Persist a single detection.

        Returns the persisted detection (a re-validated copy).
        Raises :class:`DuplicateEventError` (named for symmetry
        with the events repo) when a detection with the same
        ``detection_id`` already exists; the caller treats
        this as an idempotent no-op, mirroring the
        :class:`SecurityEventRepository` policy.
        """
        if not isinstance(detection, Detection):
            raise ValidationError(
                safe_message="create() requires a Detection",
                internal_detail=f"got {type(detection).__name__}",
            )
        try:
            payload = detection.to_dict()
            from datetime import datetime
            if isinstance(payload["detected_at"], str):
                payload["detected_at"] = datetime.fromisoformat(
                    payload["detected_at"]
                )
            payload["correlated"] = False
            self._collection.insert_one(payload)
        except DuplicateKeyError as exc:
            raise DuplicateEventError(
                safe_message=(
                    f"detection {detection.detection_id!r} already exists"
                ),
                internal_detail=f"insert_one duplicate: {type(exc).__name__}",
            ) from exc
        except PyMongoError as exc:
            raise PersistenceError(
                safe_message="could not persist detection",
                internal_detail=f"insert_one failed: {type(exc).__name__}",
            ) from exc
        except PydanticValidationError:
            raise
        return detection

    def get_by_detection_id(
        self, detection_id: str
    ) -> Optional[Detection]:
        """Look up a detection by its ``detection_id``."""
        try:
            doc = self._collection.find_one(
                {"detection_id": detection_id}
            )
        except PyMongoError as exc:
            raise PersistenceError(
                safe_message="could not read detection",
                internal_detail=f"find_one failed: {type(exc).__name__}",
            ) from exc
        if doc is None:
            return None
        return _document_to_detection(doc)

    def find_by_event_id(self, event_id: str) -> List[Detection]:
        """Return every detection produced from a given event_id.

        The list is sorted by ``detected_at`` ascending so the
        caller can render a deterministic per-event timeline.

        ``event_id`` MUST be a ``str``. A non-``str`` input is
        rejected up-front with a :class:`ValidationError` to
        prevent NoSQL-injection-shaped queries from reaching
        pymongo.
        """
        if not isinstance(event_id, str):
            raise ValidationError(
                safe_message="invalid event_id",
                internal_detail=(
                    f"event_id must be a str, got "
                    f"{type(event_id).__name__}"
                ),
            )
        try:
            cursor = self._collection.find({"event_id": event_id}).sort(
                "detected_at", ASCENDING
            )
            docs = list(cursor)
        except PyMongoError as exc:
            raise PersistenceError(
                safe_message="could not read detections by event",
                internal_detail=f"find failed: {type(exc).__name__}",
            ) from exc
        return [_document_to_detection(d) for d in docs]

    def find_by_rule(
        self, rule_id: str, *, rule_version: Optional[int] = None
    ) -> List[Detection]:
        """Return detections produced by a given rule.

        When ``rule_version`` is ``None``, every version is
        returned. The list is sorted by ``detected_at``
        ascending for deterministic time-ordering.

        ``rule_id`` MUST be a ``str``. A non-``str`` input is
        rejected up-front with a :class:`ValidationError` to
        prevent NoSQL-injection-shaped queries from reaching
        pymongo.
        """
        if not isinstance(rule_id, str):
            raise ValidationError(
                safe_message="invalid rule_id",
                internal_detail=(
                    f"rule_id must be a str, got "
                    f"{type(rule_id).__name__}"
                ),
            )
        query: Dict[str, Any] = {"rule_id": rule_id}
        if rule_version is not None:
            query["rule_version"] = rule_version
        try:
            cursor = self._collection.find(query).sort(
                "detected_at", ASCENDING
            )
            docs = list(cursor)
        except PyMongoError as exc:
            raise PersistenceError(
                safe_message="could not read detections by rule",
                internal_detail=f"find failed: {type(exc).__name__}",
            ) from exc
        return [_document_to_detection(d) for d in docs]

    def count(self) -> int:
        try:
            return int(self._collection.count_documents({}))
        except PyMongoError as exc:
            raise PersistenceError(
                safe_message="could not count detections",
                internal_detail=(
                    f"count_documents failed: {type(exc).__name__}"
                ),
            ) from exc


# ----------------------------------------------------------------- helpers
def _document_to_detection(doc: Dict[str, Any]) -> Detection:
    """Convert a MongoDB document back into a Detection.

    The Detection model is ``frozen=True, extra="forbid"`` so
    we MUST strip the MongoDB-managed ``_id`` field and the
    persistence-only ``correlated`` flag before re-validating.
    The ``extra`` field is stored as a dict and must be
    converted back to a tuple of (key, value) pairs.
    ``detected_at`` is re-attachd UTC tzinfo because BSON Date
    round-trips as a naive Python ``datetime``.
    """
    from datetime import datetime, timezone
    cleaned = {
        k: v
        for k, v in doc.items()
        if k not in ("_id", "correlated")
    }
    if "extra" in cleaned and isinstance(cleaned["extra"], dict):
        cleaned["extra"] = tuple(sorted(cleaned["extra"].items()))
    if "detected_at" in cleaned and isinstance(
        cleaned["detected_at"], datetime
    ) and cleaned["detected_at"].tzinfo is None:
        cleaned["detected_at"] = cleaned["detected_at"].replace(
            tzinfo=timezone.utc
        )
    return Detection.model_validate(cleaned)
