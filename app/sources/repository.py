"""Source-instance persistence boundary (Phase 4.9).

Reference: docs/PHASE 4/PHASE-04-09-REPORT.md,
docs/PHASE 2/CONTRACT_DECISIONS.md (ADR-001, ADR-002).

The :class:`SourceRepository` is the only place in the
codebase that talks to pymongo about source-instance
documents. It mirrors the documented security-event,
detection, correlation, and rule-repository policies:

* Translates driver errors to safe :class:`DomainError`
  subclasses so callers have a single error contract.
* Maintains a documented index set and the
  idempotency / duplicate-handling policy for the
  ``source_instances`` collection.
* Pairs every read / write with the framework's Pydantic
  :class:`SourceInstance` model.
* Enforces the documented secret-redaction gate at the
  persistence boundary.

A retired source instance is **preserved** with
``state = "retired"`` and ``retired_at`` set.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
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
from ..domain.errors import PersistenceError
from ..domain.security_event import ALLOWED_SOURCES
from .errors import (
    DuplicateSourceInstanceError,
    SourceInstanceNotFoundError,
    SourcePersistenceError,
)
from .models import (
    MAX_ASSET_TAGS,
    MAX_TAGS_PER_SOURCE,
    SourceConnectionType,
    SourceInstance,
    SourceInstanceConfiguration,
    SourceInstanceId,
    SourceState,
    SourceType,
)
from .registry import SUPPORTED_CONNECTOR_TYPES


_log = logging.getLogger(__name__)


# ----------------------------------------------------------------- index specs
INDEX_SPECS: List[Dict[str, Any]] = [
    {
        "name": "source_source_instance_id_unique",
        "key": [("source_instance_id", ASCENDING)],
        "unique": True,
    },
    {
        "name": "source_source_type",
        "key": [("source_type", ASCENDING)],
    },
    {
        "name": "source_state",
        "key": [("state", ASCENDING)],
    },
    {
        "name": "source_created_at",
        "key": [("created_at", DESCENDING)],
    },
    {
        "name": "source_display_name",
        "key": [("display_name", ASCENDING)],
    },
]


SOURCE_INSTANCES_VALIDATOR: Dict[str, Any] = {
    "$jsonSchema": {
        "bsonType": "object",
        "additionalProperties": False,
        "required": [
            "source_instance_id",
            "source_type",
            "source",
            "display_name",
            "description",
            "configuration",
            "state",
            "created_by",
            "created_at",
            "updated_by",
            "updated_at",
            "tags",
            "asset_tags",
        ],
        "properties": {
            "_id": {"bsonType": "objectId"},
            "source_instance_id": {
                "bsonType": "string",
                "minLength": 8,
                "maxLength": 96,
                "pattern": r"^src-[0-9a-f]{8}-[0-9a-f]{4}-"
                           r"7[0-9a-f]{3}-[89ab][0-9a-f]{3}-"
                           r"[0-9a-f]{12}(-[a-z0-9][a-z0-9-]{0,32})?$",
            },
            "source_type": {
                "bsonType": "string",
                "enum": sorted(t.value for t in SourceType),
            },
            "source": {
                "bsonType": "string",
                "enum": sorted(ALLOWED_SOURCES),
            },
            "display_name": {
                "bsonType": "string",
                "minLength": 1,
                "maxLength": 128,
            },
            "description": {
                "bsonType": "string",
                "maxLength": 1024,
            },
            "configuration": {
                "bsonType": "object",
                "required": ["connection_type", "endpoint"],
                "properties": {
                    "connection_type": {
                        "bsonType": "string",
                        "enum": sorted(
                            c.value for c in SourceConnectionType
                        ),
                    },
                    "endpoint": {
                        "bsonType": "string",
                        "minLength": 1,
                        "maxLength": 512,
                    },
                    "proxy_path": {
                        "bsonType": "string",
                        "maxLength": 256,
                    },
                    "destination": {
                        "bsonType": "string",
                        "maxLength": 256,
                    },
                    "asset_tags": {
                        "bsonType": "array",
                        "maxItems": MAX_ASSET_TAGS,
                    },
                    "tags": {
                        "bsonType": "array",
                        "maxItems": MAX_TAGS_PER_SOURCE,
                    },
                    "references": {
                        "bsonType": "array",
                    },
                    "secret_ref_set": {"bsonType": "bool"},
                },
            },
            "state": {
                "bsonType": "string",
                "enum": sorted(s.value for s in SourceState),
            },
            "created_by": {
                "bsonType": "string",
                "minLength": 1,
                "maxLength": 128,
            },
            "created_at": {"bsonType": "date"},
            "updated_by": {
                "bsonType": "string",
                "minLength": 1,
                "maxLength": 128,
            },
            "updated_at": {"bsonType": "date"},
            "last_validation_at": {
                "bsonType": ["date", "null"],
            },
            "tags": {
                "bsonType": "array",
                "maxItems": MAX_TAGS_PER_SOURCE,
            },
            "asset_tags": {
                "bsonType": "array",
                "maxItems": MAX_ASSET_TAGS,
            },
            "retired_at": {
                "bsonType": ["date", "null"],
            },
        },
    },
}


def managed_source_collection_name(env_name: str) -> str:
    """Return the canonical collection name for ``env_name``."""
    return "source_instances"


class SourceRepository:
    """Repository for the ``source_instances`` collection."""

    def __init__(self, db: Database, config: ProShieldConfig) -> None:
        self._db = db
        self._config = config
        self._collection: Collection = db[
            managed_source_collection_name(config.env_name)
        ]

    # ----------------------------------------------------------------- schema
    def ensure_schema(self) -> None:
        """Apply the ``$jsonSchema`` validator to the collection."""
        try:
            existing = self._db.command(
                "listCollections",
                filter={"name": self._collection.name},
            )
        except PyMongoError as exc:
            raise PersistenceError(
                safe_message="could not list source collections",
                internal_detail=f"{type(exc).__name__}: {exc}",
            ) from exc
        cursor = existing.get("cursor", {})
        first = (cursor.get("firstBatch") or [])
        if first:
            try:
                self._db.command(
                    "collMod",
                    self._collection.name,
                    validator=SOURCE_INSTANCES_VALIDATOR,
                    validationLevel="strict",
                    validationAction="error",
                )
            except PyMongoError as exc:
                raise PersistenceError(
                    safe_message=(
                        "could not apply source validator"
                    ),
                    internal_detail=f"{type(exc).__name__}: {exc}",
                ) from exc
        else:
            try:
                self._db.create_collection(
                    self._collection.name,
                    validator=SOURCE_INSTANCES_VALIDATOR,
                    validationLevel="strict",
                    validationAction="error",
                )
            except PyMongoError as exc:
                raise PersistenceError(
                    safe_message=(
                        "could not create source_instances "
                        "collection"
                    ),
                    internal_detail=f"{type(exc).__name__}: {exc}",
                ) from exc

    def ensure_indexes(self) -> List[str]:
        """Create the documented index set; return the names created."""
        created: List[str] = []
        for spec in INDEX_SPECS:
            try:
                self._collection.create_index(
                    spec["key"],
                    name=spec["name"],
                    unique=spec.get("unique", False),
                )
                created.append(spec["name"])
            except PyMongoError as exc:
                raise PersistenceError(
                    safe_message=(
                        "could not create source_instances index"
                    ),
                    internal_detail=f"{type(exc).__name__}: {exc}",
                ) from exc
        return created

    # ----------------------------------------------------------------- writes
    def create(self, instance: SourceInstance) -> SourceInstance:
        """Persist a new instance; raise on duplicate."""
        if not isinstance(instance, SourceInstance):
            raise SourcePersistenceError(
                safe_message="could not persist source instance",
                internal_detail=(
                    f"expected SourceInstance, "
                    f"got {type(instance).__name__}"
                ),
            )
        doc = instance.to_canonical_dict()
        try:
            self._collection.insert_one(doc)
        except DuplicateKeyError as exc:
            raise DuplicateSourceInstanceError(
                safe_message=(
                    f"source instance "
                    f"{instance.source_instance_id!r} "
                    "already exists"
                ),
                internal_detail=str(exc)[:512],
            ) from exc
        except PyMongoError as exc:
            raise SourcePersistenceError(
                safe_message="could not persist source instance",
                internal_detail=f"{type(exc).__name__}: {exc}",
            ) from exc
        return instance

    def upsert(self, instance: SourceInstance) -> SourceInstance:
        """Replace or insert an instance."""
        if not isinstance(instance, SourceInstance):
            raise SourcePersistenceError(
                safe_message="could not persist source instance",
                internal_detail=(
                    f"expected SourceInstance, "
                    f"got {type(instance).__name__}"
                ),
            )
        doc = instance.to_canonical_dict()
        try:
            self._collection.replace_one(
                {"source_instance_id": instance.source_instance_id},
                doc,
                upsert=True,
            )
        except PyMongoError as exc:
            raise SourcePersistenceError(
                safe_message="could not persist source instance",
                internal_detail=f"{type(exc).__name__}: {exc}",
            ) from exc
        return instance

    def retire(self, source_instance_id: SourceInstanceId) -> None:
        """Mark the instance retired (state=retired, retired_at=now)."""
        if not isinstance(source_instance_id, str) or not source_instance_id:
            raise SourcePersistenceError(
                safe_message="could not retire source instance",
                internal_detail="invalid source_instance_id",
            )
        try:
            self._collection.update_one(
                {"source_instance_id": source_instance_id},
                {
                    "$set": {
                        "state": SourceState.RETIRED.value,
                        "retired_at": datetime.now(timezone.utc),
                        "updated_at": datetime.now(timezone.utc),
                    },
                },
            )
        except PyMongoError as exc:
            raise SourcePersistenceError(
                safe_message="could not retire source instance",
                internal_detail=f"{type(exc).__name__}: {exc}",
            ) from exc

    # ----------------------------------------------------------------- reads
    def get(
        self,
        source_instance_id: SourceInstanceId,
    ) -> Optional[SourceInstance]:
        try:
            doc = self._collection.find_one(
                {"source_instance_id": source_instance_id}
            )
        except PyMongoError as exc:
            raise PersistenceError(
                safe_message="could not read source instance",
                internal_detail=f"{type(exc).__name__}: {exc}",
            ) from exc
        if doc is None:
            return None
        return _document_to_instance(doc)

    def get_required(
        self,
        source_instance_id: SourceInstanceId,
    ) -> SourceInstance:
        inst = self.get(source_instance_id)
        if inst is None:
            raise SourceInstanceNotFoundError(
                safe_message=(
                    f"source instance "
                    f"{source_instance_id!r} is not registered"
                ),
                internal_detail="repository.get_required() failed",
            )
        return inst

    def find_by_state(self, state: SourceState) -> List[SourceInstance]:
        try:
            cursor = self._collection.find({"state": state.value})
        except PyMongoError as exc:
            raise PersistenceError(
                safe_message="could not list source instances",
                internal_detail=f"{type(exc).__name__}: {exc}",
            ) from exc
        return [d for d in (_document_to_instance(c) for c in cursor) if d]

    def find_all(self) -> List[SourceInstance]:
        try:
            cursor = self._collection.find({}).sort("created_at", 1)
        except PyMongoError as exc:
            raise PersistenceError(
                safe_message="could not list source instances",
                internal_detail=f"{type(exc).__name__}: {exc}",
            ) from exc
        return [d for d in (_document_to_instance(c) for c in cursor) if d]

    def count(self) -> int:
        try:
            return int(self._collection.count_documents({}))
        except PyMongoError as exc:
            raise PersistenceError(
                safe_message="could not count source instances",
                internal_detail=f"{type(exc).__name__}: {exc}",
            ) from exc


# ----------------------------------------------------------------- helpers
def _document_to_instance(
    doc: Dict[str, Any],
) -> Optional[SourceInstance]:
    """Convert a MongoDB document back into a :class:`SourceInstance`.

    The canonical dict stored on disk uses the safe configuration
    view (``secret_ref_set`` boolean in place of the raw
    ``secret_ref``). This loader re-attaches an empty
    ``secret_ref`` so the Pydantic model can validate without
    the raw secret ever leaving the model layer.
    """
    cleaned = {k: v for k, v in doc.items() if k != "_id"}
    for ts_field in (
        "created_at", "updated_at", "last_validation_at", "retired_at",
    ):
        v = cleaned.get(ts_field)
        if isinstance(v, datetime) and v.tzinfo is None:
            cleaned[ts_field] = v.replace(tzinfo=timezone.utc)
    cfg = cleaned.get("configuration") or {}
    if isinstance(cfg, dict):
        cfg = dict(cfg)
        # Strip the safe-view ``secret_ref_set`` flag and
        # re-attach an empty ``secret_ref``.
        cfg.pop("secret_ref_set", None)
        cfg["secret_ref"] = ""
        cleaned["configuration"] = cfg
    try:
        return SourceInstance.model_validate(cleaned)
    except (PydanticValidationError, ValueError, TypeError) as exc:
        _log.warning(
            "source_repository.document_quarantined",
            extra={
                "source_instance_id": cleaned.get(
                    "source_instance_id"
                ),
                "error_type": type(exc).__name__,
                "error": str(exc)[:512],
            },
        )
        return None


__all__ = [
    "INDEX_SPECS",
    "SOURCE_INSTANCES_VALIDATOR",
    "SourceRepository",
    "managed_source_collection_name",
]