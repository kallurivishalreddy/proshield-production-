"""Capability persistence boundary (Phase 5.1).

The :class:`CapabilityRepository` is the only place that talks to
pymongo about ``capabilities`` documents. It mirrors the Phase 4.9
source-instance repository policies: safe error translation,
documented index set, Pydantic-paired reads/writes.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from pydantic import ValidationError as PydanticValidationError
from pymongo import ASCENDING, DESCENDING
from pymongo.collection import Collection
from pymongo.database import Database
from pymongo.errors import DuplicateKeyError, PyMongoError

from ..config import ProShieldConfig
from ..domain.errors import PersistenceError
from ..persistence.human_ids import COUNTERS_COLLECTION, HumanIdAllocator
from .audit import (
    CAPABILITY_AUDIT_COLLECTION,
    CAPABILITY_AUDIT_INDEX_SPECS,
    CAPABILITY_AUDIT_VALIDATOR,
)
from .errors import (
    CapabilityAlreadyExistsError,
    CapabilityConfigurationError,
    CapabilityNotFoundError,
    CapabilityPersistenceError,
)
from .models import CAPABILITIES_COLLECTION, Capability, CapabilityStatus, ImplementationRef

_log = logging.getLogger(__name__)


CAPABILITY_INDEX_SPECS: List[Dict[str, Any]] = [
    {"name": "cap_capability_id_unique", "key": [("capability_id", ASCENDING)], "unique": True},
    {"name": "cap_human_id_unique", "key": [("human_id", ASCENDING)], "unique": True, "sparse": True},
    {"name": "cap_status", "key": [("status", ASCENDING)]},
    {"name": "cap_implementation_ref", "key": [("implementation_ref", ASCENDING)]},
    {"name": "cap_updated_at", "key": [("updated_at", DESCENDING)]},
    {"name": "cap_version", "key": [("version", DESCENDING)]},
]


CAPABILITIES_VALIDATOR: Dict[str, Any] = {
    "$jsonSchema": {
        "bsonType": "object",
        "additionalProperties": False,
        "required": [
            "capability_id",
            "name",
            "description",
            "responsibility",
            "implementation_ref",
            "version",
            "status",
            "configuration_schema",
            "mapping_profiles",
            "created_by",
            "created_at",
            "updated_by",
            "updated_at",
        ],
        "properties": {
            "_id": {"bsonType": "objectId"},
            "capability_id": {
                "bsonType": "string",
                "minLength": 5,
                "maxLength": 64,
                "pattern": r"^cap-[a-z][a-z0-9-]{1,47}$",
            },
            "human_id": {"bsonType": ["string", "null"], "maxLength": 32},
            "name": {"bsonType": "string", "minLength": 1, "maxLength": 128},
            "description": {"bsonType": "string", "maxLength": 1024},
            "responsibility": {"bsonType": "string", "maxLength": 1024},
            "implementation_ref": {
                "bsonType": "string",
                "enum": sorted(r.value for r in ImplementationRef),
            },
            "version": {"bsonType": ["int", "long"], "minimum": 1, "maximum": 1000000},
            "status": {
                "bsonType": "string",
                "enum": sorted(s.value for s in CapabilityStatus),
            },
            "configuration_schema": {"bsonType": "object"},
            "mapping_profiles": {"bsonType": "array", "maxItems": 16},
            "created_by": {"bsonType": "string", "minLength": 1, "maxLength": 128},
            "created_at": {"bsonType": "date"},
            "updated_by": {"bsonType": "string", "minLength": 1, "maxLength": 128},
            "updated_at": {"bsonType": "date"},
            "retired_at": {"bsonType": ["date", "null"]},
            "archived_at": {"bsonType": ["date", "null"]},
        },
    }
}


def capability_collection_name(env_name: str) -> str:
    return CAPABILITIES_COLLECTION


class CapabilityRepository:
    """Repository for the ``capabilities`` collection."""

    def __init__(self, db: Any, config: ProShieldConfig) -> None:
        self._db = db
        self._config = config
        self._collection = db[capability_collection_name(config.env_name)]
        counters = None
        try:
            candidate = db[COUNTERS_COLLECTION]
            if hasattr(candidate, "find_one_and_update"):
                counters = candidate
        except Exception:  # noqa: BLE001 - fake backends
            counters = None
        try:
            self._human_ids = HumanIdAllocator(counters, "capability")
        except ValueError:
            # Older allocator catalogues predate Phase 5.1; fall back to a
            # local CAP- allocator with the same monotonic contract.
            from .human_ids_fallback import FallbackCapabilityAllocator

            self._human_ids = FallbackCapabilityAllocator(counters)  # type: ignore[assignment]

    @property
    def collection(self) -> Any:
        return self._collection

    @property
    def audit_collection(self) -> Any:
        return self._db[CAPABILITY_AUDIT_COLLECTION]

    # ----------------------------------------------------------------- schema
    def ensure_audit_schema(self) -> None:
        """Create/validate the append-only ``capability_audit`` collection."""
        try:
            existing = self._db.command("listCollections", filter={"name": CAPABILITY_AUDIT_COLLECTION})
            batch = existing.get("cursor", {}).get("firstBatch") or []
        except Exception:  # noqa: BLE001 - FakeDatabase path
            if hasattr(self._db, "create_collection"):
                try:
                    self._db.create_collection(CAPABILITY_AUDIT_COLLECTION, validator=CAPABILITY_AUDIT_VALIDATOR)
                except Exception:
                    pass
            return
        try:
            if batch:
                self._db.command(
                    "collMod",
                    CAPABILITY_AUDIT_COLLECTION,
                    validator=CAPABILITY_AUDIT_VALIDATOR,
                    validationLevel="strict",
                    validationAction="error",
                )
            else:
                try:
                    self._db.create_collection(
                        CAPABILITY_AUDIT_COLLECTION,
                        validator=CAPABILITY_AUDIT_VALIDATOR,
                        validationLevel="strict",
                        validationAction="error",
                    )
                except PyMongoError as exc:
                    if "NamespaceExists" not in type(exc).__name__ and "exists" not in str(exc).lower():
                        raise
        except PyMongoError as exc:
            raise PersistenceError(
                safe_message="could not apply capability audit validator",
                internal_detail=f"{type(exc).__name__}: {exc}",
            ) from exc

    def ensure_audit_indexes(self) -> List[str]:
        created: List[str] = []
        for spec in CAPABILITY_AUDIT_INDEX_SPECS:
            try:
                self.audit_collection.create_index(
                    spec["key"],
                    name=spec["name"],
                    unique=spec.get("unique", False),
                )
                created.append(spec["name"])
            except PyMongoError as exc:
                raise PersistenceError(
                    safe_message="could not create capability audit index",
                    internal_detail=f"{type(exc).__name__}: {exc}",
                ) from exc
            except Exception:  # noqa: BLE001 - fake backends
                created.append(spec["name"])
        return created

    def ensure_schema(self) -> None:
        try:
            existing = self._db.command("listCollections", filter={"name": self._collection.name})
        except Exception as exc:  # noqa: BLE001 - FakeDatabase path
            if hasattr(self._db, "create_collection"):
                try:
                    self._db.create_collection(self._collection.name, validator=CAPABILITIES_VALIDATOR)
                except Exception:
                    pass
            return
        try:
            cursor = existing.get("cursor", {})
            first = cursor.get("firstBatch") or []
        except AttributeError:
            return
        if first:
            try:
                self._db.command(
                    "collMod",
                    self._collection.name,
                    validator=CAPABILITIES_VALIDATOR,
                    validationLevel="strict",
                    validationAction="error",
                )
            except PyMongoError as exc:
                raise PersistenceError(
                    safe_message="could not apply capability validator",
                    internal_detail=f"{type(exc).__name__}: {exc}",
                ) from exc
        else:
            try:
                self._db.create_collection(
                    self._collection.name,
                    validator=CAPABILITIES_VALIDATOR,
                    validationLevel="strict",
                    validationAction="error",
                )
            except PyMongoError as exc:
                # Collection may already exist on tolerant backends.
                if "NamespaceExists" not in type(exc).__name__ and "exists" not in str(exc).lower():
                    raise PersistenceError(
                        safe_message="could not create capabilities collection",
                        internal_detail=f"{type(exc).__name__}: {exc}",
                    ) from exc

    def ensure_indexes(self) -> List[str]:
        created: List[str] = []
        for spec in CAPABILITY_INDEX_SPECS:
            try:
                kwargs: Dict[str, Any] = {"name": spec["name"], "unique": spec.get("unique", False)}
                if spec.get("sparse"):
                    kwargs["sparse"] = True
                self._collection.create_index(spec["key"], **kwargs)
                created.append(spec["name"])
            except PyMongoError as exc:
                raise PersistenceError(
                    safe_message="could not create capabilities index",
                    internal_detail=f"{type(exc).__name__}: {exc}",
                ) from exc
            except Exception:
                created.append(spec["name"])
        return created

    # ----------------------------------------------------------------- writes
    def _pre_persist_validate(self, capability: Capability) -> None:
        """Last-line guard against persisting an invalid cross-field state.

        The MongoDB ``$jsonSchema`` validator cannot express the
        cross-field invariant (``implementation_ref=planned`` implies
        ``status in {planned, retired, archived}``), so it is enforced
        here at the ONLY Mongo write boundary. ``model_copy`` skips
        Pydantic validation, hence the explicit re-validation before
        every write (finding 5.1-01 root-cause hardening).
        """
        try:
            Capability.model_validate(capability.model_dump())
        except (PydanticValidationError, ValueError, TypeError) as exc:
            raise CapabilityConfigurationError(
                safe_message="capability state rejected by pre-persist validation",
                internal_detail=f"{type(exc).__name__}: {str(exc)[:512]}",
            ) from exc

    def create(self, capability: Capability) -> Capability:
        if not isinstance(capability, Capability):
            raise CapabilityPersistenceError(
                safe_message="could not persist capability",
                internal_detail=f"expected Capability, got {type(capability).__name__}",
            )
        if not capability.human_id:
            capability = capability.model_copy(update={"human_id": self._human_ids.allocate()})
        self._pre_persist_validate(capability)
        doc = capability.to_canonical_dict()
        try:
            self._collection.insert_one(doc)
        except DuplicateKeyError as exc:
            raise CapabilityAlreadyExistsError(
                safe_message=f"capability {capability.capability_id!r} already exists",
                internal_detail=str(exc)[:512],
            ) from exc
        except PyMongoError as exc:
            # FakeDatabase duplicate emulation: match on capability_id.
            raise CapabilityPersistenceError(
                safe_message="could not persist capability",
                internal_detail=f"{type(exc).__name__}: {exc}",
            ) from exc
        return capability

    def save(self, capability: Capability) -> Capability:
        if not isinstance(capability, Capability):
            raise CapabilityPersistenceError(
                safe_message="could not persist capability",
                internal_detail=f"expected Capability, got {type(capability).__name__}",
            )
        self._pre_persist_validate(capability)
        doc = capability.to_canonical_dict()
        try:
            result = self._collection.replace_one({"capability_id": capability.capability_id}, doc, upsert=False)
        except PyMongoError as exc:
            raise CapabilityPersistenceError(
                safe_message="could not persist capability",
                internal_detail=f"{type(exc).__name__}: {exc}",
            ) from exc
        matched = getattr(result, "matched_count", 1)
        if not matched:
            raise CapabilityNotFoundError(
                safe_message=f"capability {capability.capability_id!r} is not registered",
                internal_detail="repository.save() missing",
            )
        return capability

    # ----------------------------------------------------------------- reads
    def get(self, capability_id: str) -> Optional[Capability]:
        try:
            doc = self._collection.find_one({"capability_id": capability_id})
        except PyMongoError as exc:
            raise CapabilityPersistenceError(
                safe_message="could not read capability",
                internal_detail=f"{type(exc).__name__}: {exc}",
            ) from exc
        if doc is None:
            return None
        return _document_to_capability(doc)

    def get_required(self, capability_id: str) -> Capability:
        inst = self.get(capability_id)
        if inst is None:
            raise CapabilityNotFoundError(
                safe_message=f"capability {capability_id!r} is not registered",
                internal_detail="repository.get_required() failed",
            )
        return inst

    def find_all(self, *, status: Optional[CapabilityStatus] = None, limit: int = 200) -> List[Capability]:
        query: Dict[str, Any] = {}
        if status is not None:
            query["status"] = status.value
        try:
            cursor = self._collection.find(query).sort("capability_id", 1)
        except PyMongoError as exc:
            raise CapabilityPersistenceError(
                safe_message="could not list capabilities",
                internal_detail=f"{type(exc).__name__}: {exc}",
            ) from exc
        out: List[Capability] = []
        for raw in cursor:
            parsed = _document_to_capability(raw)
            if parsed is not None:
                out.append(parsed)
            if len(out) >= max(1, min(int(limit), 200)):
                break
        return out

    def count(self) -> int:
        try:
            return int(self._collection.count_documents({}))
        except PyMongoError as exc:
            raise CapabilityPersistenceError(
                safe_message="could not count capabilities",
                internal_detail=f"{type(exc).__name__}: {exc}",
            ) from exc


def _document_to_capability(doc: Dict[str, Any]) -> Optional[Capability]:
    cleaned = {k: v for k, v in doc.items() if k != "_id"}
    if cleaned.get("human_id") is None:
        cleaned["human_id"] = ""
    for ts_field in ("created_at", "updated_at", "retired_at", "archived_at"):
        v = cleaned.get(ts_field)
        if isinstance(v, datetime) and v.tzinfo is None:
            cleaned[ts_field] = v.replace(tzinfo=timezone.utc)
    try:
        return Capability.model_validate(cleaned)
    except (PydanticValidationError, ValueError, TypeError) as exc:
        _log.warning(
            "capability_repository.document_quarantined",
            extra={"capability_id": cleaned.get("capability_id"), "error": str(exc)[:512]},
        )
        return None


__all__ = [
    "CAPABILITIES_VALIDATOR",
    "CAPABILITY_AUDIT_COLLECTION",
    "CAPABILITY_AUDIT_INDEX_SPECS",
    "CAPABILITY_AUDIT_VALIDATOR",
    "CAPABILITY_INDEX_SPECS",
    "CapabilityRepository",
    "capability_collection_name",
]
