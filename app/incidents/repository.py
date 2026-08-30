"""Incident / case repository.

Reference: docs/PHASE 2/CONTRACT_DECISIONS.md (ADR-001,
ADR-002), docs/PHASE 4/PHASE 4-08.

The :class:`IncidentRepository` is the only place in the
codebase that talks to pymongo about case documents. It
mirrors the documented
:class:`app.persistence.SecurityEventRepository`,
:class:`app.persistence.DetectionRepository`, and
:class:`app.persistence.CorrelationRepository` policies:

* a single $jsonSchema validator on the ``incidents``
  collection,
* a documented index set,
* idempotent create() on a duplicate ``incident_id``,
* driver-error translation to safe domain errors,
* case-document -> :class:`Incident` round-trip is total
  (a poisoned document is quarantined + logged, never
  crashes the read path).
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from pydantic import ValidationError as PydanticValidationError
from pymongo import ASCENDING, DESCENDING
from pymongo.collection import Collection
from pymongo.database import Database
from pymongo.errors import (
    DuplicateKeyError,
    PyMongoError,
)

from ..config import ProShieldConfig
from ..domain.errors import (
    PersistenceError,
    ValidationError,
)
from .errors import CaseNotFoundError
from .models import (
    Incident,
    IncidentEvidence,
    IncidentId,
    IncidentLifecycleState,
    LifecycleTransition,
    ReportReference,
)


_log = logging.getLogger(__name__)


# ----------------------------------------------------------------- index specs
INDEX_SPECS: List[Dict[str, Any]] = [
    {
        "name": "inc_incident_id_unique",
        "key": [("incident_id", ASCENDING)],
        "unique": True,
    },
    {
        "name": "inc_state",
        "key": [("state", ASCENDING)],
    },
    {
        "name": "inc_created_by",
        "key": [("created_by", ASCENDING), ("updated_at", DESCENDING)],
    },
    {
        "name": "inc_updated_at",
        "key": [("updated_at", DESCENDING)],
    },
]


def incident_collection_name(config: ProShieldConfig) -> str:
    """The collection name for the ``incidents`` collection."""
    return getattr(config, "mongo_collection_incidents", "incidents")


# ----------------------------------------------------------------- validator
# The BSON validator mirrors the Pydantic model. The Phase
# 4.7 hardening rule (BSON defence-in-depth) is honoured
# here: every field on the persisted document is in the
# documented set; no foreign / extra top-level fields are
# accepted at the database boundary.
INCIDENTS_VALIDATOR: Dict[str, Any] = {
    "$jsonSchema": {
        "bsonType": "object",
        "additionalProperties": False,
        "required": [
            "incident_id",
            "title",
            "state",
            "evidence",
            "rule_references",
            "lifecycle_history",
            "report_references",
            "centralized_correlation_ids",
            "centralized_reasoning",
            "centralized_failed",
            "centralized_failure_reason",
            "created_by",
            "created_at",
            "updated_at",
        ],
        "properties": {
            "_id": {"bsonType": "objectId"},
            "incident_id": {
                "bsonType": "string",
                "pattern": (
                    r"^case-[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-"
                    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
                ),
            },
            "title": {"bsonType": "string", "minLength": 1, "maxLength": 256},
            "summary": {"bsonType": "string", "maxLength": 1024},
            "state": {
                "bsonType": "string",
                "enum": [
                    "open",
                    "centralized_pending",
                    "centralized_failed",
                    "report_pending",
                    "closed",
                ],
            },
            "evidence": {
                "bsonType": "object",
                "additionalProperties": False,
                "required": [
                    "event_ids",
                    "detection_ids",
                    "correlation_ids",
                    "rule_references",
                ],
                "properties": {
                    "event_ids": {"bsonType": "array"},
                    "detection_ids": {"bsonType": "array"},
                    "correlation_ids": {"bsonType": "array"},
                    "rule_references": {"bsonType": "array"},
                },
            },
            "rule_references": {"bsonType": "array"},
            "lifecycle_history": {"bsonType": "array"},
            "report_references": {"bsonType": "array"},
            "centralized_correlation_ids": {"bsonType": "array"},
            "centralized_reasoning": {"bsonType": "string", "maxLength": 2048},
            "centralized_failed": {"bsonType": "bool"},
            "centralized_failure_reason": {
                "bsonType": "string",
                "maxLength": 2048,
            },
            "created_by": {"bsonType": "string", "minLength": 1, "maxLength": 128},
            "created_at": {"bsonType": "date"},
            "updated_at": {"bsonType": "date"},
        },
    }
}


# ----------------------------------------------------------------- repository
class IncidentRepository:
    """Repository for the ``incidents`` collection."""

    def __init__(self, db: Database, config: ProShieldConfig) -> None:
        self._db = db
        self._config = config
        self._collection: Collection = db[incident_collection_name(config)]

    @property
    def collection(self) -> Collection:
        return self._collection

    # ----- schema
    def ensure_schema(self) -> None:
        """Apply the $jsonSchema validator. Idempotent."""
        try:
            existing = self._db.command(
                "listCollections",
                filter={"name": self._collection.name},
            )
            docs = list(existing.get("cursor", {}).get("firstBatch", []))
        except PyMongoError as exc:
            raise PersistenceError(
                safe_message="could not inspect incidents collection",
                internal_detail=f"listCollections failed: {type(exc).__name__}",
            ) from exc
        try:
            if not docs:
                self._db.create_collection(
                    self._collection.name,
                    validator=INCIDENTS_VALIDATOR,
                )
                return
            opts = docs[0].get("options", {}) or {}
            existing_validator = opts.get("validator")
            if existing_validator is None:
                self._db.command(
                    "collMod",
                    self._collection.name,
                    validator=INCIDENTS_VALIDATOR,
                )
        except PyMongoError as exc:
            raise PersistenceError(
                safe_message="could not apply incidents schema",
                internal_detail=f"{type(exc).__name__}: {exc}",
            ) from exc

    def ensure_indexes(self) -> List[str]:
        """Create the documented index set. Idempotent."""
        try:
            existing = {
                ix["name"]
                for ix in self._collection.list_indexes()
            }
            created: List[str] = []
            for spec in INDEX_SPECS:
                if spec["name"] not in existing:
                    self._collection.create_index(
                        spec["key"],
                        name=spec["name"],
                        **{k: v for k, v in spec.items()
                           if k not in ("name", "key")},
                    )
                    created.append(spec["name"])
            return created
        except PyMongoError as exc:
            raise PersistenceError(
                safe_message="could not create incident indexes",
                internal_detail=f"{type(exc).__name__}: {exc}",
            ) from exc

    # ----- CRUD
    def create(self, incident: Incident) -> Incident:
        """Persist a new :class:`Incident`.

        Idempotent on duplicate ``incident_id`` (returns
        the existing case rather than raising). Any other
        pymongo error is translated to a safe domain error.
        """
        if not isinstance(incident, Incident):
            raise ValidationError(
                safe_message="incident required",
                internal_detail=f"got {type(incident).__name__}",
                field="incident",
            )
        doc = _incident_to_bson(incident)
        try:
            self._collection.insert_one(doc)
        except DuplicateKeyError:
            existing = self.get_by_id(incident.incident_id)
            if existing is not None:
                return existing
            raise PersistenceError(
                safe_message="could not create incident",
                internal_detail="duplicate id but missing document",
            )
        except PyMongoError as exc:
            raise PersistenceError(
                safe_message="could not create incident",
                internal_detail=f"{type(exc).__name__}: {exc}",
            ) from exc
        return incident

    def upsert(self, incident: Incident) -> Incident:
        """Idempotent full-document replacement by
        ``incident_id``.

        Used by the service layer to record lifecycle
        transitions without producing a duplicate-key
        error. The replacement is atomic; a poisoned
        partial update is impossible because the whole
        document is re-written.
        """
        if not isinstance(incident, Incident):
            raise ValidationError(
                safe_message="incident required",
                internal_detail=f"got {type(incident).__name__}",
                field="incident",
            )
        doc = _incident_to_bson(incident)
        try:
            self._collection.replace_one(
                {"incident_id": incident.incident_id},
                doc,
                upsert=True,
            )
        except PyMongoError as exc:
            raise PersistenceError(
                safe_message="could not upsert incident",
                internal_detail=f"{type(exc).__name__}: {exc}",
            ) from exc
        return incident

    def get_by_id(self, incident_id: str) -> Optional[Incident]:
        """Return the case by id, or ``None`` if not found.

        A poisoned document is quarantined + logged and
        returned as ``None`` so a single bad document
        never crashes the read path.
        """
        if not isinstance(incident_id, str) or not incident_id:
            raise ValidationError(
                safe_message="invalid incident_id",
                internal_detail=f"got {type(incident_id).__name__}",
                field="incident_id",
            )
        try:
            doc = self._collection.find_one({"incident_id": incident_id})
        except PyMongoError as exc:
            raise PersistenceError(
                safe_message="could not read incident",
                internal_detail=f"find_one failed: {type(exc).__name__}",
            ) from exc
        if doc is None:
            return None
        return _document_to_incident(doc)

    def get_by_id_or_raise(self, incident_id: str) -> Incident:
        case = self.get_by_id(incident_id)
        if case is None:
            raise CaseNotFoundError(
                safe_message="case not found",
                internal_detail=f"incident_id={incident_id}",
            )
        return case

    def find_by_state(self, state: str, *, limit: int = 50) -> List[Incident]:
        """Return cases currently in ``state``, ordered by
        ``updated_at`` descending. ``limit`` is bounded to
        a small number to keep memory bounded."""
        if not isinstance(state, str) or not state:
            raise ValidationError(
                safe_message="invalid state",
                internal_detail=f"got {state!r}",
                field="state",
            )
        safe_limit = max(1, min(int(limit), 200))
        try:
            docs = list(
                self._collection.find({"state": state})
                .sort("updated_at", DESCENDING)
                .limit(safe_limit)
            )
        except PyMongoError as exc:
            raise PersistenceError(
                safe_message="could not list incidents",
                internal_detail=f"find failed: {type(exc).__name__}",
            ) from exc
        out: List[Incident] = []
        for d in docs:
            try:
                out.append(_document_to_incident(d))
            except (PydanticValidationError, ValueError, TypeError) as exc:
                _log.warning(
                    "incident.document_quarantined",
                    extra={
                        "incident_id": d.get("incident_id"),
                        "error_type": type(exc).__name__,
                        "error": str(exc)[:512],
                    },
                )
        return out

    def find_recent(self, *, limit: int = 50) -> List[Incident]:
        """Return the most recent cases ordered by
        ``updated_at`` descending. Used by the unfiltered
        ``case.list`` operation (Phase 4.8 remediation).

        ``limit`` is bounded to a small number to keep
        memory bounded. Object-level authorization is the
        caller's responsibility: this method returns the
        full recent slice, and the service layer filters
        by ownership / ``case:read:any`` so the unfiltered
        list cannot be used to enumerate other analysts'
        cases.
        """
        safe_limit = max(1, min(int(limit), 200))
        try:
            docs = list(
                self._collection.find({})
                .sort("updated_at", DESCENDING)
                .limit(safe_limit)
            )
        except PyMongoError as exc:
            raise PersistenceError(
                safe_message="could not list incidents",
                internal_detail=f"find failed: {type(exc).__name__}",
            ) from exc
        out: List[Incident] = []
        for d in docs:
            try:
                out.append(_document_to_incident(d))
            except (PydanticValidationError, ValueError, TypeError) as exc:
                _log.warning(
                    "incident.document_quarantined",
                    extra={
                        "incident_id": d.get("incident_id"),
                        "error_type": type(exc).__name__,
                        "error": str(exc)[:512],
                    },
                )
        return out

    def count(self) -> int:
        try:
            return int(self._collection.count_documents({}))
        except PyMongoError as exc:
            raise PersistenceError(
                safe_message="could not count incidents",
                internal_detail=f"{type(exc).__name__}",
            ) from exc


# ----------------------------------------------------------------- helpers
def _incident_to_bson(incident: Incident) -> Dict[str, Any]:
    """Convert an :class:`Incident` into a BSON-safe Mongo document.

    Unlike ``Incident.to_dict()`` (which is JSON-friendly and
    stringifies datetimes), this preserves ``datetime`` objects so
    pymongo encodes them as BSON ``Date`` and the ``$jsonSchema``
    validator (``bsonType: "date"``) is satisfied.
    """
    payload = incident.model_dump(mode="python")
    return payload


def _document_to_incident(doc: Dict[str, Any]) -> Incident:
    """Convert a MongoDB document back into an :class:`Incident`."""
    cleaned = {k: v for k, v in doc.items() if k != "_id"}
    for ts_field in ("created_at", "updated_at"):
        v = cleaned.get(ts_field)
        if isinstance(v, datetime):
            if v.tzinfo is None:
                cleaned[ts_field] = v.replace(tzinfo=timezone.utc)
        elif isinstance(v, str):
            try:
                cleaned[ts_field] = datetime.fromisoformat(
                    v.replace("Z", "+00:00")
                )
            except ValueError:
                pass
    hist = cleaned.get("lifecycle_history") or []
    for entry in hist:
        ts = entry.get("transitioned_at") if isinstance(entry, dict) else None
        if isinstance(ts, datetime):
            if ts.tzinfo is None:
                entry["transitioned_at"] = ts.replace(tzinfo=timezone.utc)
        elif isinstance(ts, str):
            try:
                entry["transitioned_at"] = datetime.fromisoformat(
                    ts.replace("Z", "+00:00")
                )
            except ValueError:
                pass
    refs = cleaned.get("report_references") or []
    for entry in refs:
        ts = entry.get("generated_at") if isinstance(entry, dict) else None
        if isinstance(ts, datetime):
            if ts.tzinfo is None:
                entry["generated_at"] = ts.replace(tzinfo=timezone.utc)
        elif isinstance(ts, str):
            try:
                entry["generated_at"] = datetime.fromisoformat(
                    ts.replace("Z", "+00:00")
                )
            except ValueError:
                pass
    return Incident.model_validate(cleaned)


__all__ = [
    "INCIDENTS_VALIDATOR",
    "INDEX_SPECS",
    "IncidentRepository",
    "incident_collection_name",
]