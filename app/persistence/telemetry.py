"""Per-source ingest telemetry (capability patch gap 9).

Reference: docs/PHASE 4/PROSHIELD-BACKEND-CAPABILITY-PATCH-REPORT.md.

The counters are maintained **at the ingress boundary** — the layer
that actually accepts or rejects source telemetry — and persisted in
a dedicated ``source_telemetry`` collection so they survive restarts
and are visible from the analyst plane.

Design:

* one document per ``source_instance_id``; updates are atomic
  ``$inc`` / ``$set`` operations (concurrency-safe, never
  read-then-write).
* counters: ``received`` (batches or events offered), ``accepted``
  (events persisted), ``rejected`` (events refused by validation /
  trust), ``errors`` (ingest failures).
* ``last_event_at`` / ``last_error`` / ``last_error_at`` are the
  truthful recency fields the Sources page renders.

A missing document means "no telemetry yet" — the wire renders
nulls, never zeros dressed up as observations.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from pymongo import ASCENDING
from pymongo.collection import Collection
from pymongo.database import Database
from pymongo.errors import PyMongoError

from ..config import ProShieldConfig


_log = logging.getLogger(__name__)

SOURCE_TELEMETRY_COLLECTION = "source_telemetry"

INDEX_SPECS: List[Dict[str, Any]] = [
    {
        "name": "tel_source_instance_id_unique",
        "key": [("source_instance_id", ASCENDING)],
        "unique": True,
    },
    {"name": "tel_last_event_at", "key": [("last_event_at", -1)]},
]

SOURCE_TELEMETRY_VALIDATOR: Dict[str, Any] = {
    "$jsonSchema": {
        "bsonType": "object",
        "additionalProperties": False,
        "required": ["source_instance_id"],
        "properties": {
            "_id": {"bsonType": "objectId"},
            "source_instance_id": {
                "bsonType": "string",
                "minLength": 8,
                "maxLength": 96,
            },
            "received": {"bsonType": "int"},
            "accepted": {"bsonType": "int"},
            "rejected": {"bsonType": "int"},
            "errors": {"bsonType": "int"},
            "last_event_at": {"bsonType": ["date", "null"]},
            "last_error": {"bsonType": "string", "maxLength": 512},
            "last_error_at": {"bsonType": ["date", "null"]},
            "updated_at": {"bsonType": "date"},
        },
    }
}


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class SourceTelemetryStore:
    """Atomic per-source ingest counters (owning store for gap 9)."""

    def __init__(self, db: Database, config: Optional[ProShieldConfig] = None) -> None:
        self._db = db
        self._collection: Collection = db[SOURCE_TELEMETRY_COLLECTION]

    @property
    def collection(self) -> Collection:
        return self._collection

    def ensure_schema(self) -> None:
        """Best-effort validator application (no-op on dev fakes)."""
        try:
            if (
                SOURCE_TELEMETRY_COLLECTION
                in self._db.list_collection_names()
            ):
                self._db.command(
                    "collMod",
                    SOURCE_TELEMETRY_COLLECTION,
                    validator=SOURCE_TELEMETRY_VALIDATOR,
                )
                return
            self._db.create_collection(
                SOURCE_TELEMETRY_COLLECTION,
                validator=SOURCE_TELEMETRY_VALIDATOR,
            )
        except Exception as exc:  # noqa: BLE001 - fakes lack collMod
            _log.warning(
                "telemetry.ensure_schema_failed error=%s",
                type(exc).__name__,
            )

    def ensure_indexes(self) -> List[str]:
        """Best-effort index creation (no-op on dev fakes)."""
        created: List[str] = []
        try:
            if hasattr(self._collection, "list_indexes"):
                existing = {
                    ix["name"] for ix in self._collection.list_indexes()
                }
            else:
                existing = set()
            for spec in INDEX_SPECS:
                if spec["name"] in existing:
                    continue
                self._collection.create_index(
                    spec["key"],
                    name=spec["name"],
                    unique=spec.get("unique", False),
                )
                created.append(spec["name"])
        except Exception as exc:  # noqa: BLE001 - fakes lack list_indexes
            _log.warning(
                "telemetry.ensure_indexes_failed error=%s",
                type(exc).__name__,
            )
        return created

    # ------------------------------------------------------------------ writes
    def record_accepted(
        self, source_instance_id: str, *, count: int = 1,
        at: Optional[datetime] = None,
    ) -> None:
        self._bump(
            source_instance_id,
            inc={"accepted": int(max(0, count))},
            last_event_at=at or _utcnow(),
        )

    def record_rejected(
        self, source_instance_id: str, *, count: int = 1,
        at: Optional[datetime] = None, message: str = "",
    ) -> None:
        now = at or _utcnow()
        self._bump(
            source_instance_id,
            inc={"rejected": int(max(0, count))},
            last_event_at=now,
        )
        if message:
            try:
                self._collection.update_one(
                    {"source_instance_id": str(source_instance_id)[:96]},
                    {
                        "$set": {
                            "last_error": str(message)[:512],
                            "last_error_at": now,
                        },
                    },
                )
            except PyMongoError as exc:
                _log.warning(
                    "telemetry.reject_message_failed error=%s",
                    type(exc).__name__,
                )

    def record_received(
        self, source_instance_id: str, *, count: int = 1,
        at: Optional[datetime] = None,
    ) -> None:
        """Count events OFFERED to the ingress (accepted + rejected)."""
        self._bump(
            source_instance_id,
            inc={"received": int(max(0, count))},
            last_event_at=at or _utcnow(),
        )

    def record_error(
        self, source_instance_id: str, *, message: str,
        at: Optional[datetime] = None,
    ) -> None:
        now = at or _utcnow()
        try:
            self._collection.update_one(
                {"source_instance_id": str(source_instance_id)[:96]},
                {
                    "$inc": {"errors": 1, "received": 0},
                    "$set": {
                        "last_error": str(message or "")[:512],
                        "last_error_at": now,
                        "updated_at": now,
                    },
                    "$setOnInsert": {
                        "last_event_at": None,
                    },
                },
                upsert=True,
            )
        except PyMongoError as exc:
            _log.warning(
                "telemetry.record_error_failed error=%s",
                type(exc).__name__,
            )

    def _bump(
        self,
        source_instance_id: str,
        *,
        inc: Dict[str, int],
        last_event_at: Optional[datetime],
    ) -> None:
        now = _utcnow()
        update: Dict[str, Any] = {
            "$inc": dict(inc),
            "$set": {"updated_at": now},
            "$setOnInsert": {"last_error": "", "last_error_at": None},
        }
        if last_event_at is not None:
            update["$max"] = {"last_event_at": last_event_at}
        try:
            self._collection.update_one(
                {"source_instance_id": str(source_instance_id)[:96]},
                update,
                upsert=True,
            )
        except PyMongoError as exc:
            _log.warning(
                "telemetry.bump_failed error=%s", type(exc).__name__,
            )

    # ------------------------------------------------------------------ reads
    def snapshot(self, source_instance_id: str) -> Optional[Dict[str, Any]]:
        doc = self._collection.find_one(
            {"source_instance_id": str(source_instance_id)[:96]}
        )
        return _document_to_snapshot(doc) if doc else None

    def snapshot_all(self) -> Dict[str, Dict[str, Any]]:
        try:
            docs = list(self._collection.find({}))
        except PyMongoError as exc:
            _log.warning(
                "telemetry.snapshot_all_failed error=%s",
                type(exc).__name__,
            )
            return {}
        out: Dict[str, Dict[str, Any]] = {}
        for doc in docs:
            snap = _document_to_snapshot(doc)
            if snap is not None:
                out[snap["source_instance_id"]] = snap
        return out

    def ensure_ready(self) -> None:
        self.ensure_schema()
        self.ensure_indexes()


def _document_to_snapshot(doc: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    sid = doc.get("source_instance_id")
    if not sid:
        return None
    last_event = doc.get("last_event_at")
    last_error_at = doc.get("last_error_at")
    return {
        "source_instance_id": sid,
        "received": int(doc.get("received") or 0),
        "accepted": int(doc.get("accepted") or 0),
        "rejected": int(doc.get("rejected") or 0),
        "errors": int(doc.get("errors") or 0),
        "last_event_at": (
            last_event.isoformat()
            if isinstance(last_event, datetime) else None
        ),
        "last_error": str(doc.get("last_error") or "") or None,
        "last_error_at": (
            last_error_at.isoformat()
            if isinstance(last_error_at, datetime) else None
        ),
    }


__all__ = [
    "INDEX_SPECS",
    "SOURCE_TELEMETRY_COLLECTION",
    "SOURCE_TELEMETRY_VALIDATOR",
    "SourceTelemetryStore",
]
