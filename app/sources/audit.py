"""Persisted Source audit trail (Phase 5.2 — Source Architecture 2.0).

The Phase 5.2 plan requires every migration / trust / lifecycle write that
touches a source instance to be auditable ("no silent security-sensitive
state changes"). Log lines alone do not satisfy that, so every successful
source write appends an immutable record to the ``source_audit``
collection, mirroring the Phase 5.1 ``capability_audit`` design.

Design notes (identical semantics to ``app/capabilities/audit.py``):
* append-only: nothing in Phase 5.2 updates or deletes audit records.
* bounded: before/after snapshots carry only the tracked administrative
  fields, and each string is length-capped.
* failure semantics: the audit write happens AFTER the state change is
  committed (standalone MongoDB has no multi-document transactions). A
  failed audit insert is logged at ERROR level and the result is still
  returned — the persisted state stays truthful and the audit gap is
  loudly visible in the server log.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from pymongo import ASCENDING, DESCENDING
from pymongo.errors import PyMongoError

_log = logging.getLogger(__name__)

SOURCE_AUDIT_COLLECTION = "source_audit"

MAX_AUDIT_FIELD_LEN = 256

#: Administrative fields tracked in before/after snapshots and diffs.
#: ``capability_id``/``capability_version``/``mapping_profile_id`` are
#: included because the Phase 5.2 binding migration is a security-relevant
#: state change that must never happen silently.
AUDIT_TRACKED_FIELDS = (
    "source_type",
    "source",
    "display_name",
    "state",
    "capability_id",
    "capability_version",
    "mapping_profile_id",
    "capability_binding_status",
    "human_id",
)

SOURCE_AUDIT_INDEX_SPECS: List[Dict[str, Any]] = [
    {
        "name": "srcaudit_source_instance_id",
        "key": [("source_instance_id", ASCENDING)],
    },
    {"name": "srcaudit_capability_id", "key": [("capability_id", ASCENDING)]},
    {"name": "srcaudit_at", "key": [("at", DESCENDING)]},
    {"name": "srcaudit_action", "key": [("action", ASCENDING)]},
]

SOURCE_AUDIT_VALIDATOR: Dict[str, Any] = {
    "$jsonSchema": {
        "bsonType": "object",
        "additionalProperties": False,
        "required": [
            "action",
            "actor",
            "source_instance_id",
            "at",
        ],
        "properties": {
            "_id": {"bsonType": "objectId"},
            "action": {
                "bsonType": "string",
                "minLength": 1,
                "maxLength": 48,
            },
            "actor": {
                "bsonType": "string",
                "minLength": 1,
                "maxLength": 128,
            },
            "source_instance_id": {
                "bsonType": "string",
                "minLength": 8,
                "maxLength": 96,
            },
            "human_id": {
                "bsonType": ["string", "null"],
                "maxLength": 32,
            },
            "capability_id": {
                "bsonType": ["string", "null"],
                "minLength": 5,
                "maxLength": 64,
                "pattern": r"^cap-[a-z][a-z0-9-]{1,47}$",
            },
            "reason": {
                "bsonType": ["string", "null"],
                "maxLength": 256,
            },
            "before": {"bsonType": "object"},
            "after": {"bsonType": "object"},
            "changed_fields": {"bsonType": "array", "maxItems": 32},
            "at": {"bsonType": "date"},
        },
    }
}


def _cap(value: Any) -> Any:
    """Bound an audit snapshot value so the store stays small."""
    if isinstance(value, str) and len(value) > MAX_AUDIT_FIELD_LEN:
        return value[:MAX_AUDIT_FIELD_LEN]
    return value


def snapshot_source(source: Any) -> Dict[str, Any]:
    """Bounded administrative snapshot used for ``before`` / ``after``."""
    out: Dict[str, Any] = {}
    for field in AUDIT_TRACKED_FIELDS:
        value = getattr(source, field, None)
        if isinstance(value, datetime):
            value = value.isoformat()
        out[field] = _cap(value)
    return out


def build_audit_record(
    *,
    action: str,
    actor: str,
    source_instance_id: str,
    human_id: Optional[str] = None,
    capability_id: Optional[str] = None,
    reason: Optional[str] = None,
    before: Optional[Dict[str, Any]] = None,
    after: Optional[Dict[str, Any]] = None,
    at: Optional[datetime] = None,
) -> Dict[str, Any]:
    """Build one append-only source audit document."""
    before_d = dict(before or {})
    after_d = dict(after or {})
    changed = sorted(
        key
        for key in set(before_d) | set(after_d)
        if before_d.get(key) != after_d.get(key)
    )
    return {
        "action": str(action)[:48],
        "actor": str(actor or "system")[:128],
        "source_instance_id": str(source_instance_id),
        "human_id": (str(human_id) if human_id else None),
        "capability_id": (str(capability_id) if capability_id else None),
        "reason": (str(reason)[:256] if reason else None),
        "before": before_d,
        "after": after_d,
        "changed_fields": changed[:32],
        "at": at or datetime.now(timezone.utc),
    }


def append_audit_record(collection: Any, record: Dict[str, Any]) -> bool:
    """Insert one audit record. Returns True on success.

    Never raises: audit persistence problems are logged at ERROR level so
    the audit gap is loudly visible (see module docstring).
    """
    try:
        collection.insert_one(dict(record))
        return True
    except PyMongoError as exc:
        _log.error(
            "source_audit_write_failed source_instance_id=%s action=%s "
            "error=%s",
            record.get("source_instance_id"),
            record.get("action"),
            f"{type(exc).__name__}: {exc}"[:256],
        )
        return False
    except Exception as exc:  # noqa: BLE001 - fake backends
        _log.error(
            "source_audit_write_failed source_instance_id=%s action=%s "
            "error=%s",
            record.get("source_instance_id"),
            record.get("action"),
            f"{type(exc).__name__}: {exc}"[:256],
        )
        return False


def _normalize_record(raw: Any) -> Dict[str, Any]:
    doc = dict(raw or {})
    doc.pop("_id", None)
    at = doc.get("at")
    if isinstance(at, datetime):
        if at.tzinfo is None:
            doc["at"] = at.replace(tzinfo=timezone.utc)
        doc["at"] = doc["at"].isoformat()
    return doc


def read_audit_records(
    collection: Any,
    source_instance_id: str,
    *,
    limit: int = 50,
) -> List[Dict[str, Any]]:
    """Bounded, newest-first audit read for one source instance."""
    bounded = max(1, min(int(limit or 50), 200))
    try:
        cursor = (
            collection.find({"source_instance_id": source_instance_id})
            .sort("at", DESCENDING)
            .limit(bounded)
        )
        out: List[Dict[str, Any]] = []
        for raw in cursor:
            out.append(_normalize_record(raw))
            if len(out) >= bounded:
                break
        return out
    except PyMongoError as exc:
        _log.error(
            "source_audit_read_failed source_instance_id=%s error=%s",
            source_instance_id,
            f"{type(exc).__name__}: {exc}"[:256],
        )
        return []
    except Exception as exc:  # noqa: BLE001 - fake backends
        _log.error(
            "source_audit_read_failed source_instance_id=%s error=%s",
            source_instance_id,
            f"{type(exc).__name__}: {exc}"[:256],
        )
        return []


def read_recent_audit_records(
    collection: Any,
    *,
    limit: int = 50,
) -> List[Dict[str, Any]]:
    """Bounded, newest-first audit read across all source instances.

    Used by the migration status surface: a migration run must be
    independently observable without already knowing which source it
    touched.
    """
    bounded = max(1, min(int(limit or 50), 200))
    try:
        cursor = collection.find({}).sort("at", DESCENDING).limit(bounded)
        out: List[Dict[str, Any]] = []
        for raw in cursor:
            out.append(_normalize_record(raw))
            if len(out) >= bounded:
                break
        return out
    except PyMongoError as exc:
        _log.error(
            "source_audit_read_failed error=%s",
            f"{type(exc).__name__}: {exc}"[:256],
        )
        return []
    except Exception as exc:  # noqa: BLE001 - fake backends
        _log.error(
            "source_audit_read_failed error=%s",
            f"{type(exc).__name__}: {exc}"[:256],
        )
        return []


__all__ = [
    "AUDIT_TRACKED_FIELDS",
    "SOURCE_AUDIT_COLLECTION",
    "SOURCE_AUDIT_INDEX_SPECS",
    "SOURCE_AUDIT_VALIDATOR",
    "append_audit_record",
    "build_audit_record",
    "read_audit_records",
    "read_recent_audit_records",
    "snapshot_source",
]