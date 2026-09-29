"""Persisted Capability audit trail (Phase 5.1, master-plan §18.27).

§18.17/§18.23/§18.27 require capability writes to be audited with
``actor / action / capability_id / diff``. Log lines alone do not
satisfy the requirement, so every successful capability write appends
an immutable record to the ``capability_audit`` collection.

Design notes:
* append-only: nothing in Phase 5.1 updates or deletes audit records.
* bounded: ``before`` / ``after`` snapshots carry only the tracked
  administrative fields (never the full document), and each string is
  length-capped so a hostile payload cannot bloat the audit store.
* failure semantics: the audit write happens AFTER the state change is
  committed (standalone MongoDB has no multi-document transactions).
  If the audit insert fails, the failure is logged at ERROR level and
  the operation result is still returned — the persisted state stays
  truthful and the audit gap is loudly visible in the server log.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from pymongo import ASCENDING, DESCENDING
from pymongo.errors import PyMongoError

_log = logging.getLogger(__name__)

CAPABILITY_AUDIT_COLLECTION = "capability_audit"

MAX_AUDIT_FIELD_LEN = 256

#: Administrative fields tracked in before/after snapshots and diffs.
AUDIT_TRACKED_FIELDS = (
    "name",
    "description",
    "responsibility",
    "implementation_ref",
    "version",
    "status",
)

CAPABILITY_AUDIT_INDEX_SPECS: List[Dict[str, Any]] = [
    {"name": "capaudit_capability_id", "key": [("capability_id", ASCENDING)]},
    {"name": "capaudit_at", "key": [("at", DESCENDING)]},
]

CAPABILITY_AUDIT_VALIDATOR: Dict[str, Any] = {
    "$jsonSchema": {
        "bsonType": "object",
        "additionalProperties": False,
        "required": ["action", "actor", "capability_id", "at"],
        "properties": {
            "_id": {"bsonType": "objectId"},
            "action": {"bsonType": "string", "minLength": 1, "maxLength": 32},
            "actor": {"bsonType": "string", "minLength": 1, "maxLength": 128},
            "capability_id": {
                "bsonType": "string",
                "minLength": 5,
                "maxLength": 64,
                "pattern": r"^cap-[a-z][a-z0-9-]{1,47}$",
            },
            "human_id": {"bsonType": ["string", "null"], "maxLength": 32},
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


def snapshot_capability(capability: Any) -> Dict[str, Any]:
    """Bounded administrative snapshot used for ``before`` / ``after``."""
    out: Dict[str, Any] = {}
    for field in AUDIT_TRACKED_FIELDS:
        out[field] = _cap(getattr(capability, field, None))
    return out


def build_audit_record(
    *,
    action: str,
    actor: str,
    capability_id: str,
    human_id: Optional[str] = None,
    before: Optional[Dict[str, Any]] = None,
    after: Optional[Dict[str, Any]] = None,
    at: Optional[datetime] = None,
) -> Dict[str, Any]:
    """Build one append-only audit document (§18.27 shape)."""
    changed = sorted(
        key
        for key in set(dict(before or {})) | set(dict(after or {}))
        if dict(before or {}).get(key) != dict(after or {}).get(key)
    )
    return {
        "action": str(action)[:32],
        "actor": str(actor or "system")[:128],
        "capability_id": str(capability_id),
        "human_id": (str(human_id) if human_id else None),
        "before": dict(before or {}),
        "after": dict(after or {}),
        "changed_fields": changed[:32],
        "at": at or datetime.now(timezone.utc),
    }


def append_audit_record(collection: Any, record: Dict[str, Any]) -> bool:
    """Insert one audit record. Returns True on success.

    Never raises: audit persistence problems are logged at ERROR level
    (see module docstring for the failure-semantics decision).
    """
    try:
        collection.insert_one(dict(record))
        return True
    except PyMongoError as exc:
        _log.error(
            "capability_audit_write_failed capability_id=%s action=%s error=%s",
            record.get("capability_id"),
            record.get("action"),
            f"{type(exc).__name__}: {exc}"[:256],
        )
        return False
    except Exception as exc:  # noqa: BLE001 - fake backends
        _log.error(
            "capability_audit_write_failed capability_id=%s action=%s error=%s",
            record.get("capability_id"),
            record.get("action"),
            f"{type(exc).__name__}: {exc}"[:256],
        )
        return False


def read_audit_records(
    collection: Any,
    capability_id: str,
    *,
    limit: int = 50,
) -> List[Dict[str, Any]]:
    """Bounded, newest-first audit read for one capability."""
    bounded = max(1, min(int(limit or 50), 200))
    try:
        cursor = (
            collection.find({"capability_id": capability_id})
            .sort("at", DESCENDING)
            .limit(bounded)
        )
        out: List[Dict[str, Any]] = []
        for raw in cursor:
            doc = dict(raw or {})
            doc.pop("_id", None)
            at = doc.get("at")
            if isinstance(at, datetime):
                if at.tzinfo is None:
                    doc["at"] = at.replace(tzinfo=timezone.utc)
                doc["at"] = doc["at"].isoformat()
            out.append(doc)
            if len(out) >= bounded:
                break
        return out
    except PyMongoError as exc:
        _log.error(
            "capability_audit_read_failed capability_id=%s error=%s",
            capability_id,
            f"{type(exc).__name__}: {exc}"[:256],
        )
        return []
    except Exception as exc:  # noqa: BLE001 - fake backends
        _log.error(
            "capability_audit_read_failed capability_id=%s error=%s",
            capability_id,
            f"{type(exc).__name__}: {exc}"[:256],
        )
        return []


__all__ = [
    "AUDIT_TRACKED_FIELDS",
    "CAPABILITY_AUDIT_COLLECTION",
    "CAPABILITY_AUDIT_INDEX_SPECS",
    "CAPABILITY_AUDIT_VALIDATOR",
    "append_audit_record",
    "build_audit_record",
    "read_audit_records",
    "snapshot_capability",
]
