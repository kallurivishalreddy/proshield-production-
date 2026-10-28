"""Notification repository (MongoDB persistence for gap 12).

Mirrors the documented repository policies of the other ProShield
collections: a ``$jsonSchema`` validator, a documented index set
(including a unique id index), driver-error translation to safe
domain errors, and a total read path (a poisoned document is
quarantined + logged, never crashes reads).
"""
from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from pydantic import ValidationError as PydanticValidationError
from pymongo import ASCENDING, DESCENDING, ReturnDocument
from pymongo.collection import Collection
from pymongo.database import Database
from pymongo.errors import DuplicateKeyError, PyMongoError

from ..config import ProShieldConfig
from ..domain.errors import PersistenceError, ValidationError
from .models import (
    MAX_NOTIFICATIONS_LIST,
    NOTIFICATION_KINDS,
    Notification,
    new_notification_id,
)


_log = logging.getLogger(__name__)

NOTIFICATIONS_COLLECTION = "notifications"

INDEX_SPECS: List[Dict[str, Any]] = [
    {
        "name": "ntf_notification_id_unique",
        "key": [("notification_id", ASCENDING)],
        "unique": True,
    },
    {"name": "ntf_created_at", "key": [("created_at", DESCENDING)]},
    {"name": "ntf_kind", "key": [("kind", ASCENDING)]},
    {"name": "ntf_incident_id", "key": [("incident_id", ASCENDING)]},
    {"name": "ntf_event_id", "key": [("event_id", ASCENDING)]},
    {"name": "ntf_read", "key": [("read", ASCENDING)]},
]

NOTIFICATIONS_VALIDATOR: Dict[str, Any] = {
    "$jsonSchema": {
        "bsonType": "object",
        "additionalProperties": False,
        "required": [
            "notification_id",
            "kind",
            "audience_roles",
            "read",
            "created_at",
        ],
        "properties": {
            "_id": {"bsonType": "objectId"},
            "notification_id": {
                "bsonType": "string",
                "minLength": 8,
                "maxLength": 64,
                "pattern": (
                    r"^ntf-[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-"
                    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
                ),
            },
            "kind": {"bsonType": "string", "minLength": 3, "maxLength": 64},
            "incident_id": {"bsonType": "string", "maxLength": 64},
            "human_id": {"bsonType": "string", "maxLength": 32},
            "event_id": {"bsonType": "string", "maxLength": 64},
            "classification": {"bsonType": "string", "maxLength": 32},
            "rule_id": {"bsonType": "string", "maxLength": 64},
            "detection_id": {"bsonType": "string", "maxLength": 64},
            "source_instance_id": {"bsonType": "string", "maxLength": 96},
            "capability_id": {"bsonType": "string", "maxLength": 64},
            "event_time": {"bsonType": ["date", "null"]},
            "evidence_refs": {
                "bsonType": "array",
                "maxItems": 32,
                "items": {"bsonType": "string", "maxLength": 128},
            },
            "explanation": {"bsonType": "string", "maxLength": 512},
            "title": {"bsonType": "string", "maxLength": 512},
            "detail": {"bsonType": "string", "maxLength": 512},
            "actor_subject_id": {"bsonType": "string", "maxLength": 128},
            "audience_roles": {"bsonType": "array"},
            "read": {"bsonType": "bool"},
            "read_by": {"bsonType": "string", "maxLength": 128},
            "read_at": {"bsonType": ["date", "null"]},
            "created_at": {"bsonType": "date"},
        },
    }
}


class NotificationRepository:
    """Repository for the ``notifications`` collection."""

    def __init__(self, db: Database, config: ProShieldConfig) -> None:
        self._db = db
        self._config = config
        self._collection: Collection = db[NOTIFICATIONS_COLLECTION]

    @property
    def collection(self) -> Collection:
        return self._collection

    def ensure_schema(self) -> None:
        try:
            if NOTIFICATIONS_COLLECTION in self._db.list_collection_names():
                self._db.command(
                    "collMod",
                    NOTIFICATIONS_COLLECTION,
                    validator=NOTIFICATIONS_VALIDATOR,
                )
                return
            self._db.create_collection(
                NOTIFICATIONS_COLLECTION,
                validator=NOTIFICATIONS_VALIDATOR,
            )
        except PyMongoError as exc:
            raise PersistenceError(
                safe_message="could not prepare notifications collection",
                internal_detail=f"{type(exc).__name__}: {exc}",
            ) from exc

    def ensure_indexes(self) -> List[str]:
        created: List[str] = []
        existing = {ix["name"] for ix in self._collection.list_indexes()}
        for spec in INDEX_SPECS:
            if spec["name"] in existing:
                continue
            self._collection.create_index(
                spec["key"],
                name=spec["name"],
                unique=spec.get("unique", False),
            )
            created.append(spec["name"])
        return created

    # ----------------------------------------------------------------- writes
    def create(self, notification: Notification) -> Notification:
        if not isinstance(notification, Notification):
            raise ValidationError(
                safe_message="notification required",
                internal_detail=f"got {type(notification).__name__}",
                field="notification",
            )
        doc = _notification_to_bson(notification)
        try:
            self._collection.insert_one(doc)
        except PyMongoError as exc:
            raise PersistenceError(
                safe_message="could not persist notification",
                internal_detail=f"{type(exc).__name__}: {exc}",
            ) from exc
        return notification

    def get(self, notification_id: str) -> Optional[Notification]:
        """Return one notification by id, or ``None`` when absent."""
        if not isinstance(notification_id, str) or not notification_id:
            return None
        try:
            doc = self._collection.find_one(
                {"notification_id": notification_id}
            )
        except PyMongoError as exc:
            raise PersistenceError(
                safe_message="could not read notification",
                internal_detail=f"{type(exc).__name__}: {exc}",
            ) from exc
        if doc is None:
            return None
        return _document_to_notification(doc)

    def create_idempotent(self, notification: Notification) -> Notification:
        """Persist a notification once, keyed by its stable id.

        Unknown-event notifications are derived from a persisted event,
        so replaying the pipeline must not create a second alert. The id
        is deterministic; an existing row is returned unchanged.
        """
        if not isinstance(notification, Notification):
            raise ValidationError(
                safe_message="notification required",
                internal_detail=f"got {type(notification).__name__}",
                field="notification",
            )
        existing = self.get(notification.notification_id)
        if existing is not None:
            return existing
        doc = _notification_to_bson(notification)
        try:
            self._collection.insert_one(doc)
        except DuplicateKeyError:
            existing = self.get(notification.notification_id)
            if existing is not None:
                return existing
            raise PersistenceError(
                safe_message="could not persist notification",
                internal_detail="duplicate notification id without a readable row",
            )
        except PyMongoError as exc:
            raise PersistenceError(
                safe_message="could not persist notification",
                internal_detail=f"{type(exc).__name__}: {exc}",
            ) from exc
        return notification

    def mark_read(
        self, notification_id: str, reader_subject_id: str,
    ) -> Optional[Notification]:
        """Atomically flip ``read`` for one notification.

        Returns the updated notification, or ``None`` when the id is
        unknown (the service turns that into a NotFoundError).
        Idempotent: marking an already-read notification again is a
        no-op that returns the current document.
        """
        if not isinstance(notification_id, str) or not notification_id:
            raise ValidationError(
                safe_message="invalid notification_id",
                internal_detail="empty notification_id",
                field="notification_id",
            )
        try:
            doc = self._collection.find_one_and_update(
                {"notification_id": notification_id},
                {
                    "$set": {
                        "read": True,
                        "read_by": str(reader_subject_id)[:128],
                        "read_at": datetime.now(timezone.utc),
                    },
                },
                return_document=ReturnDocument.AFTER,
            )
        except PyMongoError as exc:
            raise PersistenceError(
                safe_message="could not mark notification read",
                internal_detail=f"{type(exc).__name__}: {exc}",
            ) from exc
        if doc is None:
            return None
        return _document_to_notification(doc)

    # ----------------------------------------------------------------- reads
    def find_for_audience(
        self,
        *,
        role: str,
        subject_id: str,
        unread_only: bool = False,
        limit: Optional[int] = None,
    ) -> List[Notification]:
        """Notifications visible to this identity, newest first.

        Visible = the identity's role is in ``audience_roles`` OR the
        identity is the acting subject of the notification. The
        query is bounded (``limit``) so a large feed cannot blow up
        the response.
        """
        safe_limit = max(1, min(int(limit or 50), MAX_NOTIFICATIONS_LIST))
        query: Dict[str, Any] = {
            "$or": [
                {"audience_roles": role},
                {"actor_subject_id": subject_id},
            ],
        }
        if unread_only:
            query["read"] = False
        try:
            docs = list(
                self._collection.find(query)
                .sort("created_at", DESCENDING)
                .limit(safe_limit)
            )
        except PyMongoError as exc:
            raise PersistenceError(
                safe_message="could not list notifications",
                internal_detail=f"{type(exc).__name__}: {exc}",
            ) from exc
        out: List[Notification] = []
        for d in docs:
            row = _document_to_notification(d)
            if row is not None:
                out.append(row)
        return out

    def count_unread_for_audience(
        self, *, role: str, subject_id: str,
    ) -> int:
        query: Dict[str, Any] = {
            "read": False,
            "$or": [
                {"audience_roles": role},
                {"actor_subject_id": subject_id},
            ],
        }
        try:
            return int(self._collection.count_documents(query))
        except PyMongoError as exc:
            raise PersistenceError(
                safe_message="could not count notifications",
                internal_detail=f"{type(exc).__name__}: {exc}",
            ) from exc

    def count(self) -> int:
        try:
            return int(self._collection.count_documents({}))
        except PyMongoError as exc:
            raise PersistenceError(
                safe_message="could not count notifications",
                internal_detail=f"{type(exc).__name__}",
            ) from exc


# ----------------------------------------------------------------- helpers
def _notification_to_bson(notification: Notification) -> Dict[str, Any]:
    payload = notification.model_dump(mode="python")
    return payload


def _document_to_notification(doc: Dict[str, Any]) -> Optional[Notification]:
    cleaned = {k: v for k, v in doc.items() if k != "_id"}
    if cleaned.get("read_at") is None:
        cleaned.pop("read_at", None)
    for ts_field in ("created_at", "read_at", "event_time"):
        v = cleaned.get(ts_field)
        if isinstance(v, datetime) and v.tzinfo is None:
            cleaned[ts_field] = v.replace(tzinfo=timezone.utc)
    for list_field in ("audience_roles",):
        if isinstance(cleaned.get(list_field), list):
            cleaned[list_field] = tuple(cleaned[list_field])
    try:
        return Notification.model_validate(cleaned)
    except (PydanticValidationError, ValueError, TypeError) as exc:
        _log.warning(
            "notification.document_quarantined",
            extra={
                "notification_id": cleaned.get("notification_id"),
                "error": str(exc)[:512],
            },
        )
        return None


def build_notification(
    *,
    kind: str,
    incident_id: str = "",
    human_id: str = "",
    title: str = "",
    detail: str = "",
    actor_subject_id: str = "",
    audience_roles: tuple = ("admin", "analyst"),
    created_at: Optional[datetime] = None,
    notification_id: Optional[str] = None,
    event_id: str = "",
    classification: str = "",
    rule_id: str = "",
    detection_id: str = "",
    source_instance_id: str = "",
    capability_id: str = "",
    event_time: Optional[datetime] = None,
    evidence_refs: tuple = (),
    explanation: str = "",
) -> Notification:
    """Factory used by the incident service's notification sink."""
    if kind not in NOTIFICATION_KINDS:
        raise ValidationError(
            safe_message="unknown notification kind",
            internal_detail=f"kind={kind!r} not in the closed catalogue",
            field="kind",
        )
    return Notification(
        notification_id=notification_id or new_notification_id(),
        kind=kind,
        incident_id=str(incident_id or "")[:64],
        human_id=str(human_id or "")[:32],
        event_id=str(event_id or "")[:64],
        classification=str(classification or "")[:32],
        rule_id=str(rule_id or "")[:64],
        detection_id=str(detection_id or "")[:64],
        source_instance_id=str(source_instance_id or "")[:96],
        capability_id=str(capability_id or "")[:64],
        event_time=event_time,
        evidence_refs=tuple(str(r)[:128] for r in evidence_refs),
        explanation=str(explanation or "")[:512],
        title=str(title or "")[:512],
        detail=str(detail or "")[:512],
        actor_subject_id=str(actor_subject_id or "")[:128],
        audience_roles=tuple(audience_roles),
        created_at=created_at or datetime.now(timezone.utc),
    )


def _unknown_notification_id(event_id: str) -> str:
    """Deterministic ``ntf-<uuidv7-shape>`` id for one event.

    Replaying the pipeline for the same persisted event must reuse the
    same notification (``create_idempotent``), so the id is derived from
    the event id rather than random.
    """
    raw = hashlib.sha256(
        f"event.unknown|{event_id}".encode("utf-8")
    ).hexdigest()
    raw = raw[:12] + "7" + raw[13:16] + "8" + raw[17:32]
    return (
        "ntf-"
        f"{raw[0:8]}-{raw[8:12]}-{raw[12:16]}-"
        f"{raw[16:20]}-{raw[20:32]}"
    )


def build_unknown_event_notification(
    event: Any,
    *,
    created_at: Optional[datetime] = None,
) -> Notification:
    """Build the ADR-037 unknown-event classification alert.

    The record is derived only from the persisted event's identity and
    provenance. It carries no rule_id, detection_id, severity, incident,
    or case: an unmatched event is not a rule match and is not malicious.
    """
    event_id = str(getattr(event, "event_id", "") or "")
    provenance = getattr(event, "provenance", None)
    source_instance_id = (
        str(getattr(provenance, "source_instance_id", "") or "")
    )
    capability_id = str(getattr(provenance, "capability_id", "") or "")
    source = str(getattr(event, "source", "") or "")
    event_type = str(getattr(event, "event_type", "") or "")
    detail = (
        f"Event {event_id} from {source} ({event_type}) matched no active "
        f"rule. source_instance={source_instance_id or 'none'}; "
        f"capability={capability_id or 'none'}; no rule or detection was "
        "fabricated."
    )[:512]
    return build_notification(
        notification_id=_unknown_notification_id(event_id),
        kind="event.unknown",
        event_id=event_id,
        classification="unknown",
        rule_id="",
        detection_id="",
        source_instance_id=source_instance_id,
        capability_id=capability_id,
        event_time=getattr(event, "event_time", None),
        evidence_refs=(event_id,) if event_id else (),
        explanation=(
            "No active rule matched the persisted event; uncertainty is "
            "preserved for human review."
        ),
        title="Unknown activity — no active rule matched",
        detail=detail,
        actor_subject_id="pipeline",
        audience_roles=("admin", "analyst"),
        created_at=created_at,
    )


__all__ = [
    "INDEX_SPECS",
    "NOTIFICATIONS_COLLECTION",
    "NOTIFICATIONS_VALIDATOR",
    "NotificationRepository",
    "build_notification",
    "build_unknown_event_notification",
]
