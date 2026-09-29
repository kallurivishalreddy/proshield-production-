"""Notification repository (MongoDB persistence for gap 12).

Mirrors the documented repository policies of the other ProShield
collections: a ``$jsonSchema`` validator, a documented index set
(including a unique id index), driver-error translation to safe
domain errors, and a total read path (a poisoned document is
quarantined + logged, never crashes reads).
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from pydantic import ValidationError as PydanticValidationError
from pymongo import ASCENDING, DESCENDING, ReturnDocument
from pymongo.collection import Collection
from pymongo.database import Database
from pymongo.errors import PyMongoError

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
    for ts_field in ("created_at", "read_at"):
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
) -> Notification:
    """Factory used by the incident service's notification sink."""
    if kind not in NOTIFICATION_KINDS:
        raise ValidationError(
            safe_message="unknown notification kind",
            internal_detail=f"kind={kind!r} not in the closed catalogue",
            field="kind",
        )
    return Notification(
        notification_id=new_notification_id(),
        kind=kind,
        incident_id=str(incident_id or "")[:64],
        human_id=str(human_id or "")[:32],
        title=str(title or "")[:512],
        detail=str(detail or "")[:512],
        actor_subject_id=str(actor_subject_id or "")[:128],
        audience_roles=tuple(audience_roles),
        created_at=created_at or datetime.now(timezone.utc),
    )


__all__ = [
    "INDEX_SPECS",
    "NOTIFICATIONS_COLLECTION",
    "NOTIFICATIONS_VALIDATOR",
    "NotificationRepository",
    "build_notification",
]
