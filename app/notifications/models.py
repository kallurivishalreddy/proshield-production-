"""Notification domain: models for the analyst notification feed.

Reference: docs/PHASE 4/PROSHIELD-BACKEND-CAPABILITY-PATCH-REPORT.md
(gap 12).

A :class:`Notification` is a **real backend event**: it is created by
the owning domain service (today: the incident lifecycle service)
through an injected sink, never by the frontend, never fabricated to
fill a UI tray. Notifications are persisted in their own collection
so they survive restarts and are visible across clients.

Design rules:

* append-only: a notification is never edited; only the ``read``
  flag (and ``read_by``/``read_at``) may change.
* audience-scoped: ``audience_roles`` is a closed set of role names;
  a reader sees a notification only when their role is in the set
  (or when they are the acting subject, ``actor_subject_id``).
* bounded: every field is length-bounded; the list op is limit-bounded.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Optional, Tuple
from uuid import uuid4

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
)
from typing_extensions import Annotated


MAX_NOTIFICATION_MESSAGE_LEN = 512
MAX_NOTIFICATION_DETAIL_LEN = 512
MAX_NOTIFICATIONS_LIST = 200

NOTIFICATION_ID_PREFIX = "ntf"

# Closed set of notification kinds the backend emits today. A new
# emitter must extend this set explicitly (fail-closed catalogue).
NOTIFICATION_KINDS = (
    "case.created",
    "case.acknowledged",
    "case.investigating",
    "case.closed",
    "case.note_added",
    "case.centralized_failed",
)

NotificationId = Annotated[
    str,
    StringConstraints(
        min_length=8,
        max_length=64,
        pattern=r"^ntf-[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-"
                r"[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    ),
]


def new_notification_id() -> str:
    """Random ``ntf-<uuidv7-shape>`` id (v4 nibble-typed, RFC-shape)."""
    raw = uuid4().hex
    # Force the uuid7-shape the pattern requires: version nibble 7,
    # variant nibble 8/9/a/b.
    raw = raw[:12] + "7" + raw[13:16] + "8" + raw[17:]
    return (
        "ntf-"
        f"{raw[0:8]}-{raw[8:12]}-{raw[12:16]}-"
        f"{raw[16:20]}-{raw[20:32]}"
    )


class Notification(BaseModel):
    """One persisted, audience-scoped analyst notification."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    notification_id: NotificationId
    kind: Annotated[
        str,
        StringConstraints(min_length=3, max_length=64),
    ]
    # The case the notification is about (empty for non-case kinds).
    incident_id: Annotated[str, StringConstraints(max_length=64)] = ""
    human_id: Annotated[str, StringConstraints(max_length=32)] = ""
    title: Annotated[
        str, StringConstraints(max_length=MAX_NOTIFICATION_MESSAGE_LEN)
    ] = ""
    detail: Annotated[
        str, StringConstraints(max_length=MAX_NOTIFICATION_DETAIL_LEN)
    ] = ""
    actor_subject_id: Annotated[
        str, StringConstraints(max_length=128)
    ] = ""
    audience_roles: Tuple[
        Annotated[str, StringConstraints(min_length=1, max_length=32)],
        ...,
    ] = ("admin", "analyst")
    read: bool = False
    read_by: Annotated[str, StringConstraints(max_length=128)] = ""
    read_at: Optional[datetime] = None
    created_at: datetime

    def to_dict(self) -> Dict[str, Any]:
        return {
            "notification_id": self.notification_id,
            "kind": self.kind,
            "incident_id": self.incident_id or None,
            "human_id": self.human_id or None,
            "title": self.title,
            "detail": self.detail or None,
            "actor_subject_id": self.actor_subject_id or None,
            "audience_roles": list(self.audience_roles),
            "read": self.read,
            "read_by": self.read_by or None,
            "read_at": self.read_at.isoformat() if self.read_at else None,
            "created_at": self.created_at.isoformat(),
        }


__all__ = [
    "MAX_NOTIFICATIONS_LIST",
    "NOTIFICATION_ID_PREFIX",
    "NOTIFICATION_KINDS",
    "Notification",
    "NotificationId",
    "new_notification_id",
]
