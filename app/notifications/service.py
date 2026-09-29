"""Notification service (gap 12): the wire-facing notification feed.

The service is the only layer the proxy talks to. It exposes:

* :meth:`sink`             - the callback the incident service calls
  after a real state change (injected at deployment wiring).
* :meth:`list_for_identity` -> ``notification.list``
* :meth:`mark_read`         -> ``notification.mark_read``
* :meth:`unread_count`      -> ``notification.unread_count``

It never fabricates notifications: entries exist only because a real
backend operation produced them.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from ..auth.identity import Identity
from ..domain.errors import NotFoundError, ValidationError
from .repository import (
    NotificationRepository,
    build_notification,
)


_log = logging.getLogger(__name__)

MAX_LIST_LIMIT = 200
DEFAULT_LIST_LIMIT = 50


class NotificationService:
    """Wire-facing notification feed orchestrator."""

    def __init__(self, repository: NotificationRepository) -> None:
        from pymongo.database import Database  # noqa: F401 - typing only

        if not isinstance(repository, NotificationRepository):
            raise ValueError(
                "repository must be a NotificationRepository"
            )
        self._repository = repository

    @property
    def repository(self) -> NotificationRepository:
        return self._repository

    # ------------------------------------------------------------------
    # Emission (called by domain services via the injected sink)
    # ------------------------------------------------------------------
    def emit(
        self,
        *,
        kind: str,
        incident_id: str = "",
        human_id: str = "",
        title: str = "",
        detail: str = "",
        actor_subject_id: str = "",
        audience_roles: tuple = ("admin", "analyst"),
    ) -> None:
        """Record one notification for a real backend event."""
        notification = build_notification(
            kind=kind,
            incident_id=incident_id,
            human_id=human_id,
            title=title,
            detail=detail,
            actor_subject_id=actor_subject_id,
            audience_roles=audience_roles,
        )
        self._repository.create(notification)

    def sink(self, **kwargs: Any) -> None:
        """The exact callable shape the incident service expects."""
        self.emit(**kwargs)

    # ------------------------------------------------------------------
    # Reads / updates (wire ops)
    # ------------------------------------------------------------------
    def list_for_identity(
        self,
        *,
        identity: Identity,
        unread_only: bool = False,
        limit: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        if not isinstance(identity, Identity):
            raise ValidationError(
                safe_message="identity required",
                internal_detail=f"got {type(identity).__name__}",
                field="identity",
            )
        rows = self._repository.find_for_audience(
            role=str(identity.role),
            subject_id=identity.subject_id,
            unread_only=bool(unread_only),
            limit=limit if limit is not None else DEFAULT_LIST_LIMIT,
        )
        return [n.to_dict() for n in rows]

    def mark_read(
        self, *, identity: Identity, notification_id: str,
    ) -> Dict[str, Any]:
        if not isinstance(identity, Identity):
            raise ValidationError(
                safe_message="identity required",
                internal_detail=f"got {type(identity).__name__}",
                field="identity",
            )
        updated = self._repository.mark_read(
            str(notification_id or ""), identity.subject_id,
        )
        if updated is None:
            raise NotFoundError(
                safe_message="notification not found",
                internal_detail=(
                    f"notification_id={notification_id!r} not registered"
                ),
            )
        return updated.to_dict()

    def unread_count(self, *, identity: Identity) -> Dict[str, Any]:
        if not isinstance(identity, Identity):
            raise ValidationError(
                safe_message="identity required",
                internal_detail=f"got {type(identity).__name__}",
                field="identity",
            )
        count = self._repository.count_unread_for_audience(
            role=str(identity.role),
            subject_id=identity.subject_id,
        )
        return {"unread_count": int(count)}


__all__ = ["DEFAULT_LIST_LIMIT", "MAX_LIST_LIMIT", "NotificationService"]
