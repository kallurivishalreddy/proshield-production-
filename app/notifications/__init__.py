"""Notification feed package (capability patch gap 12).

Real backend events only: the incident lifecycle service emits
notifications through an injected sink; nothing here is fabricated
to satisfy a UI tray.
"""
from .models import (
    MAX_NOTIFICATIONS_LIST,
    NOTIFICATION_KINDS,
    Notification,
    new_notification_id,
)
from .repository import (
    NOTIFICATIONS_COLLECTION,
    NOTIFICATIONS_VALIDATOR,
    NotificationRepository,
    build_notification,
)
from .service import NotificationService

__all__ = [
    "MAX_NOTIFICATIONS_LIST",
    "NOTIFICATION_KINDS",
    "NOTIFICATIONS_COLLECTION",
    "NOTIFICATIONS_VALIDATOR",
    "Notification",
    "NotificationRepository",
    "NotificationService",
    "build_notification",
    "new_notification_id",
]
