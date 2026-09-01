"""Detection read service (Phase 4.10 wire-promotion).

Reference: docs/PHASE 4/PROSHIELD-FINAL-FRONTEND-BACKEND-CONTRACT.md
(Components 3 / 4) and docs/PHASE 4/DETECTION_ENGINEERING_AND_FUTURE_AI.md.

The :class:`DetectionReadService` is the thin orchestration layer the
Phase 4.10 wire boundary sits on top of. It exposes the documented
read-only surface required by the Phase 4 frontend (the 3 detection
ops on Component 3):

* :meth:`list`             -> ``detection.list``
* :meth:`get`              -> ``detection.get``
* :meth:`list_for_incident` -> ``detection.list_for_incident``

The service is intentionally narrow. It does NOT persist detections
(that's :class:`app.detection.pipeline.DetectionPipeline` and the
:class:`app.persistence.detection_repository.DetectionRepository`),
it does NOT assign severity / confidence, and it does NOT call out to
the connector layer. It is the **security boundary** the proxy
authorizes against and the only layer that constructs the
**per-detection wire payload** the frontend sees.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from ..domain.errors import NotFoundError, ValidationError
from ..persistence.detection_repository import DetectionRepository
from .models import Detection


MAX_LIST_LIMIT = 200
DEFAULT_LIST_LIMIT = 50
MAX_RULE_ID_LEN = 64
MAX_EVENT_ID_LEN = 64
MAX_INCIDENT_ID_LEN = 64


class DetectionReadService:
    """The Phase 4.10 detection read orchestrator."""

    def __init__(self, repository: DetectionRepository) -> None:
        if repository is None:
            raise ValueError("repository is required")
        if not isinstance(repository, DetectionRepository):
            raise ValueError(
                f"repository must be a DetectionRepository, "
                f"got {type(repository).__name__}"
            )
        self._repository = repository

    @property
    def repository(self) -> DetectionRepository:
        return self._repository

    def list(
        self,
        *,
        rule_id: Optional[str] = None,
        event_id: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> List[Detection]:
        """Return detections matching the supplied filters."""
        if rule_id is not None and (
            not isinstance(rule_id, str) or not rule_id
            or len(rule_id) > MAX_RULE_ID_LEN
        ):
            raise ValidationError(
                safe_message="invalid rule_id",
                internal_detail="rule_id must be a non-empty str",
                field="rule_id",
            )
        if event_id is not None and (
            not isinstance(event_id, str) or not event_id
            or len(event_id) > MAX_EVENT_ID_LEN
        ):
            raise ValidationError(
                safe_message="invalid event_id",
                internal_detail="event_id must be a non-empty str",
                field="event_id",
            )
        effective_limit = _clamp_limit(limit)

        if rule_id is not None and event_id is not None:
            rows = self._repository.find_by_rule(rule_id)
            rows = [d for d in rows if d.event_id == event_id]
        elif rule_id is not None:
            rows = self._repository.find_by_rule(rule_id)
        elif event_id is not None:
            rows = self._repository.find_by_event_id(event_id)
        else:
            return []
        return rows[:effective_limit]

    def get(self, detection_id: str) -> Detection:
        """Return a single detection by id or raise NotFoundError."""
        if not isinstance(detection_id, str) or not detection_id:
            raise ValidationError(
                safe_message="invalid detection_id",
                internal_detail="detection_id must be a non-empty str",
                field="detection_id",
            )
        row = self._repository.get_by_detection_id(detection_id)
        if row is None:
            raise NotFoundError(
                safe_message="detection not found",
                internal_detail=(
                    f"detection_id={detection_id!r} is not registered"
                ),
            )
        return row

    def list_for_incident(
        self,
        *,
        incident_event_ids: Tuple[str, ...],
        limit: Optional[int] = None,
    ) -> List[Detection]:
        """Return every detection bound to a case's events."""
        if incident_event_ids is None:
            raise ValidationError(
                safe_message="incident_event_ids required",
                internal_detail="got None",
                field="incident_event_ids",
            )
        if not isinstance(incident_event_ids, tuple):
            raise ValidationError(
                safe_message="invalid incident_event_ids",
                internal_detail=(
                    f"expected tuple, got "
                    f"{type(incident_event_ids).__name__}"
                ),
                field="incident_event_ids",
            )
        effective_limit = _clamp_limit(limit)

        out: List[Detection] = []
        seen: set = set()
        for eid in incident_event_ids:
            if not isinstance(eid, str) or not eid:
                continue
            for d in self._repository.find_by_event_id(eid):
                if d.detection_id in seen:
                    continue
                seen.add(d.detection_id)
                out.append(d)
        out.sort(key=lambda d: d.detected_at)
        return out[:effective_limit]


def _clamp_limit(limit: Optional[int]) -> int:
    """Clamp ``limit`` to ``[1, MAX_LIST_LIMIT]``; default if missing."""
    if limit is None:
        return DEFAULT_LIST_LIMIT
    if not isinstance(limit, int):
        raise ValidationError(
            safe_message="invalid limit",
            internal_detail=f"limit must be int, got {type(limit).__name__}",
            field="limit",
        )
    if limit <= 0:
        return DEFAULT_LIST_LIMIT
    if limit > MAX_LIST_LIMIT:
        return MAX_LIST_LIMIT
    return limit


def detections_to_wire_payload(
    detections: List[Detection],
) -> List[Dict[str, Any]]:
    """Serialise a list of Detection into the wire payload."""
    return [d.to_dict() for d in detections]


__all__ = [
    "DEFAULT_LIST_LIMIT",
    "DetectionReadService",
    "MAX_LIST_LIMIT",
    "detections_to_wire_payload",
]