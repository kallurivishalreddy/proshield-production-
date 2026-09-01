"""Correlation read service (Phase 4.10 wire-promotion).

Reference: docs/PHASE 4/PROSHIELD-FINAL-FRONTEND-BACKEND-CONTRACT.md
(Component 4) and docs/PHASE 4/DETECTION_ENGINEERING_AND_FUTURE_AI.md.

The :class:`CorrelationReadService` is the thin orchestration layer
the Phase 4.10 wire boundary sits on top of. It exposes the
documented read-only surface required by the Phase 4 frontend (the
3 correlation ops on Component 4):

* :meth:`list`             -> ``correlation.list``
* :meth:`get`              -> ``correlation.get``
* :meth:`list_for_incident` -> ``correlation.list_for_incident``

The service mirrors :class:`app.detection.service.DetectionReadService`
in shape and invariants. It owns no state; its only collaborator is
the :class:`app.persistence.correlation_repository.CorrelationRepository`.
"""
from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Tuple

from ..domain.errors import NotFoundError, ValidationError
from .models import Correlation

if TYPE_CHECKING:  # pragma: no cover - typing only
    from ..persistence.correlation_repository import (
        CorrelationRepository,
    )


MAX_LIST_LIMIT = 200
DEFAULT_LIST_LIMIT = 50
MAX_PATTERN_ID_LEN = 64
MAX_CORRELATION_ID_LEN = 64
MAX_INCIDENT_ID_LEN = 64


class CorrelationReadService:
    """The Phase 4.10 correlation read orchestrator."""

    def __init__(self, repository: "CorrelationRepository") -> None:
        # Local import to break the cycle:
        # app.persistence.correlation_repository imports from
        # app.correlation.models, and app.correlation.__init__ imports
        # this service. Importing CorrelationRepository lazily
        # here defers the resolution until the class is actually
        # instantiated (not at module import time).
        from ..persistence.correlation_repository import (
            CorrelationRepository as _CorrelationRepository,
        )
        if repository is None:
            raise ValueError("repository is required")
        if not isinstance(repository, _CorrelationRepository):
            raise ValueError(
                f"repository must be a CorrelationRepository, "
                f"got {type(repository).__name__}"
            )
        self._repository = repository

    @property
    def repository(self) -> "CorrelationRepository":
        return self._repository

    def list(
        self,
        *,
        pattern_id: Optional[str] = None,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
        limit: Optional[int] = None,
    ) -> List[Correlation]:
        """Return correlations matching the supplied filters."""
        if pattern_id is not None and (
            not isinstance(pattern_id, str) or not pattern_id
            or len(pattern_id) > MAX_PATTERN_ID_LEN
        ):
            raise ValidationError(
                safe_message="invalid pattern_id",
                internal_detail="pattern_id must be a non-empty str",
                field="pattern_id",
            )
        _validate_iso_datetime(since, "since")
        _validate_iso_datetime(until, "until")
        if since is not None and until is not None and until < since:
            raise ValidationError(
                safe_message="invalid time range",
                internal_detail="until must be >= since",
                field="until",
            )
        effective_limit = _clamp_limit(limit)

        rows: List[Correlation]
        if pattern_id is not None:
            rows = self._repository.find_by_pattern(pattern_id)
        else:
            return []
        if since is not None:
            rows = [c for c in rows if c.window_start >= since]
        if until is not None:
            rows = [c for c in rows if c.window_end <= until]
        return rows[:effective_limit]

    def get(self, correlation_id: str) -> Correlation:
        """Return a single correlation by id or raise NotFoundError."""
        if not isinstance(correlation_id, str) or not correlation_id:
            raise ValidationError(
                safe_message="invalid correlation_id",
                internal_detail="correlation_id must be a non-empty str",
                field="correlation_id",
            )
        row = self._repository.get_by_correlation_id(correlation_id)
        if row is None:
            raise NotFoundError(
                safe_message="correlation not found",
                internal_detail=(
                    f"correlation_id={correlation_id!r} is not registered"
                ),
            )
        return row

    def list_for_incident(
        self,
        *,
        incident_correlation_ids: Tuple[str, ...],
        limit: Optional[int] = None,
    ) -> List[Correlation]:
        """Return every correlation bound to a case."""
        if incident_correlation_ids is None:
            raise ValidationError(
                safe_message="incident_correlation_ids required",
                internal_detail="got None",
                field="incident_correlation_ids",
            )
        if not isinstance(incident_correlation_ids, tuple):
            raise ValidationError(
                safe_message="invalid incident_correlation_ids",
                internal_detail=(
                    f"expected tuple, got "
                    f"{type(incident_correlation_ids).__name__}"
                ),
                field="incident_correlation_ids",
            )
        effective_limit = _clamp_limit(limit)

        out: List[Correlation] = []
        seen: set = set()
        for cid in incident_correlation_ids:
            if not isinstance(cid, str) or not cid:
                continue
            if cid in seen:
                continue
            seen.add(cid)
            row = self._repository.get_by_correlation_id(cid)
            if row is None:
                continue
            out.append(row)
        out.sort(key=lambda c: c.window_start)
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


def _validate_iso_datetime(value: Any, field_name: str) -> None:
    if value is None:
        return
    if isinstance(value, datetime):
        return
    if isinstance(value, str):
        try:
            from datetime import datetime as _dt
            _dt.fromisoformat(value.replace("Z", "+00:00"))
            return
        except (TypeError, ValueError):
            raise ValidationError(
                safe_message=f"invalid {field_name}",
                internal_detail=(
                    f"{field_name} must be an ISO 8601 datetime"
                ),
                field=field_name,
            )
    raise ValidationError(
        safe_message=f"invalid {field_name}",
        internal_detail=(
            f"{field_name} must be ISO 8601 datetime or None"
        ),
        field=field_name,
    )


def correlations_to_wire_payload(
    correlations: List[Correlation],
) -> List[Dict[str, Any]]:
    """Serialise a list of Correlation into the wire payload."""
    return [c.to_dict() for c in correlations]


__all__ = [
    "CorrelationReadService",
    "DEFAULT_LIST_LIMIT",
    "MAX_LIST_LIMIT",
    "correlations_to_wire_payload",
]