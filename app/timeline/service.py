"""Timeline read service (Phase 4.10 wire-promotion).

Reference: docs/PHASE 4/PROSHIELD-FINAL-FRONTEND-BACKEND-CONTRACT.md
(Component 7 / Action 8.1) and docs/PHASE 2/DOMAIN_DATA_MODEL.md,
Section 8 (TimelineEvent) + Section 21 (Core Relationships).

The :class:`TimelineReadService` is the thin orchestration layer
that wraps the pure :class:`app.timeline.engine.TimelineEngine` and
exposes it to the proxy. The proxy's :class:`SecureProxy` calls
:meth:`build_for_incident` for the ``timeline.build_for_incident``
wire op.

The service resolves the case's evidence (events / detections /
correlations) once and feeds the deterministic engine; it does NOT
call out to the connector layer or perform any new correlation. It
is pure orchestration: read-only, bounded, IDOR-neutral.

Why a dedicated service
-----------------------

The :class:`TimelineEngine` is documented as a pure in-memory
organiser (Section 66 of DETECTION_ENGINEERING_AND_FUTURE_AI.md).
A service layer wraps it so:

* the proxy can call one method with case ids;
* repository fan-out (events + detections + correlations) is
  co-located, not scattered across the proxy handler;
* future filters (``since`` / ``until`` / source-id) can be added
  here without touching the engine or the proxy.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

from ..correlation.service import CorrelationReadService
from ..detection.service import DetectionReadService
from ..domain.errors import NotFoundError, ValidationError
from ..domain.security_event import SecurityEvent
from ..incidents.models import Incident
from ..persistence.security_event_repository import SecurityEventRepository
from .engine import TimelineEngine
from .models import TimelineResult


MAX_ITED_PER_INCIDENT = 256


class TimelineReadService:
    """The Phase 4.10 timeline orchestrator.

    Constructor takes the pure engine plus the three repository
    collaborators (events / detections / correlations). The class
    is intentionally small: it builds the inputs, hands them to
    the engine, and forwards the result.
    """

    def __init__(
        self,
        engine: TimelineEngine,
        security_event_repository: SecurityEventRepository,
        detection_service: DetectionReadService,
        correlation_service: CorrelationReadService,
    ) -> None:
        if engine is None:
            raise ValueError("engine is required")
        if security_event_repository is None:
            raise ValueError("security_event_repository is required")
        if detection_service is None:
            raise ValueError("detection_service is required")
        if correlation_service is None:
            raise ValueError("correlation_service is required")
        self._engine = engine
        self._event_repo = security_event_repository
        self._detection_service = detection_service
        self._correlation_service = correlation_service

    @property
    def engine(self) -> TimelineEngine:
        return self._engine

    def build_for_incident(
        self,
        *,
        case: Incident,
    ) -> TimelineResult:
        """Build the deterministic timeline for a case.

        The case's evidence catalogue drives the input fan-out:

        * ``case.evidence.event_ids`` -> SecurityEvents (via the
          event repository ``get_by_event_id``),
        * ``case.evidence.detection_ids`` -> Detections (via the
          detection service ``list_for_incident``),
        * ``case.evidence.correlation_ids`` +
          ``case.centralized_correlation_ids`` -> Correlations (via
          the correlation service ``list_for_incident``).

        The service NEVER invents evidence; missing inputs are
        silently skipped (forward-compat: a case may reference a
        record that has been purged). The result is the
        :class:`TimelineResult` from the engine, deterministic
        when the engine's ``now`` is injected.
        """
        if case is None:
            raise ValidationError(
                safe_message="case required",
                internal_detail="got None",
                field="case",
            )
        if not hasattr(case, "evidence"):
            raise ValidationError(
                safe_message="invalid case",
                internal_detail=f"got {type(case).__name__}",
                field="case",
            )

        events = self._resolve_events(case)
        detections = self._detection_service.list_for_incident(
            incident_event_ids=tuple(case.evidence.event_ids),
        )
        # Combine the case's normal correlation_ids with the
        # centralized ones (the wire contract documents
        # ``case.centralized_correlation_ids`` as part of the
        # centralized evidence).
        corr_ids = tuple(case.evidence.correlation_ids) + tuple(
            case.centralized_correlation_ids
        )
        correlations = self._correlation_service.list_for_incident(
            incident_correlation_ids=corr_ids,
        )

        now = datetime.now(timezone.utc)
        return self._engine.run(
            events=events,
            detections=detections,
            correlations=correlations,
            now=now,
        )

    def _resolve_events(
        self,
        case: Incident,
    ) -> List[SecurityEvent]:
        """Resolve case event_ids to SecurityEvent instances."""
        out: List[SecurityEvent] = []
        seen: set = set()
        for eid in case.evidence.event_ids:
            if not isinstance(eid, str) or not eid:
                continue
            if eid in seen:
                continue
            seen.add(eid)
            try:
                ev = self._event_repo.get_by_event_id(eid)
            except Exception:  # noqa: BLE001 - fail-closed aggregate.
                continue
            if ev is not None:
                out.append(ev)
        return out


__all__ = ["TimelineReadService"]