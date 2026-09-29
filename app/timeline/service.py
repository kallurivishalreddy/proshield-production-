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
# Capability patch gap 13: per-kind fetch bound for the global
# timeline query (bounded scan; the merged stream is paginated
# afterwards).
_GLOBAL_FETCH = 1000


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

    def resolve_case_evidence(self, case: Incident) -> Tuple[
        List[SecurityEvent], List[Any], List[Any]
    ]:
        """V2-05: resolve a case's *real* evidence from the stores.

        Returns ``(events, detections, correlations)`` exactly as the
        timeline builder resolves them: case evidence ids -> persisted
        records. The centralized-analysis handler uses this so the
        correlation engine analyses the case's real evidence instead of
        the (empty) payload the UI happened to send — a no-op analysis
        that reported a misleading success (V2-05) is impossible when
        the server owns evidence resolution.
        """
        if case is None or not hasattr(case, "evidence"):
            raise ValidationError(
                safe_message="invalid case",
                internal_detail=f"got {type(case).__name__}",
                field="case",
            )
        events = self._resolve_events(case)
        detections = self._detection_service.list_for_incident(
            incident_event_ids=tuple(case.evidence.event_ids),
        )
        corr_ids = tuple(case.evidence.correlation_ids) + tuple(
            case.centralized_correlation_ids
        )
        correlations = self._correlation_service.list_for_incident(
            incident_correlation_ids=corr_ids,
        )
        return events, detections, correlations

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

        events, detections, correlations = self.resolve_case_evidence(case)

        now = datetime.now(timezone.utc)
        return self._engine.run(
            events=events,
            detections=detections,
            correlations=correlations,
            now=now,
        )

    def global_query(
        self,
        *,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
        kinds: Optional[Tuple[str, ...]] = None,
        limit: int = 200,
        offset: int = 0,
        now: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        """Global (cross-case) timeline query (capability patch gap 13).

        Aggregates the supported timeline event kinds from the
        persistence layer in one bounded, deterministic read:

        * ``event``       - canonical SecurityEvents (event_time),
        * ``detection``   - Detections (detected_at),
        * ``correlation`` - Correlations (correlated_at).

        The merged stream is sorted newest-first, optionally
        time/kind-filtered, and paginated with ``offset``/``limit``.
        There is no case context here by definition (global scope);
        no cross-case contamination is possible because every item
        carries its own ids only.

        Bounded: each source contributes at most ``_GLOBAL_FETCH``
        rows before the merge, so the query cannot scan unbounded
        history.
        """
        ref = now or datetime.now(timezone.utc)
        if ref.tzinfo is None:
            ref = ref.replace(tzinfo=timezone.utc)
        allowed_kinds = ("event", "detection", "correlation")
        selected = tuple(
            k for k in (kinds or allowed_kinds) if k in allowed_kinds
        ) or allowed_kinds

        items: List[Dict[str, Any]] = []

        def _in_window(ts: datetime) -> bool:
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            if since is not None:
                s = since if since.tzinfo else since.replace(
                    tzinfo=timezone.utc
                )
                if ts < s:
                    return False
            if until is not None:
                u = until if until.tzinfo else until.replace(
                    tzinfo=timezone.utc
                )
                if ts > u:
                    return False
            return True

        if "event" in selected:
            for ev in self._event_repo.find_recent(limit=_GLOBAL_FETCH):
                ts = ev.event_time
                if not _in_window(ts):
                    continue
                items.append({
                    "kind": "event",
                    "timestamp": ts.isoformat(),
                    "item_id": ev.event_id,
                    "title": str(ev.event_type),
                    "source": str(ev.source),
                    "detail": {
                        "source_ip": ev.source_ip,
                        "endpoint": ev.endpoint,
                    },
                })
        if "detection" in selected:
            for det in self._detection_service.repository.find_latest(
                limit=_GLOBAL_FETCH,
            ):
                ts = det.detected_at
                if not _in_window(ts):
                    continue
                items.append({
                    "kind": "detection",
                    "timestamp": ts.isoformat(),
                    "item_id": det.detection_id,
                    "human_id": det.human_id or None,
                    "title": f"{det.rule_id} v{det.rule_version}",
                    "detail": {
                        "event_id": det.event_id,
                        "severity": det.severity or None,
                        "category": det.category.value,
                    },
                })
        if "correlation" in selected:
            for corr in self._correlation_service.repository.find_recent(
                limit=_GLOBAL_FETCH,
            ):
                ts = corr.correlated_at
                if not _in_window(ts):
                    continue
                items.append({
                    "kind": "correlation",
                    "timestamp": ts.isoformat(),
                    "item_id": corr.correlation_id,
                    "human_id": corr.human_id or None,
                    "title": corr.pattern_id,
                    "detail": {
                        "count": corr.count,
                        "key": list(corr.key.parts),
                        "confidence": corr.confidence or None,
                    },
                })

        items.sort(key=lambda i: i["timestamp"], reverse=True)
        safe_limit = max(1, min(int(limit), 200))
        safe_offset = max(0, int(offset))
        page = items[safe_offset:safe_offset + safe_limit]
        return {
            "items": page,
            "total_returned": len(page),
            "total_matched": len(items),
            "truncated": (
                len(items) >= _GLOBAL_FETCH * len(selected)
            ),
            "offset": safe_offset,
            "limit": safe_limit,
            "kinds": list(selected),
            "produced_at": ref.isoformat(),
        }

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