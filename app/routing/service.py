"""The deterministic routing engine.

Reference: docs/PHASE 0/ROUTING_MATRIX.md (Section 20 MVP
Routing Boundaries), docs/PHASE 4/PHASE 4-08.

The :class:`RoutingEngine` consumes a case's security
context and returns a :class:`RoutingResult`. The engine
is:

* deterministic - same context -> same result;
* backend-authoritative - the proxy NEVER overrides
  the routing recommendation or fabricates a destination;
* auditable - every recommendation / failure is
  accompanied by a deterministic list of
  :class:`RoutingReason` entries;
* fail-safe - a routing failure NEVER lowers the
  case's security meaning or suppresses the case.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import (
    List,
    Optional,
    Tuple,
)

from ..auth.identity import Identity
from ..auth.permissions import Permission, has_permission
from ..incidents.models import Incident
from ..incidents.service import authorize_case_access
from ..severity.models import (
    ConfidenceBand,
    SeverityBand,
)
from .errors import InvalidRoutingInputError
from .models import (
    COMPLEXITY_COMPLEX,
    COMPLEXITY_SIMPLE,
    COMPLEXITY_STANDARD,
    LEVEL_L1,
    LEVEL_L2,
    LEVEL_L3,
    ROUTING_STATE_FAILED,
    ROUTING_STATE_OK,
    ROUTING_TEAM_APPLICATION_SECURITY,
    ROUTING_TEAM_GENERAL_TRIAGE,
    ROUTING_TEAM_SOC,
    RoutingComplexity,
    RoutingFailure,
    RoutingLevel,
    RoutingReason,
    RoutingRecommendation,
    RoutingResult,
    RoutingState,
    RoutingTeam,
)


_log = logging.getLogger(__name__)


_ALLOWED_SEVERITY = {b.value for b in SeverityBand}
_ALLOWED_CONFIDENCE = {b.value for b in ConfidenceBand}


# ----------------------------------------------------------------- input
class RoutingContext:
    """The deterministic routing input shape."""

    def __init__(
        self,
        *,
        incident: Incident,
        severity_band: Optional[str] = None,
        confidence_band: Optional[str] = None,
        complexity: Optional[str] = None,
        has_centralized_correlation: Optional[bool] = None,
        has_specialized_correlation: Optional[bool] = None,
        evidence_count: Optional[int] = None,
    ) -> None:
        if not isinstance(incident, Incident):
            raise InvalidRoutingInputError(
                safe_message="incident required",
                internal_detail=f"got {type(incident).__name__}",
                field="incident",
            )
        if severity_band is not None and severity_band not in _ALLOWED_SEVERITY:
            raise InvalidRoutingInputError(
                safe_message="invalid severity_band",
                internal_detail=f"got {severity_band!r}",
                field="severity_band",
            )
        if confidence_band is not None and confidence_band not in _ALLOWED_CONFIDENCE:
            raise InvalidRoutingInputError(
                safe_message="invalid confidence_band",
                internal_detail=f"got {confidence_band!r}",
                field="confidence_band",
            )
        if complexity is not None and complexity not in {
            COMPLEXITY_SIMPLE, COMPLEXITY_STANDARD, COMPLEXITY_COMPLEX,
        }:
            raise InvalidRoutingInputError(
                safe_message="invalid complexity",
                internal_detail=f"got {complexity!r}",
                field="complexity",
            )
        self.incident = incident
        self.severity_band = severity_band
        self.confidence_band = confidence_band
        self.complexity = complexity
        self.has_centralized_correlation = (
            has_centralized_correlation
            if has_centralized_correlation is not None
            else bool(incident.centralized_correlation_ids)
        )
        self.has_specialized_correlation = (
            has_specialized_correlation
            if has_specialized_correlation is not None
            else bool(incident.evidence.correlation_ids)
        )
        self.evidence_count = (
            evidence_count
            if evidence_count is not None
            else (
                len(incident.evidence.event_ids)
                + len(incident.evidence.detection_ids)
                + len(incident.evidence.correlation_ids)
            )
        )


# ----------------------------------------------------------------- engine
class RoutingEngine:
    """The deterministic, backend-authoritative routing
    engine."""

    def route(self, context: RoutingContext) -> RoutingResult:
        if not isinstance(context, RoutingContext):
            raise InvalidRoutingInputError(
                safe_message="routing context required",
                internal_detail=f"got {type(context).__name__}",
                field="context",
            )
        now = datetime.now(timezone.utc)
        reasons: List[RoutingReason] = []
        severity = context.severity_band or _derive_severity(context)
        confidence = context.confidence_band or _derive_confidence(context)
        complexity = context.complexity or _derive_complexity(context)
        reasons.append(RoutingReason(
            factor="severity",
            detail=f"severity_band={severity}",
        ))
        reasons.append(RoutingReason(
            factor="complexity",
            detail=f"complexity={complexity}",
        ))
        if context.has_centralized_correlation:
            reasons.append(RoutingReason(
                factor="centralized_correlation",
                detail="centralized correlation evidence present",
            ))
        if context.has_specialized_correlation:
            reasons.append(RoutingReason(
                factor="specialized_correlation",
                detail="specialized correlation evidence present",
            ))
        reasons.append(RoutingReason(
            factor="evidence_count",
            detail=f"evidence_count={context.evidence_count}",
        ))
        decision = _decide(
            severity=severity,
            complexity=complexity,
            has_centralized=context.has_centralized_correlation,
        )
        if decision is None:
            return RoutingResult(
                state=RoutingState(ROUTING_STATE_FAILED),
                failure=RoutingFailure(
                    safe_message=(
                        "routing failed: no safe destination for the "
                        "given case context"
                    ),
                    detail=(
                        f"severity={severity} complexity={complexity} "
                        f"centralized={context.has_centralized_correlation}"
                    ),
                    reasons=tuple(reasons),
                    generated_at=now,
                ),
            )
        level, team, queue = decision
        rec = RoutingRecommendation(
            level=RoutingLevel(level),
            team=RoutingTeam(team),
            queue=queue,
            reasons=tuple(reasons),
            is_centralized=context.has_centralized_correlation,
            severity_band=severity,
            confidence_band=confidence,
            generated_at=now,
        )
        return RoutingResult(
            state=RoutingState(ROUTING_STATE_OK),
            recommendation=rec,
        )

    def route_for_identity(
        self, identity: Identity, context: RoutingContext
    ) -> RoutingResult:
        """Authorization-gated entry point used by the proxy."""
        if not isinstance(identity, Identity):
            raise InvalidRoutingInputError(
                safe_message="identity required",
                internal_detail=f"got {type(identity).__name__}",
                field="identity",
            )
        perms = tuple(identity.permissions)
        if not has_permission(
            role=identity.role,
            identity_permissions=perms,
            permission=Permission.ROUTING_READ,
        ) and not has_permission(
            role=identity.role,
            identity_permissions=perms,
            permission=Permission.ROUTING_READ_ANY,
        ):
            raise InvalidRoutingInputError(
                safe_message="routing access denied",
                internal_detail="missing routing:read",
            )
        authorize_case_access(identity, context.incident)
        return self.route(context)


# ----------------------------------------------------------------- helpers
def _derive_severity(context: RoutingContext) -> str:
    """Deterministic severity derivation from a context.

    The slice uses a conservative, documented heuristic:
    if the case carries a centralized correlation OR has
    many evidence pieces, severity is HIGH; if it has
    any correlation, severity is MEDIUM; otherwise LOW.

    The proxy may override this by passing a
    ``severity_band`` computed by the Phase 4.6
    severity engine.
    """
    if context.has_centralized_correlation:
        return SeverityBand.HIGH.value
    if context.has_specialized_correlation:
        return SeverityBand.MEDIUM.value
    if context.evidence_count >= 8:
        return SeverityBand.MEDIUM.value
    return SeverityBand.LOW.value


def _derive_confidence(context: RoutingContext) -> str:
    if context.has_centralized_correlation:
        return ConfidenceBand.VERY_HIGH.value
    if context.has_specialized_correlation:
        return ConfidenceBand.HIGH.value
    return ConfidenceBand.LOW.value


def _derive_complexity(context: RoutingContext) -> str:
    n = context.evidence_count
    if n >= 10 or context.has_centralized_correlation:
        return COMPLEXITY_COMPLEX
    if n >= 3 or context.has_specialized_correlation:
        return COMPLEXITY_STANDARD
    return COMPLEXITY_SIMPLE


def _decide(
    *,
    severity: str,
    complexity: str,
    has_centralized: bool,
) -> Optional[Tuple[str, str, str]]:
    """Return ``(level, team, queue)`` or ``None`` for an
    explicit routing failure.

    Rules (documented MVP routing matrix):

    * centralized correlation present -> minimum L2
    * CRITICAL + complex -> L3
    * CRITICAL + standard/simple -> L2
    * HIGH -> L2
    * MEDIUM + standard/simple -> L1
    * MEDIUM + complex -> L2
    * LOW + simple/standard -> L1
    * LOW + complex -> L2

    The function is total: every input maps to a single
    documented decision. ``None`` is reserved for inputs
    the slice refuses (e.g. unknown severity band).
    """
    if has_centralized:
        if severity == SeverityBand.CRITICAL.value:
            return (LEVEL_L3, ROUTING_TEAM_SOC, "soc-L2")
        return (LEVEL_L2, ROUTING_TEAM_SOC, "soc-L2")
    if severity == SeverityBand.CRITICAL.value:
        if complexity == COMPLEXITY_COMPLEX:
            return (LEVEL_L3, ROUTING_TEAM_SOC, "soc-L3")
        return (LEVEL_L2, ROUTING_TEAM_SOC, "soc-L2")
    if severity == SeverityBand.HIGH.value:
        return (LEVEL_L2, ROUTING_TEAM_SOC, "soc-L2")
    if severity == SeverityBand.MEDIUM.value:
        if complexity == COMPLEXITY_COMPLEX:
            return (LEVEL_L2, ROUTING_TEAM_SOC, "soc-L2")
        return (LEVEL_L1, ROUTING_TEAM_GENERAL_TRIAGE, "triage-L1")
    if severity == SeverityBand.LOW.value:
        if complexity == COMPLEXITY_COMPLEX:
            return (LEVEL_L2, ROUTING_TEAM_SOC, "soc-L2")
        return (LEVEL_L1, ROUTING_TEAM_GENERAL_TRIAGE, "triage-L1")
    # Unknown severity band -> explicit routing failure.
    return None


__all__ = [
    "RoutingContext",
    "RoutingEngine",
]