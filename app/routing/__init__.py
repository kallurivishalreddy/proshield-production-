"""ProShield deterministic routing engine (Phase 4.8).

Reference: docs/PHASE 0/ROUTING_MATRIX.md,
docs/PHASE 4/PHASE 4-08.

The routing engine is the documented MVP deterministic
backend-authoritative routing service. It consumes a
case's security context (severity, category, complexity,
specialized / centralized evidence presence) and emits a
:routing:`RoutingRecommendation` plus a deterministic
:routing:`RoutingReason`.

The engine is intentionally minimal. It does NOT claim
analyst availability, current workload, individual
assignment, or AI-assisted routing. It is NOT a queue
manager, escalation engine, or assignment system. Those
capabilities are explicitly future scope.

Routing failure semantics
-------------------------

The routing layer MUST NEVER:

* silently discard a case,
* suppress a case,
* lower its security meaning because routing fails,
* fabricate a destination.

If no safe destination can be determined, the engine
returns an explicit auditable
:routing:`RoutingFailure` carrying the safe reason and
the case stays in its previous state (the routing
service NEVER mutates the case).

Documented routing levels
-------------------------

* ``L1`` - standard / simple investigation
* ``L2`` - advanced / specialized investigation
* ``L3`` - critical / complex investigation
"""
from __future__ import annotations

from .errors import (
    InvalidRoutingInputError,
    RoutingError,
)
from .models import (
    COMPLEXITY_COMPLEX,
    COMPLEXITY_SIMPLE,
    COMPLEXITY_STANDARD,
    LEVEL_L1,
    LEVEL_L2,
    LEVEL_L3,
    ROUTING_STATE_FAILED,
    ROUTING_STATE_OK,
    ROUTING_STATE_UNRESOLVED,
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
from .service import RoutingEngine, RoutingContext

__all__ = [
    "COMPLEXITY_COMPLEX",
    "COMPLEXITY_SIMPLE",
    "COMPLEXITY_STANDARD",
    "LEVEL_L1",
    "LEVEL_L2",
    "LEVEL_L3",
    "ROUTING_STATE_FAILED",
    "ROUTING_STATE_OK",
    "ROUTING_STATE_UNRESOLVED",
    "ROUTING_TEAM_APPLICATION_SECURITY",
    "ROUTING_TEAM_GENERAL_TRIAGE",
    "ROUTING_TEAM_SOC",
    "InvalidRoutingInputError",
    "RoutingComplexity",
    "RoutingContext",
    "RoutingEngine",
    "RoutingError",
    "RoutingFailure",
    "RoutingLevel",
    "RoutingReason",
    "RoutingRecommendation",
    "RoutingResult",
    "RoutingState",
    "RoutingTeam",
]