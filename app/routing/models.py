"""Routing engine data models.

Reference: docs/PHASE 0/ROUTING_MATRIX.md,
docs/PHASE 4/PHASE 4-08.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import (
    Annotated,
    Any,
    Dict,
    Optional,
    Tuple,
)

from pydantic import (
    BaseModel,
    ConfigDict,
    StringConstraints,
)


# ----------------------------------------------------------------- levels
class RoutingLevel(str, Enum):
    L1 = "L1"
    L2 = "L2"
    L3 = "L3"


LEVEL_L1 = RoutingLevel.L1.value
LEVEL_L2 = RoutingLevel.L2.value
LEVEL_L3 = RoutingLevel.L3.value


class RoutingComplexity(str, Enum):
    SIMPLE = "simple"
    STANDARD = "standard"
    COMPLEX = "complex"


COMPLEXITY_SIMPLE = RoutingComplexity.SIMPLE.value
COMPLEXITY_STANDARD = RoutingComplexity.STANDARD.value
COMPLEXITY_COMPLEX = RoutingComplexity.COMPLEX.value


class RoutingTeam(str, Enum):
    GENERAL_TRIAGE = "general_triage"
    SOC = "soc"
    APPLICATION_SECURITY = "application_security"


ROUTING_TEAM_GENERAL_TRIAGE = RoutingTeam.GENERAL_TRIAGE.value
ROUTING_TEAM_SOC = RoutingTeam.SOC.value
ROUTING_TEAM_APPLICATION_SECURITY = (
    RoutingTeam.APPLICATION_SECURITY.value
)


class RoutingState(str, Enum):
    OK = "ok"
    UNRESOLVED = "unresolved"
    FAILED = "failed"


ROUTING_STATE_OK = RoutingState.OK.value
ROUTING_STATE_UNRESOLVED = RoutingState.UNRESOLVED.value
ROUTING_STATE_FAILED = RoutingState.FAILED.value


# ----------------------------------------------------------------- models
class RoutingReason(BaseModel):
    """A single, deterministic reason supporting a
    recommendation or failure.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    factor: Annotated[
        str,
        StringConstraints(
            min_length=1,
            max_length=64,
            pattern=(
                r"^(severity|complexity|category|"
                r"centralized_correlation|specialized_correlation|"
                r"evidence_count|unknown)$"
            ),
        ),
    ]
    detail: Annotated[
        str,
        StringConstraints(min_length=0, max_length=512),
    ] = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "factor": self.factor,
            "detail": self.detail,
        }


class RoutingRecommendation(BaseModel):
    """A successful routing recommendation."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    level: RoutingLevel
    team: RoutingTeam
    queue: Annotated[
        str,
        StringConstraints(min_length=1, max_length=64),
    ]
    reasons: Tuple[RoutingReason, ...] = ()
    is_centralized: bool = False
    severity_band: Annotated[
        str,
        StringConstraints(min_length=1, max_length=32),
    ]
    confidence_band: Annotated[
        str,
        StringConstraints(min_length=1, max_length=32),
    ] = "low"
    generated_at: datetime

    def to_dict(self) -> Dict[str, Any]:
        return {
            "level": self.level.value,
            "team": self.team.value,
            "queue": self.queue,
            "reasons": [r.to_dict() for r in self.reasons],
            "is_centralized": self.is_centralized,
            "severity_band": self.severity_band,
            "confidence_band": self.confidence_band,
            "generated_at": self.generated_at.isoformat(),
        }


class RoutingFailure(BaseModel):
    """An explicit, auditable routing failure."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    safe_message: Annotated[
        str,
        StringConstraints(min_length=1, max_length=512),
    ]
    detail: Annotated[
        str,
        StringConstraints(min_length=0, max_length=1024),
    ] = ""
    reasons: Tuple[RoutingReason, ...] = ()
    generated_at: datetime

    def to_dict(self) -> Dict[str, Any]:
        return {
            "safe_message": self.safe_message,
            "detail": self.detail,
            "reasons": [r.to_dict() for r in self.reasons],
            "generated_at": self.generated_at.isoformat(),
        }


class RoutingResult(BaseModel):
    """The routing engine's output.

    Exactly one of :attr:`recommendation` (state ``ok``)
    or :attr:`failure` (state ``failed`` /
    ``unresolved``) is set.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    state: RoutingState
    recommendation: Optional[RoutingRecommendation] = None
    failure: Optional[RoutingFailure] = None

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "state": self.state.value,
        }
        if self.recommendation is not None:
            out["recommendation"] = self.recommendation.to_dict()
        if self.failure is not None:
            out["failure"] = self.failure.to_dict()
        return out


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
    "RoutingComplexity",
    "RoutingFailure",
    "RoutingLevel",
    "RoutingReason",
    "RoutingRecommendation",
    "RoutingResult",
    "RoutingState",
    "RoutingTeam",
]