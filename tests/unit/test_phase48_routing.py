"""Unit tests for the Phase 4.8 routing engine."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from app.auth import ADMIN_ROLE, ANALYST_ROLE, Identity
from app.incidents.models import Incident, IncidentEvidence
from app.routing import (
    COMPLEXITY_COMPLEX,
    COMPLEXITY_SIMPLE,
    LEVEL_L1,
    LEVEL_L2,
    LEVEL_L3,
    RoutingContext,
    RoutingEngine,
)
from app.routing.errors import InvalidRoutingInputError


def _make_incident(
    *,
    event_ids=("e1", "e2"),
    detection_ids=("d1",),
    correlation_ids=("c1",),
    centralized_ids=(),
    created_by="user-analyst-001",
) -> Incident:
    now = datetime.now(timezone.utc)
    evidence = IncidentEvidence(
        event_ids=event_ids,
        detection_ids=detection_ids,
        correlation_ids=correlation_ids,
        rule_references=(("NGINX-AUTH-FAILURE-001", 1),),
    )
    return Incident(
        incident_id="case-00000000-0000-7000-8000-000000000001",
        title="demo",
        summary="",
        state="open",
        evidence=evidence,
        rule_references=(("NGINX-AUTH-FAILURE-001", 1),),
        lifecycle_history=(),
        report_references=(),
        centralized_correlation_ids=centralized_ids,
        centralized_reasoning="",
        centralized_failed=False,
        centralized_failure_reason="",
        created_by=created_by,
        created_at=now,
        updated_at=now,
    )


class TestRoutingContext:
    def test_incident_required(self) -> None:
        with pytest.raises(InvalidRoutingInputError):
            RoutingContext(incident=None)  # type: ignore[arg-type]

    def test_invalid_severity_band(self) -> None:
        with pytest.raises(InvalidRoutingInputError):
            RoutingContext(
                incident=_make_incident(),
                severity_band="catastrophic",
            )

    def test_invalid_complexity(self) -> None:
        with pytest.raises(InvalidRoutingInputError):
            RoutingContext(
                incident=_make_incident(),
                complexity="impossible",
            )

    def test_derives_counts_from_incident(self) -> None:
        ctx = RoutingContext(incident=_make_incident())
        assert ctx.evidence_count == 4
        assert ctx.has_specialized_correlation is True
        assert ctx.has_centralized_correlation is False


class TestRoutingEngine:
    def test_low_simple_routes_to_L1(self) -> None:
        engine = RoutingEngine()
        ctx = RoutingContext(
            incident=_make_incident(event_ids=(), detection_ids=()),
            severity_band="low",
            complexity="simple",
        )
        result = engine.route(ctx)
        assert result.state.value == "ok"
        rec = result.recommendation
        assert rec is not None
        assert rec.level.value == LEVEL_L1
        assert rec.team.value == "general_triage"
        assert rec.queue == "triage-L1"

    def test_medium_complex_routes_to_L2(self) -> None:
        engine = RoutingEngine()
        ctx = RoutingContext(
            incident=_make_incident(),
            severity_band="medium",
            complexity=COMPLEXITY_COMPLEX,
        )
        result = engine.route(ctx)
        assert result.state.value == "ok"
        assert result.recommendation.level.value == LEVEL_L2

    def test_high_routes_to_L2(self) -> None:
        engine = RoutingEngine()
        ctx = RoutingContext(
            incident=_make_incident(), severity_band="high",
        )
        result = engine.route(ctx)
        assert result.recommendation.level.value == LEVEL_L2

    def test_critical_complex_routes_to_L3(self) -> None:
        engine = RoutingEngine()
        ctx = RoutingContext(
            incident=_make_incident(),
            severity_band="critical",
            complexity=COMPLEXITY_COMPLEX,
        )
        result = engine.route(ctx)
        assert result.recommendation.level.value == LEVEL_L3

    def test_centralized_correlation_forces_minimum_L2(self) -> None:
        engine = RoutingEngine()
        ctx = RoutingContext(
            incident=_make_incident(centralized_ids=("c-new",)),
            severity_band="medium",
            complexity=COMPLEXITY_SIMPLE,
        )
        result = engine.route(ctx)
        assert result.recommendation.level.value == LEVEL_L2

    def test_unknown_severity_returns_invalid(self) -> None:
        # Invalid severity bands are rejected at context
        # construction time (defensive boundary). This
        # prevents the routing engine from ever seeing an
        # invalid band.
        with pytest.raises(InvalidRoutingInputError):
            RoutingContext(
                incident=_make_incident(),
                severity_band="banana",
            )

    def test_deterministic_decision(self) -> None:
        engine = RoutingEngine()
        ctx = RoutingContext(
            incident=_make_incident(),
            severity_band="medium", complexity="standard",
        )
        a = engine.route(ctx)
        b = engine.route(ctx)
        # The decision (level / team / queue / state) is
        # deterministic. The generated_at timestamp varies
        # so we compare the structural fields.
        assert a.state == b.state
        assert a.recommendation.level == b.recommendation.level
        assert a.recommendation.team == b.recommendation.team
        assert a.recommendation.queue == b.recommendation.queue


class TestRoutingAuthorization:
    def test_collector_cannot_route(self) -> None:
        engine = RoutingEngine()
        ctx = RoutingContext(incident=_make_incident())
        collector = Identity(subject_id="c", role="collector")
        with pytest.raises(InvalidRoutingInputError):
            engine.route_for_identity(collector, ctx)

    def test_analyst_can_route_owned_case(self) -> None:
        engine = RoutingEngine()
        case = _make_incident(created_by="user-analyst-001")
        ctx = RoutingContext(incident=case, severity_band="high")
        analyst = Identity(
            subject_id="user-analyst-001", role=ANALYST_ROLE,
        )
        result = engine.route_for_identity(analyst, ctx)
        assert result.state.value == "ok"

    def test_admin_can_route_any_case(self) -> None:
        engine = RoutingEngine()
        case = _make_incident(created_by="other-user")
        ctx = RoutingContext(incident=case, severity_band="high")
        admin = Identity(subject_id="admin-1", role=ADMIN_ROLE)
        result = engine.route_for_identity(admin, ctx)
        assert result.state.value == "ok"

    def test_analyst_cannot_route_other_analysts_case(self) -> None:
        engine = RoutingEngine()
        case = _make_incident(created_by="other-user")
        ctx = RoutingContext(incident=case, severity_band="high")
        analyst = Identity(
            subject_id="user-analyst-001", role=ANALYST_ROLE,
        )
        with pytest.raises(Exception):
            engine.route_for_identity(analyst, ctx)
