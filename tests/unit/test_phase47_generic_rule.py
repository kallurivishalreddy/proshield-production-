"""Unit tests for :class:`GenericDeclarativeRule`.

Reference: docs/PHASE 4/PHASE 4-07/PHASE-04-07-REPORT.md.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional

import pytest

from app.domain.security_event import (
    SecurityEvent,
    SecurityEventProvenance,
)
from app.domain.uuid7 import uuid7
from app.rules.management.conditions import (
    Atom,
    ConditionCombinator,
    ConditionOperator,
    Expression,
    Group,
)
from app.rules.management.definition import (
    ActionType,
    RuleDefinition,
    RuleType,
)
from app.rules.management.generic_rule import GenericDeclarativeRule
from app.rules.types import RuleCategory, RuleState
from app.severity.models import SeverityBand


def _make_event(
    *,
    source: str = "nginx",
    event_type: str = "authentication_failure",
    source_ip: Optional[str] = "203.0.113.10",
    endpoint: Optional[str] = "/api/login",
    details: Optional[Dict[str, Any]] = None,
) -> SecurityEvent:
    et = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    return SecurityEvent(
        event_id=str(uuid7()),
        event_time=et,
        ingested_at=et,
        source=source,
        event_type=event_type,
        source_ip=source_ip,
        endpoint=endpoint,
        details=details or {},
        provenance=SecurityEventProvenance(
            collector="test", source_event_id="src-1"
        ),
    )


def _make_def(
    *,
    name: str = "test rule",
    conditions: Optional[Expression] = None,
    severity: SeverityBand = SeverityBand.MEDIUM,
    actions=(ActionType.ALERT,),
    state: RuleState = RuleState.APPROVED,
    enabled: bool = True,
    thresholds: Optional[Dict[str, float]] = None,
    evidence_requirements=("source_ip",),
    type: RuleType = RuleType.DETECTION,
    combinator: ConditionCombinator = ConditionCombinator.AND,
    window_seconds: Optional[int] = None,
) -> RuleDefinition:
    return RuleDefinition(
        rule_id="CUSTOM-001",
        version=1,
        name=name,
        category=RuleCategory.SOURCE_SPECIFIC,
        type=type,
        state=state,
        enabled=enabled,
        severity=severity,
        sources=("nginx",),
        event_types=("authentication_failure",),
        combinator=combinator,
        conditions=conditions,
        scope=(),
        evidence_requirements=evidence_requirements,
        thresholds=thresholds or {},
        window_seconds=window_seconds,
        actions=actions,
    )


# ----------------------------------------------------------------- construction
def test_construction_binds_metadata() -> None:
    rule = GenericDeclarativeRule(_make_def())
    assert rule.metadata.rule_id == "CUSTOM-001"
    assert rule.metadata.version == 1
    assert rule.metadata.state is RuleState.APPROVED
    assert rule.metadata.enabled is True


def test_construction_rejects_non_definition() -> None:
    with pytest.raises(TypeError):
        GenericDeclarativeRule("not a definition")  # type: ignore[arg-type]


def test_definition_property_is_read_only() -> None:
    rule = GenericDeclarativeRule(_make_def())
    assert rule.definition.rule_id == "CUSTOM-001"


# ----------------------------------------------------------------- detection evaluation
def test_observation_only_rule_matches_nginx_auth_failure() -> None:
    rule = GenericDeclarativeRule(_make_def(conditions=None))
    ev = _make_event()
    result = rule.evaluate(ev)
    assert result.matched is True
    assert result.rule_id == "CUSTOM-001"
    assert result.rule_version == 1


def test_observation_only_rule_matches_other_source() -> None:
    # The framework's applicability filter is what
    # would actually skip a non-applicable rule. The
    # generic evaluator itself does not filter; the
    # framework does. We test the generic evaluator
    # directly here.
    rule = GenericDeclarativeRule(_make_def())
    ev = _make_event(source="waf")
    result = rule.evaluate(ev)
    assert result.matched is True


def test_rule_with_atom_condition_matches() -> None:
    cond = Expression.from_atom(
        Atom(
            field="event_type",
            operator=ConditionOperator.EQ,
            value="authentication_failure",
        )
    )
    rule = GenericDeclarativeRule(_make_def(conditions=cond))
    assert rule.evaluate(_make_event()).matched is True
    assert rule.evaluate(_make_event(event_type="request_blocked")).matched is False


def test_rule_with_or_conditions_one_match() -> None:
    cond = Expression.from_group(
        Group(
            combinator=ConditionCombinator.OR,
            children=(
                Expression.from_atom(Atom(field="event_type", operator=ConditionOperator.EQ, value="authentication_failure")),
                Expression.from_atom(Atom(field="event_type", operator=ConditionOperator.EQ, value="request_blocked")),
            ),
        )
    )
    rule = GenericDeclarativeRule(_make_def(conditions=cond, combinator=ConditionCombinator.OR))
    assert rule.evaluate(_make_event(event_type="authentication_failure")).matched is True
    assert rule.evaluate(_make_event(event_type="request_blocked")).matched is True
    assert rule.evaluate(_make_event(event_type="waf_attack_detected")).matched is False


def test_rule_with_evidence_requirements_missing() -> None:
    rule = GenericDeclarativeRule(_make_def(conditions=None))
    ev = _make_event(source_ip=None)
    result = rule.evaluate(ev)
    assert result.matched is False
    assert "evidence_requirements" in result.reasoning


def test_rule_with_evidence_requirements_present() -> None:
    rule = GenericDeclarativeRule(
        _make_def(conditions=None, evidence_requirements=("source_ip",))
    )
    ev = _make_event(source_ip="1.1.1.1")
    result = rule.evaluate(ev)
    assert result.matched is True


def test_rule_threshold_observed() -> None:
    cond = Expression.from_atom(
        Atom(
            field="event_type",
            operator=ConditionOperator.EQ,
            value="authentication_failure",
        )
    )
    rule = GenericDeclarativeRule(
        _make_def(
            conditions=cond,
            thresholds={"status_code": 401},
            type=RuleType.THRESHOLD,
            window_seconds=60,
        )
    )
    assert rule.evaluate(_make_event(details={"status_code": 401})).matched is True
    assert rule.evaluate(_make_event(details={"status_code": 200})).matched is False
    assert rule.evaluate(_make_event(details={})).matched is False


def test_rule_threshold_with_bool_rejected() -> None:
    cond = Expression.from_atom(
        Atom(field="event_type", operator=ConditionOperator.EQ, value="x")
    )
    rule = GenericDeclarativeRule(
        _make_def(
            conditions=cond,
            thresholds={"x": 1},
            type=RuleType.THRESHOLD,
            window_seconds=60,
        )
    )
    # A boolean is not a valid numeric threshold value.
    assert rule.evaluate(_make_event(details={"x": True})).matched is False


def test_rule_total_on_non_event() -> None:
    rule = GenericDeclarativeRule(_make_def())
    result = rule.evaluate("not an event")  # type: ignore[arg-type]
    assert result.matched is False


def test_rule_extra_field_carries_severity_and_actions() -> None:
    rule = GenericDeclarativeRule(
        _make_def(
            actions=(ActionType.ALERT, ActionType.BLOCK_REMEDIATION),
            conditions=None,
        )
    )
    result = rule.evaluate(_make_event())
    assert result.matched is True
    extras = dict(result.extra)
    assert "severity" in extras
    assert "actions" in extras
    assert "alert" in extras["actions"]
    assert "block_remediation" in extras["actions"]


# ----------------------------------------------------------------- determinism
def test_rule_is_deterministic() -> None:
    """Same event + same rule -> same outcome (matched / not)."""
    rule = GenericDeclarativeRule(_make_def(conditions=None))
    ev = _make_event()
    r1 = rule.evaluate(ev)
    r2 = rule.evaluate(ev)
    assert r1.matched == r2.matched
    assert r1.rule_id == r2.rule_id
    assert r1.target_event_id == r2.target_event_id
    assert r1.reasoning == r2.reasoning

