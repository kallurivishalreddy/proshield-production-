"""Unit tests for the ``Rule`` abstract base and ``SimpleRule`` helper.

Reference: docs/PHASE 4/DETECTION_ENGINEERING_AND_FUTURE_AI.md,
Sections 9, 13, 87.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import pytest

from app.rules import (
    Rule,
    RuleEvaluation,
    RuleEvaluationError,
    RuleRegistry,
    RuleState,
    SimpleRule,
)
from tests.unit._rules_helpers import (
    correlation_metadata,
    make_event,
    waf_metadata,
)


# ---------------------------------------------------------------------------
# SimpleRule: positive / negative / reasoner
# ---------------------------------------------------------------------------
def test_simple_rule_match_returns_matched_true() -> None:
    meta = waf_metadata()
    rule = SimpleRule(meta, predicate=lambda e: True)
    ev = make_event(source="waf", event_type="waf_attack_detected")
    out = rule.evaluate(ev)
    assert isinstance(out, RuleEvaluation)
    assert out.matched is True
    assert out.rule_id == "WAF-001"
    assert out.rule_version == 1
    assert out.target_event_id == ev.event_id


def test_simple_rule_no_match_returns_matched_false() -> None:
    meta = waf_metadata()
    rule = SimpleRule(meta, predicate=lambda e: False)
    ev = make_event()
    out = rule.evaluate(ev)
    assert out.matched is False
    assert out.reasoning == ""


def test_simple_rule_reasoner_only_called_on_match() -> None:
    calls: list[Any] = []

    def reasoner(e: Any) -> str:
        calls.append(e.event_id)
        return "explained"

    meta = waf_metadata()
    rule = SimpleRule(
        meta,
        predicate=lambda e: False,
        reasoner=reasoner,
    )
    ev = make_event()
    rule.evaluate(ev)  # no match -> reasoner NOT called
    assert calls == []

    rule2 = SimpleRule(
        waf_metadata(rule_id="WAF-100", version=1),
        predicate=lambda e: True,
        reasoner=reasoner,
    )
    rule2.evaluate(ev)  # match -> reasoner called once
    assert calls == [ev.event_id]
    assert rule2.evaluate(ev).reasoning == "explained"


def test_simple_rule_evaluation_is_deterministic() -> None:
    meta = waf_metadata()
    rule = SimpleRule(
        meta,
        predicate=lambda e: e.source_ip == "203.0.113.10",
    )
    ev = make_event()
    a = rule.evaluate(ev)
    b = rule.evaluate(ev)
    # ``detected_at`` is wall-clock, so the two evaluations are not
    # equal as objects. The deterministic contract is on the
    # reasoning + matched + target fields; we compare those.
    assert a.matched == b.matched
    assert a.rule_id == b.rule_id == "WAF-001"
    assert a.rule_version == b.rule_version == 1
    assert a.target_event_id == b.target_event_id == ev.event_id
    assert a.reasoning == b.reasoning == ""


# ---------------------------------------------------------------------------
# SimpleRule: error surfacing
# ---------------------------------------------------------------------------
def test_simple_rule_buggy_predicate_raises_rule_evaluation_error() -> None:
    meta = waf_metadata()

    def buggy(_e: Any) -> bool:
        raise RuntimeError("boom")

    rule = SimpleRule(meta, predicate=buggy)
    ev = make_event()
    with pytest.raises(RuleEvaluationError) as ei:
        rule.evaluate(ev)
    err = ei.value
    assert err.rule_id == "WAF-001"
    assert err.rule_version == 1
    assert err.event_id == ev.event_id
    assert isinstance(err.cause, RuntimeError)
    assert "boom" in str(err)


def test_simple_rule_rejects_cross_source_correlation() -> None:
    meta = correlation_metadata()
    with pytest.raises(ValueError):
        SimpleRule(meta, predicate=lambda e: True)


def test_simple_rule_rejects_non_callable_predicate() -> None:
    with pytest.raises(TypeError):
        SimpleRule(waf_metadata(), predicate="not callable")  # type: ignore[arg-type]


def test_simple_rule_rejects_non_metadata() -> None:
    with pytest.raises(TypeError):
        SimpleRule("not a metadata", predicate=lambda e: True)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Rule abstract base
# ---------------------------------------------------------------------------
def test_rule_cannot_be_instantiated_directly() -> None:
    with pytest.raises(TypeError):
        Rule()  # type: ignore[abstract]


def test_rule_make_evaluation_default_now() -> None:
    meta = waf_metadata()
    rule = SimpleRule(meta, predicate=lambda e: True)
    ev = make_event()
    out = rule.evaluate(ev)
    assert out.detected_at.tzinfo is not None


def test_rule_make_evaluation_rejects_naive_now() -> None:
    meta = waf_metadata()
    rule = SimpleRule(meta, predicate=lambda e: True)
    ev = make_event()
    naive = datetime(2026, 1, 1)
    with pytest.raises(ValueError):
        rule.make_evaluation(ev, matched=True, now=naive)


# ---------------------------------------------------- FINDING-2 regression
# The framework's contract (Rule.metadata docstring) is that
# ``metadata`` is an **instance attribute** and that the registry
# mutates it. The following test exercises the documented instance
# pattern against ``set_state`` and ``set_enabled`` to lock the
# contract in.
def test_set_state_mutates_rule_instance_metadata_not_class() -> None:
    """A rule's lifecycle state lives on the instance, not the
    class. ``SimpleRule`` already follows the instance pattern; this
    test pins the contract so a future refactor cannot regress it.
    """
    meta = waf_metadata()
    rule_a = SimpleRule(meta, predicate=lambda e: True)
    rule_b = SimpleRule(meta, predicate=lambda e: True)
    r = RuleRegistry()
    r.register(rule_a)
    r.set_state("WAF-001", RuleState.CANDIDATE)
    # The registered instance is now CANDIDATE.
    assert rule_a.metadata.state is RuleState.CANDIDATE
    # The unregistered sibling instance is untouched: the metadata
    # on the *class* (or any other instance) is not mutated.
    assert rule_b.metadata.state is RuleState.APPROVED


def test_set_enabled_mutates_rule_instance_metadata_not_class() -> None:
    meta = waf_metadata()
    rule_a = SimpleRule(meta, predicate=lambda e: True)
    rule_b = SimpleRule(meta, predicate=lambda e: True)
    r = RuleRegistry()
    r.register(rule_a)
    r.set_enabled("WAF-001", False)
    assert rule_a.metadata.enabled is False
    # The unregistered sibling is untouched.
    assert rule_b.metadata.enabled is True


def test_rule_metadata_annotation_docstring_requires_instance() -> None:
    """Sanity check on the documented contract: the ``Rule`` base
    class's docstring now states that ``metadata`` is an instance
    attribute, not a class attribute. This protects the contract
    against silent regression.
    """
    # The Rule class's docstring must mention the instance-attribute
    # contract. The exact wording may evolve; "instance attribute"
    # (case-insensitive) is the load-bearing phrase.
    assert "instance attribute" in (Rule.__doc__ or "").lower()
