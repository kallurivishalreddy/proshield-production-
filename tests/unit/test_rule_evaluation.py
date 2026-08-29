"""Unit tests for :class:`app.rules.RuleEvaluation`.

Reference: docs/PHASE 4/DETECTION_ENGINEERING_AND_FUTURE_AI.md,
Section 13 (Detection Signals).
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from app.rules import RuleEvaluation


def _now() -> datetime:
    return datetime(2026, 1, 1, tzinfo=timezone.utc)


def test_evaluation_minimal_fields() -> None:
    e = RuleEvaluation(
        rule_id="WAF-001",
        rule_version=1,
        matched=True,
        target_event_id="evt-1",
        detected_at=_now(),
    )
    assert e.matched is True
    assert e.rule_id == "WAF-001"
    assert e.rule_version == 1
    assert e.reasoning == ""
    assert e.extra == ()


def test_evaluation_matched_must_be_bool() -> None:
    with pytest.raises(TypeError):
        RuleEvaluation(
            rule_id="WAF-001",
            rule_version=1,
            matched="yes",  # type: ignore[arg-type]
            target_event_id="evt-1",
            detected_at=_now(),
        )


def test_evaluation_empty_rule_id_rejected() -> None:
    with pytest.raises(ValueError):
        RuleEvaluation(
            rule_id="",
            rule_version=1,
            matched=True,
            target_event_id="evt-1",
            detected_at=_now(),
        )


def test_evaluation_version_must_be_positive() -> None:
    with pytest.raises(ValueError):
        RuleEvaluation(
            rule_id="WAF-001",
            rule_version=0,
            matched=True,
            target_event_id="evt-1",
            detected_at=_now(),
        )


def test_evaluation_missing_target_event_id_rejected() -> None:
    with pytest.raises(ValueError):
        RuleEvaluation(
            rule_id="WAF-001",
            rule_version=1,
            matched=True,
            target_event_id="",
            detected_at=_now(),
        )


def test_evaluation_detected_at_must_be_aware() -> None:
    with pytest.raises(ValueError):
        RuleEvaluation(
            rule_id="WAF-001",
            rule_version=1,
            matched=True,
            target_event_id="evt-1",
            detected_at=datetime(2026, 1, 1),
        )


def test_evaluation_reasoning_bounded() -> None:
    with pytest.raises(ValueError):
        RuleEvaluation(
            rule_id="WAF-001",
            rule_version=1,
            matched=True,
            target_event_id="evt-1",
            detected_at=_now(),
            reasoning="x" * 5000,
        )


def test_evaluation_extra_keys_must_be_strings() -> None:
    with pytest.raises(TypeError):
        RuleEvaluation(
            rule_id="WAF-001",
            rule_version=1,
            matched=True,
            target_event_id="evt-1",
            detected_at=_now(),
            extra=((1, "v"),),  # type: ignore[arg-type]
        )


def test_evaluation_is_frozen() -> None:
    e = RuleEvaluation(
        rule_id="WAF-001",
        rule_version=1,
        matched=True,
        target_event_id="evt-1",
        detected_at=_now(),
    )
    with pytest.raises(Exception):
        e.matched = False  # type: ignore[misc]


def test_evaluation_to_dict_is_json_safe() -> None:
    e = RuleEvaluation(
        rule_id="WAF-001",
        rule_version=2,
        matched=True,
        target_event_id="evt-7",
        detected_at=_now(),
        reasoning="matched",
        extra=(("a", 1), ("b", "x")),
    )
    d = e.to_dict()
    assert d["rule_id"] == "WAF-001"
    assert d["rule_version"] == 2
    assert d["matched"] is True
    assert d["target_event_id"] == "evt-7"
    assert d["reasoning"] == "matched"
    assert d["extra"] == {"a": 1, "b": "x"}
    assert isinstance(d["detected_at"], str)
