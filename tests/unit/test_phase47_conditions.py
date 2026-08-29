"""Unit tests for the Phase 4.7 conditions DSL.

Reference: docs/PHASE 4/PHASE 4-07/PHASE-04-07-REPORT.md.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional

import pytest
from pydantic import ValidationError as PydanticValidationError

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
    MAX_NESTING_DEPTH,
    _is_catastrophic_backtracking,
    evaluate_expression,
    get_event_field,
    validate_field_path,
)


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


# ---------------------------------------------------------------- atom construction
def test_atom_eq_string() -> None:
    a = Atom(field="event_type", operator=ConditionOperator.EQ, value="authentication_failure")
    assert a.field == "event_type"
    assert a.operator is ConditionOperator.EQ
    assert a.value == "authentication_failure"


def test_atom_rejects_unknown_operator() -> None:
    with pytest.raises(PydanticValidationError):
        Atom.model_validate(
            {"field": "source", "operator": "magic", "value": "nginx"}
        )


def test_atom_regex_requires_string_value() -> None:
    with pytest.raises(PydanticValidationError):
        Atom.model_validate(
            {"field": "endpoint", "operator": "regex", "value": 42}
        )


def test_atom_regex_rejects_compile_error() -> None:
    with pytest.raises(PydanticValidationError):
        Atom.model_validate(
            {"field": "endpoint", "operator": "regex", "value": "(["}
        )


def test_atom_regex_rejects_oversized_pattern() -> None:
    with pytest.raises(PydanticValidationError):
        Atom.model_validate(
            {"field": "endpoint", "operator": "regex", "value": "a" * 1024}
        )


def test_atom_in_requires_list() -> None:
    with pytest.raises(PydanticValidationError):
        Atom.model_validate(
            {"field": "source", "operator": "in", "value": "nginx"}
        )


def test_atom_in_rejects_empty_list() -> None:
    with pytest.raises(PydanticValidationError):
        Atom.model_validate(
            {"field": "source", "operator": "in", "value": []}
        )


def test_atom_in_rejects_non_primitive_values() -> None:
    with pytest.raises(PydanticValidationError):
        Atom.model_validate(
            {
                "field": "source",
                "operator": "in",
                "value": [{"nested": "object"}],
            }
        )


def test_atom_gt_rejects_bool() -> None:
    with pytest.raises(PydanticValidationError):
        Atom.model_validate(
            {"field": "details.count", "operator": "gt", "value": True}
        )


def test_atom_gt_accepts_number() -> None:
    a = Atom(field="details.count", operator=ConditionOperator.GT, value=3)
    assert a.value == 3


def test_atom_ip_in_cidr_validates_cidr() -> None:
    with pytest.raises(PydanticValidationError):
        Atom.model_validate(
            {"field": "source_ip", "operator": "ip_in_cidr", "value": "not-a-cidr"}
        )


def test_atom_ip_in_cidr_accepts_valid_cidr() -> None:
    a = Atom(field="source_ip", operator=ConditionOperator.IP_IN_CIDR, value="10.0.0.0/8")
    assert a.value == "10.0.0.0/8"


def test_atom_exists_ignores_value() -> None:
    a = Atom(field="source_ip", operator=ConditionOperator.EXISTS, value=None)
    assert a.operator is ConditionOperator.EXISTS


def test_atom_rejects_unknown_field_path() -> None:
    with pytest.raises(PydanticValidationError):
        Atom.model_validate(
            {"field": "__class__", "operator": "eq", "value": "x"}
        )



# ---------------------------------------------------------------- field path validation
def test_validate_field_path_accepts_top_level() -> None:
    validate_field_path("source")
    validate_field_path("event_type")


def test_validate_field_path_rejects_unknown_top_level() -> None:
    with pytest.raises(ValueError):
        validate_field_path("not_a_field")


def test_validate_field_path_accepts_details() -> None:
    validate_field_path("details")
    validate_field_path("details.status_code")


def test_validate_field_path_rejects_dunder() -> None:
    with pytest.raises(ValueError):
        validate_field_path("__class__")


def test_validate_field_path_rejects_dotted_top_level() -> None:
    with pytest.raises(ValueError):
        validate_field_path("source.evil")


def test_validate_field_path_rejects_oversized_details_key() -> None:
    with pytest.raises(ValueError):
        validate_field_path("details." + ("x" * 200))


# ---------------------------------------------------------------- evaluation
def test_evaluate_atom_eq_match() -> None:
    a = Atom(field="event_type", operator=ConditionOperator.EQ, value="authentication_failure")
    ev = _make_event(event_type="authentication_failure")
    assert evaluate_expression(Expression.from_atom(a), ev) is True


def test_evaluate_atom_eq_no_match() -> None:
    a = Atom(field="event_type", operator=ConditionOperator.EQ, value="authentication_failure")
    ev = _make_event(event_type="request_blocked")
    assert evaluate_expression(Expression.from_atom(a), ev) is False


def test_evaluate_atom_in_match() -> None:
    a = Atom(field="source", operator=ConditionOperator.IN, value=["nginx", "waf"])
    ev = _make_event(source="nginx")
    assert evaluate_expression(Expression.from_atom(a), ev) is True


def test_evaluate_atom_regex_match() -> None:
    a = Atom(field="endpoint", operator=ConditionOperator.REGEX, value=r"^/api/.*")
    ev = _make_event(endpoint="/api/login")
    assert evaluate_expression(Expression.from_atom(a), ev) is True


def test_evaluate_atom_regex_no_match() -> None:
    a = Atom(field="endpoint", operator=ConditionOperator.REGEX, value=r"^/admin/.*")
    ev = _make_event(endpoint="/api/login")
    assert evaluate_expression(Expression.from_atom(a), ev) is False


def test_evaluate_atom_ip_in_cidr_match() -> None:
    a = Atom(field="source_ip", operator=ConditionOperator.IP_IN_CIDR, value="203.0.113.0/24")
    ev = _make_event(source_ip="203.0.113.10")
    assert evaluate_expression(Expression.from_atom(a), ev) is True


def test_evaluate_atom_ip_in_cidr_no_match() -> None:
    a = Atom(field="source_ip", operator=ConditionOperator.IP_IN_CIDR, value="10.0.0.0/8")
    ev = _make_event(source_ip="203.0.113.10")
    assert evaluate_expression(Expression.from_atom(a), ev) is False


def test_evaluate_atom_exists() -> None:
    a = Atom(field="source_ip", operator=ConditionOperator.EXISTS, value=None)
    assert evaluate_expression(Expression.from_atom(a), _make_event(source_ip="1.1.1.1")) is True
    assert evaluate_expression(Expression.from_atom(a), _make_event(source_ip=None)) is False


def test_evaluate_atom_not_exists() -> None:
    a = Atom(field="source_ip", operator=ConditionOperator.NOT_EXISTS, value=None)
    assert evaluate_expression(Expression.from_atom(a), _make_event(source_ip=None)) is True


def test_evaluate_atom_contains() -> None:
    a = Atom(field="endpoint", operator=ConditionOperator.CONTAINS, value="login")
    assert evaluate_expression(Expression.from_atom(a), _make_event(endpoint="/api/v1/login")) is True


def test_evaluate_atom_starts_with() -> None:
    a = Atom(field="endpoint", operator=ConditionOperator.STARTS_WITH, value="/api/")
    assert evaluate_expression(Expression.from_atom(a), _make_event(endpoint="/api/login")) is True


def test_evaluate_atom_ends_with() -> None:
    a = Atom(field="endpoint", operator=ConditionOperator.ENDS_WITH, value="login")
    assert evaluate_expression(Expression.from_atom(a), _make_event(endpoint="/api/login")) is True


def test_evaluate_atom_details_key() -> None:
    a = Atom(field="details.status_code", operator=ConditionOperator.EQ, value=401)
    ev = _make_event(details={"status_code": 401})
    assert evaluate_expression(Expression.from_atom(a), ev) is True


def test_evaluate_atom_details_key_missing() -> None:
    a = Atom(field="details.status_code", operator=ConditionOperator.EQ, value=401)
    ev = _make_event(details={})
    assert evaluate_expression(Expression.from_atom(a), ev) is False



# ---------------------------------------------------------------- group / AND / OR
def test_group_and_all_match() -> None:
    g = Group(
        combinator=ConditionCombinator.AND,
        children=(
            Expression.from_atom(Atom(field="source", operator=ConditionOperator.EQ, value="nginx")),
            Expression.from_atom(Atom(field="event_type", operator=ConditionOperator.EQ, value="authentication_failure")),
        ),
    )
    assert evaluate_expression(Expression.from_group(g), _make_event()) is True


def test_group_and_one_mismatch() -> None:
    g = Group(
        combinator=ConditionCombinator.AND,
        children=(
            Expression.from_atom(Atom(field="source", operator=ConditionOperator.EQ, value="nginx")),
            Expression.from_atom(Atom(field="event_type", operator=ConditionOperator.EQ, value="request_blocked")),
        ),
    )
    assert evaluate_expression(Expression.from_group(g), _make_event()) is False


def test_group_or_one_match() -> None:
    g = Group(
        combinator=ConditionCombinator.OR,
        children=(
            Expression.from_atom(Atom(field="source", operator=ConditionOperator.EQ, value="waf")),
            Expression.from_atom(Atom(field="source", operator=ConditionOperator.EQ, value="nginx")),
        ),
    )
    assert evaluate_expression(Expression.from_group(g), _make_event(source="nginx")) is True


def test_group_or_none_match() -> None:
    g = Group(
        combinator=ConditionCombinator.OR,
        children=(
            Expression.from_atom(Atom(field="source", operator=ConditionOperator.EQ, value="waf")),
            Expression.from_atom(Atom(field="source", operator=ConditionOperator.EQ, value="iam")),
        ),
    )
    assert evaluate_expression(Expression.from_group(g), _make_event(source="nginx")) is False


def test_group_rejects_empty_children() -> None:
    with pytest.raises(PydanticValidationError):
        Group(combinator=ConditionCombinator.AND, children=())


def test_nested_group() -> None:
    inner = Group(
        combinator=ConditionCombinator.OR,
        children=(
            Expression.from_atom(Atom(field="event_type", operator=ConditionOperator.EQ, value="request_blocked")),
            Expression.from_atom(Atom(field="event_type", operator=ConditionOperator.EQ, value="authentication_failure")),
        ),
    )
    outer = Group(
        combinator=ConditionCombinator.AND,
        children=(
            Expression.from_atom(Atom(field="source", operator=ConditionOperator.EQ, value="nginx")),
            Expression.from_group(inner),
        ),
    )
    assert evaluate_expression(Expression.from_group(outer), _make_event()) is True


def test_nested_group_depth_limit() -> None:
    def build(depth: int) -> Expression:
        if depth <= 0:
            return Expression.from_atom(Atom(field="source", operator=ConditionOperator.EQ, value="nginx"))
        return Expression.from_group(Group(
            combinator=ConditionCombinator.AND,
            children=(build(depth - 1),),
        ))
    too_deep = build(MAX_NESTING_DEPTH + 2)
    ev = _make_event(source="nginx")
    assert evaluate_expression(too_deep, ev) is False


def test_get_event_field_top_level() -> None:
    ev = _make_event()
    assert get_event_field(ev, "source") == "nginx"


def test_get_event_field_details() -> None:
    ev = _make_event(details={"k": "v"})
    assert get_event_field(ev, "details.k") == "v"
    assert get_event_field(ev, "details") == {"k": "v"}


def test_get_event_field_missing() -> None:
    ev = _make_event(source_ip=None)
    assert get_event_field(ev, "source_ip") is None
    assert get_event_field(ev, "details.missing") is None


def test_evaluator_is_total_for_garbage() -> None:
    """The evaluator never raises for a bad event shape."""
    class FakeEvent:
        pass
    a = Atom(field="source", operator=ConditionOperator.EQ, value="nginx")
    assert evaluate_expression(Expression.from_atom(a), FakeEvent()) is False


# ----------------------------------------------------------------- ReDoS
# Regression tests for the review's section 7.2
# (catastrophic-backtracking regex). Each malicious pattern
# below is a documented ReDoS shape; the static gate at
# validation time must reject it.


def test_redos_detector_flags_nested_quantifier_plus_plus() -> None:
    """``(a+)+`` is a documented ReDoS shape."""
    assert _is_catastrophic_backtracking("(a+)+") is True
    assert _is_catastrophic_backtracking("(a+)+$") is True


def test_redos_detector_flags_nested_quantifier_star_star() -> None:
    """``(a*)*`` is a documented ReDoS shape."""
    assert _is_catastrophic_backtracking("(a*)*") is True
    assert _is_catastrophic_backtracking("(.+)*") is True


def test_redos_detector_flags_nested_quantifier_mixed() -> None:
    """``(a+)*`` and ``(a+)?`` are documented ReDoS shapes."""
    assert _is_catastrophic_backtracking("(a+)*") is True
    assert _is_catastrophic_backtracking("(a+)?") is True
    assert _is_catastrophic_backtracking("([a-z]+)+") is True


def test_redos_detector_flags_nested_groups() -> None:
    """``((a+))+`` (nested groups) is a documented ReDoS shape."""
    assert _is_catastrophic_backtracking("((a+))+") is True
    assert _is_catastrophic_backtracking("(?:a+)+") is True


def test_redos_detector_flags_brace_upper_bound() -> None:
    """``(a+){2,3}`` is catastrophic; ``(a+){1}`` is not."""
    assert _is_catastrophic_backtracking("(a+){2,3}") is True
    assert _is_catastrophic_backtracking("(a+){1,3}") is True
    assert _is_catastrophic_backtracking("(a+){3}") is False
    assert _is_catastrophic_backtracking("(a+){1}") is False


def test_redos_detector_accepts_legitimate_patterns() -> None:
    """The detector does NOT flag legitimate patterns.

    Each of the patterns below is a common, safe
    expression; the structural gate must let them pass.
    """
    legitimate = [
        r"^/api/v[0-9]+/.*$",
        r"^[A-Z][a-z]+$",
        r"[a-zA-Z0-9_]+",
        r"^(a+)$",          # group quantified once (no nesting)
        r"a+b+",            # adjacent quantifiers, no group
        r"^abc{3}$",        # {3} is a single-quantifier
        r"^(ab)+$",         # group with no inner quantifier
        r"foo|bar",         # alternation, no group quantifier
        r"\b\w+@\w+\.\w+\b",
    ]
    for pat in legitimate:
        assert _is_catastrophic_backtracking(pat) is False, pat


def test_atom_regex_rejects_catastrophic_nested_quantifier() -> None:
    """The ``Atom`` model rejects ``(a+)+$`` with a clear error."""
    with pytest.raises(PydanticValidationError) as excinfo:
        Atom(
            field="endpoint",
            operator=ConditionOperator.REGEX,
            value="(a+)+$",
        )
    assert "ReDoS" in str(excinfo.value) or "regex" in str(excinfo.value).lower()


def test_atom_regex_rejects_catastrophic_star() -> None:
    """The ``Atom`` model rejects ``(a*)*`` with a clear error."""
    with pytest.raises(PydanticValidationError):
        Atom(
            field="endpoint",
            operator=ConditionOperator.REGEX,
            value="(a*)*",
        )


def test_atom_regex_accepts_legitimate_pattern() -> None:
    """The ``Atom`` model still accepts a legitimate pattern."""
    a = Atom(
        field="endpoint",
        operator=ConditionOperator.REGEX,
        value=r"^/api/v[0-9]+/.*$",
    )
    assert a.value == r"^/api/v[0-9]+/.*$"


def test_evaluate_atom_regex_no_dos_on_catastrophic() -> None:
    """The runtime ``_regex_match`` is also safe: a catastrophic
    pattern never reaches the regex engine."""
    # Even if a catastrophic pattern somehow reached
    # _regex_match (e.g. an internal construction that
    # bypassed the Atom validator), the runtime
    # defence-in-depth refuses to run the engine.
    from app.rules.management.conditions import _regex_match
    result = _regex_match("aaaaaaaaaaaaaaaaaZ", "(a+)+$")
    assert result is False
    # And the runtime is fast (the engine never started).
    import time
    start = time.perf_counter()
    _regex_match("a" * 30 + "Z", "(a+)+$")
    elapsed_ms = (time.perf_counter() - start) * 1000.0
    # The catastrophic search (if the engine ran) would
    # take seconds on this input. The structural gate
    # returns False almost instantly.
    assert elapsed_ms < 5.0, f"expected < 5ms, got {elapsed_ms:.2f}ms"


def test_redos_detector_skips_escaped_and_character_class() -> None:
    """The detector correctly ignores escapes and character classes.

    ``\\+`` is an escaped plus, not a quantifier; the
    pattern is safe. ``[+]+`` is a character class
    containing ``+`` quantified - also safe (the class
    is a single token).
    """
    # An escaped + is not a quantifier.
    assert _is_catastrophic_backtracking(r"\+") is False
    # A class can be quantified without backtracking risk.
    assert _is_catastrophic_backtracking(r"[+]+") is False
    # A nested group that itself contains an escaped +
    # is also safe.
    assert _is_catastrophic_backtracking(r"(\+)+") is False


