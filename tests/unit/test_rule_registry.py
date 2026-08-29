"""Unit tests for the authoritative :class:`RuleRegistry`.

Reference: docs/PHASE 4/DETECTION_ENGINEERING_AND_FUTURE_AI.md
(Sections 10, 11, 88, 89, 90) and docs/PHASE 2/DOMAIN_DATA_MODEL.md.
"""
from __future__ import annotations

import pytest

from app.rules import (
    CandidateNotPromotableError,
    DuplicateRuleError,
    Rule,
    RuleCategory,
    RuleMetadata,
    RuleRegistry,
    RuleState,
    RuleValidationError,
    SimpleRule,
    SupersededVersionNotReenablableError,
    UnknownRuleError,
)
from tests.unit._rules_helpers import (
    auth_metadata,
    correlation_metadata,
    make_event,
    waf_metadata,
    NoopRule,
)


def _empty() -> RuleRegistry:
    return RuleRegistry()


def test_empty_registry_is_empty() -> None:
    r = _empty()
    assert r.is_empty() is True
    assert len(r) == 0
    assert r.list_all() == []
    assert r.list_enabled() == []
    assert r.list_for_category(RuleCategory.SOURCE_SPECIFIC) == []
    assert r.get("WAF-001") is None
    assert r.has("WAF-001") is False
    assert "WAF-001" not in r


def test_empty_registry_applicability_returns_empty() -> None:
    r = _empty()
    ev = make_event()
    assert r.applies_to(ev) == []
    assert r.list_for_event("waf", "waf_attack_detected") == []


# ----------------------------------------------------------------- Positive
def test_register_and_get_default_version() -> None:
    r = _empty()
    rule = SimpleRule(waf_metadata(), predicate=lambda e: True)
    r.register(rule)
    assert len(r) == 1
    assert r.is_empty() is False
    assert r.get("WAF-001") is rule
    assert r.get("WAF-001", version=1) is rule
    assert r.latest_version("WAF-001") == 1
    assert "WAF-001" in r


def test_register_multiple_rules() -> None:
    r = _empty()
    r.register(SimpleRule(waf_metadata(), predicate=lambda e: True))
    r.register(SimpleRule(auth_metadata(), predicate=lambda e: True))
    r.register(NoopRule(correlation_metadata()))
    assert len(r) == 3
    assert {rule.metadata.rule_id for rule in r.list_all()} == {
        "WAF-001",
        "AUTH-BRUTEFORCE-001",
        "CORR-WEB-001",
    }


def test_list_all_is_deterministic_by_rule_id_then_version() -> None:
    r = _empty()
    r.register(SimpleRule(waf_metadata(rule_id="WAF-001"), predicate=lambda e: True))
    r.register(SimpleRule(auth_metadata(), predicate=lambda e: True))
    r.register(SimpleRule(waf_metadata(rule_id="WAF-001", version=2), predicate=lambda e: True))
    ids = [(rule.metadata.rule_id, rule.metadata.version) for rule in r.list_all()]
    assert ids == [
        ("AUTH-BRUTEFORCE-001", 1),
        ("WAF-001", 1),
        ("WAF-001", 2),
    ]


# ----------------------------------------------------------------- Versioning
def test_register_new_version_strictly_greater() -> None:
    r = _empty()
    r.register(SimpleRule(waf_metadata(version=1), predicate=lambda e: True))
    r.register(SimpleRule(waf_metadata(version=2), predicate=lambda e: True))
    assert r.latest_version("WAF-001") == 2
    assert r.get("WAF-001").metadata.version == 2
    assert r.get("WAF-001", version=1) is not None


def test_register_rejects_non_monotonic_version() -> None:
    r = _empty()
    r.register(SimpleRule(waf_metadata(version=2), predicate=lambda e: True))
    # Re-registering the same id+version with a different object is a
    # duplicate, not a version-validation error.
    with pytest.raises(DuplicateRuleError):
        r.register(SimpleRule(waf_metadata(version=2), predicate=lambda e: True))
    # A strictly smaller new version is rejected.
    with pytest.raises(RuleValidationError):
        r.register(SimpleRule(waf_metadata(version=1), predicate=lambda e: True))


def test_register_rejects_same_id_version_with_different_object() -> None:
    r = _empty()
    r.register(SimpleRule(waf_metadata(), predicate=lambda e: True))
    other = SimpleRule(waf_metadata(), predicate=lambda e: False)
    with pytest.raises(DuplicateRuleError):
        r.register(other)


def test_register_same_object_is_idempotent() -> None:
    r = _empty()
    rule = SimpleRule(waf_metadata(), predicate=lambda e: True)
    r.register(rule)
    r.register(rule)
    assert len(r) == 1


# ----------------------------------------------------------------- Negative
def test_register_rejects_non_rule_object() -> None:
    r = _empty()
    with pytest.raises(RuleValidationError):
        r.register("not a rule")  # type: ignore[arg-type]
    with pytest.raises(RuleValidationError):
        r.register(None)  # type: ignore[arg-type]


# ------------------------------------------- Candidate vs Approved gate
def test_register_rejects_enabled_candidate() -> None:
    r = _empty()
    meta = waf_metadata(state=RuleState.CANDIDATE, enabled=True)
    rule = SimpleRule(meta, predicate=lambda e: True)
    with pytest.raises(CandidateNotPromotableError):
        r.register(rule)


def test_register_candidate_is_allowed() -> None:
    r = _empty()
    meta = waf_metadata(state=RuleState.CANDIDATE, enabled=False)
    r.register(SimpleRule(meta, predicate=lambda e: True))
    assert r.get("WAF-001") is not None
    assert r.list_enabled() == []


# ----------------------------------------------------------------- set_state
def test_set_state_promotes_candidate_to_approved() -> None:
    r = _empty()
    r.register(SimpleRule(
        waf_metadata(state=RuleState.CANDIDATE, enabled=False),
        predicate=lambda e: True,
    ))
    r.set_state("WAF-001", RuleState.APPROVED)
    assert r.get("WAF-001").metadata.state is RuleState.APPROVED


def test_set_state_demote_keeps_disabled() -> None:
    r = _empty()
    r.register(SimpleRule(waf_metadata(), predicate=lambda e: True))
    r.set_state("WAF-001", RuleState.CANDIDATE)
    rule = r.get("WAF-001")
    assert rule.metadata.state is RuleState.CANDIDATE
    assert rule.metadata.enabled is False


def test_set_state_unknown_rule_raises() -> None:
    r = _empty()
    with pytest.raises(UnknownRuleError):
        r.set_state("WAF-NOT-THERE", RuleState.APPROVED)


def test_set_state_same_state_is_noop() -> None:
    r = _empty()
    rule = SimpleRule(waf_metadata(), predicate=lambda e: True)
    r.register(rule)
    out = r.set_state("WAF-001", RuleState.APPROVED)
    assert out is rule
    assert out.metadata.state is RuleState.APPROVED


def test_set_state_requires_enum() -> None:
    r = _empty()
    r.register(SimpleRule(waf_metadata(), predicate=lambda e: True))
    with pytest.raises(RuleValidationError):
        r.set_state("WAF-001", "approved")  # type: ignore[arg-type]


# ----------------------------------------------------------------- set_enabled
def test_set_enabled_on_approved_works() -> None:
    r = _empty()
    r.register(SimpleRule(
        waf_metadata(state=RuleState.APPROVED, enabled=False),
        predicate=lambda e: True,
    ))
    r.set_enabled("WAF-001", True)
    assert r.get("WAF-001").metadata.enabled is True
    assert r.list_enabled() != []


def test_set_enabled_rejects_candidate_promotion_via_set_enabled() -> None:
    r = _empty()
    r.register(SimpleRule(
        waf_metadata(state=RuleState.CANDIDATE, enabled=False),
        predicate=lambda e: True,
    ))
    with pytest.raises(CandidateNotPromotableError):
        r.set_enabled("WAF-001", True)


def test_set_enabled_false_always_allowed() -> None:
    r = _empty()
    r.register(SimpleRule(
        waf_metadata(state=RuleState.APPROVED, enabled=True),
        predicate=lambda e: True,
    ))
    r.set_enabled("WAF-001", False)
    assert r.get("WAF-001").metadata.enabled is False


def test_set_enabled_unknown_rule_raises() -> None:
    r = _empty()
    with pytest.raises(UnknownRuleError):
        r.set_enabled("WAF-NOT-THERE", True)


def test_set_enabled_requires_bool() -> None:
    r = _empty()
    r.register(SimpleRule(waf_metadata(), predicate=lambda e: True))
    with pytest.raises(RuleValidationError):
        r.set_enabled("WAF-001", "yes")  # type: ignore[arg-type]


# ----------------------------------------------------- Applicability filter
def test_applicability_filters_by_source_and_event_type() -> None:
    r = _empty()
    r.register(SimpleRule(waf_metadata(), predicate=lambda e: True))
    r.register(SimpleRule(auth_metadata(), predicate=lambda e: True))
    r.register(NoopRule(correlation_metadata()))
    ev = make_event(source="waf", event_type="waf_attack_detected")
    out = r.applies_to(ev)
    assert [rule.metadata.rule_id for rule in out] == ["WAF-001"]


def test_applicability_skips_candidate_and_disabled() -> None:
    r = _empty()
    r.register(SimpleRule(
        waf_metadata(state=RuleState.APPROVED, enabled=True),
        predicate=lambda e: True,
    ))
    # Disabled even though APPROVED: must not enter applicability.
    r.register(SimpleRule(
        waf_metadata(rule_id="WAF-002", state=RuleState.APPROVED, enabled=False),
        predicate=lambda e: True,
    ))
    # CANDIDATE: must not enter applicability (cannot be enabled at
    # construction; this is the rule that would never be approved).
    r.register(SimpleRule(
        waf_metadata(rule_id="WAF-003", state=RuleState.CANDIDATE, enabled=False),
        predicate=lambda e: True,
    ))
    ev = make_event(source="waf", event_type="waf_attack_detected")
    out = r.applies_to(ev)
    assert [rule.metadata.rule_id for rule in out] == ["WAF-001"]


def test_list_for_event_invalid_args_return_empty() -> None:
    r = _empty()
    r.register(SimpleRule(waf_metadata(), predicate=lambda e: True))
    assert r.list_for_event("", "waf_attack_detected") == []
    assert r.list_for_event("waf", "") == []


def test_list_for_category() -> None:
    r = _empty()
    r.register(SimpleRule(waf_metadata(), predicate=lambda e: True))
    r.register(SimpleRule(auth_metadata(), predicate=lambda e: True))
    r.register(NoopRule(correlation_metadata()))
    assert {rule.metadata.rule_id for rule in r.list_for_category(
        RuleCategory.SOURCE_SPECIFIC)} == {"WAF-001"}
    assert {rule.metadata.rule_id for rule in r.list_for_category(
        RuleCategory.COMMON_BEHAVIORAL)} == {"AUTH-BRUTEFORCE-001"}
    assert {rule.metadata.rule_id for rule in r.list_for_category(
        RuleCategory.CROSS_SOURCE_CORRELATION)} == {"CORR-WEB-001"}


def test_list_enabled_only_returns_approved_enabled() -> None:
    r = _empty()
    r.register(SimpleRule(waf_metadata(), predicate=lambda e: True))
    r.register(SimpleRule(
        waf_metadata(rule_id="WAF-002", state=RuleState.CANDIDATE, enabled=False),
        predicate=lambda e: True,
    ))
    r.register(SimpleRule(
        waf_metadata(rule_id="WAF-003", state=RuleState.APPROVED, enabled=False),
        predicate=lambda e: True,
    ))
    enabled = r.list_enabled()
    assert {rule.metadata.rule_id for rule in enabled} == {"WAF-001"}


# --------------------------------------------------------- Concurrency smoke
def test_registry_is_safe_under_repeated_registration() -> None:
    r = _empty()
    rule = SimpleRule(waf_metadata(), predicate=lambda e: True)
    for _ in range(50):
        r.register(rule)
    assert len(r) == 1
    assert r.list_all() == [rule]


# ---------------------------------------------------- FINDING-1 regression
# Re-enabling a superseded version (a version that is not the latest
# for its rule_id) must be rejected. Otherwise a deprecated rule
# would silently re-enter the live evaluation set and produce
# duplicate detections on every matching event.
def test_set_enabled_rejects_reenabling_superseded_version() -> None:
    r = _empty()
    r.register(SimpleRule(waf_metadata(version=1), predicate=lambda e: True))
    r.register(
        SimpleRule(
            waf_metadata(version=2),
            predicate=lambda e: True,
        )
    )
    # Sanity: v1 is enabled by default, latest is 2.
    assert r.latest_version("WAF-001") == 2
    assert r.get("WAF-001", version=1).metadata.enabled is True
    # Disable v1 (allowed).
    r.set_enabled("WAF-001", False, version=1)
    assert r.get("WAF-001", version=1).metadata.enabled is False
    # Re-enable v1 must be rejected: v1 is superseded by v2.
    with pytest.raises(SupersededVersionNotReenablableError):
        r.set_enabled("WAF-001", True, version=1)
    # The rule must remain disabled.
    assert r.get("WAF-001", version=1).metadata.enabled is False


def test_set_enabled_latest_version_always_reenablable() -> None:
    """Disabling and re-enabling the latest version is the normal
    toggle path and must keep working.
    """
    r = _empty()
    r.register(SimpleRule(waf_metadata(version=1), predicate=lambda e: True))
    r.register(
        SimpleRule(waf_metadata(version=2), predicate=lambda e: True)
    )
    # Disable + re-enable the latest (v2). This is allowed.
    r.set_enabled("WAF-001", False)
    assert r.get("WAF-001", version=2).metadata.enabled is False
    r.set_enabled("WAF-001", True)
    assert r.get("WAF-001", version=2).metadata.enabled is True


def test_set_enabled_only_version_can_be_disabled_and_reenabled() -> None:
    """A sole version (no newer one registered) can always be
    disabled and re-enabled.
    """
    r = _empty()
    r.register(SimpleRule(waf_metadata(), predicate=lambda e: True))
    r.set_enabled("WAF-001", False)
    r.set_enabled("WAF-001", True)
    assert r.get("WAF-001", version=1).metadata.enabled is True


def test_set_enabled_reenabling_superseded_with_no_op_state() -> None:
    """If the targeted version is ALREADY enabled, the superseded
    guard must NOT fire (no-op returns the rule, never raises).
    """
    r = _empty()
    r.register(SimpleRule(waf_metadata(version=1), predicate=lambda e: True))
    r.register(
        SimpleRule(waf_metadata(version=2), predicate=lambda e: True)
    )
    # v1 is enabled by default; calling set_enabled(True, version=1)
    # is a no-op and must not raise, even though v1 is superseded.
    rule = r.set_enabled("WAF-001", True, version=1)
    assert rule.metadata.version == 1
    assert rule.metadata.enabled is True


def test_set_enabled_reenabling_superseded_error_subclass() -> None:
    """SupersededVersionNotReenablableError is a registry error and
    carries a safe_message that callers can surface to clients
    without leaking internals.
    """
    r = _empty()
    r.register(SimpleRule(waf_metadata(version=1), predicate=lambda e: True))
    r.register(
        SimpleRule(waf_metadata(version=2), predicate=lambda e: True)
    )
    r.set_enabled("WAF-001", False, version=1)
    with pytest.raises(SupersededVersionNotReenablableError) as ei:
        r.set_enabled("WAF-001", True, version=1)
    err = ei.value
    # safe_message is for client consumption.
    assert "superseded" in err.safe_message.lower()
    assert "WAF-001" in err.safe_message
    # internal_detail is for server-side logs only.
    assert err.internal_detail is not None
    assert "targeted_version=1" in err.internal_detail
    assert "latest_version=2" in err.internal_detail


def test_list_for_event_after_superseded_guard_does_not_include_v1() -> None:
    """After the guard fires, v1 must remain disabled and excluded
    from the live evaluation set.
    """
    r = _empty()
    r.register(SimpleRule(waf_metadata(version=1), predicate=lambda e: True))
    r.register(
        SimpleRule(waf_metadata(version=2), predicate=lambda e: True)
    )
    r.set_enabled("WAF-001", False, version=1)
    # Attempted re-enable of v1 is rejected.
    with pytest.raises(SupersededVersionNotReenablableError):
        r.set_enabled("WAF-001", True, version=1)
    ev = make_event(source="waf", event_type="waf_attack_detected")
    out = r.list_for_event("waf", "waf_attack_detected")
    # Only v2 is in the live set.
    assert [rule.metadata.version for rule in out] == [2]