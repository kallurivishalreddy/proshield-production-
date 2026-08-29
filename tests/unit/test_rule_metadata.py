"""Unit tests for :class:`app.rules.RuleMetadata`.

Reference: docs/PHASE 4/DETECTION_ENGINEERING_AND_FUTURE_AI.md
(Sections 8, 9, 90) and docs/PHASE 2/DOMAIN_DATA_MODEL.md (Section 5).
"""
from __future__ import annotations

import pytest
from pydantic import ValidationError as PydanticValidationError

from app.rules import RuleCategory, RuleMetadata, RuleState
from tests.unit._rules_helpers import (
    auth_metadata,
    correlation_metadata,
    waf_metadata,
)


# ---------------------------------------------------------------------------
# Required field validation
# ---------------------------------------------------------------------------
def test_metadata_minimal_waf_rule_constructs() -> None:
    m = waf_metadata()
    assert m.rule_id == "WAF-001"
    assert m.version == 1
    assert m.sources == ("waf",)
    assert m.event_types == ("waf_attack_detected",)
    assert m.state is RuleState.APPROVED
    assert m.enabled is True


def test_metadata_default_state_is_candidate() -> None:
    m = RuleMetadata(
        rule_id="WAF-002",
        version=1,
        name="x",
        category=RuleCategory.SOURCE_SPECIFIC,
        sources=("waf",),
        event_types=("waf_attack_detected",),
    )
    assert m.state is RuleState.CANDIDATE
    assert m.enabled is False


def test_metadata_missing_rule_id_raises() -> None:
    with pytest.raises(PydanticValidationError):
        RuleMetadata(
            version=1,
            name="x",
            category=RuleCategory.SOURCE_SPECIFIC,
            sources=("waf",),
            event_types=("waf_attack_detected",),
        )


def test_metadata_missing_version_raises() -> None:
    with pytest.raises(PydanticValidationError):
        RuleMetadata(
            rule_id="WAF-003",
            name="x",
            category=RuleCategory.SOURCE_SPECIFIC,
            sources=("waf",),
            event_types=("waf_attack_detected",),
        )


def test_metadata_missing_name_raises() -> None:
    with pytest.raises(PydanticValidationError):
        RuleMetadata(
            rule_id="WAF-004",
            version=1,
            category=RuleCategory.SOURCE_SPECIFIC,
            sources=("waf",),
            event_types=("waf_attack_detected",),
        )


# ---------------------------------------------------------------------------
# rule_id pattern
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "rid",
    [
        "WAF",
        "WAF-001",
        "AUTH-BRUTEFORCE-7",
        "RATE",
        "CORR-WEB-001",
    ],
)
def test_rule_id_valid_patterns_accepted(rid: str) -> None:
    m = waf_metadata(rule_id=rid)
    assert m.rule_id == rid


@pytest.mark.parametrize(
    "rid",
    [
        "waf-001",
        "WAF_001",
        "1WAF",
        "-WAF",
        "WAF-",
        "WAF--001",
        "waf",
        "WAF 001",
        "",
        "x",
    ],
)
def test_rule_id_invalid_patterns_rejected(rid: str) -> None:
    with pytest.raises(PydanticValidationError):
        waf_metadata(rule_id=rid)


# ---------------------------------------------------------------------------
# Version bounds
# ---------------------------------------------------------------------------
def test_version_must_be_positive() -> None:
    with pytest.raises(PydanticValidationError):
        waf_metadata(version=0)
    with pytest.raises(PydanticValidationError):
        waf_metadata(version=-1)


def test_version_too_large_rejected() -> None:
    with pytest.raises(PydanticValidationError):
        waf_metadata(version=1_000_000)


# ---------------------------------------------------------------------------
# source / event_type catalogue enforcement
# ---------------------------------------------------------------------------
def test_unknown_source_rejected() -> None:
    with pytest.raises(PydanticValidationError):
        RuleMetadata(
            rule_id="WAF-005",
            version=1,
            name="x",
            category=RuleCategory.SOURCE_SPECIFIC,
            sources=("not-a-real-source",),
            event_types=("waf_attack_detected",),
        )


def test_unknown_event_type_rejected() -> None:
    with pytest.raises(PydanticValidationError):
        RuleMetadata(
            rule_id="WAF-006",
            version=1,
            name="x",
            category=RuleCategory.SOURCE_SPECIFIC,
            sources=("waf",),
            event_types=("not_a_real_event_type",),
        )


def test_sources_must_be_sorted() -> None:
    with pytest.raises(PydanticValidationError):
        RuleMetadata(
            rule_id="AUTH-001",
            version=1,
            name="x",
            category=RuleCategory.COMMON_BEHAVIORAL,
            sources=("waf", "iam"),
            event_types=("authentication_failure",),
        )


def test_sources_must_be_unique() -> None:
    with pytest.raises(PydanticValidationError):
        RuleMetadata(
            rule_id="AUTH-002",
            version=1,
            name="x",
            category=RuleCategory.COMMON_BEHAVIORAL,
            sources=("iam", "iam"),
            event_types=("authentication_failure",),
        )


def test_event_types_must_be_sorted_unique() -> None:
    with pytest.raises(PydanticValidationError):
        RuleMetadata(
            rule_id="WAF-007",
            version=1,
            name="x",
            category=RuleCategory.SOURCE_SPECIFIC,
            sources=("waf",),
            event_types=("waf_attack_detected", "suspicious_request"),
        )
    with pytest.raises(PydanticValidationError):
        RuleMetadata(
            rule_id="WAF-008",
            version=1,
            name="x",
            category=RuleCategory.SOURCE_SPECIFIC,
            sources=("waf",),
            event_types=("waf_attack_detected", "waf_attack_detected"),
        )


# ---------------------------------------------------------------------------
# Category-vs-applicability sanity checks
# ---------------------------------------------------------------------------
def test_source_specific_requires_source_and_event_type() -> None:
    with pytest.raises(PydanticValidationError):
        RuleMetadata(
            rule_id="WAF-009",
            version=1,
            name="x",
            category=RuleCategory.SOURCE_SPECIFIC,
            sources=("waf",),
            event_types=(),
        )
    with pytest.raises(PydanticValidationError):
        RuleMetadata(
            rule_id="WAF-010",
            version=1,
            name="x",
            category=RuleCategory.SOURCE_SPECIFIC,
            sources=(),
            event_types=("waf_attack_detected",),
        )


def test_common_behavioral_requires_event_type() -> None:
    with pytest.raises(PydanticValidationError):
        RuleMetadata(
            rule_id="AUTH-003",
            version=1,
            name="x",
            category=RuleCategory.COMMON_BEHAVIORAL,
            sources=("iam",),
            event_types=(),
        )


def test_cross_source_correlation_requires_two_sources() -> None:
    with pytest.raises(PydanticValidationError):
        RuleMetadata(
            rule_id="CORR-001",
            version=1,
            name="x",
            category=RuleCategory.CROSS_SOURCE_CORRELATION,
            sources=("waf", "nginx"),
            event_types=("waf_attack_detected",),
        )
    with pytest.raises(PydanticValidationError):
        RuleMetadata(
            rule_id="CORR-002",
            version=1,
            name="x",
            category=RuleCategory.CROSS_SOURCE_CORRELATION,
            sources=("waf",),
            event_types=(),
        )


def test_cross_source_correlation_allows_empty_event_types() -> None:
    m = correlation_metadata()
    assert m.event_types == ()


# ---------------------------------------------------------------------------
# Extra fields are forbidden / metadata is frozen
# ---------------------------------------------------------------------------
def test_extra_fields_rejected() -> None:
    with pytest.raises(PydanticValidationError):
        RuleMetadata(
            rule_id="WAF-011",
            version=1,
            name="x",
            category=RuleCategory.SOURCE_SPECIFIC,
            sources=("waf",),
            event_types=("waf_attack_detected",),
            extra_field="not allowed",  # type: ignore[call-arg]
        )


def test_metadata_is_frozen() -> None:
    m = waf_metadata()
    with pytest.raises(Exception):
        m.enabled = False  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Helper methods
# ---------------------------------------------------------------------------
def test_is_evaluable_requires_approved_and_enabled() -> None:
    a = waf_metadata(state=RuleState.APPROVED, enabled=True)
    b = waf_metadata(state=RuleState.APPROVED, enabled=False)
    c = waf_metadata(state=RuleState.CANDIDATE, enabled=True)
    d = waf_metadata(state=RuleState.CANDIDATE, enabled=False)
    assert a.is_evaluable() is True
    assert b.is_evaluable() is False
    assert c.is_evaluable() is False
    assert d.is_evaluable() is False


def test_applies_to_source_and_event_type() -> None:
    m = auth_metadata()
    assert m.applies_to_source("iam") is True
    assert m.applies_to_source("siem") is False
    assert m.applies_to_event_type("authentication_failure") is True
    assert m.applies_to_event_type("authentication_success") is False


def test_applicability_signature_is_sorted_deterministic() -> None:
    m = auth_metadata(sources=("iam", "nginx", "waf"))
    sig = m.applicability_signature()
    # The category is included as the trailing element so the
    # signature cannot collide with a different category that
    # shares the same (source, event_type) pairs.
    assert sig == (
        "iam::authentication_failure",
        "nginx::authentication_failure",
        "waf::authentication_failure",
        "common_behavioral",
    )
    assert m.applicability_signature() == sig


def test_applicability_signature_empty_when_missing_either_side() -> None:
    m = correlation_metadata()
    # A correlation rule has no event_types, so the per-source /
    # event-type pairs are empty. The category is still encoded so
    # cross-category signatures never collide.
    assert m.applicability_signature() == ("cross_source_correlation",)


def test_applicability_signature_is_unique_across_categories() -> None:
    """Regression for FINDING-3: cross-category signatures must not
    collide, even when (sources, event_types) are identical.
    """
    from app.rules import RuleCategory, RuleState

    source_specific = RuleMetadata(
        rule_id="WAF-001",
        version=1,
        name="waf",
        category=RuleCategory.SOURCE_SPECIFIC,
        sources=("waf",),
        event_types=("waf_attack_detected",),
        state=RuleState.APPROVED,
        enabled=True,
    )
    common_behavioral = RuleMetadata(
        rule_id="WAF-002",
        version=1,
        name="waf common",
        category=RuleCategory.COMMON_BEHAVIORAL,
        sources=("waf",),
        event_types=("waf_attack_detected",),
        state=RuleState.APPROVED,
        enabled=True,
    )
    correlation = RuleMetadata(
        rule_id="CORR-WEB-001",
        version=1,
        name="waf+nginx+rate correlation",
        category=RuleCategory.CROSS_SOURCE_CORRELATION,
        sources=("nginx", "rate_limiter", "waf"),
        event_types=(),
        state=RuleState.APPROVED,
        enabled=True,
    )
    assert source_specific.applicability_signature() != (
        common_behavioral.applicability_signature()
    )
    assert source_specific.applicability_signature() != (
        correlation.applicability_signature()
    )
    assert common_behavioral.applicability_signature() != (
        correlation.applicability_signature()
    )