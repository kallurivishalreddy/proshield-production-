"""Unit tests for the Phase 4.7 :class:`RuleDefinition` model.

Reference: docs/PHASE 4/PHASE 4-07/PHASE-04-07-REPORT.md.
"""
from __future__ import annotations

from typing import Any, Dict

import pytest
from pydantic import ValidationError as PydanticValidationError

from app.rules.management.conditions import (
    ConditionCombinator,
)
from app.rules.management.definition import (
    ActionType,
    RuleDefinition,
    RuleType,
)
from app.rules.types import RuleCategory, RuleState
from app.severity.models import SeverityBand


def _base_payload() -> Dict[str, Any]:
    return {
        "rule_id": "CUSTOM-001",
        "version": 1,
        "name": "Custom NGINX 401 detector",
        "description": "A user-defined rule",
        "category": RuleCategory.SOURCE_SPECIFIC.value,
        "type": RuleType.DETECTION.value,
        "state": RuleState.CANDIDATE.value,
        "enabled": False,
        "severity": SeverityBand.MEDIUM.value,
        "sources": ["nginx"],
        "event_types": ["authentication_failure"],
        "tags": ["AUTH", "CUSTOM"],
        "references": ["docs/PHASE 4/PHASE 4-07/PHASE-04-07-REPORT.md"],
        "combinator": ConditionCombinator.AND.value,
        "scope": ["asset=web-api-01"],
        "evidence_requirements": ["source_ip"],
        "thresholds": {},
        "window_seconds": None,
        "actions": [ActionType.ALERT.value],
    }


# ----------------------------------------------------------------- valid definitions
def test_minimal_valid_definition() -> None:
    d = RuleDefinition.model_validate(_base_payload())
    assert d.rule_id == "CUSTOM-001"
    assert d.version == 1
    assert d.state == "candidate"
    assert d.enabled is False
    assert d.severity is SeverityBand.MEDIUM


def test_definition_round_trip_canonical_dict() -> None:
    d = RuleDefinition.model_validate(_base_payload())
    payload = d.to_canonical_dict()
    assert payload["rule_id"] == "CUSTOM-001"
    assert payload["category"] == "source_specific"
    assert payload["type"] == "detection"
    assert payload["state"] == "candidate"
    assert payload["enabled"] is False
    rebuilt = RuleDefinition.model_validate(payload)
    assert rebuilt == d


def test_definition_to_metadata() -> None:
    d = RuleDefinition.model_validate(_base_payload())
    meta = d.to_metadata()
    assert meta.rule_id == "CUSTOM-001"
    assert meta.version == 1
    assert meta.category is RuleCategory.SOURCE_SPECIFIC


# ----------------------------------------------------------------- rule_id pattern
@pytest.mark.parametrize("rid", ["WAF", "WAF-001", "AUTH-BRUTEFORCE-7", "RATE", "CUSTOM-123"])
def test_valid_rule_ids(rid: str) -> None:
    p = _base_payload()
    p["rule_id"] = rid
    d = RuleDefinition.model_validate(p)
    assert d.rule_id == rid


@pytest.mark.parametrize("rid", ["waf-001", "WAF_001", "1WAF", "-WAF", "WAF--001", "waf", "WAF 001", ""])
def test_invalid_rule_ids(rid: str) -> None:
    p = _base_payload()
    p["rule_id"] = rid
    with pytest.raises(PydanticValidationError):
        RuleDefinition.model_validate(p)


# ----------------------------------------------------------------- sources / event_types
def test_invalid_source_rejected() -> None:
    p = _base_payload()
    p["sources"] = ["not_a_source"]
    with pytest.raises(PydanticValidationError):
        RuleDefinition.model_validate(p)


def test_sources_must_be_sorted() -> None:
    p = _base_payload()
    p["sources"] = ["waf", "nginx"]  # not sorted
    with pytest.raises(PydanticValidationError):
        RuleDefinition.model_validate(p)


def test_invalid_event_type_rejected() -> None:
    p = _base_payload()
    p["event_types"] = ["bogus_event_type"]
    with pytest.raises(PydanticValidationError):
        RuleDefinition.model_validate(p)


# ----------------------------------------------------------------- severity / state
def test_invalid_severity_rejected() -> None:
    p = _base_payload()
    p["severity"] = "ultra"
    with pytest.raises(PydanticValidationError):
        RuleDefinition.model_validate(p)


def test_enabled_candidate_state_rejected() -> None:
    p = _base_payload()
    p["enabled"] = True
    p["state"] = "candidate"
    with pytest.raises(PydanticValidationError):
        RuleDefinition.model_validate(p)


def test_enabled_approved_state_accepted() -> None:
    p = _base_payload()
    p["enabled"] = True
    p["state"] = "approved"
    d = RuleDefinition.model_validate(p)
    assert d.enabled is True
    assert d.state == "approved"



# ----------------------------------------------------------------- category invariants
def test_source_specific_requires_event_type() -> None:
    p = _base_payload()
    p["event_types"] = ()
    with pytest.raises(PydanticValidationError):
        RuleDefinition.model_validate(p)


def test_cross_source_correlation_requires_two_sources() -> None:
    p = _base_payload()
    p["category"] = "cross_source_correlation"
    p["sources"] = ["nginx"]
    p["event_types"] = ()
    with pytest.raises(PydanticValidationError):
        RuleDefinition.model_validate(p)


def test_cross_source_correlation_accepts_two_sources() -> None:
    p = _base_payload()
    p["category"] = "cross_source_correlation"
    p["sources"] = ["nginx", "waf"]
    p["event_types"] = ()
    d = RuleDefinition.model_validate(p)
    assert d.category is RuleCategory.CROSS_SOURCE_CORRELATION


# ----------------------------------------------------------------- type invariants
def test_threshold_requires_window() -> None:
    p = _base_payload()
    p["type"] = "threshold"
    p["thresholds"] = {"status_code": 401}
    p["window_seconds"] = None
    with pytest.raises(PydanticValidationError):
        RuleDefinition.model_validate(p)


def test_threshold_requires_thresholds_dict() -> None:
    p = _base_payload()
    p["type"] = "threshold"
    p["window_seconds"] = 60
    p["thresholds"] = {}
    with pytest.raises(PydanticValidationError):
        RuleDefinition.model_validate(p)


def test_rate_limit_rule() -> None:
    p = _base_payload()
    p["type"] = "rate_limit"
    p["thresholds"] = {"status_code": 429}
    p["window_seconds"] = 60
    p["conditions"] = {
        "kind": "atom",
        "atom": {
            "field": "event_type",
            "operator": "eq",
            "value": "authentication_failure",
        },
    }
    d = RuleDefinition.model_validate(p)
    assert d.type is RuleType.RATE_LIMIT


def test_correlation_rule_requires_window() -> None:
    p = _base_payload()
    p["type"] = "correlation"
    p["category"] = "cross_source_correlation"
    p["sources"] = ["nginx", "waf"]
    p["event_types"] = ()
    p["thresholds"] = {"count": 10}
    p["window_seconds"] = None
    with pytest.raises(PydanticValidationError):
        RuleDefinition.model_validate(p)


def test_correlation_rule_requires_one_threshold() -> None:
    p = _base_payload()
    p["type"] = "correlation"
    p["category"] = "cross_source_correlation"
    p["sources"] = ["nginx", "waf"]
    p["event_types"] = ()
    p["thresholds"] = {"count": 10, "extra": 1}
    p["window_seconds"] = 60
    with pytest.raises(PydanticValidationError):
        RuleDefinition.model_validate(p)


def test_correlation_rule_with_one_threshold() -> None:
    p = _base_payload()
    p["type"] = "correlation"
    p["category"] = "cross_source_correlation"
    p["sources"] = ["nginx", "waf"]
    p["event_types"] = ()
    p["thresholds"] = {"count": 10}
    p["window_seconds"] = 60
    p["conditions"] = {
        "kind": "atom",
        "atom": {
            "field": "source",
            "operator": "in",
            "value": ["nginx", "waf"],
        },
    }
    d = RuleDefinition.model_validate(p)
    assert d.type is RuleType.CORRELATION


def test_non_detection_requires_conditions() -> None:
    p = _base_payload()
    p["type"] = "threshold"
    p["thresholds"] = {"status_code": 401}
    p["window_seconds"] = 60
    p["conditions"] = None
    with pytest.raises(PydanticValidationError):
        RuleDefinition.model_validate(p)



# ----------------------------------------------------------------- actions
def test_invalid_action_rejected() -> None:
    p = _base_payload()
    p["actions"] = ["magic"]
    with pytest.raises(PydanticValidationError):
        RuleDefinition.model_validate(p)


def test_block_remediation_action_accepted() -> None:
    p = _base_payload()
    p["actions"] = ["alert", "block_remediation"]
    d = RuleDefinition.model_validate(p)
    assert ActionType.BLOCK_REMEDIATION in d.actions


# ----------------------------------------------------------------- thresholds bounds
def test_threshold_rejects_bool() -> None:
    p = _base_payload()
    p["thresholds"] = {"x": True}
    with pytest.raises(PydanticValidationError):
        RuleDefinition.model_validate(p)


def test_threshold_rejects_oversized_value() -> None:
    p = _base_payload()
    p["thresholds"] = {"x": 1e15}
    with pytest.raises(PydanticValidationError):
        RuleDefinition.model_validate(p)


# ----------------------------------------------------------------- evidence_requirements
def test_evidence_requirements_validates_field_paths() -> None:
    p = _base_payload()
    p["evidence_requirements"] = ["__class__"]
    with pytest.raises(PydanticValidationError):
        RuleDefinition.model_validate(p)


def test_evidence_requirements_accepts_details_keys() -> None:
    p = _base_payload()
    p["evidence_requirements"] = ["source_ip", "details.status_code"]
    d = RuleDefinition.model_validate(p)
    assert "source_ip" in d.evidence_requirements


# ----------------------------------------------------------------- scope
def test_scope_must_be_unique() -> None:
    p = _base_payload()
    p["scope"] = ["a", "a"]
    with pytest.raises(PydanticValidationError):
        RuleDefinition.model_validate(p)


# ----------------------------------------------------------------- conditions
def test_conditions_persisted() -> None:
    p = _base_payload()
    p["conditions"] = {
        "kind": "atom",
        "atom": {
            "field": "event_type",
            "operator": "eq",
            "value": "authentication_failure",
        },
    }
    d = RuleDefinition.model_validate(p)
    assert d.conditions is not None
    assert d.conditions.kind == "atom"


def test_conditions_persisted_with_group() -> None:
    p = _base_payload()
    p["conditions"] = {
        "kind": "group",
        "group": {
            "combinator": "and",
            "children": [
                {
                    "kind": "atom",
                    "atom": {
                        "field": "source",
                        "operator": "eq",
                        "value": "nginx",
                    },
                },
                {
                    "kind": "atom",
                    "atom": {
                        "field": "event_type",
                        "operator": "eq",
                        "value": "authentication_failure",
                    },
                },
            ],
        },
    }
    d = RuleDefinition.model_validate(p)
    assert d.conditions is not None
    assert d.conditions.group is not None
    assert d.conditions.group.combinator is ConditionCombinator.AND
    assert len(d.conditions.group.children) == 2


# ----------------------------------------------------------------- malformed inputs
def test_definition_rejects_oversized_description() -> None:
    p = _base_payload()
    p["description"] = "x" * 5000
    with pytest.raises(PydanticValidationError):
        RuleDefinition.model_validate(p)


def test_definition_rejects_oversized_name() -> None:
    p = _base_payload()
    p["name"] = "x" * 500
    with pytest.raises(PydanticValidationError):
        RuleDefinition.model_validate(p)


def test_definition_rejects_extra_field() -> None:
    p = _base_payload()
    p["extra_field"] = "evil"
    with pytest.raises(PydanticValidationError):
        RuleDefinition.model_validate(p)

