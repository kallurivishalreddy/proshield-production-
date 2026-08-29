"""Integration tests for the Phase 4.7 BSON ``$jsonSchema`` validator.

These tests run against the real local MongoDB. They
verify that the second layer of the review's
reload-resilience fix (the closed-set enum /
cross-field invariants in ``MANAGED_RULES_VALIDATOR``)
actually rejects every shape the model rejects, even
when the write is performed by a direct pymongo call
that bypasses the service layer.

The tests are isolated to the ``proshield_test``
database which the conftest drops and recreates on
every session.
"""
from __future__ import annotations

from typing import Any, Dict

import pytest
from pymongo.errors import WriteError

from app.config import ProShieldConfig
from app.persistence.rule_repository import RuleRepository


_BASE_DOC: Dict[str, Any] = {
    "rule_id": "BSON-RR-001",
    "version": 1,
    "name": "BSON validator base",
    "description": "Used as the template for invalid variants.",
    "category": "source_specific",
    "type": "detection",
    "state": "approved",
    "enabled": True,
    "severity": "low",
    "sources": ["nginx"],
    "event_types": ["authentication_failure"],
    "tags": [],
    "references": [],
    "combinator": "and",
    "conditions": {
        "kind": "atom",
        "atom": {
            "field": "event_type",
            "operator": "eq",
            "value": "authentication_failure",
        },
    },
    "scope": [],
    "evidence_requirements": ["source_ip"],
    "thresholds": {},
    "window_seconds": None,
    "actions": ["alert"],
}


@pytest.fixture
def rule_repository(db, test_config: ProShieldConfig) -> RuleRepository:
    repo = RuleRepository(db, test_config)
    repo.ensure_schema()
    repo.ensure_indexes()
    return repo


def _mutate_and_insert(repo: RuleRepository, mutation: Dict[str, Any]) -> None:
    doc = dict(_BASE_DOC)
    doc.update(mutation)
    repo.collection.insert_one(doc)


def test_bson_validator_rejects_state_candidate_enabled_true(
    rule_repository: RuleRepository,
) -> None:
    """A doc with ``state=candidate, enabled=True`` is rejected at the BSON level.

    The model layer also rejects this; the BSON validator
    is the second line of defence that the review found
    missing.
    """
    with pytest.raises(WriteError) as excinfo:
        _mutate_and_insert(
            rule_repository,
            {"state": "candidate", "enabled": True},
        )
    assert "Document failed validation" in str(excinfo.value)


def test_bson_validator_rejects_unknown_source(
    rule_repository: RuleRepository,
) -> None:
    """A doc with an unknown source is rejected at the BSON level."""
    with pytest.raises(WriteError):
        _mutate_and_insert(
            rule_repository,
            {"sources": ["ghost_source"]},
        )


def test_bson_validator_rejects_unknown_event_type(
    rule_repository: RuleRepository,
) -> None:
    """A doc with an unknown event_type is rejected at the BSON level."""
    with pytest.raises(WriteError):
        _mutate_and_insert(
            rule_repository,
            {"event_types": ["no_such_event_type"]},
        )


def test_bson_validator_rejects_unknown_combinator(
    rule_repository: RuleRepository,
) -> None:
    """A doc with an unknown combinator is rejected at the BSON level."""
    with pytest.raises(WriteError):
        _mutate_and_insert(
            rule_repository,
            {"combinator": "xor"},
        )


def test_bson_validator_rejects_invalid_state_value(
    rule_repository: RuleRepository,
) -> None:
    """A doc with a state value outside the closed enum is rejected."""
    with pytest.raises(WriteError):
        _mutate_and_insert(
            rule_repository,
            {"state": "approved-but-not-really"},
        )


def test_bson_validator_accepts_disabled_candidate(
    rule_repository: RuleRepository,
) -> None:
    """A doc with ``state=candidate, enabled=False`` IS accepted.

    This is the legitimate "draft" state; the new
    validator's ``oneOf`` invariant must NOT reject it.
    """
    _mutate_and_insert(
        rule_repository,
        {
            "rule_id": "BSON-RR-DRAFT",
            "state": "candidate",
            "enabled": False,
        },
    )
    # Read it back to confirm.
    doc = rule_repository.collection.find_one(
        {"rule_id": "BSON-RR-DRAFT"}
    )
    assert doc is not None
    assert doc["state"] == "candidate"
    assert doc["enabled"] is False


def test_bson_validator_accepts_retired_disabled(
    rule_repository: RuleRepository,
) -> None:
    """A doc with ``state=retired, enabled=False`` IS accepted."""
    _mutate_and_insert(
        rule_repository,
        {
            "rule_id": "BSON-RR-RETIRED",
            "state": "retired",
            "enabled": False,
        },
    )
    doc = rule_repository.collection.find_one(
        {"rule_id": "BSON-RR-RETIRED"}
    )
    assert doc is not None
    assert doc["state"] == "retired"
    assert doc["enabled"] is False


def test_bson_validator_accepts_approved_enabled(
    rule_repository: RuleRepository,
) -> None:
    """A doc with ``state=approved, enabled=True`` IS accepted."""
    _mutate_and_insert(
        rule_repository,
        {
            "rule_id": "BSON-RR-APPROVED",
            "state": "approved",
            "enabled": True,
        },
    )
    doc = rule_repository.collection.find_one(
        {"rule_id": "BSON-RR-APPROVED"}
    )
    assert doc is not None
    assert doc["state"] == "approved"
    assert doc["enabled"] is True
