"""Regression tests for the Phase 4.7 reload-resilience fix.

The independent review (docs/PHASE 4/PHASE 4-07/
PHASE-04-07-REVIEW.md, section 8.1) found that a single
malformed ``managed_rules`` document could cause
``RuleManagementService.reload_registry()`` to raise an
uncaught :class:`pydantic.ValidationError`, leaving the
in-memory ``RuleRegistry`` partially applied.

The fix is two-layered:

1. The MongoDB ``$jsonSchema`` validator mirrors the
   closed-set enums and the cross-field
   ``enabled == true => state == 'approved'`` invariant
   so a direct pymongo write that bypasses the service
   layer is rejected at the database boundary.
2. ``_document_to_definition`` is total: it returns
   ``None`` (with a structured warning) when a
   document cannot be validated as a
   :class:`RuleDefinition`. ``find_latest_versions`` and
   ``find_all`` filter out ``None`` entries, so a
   poisoned document that nevertheless reaches the
   repository is silently quarantined and never aborts
   the registry reload.

These tests cover the second layer (the model is
exercised at the unit level using the in-memory
:class:`FakeCollection` so the test does not need a
running MongoDB). The BSON-level validator
hardening is covered by the integration test suite.
"""
from __future__ import annotations

from typing import Any, Dict

import pytest

from app.config import ProShieldConfig
from app.persistence.rule_repository import (
    _document_to_definition,
)
from app.rules.management.definition import RuleDefinition
from tests.unit._phase47_fakes import FakeDatabase


_BASE_DOC: Dict[str, Any] = {
    "rule_id": "REGR-001",
    "version": 1,
    "name": "Regression base rule",
    "description": "Used as the template for poisoned variants.",
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


# ----------------------------------------------------------------- quarantine
# ``_document_to_definition`` must be total: a poisoned
# document returns None, never raises.


def test_quarantine_invalid_state_enabled() -> None:
    """A doc with ``state=candidate, enabled=True`` is quarantined."""
    doc = dict(_BASE_DOC)
    doc["state"] = "candidate"
    doc["enabled"] = True
    result = _document_to_definition(doc)
    assert result is None


def test_quarantine_unknown_source() -> None:
    """A doc with an unknown source is quarantined."""
    doc = dict(_BASE_DOC)
    doc["sources"] = ["ghost_source"]
    result = _document_to_definition(doc)
    assert result is None


def test_quarantine_unknown_event_type() -> None:
    """A doc with an unknown event_type is quarantined."""
    doc = dict(_BASE_DOC)
    doc["event_types"] = ["no_such_event_type"]
    result = _document_to_definition(doc)
    assert result is None


def test_quarantine_unknown_operator() -> None:
    """A doc with an unknown condition operator is quarantined."""
    doc = dict(_BASE_DOC)
    doc["conditions"] = {
        "kind": "atom",
        "atom": {
            "field": "event_type",
            "operator": "matches_everything",
            "value": "x",
        },
    }
    result = _document_to_definition(doc)
    assert result is None


def test_quarantine_unknown_action() -> None:
    """A doc with an unknown action is quarantined."""
    doc = dict(_BASE_DOC)
    doc["actions"] = ["auto_pwn"]
    result = _document_to_definition(doc)
    assert result is None


def test_quarantine_extra_field() -> None:
    """A doc with an extra field is quarantined (model is strict)."""
    doc = dict(_BASE_DOC)
    doc["sneaky"] = "haha"
    result = _document_to_definition(doc)
    assert result is None


def test_quarantine_missing_required_field() -> None:
    """A doc with a missing required field is quarantined."""
    doc = dict(_BASE_DOC)
    doc.pop("rule_id", None)  # rule_id has no default; required
    result = _document_to_definition(doc)
    assert result is None


def test_quarantine_invalid_state_value() -> None:
    """A doc with an invalid state string is quarantined."""
    doc = dict(_BASE_DOC)
    doc["state"] = "approved-but-not-really"
    result = _document_to_definition(doc)
    assert result is None


def test_valid_doc_returns_definition() -> None:
    """A well-formed doc returns a :class:`RuleDefinition`."""
    result = _document_to_definition(dict(_BASE_DOC))
    assert isinstance(result, RuleDefinition)
    assert result.rule_id == "REGR-001"
    assert result.version == 1


# ----------------------------------------------------------------- reload path
# End-to-end: even with poisoned docs in the collection,
# the repository returns only valid definitions, and the
# service reload never crashes.


def _make_repo():  # type: ignore[no-untyped-def]
    from app.persistence.rule_repository import RuleRepository
    db = FakeDatabase()
    return RuleRepository(db, ProShieldConfig.from_env())


def test_find_latest_versions_filters_poisoned() -> None:
    """``find_latest_versions`` skips poisoned docs."""
    repo = _make_repo()
    coll = repo.collection
    valid = dict(_BASE_DOC)
    valid["rule_id"] = "REGR-VALID"
    coll.insert_one(valid)
    poisoned = dict(_BASE_DOC)
    poisoned["rule_id"] = "REGR-POISON"
    poisoned["sources"] = ["ghost_source"]
    coll.insert_one(poisoned)
    results = repo.find_latest_versions()
    ids = sorted(r.rule_id for r in results)
    assert ids == ["REGR-VALID"]


def test_find_all_filters_poisoned() -> None:
    """``find_all`` skips poisoned docs."""
    repo = _make_repo()
    coll = repo.collection
    valid = dict(_BASE_DOC)
    valid["rule_id"] = "REGR-VALID-1"
    coll.insert_one(valid)
    poisoned = dict(_BASE_DOC)
    poisoned["rule_id"] = "REGR-POISON-1"
    poisoned["actions"] = ["auto_pwn"]
    coll.insert_one(poisoned)
    results = repo.find_all()
    ids = sorted(r.rule_id for r in results)
    assert ids == ["REGR-VALID-1"]


def test_get_returns_none_for_poisoned() -> None:
    """``get`` returns None when the only document for an id is poisoned."""
    repo = _make_repo()
    coll = repo.collection
    poisoned = dict(_BASE_DOC)
    poisoned["rule_id"] = "REGR-POISON-GET"
    poisoned["sources"] = ["ghost_source"]
    coll.insert_one(poisoned)
    result = repo.get("REGR-POISON-GET")
    assert result is None


def test_reload_registry_does_not_crash_on_poisoned() -> None:
    """The full ``reload_registry`` path survives poisoned docs."""
    from app.rules import RuleRegistry
    from app.rules.management import RuleManagementService
    repo = _make_repo()
    coll = repo.collection
    valid = dict(_BASE_DOC)
    valid["rule_id"] = "REGR-VALID-FULL"
    coll.insert_one(valid)
    poisoned = dict(_BASE_DOC)
    poisoned["rule_id"] = "REGR-POISON-FULL"
    poisoned["sources"] = ["ghost_source"]
    coll.insert_one(poisoned)
    registry = RuleRegistry()
    svc = RuleManagementService(repo, registry)
    n = svc.reload_registry()  # MUST NOT RAISE
    assert n == 1
    rule = registry.get("REGR-VALID-FULL", 1)
    assert rule is not None
    assert registry.get("REGR-POISON-FULL", 1) is None


def test_reload_registry_works_with_only_poisoned() -> None:
    """``reload_registry`` succeeds (returns 0) with only a poisoned doc."""
    from app.rules import RuleRegistry
    from app.rules.management import RuleManagementService
    repo = _make_repo()
    coll = repo.collection
    poisoned = dict(_BASE_DOC)
    poisoned["rule_id"] = "REGR-ONLY-POISON"
    poisoned["actions"] = ["auto_pwn"]
    coll.insert_one(poisoned)
    registry = RuleRegistry()
    svc = RuleManagementService(repo, registry)
    n = svc.reload_registry()  # MUST NOT RAISE
    assert n == 0
    assert len(registry._by_version) == 0


def test_reload_registry_with_mixed_keeps_state_consistent() -> None:
    """A mixed collection reloads consistently."""
    from app.rules import RuleRegistry
    from app.rules.management import RuleManagementService
    repo = _make_repo()
    coll = repo.collection
    for i in range(2):
        d = dict(_BASE_DOC)
        d["rule_id"] = f"REGR-OK-{i}"
        d["version"] = 1
        coll.insert_one(d)
    for i in range(3):
        d = dict(_BASE_DOC)
        d["rule_id"] = f"REGR-BAD-{i}"
        d["version"] = 1
        d["sources"] = ["ghost_source"]
        coll.insert_one(d)
    registry = RuleRegistry()
    svc = RuleManagementService(repo, registry)
    n = svc.reload_registry()  # MUST NOT RAISE
    assert n == 2
    assert registry.get("REGR-OK-0", 1) is not None
    assert registry.get("REGR-OK-1", 1) is not None
    for i in range(3):
        assert registry.get(f"REGR-BAD-{i}", 1) is None


def test_reload_is_deterministic_across_calls() -> None:
    """``reload_registry`` produces the same state across calls."""
    from app.rules import RuleRegistry
    from app.rules.management import RuleManagementService
    repo = _make_repo()
    coll = repo.collection
    valid = dict(_BASE_DOC)
    valid["rule_id"] = "REGR-DETERMINISTIC"
    coll.insert_one(valid)
    poisoned = dict(_BASE_DOC)
    poisoned["rule_id"] = "REGR-DETERMINISTIC-POISON"
    poisoned["sources"] = ["ghost_source"]
    coll.insert_one(poisoned)
    registry1 = RuleRegistry()
    svc1 = RuleManagementService(repo, registry1)
    n1 = svc1.reload_registry()
    registry2 = RuleRegistry()
    svc2 = RuleManagementService(repo, registry2)
    n2 = svc2.reload_registry()
    assert n1 == n2 == 1
    assert sorted(registry1._by_version.keys()) == sorted(
        registry2._by_version.keys()
    )


def test_reload_does_not_register_quarantined_rule() -> None:
    """A quarantined rule MUST NEVER be registered."""
    from app.rules import RuleRegistry
    from app.rules.management import RuleManagementService
    repo = _make_repo()
    coll = repo.collection
    poisoned = dict(_BASE_DOC)
    poisoned["rule_id"] = "REGR-NEVER-REGISTER"
    poisoned["sources"] = ["ghost_source"]  # model rejects unknown source
    coll.insert_one(poisoned)
    registry = RuleRegistry()
    svc = RuleManagementService(repo, registry)
    svc.reload_registry()  # MUST NOT RAISE
    assert registry.get("REGR-NEVER-REGISTER", 1) is None
    assert (("REGR-NEVER-REGISTER", 1)) not in svc._known_persisted_ids
