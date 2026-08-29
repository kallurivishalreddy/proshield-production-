"""Unit tests for :class:`RuleManagementService`.

Reference: docs/PHASE 4/PHASE 4-07/PHASE-04-07-REPORT.md.

These tests use a fake repository pattern so the
service layer is exercised end-to-end without a running
MongoDB. The integration tests in
``tests/integration/test_phase47_pipeline.py`` exercise
the same code path against the real local MongoDB.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

import pytest

from app.config import ProShieldConfig
from app.persistence.rule_repository import (
    RuleRepository,
    managed_rule_collection_name,
)
from app.rules.management.definition import (
    ActionType,
    RuleDefinition,
    RuleType,
)
from app.rules.management.errors import (
    DuplicateManagedRuleError,
    ManagedRuleRetiredError,
    RuleDefinitionValidationError,
    RuleNotInExpectedStateError,
    RuleVersionConflictError,
    UnknownManagedRuleError,
)
from app.rules.management.service import RuleManagementService, STATE_RETIRED
from app.rules.registry import RuleRegistry
from app.rules.types import RuleCategory, RuleState
from app.severity.models import SeverityBand
from tests.unit._phase47_fakes import (
    FakeCollection,
    FakeDatabase,
)


def _make_config() -> ProShieldConfig:
    return ProShieldConfig(
        env_name="test",
        log_level="INFO",
        mongo_uri="mongodb://127.0.0.1:27017",
        mongo_db="test",
        mongo_collection_events="security_events",
    )


def _det_payload(
    *,
    rule_id: str = "CUSTOM-001",
    version: int = 1,
    name: str = "Test",
    state: str = "candidate",
    enabled: bool = False,
    severity: str = "medium",
    actions: Optional[List[str]] = None,
    conditions: Optional[Dict[str, Any]] = None,
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    payload: Dict[str, Any] = {
        "rule_id": rule_id,
        "version": version,
        "name": name,
        "description": "test",
        "category": "source_specific",
        "type": "detection",
        "state": state,
        "enabled": enabled,
        "severity": severity,
        "sources": ["nginx"],
        "event_types": ["authentication_failure"],
        "tags": [],
        "references": [],
        "combinator": "and",
        "scope": [],
        "evidence_requirements": [],
        "thresholds": {},
        "window_seconds": None,
        # ``actions is None`` -> use the default; an
        # explicit empty list passes through (the
        # service is supposed to reject it).
        "actions": ["alert"] if actions is None else actions,
    }
    if conditions is not None:
        payload["conditions"] = conditions
    if extra:
        payload.update(extra)
    return payload


# ----------------------------------------------------------------- service creation
def test_service_requires_repository_and_registry() -> None:
    registry = RuleRegistry()
    with pytest.raises(ValueError):
        RuleManagementService(None, registry)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        RuleManagementService("repo", None)  # type: ignore[arg-type]


# ----------------------------------------------------------------- validation path
def test_create_rejects_malformed_payload() -> None:
    db = FakeDatabase()
    repo = RuleRepository(db, _make_config())
    service = RuleManagementService(repo, RuleRegistry())
    with pytest.raises(RuleDefinitionValidationError):
        service.create({"rule_id": "CUSTOM-001"})


def test_create_rejects_unknown_action() -> None:
    db = FakeDatabase()
    repo = RuleRepository(db, _make_config())
    service = RuleManagementService(repo, RuleRegistry())
    with pytest.raises(RuleDefinitionValidationError):
        service.create(_det_payload(actions=["bogus"]))


def test_create_rejects_invalid_rule_id_pattern() -> None:
    db = FakeDatabase()
    repo = RuleRepository(db, _make_config())
    service = RuleManagementService(repo, RuleRegistry())
    with pytest.raises(RuleDefinitionValidationError):
        service.create(_det_payload(rule_id="bad_id"))


def test_create_rejects_empty_actions() -> None:
    db = FakeDatabase()
    repo = RuleRepository(db, _make_config())
    service = RuleManagementService(repo, RuleRegistry())
    with pytest.raises(RuleDefinitionValidationError):
        service.create(_det_payload(actions=[]))



# ----------------------------------------------------------------- create / read
def test_create_persists_and_registers() -> None:
    db = FakeDatabase()
    repo = RuleRepository(db, _make_config())
    registry = RuleRegistry()
    service = RuleManagementService(repo, registry)
    payload = _det_payload(state="approved", enabled=True)
    d = service.create(payload)
    assert d.rule_id == "CUSTOM-001"
    assert d.state == "approved"
    in_registry = registry.get("CUSTOM-001", 1)
    assert in_registry is not None
    assert in_registry.metadata.rule_id == "CUSTOM-001"
    in_repo = repo.get("CUSTOM-001", 1)
    assert in_repo is not None


def test_create_duplicate_raises() -> None:
    db = FakeDatabase()
    repo = RuleRepository(db, _make_config())
    service = RuleManagementService(repo, RuleRegistry())
    service.create(_det_payload(state="approved", enabled=True))
    with pytest.raises(DuplicateManagedRuleError):
        service.create(_det_payload(state="approved", enabled=True))


def test_get_returns_definition() -> None:
    db = FakeDatabase()
    repo = RuleRepository(db, _make_config())
    service = RuleManagementService(repo, RuleRegistry())
    service.create(_det_payload())
    d = service.get("CUSTOM-001", 1)
    assert d is not None
    assert d.rule_id == "CUSTOM-001"


def test_list_all_returns_every_rule() -> None:
    db = FakeDatabase()
    repo = RuleRepository(db, _make_config())
    service = RuleManagementService(repo, RuleRegistry())
    service.create(_det_payload(rule_id="X-001"))
    service.create(_det_payload(rule_id="Y-001"))
    all_defs = service.list_all()
    assert {d.rule_id for d in all_defs} == {"X-001", "Y-001"}


def test_list_evaluable_returns_only_approved_enabled() -> None:
    db = FakeDatabase()
    repo = RuleRepository(db, _make_config())
    service = RuleManagementService(repo, RuleRegistry())
    service.create(_det_payload(rule_id="X-001", state="approved", enabled=True))
    service.create(_det_payload(rule_id="Y-001", state="candidate", enabled=False))
    service.create(_det_payload(rule_id="Z-001", state="approved", enabled=False))
    evaluable = service.list_evaluable()
    assert {d.rule_id for d in evaluable} == {"X-001"}



# ----------------------------------------------------------------- update
def test_update_modifies_in_place() -> None:
    db = FakeDatabase()
    repo = RuleRepository(db, _make_config())
    registry = RuleRegistry()
    service = RuleManagementService(repo, registry)
    service.create(_det_payload(name="v1"))
    updated = service.update("CUSTOM-001", 1, _det_payload(name="v2"))
    assert updated.name == "v2"
    in_registry = registry.get("CUSTOM-001", 1)
    assert in_registry is not None
    assert in_registry.metadata.name == "v2"


def test_update_preserves_lifecycle() -> None:
    db = FakeDatabase()
    repo = RuleRepository(db, _make_config())
    service = RuleManagementService(repo, RuleRegistry())
    service.create(_det_payload(state="approved", enabled=True))
    updated = service.update(
        "CUSTOM-001", 1, _det_payload(state="candidate", enabled=False)
    )
    assert updated.state == "approved"
    assert updated.enabled is True


def test_update_unknown_rule_raises() -> None:
    db = FakeDatabase()
    repo = RuleRepository(db, _make_config())
    service = RuleManagementService(repo, RuleRegistry())
    with pytest.raises(UnknownManagedRuleError):
        service.update("NOPE-001", 1, _det_payload())


# ----------------------------------------------------------------- versioning
def test_create_new_version_strictly_greater() -> None:
    db = FakeDatabase()
    repo = RuleRepository(db, _make_config())
    registry = RuleRegistry()
    service = RuleManagementService(repo, registry)
    service.create(_det_payload(state="approved", enabled=True))
    v2 = service.create_new_version("CUSTOM-001", _det_payload(version=2))
    assert v2.version == 2
    assert v2.state == "candidate"
    assert v2.enabled is False


def test_create_new_version_rejects_older_version() -> None:
    db = FakeDatabase()
    repo = RuleRepository(db, _make_config())
    service = RuleManagementService(repo, RuleRegistry())
    service.create(_det_payload())
    with pytest.raises(RuleVersionConflictError):
        service.create_new_version("CUSTOM-001", _det_payload(version=1))


def test_create_new_version_rejects_equal_version() -> None:
    db = FakeDatabase()
    repo = RuleRepository(db, _make_config())
    service = RuleManagementService(repo, RuleRegistry())
    service.create(_det_payload())
    with pytest.raises(RuleVersionConflictError):
        service.create_new_version("CUSTOM-001", _det_payload(version=1))



# ----------------------------------------------------------------- lifecycle
def test_set_state_candidate_to_approved() -> None:
    db = FakeDatabase()
    repo = RuleRepository(db, _make_config())
    service = RuleManagementService(repo, RuleRegistry())
    service.create(_det_payload(state="candidate", enabled=False))
    out = service.set_state("CUSTOM-001", "approved")
    assert out.state == "approved"


def test_set_state_rejects_unknown_state() -> None:
    db = FakeDatabase()
    repo = RuleRepository(db, _make_config())
    service = RuleManagementService(repo, RuleRegistry())
    service.create(_det_payload(state="approved", enabled=True))
    with pytest.raises(RuleNotInExpectedStateError):
        service.set_state("CUSTOM-001", "weird_state")


def test_set_enabled_to_true_on_approved() -> None:
    db = FakeDatabase()
    repo = RuleRepository(db, _make_config())
    service = RuleManagementService(repo, RuleRegistry())
    service.create(_det_payload(state="approved", enabled=False))
    out = service.set_enabled("CUSTOM-001", True)
    assert out.enabled is True


def test_set_enabled_to_true_on_candidate_rejected() -> None:
    db = FakeDatabase()
    repo = RuleRepository(db, _make_config())
    service = RuleManagementService(repo, RuleRegistry())
    service.create(_det_payload(state="candidate", enabled=False))
    with pytest.raises(RuleNotInExpectedStateError):
        service.set_enabled("CUSTOM-001", True)


def test_retire_unregisters_and_marks_retired() -> None:
    db = FakeDatabase()
    repo = RuleRepository(db, _make_config())
    registry = RuleRegistry()
    service = RuleManagementService(repo, registry)
    service.create(_det_payload(state="approved", enabled=True))
    assert registry.get("CUSTOM-001", 1) is not None
    service.retire("CUSTOM-001", version=1)
    assert registry.get("CUSTOM-001", 1) is None
    raw = db[managed_rule_collection_name(_make_config())].docs[0]
    assert raw["state"] == STATE_RETIRED


def test_update_retired_rejected() -> None:
    db = FakeDatabase()
    repo = RuleRepository(db, _make_config())
    service = RuleManagementService(repo, RuleRegistry())
    service.create(_det_payload(state="approved", enabled=True))
    service.retire("CUSTOM-001", version=1)
    with pytest.raises(ManagedRuleRetiredError):
        service.update("CUSTOM-001", 1, _det_payload(name="after-retire"))


# ----------------------------------------------------------------- reload
def test_reload_registry_picks_up_persisted_rules() -> None:
    db = FakeDatabase()
    repo = RuleRepository(db, _make_config())
    registry = RuleRegistry()
    d = RuleDefinition(
        rule_id="CUSTOM-001",
        version=1,
        name="reloaded",
        category=RuleCategory.SOURCE_SPECIFIC,
        type=RuleType.DETECTION,
        state=RuleState.APPROVED,
        enabled=True,
        severity=SeverityBand.MEDIUM,
        sources=("nginx",),
        event_types=("authentication_failure",),
        actions=(ActionType.ALERT,),
    )
    repo.create(d)
    assert registry.get("CUSTOM-001", 1) is None
    service = RuleManagementService(repo, registry)
    n = service.reload_registry()
    assert n == 1
    assert registry.get("CUSTOM-001", 1) is not None


def test_reload_unregisters_retired() -> None:
    db = FakeDatabase()
    repo = RuleRepository(db, _make_config())
    registry = RuleRegistry()
    service = RuleManagementService(repo, registry)
    service.create(_det_payload(state="approved", enabled=True))
    assert registry.get("CUSTOM-001", 1) is not None
    service.retire("CUSTOM-001", version=1)
    assert registry.get("CUSTOM-001", 1) is None

