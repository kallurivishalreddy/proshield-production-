"""Unit tests for :class:`RuleRepository`.

These tests use a fake pymongo collection so the
repository is exercised end-to-end without needing a
running MongoDB. The integration tests in
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
from app.rules.types import RuleCategory, RuleState
from app.severity.models import SeverityBand
from tests.unit._phase47_fakes import (
    FakeCollection,
    FakeCursor,
    FakeDatabase,
    _match,
)  # noqa: F401  (re-exported to keep backward imports)


def _make_config() -> ProShieldConfig:
    return ProShieldConfig(
        env_name="test",
        log_level="INFO",
        mongo_uri="mongodb://127.0.0.1:27017",
        mongo_db="test",
        mongo_collection_events="security_events",
    )


def _make_definition(
    *,
    rule_id: str = "CUSTOM-001",
    version: int = 1,
    name: str = "Test",
    state: RuleState = RuleState.APPROVED,
    enabled: bool = True,
) -> RuleDefinition:
    return RuleDefinition(
        rule_id=rule_id,
        version=version,
        name=name,
        category=RuleCategory.SOURCE_SPECIFIC,
        type=RuleType.DETECTION,
        state=state.value,
        enabled=enabled,
        severity=SeverityBand.MEDIUM,
        sources=("nginx",),
        event_types=("authentication_failure",),
        actions=(ActionType.ALERT,),
    )


# ----------------------------------------------------------------- basic CRUD
def test_create_and_get() -> None:
    db = FakeDatabase()
    repo = RuleRepository(db, _make_config())
    d = _make_definition()
    repo.create(d)
    fetched = repo.get("CUSTOM-001", 1)
    assert fetched is not None
    assert fetched.rule_id == "CUSTOM-001"
    assert fetched.version == 1
    assert fetched.name == "Test"


def test_create_duplicate_raises() -> None:
    db = FakeDatabase()
    repo = RuleRepository(db, _make_config())
    d = _make_definition()
    repo.create(d)
    with pytest.raises(Exception):
        repo.create(d)


def test_get_latest_version_when_no_version_supplied() -> None:
    db = FakeDatabase()
    repo = RuleRepository(db, _make_config())
    repo.create(_make_definition(rule_id="X-001", version=1))
    repo.create(_make_definition(rule_id="X-001", version=2, name="v2"))
    latest = repo.get("X-001")
    assert latest is not None
    assert latest.version == 2


def test_get_returns_none_when_missing() -> None:
    db = FakeDatabase()
    repo = RuleRepository(db, _make_config())
    assert repo.get("NOPE-001") is None



# ----------------------------------------------------------------- listing
def test_find_latest_versions_returns_one_per_rule_id() -> None:
    db = FakeDatabase()
    repo = RuleRepository(db, _make_config())
    repo.create(_make_definition(rule_id="X-001", version=1))
    repo.create(_make_definition(rule_id="X-001", version=2))
    repo.create(_make_definition(rule_id="Y-001", version=1))
    latest = repo.find_latest_versions()
    by_id = {d.rule_id: d.version for d in latest}
    assert by_id == {"X-001": 2, "Y-001": 1}


def test_find_latest_versions_state_filter() -> None:
    db = FakeDatabase()
    repo = RuleRepository(db, _make_config())
    repo.create(_make_definition(rule_id="AAA-001", version=1, state=RuleState.APPROVED))
    repo.create(_make_definition(rule_id="BBB-001", version=1, state=RuleState.CANDIDATE, enabled=False))
    latest = repo.find_latest_versions(state=RuleState.APPROVED)
    assert {d.rule_id for d in latest} == {"AAA-001"}


def test_find_all_returns_every_version() -> None:
    db = FakeDatabase()
    repo = RuleRepository(db, _make_config())
    repo.create(_make_definition(rule_id="X-001", version=1))
    repo.create(_make_definition(rule_id="X-001", version=2))
    repo.create(_make_definition(rule_id="Y-001", version=1))
    all_defs = repo.find_all()
    assert len(all_defs) == 3


# ----------------------------------------------------------------- update
def test_update_replaces_existing() -> None:
    db = FakeDatabase()
    repo = RuleRepository(db, _make_config())
    repo.create(_make_definition(name="v1"))
    d = repo.get("CUSTOM-001", 1)
    assert d is not None
    updated = d.model_copy(update={"name": "v1-updated"})
    repo.update(updated)
    refetched = repo.get("CUSTOM-001", 1)
    assert refetched is not None
    assert refetched.name == "v1-updated"


def test_update_missing_raises() -> None:
    db = FakeDatabase()
    repo = RuleRepository(db, _make_config())
    d = _make_definition()
    with pytest.raises(Exception):
        repo.update(d)


# ----------------------------------------------------------------- state / enabled fields
def test_set_state_field() -> None:
    db = FakeDatabase()
    repo = RuleRepository(db, _make_config())
    repo.create(_make_definition(state=RuleState.CANDIDATE, enabled=False))
    repo.set_state_field("CUSTOM-001", 1, "approved")
    d = repo.get("CUSTOM-001", 1)
    assert d is not None
    assert d.state == "approved"


def test_set_enabled_field() -> None:
    db = FakeDatabase()
    repo = RuleRepository(db, _make_config())
    repo.create(_make_definition(enabled=False))
    repo.set_enabled_field("CUSTOM-001", 1, True)
    d = repo.get("CUSTOM-001", 1)
    assert d is not None
    assert d.enabled is True


# ----------------------------------------------------------------- soft delete
def test_soft_delete_marks_retired_and_disables() -> None:
    db = FakeDatabase()
    repo = RuleRepository(db, _make_config())
    repo.create(_make_definition())
    repo.soft_delete("CUSTOM-001", 1)
    raw = db[managed_rule_collection_name(_make_config())].docs[0]
    assert raw["state"] == "retired"
    assert raw["enabled"] is False


# ----------------------------------------------------------------- input validation
def test_create_rejects_non_definition() -> None:
    db = FakeDatabase()
    repo = RuleRepository(db, _make_config())
    with pytest.raises(Exception):
        repo.create("not a definition")  # type: ignore[arg-type]


def test_get_rejects_non_str_rule_id() -> None:
    db = FakeDatabase()
    repo = RuleRepository(db, _make_config())
    with pytest.raises(Exception):
        repo.get(123)  # type: ignore[arg-type]


def test_set_state_field_rejects_invalid_state() -> None:
    db = FakeDatabase()
    repo = RuleRepository(db, _make_config())
    repo.create(_make_definition())
    with pytest.raises(Exception):
        repo.set_state_field("CUSTOM-001", 1, "weird_state")


# ----------------------------------------------------------------- count
def test_count() -> None:
    db = FakeDatabase()
    repo = RuleRepository(db, _make_config())
    assert repo.count() == 0
    repo.create(_make_definition())
    assert repo.count() == 1
    repo.create(_make_definition(rule_id="OTHER-001", version=1))
    assert repo.count() == 2


# ----------------------------------------------------------------- collection name
def test_collection_name_default() -> None:
    assert managed_rule_collection_name(_make_config()) == "managed_rules"



# ----------------------------------------------------------------- conditions round-trip
def test_create_with_atom_condition_persists() -> None:
    from app.rules.management.conditions import (
        Atom,
        ConditionOperator,
        Expression,
    )

    db = FakeDatabase()
    repo = RuleRepository(db, _make_config())
    d = _make_definition()
    d2 = d.model_copy(update={
        "conditions": Expression.from_atom(
            Atom(
                field="event_type",
                operator=ConditionOperator.EQ,
                value="authentication_failure",
            )
        )
    })
    repo.create(d2)
    fetched = repo.get("CUSTOM-001", 1)
    assert fetched is not None
    assert fetched.conditions is not None
    assert fetched.conditions.kind == "atom"


def test_create_with_group_condition_persists() -> None:
    from app.rules.management.conditions import (
        Atom,
        ConditionCombinator,
        ConditionOperator,
        Expression,
        Group,
    )

    db = FakeDatabase()
    repo = RuleRepository(db, _make_config())
    d = _make_definition()
    d2 = d.model_copy(update={
        "conditions": Expression.from_group(
            Group(
                combinator=ConditionCombinator.AND,
                children=(
                    Expression.from_atom(
                        Atom(
                            field="source",
                            operator=ConditionOperator.EQ,
                            value="nginx",
                        )
                    ),
                    Expression.from_atom(
                        Atom(
                            field="event_type",
                            operator=ConditionOperator.EQ,
                            value="authentication_failure",
                        )
                    ),
                ),
            )
        )
    })
    repo.create(d2)
    fetched = repo.get("CUSTOM-001", 1)
    assert fetched is not None
    assert fetched.conditions is not None
    assert fetched.conditions.kind == "group"
    assert fetched.conditions.group is not None
    assert len(fetched.conditions.group.children) == 2

