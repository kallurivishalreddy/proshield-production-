"""Phase 5.2 — legacy Rule -> Capability backfill tests.

The source side of the migration is covered in
``tests/unit/test_phase52_sources.py``. This module covers the rule side:
a legacy rule's ``sources[]`` is resolved to an owning capability **only
when that is unambiguous**, and the change is audited through the existing
capability audit trail.

Reference: docs/PHASE 5(V3)/PHASE-05-V3-IMPLEMENTATION-MASTER-PLAN.md §19.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.sources.capability_binding import builtin_capability_index
from app.sources.migration import (
    ACTION_RULE_BACKFILL,
    OUTCOME_ALREADY_BOUND,
    OUTCOME_AMBIGUOUS,
    SourceCapabilityMigration,
)
from app.sources.repository import SourceRepository
from tests.unit._phase49_fakes import FakeDatabase, FakeSourceCollection

_NOW = datetime(2026, 9, 16, 12, 0, 0, tzinfo=timezone.utc)


def _config():
    from app.config import ProShieldConfig

    return ProShieldConfig(
        env_name="test",
        log_level="INFO",
        mongo_uri="mongodb://127.0.0.1:27017",
        mongo_db="proshield_phase52_rule_migration",
        mongo_collection_events="security_events",
        source_signing_key="phase52-rule-migration-secret",
    )


class _RuleRepo:
    """Minimal rule-repository double for the backfill path."""

    def __init__(self, definitions: List[Any]) -> None:
        self._defs = list(definitions)
        self.updates: List[Any] = []

    def find_all(self, **_kw: Any) -> List[Any]:
        return list(self._defs)

    def get(self, rule_id: str, version: Optional[int] = None) -> Any:
        for d in self._defs:
            if d.rule_id == rule_id:
                return d
        return None

    def update(self, definition: Any) -> Any:
        """Replace the stored definition, mirroring RuleRepository.update."""
        self.updates.append(definition)
        for i, existing in enumerate(self._defs):
            if existing.rule_id == definition.rule_id:
                self._defs[i] = definition
                break
        return definition


class _AuditCollection(FakeSourceCollection):
    """Append-only audit double (no source_instance_id uniqueness)."""

    def insert_one(self, doc: Dict[str, Any]) -> Any:
        import copy as _copy

        self.docs.append(_copy.deepcopy(dict(doc)))
        return type("R", (), {"inserted_id": "fake"})()


def _definition(
    rule_id: str,
    sources: tuple,
    capability_id: Optional[str] = None,
    event_types: tuple = ("authentication_failure",),
):
    from app.rules.management.definition import (
        ConditionCombinator,
        RuleDefinition,
    )
    from app.rules.types import RuleCategory

    return RuleDefinition(
        rule_id=rule_id,
        version=1,
        name="migration test rule",
        description="",
        category=RuleCategory.SOURCE_SPECIFIC,
        sources=sources,
        event_types=event_types,
        state="approved",
        enabled=True,
        combinator=ConditionCombinator.AND,
        conditions=None,
        capability_id=capability_id,
    )


def _engine(rules: Optional[_RuleRepo] = None, audit: Any = None):
    db = FakeDatabase()
    repo = SourceRepository(db, _config())
    engine = SourceCapabilityMigration(
        source_repository=repo,
        capability_lookup=lambda cid: builtin_capability_index().get(cid),
        registry=None,
        rule_repository=rules,
        capability_audit_collection=audit,
    )
    return engine, repo


class TestRuleCapabilityBackfill:
    def test_unambiguous_rule_is_backfilled(self) -> None:
        rules = _RuleRepo([_definition("NGINX-TEST-001", ("nginx",))])
        engine, _ = _engine(rules)
        report = engine.run(dry_run=False, include_rules=True)
        assert report.rules_bound == 1
        assert rules.updates[0].capability_id == "cap-nginx"

    def test_backfill_is_audited_in_the_capability_trail(self) -> None:
        audit = _AuditCollection()
        rules = _RuleRepo([_definition("NGINX-TEST-001", ("nginx",))])
        engine, _ = _engine(rules, audit=audit)
        report = engine.run(dry_run=False, include_rules=True)
        assert report.audit_records_written == 1
        rec = audit.docs[0]
        assert rec["action"] == ACTION_RULE_BACKFILL
        assert rec["capability_id"] == "cap-nginx"
        assert rec["before"]["capability_id"] is None
        assert rec["after"]["capability_id"] == "cap-nginx"
        assert rec["after"]["rule_id"] == "NGINX-TEST-001"

    def test_cross_source_rule_is_ambiguous_and_never_rewritten(self) -> None:
        """A rule owned by no single capability must not be given one."""
        rules = _RuleRepo([_definition("CORR-TEST-001", ("nginx", "waf"))])
        engine, _ = _engine(rules)
        report = engine.run(dry_run=False, include_rules=True)
        assert report.rules_ambiguous == 1
        assert report.rules_bound == 0
        assert rules.updates == []
        assert report.rule_changes[0].outcome == OUTCOME_AMBIGUOUS
        assert report.rule_changes[0].capability_id is None

    def test_already_bound_rule_is_not_rewritten(self) -> None:
        rules = _RuleRepo([
            _definition(
                "NGINX-TEST-001", ("nginx",), capability_id="cap-nginx",
            )
        ])
        engine, _ = _engine(rules)
        report = engine.run(dry_run=False, include_rules=True)
        assert report.rules_already_bound == 1
        assert report.rules_bound == 0
        assert rules.updates == []
        assert report.rule_changes[0].outcome == OUTCOME_ALREADY_BOUND

    def test_dry_run_does_not_touch_rules(self) -> None:
        rules = _RuleRepo([_definition("NGINX-TEST-001", ("nginx",))])
        engine, _ = _engine(rules)
        report = engine.run(dry_run=True, include_rules=True)
        assert report.rules_bound == 1
        assert rules.updates == []

    def test_rule_plan_is_deterministic(self) -> None:
        defs = [
            _definition("B-002", ("nginx",)),
            _definition("A-001", ("nginx",)),
        ]
        engine_a, _ = _engine(_RuleRepo(list(defs)))
        engine_b, _ = _engine(_RuleRepo(list(reversed(defs))))
        plan_a = [
            c.as_dict() for c in engine_a.run(
                dry_run=True, include_rules=True
            ).rule_changes
        ]
        plan_b = [
            c.as_dict() for c in engine_b.run(
                dry_run=True, include_rules=True
            ).rule_changes
        ]
        assert plan_a == plan_b
        assert [c["rule_id"] for c in plan_a] == ["A-001", "B-002"]

    def test_rules_can_be_excluded(self) -> None:
        rules = _RuleRepo([_definition("NGINX-TEST-001", ("nginx",))])
        engine, _ = _engine(rules)
        report = engine.run(dry_run=False, include_rules=False)
        assert report.rules_scanned == 0
        assert report.rules_bound == 0
        assert rules.updates == []

    def test_second_run_is_idempotent_for_rules(self) -> None:
        """Once persisted, a re-run proposes and writes nothing."""
        rules = _RuleRepo([_definition("NGINX-TEST-001", ("nginx",))])
        engine, _ = _engine(rules)
        engine.run(dry_run=False, include_rules=True)
        assert len(rules.updates) == 1
        second = engine.run(dry_run=False, include_rules=True)
        assert second.rules_bound == 0
        assert second.rules_already_bound == 1
        assert len(rules.updates) == 1  # no second write
        assert second.rule_changes[0].outcome == OUTCOME_ALREADY_BOUND