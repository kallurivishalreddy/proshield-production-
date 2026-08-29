"""Unit tests for deterministic rule loading and discovery.

Reference: docs/PHASE 4/DETECTION_ENGINEERING_AND_FUTURE_AI.md,
Sections 9, 87-91.
"""
from __future__ import annotations

import sys
import types
from typing import Any

import pytest

from app.rules import (
    Rule,
    RuleRegistry,
    RuleValidationError,
    SimpleRule,
    discover_rules_in_module,
    load_rules_from_specs,
)
from tests.unit._rules_helpers import (
    auth_metadata,
    waf_metadata,
)


def _install_module(name: str, **attrs: Any) -> types.ModuleType:
    mod = types.ModuleType(name)
    for k, v in attrs.items():
        setattr(mod, k, v)
    sys.modules[name] = mod
    return mod


@pytest.fixture(autouse=True)
def _cleanup_modules():
    created: list[str] = []
    yield created
    for name in list(sys.modules.keys()):
        if name in created and name in sys.modules:
            del sys.modules[name]


# ---------------------------------------------- discover_rules_in_module
def test_discover_in_empty_module_returns_empty() -> None:
    mod = _install_module("proshield_test_no_rules")
    assert discover_rules_in_module(mod) == []


def test_discover_via_RULES() -> None:
    r1 = SimpleRule(waf_metadata(), predicate=lambda e: True)
    r2 = SimpleRule(auth_metadata(), predicate=lambda e: True)
    mod = _install_module("proshield_test_rules_list", RULES=[r1, r2])
    out = discover_rules_in_module(mod)
    assert [r.metadata.rule_id for r in out] == [
        "AUTH-BRUTEFORCE-001", "WAF-001"
    ]


def test_discover_via_RULE_FACTORIES() -> None:
    def make_waf() -> Rule:
        return SimpleRule(waf_metadata(), predicate=lambda e: True)

    def make_auth() -> Rule:
        return SimpleRule(auth_metadata(), predicate=lambda e: True)

    mod = _install_module(
        "proshield_test_factories", RULE_FACTORIES=[make_waf, make_auth]
    )
    out = discover_rules_in_module(mod)
    assert [r.metadata.rule_id for r in out] == [
        "AUTH-BRUTEFORCE-001", "WAF-001"
    ]


def test_discover_factories_and_rules_merge_sorted() -> None:
    # Use a common-behavioral rule from a factory + a WAF rule
    # directly. CORR-* rules cannot be a SimpleRule so we keep the
    # cross-source test orthogonal.
    def make_auth() -> Rule:
        return SimpleRule(auth_metadata(), predicate=lambda e: True)

    r1 = SimpleRule(waf_metadata(), predicate=lambda e: True)
    mod = _install_module(
        "proshield_test_merge",
        RULE_FACTORIES=[make_auth],
        RULES=[r1],
    )
    out = discover_rules_in_module(mod)
    assert [r.metadata.rule_id for r in out] == [
        "AUTH-BRUTEFORCE-001",
        "WAF-001",
    ]


def test_discover_rejects_non_callable_factory() -> None:
    mod = _install_module(
        "proshield_test_bad_factory",
        RULE_FACTORIES=["not a factory"],  # type: ignore[list-item]
    )
    with pytest.raises(RuleValidationError):
        discover_rules_in_module(mod)


def test_discover_rejects_factory_returning_non_rule() -> None:
    def bad() -> str:
        return "not a rule"

    mod = _install_module(
        "proshield_test_bad_factory_return", RULE_FACTORIES=[bad]
    )
    with pytest.raises(RuleValidationError):
        discover_rules_in_module(mod)


def test_discover_rejects_RULES_with_non_rule_entries() -> None:
    mod = _install_module(
        "proshield_test_bad_rules",
        RULES=[SimpleRule(waf_metadata(), predicate=lambda e: True), "x"],  # type: ignore[list-item]
    )
    with pytest.raises(RuleValidationError):
        discover_rules_in_module(mod)


def test_discover_rejects_non_iterable_export() -> None:
    mod = _install_module("proshield_test_bad_export", RULES="not a list")
    with pytest.raises(RuleValidationError):
        discover_rules_in_module(mod)


def test_discover_requires_a_module() -> None:
    with pytest.raises(RuleValidationError):
        discover_rules_in_module("not a module")  # type: ignore[arg-type]


# ---------------------------------------------- load_rules_from_specs
def test_load_rules_from_specs_registers_all() -> None:
    r1 = SimpleRule(waf_metadata(), predicate=lambda e: True)
    r2 = SimpleRule(auth_metadata(), predicate=lambda e: True)
    _install_module("proshield_test_load_all", RULES=[r1, r2])
    r = RuleRegistry()
    n, registered = load_rules_from_specs(
        r, ["proshield_test_load_all"]
    )
    assert n == 2
    assert len(registered) == 2
    assert r.has("WAF-001")
    assert r.has("AUTH-BRUTEFORCE-001")


def test_load_rules_from_specs_processes_in_input_order() -> None:
    r1 = SimpleRule(waf_metadata(), predicate=lambda e: True)
    r2 = SimpleRule(auth_metadata(), predicate=lambda e: True)
    _install_module("proshield_test_a", RULES=[r1])
    _install_module("proshield_test_b", RULES=[r2])
    r = RuleRegistry()
    load_rules_from_specs(r, ["proshield_test_a", "proshield_test_b"])
    assert [rule.metadata.rule_id for rule in r.list_all()] == [
        "AUTH-BRUTEFORCE-001", "WAF-001"
    ]


def test_load_rules_from_specs_rejects_missing_module() -> None:
    r = RuleRegistry()
    with pytest.raises(RuleValidationError):
        load_rules_from_specs(r, ["proshield_test_does_not_exist_42"])


def test_load_rules_from_specs_rejects_empty_spec() -> None:
    r = RuleRegistry()
    with pytest.raises(RuleValidationError):
        load_rules_from_specs(r, [""])


def test_load_rules_from_specs_rejects_non_string_spec() -> None:
    r = RuleRegistry()
    with pytest.raises(RuleValidationError):
        load_rules_from_specs(r, [123])  # type: ignore[list-item]


def test_load_rules_from_specs_requires_registry() -> None:
    with pytest.raises(RuleValidationError):
        load_rules_from_specs("not a registry", [])  # type: ignore[arg-type]