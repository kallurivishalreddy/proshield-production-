"""Phase 4.7 — Generic rule management backend.

This package provides the secure, generic, data-driven
rule-management backend described in
``docs/PHASE 4/PHASE 4-07/PHASE-04-07-REPORT.md``.

It exports:

* :class:`RuleDefinition` - the strict, declarative
  rule-definition model. The wire form the Phase 4.7
  UI/API sends and the form the runtime evaluator
  consumes.
* :class:`RuleType` - the four documented rule types
  (detection, correlation, threshold, rate_limit).
* :class:`ActionType` - the closed-set list of action
  identifiers (alert, log, block_remediation).
* :class:`ConditionOperator` / :class:`ConditionCombinator`
  - the strict, allow-listed condition DSL.
* :class:`Atom` / :class:`Group` / :class:`Expression`
  - the recursive condition tree.
* :class:`GenericDeclarativeRule` - the single Rule
  subclass that evaluates any :class:`RuleDefinition`.
* :class:`RuleManagementService` - the orchestrator that
  handles validation, persistence, lifecycle, and
  dynamic loading into the framework's RuleRegistry.
* :class:`RuleRepository` (re-exported from
  :mod:`app.persistence.rule_repository`) - the
  MongoDB boundary for the ``managed_rules`` collection.
* :class:`RuleDefinitionValidationError`,
  :class:`DuplicateManagedRuleError`,
  :class:`UnknownManagedRuleError`,
  :class:`RuleVersionConflictError`,
  :class:`RuleNotInExpectedStateError`,
  :class:`ManagedRuleRetiredError`,
  :class:`RulePersistenceError` - the service-layer
  domain errors.

What this layer does NOT do
----------------------------

* It does NOT execute arbitrary code, ``eval``,
  ``exec``, ``subprocess``, ``importlib``, or shell
  commands. The conditions DSL is the only input
  language the runtime supports; anything outside the
  closed set is rejected at validation time.
* It does NOT implement frontend / dashboard UI.
* It does NOT implement analyst queue, escalation,
  routing, or report generation. Those are documented
  responsibilities of later slices.
* It does NOT implement arbitrary enforcement
  integrations. The ``block_remediation`` action is
  a structured record that downstream enforcement
  layers (out of scope for Phase 4.7) will consume.
"""
from __future__ import annotations

from .conditions import (
    Atom,
    ConditionCombinator,
    ConditionOperator,
    Expression,
    Group,
    evaluate_expression,
    get_event_field,
    validate_field_path,
)
from .definition import (
    ActionType,
    RuleDefinition,
    RuleType,
)
from .errors import (
    DuplicateManagedRuleError,
    ManagedRuleRetiredError,
    RuleDefinitionValidationError,
    RuleManagementError,
    RuleNotInExpectedStateError,
    RulePersistenceError,
    RuleVersionConflictError,
    UnknownManagedRuleError,
)
from .generic_rule import GenericDeclarativeRule
from .service import RuleManagementService, STATE_RETIRED

__all__ = [
    "ActionType",
    "Atom",
    "ConditionCombinator",
    "ConditionOperator",
    "DuplicateManagedRuleError",
    "Expression",
    "GenericDeclarativeRule",
    "Group",
    "ManagedRuleRetiredError",
    "RuleDefinition",
    "RuleDefinitionValidationError",
    "RuleManagementError",
    "RuleManagementService",
    "RuleNotInExpectedStateError",
    "RulePersistenceError",
    "RuleType",
    "RuleVersionConflictError",
    "STATE_RETIRED",
    "UnknownManagedRuleError",
    "evaluate_expression",
    "get_event_field",
    "validate_field_path",
]
