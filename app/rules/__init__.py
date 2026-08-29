"""ProShield rule framework foundation.

This package establishes the **deterministic Rule Framework and Rule
Registry** documented in
``docs/PHASE 4/DETECTION_ENGINEERING_AND_FUTURE_AI.md`` (Sections 8-11
and 87-91) and ``docs/PHASE 2/DOMAIN_DATA_MODEL.md`` (Section 5).

Phase 4.2 ships the **foundation only**:

* Rule domain models (metadata, state, category, version, applicability).
* The ``Rule`` interface and its evaluation contract (``RuleEvaluation``).
* A single authoritative in-memory ``RuleRegistry``.
* Rule discovery and deterministic loading/validation.
* Applicability filtering by ``source`` / ``event_type``.

It deliberately does **NOT** implement:

* The full detection engine (engine wiring, scheduling, batching).
* The correlation engine, incident engine, report, routing, AI.
* A production rule library. No WAF / NGINX / IAM / rate-limit / network
  / correlation rules are shipped in this slice. Rule *categories* and
  the file-system *organisation* are established (see
  ``app/rules/_library/``), but the slots are intentionally empty until
  rules pass the documented research-to-approval governance.

The mandatory principle (DETECTION_ENGINEERING_AND_FUTURE_AI.md §89) is
preserved by construction: the registry refuses anything that is not
CANDIDATE or APPROVED, and ``enabled=True`` requires ``state=APPROVED``.

Reference: docs/PHASE 4/DETECTION_ENGINEERING_AND_FUTURE_AI.md
           docs/PHASE 2/DOMAIN_DATA_MODEL.md (Section 5: Rule)
"""
from __future__ import annotations

from .types import (
    RuleCategory,
    RuleState,
    RuleMetadata,
    RuleEvaluation,
    RuleVersion,
    RuleId,
)
from .rule import Rule, SimpleRule, RuleEvaluationError
from .registry import (
    RuleRegistry,
    RuleRegistryError,
    DuplicateRuleError,
    RuleValidationError,
    CandidateNotPromotableError,
    UnknownRuleError,
    SupersededVersionNotReenablableError,
)
from .loader import (
    load_rules_from_specs,
    discover_rules_in_module,
)

__all__ = [
    "RuleCategory",
    "RuleState",
    "RuleMetadata",
    "RuleEvaluation",
    "RuleVersion",
    "RuleId",
    "Rule",
    "SimpleRule",
    "RuleEvaluationError",
    "RuleRegistry",
    "RuleRegistryError",
    "DuplicateRuleError",
    "RuleValidationError",
    "CandidateNotPromotableError",
    "UnknownRuleError",
    "SupersededVersionNotReenablableError",
    "load_rules_from_specs",
    "discover_rules_in_module",
]
