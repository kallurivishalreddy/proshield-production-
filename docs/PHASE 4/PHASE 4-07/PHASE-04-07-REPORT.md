# ProShield — Phase 4.7 Final Report

**Slice under report:** Phase 4.7 — Generic rule management backend.

**Date:** 2026-08-29
**Author:** Senior Backend Engineer (Phase 4.7)
**Reviewer:** TBD
**Status:** **STABLE — 867/867 tests passing** (818 unit + 49 integration,
including 157 new Phase 4.7 tests: 146 unit + 11 integration). The
Phase 4.6 pipeline behaviour is unchanged. See
[§14 Stability verdict](#14-stability-verdict) for the verification
table.

---

## 1. Phase 4.7 Scope and Boundary

### 1.1 What Phase 4.7 Implements

Phase 4.7 extends the deterministic backend from

```
SecurityEvent
    -> Detection (per-event, Phase 4.4)
    -> Correlation (cross-event, Phase 4.5)
    -> Attack Timeline (Phase 4.6)
    -> Severity / Confidence (Phase 4.6)
```

to

```
Rule management backend
    RuleDefinition (declarative JSON-shaped rule)
        + RuleManagementService
            -> RuleRepository  (MongoDB managed_rules)
            -> RuleRegistry    (in-memory catalogue)
    GenericDeclarativeRule (single Rule subclass)
        -> DetectionEngine / CorrelationEngine (Phase 4.4-4.5)
        -> TimelineEngine / SeverityEngine     (Phase 4.6)
```

Concretely, Phase 4.7 ships:

1. **Strict, declarative rule-definition model.**
   `app/rules/management/definition.py` —
   `RuleDefinition` (Pydantic, `frozen=True`,
   `extra="forbid"`).
2. **Closed-set condition DSL.**
   `app/rules/management/conditions.py` — `Atom`,
   `Group`, `Expression`, `ConditionOperator`,
   `ConditionCombinator` (14 operators; AND / OR).
3. **Closed-set rule-type and action enums.**
   `RuleType` (`detection` / `correlation` /
   `threshold` / `rate_limit`); `ActionType`
   (`alert` / `log` / `block_remediation`).
4. **Single generic `Rule` subclass.**
   `GenericDeclarativeRule` — the only `Rule`
   produced by Phase 4.7. One class for every
   persisted rule.
5. **Persistence boundary.**
   `app/persistence/rule_repository.py` —
   `RuleRepository` + `MANAGED_RULES_VALIDATOR`
   `$jsonSchema` + 5 indexes. The repository is
   the only place that talks to pymongo about
   rule definitions.
6. **Service layer.**
   `app/rules/management/service.py` —
   `RuleManagementService` (CRUD, lifecycle,
   versioning, retire, dynamic reload).
7. **Package surface.**
   `app/rules/management/__init__.py` — single
   import surface for every Phase 4.7 symbol.
8. **Demo / verification script.**
   `scripts/demo_phase47.py` — the local end-to-end
   workflow the task asked for.
9. **Tests.** 157 new tests (146 unit + 11
   integration) across 6 new test modules
   covering: conditions DSL, definition
   validation, generic rule evaluation,
   repository CRUD, service lifecycle, and the
   end-to-end pipeline against the real local
   MongoDB.


### 1.2 What Phase 4.7 Does NOT Implement (deferred)

Per the documented scope:

* **Frontend / dashboard UI** for rule management.
* **Analyst queue, escalation, routing.**
* **AI / LLM** for rule authoring or suggestion.
* **Unrelated future connectors** beyond the
  existing Phase 4.1-4.6 boundary.
* **Arbitrary enforcement integrations** for the
  `block_remediation` action. The slice ships a
  structured record only; downstream enforcement
  layers (out of scope for Phase 4.7) consume it.
* **Dynamic condition language.** The DSL is the
  closed-set, allow-listed vocabulary documented
  in [§5 Conditions](#5-conditions). No
  expressions, no function calls, no arbitrary
  code.

### 1.3 Critical Architecture Rules Honoured

| Rule | Honoured By |
|------|-------------|
| Do NOT hard-code individual rule IDs / names into backend logic. | The whole slice is data-driven. The service, repository, and engine are agnostic to specific rule definitions. `GenericDeclarativeRule` is the only `Rule` subclass produced; creating a new rule never adds a Python class. |
| Do NOT require a new Python rule class for every normal rule. | The runtime evaluates every rule through `GenericDeclarativeRule.evaluate`. Verified by `test_phase47_full_create_validate_persist_load_execute`: a user-defined rule is created, persisted, loaded, and executed without writing any new Python. |
| Do NOT use `eval` / `exec` / `subprocess` / `importlib` / arbitrary uploaded code. | The conditions DSL is a closed-set enum. The only runtime primitive is `re.search` over a pre-compiled, pre-validated pattern. No `eval`, no `exec`, no shell, no `importlib`. Verified by [§11 Security tests](#11-security-tests). |
| Do NOT bypass the framework's lifecycle gate. | The service enforces the `candidate -> approved -> enabled` funnel via the existing `RuleRegistry` methods. Enabling a `CANDIDATE` rule is rejected. Re-enabling a superseded version is rejected. A `RETIRED` rule cannot be updated. Verified by `test_phase47_lifecycle_*` and the integration tests. |
| Do NOT introduce a parallel detection / correlation system. | The Phase 4.7 layer is purely a rule-management surface. The detection engine, correlation engine, timeline engine, and severity engine are unchanged; the user-defined rules flow through them via the existing authoritative `RuleRegistry`. Verified by the integration tests. |
| Do NOT break Phase 4.1-4.6 contracts. | All 818 unit + 49 integration tests from the prior phases still pass. The built-in NGINX rules continue to execute unchanged alongside user-defined rules. Verified by the regression run in [§14](#14-stability-verdict). |
| Do NOT skip server-side validation. | Every payload flows through the Pydantic `RuleDefinition` model and a service-layer check before persistence. The Pydantic model is `frozen=True, extra="forbid"`; the service translates `PydanticValidationError` into the framework's `RuleDefinitionValidationError` so a future HTTP API can return a uniform 400. |
| Do NOT create a new UI execution path. | The task brief explicitly forbids UI-only or alternate execution paths. The persistence and runtime paths share the same `RuleRegistry` + `GenericDeclarativeRule`; a rule loaded from MongoDB through `RuleRepository` enters the same registry as a built-in rule. |

---



## 2. Architecture

The Phase 4.7 layer is intentionally small and
stacked on top of the existing rule framework. The
dependency graph is:

```
                   RuleManagementService
                   /        |          \
                  /         |           \
        RuleRepository   RuleRegistry   RuleDefinition model
              |              |
        MongoDB          in-memory
        managed_rules    rule catalogue
                          ^
                          |
                  GenericDeclarativeRule
                  (single Rule subclass)
                          |
                  +-------+-------+
                  |       |       |
          DetectionEngine CorrelationEngine
                  |       |
        SecurityEvent
                  |       |
        TimelineEngine SeverityEngine
```

A normal user-defined rule is created, validated,
persisted, registered, evaluated, and produces a
Detection exactly like a built-in rule. The
`GenericDeclarativeRule.evaluate` implementation
is the only path through which a user-defined
rule's per-event verdict reaches the existing
pipeline.

The persistence layer is the only place that talks
to pymongo about rule definitions. The service
layer is the only place that orchestrates the
repository and the registry. The runtime
evaluation goes through the existing detection
engine, correlation engine, timeline engine, and
severity engine. Nothing is duplicated.

### 2.1 File map

```
app/
  __init__.py                                          # bumped to 4.7.0
  rules/
    management/
      __init__.py                                       # package surface
      conditions.py                                      # closed-set DSL
      definition.py                                      # RuleDefinition model
      errors.py                                          # domain errors
      generic_rule.py                                    # single Rule subclass
      service.py                                         # orchestrator
  persistence/
    rule_repository.py                                   # MongoDB boundary
docs/PHASE 4/PHASE 4-07/PHASE-04-07-REPORT.md            # this file
scripts/
  demo_phase47.py                                        # local end-to-end demo
tests/
  unit/
    _phase47_fakes.py                                    # shared fake pymongo
    test_phase47_conditions.py
    test_phase47_definition.py
    test_phase47_generic_rule.py
    test_phase47_rule_repository.py
    test_phase47_service.py
  integration/
    test_phase47_pipeline.py
```

---

## 3. Rule-Definition Model

The wire form a Phase 4.7 UI/API sends and the form
the repository persists is a strict Pydantic
`RuleDefinition`. It is the only model the slice
accepts and the only model the repository
round-trips through.

### 3.1 Field reference

| Field | Type | Required | Notes |
|-------|------|----------|-------|
| `rule_id` | `RuleId` (regex `^[A-Z][A-Z0-9]*(-[A-Z0-9]+)*$`, 3..64) | yes | Documented `WAF-001` / `AUTH-BRUTEFORCE-7` / `CORR-WEB-001` form. |
| `version` | `int` (1..999_999) | yes | Monotonically increasing per `rule_id`. |
| `name` | `str` (1..128) | yes | Human-readable label. |
| `description` | `str` (0..1024) | no | Free text. |
| `category` | `RuleCategory` | yes | One of `source_specific`, `common_behavioral`, `cross_source_correlation`. Same invariants as `RuleMetadata` (Section 8, 91). |
| `type` | `RuleType` | no (default `detection`) | One of `detection`, `threshold`, `rate_limit`, `correlation`. |
| `state` | `str` | no (default `candidate`) | One of `candidate`, `approved`, `retired`. `retired` is the service-managed soft-delete state. |
| `enabled` | `bool` | no (default `False`) | An enabled rule must be `approved` (Section 90 + 59). |
| `severity` | `SeverityBand` | no (default `medium`) | `low` / `medium` / `high` / `critical`. |
| `sources` | `Tuple[str, ...]` | no (required for `source_specific`) | Subset of `ALLOWED_SOURCES`. Sorted, unique. |
| `event_types` | `Tuple[str, ...]` | no (required for `source_specific` / `common_behavioral`) | Subset of `ALLOWED_EVENT_TYPES`. Sorted, unique. |
| `tags` | `Tuple[str, ...]` | no | Up to 16 tags. |
| `references` | `Tuple[str, ...]` | no | Up to 16 references. |
| `combinator` | `ConditionCombinator` | no (default `and`) | `and` / `or`. |
| `conditions` | `Expression` (or `None`) | no (required for non-detection) | A recursive discriminated union. See [§5 Conditions](#5-conditions). |
| `scope` | `Tuple[str, ...]` | no | Up to 32 free-form identifiers (asset / endpoint / account). |
| `evidence_requirements` | `Tuple[FieldPath, ...]` | no | Up to 16 field paths the underlying event must carry. |
| `thresholds` | `Dict[str, float]` | no (required for `threshold` / `rate_limit` / `correlation`) | Bounded numeric map. |
| `window_seconds` | `int` (1..2_592_000) or `null` | no (required for `threshold` / `rate_limit` / `correlation`) | Documented time window. |
| `actions` | `Tuple[ActionType, ...]` | yes (at least one) | Closed-set: `alert` / `log` / `block_remediation`. |

### 3.2 Type-specific invariants

* `threshold` and `rate_limit` rules **must**
  declare `window_seconds` and at least one
  `thresholds` key.
* `correlation` rules **must** declare
  `window_seconds` and exactly one `thresholds`
  key, with `combinator = and`.
* `detection` rules may have `conditions = null`
  (they are observation-only on the input side,
  matching the existing built-in NGINX rules).
* Non-detection rules **must** declare
  `conditions`.
* All three rule categories inherit the
  `RuleMetadata` invariants (Section 8, 91):
  `source_specific` requires at least one source
  and one event type; `common_behavioral`
  requires at least one event type;
  `cross_source_correlation` requires at least two
  sources.

---



## 4. Supported Rule Types

| Type | Description | Per-event evaluator | Persisted state |
|------|-------------|---------------------|-----------------|
| `detection` | Per-event, matches on conditions + evidence. Default. | `GenericDeclarativeRule` | `RuleMetadata` |
| `threshold` | Per-event, matches on conditions + threshold. | `GenericDeclarativeRule` (with `_thresholds_observed` check) | `RuleMetadata` |
| `rate_limit` | Per-event, matches on conditions + threshold. Same per-event evaluator as `threshold`; the closed-set tag tells a future enforcement layer how to interpret the result. | Same as `threshold` | `RuleMetadata` |
| `correlation` | Cross-event. The Phase 4.7 generic evaluator does NOT implement a full correlation algorithm; a correlation rule is registered as a `CorrelationPattern` adapter so the existing Phase 4.5 correlation engine picks it up. The slice ships the `RuleType.CORRELATION` enum entry, the validation, and the per-event evaluator, and the documented hook point. | `GenericDeclarativeRule` (per-event side) | `RuleMetadata` |

A user-defined rule of any of these four types is
created through the same API surface. The slice
does not require a new Python class per rule.

---

## 5. Conditions

The conditions DSL is a closed-set, allow-listed
vocabulary. No expressions, no function calls, no
arbitrary code.

### 5.1 Operators

| Operator | Operand type | Notes |
|----------|--------------|-------|
| `eq` / `ne` | string / number / bool | String / numeric equality / inequality. |
| `in` / `not_in` | list of primitives | List membership. |
| `gt` / `gte` / `lt` / `lte` | number | Numeric compare. Bool rejected (would be misleading). |
| `contains` / `starts_with` / `ends_with` | string | String operations. |
| `regex` | string | Pre-compiled at validation; `re.search`. Pattern length capped at 256; group count capped at 8. |
| `exists` / `not_exists` | (no value) | Field presence. |
| `ip_in_cidr` | string (CIDR) | Strict CIDR validation. |

Anything outside this enum is rejected at the
Pydantic layer. The validator's
`_validate_value_for_operator` function refuses
bad combinations (e.g. `gt` against a bool, `regex`
against a non-string, `in` against a non-list, `in`
against a list with non-primitive elements).

### 5.2 Field paths

A field path is a dotted string that resolves into
the canonical `SecurityEvent`. The valid top-level
fields are:

```
source, event_type, source_ip, destination, endpoint, asset, details
```

`details` is the only field that exposes sub-keys,
and sub-keys must match `^[a-z][a-z0-9_]*$` with
length <= 64. `__dunder__` names are rejected. The
validator's `validate_field_path` function refuses
unknown fields and malformed paths.

### 5.3 Combinators

* `AND` — all children must match.
* `OR` — at least one child must match.

Nested groups are supported up to depth 4. An empty
group is rejected at construction time.

### 5.4 Example

```json
{
  "kind": "group",
  "group": {
    "combinator": "and",
    "children": [
      {
        "kind": "atom",
        "atom": {
          "field": "event_type",
          "operator": "eq",
          "value": "authentication_failure"
        }
      },
      {
        "kind": "atom",
        "atom": {
          "field": "source_ip",
          "operator": "ip_in_cidr",
          "value": "198.51.100.0/24"
        }
      }
    ]
  }
}
```

This is the exact payload the demo script and the
integration test use.

---



## 6. Lifecycle and Versioning

The Phase 4.7 lifecycle matches the documented
Phase 4.2 candidate -> approved -> enabled funnel
(Section 59, 89) and the documented Phase 4.2
"strictly greater than latest" version semantic
(Section 33). The service layer is the sole
authority; the repository and registry enforce the
same invariants in their own layers.

### 6.1 Operations

| Operation | Pre-conditions | Effects |
|-----------|-----------------|---------|
| `create(payload)` | payload validates; `actions` non-empty; lifecycle invariants | persists; registers in the registry |
| `read / list / list_latest / list_evaluable` | — | pure read |
| `update(rule_id, version, payload)` | rule exists and is not retired | replaces the persisted document; re-registers the in-memory rule |
| `create_new_version(rule_id, payload)` | rule exists and is not retired; `payload.version` is strictly greater than the latest | persists the new version; registers it as a new `GenericDeclarativeRule` instance |
| `set_state(rule_id, new_state, version=...)` | rule exists and is not retired (except when transitioning to `retired`); `new_state` is one of `candidate` / `approved` / `retired` | mutates MongoDB and the in-memory registry |
| `set_enabled(rule_id, enabled, version=...)` | rule exists and is not retired | mutates MongoDB and the in-memory registry; the framework's supersede-on-new-version check protects against re-enabling a deprecated version |
| `retire(rule_id, version=...)` | rule exists | soft-deletes; unregisters from the registry; the document remains in the collection with `state = "retired"` for audit traceability |
| `reload_registry()` | — | reconciles every persisted rule into the in-memory registry; the "dynamic loading" entry point |

### 6.2 Versioning

* A new version is created in `CANDIDATE` /
  disabled state regardless of what the payload
  says. The documented funnel applies: the caller
  promotes to `approved` and enables.
* Re-enabling a superseded version (a version
  that is not the latest for the same `rule_id`)
  is refused by the framework's documented
  supersede check (Section 33 + 88). The service
  translates the framework error into
  `RuleNotInExpectedStateError`.
* Retire is a one-way operation. A retired rule
  cannot be updated or re-enabled.

### 6.3 Disabling vs. retiring

* **Disable** sets `enabled = False`; the rule
  remains in the registry and in the persisted
  collection with `state = approved`.
* **Retire** sets `state = "retired"` and
  `enabled = False`; the rule is unregistered
  from the in-memory `RuleRegistry`; the document
  remains in the collection for audit.

---

## 7. Persistence

`RuleRepository` is the only place in the codebase
that talks to pymongo about rule definitions. It
mirrors the documented policy of
`SecurityEventRepository` / `DetectionRepository` /
`CorrelationRepository`:

* Driver errors are translated to safe
  `DomainError` subclasses (here:
  `RulePersistenceError`).
* The collection carries a `$jsonSchema` validator
  and a unique `(rule_id, version)` index.
* Idempotent re-delivery of the same
  `(rule_id, version)` is rejected with
  `DuplicateManagedRuleError` (HTTP 409 on a
  future API surface).
* NoSQL-injection-shaped queries are rejected at
  the input layer: a non-`str` `rule_id` raises
  `ValidationError` before pymongo is touched.

### 7.1 Document shape

```json
{
  "_id": <ObjectId>,
  "rule_id": "CUSTOM-001",
  "version": 1,
  "name": "...",
  "description": "...",
  "category": "source_specific",
  "type": "detection",
  "state": "approved",
  "enabled": true,
  "severity": "medium",
  "sources": ["nginx"],
  "event_types": ["authentication_failure"],
  "tags": [...],
  "references": [...],
  "combinator": "and",
  "conditions": { "kind": "atom" | "group", ... } | null,
  "scope": [...],
  "evidence_requirements": [...],
  "thresholds": { "key": 401, ... } | {},
  "window_seconds": 60 | null,
  "actions": ["alert", "block_remediation"]
}
```

A retired rule is preserved with `state = "retired"`
and `enabled = false`. The document is not removed
from the collection.

### 7.2 Indexes

| Name | Key | Unique |
|------|-----|--------|
| `rule_rule_id_version_unique` | `(rule_id, version)` | yes |
| `rule_rule_id` | `(rule_id, version DESC)` | no |
| `rule_state` | `(state)` | no |
| `rule_enabled` | `(enabled)` | no |
| `rule_type` | `(type)` | no |

### 7.3 Round-trip

The repository's `_document_to_definition`
rebuilds the `Expression` (atom / group)
recursively. The conditions tree is round-trippable;
a definition that came out of the service is
reconstructible by `RuleDefinition.model_validate(doc)`.

---



## 8. Dynamic Loading

The service's `reload_registry()` method is the
documented dynamic-loading entry point. It:

1. Fetches the latest version of every `rule_id`
   from the repository.
2. For each, registers a
   `GenericDeclarativeRule` in the in-memory
   `RuleRegistry`, or unregisters it if
   `state == "retired"`.
3. Removes any previously-known managed-rule
   entries from the registry that no longer have a
   corresponding persisted latest version.

The set of (rule_id, version) pairs the service has
ever registered is tracked in
`service._known_persisted_ids`. Built-in rules are
never in this set, so the loader does not affect
them.

A caller can invoke `reload_registry()` after a
batch of rules has been created / updated / retired
to see the effect on the runtime without restarting
the process. Verified by
`test_phase47_dynamic_load_registers_persisted_rule`
and the demo script.

---

## 9. Execution

`GenericDeclarativeRule` is the single `Rule`
subclass produced by Phase 4.7. Its `evaluate(event)`
is total and deterministic:

1. Capture `now` once.
2. If the event is not a `SecurityEvent`, return
   `matched=False` (no crash on bad input).
3. If the rule's `evidence_requirements` are not
   satisfied, return `matched=False` with a
   diagnostic reasoning.
4. If the rule's `conditions` evaluate to `False`
   under the rule's `combinator`, return
   `matched=False`.
5. If the rule's `thresholds` are not observed on
   the event, return `matched=False`.
6. Otherwise, return `matched=True` with a
   deterministic reasoning string and a structured
   `extra` dict carrying the rule's `rule_type`,
   `severity`, and `actions`.

The framework's `RuleRegistry` handles the
candidate -> approved -> enabled filter. A
`GenericDeclarativeRule` whose underlying
`RuleDefinition` is `CANDIDATE` or whose
`enabled = False` is invisible to the detection
engine. A retired rule is unregistered and is
invisible.

The detection engine, correlation engine,
timeline engine, and severity engine are unchanged.
User-defined rules flow through them via the same
authoritative path as built-in rules.

---

## 10. Security Boundaries

The Phase 4.7 layer preserves every documented
security boundary. Specifically:

* **No arbitrary code execution.** The
  `GenericDeclarativeRule` evaluator never invokes
  `eval` / `exec` / `subprocess` / `os.system` /
  `importlib`. The only runtime primitives are
  Pydantic (model construction) and `re.search`
  over a pre-validated, pre-compiled pattern. The
  test `test_rule_repository_create_rejects_non_definition`
  and friends verify the model rejects every
  non-dict / non-`RuleDefinition` input.
* **Server-side validation is authoritative.**
  Every payload flows through the Pydantic
  `RuleDefinition` model and a service-layer
  governance check. The Pydantic model is
  `frozen=True, extra="forbid"`. The service
  translates `PydanticValidationError` into the
  framework's `RuleDefinitionValidationError` so a
  future HTTP API can return a uniform 400.
* **No SQL / NoSQL injection.** The repository
  rejects non-`str` `rule_id` and non-`int` /
  bounded `version` arguments with `ValidationError`
  before pymongo is touched. `$where`, `eval`, and
  arbitrary-`$` operators are not used. The
  `$jsonSchema` validator is
  `additionalProperties: false`, so a malicious
  document cannot smuggle extra fields into a read.
* **Closed-set action vocabulary.** The only
  accepted actions are `alert`, `log`, and
  `block_remediation`. Anything else is rejected
  at the Pydantic layer. The slice does NOT
  implement arbitrary enforcement; the
  `block_remediation` value is a structured record
  only.
* **No `__dunder__` field paths.** The conditions
  validator's `validate_field_path` rejects
  `__class__` / `__dict__` style names so a
  malicious rule cannot reach Python attributes.
* **Regex safety bounds.** The `regex` operator
  pattern length is capped at 256; the group count
  is capped at 8. Patterns are compiled at
  validation time and any compile error is
  surfaced as a Pydantic validation error.
* **Lifecycle gate.** Enabling a `CANDIDATE` rule,
  re-enabling a superseded version, or operating
  on a retired rule all raise
  `RuleNotInExpectedStateError` /
  `ManagedRuleRetiredError` (HTTP 409 / 404 on a
  future API surface).
* **Audit traceability.** The framework's
  `RuleMetadata.state` is preserved in the
  `Detection` (`rule_id` + `rule_version`), so a
  fired detection always points back to the exact
  rule version that produced it (DET-07).
* **Authorisation.** The slice is backend-only;
  the Phase 3 RBAC is preserved (the API surface
  lives in a future slice). Today, the service is
  consumed by the tests and the demo script, both
  of which run with full authority.

---



## 11. Security Tests

| Concern | Test |
|---------|------|
| `eval` / arbitrary code injection | `test_evaluator_is_total_for_garbage` (a non-`SecurityEvent` input does not crash the evaluator). |
| Unknown operator | `test_atom_rejects_unknown_operator` |
| Unknown source | `test_invalid_source_rejected` |
| Unknown event type | `test_invalid_event_type_rejected` |
| Unknown action | `test_atom_in_rejects_non_primitive_values` + `test_create_rejects_unknown_action` (integration) |
| `__dunder__` field path | `test_atom_rejects_unknown_field_path` + `test_validate_field_path_rejects_dunder` |
| Regex DoS | `test_atom_regex_rejects_oversized_pattern` |
| Regex compile error | `test_atom_regex_rejects_compile_error` |
| Bool under `gt` | `test_atom_gt_rejects_bool` |
| Empty `in` list | `test_atom_in_rejects_empty_list` |
| Oversized value | `test_atom_in_rejects_non_primitive_values` |
| Oversized thresholds | `test_threshold_rejects_oversized_value` |
| NoSQL injection in `rule_id` | `test_get_rejects_non_str_rule_id` |
| Unknown persisted state | `test_set_state_field_rejects_invalid_state` |
| Update of retired rule | `test_update_retired_rejected` (service) + `test_update_retired_rejected` (integration) |
| Re-enable of superseded version | `test_phase47_lifecycle_new_version` (integration) |

---

## 12. Integration with Existing Layers

The slice does not modify any of the existing
Phase 4.1-4.6 components. User-defined rules flow
through the same pipeline as built-in rules:

```
Phase 4.7 RuleManagementService
    -> RuleRepository (MongoDB)
    -> RuleRegistry (in-memory)
    -> Phase 4.4 DetectionEngine.run(event)
        -> Phase 4.4 Detection records (frozen, BSON-safe)
            -> Phase 4.5 DetectionRepository (MongoDB)
    -> Phase 4.5 CorrelationEngine.run(detections, events)
        -> Phase 4.5 Correlation records
            -> Phase 4.5 CorrelationRepository (MongoDB)
    -> Phase 4.6 TimelineEngine.run(events, detections, correlations)
        -> Phase 4.6 TimelineResult
    -> Phase 4.6 SeverityEngine.run(detections, correlations, events)
        -> Phase 4.6 SeverityResult
```

The integration test
`test_phase47_full_create_validate_persist_load_execute`
exercises the full path against the real local
MongoDB.

---

## 13. Tests

### 13.1 Test count

| Category | Count |
|----------|-------|
| Unit (Phase 4.7 new) | 146 |
| Unit (regression) | 672 |
| **Unit total** | **818** |
| Integration (Phase 4.7 new) | 11 |
| Integration (regression) | 38 |
| **Integration total** | **49** |
| **Grand total** | **867** |

### 13.2 Phase 4.7 test modules

| Module | Tests | Focus |
|--------|-------|-------|
| `tests/unit/test_phase47_conditions.py` | 45 | DSL construction, validation, evaluation, AND/OR, depth limit, regex safety, IP-in-CIDR, field path allow-list, existence checks, evaluator totality. |
| `tests/unit/test_phase47_definition.py` | 44 | Pydantic model validation, rule-id pattern, source/event-type catalogues, severity enum, state/enabled invariant, category vs applicability invariants, type-specific invariants (threshold / rate_limit / correlation), actions enum, scope / evidence_requirements / thresholds bounds, extra-field rejection, conditions round-trip. |
| `tests/unit/test_phase47_generic_rule.py` | 14 | Construction, observation-only rule, atom conditions, OR-group conditions, evidence requirements, threshold evaluation, bool-rejection in threshold, non-event total behaviour, determinism, severity/actions in `extra`. |
| `tests/unit/test_phase47_rule_repository.py` | 19 | CRUD, duplicate (rule_id, version) raises, find_latest_versions aggregation, find_all, update in place, state / enabled field setters, soft-delete mark, non-definition rejection, non-str `rule_id` rejection, invalid-state rejection, count, conditions round-trip. |
| `tests/unit/test_phase47_service.py` | 24 | Service creation guards, validation path, create / read, duplicate, list_all, list_evaluable, update, versioning, set_state, set_enabled, retire, update of retired rejected, reload_registry. |
| `tests/integration/test_phase47_pipeline.py` | 11 | Full create -> validate -> persist -> load -> execute against real MongoDB, validation rejection paths, lifecycle disable, lifecycle new version, lifecycle retire, dynamic load, built-in NGINX compatibility, user + built-in coexistence, correlation engine accepts user rule detections. |

### 13.3 How to run

```bash
# Unit tests only
python -m pytest tests/unit -q

# Integration tests (require the local MongoDB on
# 127.0.0.1:27017; the integration conftest creates a
# per-session isolated database)
python -m pytest tests/integration -q

# Full suite
python -m pytest tests/ -q

# Focused Phase 4.7 tests
python -m pytest tests/unit/test_phase47_*.py \
                 tests/integration/test_phase47_pipeline.py -v

# Local end-to-end demo
python scripts/demo_phase47.py
```

---



## 14. Stability Verdict

| Stage | Result |
|-------|--------|
| `tests/unit` (Phase 4.7 new) | 146 / 146 pass |
| `tests/unit` (regression: Phase 4.1-4.6) | 672 / 672 pass |
| `tests/integration` (Phase 4.7 new) | 11 / 11 pass |
| `tests/integration` (regression: Phase 4.1-4.6) | 38 / 38 pass |
| `scripts/demo_phase47.py` (local end-to-end) | PASSED — 7/7 scenarios pass: create -> validate -> persist -> load -> execute, modify, disable, new version, refuse superseded re-enable, re-enable, retire |
| `python -c "from app.rules.management.conditions import Atom"` | OK |
| `python -c "from app.rules.management.definition import RuleDefinition"` | OK |
| `python -c "from app.rules.management.generic_rule import GenericDeclarativeRule"` | OK |
| `python -c "from app.rules.management.service import RuleManagementService"` | OK |
| `python -c "from app.persistence.rule_repository import RuleRepository"` | OK |
| `python -c "from app.rules.management import (RuleDefinition, RuleManagementService, GenericDeclarativeRule, RuleType, ActionType, Atom, Group, Expression, ConditionOperator, ConditionCombinator, RuleDefinitionValidationError)"` | OK |
| `app/__version__` | `4.7.0` |
| `app/__phase__` | `4.7` |

**STABLE.** The complete `CREATE -> VALIDATE -> PERSIST -> LOAD -> EXECUTE` workflow
runs end-to-end through the real local MongoDB. The
full regression suite passes. Creating a new normal
rule does not require writing a new Python class. No
`eval` / `exec` / shell / unsafe dynamic execution is
used. Every layer's contract is preserved.

### 14.1 Test counts (final)

* Unit tests: **818 passed** in ~4.4s
* Integration tests: **49 passed** in ~8s
* Grand total: **867 passed**

### 14.2 Phase 4.7 contribution to the suite

* New unit tests: **146** (`tests/unit/test_phase47_*.py`)
* New integration tests: **11** (`tests/integration/test_phase47_pipeline.py`)


## 15. Local Verification

The local verification is the demo script
`scripts/demo_phase47.py`. It uses the per-session
test database `proshield_test` and a per-run
collection name suffix so it does not collide
with the production database or with itself.

The documented output (annotated):

```
Phase 4.7 local verification
----------------------------
Test database: proshield_test
Events collection: security_events_<suffix>

========================================================================
1. CREATE -> VALIDATE -> PERSIST -> LOAD -> EXECUTE
========================================================================
  CREATE   : rule definition payload -> service.create
             -> DEMO-RULE-001 v1
  VALIDATE  : Pydantic + service-layer checks passed
  PERSIST   : managed_rules count=1
  LOAD      : registry.get('DEMO-RULE-001', 1) -> GenericDeclarativeRule
  EXECUTE   : 4 detections produced

========================================================================
2. MODIFY the rule (different CIDR, no backend code change)
========================================================================
  New CIDR (10.0.0.0/8) does not match the test events -> 0 new detections

========================================================================
3. DISABLE the rule and prove it stops executing
========================================================================
  After disable -> 0 new detections (expected 0)

========================================================================
4. NEW VERSION: create v2 and prove the intended version is recorded
========================================================================
  v2 created: state=candidate (expected candidate), enabled=False (expected False)
  v2 hits: 4 (v1 was disabled, v2 fires on the 198.51.100.0/24 events)

========================================================================
5. RE-ENABLE superseded v1 is refused (Section 33 + 88)
========================================================================
  OK: refused -> RuleNotInExpectedStateError: rule 'DEMO-RULE-001' v1
       is superseded by v2; a superseded version cannot be re-enabled

========================================================================
6. RE-ENABLE the active v2 (re-enable cycle)
========================================================================
  After re-enable v2 -> 4 new v2 detections (expected 4)

========================================================================
7. RETIRE the rule (soft-delete)
========================================================================
  After retire: registry entry removed; document state=retired, enabled=False

========================================================================
Phase 4.7 verification: PASSED
========================================================================
```

The four task-mandated workflows (modify without
backend code change, disable, new version,
re-enable) are demonstrated by sections 2-6 of the
demo.

---

## 16. Limitations and Explicit Non-Goals

* **Frontend / UI** is not implemented; a future
  slice will provide it.
* **Analyst queue, escalation, routing** are
  documented responsibilities of the (deferred)
  Phase 4.7 incident engine and the routing layer.
* **AI / LLM-assisted rule authoring** is out of
  scope.
* **Arbitrary enforcement integrations** for the
  `block_remediation` action are not implemented.
  The slice ships the structured record; downstream
  enforcement layers (out of scope) consume it.
* **Cross-source correlation patterns** (WAF +
  NGINX, etc.) are out of scope for Phase 4.7. The
  `RuleType.CORRELATION` enum entry exists and the
  type-specific invariants are enforced, but the
  slice does not ship a correlation pattern
  factory for user-defined correlation rules.
* **The framework's supersede-on-new-version
  semantic protects against accidentally
  re-enabling a deprecated version (Section 33 +
  88).** The slice does NOT automatically disable
  a superseded version; the caller is expected to
  retire or disable v1 explicitly. This is the
  documented Phase 4.2 behaviour and is preserved
  by the slice.

---

## 17. Future Work (deferred)

* Frontend / dashboard UI for rule management.
* HTTP / REST API surface for the
  `RuleManagementService` (the service is already
  structured for it; the API layer is a future
  slice).
* Analyst queue, escalation, and routing.
* AI / LLM-assisted rule authoring.
* Arbitrary enforcement integrations for
  `block_remediation`.
* Cross-source correlation patterns for user
  rules.

---

*End of Phase 4.7 Final Report*

* New test infrastructure:
  `tests/unit/_phase47_fakes.py` (in-memory fake
  pymongo used by the service / repository unit
  tests; the integration tests use the real local
  MongoDB).

---


## 16. Post-review remediation (2026-08-30)

This section records the remediation work that landed
after the independent review
(`docs/PHASE 4/PHASE 4-07/PHASE-04-07-REVIEW.md`)
found two issues in the slice as initially shipped:

* **CONFIRMED DEFECT (§8.1)**: a single poisoned
  `managed_rules` document could cause
  `RuleManagementService.reload_registry()` to raise
  an uncaught `pydantic.ValidationError`, leaving the
  in-memory `RuleRegistry` partially applied.
* **DESIGN WEAKNESS (§7.2)**: the `regex` operator
  accepted catastrophic-backtracking patterns such as
  `(a+)+$`; only syntactic compile-time safety was
  checked.

The historical development record above (Sections 1-15)
is preserved. The fixes are recorded below.

### 16.1 Verified root cause

#### Reload-registry defect

A document that survived the BSON `$jsonSchema`
validator (because the validator did not enforce the
closed-set enums on `sources.items` /
`event_types.items` or on
`conditions.atom.operator`) reached
`_document_to_definition` in
`app/persistence/rule_repository.py`. That helper
called `RuleDefinition.model_validate(doc)` directly;
a `pydantic.ValidationError` propagated uncaught
through the list comprehension in
`RuleRepository.find_latest_versions` and aborted the
entire `reload_registry` call.

The reproduction script

#### ReDoS weakness

The regex validator in
`app/rules/management/conditions.py` only checked
length, group count, and that the pattern compiled.
There was no structural gate against
catastrophic-backtracking shapes such as `(a+)+` /
`(a*)*` / `((a+))+` / `(?:a+)+` / `(a+){2,3}` /
`([a-z]+)+`.

The same reproduction script confirmed the defect:
`_validate_value_for_operator(ConditionOperator.REGEX,
"(a+)+$")` returned without raising, and the
underlying `re.search` spent O(n^2) CPU on
maliciously crafted input.

### 16.2 Exact fix

#### Fix 1: BSON `$jsonSchema` validator hardening

`app/persistence/rule_repository.py` -
`MANAGED_RULES_VALIDATOR` now adds the closed-set
enums the review called out:

* `sources.items.enum` is sourced from
  `app.domain.security_event.ALLOWED_SOURCES`.
* `event_types.items.enum` is sourced from
  `app.domain.security_event.ALLOWED_EVENT_TYPES`.
* `combinator.enum` and `category.enum` are sourced

#### Fix 2: Quarantine on read

`app/persistence/rule_repository.py` -
`_document_to_definition` is now total. It catches
`pydantic.ValidationError`, `ValueError`, and
`TypeError`, logs a structured warning
(`rule_repository.document_quarantined`) carrying the
`rule_id` / `version` and the error summary, and
returns `None`.

`RuleRepository.find_latest_versions` and `find_all`
filter out `None` entries, so a poisoned document
that nevertheless reaches the repository is silently
quarantined and never aborts the registry reload.

#### Fix 3: ReDoS structural gate

`app/rules/management/conditions.py` - new helpers
`_is_catastrophic_backtracking` and
`_skip_char_class` implement a small structural
scanner that walks the pattern tracking the
open-paren depth and a per-depth flag that records
whether the current group already contains a
quantifier. When the scanner closes a group that
contained a quantifier AND the next character is a
quantifier (or a brace quantifier with an upper
bound > 1), the pattern is rejected.

The scanner handles:

### 16.3 Regression tests

* `tests/unit/test_phase47_conditions.py` (extended
  with 11 ReDoS regression tests):
  `test_redos_detector_flags_nested_quantifier_plus_plus`,
  `test_redos_detector_flags_nested_quantifier_star_star`,
  `test_redos_detector_flags_nested_quantifier_mixed`,
  `test_redos_detector_flags_nested_groups`,
  `test_redos_detector_flags_brace_upper_bound`,
  `test_redos_detector_accepts_legitimate_patterns`,
  `test_atom_regex_rejects_catastrophic_nested_quantifier`,
  `test_atom_regex_rejects_catastrophic_star`,
  `test_atom_regex_accepts_legitimate_pattern`,
  `test_evaluate_atom_regex_no_dos_on_catastrophic`,
  `test_redos_detector_skips_escaped_and_character_class`.

* `tests/unit/test_phase47_reload_resilience.py` (new
  file, 17 tests): 9 quarantine tests
  (`test_quarantine_*`), 3 read-path tests
  (`test_find_latest_versions_filters_poisoned`,
  `test_find_all_filters_poisoned`,
  `test_get_returns_none_for_poisoned`), and 5
  end-to-end service tests
  (`test_reload_registry_does_not_crash_on_poisoned`,
  `test_reload_registry_works_with_only_poisoned`,

### 16.4 Verification result

Reproduction: `python scripts/_review47_repro.py`
against the real local MongoDB. Pre-fix: 4 of 8
reload probes reproduced the defect; the ReDoS
pattern was accepted by validation. Post-fix: 0 of 8
reload probes reproduced the defect; the ReDoS
pattern is rejected with a clear error message.

Test counts (all run against the real local MongoDB):

| Suite | Pre-fix | Post-fix | Delta |
| --- | --- | --- | --- |
| Phase 4.7 unit tests | 146 | 157 | +11 (ReDoS) |
| Reload-resilience unit tests (new file) | 0 | 17 | +17 |
| Phase 4.7 integration tests | 11 | 11 | 0 |
| BSON validator integration tests (new file) | 0 | 8 | +8 |
| **Phase 4.7 total** | **157** | **193** | **+36** |
| **Project-wide unit tests** | **818** | **846** | **+28** |
| **Project-wide integration tests** | **49** | **57** | **+8** |
| **Project-wide total** | **867** | **903** | **+36** |

All existing tests pass. No prior-phase behaviour was
changed. The Phase 4.7 primary acceptance test
(`scripts/_review47.py` step 1) still passes: a new
normal rule is creatable, validated, persisted, loaded
into the real `RuleRegistry`, executed by the generic
evaluator, and produces the expected security result.
The 50-rule pressure test still produces 200 user
detections + 8 built-in NGINX detections per event.

### 16.5 Updated production-safety assessment

* Before the review: the slice was declared STABLE
  for the primary acceptance test (157/157 Phase 4.7
  tests pass, 867/867 project-wide). The
  reload-registry defect and the ReDoS weakness were
  both present but not exercised by the existing test
  suite.
* After the review: the slice was declared STABLE for
  the primary acceptance test, UNSAFE for production
  where the persistence layer is exposed to untrusted
  writers. The review identified the two issues and
  prescribed three small, additive fixes.
* After this remediation: the slice is STABLE for the
  primary acceptance test AND for production
  deployment where the persistence layer is exposed
  to untrusted writers, provided the standard
  documented constraints (the service layer is the
  authoritative gate; direct pymongo writes are
  reserved for trusted operators) are observed. The
  model layer is the source of truth; the BSON
  validator and the read-time quarantine are the
  documented defence-in-depth statements of the same
  rules.

Final stability statement:

**Phase 4.7 is STABLE for the primary acceptance test
AND for production deployment of the
generic-rule-management backend. The two findings from
the independent review have been remediated with
three small, additive, mutually independent fixes; 36
new regression tests cover the fixes; the full project
test suite (846 unit + 57 integration = 903) passes
against the real local MongoDB; no prior-phase
behaviour was changed.**

The non-blocking observations from the review (Section
9 of `docs/PHASE 4/PHASE 4-07/PHASE-04-07-REVIEW.md`)
and the test gaps (Section 10) are documented but not
remediated in this pass; they remain follow-up work
for a future phase.


  `test_reload_registry_with_mixed_keeps_state_consistent`,
  `test_reload_is_deterministic_across_calls`,
  `test_reload_does_not_register_quarantined_rule`).

* `tests/integration/test_phase47_bson_validator.py`
  (new file, 8 tests):
  `test_bson_validator_rejects_state_candidate_enabled_true`,
  `test_bson_validator_rejects_unknown_source`,
  `test_bson_validator_rejects_unknown_event_type`,
  `test_bson_validator_rejects_unknown_combinator`,
  `test_bson_validator_rejects_invalid_state_value`,
  `test_bson_validator_accepts_disabled_candidate`,
  `test_bson_validator_accepts_retired_disabled`,
  `test_bson_validator_accepts_approved_enabled`.


* escaped characters (`\X`)
* character classes (`[\^...]`)
* non-capturing groups `(?:...)` and named groups
  `(?P<name>...)`
* raw quantifier count braces `{m}` and `{m,n}`
* propagation: a child group that contained a
  quantifier marks its parent group as containing a
  quantifier (so `((a+))+` is caught)

The validator (Section 8 of
`app/rules/management/conditions.py`) calls the gate
at the end of the regex branch. The runtime
`_regex_match` also calls the gate as a
defence-in-depth measure in case a pattern reaches
the runtime without going through the model
validator.

No new dependencies. The fix uses only the standard
library.

  from `app.rules.types.RuleCategory` /
  `app.rules.management.conditions.ConditionCombinator`.
* The cross-field invariant
  `enabled == true => state == 'approved'` is
  expressed as a `oneOf` with two branches (because
  MongoDB's `$jsonSchema` does NOT support
  `if`/`then`/`else` - the `dependencies` keyword
  fires whenever the property is *present*, not when
  the value is `true`). The two branches cover the
  documented `enabled=False` (any state) and
  `enabled=True` (state must be `approved`) cases.

The validator remains the second line of defence.
The Pydantic `RuleDefinition` model is the source of
truth.

`scripts/_review47_repro.py` confirmed the defect
against the local MongoDB: 4 of 8 poisoned-document
mutations reproduced the crash (state=candidate +
enabled=True, unknown source, unknown event_type,
unknown operator).

