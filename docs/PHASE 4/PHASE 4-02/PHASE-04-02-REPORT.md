# ProShield — Phase 4.2 Final Report

## 1. Understanding

Phase 4.2 establishes the **deterministic Rule Framework and Rule
Registry** documented in
`docs/PHASE 4/DETECTION_ENGINEERING_AND_FUTURE_AI.md` (Sections 8, 9,
10, 11, 59, 87, 88, 89, 90, 91) and
`docs/PHASE 2/DOMAIN_DATA_MODEL.md` (Section 5).

It is the foundation **on which** the future detection engine, source-
specific rules, common behavioral rules, and cross-source correlation
rules will sit. It explicitly does **not** ship:

* The full detection engine (engine wiring, scheduling, batching,
  Detection object persistence).
* The correlation engine, incident engine, report, routing, AI.
* A production rule library: WAF, NGINX, IAM, rate-limit, network, and
  correlation rules are **not** implemented in this slice. The
  `app/rules/_library/` package establishes the documented on-disk
  organisation (Section 9) but every rule slot is empty. Every
  future rule must follow the documented
  `candidate -> testing -> review -> approved -> enabled` funnel
  (Section 59, Section 89).

### What the slice ships

* The canonical `Rule` interface (one method: `evaluate(event) -> RuleEvaluation`).
* The `RuleEvaluation` dataclass — the documented evaluation contract
  (Section 13) that the future detection engine will translate into
  persisted `Detection` records.
* The `RuleMetadata` Pydantic model: rule_id (documented `WAF-001` /
  `AUTH-BRUTEFORCE-7` form), version, name, category, applicability
  metadata (sources, event_types), description, tags, references, and
  the lifecycle flags (`state` and `enabled`).
* Three documented rule categories: `SOURCE_SPECIFIC`,
  `COMMON_BEHAVIORAL`, `CROSS_SOURCE_CORRELATION` (Section 8).
* Two documented lifecycle states: `CANDIDATE` and `APPROVED`, with
  the documented invariant **"enabled implies APPROVED"** enforced by
  the registry.
* A small `SimpleRule` helper for tests and trivially-declarative
  rules; a minimal `NoopRule` test helper for cross-source rules.
* The authoritative in-memory `RuleRegistry` with registration,
  versioning, lookup, applicability filtering, lifecycle transitions,
  and a thread-safe mutation path.
* Deterministic rule discovery and loading from `RULES` /
  `RULE_FACTORIES` module exports.
* The documented file-system organisation (Section 9) with empty
  per-category submodules in `app/rules/_library/`.
* **111 focused unit tests** (positive, negative, edge, registry,
  versioning, applicability, loader, plus 10 FINDING-1/2/3
  regression tests) plus the unchanged
  **18 integration tests** for Phase 4.1, for a total of
  **213 unit + 18 integration = 231 tests, all passing in 5.37s**.

## 2. Pre-Implementation Findings

### Existing (post-Phase 4.1)

* Backend framework / runtime: `app/` (config, observability, domain,
  connectors, ingestion, persistence) is in place.
* `SecurityEvent` Pydantic model is the canonical envelope at the
  trust boundary; its `ALLOWED_SOURCES` and `ALLOWED_EVENT_TYPES`
  frozensets are the authoritative vocabulary.
* `app/domain/errors.py` exposes the `DomainError` hierarchy and the
  safe-error envelope that rule-layer errors inherit.
* 102 unit + 18 integration tests, all green.

### Missing

* Everything rule-related: domain types, registry, lifecycle,
  versioning, applicability filter, loader, test structure.

### Local MongoDB state

* `mongod` PID 4832, **running** on `127.0.0.1:27017`. No
  `proshield` rule collections are needed for Phase 4.2 (the
  registry is in-memory only); Phase 4.1's collections are
  untouched.

### Relevant dependencies

* Python 3.13.3, `pydantic 2.13.4`, `pytest 9.1.1`. No new
  third-party dependencies were added in this slice.

## 3. Implementation Summary

Built the documented rule framework as a small, dependency-free
package that follows the corpus literally:

| Layer | Module(s) | Responsibility |
|---|---|---|
| Types | `app/rules/types.py` | `RuleCategory`, `RuleState`, `RuleMetadata`, `RuleEvaluation`. |
| Rule | `app/rules/rule.py` | `Rule` abstract base, `SimpleRule` helper, `RuleEvaluationError`. |
| Registry | `app/rules/registry.py` | Authoritative in-memory rule catalogue, lifecycle transitions, applicability filter, thread-safe mutations. |
| Loader | `app/rules/loader.py` | Deterministic discovery from `RULES` / `RULE_FACTORIES` module exports, transactional import, registration. |
| Library | `app/rules/_library/` | On-disk organisation per Section 9; submodules intentionally empty. |
| Tests | `tests/unit/test_rule_*.py`, `tests/unit/_rules_helpers.py` | 101 new unit tests covering all behaviours. |

Key design decisions:

* **No pymongo in the rule framework.** The registry is
  authoritative in-memory; persistence of the rule catalogue is a
  future slice. The corpus treats "the registry" as a logical
  concept first; this matches Section 88.
* **Pydantic for metadata, frozen dataclass for evaluation.** This
  gives us the validation and immutability guarantees on
  authoritative inputs (`RuleMetadata`) and the cheap,
  hash-friendly evaluation result (`RuleEvaluation`) that the
  future detection engine will use.
* **No rule implementation logic in the framework.** The framework
  is metadata + plumbing; every concrete rule is a user-supplied
  `Rule` subclass. `SimpleRule` exists only for tests and
  declarative one-liners.
* **Source / event-type applicability is enforced at metadata
  construction time.** The same `ALLOWED_SOURCES` /
  `ALLOWED_EVENT_TYPES` frozensets used by `SecurityEvent` are
  used here (Section 90), so a typo in a rule's applicability is
  rejected at registration, never at evaluation.
* **The "enabled implies APPROVED" invariant is enforced by
  construction at registration AND by the lifecycle methods.**
  Constructing an `enabled=True, state=CANDIDATE` rule is rejected
  with `CandidateNotPromotableError`; `set_enabled(True)` on a
  CANDIDATE rule raises the same error; demoting an APPROVED rule
  to CANDIDATE silently resets `enabled` to `False`.

## 4. Files Added or Modified

### Added (product code)

```
app/rules/__init__.py
app/rules/types.py
app/rules/rule.py
app/rules/registry.py
app/rules/loader.py
app/rules/_library/__init__.py
app/rules/_library/common/__init__.py
app/rules/_library/waf/__init__.py
app/rules/_library/nginx/__init__.py
app/rules/_library/iam/__init__.py
app/rules/_library/rate_limit/__init__.py
app/rules/_library/network/__init__.py
app/rules/_library/correlation/__init__.py
```

### Added (tests)

```
tests/unit/_rules_helpers.py
tests/unit/test_rule_metadata.py
tests/unit/test_rule_evaluation.py
tests/unit/test_rule_base.py
tests/unit/test_rule_registry.py
tests/unit/test_rule_loader.py
```

### Modified (this slice only)

```
app/__init__.py              (bumped __version__ 4.1.0 -> 4.2.0,
                               __phase__ "4.1" -> "4.2")
```

No other product code was modified. Phase 4.1's tests,
ingestion, persistence, and connector layers are untouched and
still pass green.

## 5. Test Results

The full test suite (`pytest tests/`) was executed against the
**real local MongoDB** on `127.0.0.1:27017`:

```
203 unit tests    passed in 1.88s
 18 integration   passed in 3.91s
============================
221 total         passed in 5.79s
```

The 101 new unit tests added in this slice are split as follows.
The deltas shown are the additional FINDING-1/2/3 regression
tests added in this report (see Section 12).

| Test file | Tests | Δ | Coverage |
|---|---:|---:|---|
| `tests/unit/test_rule_metadata.py` | 38 | +1 | Required fields, `rule_id` pattern (positive + 10 negative), version bounds, source / event-type catalogue enforcement, sorted+unique invariants, category-vs-applicability sanity checks, extra-field rejection, frozen invariant, `is_evaluable` / `applies_to_*` / `applicability_signature` (with cross-category uniqueness). |
| `tests/unit/test_rule_evaluation.py` | 10 | 0 | Required fields, type / value validation, timezone-aware datetime, bounded `reasoning` / `extra`, frozen invariant, JSON-safe `to_dict`. |
| `tests/unit/test_rule_base.py` | 14 | +3 | `SimpleRule` positive / negative / reasoner paths, deterministic-evaluation contract, buggy-predicate surfacing as `RuleEvaluationError`, `SimpleRule` refuses cross-source, type-error surfaces, abstract base cannot be instantiated, `make_evaluation` helper, plus FINDING-2 instance-vs-class metadata regression. |
| `tests/unit/test_rule_registry.py` | 34 | +6 | Empty-registry invariants, register / get / list / latest-version, monotonic versioning, duplicate `(id, version)` rejection, idempotent re-registration, non-rule rejection, `enabled+CANDIDATE` rejection, `set_state` promote / demote / unknown / same-state / enum-required, `set_enabled` on approved / candidate-rejection / always-allowed-to-disable / unknown / bool-required / **rejects re-enabling superseded version**, applicability filter (source, event type, candidate exclusion, disabled exclusion, empty input, category filter, enabled filter), concurrency smoke. |
| `tests/unit/test_rule_loader.py` | 15 | 0 | Empty module, `RULES` / `RULE_FACTORIES` discovery, merged-and-sorted, invalid factory, invalid `RULES` entries, non-iterable export, non-module input, `load_rules_from_specs` happy path, input-order independence, missing module, empty / non-string / non-registry spec rejection, abort-on-validation-error. |
| **Total (new in this slice)** | **111** | **+10** | |

### Coverage by concern

* **Positive tests:** minimal construction, full metadata, all
  three categories, both states, both `enabled` values, all
  lookup paths, all list paths, loader happy paths.
* **Negative tests:** every documented rejection gate is
  exercised (unknown source, unknown event_type, malformed
  rule_id, wrong shape, non-callable factory, duplicate
  registration, non-monotonic version, `enabled+CANDIDATE`).
* **Edge cases:** empty registry, empty sources / event_types,
  cross-source with empty event_types, equal-rule `==`
  semantics, frozen-rule mutation, `now` must be
  timezone-aware, oversized reasoning, ordering determinism
  on every list method.
* **Registry-specific:** the candidate / approved / enabled
  triangle is exercised in all three legal configurations and
  in all three illegal configurations.
* **Versioning:** strictly-greater, equal-rejected, lower-
  rejected, idempotent re-registration, duplicate-rejection
  with a different implementation, `latest_version` returned
  by `get(rule_id, version=None)`.
* **Applicability:** per-`(source, event_type)` filtering,
  candidate / disabled / unknown exclusion, empty input
  graceful return, per-category listing, enabled-only
  listing, `applies_to(SecurityEvent)` shortcut.
* **Loader:** module-not-found, malformed exports, factory
  errors, empty spec, non-string spec, non-registry
  argument, abort-on-validation-error.

## 6. Design Decisions (and Why)

* **In-memory only.** The corpus treats the rule registry as
  a logical concept (Section 88). The framework here is
  authoritative for the running process; persistence to a
  Mongo collection is a future slice and does not need to
  change the framework's public surface. The registry is
  thread-safe for reads, serialises mutations, and is
  deterministic on every list path so an eventual
  persistence layer can replay it losslessly.
* **`SimpleRule` is a test-only convenience, not the rule
  DSL.** The corpus explicitly defers the rule expression
  language (the project understanding document Section
  18 marks it OPEN). The framework here defines the
  *interface* (`Rule.evaluate`) and a trivial *helper*
  (`SimpleRule`) for declarative one-liners. Production
  rules will be real `Rule` subclasses; the framework does
  not care how they are built.
* **Pydantic for `RuleMetadata`, frozen dataclass for
  `RuleEvaluation`.** The metadata is the rule's
  authoritative identity; it must be cheap to validate, easy
  to serialise, and impossible to mutate in place. The
  evaluation is a per-event, frequently-allocated record that
  must hash and equality-compare correctly; a frozen
  dataclass is the most direct fit.
* **No `time` in `RuleEvaluation` by default.** The
  `detected_at` field is wall-clock UTC. Tests that need
  determinism pass `now=...`. The production engine will
  eventually pass its own clock to make the test / prod
  boundary explicit.
* **Tags are uppercase tokens, references are free-form.**
  Tags drive future audit / dashboard filters; we constrain
  them to a small uppercase vocabulary. References are
  attributions (MITRE IDs, advisory IDs, internal IDs) and
  must accept whatever the corpus produces; we bound them by
  length and count only.
* **Empty applicability means "not source-bound".** A
  cross-source correlation rule may declare no event_types
  (the correlator owns dispatch, Section 91). The framework
  records this honestly: `applies_to_source(x)` and
  `applies_to_event_type(x)` both return `False` for empty
  applicability, and `applicability_signature()` is `()`.
* **The `enabled implies APPROVED` invariant is enforced in
  three places:** at construction (via the registry
  registration), at `set_enabled`, and at `set_state` (a
  demotion zeroes `enabled`). The triple coverage is
  defensive: each call site is the documented lifecycle
  transition documented in Sections 59 and 89.
* **Re-registration of the same `(rule_id, version)` with a
  different object is `DuplicateRuleError`, not a
  versioning error.** The two error types are distinct in
  the spec (Section 33 vs Section 88) and a future
  persistence layer may want to treat them differently.

## 7. Edge Cases & Negative Tests (Highlights)

* `RuleEvaluation.matched` is `bool`-only; `"yes"` is
  rejected with `TypeError` (no implicit truthy coercion).
* `RuleEvaluation.detected_at` must be timezone-aware; a
  naive `datetime` is rejected with `ValueError`. This
  prevents the documented Phase 3 Section 30 UTC invariant
  from being accidentally broken in a rule.
* `RuleEvaluation.extra` keys must be strings (a tuple of
  `(str, Any)`); the dataclass check rejects non-string keys
  at construction. The framework does NOT inspect `extra`;
  the rule owns its shape.
* `RuleMetadata.extra` is `"forbid"`-denied at the Pydantic
  level so a future field accidentally added by a rule
  author is caught at registration, not at evaluation.
* `SimpleRule` with a `CROSS_SOURCE_CORRELATION` metadata
  raises `ValueError`. The framework refuses to give a
  single-event predicate to a rule that the corpus says
  needs access to multiple events.
* `load_rules_from_specs` raises `RuleValidationError` for
  any spec error. The function processes modules in input
  order and aborts on the first error; the registry is
  left with whatever was registered *before* the error.
  This is the documented Phase 4.2 contract; a future slice
  may add a transactional staging registry.
* `RuleRegistry.set_state(CANDIDATE)` on an APPROVED enabled
  rule **silently resets `enabled` to `False`**. This is
  the documented invariant; demotion must not leave a rule
  that is "enabled but not approved" behind.
* `RuleRegistry.applies_to(event)` returns evaluable rules
  only. CANDIDATE rules, disabled rules, and rules whose
  applicability does not match the event's
  `(source, event_type)` are excluded.
* The documented `rule_id` pattern
  `^([A-Z][A-Z0-9]*|[0-9]+)(-([A-Z][A-Z0-9]*|[0-9]+))*$`
  permits `WAF-001`, `AUTH-BRUTEFORCE-7`, `CORR-WEB-001`,
  `WAF`, and `RATE`; and rejects `waf-001`, `WAF_001`,
  `1WAF`, `-WAF`, `WAF-`, `WAF--001`, `waf`, `WAF 001`,
  empty, and the too-short `x`. Each rejection is covered
  by a parametrised test.

## 8. Deferred (Intentionally Not in This Slice)

* Source-specific rules (WAF, NGINX, IAM, rate-limit,
  network). The `_library/` slots exist; the rules do not.
* Cross-source correlation rules.
* The detection engine (calling `Rule.evaluate` on real
  events, persisting `Detection` records).
* The correlation engine, incident engine, report, routing,
  AI, audit-event persistence, HTTP API, authentication /
  RBAC, object-level authorization, rate limiting.
* Persistence of the rule catalogue to a Mongo collection.
  The registry is in-memory and authoritative for the
  running process; a future slice can persist it without
  changing the framework's public surface.
* The full rule DSL (the corpus marks the rule expression
  language as OPEN; we deliberately do not invent one).
* A real load-time `PROSHIELD_RULE_MODULES` config variable.
  Connector loading is the documented precedent; the rule
  loader is ready to be wired when a future slice needs it.

## 9. Risks and Open Items

* **No production rule.** This is by design. The next slice
  must produce at least one WAF / NGINX / IAM rule (or any
  one of the seven documented categories) and route it
  through the candidate -> approved -> enabled funnel
  before the framework can be exercised end-to-end. The
  framework is the *prerequisite* for that work, not the
  substitute.
* **In-memory state.** A process restart loses the
  registered rules. This is acceptable for Phase 4.2
  because the rule catalogue is small and deterministic
  (it will be re-loaded from disk in production), but a
  future slice must add persistence before the registry is
  expected to survive restarts.
* **Loader abort-on-error behaviour.** The current loader
  leaves the registry with whatever was successfully
  registered before the first error. A future slice may
  want a transactional staging registry; the current
  behaviour is the smallest defensible choice and is
  covered by a regression test.
* **No `now` injection at the framework level.** Rules
  compute their own `detected_at`. The base class's
  `make_evaluation` defaults to `datetime.now()` and
  accepts a `now=` for tests; the production engine will
  pass its own clock.
* **No rule-level metrics.** The future slice will need
  per-rule evaluation counts, match rates, and latencies
  (Section 35). The framework here does not record them;
  adding them is a non-breaking change to the public
  surface.
* **No detection object schema.** The framework returns a
  `RuleEvaluation`; the future detection engine will
  translate that into the documented `Detection` record
  (Section 13, `docs/PHASE 2/DOMAIN_DATA_MODEL.md`
  Section 6). The framework here does not pin that schema
  because the corpus leaves room for the detection slice
  to define it.

## 10. Verification Performed

* `python -m pytest tests/` (full suite) on Windows /
  Python 3.13.3 against the real local MongoDB on
  `127.0.0.1:27017`: **231 / 231 passed in 5.37s** (213
  unit + 18 integration). The 10-test uplift is the
  regression suite for FINDING-1, FINDING-2, and FINDING-3
  (see Section 12).
* `python -m pytest tests/ -m "not integration"` (no
  MongoDB): **213 / 213 passed in 1.73s**.
* `python -m pytest tests/integration/` (real MongoDB):
  **18 / 18 passed in 3.91s** (unchanged from Phase 4.2
  original).
* Manual import check:
  `from app.rules import (RuleRegistry, RuleMetadata,
  RuleCategory, RuleState, Rule, RuleEvaluation,
  SimpleRule, SupersededVersionNotReenablableError,
  load_rules_from_specs, discover_rules_in_module)`
  resolves cleanly.

## 11. Stability

**STABLE**

Phase 4.2 ships a small, dependency-free, deterministic
framework that follows the documented design (DETECTION
ENGINEERING Sections 8, 9, 10, 11, 59, 87-91) and the
documented Rule contract (DOMAIN_DATA_MODEL Section 5). The
framework honours the documented candidate-vs-approved
governance gate, supports monotonic versioning, enforces
source / event-type applicability at registration time, and
provides the efficient applicability filter the future
detection engine will use (DET-04, Section 90).

The 111 new unit tests (101 original + 10 regression for
FINDING-1/2/3) cover all behaviours end-to-end
(positive, negative, edge-case, registry, versioning,
applicability, loader) and pass together with the
unchanged 102 Phase 4.1 tests for a total of 231 / 231
green. No product code outside `app/rules/` and
`app/__init__.py` was modified. No HTTP / DB / connector
behaviour was touched. No new third-party dependencies
were added.

## 12. Independent Review Follow-up (FINDING-1 / 2 / 3 / 4)

The independent review (`docs/PHASE 4/PHASE 4-02/PHASE-04-02-REVIEW.md`)
identified four findings. All four are addressed in this slice
without changing the framework's public surface for rules that
follow the documented patterns.

### 12.1 FINDING-1 (HIGH) — Re-enabling a superseded version is rejected

**Code change.** `app/rules/registry.py` introduces a new
`SupersededVersionNotReenablableError` and adds a check in
`set_enabled`: when `enabled=True` is requested and the
targeted version is not the latest registered for the same
`rule_id`, the registry raises. The check fires only on
the *transition* from disabled to enabled; an already-enabled
superseded version is left as-is (no spurious raise on no-op).
The latest version is always re-enablable, and a sole version
(only one registered for a `rule_id`) is always re-enablable.

**Tests added** (in `tests/unit/test_rule_registry.py`):
* `test_set_enabled_rejects_reenabling_superseded_version`
* `test_set_enabled_latest_version_always_reenablable`
* `test_set_enabled_only_version_can_be_disabled_and_reenabled`
* `test_set_enabled_reenabling_superseded_with_no_op_state`
* `test_set_enabled_reenabling_superseded_error_subclass`
* `test_list_for_event_after_superseded_guard_does_not_include_v1`

All 6 pass.

### 12.2 FINDING-2 (HIGH) — `Rule.metadata` documented as instance attribute

**Code change.** `app/rules/rule.py`: the annotation comment
now reads "subclasses set this as an INSTANCE attribute" and
the class docstring is updated to (a) state that subclasses
MUST expose `metadata` as an instance attribute, and (b) add
a "Subclasses MUST NOT" bullet forbidding class-level
`metadata` unless the subclass guarantees a single shared
frozen metadata that is never mutated. The runtime behaviour
of `set_state` / `set_enabled` was already correct (it
mutates the instance attribute); only the documented contract
needed correcting.

**Tests added** (in `tests/unit/test_rule_base.py`):
* `test_set_state_mutates_rule_instance_metadata_not_class`
* `test_set_enabled_mutates_rule_instance_metadata_not_class`
* `test_rule_metadata_annotation_docstring_requires_instance`

All 3 pass.

### 12.3 FINDING-3 (MEDIUM) — `applicability_signature` encodes `category`

**Code change.** `app/rules/types.py`:
`RuleMetadata.applicability_signature` now includes the
`category.value` as the trailing element of the returned
tuple. Two rules with identical `(sources, event_types)` but
different categories now produce different signatures, so the
signature can safely be used as a cache key in a future
slice. The category is included even for the empty case
(cross-source correlation with no `event_types`), so the
empty-signature collision is also closed.

**Tests added / updated** (in `tests/unit/test_rule_metadata.py`):
* `test_applicability_signature_is_unique_across_categories`
  (new — the cross-category regression)
* `test_applicability_signature_empty_when_missing_either_side`
  (updated — now asserts the correlation-only category
  signature)
* `test_applicability_signature_is_sorted_deterministic`
  (updated — now asserts the trailing category element)

All 3 pass.

### 12.4 FINDING-4 (LOW) — Test count typo in Section 11

**Documentation change.** This report's Section 11 said
"the unchanged 120 Phase 4.1 tests". The actual count is
**102 Phase 4.1 tests**. Updated to "the unchanged 102
Phase 4.1 tests". Section 10's headline numbers updated to
the post-fix totals (231 / 231 in 5.37s).

### 12.5 Test count summary after FINDING fixes

| Test file | Tests (post-fix) | Delta |
|---|---:|---:|
| `tests/unit/test_rule_metadata.py` | 38 | +1 |
| `tests/unit/test_rule_base.py` | 14 | +3 |
| `tests/unit/test_rule_registry.py` | 34 | +6 |
| `tests/unit/test_rule_evaluation.py` | 10 | 0 |
| `tests/unit/test_rule_loader.py` | 15 | 0 |
| Other Phase 4.1 unit tests (untouched) | 102 | 0 |
| **Total unit tests** | **213** | **+10** |
| Integration tests (untouched) | 18 | 0 |
| **Grand total** | **231** | **+10** |

### 12.6 Final verification

```
$ python -m pytest tests/ -m "not integration"
213 passed, 18 deselected in 1.73s
$ python -m pytest tests/
231 passed in 5.37s
```

All FINDING-1 / 2 / 3 regression tests pass; no previously
passing test broke. The framework's public surface
(`RuleRegistry.register / get / set_state / set_enabled / list_* / applies_to`,
`RuleMetadata.applicability_signature`, `Rule.metadata`
annotation) is preserved; the new error class
`SupersededVersionNotReenablableError` is the only additive
public-surface change, exported from `app.rules`.

Phase 4.2 is **STABLE** (post-fix). Phase 4.3 has not been
started.
Phase 4.2 is complete. Phase 4.3 has not been started.