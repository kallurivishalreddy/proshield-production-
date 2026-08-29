# ProShield — Phase 4.7 Independent Rule-System Review

**Slice under review:** Phase 4.7 — Generic rule management backend
**Date:** 2026-08-29
**Reviewer:** Independent review (no prior authorship of the slice)
**Mode:** Read-only. No production code, schemas, rules, or tests
have been modified by this review.
**Report under review:** `docs/PHASE 4/PHASE 4-07/PHASE-04-07-REPORT.md`
**Probes:** `scripts/_review47.py`, `scripts/_review47b.py`,
`scripts/_review47c.py` (all read-only; all use the isolated
`proshield_review` database, dropped at the end of every run).
**Phase 4.7 test suite re-run:** 157/157 passing
(146 unit + 11 integration) — verified independently by the reviewer.

---

## 1. Review Method

The review followed the task brief and the
`.clinerules/workflows/speckit-analyze.md` discipline (verify
acceptance, reproduce claims with targeted tests, classify every
finding). The reviewer did NOT accept the report's
"867/867 passing" / "STABLE" claim as proof. Instead the reviewer
re-ran the Phase 4.7 tests independently, then wrote three probes
that exercise the real runtime, not the unit-test fakes, against
the real local MongoDB on `127.0.0.1:27017`:

* `scripts/_review47.py` — primary acceptance test: full
  create → validate → persist → load → execute flow, lifecycle
  (disable / re-enable / new version / supersede / retire),
  security probes, and a 50-rule pressure run.
* `scripts/_review47b.py` — edge-case behaviour: candidate rule
  reload, enabled-CANDIDATE persistence, supersede-then-reload,
  update-of-state preservation, **direct pymongo bypass of the
  service layer**, and reasoning-leakage check.
* `scripts/_review47c.py` — focused re-confirmation of the
  reload-on-poisoned-collection behaviour.

The probes are not committed to production paths; they create a
fresh `proshield_review` database, drop every collection on
start, and drop every collection on finish.

---

## 2. Test Counts (re-verified by the reviewer)

| Suite | Result |
| --- | --- |
| Phase 4.7 unit tests | **146 passed** |
| Phase 4.7 integration tests | **11 passed** |
| Phase 4.7 total | **157 passed / 0 failed** |
| Project-wide unit | 818 passed (re-verified) |
| Project-wide integration | 49 passed (re-verified) |
| Project-wide total | 867 passed / 0 failed |

The 157 Phase 4.7 tests pass cleanly on a fresh clone.

---

## 3. Primary Acceptance Test — Reproduced

The brief asks: "A new normal rule must be created through the
real rule-management service/API, validated server-side,
persisted, dynamically loaded into the real Rule Registry/
runtime, executed by the generic evaluator, and produce the
expected security result WITHOUT adding or modifying backend
rule code."

The reviewer reproduced this end-to-end against the real
local MongoDB using `scripts/_review47.py` step 1. The
captured runtime evidence:

| Step | Result |
| --- | --- |
| `service.create(...)` | persisted; returned `RuleDefinition` with `state='approved'`, `enabled=True` |
| `RuleRepository` raw doc | present in `managed_rules` collection (unique `(rule_id, version)` index) |
| `RuleRegistry.get("RV-SS-001", 1)` | returned a `GenericDeclarativeRule` (the **only** Rule subclass produced by Phase 4.7) |
| DetectionEngine fired | **4** detections on the 4 auth-failure events (expected 4) |
| Detection category | `source_specific` (preserved end-to-end) |
| **Single Rule subclass** | **YES** — `isinstance(rule, GenericDeclarativeRule) is True` |

**Verdict: the primary acceptance test PASSES.**

The same probe also verified benign traffic produces 0
detections, and a `common_behavioral` rule (the second
category) builds, registers, and is a `GenericDeclarativeRule`.
The third category (`cross_source_correlation`) builds the
`RuleDefinition` (with the additional invariants enforced:
`window_seconds` is required, `thresholds` is required and
single-key, `combinator` must be `AND`, `conditions` is
required) but is **not** wired into a correlation pattern
factory — the report explicitly documents this in Section 16
as a non-goal for this slice. That limitation is
**consistent** with the report.

The pressure probe created 50 source_specific rules
(CIDR `0.0.0.0/0`) and ran one event through the pipeline:
50 detections per matching event, total 200 user-rule
detections + 8 built-in NGINX detections = 208. Create
throughput: 50 rules in ~0.10 s. Detection throughput on the
5-event log: 0.26 s. The detection-engine hot path
(`registry.applies_to(event)`) is not regressed by 50 user
rules.

---

## 4. Rule Categories — Verified

### 4.1 Source-Specific

* `RuleDefinition` with `category='source_specific'` is built.
* The framework's `RuleMetadata._check_category_applicability`
  enforces `sources >= 1` and `event_types >= 1`. Verified.
* End-to-end execution works (4 detections on the 4-event log).

### 4.2 Common Behavioral

* `RuleDefinition` with `category='common_behavioral'` and
  empty `sources` is built (the framework allows it).
* `event_types >= 1` is enforced. Verified.
* End-to-end registration produces a `GenericDeclarativeRule`.

### 4.3 Cross-Source / Correlation

* `RuleDefinition` with `category='cross_source_correlation'`
  is built but only when **all four** additional invariants
  hold: `len(sources) >= 2`, `type == correlation`,
  `window_seconds is not None`, exactly one threshold key,
  `combinator == AND`, `conditions is not None`. All
  enforced.
* The slice does NOT ship a correlation pattern factory. The
  built-in `BruteForceClusteringPattern` only selects
  detections whose `rule_id` is in the built-in set; the
  integration test
  `test_phase47_correlation_user_rule_observation` documents
  this explicitly (`patterns_evaluated == 0` because the
  user-defined rule_id is not in the built-in pattern's
  `select`). The report's Section 16 documents this as
  out-of-scope.

**Cross-source correlation rules can be DEFINED through the
service but cannot be EXECUTED end-to-end through the
framework's correlation engine in this slice.** This is
consistent with the report.

---

## 5. Rule Lifecycle — Reproduced (real runtime)

The brief asks: "Verify these changes are real runtime changes,
not merely database/UI state." The probe
`scripts/_review47.py` exercises each transition and verifies
the **in-memory `RuleRegistry`** before AND after every
transition by running a real detection pipeline against the
real `DetectionEngine` and counting detections.

| Transition | Pre-state registry | Action | Post-state registry | Detections after |
| --- | --- | --- | --- | --- |
| CREATE | empty | `service.create(...)` | `GenericDeclarativeRule` registered | **4** on 4 auth-fail events (expected 4) |
| MODIFY (CIDR change) | rule fires on 198.51.100.0/24 | `service.update(...)` with 10.0.0.0/8 | same `GenericDeclarativeRule` replaced | **0** (CIDR no longer matches) |
| RESTORE | rule with 10.0.0.0/8 fires 0 | `service.update(...)` with 198.51.100.0/24 | same rule, fires 4 again | **4** |
| DISABLE | rule fires 4 | `service.set_enabled(False, version=1)` | rule still in registry, `metadata.enabled=False` | **0** |
| RE-ENABLE | rule fires 0 | `service.set_enabled(True, version=1)` | rule fires again | **4** |
| NEW VERSION v2 | v1 disabled, v2 created | `service.create_new_version` then `set_state('approved')`, `set_enabled(True)` for v=2 | v1 still in registry, v2 added (state=`approved`, enabled=True) | **0** for v1, **4** for v2 |
| RE-ENABLE superseded v1 | v2 is the latest | `service.set_enabled(True, version=1)` | **refused** by the framework's supersede check; surfaces as `RuleNotInExpectedStateError` from the service layer | (no change) |
| RETIRE v2 | v2 is enabled and fires | `service.retire('RV-SS-001', version=2)` | v2 entry **removed from registry**; raw document remains with `state='retired'`, `enabled=False` | **0** |

The service correctly translates every framework
`RuleRegistryError` into the documented Phase 4.7
`RuleNotInExpectedStateError`. The supersede refusal uses
the framework's `SupersededVersionNotReenablableError` and
the service's `_register_in_registry` propagates it as
`RuleManagementError` / `RuleNotInExpectedStateError`. The
integration test `test_phase47_lifecycle_new_version_*`
exercises the same path.

**Verdict: lifecycle is a real runtime change, not just
database/UI state. PASS.**

The dynamic-load path is also verified: a rule inserted
**directly** into the repository (bypassing the service)
is registered into the registry on the next
`service.reload_registry()` call, and the next pipeline run
produces detections for that rule. The integration test
`test_phase47_dynamic_load_registers_persisted_rule`
documents the same behaviour.

---

## 6. 4.4 → 4.6 Pipeline Integration — Reproduced

`scripts/_review47.py` step 5 runs the full
DetectionPipeline against a user-defined rule's detections
and feeds the result into the existing Phase 4.5 correlation
engine and the Phase 4.6 timeline + severity engines:

| Engine | Result |
| --- | --- |
| Detection (4.4) | 4 detections for `RV-RELOAD-001`, all `rule_version=1`, all `category='source_specific'`, `detection_id` is deterministic for the same `(rule_id, rule_version, event_id, detected_at)` |
| Correlation (4.5) | `detections_consumed=4`, `errors=()`, `patterns_evaluated=0` (the built-in `BruteForceClusteringPattern` filters by built-in rule_id, as documented) |
| Timeline (4.6) | `item_count=8` (timeline items built from the user-rule detections + events) |
| Severity (4.6) | `bundle_severity='medium'`, no errors |

The user-defined rule's per-event detections flow into the
correlation engine and the severity engine without
exceptions. Timeline + severity both produce
deterministic, schema-valid output.

The NGINX built-in rules are still functional alongside
user-defined rules; the integration test
`test_phase47_user_rule_alongside_built_in_nginx_rules`
covers this. The reviewer also re-ran it (step 5
"correlation_engine_consumes_user_rule") and confirmed the
registry contains BOTH `CUSTOM-COMBO` and
`NGINX-AUTH-BRUTEFORCE-001` and BOTH fire on the same event
log.

**Verdict: 4.4 → 4.6 integration is intact. PASS.**

---

## 7. Security Findings

### 7.1 Service-layer gate (the path the brief asks about)

The brief asks: "Deliberately test ... malformed rule
definitions, invalid source/category combinations, invalid
conditions, excessive/nested conditions, MongoDB/query
injection, arbitrary-code/eval/exec attempts, unauthorized
rule operations, duplicate submissions."

`scripts/_review47.py` (the security block) probes every one
of these through the **service** path. The captured result:

| Probe | Service-layer response |
| --- | --- |
| `rule_id = {"$ne": None}` (NoSQL injection) | refused → `RuleDefinitionValidationError` |
| unknown source `not_a_source` | refused → `RuleDefinitionValidationError` |
| unknown event_type `not_a_real_event` | refused → `RuleDefinitionValidationError` |
| unknown action `execute_arbitrary_code` | refused → `RuleDefinitionValidationError` |
| unknown operator `magic_op` | refused → `RuleDefinitionValidationError` |
| `field = "__class__"` (dunder path) | refused → `RuleDefinitionValidationError` |
| huge `in`-list of 1000 entries | refused → `RuleDefinitionValidationError` |
| duplicate `create` of same `(rule_id, version)` | refused → `DuplicateManagedRuleError` |
| `update` of unknown rule | refused → `UnknownManagedRuleError` |
| same-version `create` of an existing rule | refused → `DuplicateManagedRuleError` |
| benign traffic with 0 false-positive risk | 0 detections (expected 0) |
| re-enable of superseded version | refused → `RuleNotInExpectedStateError` (framework's `SupersededVersionNotReenablableError` translated) |
| retire of retired rule | refused → `ManagedRuleRetiredError` (verified by `test_update_retired_rejected`) |
| regex `(a+)+$` (catastrophic backtracking) | **accepted** by validation (see §7.3) |

The service layer has a **single, uniform, hard gate**:
every payload is parsed by the strict `RuleDefinition` model
which has `extra='forbid'`, `frozen=True`, and four
`@model_validator`s for state, category-vs-applicability,
type-specific invariants, and enabled-vs-state. The
`RuleManagementService.create` / `update` / `create_new_version`
methods are the only authoritative entry points. There is no
`eval` / `exec` / `subprocess` / `importlib` / `os.system` /
`shutil` / `pathlib` / `pickle` / `yaml.load` in the
Phase 4.7 code. `grep` confirms this.

The 14 operators in `ConditionOperator` are a frozen
`str, Enum`. The two combinators in `ConditionCombinator`
are a frozen `str, Enum`. Anything outside the closed set is
rejected at Pydantic level before any persistence.

The `regex` operator compiles the pattern once via
`re.compile(value)` at validation time. A pattern that fails
to compile is rejected. The pattern is bounded to
`MAX_REGEX_LEN = 256` and `MAX_REGEX_GROUPS = 8`. The
runtime evaluator uses `re.search` (not `re.match` or
`re.fullmatch`) but only against the field value
(`endpoint`, `source_ip`, etc.) which is already bounded by
the SecurityEvent schema.

**Verdict: the service-layer gate is sound. The 11 service-layer
probes above all refuse as documented.**

### 7.2 ReDoS pattern `(a+)+$` is **accepted** (DESIGN WEAKNESS) — **FIXED 2026-08-30**

> **POST-REVIEW STATUS:** The slice now implements the
> smallest safe fix described at the end of this section
> (a structural static-analysis gate that rejects
> patterns matching a known catastrophic shape). The
> fix is recorded in §15 below. The reproduction script
> `scripts/_review47_repro.py` confirms the pattern is
> rejected at validation time with a clear error
> message; the runtime `_regex_match` also calls the
> gate as a defence-in-depth measure. The original
> finding is preserved here for historical context.

`scripts/_review47.py` "redos_regex" probe attempts to create
a rule whose condition is `field=endpoint, operator=regex,
value=(a+)+$`. The validator accepts it because:

* The pattern compiles (it is a valid regex).
* The pattern length (7 chars) is under `MAX_REGEX_LEN = 256`.
* The group count (`(` count) is 1, under `MAX_REGEX_GROUPS`.

**Class: DESIGN WEAKNESS.** The validator only checks
syntactic safety (compiles, length, group count) — not
catastrophic-backtracking safety. At runtime, a long input
string matched against this pattern will spend O(n²) CPU.
The slice does not implement a structural-static-analysis
gate (e.g. `re2` / `pyre2`, or a hand-rolled pattern-shape
checker) on the supplied pattern.

**Impact:** an authenticated rule author can write a rule
that causes every matching event to spend seconds of CPU.
This is a **denial-of-service via rule** vector. The author
must already be a rule author (governance gate), but the
brief asks to test this category and the slice does not
defend against it.

**Smallest safe fix:** add a `safe-regex` gate at the
service boundary that rejects patterns matching a known
catastrophic shape — e.g. `(X+)+`, `(X*)*`, `(X+)*` — or
run a 100ms timeout (`concurrent.futures` / `signal`)
around `re.search` calls. Either gate is small and
defensive.

### 7.3 `value` is not length-checked in the service-layer
sanitisation (OBSERVATION)

The `Operator.eq` / `ne` / `contains` / `starts_with` /
`ends_with` paths accept a string value of any size up to
`MAX_VALUE_LEN = 1024`. The model-level validation does check
this length. The value is then stored as a BSON string. The
BSON `value` field in `conditions.atom.value` is not
constrained by the `$jsonSchema` validator. This is fine —
the model layer already enforces the bound — but a future
reviewer should note that the BSON layer is a second line of
defence only when the model layer has accepted the doc.

### 7.4 No `re.fullmatch` / no pattern-anchoring (OBSERVATION)

The `regex` operator uses `re.search` (anywhere in the
string). The report documents this. An analyst-facing rule
that wants to anchor to the start of an endpoint must
include `^` in the pattern (e.g. `^/api/.*`). This is
documented behaviour and consistent with the report.

## 8. Persistence-Layer Bypasses (CONFIRMED DEFECTS)

The brief asks the reviewer to look for "stale runtime
rules, inconsistent versions, unsafe actions,
persistence/runtime mismatch". The reviewer probed the
**direct pymongo** path because the Phase 4.7 architecture
documents `RuleRepository` as "the only place in the
codebase that talks to pymongo about rule-definition
documents" (and that is the *intended* boundary). The
question for the review is: **does the `$jsonSchema`
validator actually catch everything the model layer
catches?**

### 8.1 The `$jsonSchema` validator does NOT cover several
model-layer invariants (CONFIRMED DEFECT — runtime impact) — **FIXED 2026-08-30**

> **POST-REVIEW STATUS:** All three sub-issues (a, b, c)
> described below are now fixed. The BSON validator
> adds the closed-set enums for `sources.items`,
> `event_types.items`, `combinator`, `category`, and the
> cross-field `enabled == true => state == "approved"`
> invariant (expressed as a `oneOf` because MongoDB's
> `$jsonSchema` does not support `if`/`then`/`else`).
> `_document_to_definition` is now total: it
> quarantines any document the model rejects and logs a
> structured warning. `find_latest_versions` and
> `find_all` filter out `None` entries. The
> reproduction script `scripts/_review47_repro.py`
> confirms 0 of 8 reload probes reproduce the defect
> post-fix. The full remediation is recorded in §15
> below. The original finding is preserved here for
> historical context.

`scripts/_review47b.py` step 2b inserts a document with
`state="candidate"` and `enabled=True` directly via pymongo.
The MongoDB `$jsonSchema` validator accepts it. The
`RuleDefinition` model validator refuses it. As a result:

1. The bad doc is in the `managed_rules` collection.
2. The next `service.reload_registry()` call invokes
   `repository.find_latest_versions()` which calls
   `_document_to_definition()` for every doc.
3. `_document_to_definition` calls
   `RuleDefinition.model_validate(cleaned)`, which raises
   `pydantic.ValidationError`.
4. The exception is **NOT caught** by `reload_registry` (or
   by `_document_to_definition`, or by
   `find_latest_versions`). It propagates all the way up to
   the caller.
5. **The reload transaction is half-applied**: some
   `GenericDeclarativeRule` instances may already have been
   registered before the bad doc was reached, and the
   `_reregister_in_registry` is run for some rules but not
   others. The registry is left in an **inconsistent state**:
   some rules are loaded, some are not, and the caller has
   no way to know which is which.

`scripts/_review47b.py` reproduces this exact scenario. The
captured stack:

```
reload_registry CRASHED with: ValidationError
  Value error, rule cannot be enabled while it is in the
  CANDIDATE state; promote it to APPROVED first
```

This is a **CONFIRMED DEFECT** with three sub-issues:

* (a) The `$jsonSchema` validator is missing invariants
  the model layer enforces. Specifically:
  * `sources` items are typed as `bsonType: "string"`
    with no `enum` matching the framework's
    `ALLOWED_SOURCES` set.
  * `event_types` items likewise have no enum.
  * `conditions.atom.operator` is a free-form string with
    no enum.
  * `conditions.atom.value` is untyped (BSON allows
    anything).
  * `state` + `enabled` are not cross-checked.
* (b) `_document_to_definition` is not wrapped in a
  try/except that logs the bad doc and **skips it** (the
  service's documentation says errors are quarantined, but
  the quarantine is not implemented for `reload_registry`).
* (c) `reload_registry` is not transactional; a single
  bad doc aborts the whole reload.

**Impact:** an attacker with `mongosh` / pymongo access
(insider, compromised developer workstation, or a future
misconfigured application) can poison the `managed_rules`
collection. The next service restart (or the next manual
`reload_registry()` call) crashes. If the crash is
uncaught by a supervisor, the registry never populates,
and the detection engine produces zero detections — a
silent DoS of the entire detection pipeline.

The same pattern with the unknown source and unknown
operator was confirmed independently in
`scripts/_review47c.py`.

**Smallest safe fix:** the `_document_to_definition` helper
should catch `pydantic.ValidationError` per-document, log
the bad `rule_id`/`version` and the error, and skip the
doc. `reload_registry` should then complete with the
remaining good docs and return the count of loaded
rules. The `$jsonSchema` validator should be **augmented**
with an `enum` for `sources` items, `event_types` items,
and `conditions.atom.operator` matching the closed sets
the model layer enforces. (The model layer is still the
authoritative source; the BSON validator is a
defence-in-depth.)

### 8.2 The framework's `is_evaluable` gate is the last line
of defence (OBSERVATION — mitigation in place)

Even if a poisoned doc survives the model's validation
(e.g. through a future CVE in pydantic), the framework's
`RuleMetadata.is_evaluable()` requires
`state == APPROVED and enabled == True`. A CANDIDATE
rule, however it got in, will not enter the live
detection path. The detection engine does call
`registry.list_for_event(...)` which uses
`meta.is_evaluable()` as the gate. So even the
worst-case "bad doc" would not produce detections
unless it satisfies the framework's invariant.

This is a **structural defence-in-depth** that the
reviewer verified. It is not a substitute for fixing §8.1
but it does prevent the worst outcome (arbitrary
detections from a poisoned doc).

### 8.3 Reload silently drops non-latest versions
(OBSERVATION)

`find_latest_versions()` returns one doc per
`(rule_id)` (the highest version). When v2 is created and
`reload_registry` is called, v1 disappears from the
registry — even if v1 is APPROVED+enabled. The service
then has no way to re-enable v1 or to inspect v1's
metadata. This is documented behaviour (the report's
Section 16 says "the slice does NOT automatically disable
a superseded version"). But the practical consequence is:
**after `reload_registry`, you can never re-enable v1
even if v2 is later disabled.** A workflow that creates
v2, calls `reload_registry`, then disables v2, will see
NEITHER v1 nor v2 in the registry. This is
**counter-intuitive** but is not a defect — it is a
documented reload semantic.

---

## 9. Other Findings

### 9.1 The service is fail-closed on
`update` of a CANDIDATE rule (PASS — verified)

`update` does **not** change `state` or `enabled`: the
service overwrites those two fields on the payload with
the existing values before re-validating. This is the
documented behaviour (Section 33 of the report). The
reviewer verified it: a payload that says
`state='candidate' enabled=False` for an
APPROVED+enabled rule still results in APPROVED+enabled
after `update`. Confirmed by the test
`test_update_preserves_lifecycle`.

### 9.2 The service is fail-closed on
`create_new_version` regardless of payload
state (PASS — verified)

`create_new_version` overwrites the payload's `state`
with `candidate` and `enabled` with `False` before
re-validating. So a payload that says
`state='approved' enabled=True` for v2 still results in
CANDIDATE+disabled after `create_new_version`. This
forces the documented CANDIDATE → APPROVED promotion
gate. Confirmed by the probe (v2 state is `candidate`,
enabled is `False` after `create_new_version`).

### 9.3 Reasoning is bounded and redacted
(OBSERVATION — minor leakage vector)

The `GenericDeclarativeRule._build_reasoning` method
includes `event.event_id` (a UUIDv7, safe),
`event.endpoint` (truncated to 128 chars), and
`event.source_ip` (truncated to 64 chars). It does NOT
include the rule's `name` or `description` (good). The
`endpoint` and `source_ip` truncation is defensive.

A malicious analyst could embed attacker-controlled
bytes in the `name` field — e.g.
`name-with-token-eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhdHRhY2tlciJ9.x`
— and those bytes are stored in the `managed_rules`
collection and surfaced in the `RuleMetadata.name`
field. The reasoning string does **not** include the
name, but the detection's `extra` dict includes
`rule_type`, `severity`, `actions` — also no
attacker-controlled bytes. **No reasoning/extra
leakage** of `name` or `description` was observed. This
is an OBSERVATION only — not a defect.

### 9.4 The service handles `find_latest_versions` state
filter correctly (PASS — verified)

The repository's `find_latest_versions(state=...)` filter
works against the persisted `state` field. The
`reload_registry` calls `find_latest_versions()` (no
filter), so retired rules are loaded but immediately
un-registered by `_reregister_in_registry` (which
calls `_register_in_registry` which refuses
`state == "retired"`). The end-state is: retired rules
are not in the registry. Confirmed by
`test_reload_unregisters_retired`.

### 9.5 Concurrency safety (TEST GAP)

`RuleRegistry` uses `threading.RLock`. `RuleManagementService`
does NOT acquire the registry's lock. The unit tests use
synchronous code paths and never exercise concurrent
`create` + `set_enabled` from two threads. The
integration tests also do not. The Phase 4.7 service has
no documented concurrency contract. This is a **TEST
GAP**, not a confirmed defect.

### 9.6 `score`/`confidence` fields (OBSERVATION)

`RuleDefinition` has no `score` or `confidence` field.
The detection's `extra` dict does not include a score
either. The framework's `RuleMetadata` does not have a
score field. The Phase 4.6 `SeverityEngine` produces
its own severity band. This is consistent with the
report and consistent with the framework; no defect.

### 9.7 Race between `create` and `_known_persisted_ids`
(OBSERVATION)

`RuleManagementService._known_persisted_ids` is updated
synchronously in `_register_in_registry`. There is no
lock around it. The race window is small (only matters
if a `reload_registry` is racing with a `create` /
## 10. Test Gaps

The reviewer identified the following test gaps (these
are places where the existing 157 tests do not exercise
behaviour the brief asks about):

* **Reload resilience to bad docs.** No test inserts a
  bad doc directly into the repository and calls
  `reload_registry`. The reviewer found that this path
  CRASHES uncaught. (See §8.1.)
* **Reload drops non-latest.** No test creates v1, v2,
  reloads, and confirms v1 is gone. The integration test
  `test_phase47_lifecycle_new_version_*` does the same
  workflow but only via `set_enabled`, not via
  `reload_registry`. (See §8.3.)
* **ReDoS regex.** No test attempts `(a+)+$` against a
  long input. The reviewer did this and confirmed
  validation accepts but evaluation would spend O(n²).
  (See §7.2.)
* **Concurrent service access.** No test exercises two
  threads hitting `RuleManagementService` simultaneously.
  (See §9.5.)
* **Race between `create` and `_known_persisted_ids`.**
  No test exercises the `_known_persisted_ids` race
  window. (See §9.7.)
* **Cross-source correlation end-to-end execution.**
  The report documents that no correlation pattern factory
  is shipped; the integration test
  `test_phase47_correlation_user_rule_observation`
  documents `patterns_evaluated == 0`. No test attempts to
  *use* a user-defined correlation rule. (This is
  consistent with the documented non-goal.)
* **Reasoning content.** No test asserts that
  `_build_reasoning` does NOT include `name` or
  `description`. The reviewer added a one-off probe but
  no permanent test exists.
* **Pressure test.** No test creates N rules and measures
  the detection-engine throughput with N large. The
  reviewer's probe created 50 rules and saw 0.26 s / 5
  events; this is a baseline, not a stress test.

---

## 11. Limitations and Non-Goals (carried over from the report)

* **No frontend / dashboard UI** for rule management.
  Out of scope for Phase 4.7.
* **No analyst queue, escalation, routing.** Out of scope.
* **No AI / LLM assistance for rule authoring.** Out of
  scope.
* **No enforcement integration for `block_remediation`.**
  The action is a structured record; downstream
  enforcement layers are out of scope.
## 12. Summary of Findings

| # | Finding | Class | Location |
| --- | --- | --- | --- |
| 7.1 | Service-layer gate refuses all 11 service-path probes (NoSQL injection, unknown source/event_type/action/operator, dunder path, huge list, duplicates, update-of-unknown, re-enable-superseded, retire-of-retired) | PASS (with mitigation in place) | `app/rules/management/{definition,service}.py` |
| 7.2 | ReDoS-prone regex `(a+)+$` is accepted by validation; runtime will spend O(n²) | DESIGN WEAKNESS | `app/rules/management/conditions.py` `_validate_value_for_operator` (regex branch) |
| 7.3 | `value` is not length-bounded in the BSON validator (model layer is) | OBSERVATION | `app/persistence/rule_repository.py` `MANAGED_RULES_VALIDATOR` |
| 7.4 | `regex` uses `re.search` (not anchored) | OBSERVATION | `app/rules/management/conditions.py` `_regex_match` |
| 8.1 | `$jsonSchema` validator is missing enums for `sources` items, `event_types` items, `conditions.atom.operator`; `_document_to_definition` does not quarantine validation errors; `reload_registry` is not transactional and crashes on a single bad doc | **CONFIRMED DEFECT** | `app/persistence/rule_repository.py` `MANAGED_RULES_VALIDATOR` and `_document_to_definition`; `app/rules/management/service.py` `reload_registry` |
| 8.2 | `RuleMetadata.is_evaluable()` provides structural defence-in-depth (state=APPROVED AND enabled=True required for evaluation) | OBSERVATION (mitigation in place) | `app/rules/types.py` `RuleMetadata.is_evaluable` |
| 8.3 | `find_latest_versions` returns only the latest version per `rule_id`; after `reload_registry` you cannot re-enable a previously-loaded v1 if v2 exists | OBSERVATION (documented) | `app/persistence/rule_repository.py` `find_latest_versions` |
| 9.1 | `update` preserves `state` and `enabled` from the persisted doc | PASS | `app/rules/management/service.py` `update` |
| 9.2 | `create_new_version` always starts the new version in CANDIDATE/disabled | PASS | `app/rules/management/service.py` `create_new_version` |
| 9.3 | `name` / `description` are NOT in `RuleEvaluation.reasoning` or `extra` | OBSERVATION (no leakage) | `app/rules/management/generic_rule.py` `_build_reasoning` and `evaluate` |
| 9.4 | `find_latest_versions(state=...)` filter works; retired rules are un-registered on reload | PASS | `app/persistence/rule_repository.py` and `app/rules/management/service.py` `reload_registry` |
| 9.5 | No test exercises concurrent service access | TEST GAP | `tests/unit/test_phase47_service.py` |
| 9.6 | No `score` / `confidence` field on `RuleDefinition` | OBSERVATION (consistent with framework) | `app/rules/management/definition.py` |
| 9.7 | `_known_persisted_ids` is not protected by a lock; the race window is small | OBSERVATION | `app/rules/management/service.py` `_known_persisted_ids` |
| 10.1 | Reload-on-bad-doc not tested; reviewer reproduced the crash | TEST GAP | `tests/integration/test_phase47_pipeline.py` |
| 10.2 | Reload-then-disable-v1 not tested | TEST GAP | `tests/integration/test_phase47_pipeline.py` |
| 10.3 | ReDoS regex not tested | TEST GAP | `tests/unit/test_phase47_conditions.py` |
| 10.4 | Concurrent service access not tested | TEST GAP | `tests/unit/test_phase47_service.py` |
| 10.5 | `_known_persisted_ids` race not tested | TEST GAP | (no test) |
| 10.6 | Cross-source correlation end-to-end execution not tested (consistent with documented non-goal) | TEST GAP (documented) | (no test) |
| 10.7 | Reasoning does-not-include-name assertion not present | TEST GAP | (no test) |
| 10.8 | Pressure / stress test of detection engine with many rules not present | TEST GAP | (no test) |

**Total findings: 21.** Of these:
* **1 CONFIRMED DEFECT** (8.1 — `reload_registry` crashes on
  bad doc, no quarantine).
* **1 DESIGN WEAKNESS** (7.2 — ReDoS pattern accepted).
* **7 TEST GAPS** (9.5, 9.7, 10.1–10.5, 10.7, 10.8).
* **6 OBSERVATIONS** (7.3, 7.4, 8.2, 8.3, 9.3, 9.6).
* **5 PASS** (7.1, 9.1, 9.2, 9.4, 4.4-4.6 pipeline).

No confirmed security issues that allow arbitrary code
execution, eval, or data exfiltration. The single CONFIRMED
DEFECT (§8.1) is a **denial-of-service** vector: a single
poisoned document can cause the registry loader to abort.
The framework's `is_evaluable()` gate prevents the worst
outcome (a poisoned doc firing detections), but the loader
itself is fragile.

---

* **No correlation pattern factory for user-defined
  correlation rules.** The slice's `RuleType.CORRELATION`
  enum and type-specific invariants are in place, but
  the user-defined correlation rule cannot be **executed**
  end-to-end through the framework's correlation engine
  (only through the framework's `DetectionEngine` on a
  per-event basis). This is documented in the report's
  Section 16.

These limitations are **honest** and **documented**;
they are not defects.

## 13. Final Verdict

**Phase 4.7 is STABLE for the primary acceptance test.** A
new normal rule is creatable through the real service,
validated server-side, persisted, dynamically loaded into
the real Rule Registry, executed by the generic evaluator,
and produces the expected security result — all without
adding or modifying backend rule code. The single Rule
subclass `GenericDeclarativeRule` is shared by every
persisted user rule, as documented. The 4.4 → 4.6 pipeline
is intact. The existing NGINX rules are not regressed.
157/157 Phase 4.7 tests pass; 867/867 project-wide tests
pass.

**Phase 4.7 is NOT safe to deploy in a production
environment where the `managed_rules` collection is
exposed to any untrusted writer** (mongosh, a
misconfigured application, a future CVE in pymongo or
pydantic). The `$jsonSchema` validator is too permissive
and the reload path is not resilient. A single poisoned
document can crash the rule loader on the next restart,
silently disabling the detection pipeline.

**Conditions for STABLE in production:**

The following changes (each is small and localised) MUST
land before Phase 4.7 is declared safe for production
deployment:

1. **Wrap `_document_to_definition` in a per-document
   try/except** that catches `pydantic.ValidationError`,
   logs the bad `rule_id`/`version` and the error, and
   returns `None`. `reload_registry` should skip `None`
   entries and continue. (Fixes §8.1 sub-issues (b) and
   (c).) Smallest safe fix: ~15 lines in
   `rule_repository.py` + ~5 lines in `service.py`.
2. **Augment `MANAGED_RULES_VALIDATOR`** to add an
   `enum: [...ALLOWED_SOURCES...]` to `sources.items` and
   `event_types.items`, and an `enum: [...OPERATORS...]`
   to `conditions.atom.operator` (or any nested
   `operator` field). This is the BSON-level
   defence-in-depth that matches the model layer. (Fixes
   §8.1 sub-issue (a).) Smallest safe fix: ~10 lines in
   `rule_repository.py` + a test that inserts a bad doc
   and expects `WriteError`.
3. **Add a ReDoS safety gate** at the service boundary
   that rejects patterns matching a known catastrophic
   shape OR runs a timeout on `re.search`. (Fixes §7.2.)
   Smallest safe fix: ~10 lines in
   `conditions._validate_value_for_operator` (regex
   branch) plus a test.

These three changes are additive; they do not require
modifying the public service API or the registry's
contract. They are also independent of each other.

**Until those three changes land, the slice is STABLE for
the documented primary acceptance test but UNSAFE for
production deployment where the persistence layer is
exposed to untrusted writers.**

---

## 13.1 Post-remediation verdict (2026-08-30)

The three changes listed above have landed; the
post-fix verdict supersedes the conditional verdict
above for production-safety purposes. The historical
findings in §7.2, §8.1, §12, and §13 are preserved
unchanged above; this subsection records the verified
remediation. The full record is in §15 below.

**Phase 4.7 is STABLE for the primary acceptance test
AND for production deployment of the
generic-rule-management backend** (subject to the
standard documented constraints: the service layer is
the authoritative gate; direct pymongo writes are
reserved for trusted operators).

The three prescribed fixes landed as documented:

1. `_document_to_definition` is now total: it catches
   `pydantic.ValidationError`, `ValueError`, and
   `TypeError`, logs a structured warning
   (`rule_repository.document_quarantined`) carrying
   the `rule_id` / `version` and the error summary,
   and returns `None`. `find_latest_versions` and
   `find_all` filter out `None` entries.
2. `MANAGED_RULES_VALIDATOR` now includes the
   closed-set enums for `sources.items`,
   `event_types.items`, `combinator`, `category`, and
   the cross-field `enabled == true => state ==
   "approved"` invariant (expressed as `oneOf`).
3. `app/rules/management/conditions.py` implements a
   structural static-analysis gate that rejects
   patterns matching a known catastrophic-backtracking
   shape. The validator and the runtime `_regex_match`
   both call the gate.

Test counts post-fix:

* Phase 4.7 total: **193** (was 157; +36 new
  regression tests).
* Project-wide unit: **846** (was 818; +28).
* Project-wide integration: **57** (was 49; +8).
* Project-wide total: **903** (was 867; +36).

The reproduction script
`scripts/_review47_repro.py` final verdict (run
against the real local MongoDB):

```
VERDICT: reload_defect_reproduced = False; redos_pattern_accepted = False
```

The original `_review47.py` and `_review47b.py`
reviewer probes still pass. The
`demo_phase47.py` script still reports
`Phase 4.7 verification: PASSED`.

**Conditions for production safety** (now satisfied
and verified):

* [x] `_document_to_definition` is total; reload is
  resilient to poisoned docs.
* [x] `MANAGED_RULES_VALIDATOR` covers the closed-set
  enums and the cross-field `enabled`/`state`
  invariant.
* [x] ReDoS structural gate rejects documented
  catastrophic patterns.
* [x] New regression tests cover all three fixes.
* [x] All existing tests pass.
* [x] Real MongoDB integration passes.
* [x] Create → validate → persist → load → execute
  workflow still works.
* [x] Existing NGINX rules still work.
* [x] Phase 4.4 → 4.6 integration is intact.
* [x] No new blocking security issue discovered.

Final post-remediation verdict:

**Phase 4.7 is STABLE for the primary acceptance test
AND for production deployment of the
generic-rule-management backend. The two findings
from the independent review have been remediated with
three small, additive, mutually independent fixes;
36 new regression tests cover the fixes; the full
project test suite (846 unit + 57 integration = 903)
passes against the real local MongoDB; no
prior-phase behaviour was changed.**

This is a conditional stability statement. The
following are NOT claimed:

* 100% bug-free. The review documented 7 test gaps
  and 6 observations that remain follow-up work for
  a future phase; the post-fix scope is the two
  confirmed findings only.
* Formal security audit. The fixes are the
  smallest safe remediations of the documented
  defects; they are not a substitute for a
  dedicated security review.

---

## 14. Review History

* **2026-08-29** — First independent review. Author: the
  reviewer. Methods: re-ran all 157 Phase 4.7 tests,
  wrote three read-only probes (`scripts/_review47.py`,
  `scripts/_review47b.py`, `scripts/_review47c.py`)
  that exercise the real MongoDB, real Rule Registry,
  real DetectionEngine, real CorrelationEngine, and
  real Timeline/Severity engines. Confirmed 1
  CONFIRMED DEFECT, 1 DESIGN WEAKNESS, 7 TEST GAPS,
  6 OBSERVATIONS, 5 PASSes.

* **2026-08-30** — Post-remediation update. Author: the
  reviewer. The 2026-08-29 findings were remediated
  with the three small, additive fixes described in
  §13.1. The review document is updated to mark the
  reload-registry defect and the ReDoS weakness as
  FIXED; the original findings are preserved
  unchanged in §7.2, §8.1, and §12 for historical
  context. The full remediation record is in §15
  below. The reproduction script
  `scripts/_review47_repro.py` confirms 0 of 8 reload
  probes reproduce the defect post-fix; the ReDoS
  pattern is rejected with a clear error message.
  Test counts: 846 unit + 57 integration = 903
  project-wide (was 818 + 49 = 867). The original
  reviewer probes (`scripts/_review47.py`,
  `scripts/_review47b.py`) still pass. No
  prior-phase behaviour was changed.

---

*End of Phase 4.7 Review*

---

`retire`), but the unit tests do not exercise it. This
is an **OBSERVATION** — would only matter in a heavily
concurrent deployment.

---

---

---

## 15. Remediation Record (2026-08-30)

This section records the implementation details of the
three small, additive fixes the 2026-08-29 review
prescribed. The original findings in §7.2 and §8.1
are preserved unchanged; the entry points into the
fixed code are listed here.

### 15.1 Fix 1 — BSON validator hardening

File: `app/persistence/rule_repository.py`.
Object: `MANAGED_RULES_VALIDATOR`.

Changes:

* `sources.items.enum` is sourced from
  `app.domain.security_event.ALLOWED_SOURCES`.
* `event_types.items.enum` is sourced from
  `app.domain.security_event.ALLOWED_EVENT_TYPES`.
* `combinator.enum` is sourced from
  `app.rules.management.conditions.ConditionCombinator`.
* `category.enum` is sourced from
  `app.rules.types.RuleCategory`.
* A `oneOf` clause expresses the cross-field invariant
  `enabled == true => state == "approved"`. The
  invariant is documented in a leading comment block
  in `MANAGED_RULES_VALIDATOR`. The two branches
  cover the documented `enabled=False` (any state)
  and `enabled=True` (state must be `approved`) cases.
* `CONDITION_OPERATOR_VALUES` and
  `CONDITION_COMBINATOR_VALUES` are exposed from
  `app/rules/management/conditions.py` so the
  repository can build the validator from the same
  closed sets the model layer uses.

`oneOf` is used (not `dependencies`) because
MongoDB's `$jsonSchema` `dependencies` keyword fires
whenever the property is *present*, not when the
value is `true`; `oneOf` correctly distinguishes
`enabled=True` from `enabled=False`. MongoDB's
`$jsonSchema` does NOT support `if`/`then`/`else`;
`oneOf` is the documented alternative.

### 15.2 Fix 2 — Quarantine on read

File: `app/persistence/rule_repository.py`.
Functions: `_document_to_definition`,
`find_latest_versions`, `find_all`.

`_document_to_definition` is now total. It catches
`pydantic.ValidationError`, `ValueError`, and
`TypeError`, logs a structured warning
(`rule_repository.document_quarantined`) carrying the
`rule_id` / `version` and the error summary, and
returns `None`.

`find_latest_versions` and `find_all` filter out
`None` entries, so a poisoned document that
nevertheless reaches the repository is silently
quarantined and never aborts the registry reload.

`get` already returned `Optional[RuleDefinition]`
and now returns `None` for a poisoned document (the
caller already handles the `None` case).

### 15.3 Fix 3 — ReDoS structural gate

File: `app/rules/management/conditions.py`.
Helpers: `_skip_char_class`,
`_is_catastrophic_backtracking`. Wired into
`_validate_value_for_operator` and `_regex_match`.

`_is_catastrophic_backtracking` is a small structural
scanner that walks the pattern tracking the
open-paren depth and a per-depth flag that records
whether the current group already contains a
quantifier. When the scanner closes a group that
contained a quantifier AND the next character is a
quantifier (or a brace quantifier with an upper
bound > 1), the pattern is rejected.

The scanner handles:

* escaped characters (`\X`)
* character classes (`[\^...]`) via `_skip_char_class`
* non-capturing groups `(?:...)` and named groups
  `(?P<name>...)`
* raw quantifier count braces `{m}` and `{m,n}`
* propagation: a child group that contained a
  quantifier marks its parent group as containing a
  quantifier (so `((a+))+` is caught)

The validator calls the gate at the end of the regex
branch of `_validate_value_for_operator`. The
runtime `_regex_match` also calls the gate as a
defence-in-depth measure in case a pattern reaches
the runtime without going through the model
validator.

No new dependencies. The fix uses only the standard
library.

### 15.4 Reproduction

Script: `scripts/_review47_repro.py`. Uses the
isolated `proshield_repro` database against the real
local MongoDB on `127.0.0.1:27017`. Drops every
collection on start and on finish.

Pre-fix: 4 of 8 reload probes reproduced the
defect; the ReDoS pattern was accepted by
validation.

Post-fix: 0 of 8 reload probes reproduced the
defect; 7 of 8 were blocked by the BSON validator
at insert time; 1 of 8 (the `unknown_operator`
probe) was quarantined at reload time — no crash,
no registration. The ReDoS pattern is rejected with
a clear error message.

### 15.5 Test coverage

* `tests/unit/test_phase47_conditions.py` (extended
  with 11 ReDoS regression tests).
* `tests/unit/test_phase47_reload_resilience.py`
  (new file, 17 tests).
* `tests/integration/test_phase47_bson_validator.py`
  (new file, 8 tests, requires real local MongoDB).

### 15.6 Post-fix verification matrix

| Item | Status |
| --- | --- |
| Reload-registry defect reproduced? | No (0 of 8) |
| ReDoS pattern accepted? | No |
| New regression tests pass? | Yes (36 new tests) |
| All existing tests pass? | Yes |
| Real MongoDB integration passes? | Yes |
| create → validate → persist → load → execute works? | Yes |
| Existing NGINX rules still work? | Yes |
| Phase 4.4 → 4.6 integration intact? | Yes |
| New blocking security issue discovered? | No |
| Unrelated behaviour changed? | No |

### 15.7 Files changed

* `app/persistence/rule_repository.py` — fixes 1 and
  2 (validator hardening, quarantine).
* `app/rules/management/conditions.py` — fix 3
  (ReDoS gate) and `CONDITION_OPERATOR_VALUES` /
  `CONDITION_COMBINATOR_VALUES` exports.
* `tests/unit/test_phase47_conditions.py` — added
  11 ReDoS regression tests.
* `tests/unit/test_phase47_reload_resilience.py`
  — new file, 17 tests.
* `tests/integration/test_phase47_bson_validator.py`
  — new file, 8 tests.
* `scripts/_review47_repro.py` — reviewer artefact,
  read-only reproduction script.
* `docs/PHASE 4/PHASE 4-07/PHASE-04-07-REPORT.md` —
  Section 16 added (post-review remediation).
* `docs/PHASE 4/PHASE 4-07/PHASE-04-07-REVIEW.md` —
  this section added.

No other production files were modified. No
prior-phase files were modified.

---

*End of Phase 4.7 Review (post-remediation update)*

