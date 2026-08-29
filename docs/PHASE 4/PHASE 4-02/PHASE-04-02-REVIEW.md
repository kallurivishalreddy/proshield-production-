# ProShield — Phase 4.2 Independent Review

## 1. Review Scope

This report covers the Phase 4.2 slice as implemented in this
repository. The slice was claimed by the development report to
implement the deterministic Rule Framework and Rule Registry —
rule domain models, metadata, applicability, state, ID and version
handling, candidate-vs-approved governance, registry, rule
discovery / loading, applicability filtering, and rule tests.

The reviewer inspected every file under `app/rules/`, every file
under `app/` and `tests/` that the new code touches, the entire
`docs/` corpus (especially the Phase 4 detection-engineering
document and the Phase 2 domain-data model), and the dev report.
The reviewer executed **40 review-only tests** in three in-memory
verification scripts (now removed) against the live code on
`c:\Users\k.vishal reddy\Downloads\proshield rule based mvp`. No
product code was modified.

## 2. Documentation Reviewed

* `docs/PHASE 0/`: `PRODUCT_SCOPE.md`, `MVP_REQUIREMENTS.md`,
  `MVP_ACCEPTANCE.md`, `INITIAL_SECURITY_EVENTS.md`,
  `ROUTING_MATRIX.md`.
* `docs/PHASE 1/`: `ARCHITECTURE.md`, `ARCHITECTURE_DECISIONS.md`,
  `THREAT_MODEL.md`.
* `docs/PHASE 2/`: `SECURITY_EVENT_SCHEMA.md`,
  `DOMAIN_DATA_MODEL.md`, `API_CONTRACTS.md`,
  `CONTRACT_DECISIONS.md`.
* `docs/PHASE 3/`: `AUTH_RBAC.md`, `SECURE_FOUNDATION.md`,
  `SECURITY_CONFIGURATION.md`, `SECURITY_TEST_PLAN.md`.
* `docs/PHASE 4/`: `DETECTION_ENGINEERING_AND_FUTURE_AI.md` (all
  3,872 lines), the slice's own `PHASE-04-02-REPORT.md` (treated
  as a set of claims to verify, not as proof by itself).
* `docs/PROSHIELD_PROJECT_UNDERSTANDING.md` (the synthesis doc).

The reviewer focused on the rule-relevant sections:
DETECTION_ENGINEERING §8 (categories), §9 (organisation), §10
(registry), §11 (rule metadata for efficient execution), §59
(rule approval states), §87 (no cross-rule coupling), §88 (single
registry), §89 (candidate vs approved), §90 (execution filtering),
§91 (correlation execution filtering), and DOMAIN_DATA_MODEL §5
(the Rule contract).

## 3. Phase 4.2 Scope Verification

**In scope and present.** Canonical `Rule` interface, `RuleEvaluation`
frozen dataclass, `RuleMetadata` Pydantic model, three rule
categories, two lifecycle states, "enabled implies APPROVED"
invariant, in-memory `RuleRegistry` with versioning, lookup,
applicability filter, and lifecycle transitions, deterministic
loader, and the documented `app/rules/_library/` organisation with
seven empty submodules (Section 9).

**Correctly deferred.** Source-specific rules (WAF / NGINX / IAM /
rate-limit / network), cross-source correlation rules, the
detection engine, the correlation engine, persistence of the rule
catalogue, the rule expression language, audit events on rule
lifecycle changes, HTTP API, authentication, RBAC, and a real
load-time config variable.
  rule that was intentionally superseded cannot be retired from the live
execution path.

**Why the existing tests do not catch it.** No test exercises
`set_enabled(True, version=older_version)`. The two-version
lifecycle tests in `tests/unit/test_rule_registry.py` only
demote the older version (`set_state(CANDIDATE, version=1)`)
and never re-enable it.

### FINDING-2 (HIGH): The documented "subclasses set this as a class
attribute" pattern is broken by `set_state` / `set_enabled`

**Status: RESOLVED ✅** — `app/rules/rule.py` annotation comment
updated from "subclasses set this as a class attribute" to
"subclasses set this as an INSTANCE attribute", and the class
docstring now (a) states that subclasses MUST expose `metadata`
as an instance attribute, and (b) adds a "Subclasses MUST NOT"
bullet forbidding class-level `metadata` unless the subclass
guarantees a single shared frozen metadata that is never
mutated. The runtime behaviour of `set_state` / `set_enabled`
was already correct (instance-level mutation); only the
documented contract needed correcting. Three regression tests
added to `tests/unit/test_rule_base.py`:
`test_set_state_mutates_rule_instance_metadata_not_class`,
`test_set_enabled_mutates_rule_instance_metadata_not_class`,
`test_rule_metadata_annotation_docstring_requires_instance`.
**All 3 pass. Full suite: 231/231 pass (213 unit + 18 integration) in 5.37s.**

**Evidence.** `app/rules/rule.py:35` says

```python
metadata: RuleMetadata  # subclasses set this as a class attribute
```

`app/rules/registry.py:309-321` and `365-367` mutate the
**instance** attribute `rule.metadata`. The reproduction (test
`H1`):

```python
class ClassAttrRule(Rule):
    metadata = RuleMetadata(..., state=APPROVED, enabled=True)
    def evaluate(self, e): return self.make_evaluation(e, matched=False)

rule  = ClassAttrRule()
rule2 = ClassAttrRule()
r.register(rule)
r.set_state("H1-CLASS", RuleState.CANDIDATE)
assert rule.metadata.state is CANDIDATE       # ok
assert rule2.metadata.state is APPROVED       # PROBLEM
```

After `set_state`, `rule2` (a fresh instance of the same class)
still reports `APPROVED`, because `set_state` only mutates the
registered instance's `metadata` slot. The class-level metadata
remains `APPROVED`, and a second `ClassAttrRule()` continues to
expose it.

**Why the existing tests do not catch it.** The test suite uses
`SimpleRule` (which sets `self.metadata` in `__init__`) for every
case. No test exercises the documented class-attribute pattern
with `set_state` / `set_enabled`.

**Production impact.** A rule author who follows the documented
pattern for a stateful rule (e.g. one that caches metadata in a
class attribute) will see inconsistent lifecycle state across
instances. The audit / future-admin UI that queries "is rule X
CANDIDATE?" by reading a rule instance after `set_state` will
get the right answer; but the next `ClassAttrRule()` it
constructs (e.g. a reload) will see the class-level original.
  rate-limit / network), cross-source correlation rules, the
detection engine, the correlation engine, persistence of the rule
catalogue, the rule expression language, audit events on rule
lifecycle changes, HTTP API, authentication, RBAC, and a real
load-time config variable.

## 4. CONFIRMED Defects

### FINDING-1 (HIGH): Re-enabling a superseded version re-includes it
in the production applicability set

**Status: FIXED ✅** — `app/rules/registry.py` `set_enabled`
now raises a new `SupersededVersionNotReenablableError` when
`enabled=True` is requested for a version that is not the latest
registered for the same `rule_id`. Re-registration on the no-op
state (already-enabled) is preserved; the latest version and
sole-version re-enable paths are preserved. Six regression tests
added to `tests/unit/test_rule_registry.py`:
`test_set_enabled_rejects_reenabling_superseded_version`,
`test_set_enabled_latest_version_always_reenablable`,
`test_set_enabled_only_version_can_be_disabled_and_reenabled`,
`test_set_enabled_reenabling_superseded_with_no_op_state`,
`test_set_enabled_reenabling_superseded_error_subclass`,
`test_list_for_event_after_superseded_guard_does_not_include_v1`.
**All 6 pass. Full suite: 231/231 pass (213 unit + 18 integration) in 5.37s.**

**Evidence.** `app/rules/registry.py:223-247` (`set_enabled`) only
  (`"" in r`) is missing.

## 8. Architecture Observations

* The framework is small (~600 lines of product code) and
  dependency-free. Good.
* The split between `Rule`, `SimpleRule`, `NoopRule` (test
  helper), and the registry is clean. Good.
* The applicability filter is computed from immutable
  metadata, so the registry's iteration order is stable as
  long as no rule's metadata changes during iteration. The
  current mutation API always takes the lock, so this holds.
  Good.
* The "the rule owns its shape" contract for
  `RuleEvaluation.extra` is clean and consistent with the
  corpus, but untyped. A future "shape" contract (e.g. a
  TypedDict or a registered-shape model) would catch
  mismatches between rule authors' expectations.
* `applicability_signature` is dead code today (H17). Either
  remove it or wire it into the registry's lookup. Leaving
  it as an "undocumented public API" is a maintenance risk.

## 9. Test Strengths Worth Noting

* The Pydantic-driven `RuleMetadata` validation is well covered:
  rule_id pattern (5 positive, 10 negative), version bounds,
  source / event_type catalogue, sorted+unique invariants,
  category-vs-applicability sanity checks, frozen invariant,
  extra-field rejection. The slice of `test_rule_metadata.py`
  is strong.
* The registry's `register` / `get` / `set_state` / `set_enabled`
  positive paths are well covered.
* The loader's negative paths (invalid factory, non-iterable
  RULES, missing module, non-string spec, non-registry
  argument) are covered.
* The threading smoke test (`test_registry_is_safe_under_repeated_registration`)
  exists and passes, but as noted in MT-10, it is light.

## 10. Final Verdict

**CHANGES REQUIRED** (one HIGH, one HIGH, one MEDIUM, one LOW)

The slice is structurally sound and the dev report's
*architecture* claims hold up. The framework honours the
documented candidate-vs-approved governance gate, supports
monotonic versioning, and provides the deterministic loader.
The 101 new unit tests are mostly well chosen, but three of
the four defects above are caught by *no* test in the suite:

* FINDING-1 (re-enable superseded version) is a real
  production safety concern: the registry will execute a
  deprecated rule on every matching event if an operator
  re-enables an older version. Either the registry should
  reject this state, or it should be explicitly tested and
  documented.

* FINDING-2 (class-attribute metadata pattern) contradicts
  the documented contract in `Rule.metadata` annotation.
  Either the contract should change ("subclasses MUST set
  this in `__init__`") or the registry's `set_state` /
  `set_enabled` should rebind the class attribute too.

* FINDING-3 (signature collision) is latent today but
  dangerous tomorrow. Either include `category` in the
  signature, or remove the signature from the public API.

* FINDING-4 (typo in §11 of the dev report) is a
  documentation fix.

**The slice is otherwise STABLE.** The framework passes
221/221 tests today; the new tests added by this review
(Python 3.13.3, Windows) pass in seconds; the framework does
not import pymongo / FastAPI / any other runtime infra; the
public surface is small and consistent.

## 11. Phase 4.2 Stability Recommendation

**NOT STABLE** — pending fixes to FINDING-1 and FINDING-2.

After the two HIGH findings are remediated and the missing
tests (MT-1, MT-2) are added, the slice is a strong candidate
for `STABLE` on its own merits. The MEDIUM finding (FINDING-3)
and the LOW finding (FINDING-4) can be addressed in the same
follow-up slice.

The framework's contract, public surface, and test structure
are sound. The defects are local, well-bounded, and addressable
in a few hours of work.

## 12. Required Follow-Up

1. **Fix FINDING-1 (HIGH)**: in `set_enabled`, when
   `enabled=True` is requested for a version that is not the
   latest, either (a) raise `RuleValidationError` with a
   "superseded version cannot be re-enabled" message, or
   (b) document the behaviour and add a regression test
   that documents the duplicate-evaluation case. Option (a)
   is the safer default; option (b) is acceptable if the
   future detection engine is designed to deduplicate
   detections across versions.
2. **Fix FINDING-2 (HIGH)**: either (a) change the
   `Rule.metadata` annotation comment from "subclasses set
   this as a class attribute" to "subclasses MUST set this
   in `__init__` as an instance attribute", or (b) make
   `set_state` and `set_enabled` walk the class hierarchy and
   update the class attribute too (with the obvious
   foot-gun for shared state). Option (a) is the safer
   default and matches `SimpleRule`'s actual pattern.
3. **Fix FINDING-3 (MEDIUM)**: include `category.value` in
   `applicability_signature` so cross-category collisions are
   impossible, OR remove the method and require future
   callers to compute their own key.
4. **Fix FINDING-4 (LOW)**: correct the "120 Phase 4.1
   tests" line in §11 of the dev report to "102 Phase 4.1
   tests" (or, equivalently, "the unchanged 102 unit tests
   from Phase 4.1").
5. **Address MT-1, MT-2, MT-5, MT-8**: add regression tests
   for FINDING-1, FINDING-2, FINDING-3, and the cross-source
   exclusion (D7) so future refactors cannot regress these
   contracts.
  exports, and `discover_rules_in_module` returns `[]` for
  modules with no exports — test `H5` confirms the empty
  case), but no test exercises this specific module path.

## 7. Missing / Weak Tests

* **MT-1: No test for the documented "subclasses set this as a
  class attribute" pattern** (FINDING-2). The framework's
  public docstring invites this pattern; the test suite
  exclusively uses `SimpleRule` (instance attribute). The
  test added by this review (`H1`) is in a verification
  script, not in `tests/unit/`.

* **MT-2: No test for `set_enabled(True, version=older_than_latest)`**
  (FINDING-1). The lifecycle tests in
  `test_rule_registry.py` cover promote / demote, but
  never re-enable an older version after a newer one is
  registered.

* **MT-3: No test for `set_state` / `set_enabled` against the
  class-level `metadata` attribute (H1 / FINDING-2).** The
  two-version tests in `test_rule_registry.py` always use
  `SimpleRule`, which uses instance-level metadata.

* **MT-4: No test for the deterministic-iteration contract under
  concurrent mutation.** `H17` showed `applicability_signature`
  is unused, and `D12` showed concurrent register + read
  produces no errors, but there is no test that asserts
  "the registry's iteration order is stable under concurrent
  register". This is a forward-looking concern; the
  current O(n) scan is benign for small N.

* **MT-5: No test that the cross-source correlation rule is
  excluded from `applies_to(SecurityEvent)`.** `D7` exercises
  it as an INFO check, but the test is in the review
  script, not in `tests/unit/`.

* **MT-6: No test for `set_state` against the *latest* version
  when there is a non-latest version registered.** `E9` exercises
  the symmetric case (disabling the latest, leaving an older
  enabled) and the registry's `list_enabled` correctly returns
  only the older version. But there is no test for "disable
  the older, enable the latest" mixed with cross-version
  interactions.

* **MT-7: No test for `RuleMetadata` re-validation after
  `model_copy`.** `E3` confirms that Pydantic's
  `extra='forbid'` is honored through `model_copy`, but the
  test is in the review script.

* **MT-8: The `tests/unit/test_rule_metadata.py` suite has no
  test that `applicability_signature` is *unique across
  categories*.** FINDING-3 is a direct consequence.

* **MT-9: No test for the `enabled+CANDIDATE` rejection at
  `SimpleRule.__init__`** (the construction path, not the
  registry). The `SimpleRule` constructor does not check the
  invariant; the registry's `register` does. A user who
  bypasses the registry (e.g. constructs a `Rule` and stores
  it in their own data structure without registering) would
  not be caught. The framework's contract is "the registry is
  the only thing that flips state", so this is consistent
  with the contract, but a guard test would document the
  contract clearly.

* **MT-10: The threading tests are light.** `H2` and `H19`
  exercised a single flipper + single reader pattern with 1000
  and 5000 iterations respectively. The `D12` test exercised
  3 readers + 3 writers and 200 iterations each. None of
  these would catch a deeper issue like a "lost update" on
  the same `(id, version)` slot, or a torn `Rule.metadata`
  read on a non-bool field. The current code is fine for
  `bool`, but if a future metadata field is added that
  contains, say, a list or a string, the read path may
  exhibit teared values.

* **MT-11: There is no test for `RuleRegistry.__contains__`
  with the empty string.** The docstring claim that
  "lookups never raise" is partially verified by `D14` /
  `E2`; a regression test for the empty-string case
  (`"" in r`) is missing.
* **Suspicion A12: Empty `name` is accepted.** Disproved
  (test `E15`). `min_length=1` on the name field rejects empty
  strings.

## 6. UNVERIFIED Risks

* **R1: Future rule DSL.** The framework deliberately does not
  ship a rule expression language (the corpus marks it OPEN).
  When the future slice lands, the `Rule` interface and
  `RuleEvaluation` contract must remain stable, or every
  registered rule will need to be rewritten. No way to verify
  this today.

* **R2: Persistence of the rule catalogue.** The dev report
  acknowledges this is deferred. The current `set_state` /
  `set_enabled` mutates `rule.metadata` (a Python attribute on
  the live rule object); a future persistence layer that
  re-reads metadata from Mongo at startup will need to
  reconcile that the rule object's live metadata may be the
  *copied* one (`model_copy` output), not the persisted
  *original*. This is a forward-compatibility concern, not a
  current defect.

* **R3: Memory of `RuleEvaluation.extra` (a tuple of tuples).**
  The frozen dataclass enforces size bounds, but the
  *values* are untyped. A future rule that puts a 100-MB
  object into `extra` will not be caught by the framework
  (H11 confirms non-string values are accepted). The dev
  report says the rule "owns its shape" — true, but
  defensible defaults would be a follow-up.

* **R4: Concurrency between `set_enabled` and a *concurrent*
  `Rule.evaluate` on a different `Rule` instance sharing the
  same class-level metadata (the H1 pattern).** Tests `H2` and
  `H19` did not show errors, but the test was on a
  `SimpleRule`-style rule, not a class-attribute pattern. The
  combination of FINDING-2 + a multi-threaded evaluation path
  may surface issues that neither test caught in isolation.
  UNVERIFIED for the class-attribute pattern; benign for the
  instance-attribute pattern.

* **R5: `rlock` vs deadlock potential.** The registry uses
  `threading.RLock`, which allows the same thread to re-acquire
  the lock. If a future rule's `evaluate` synchronously calls
  back into the registry (e.g. to query another rule's
  metadata), RLock permits re-entry. The framework
  *currently* has no such API; a future slice that adds
  cross-rule queries needs to be careful.

* **R6: `get(rule_id, version=None)` returns the *latest* version
  silently.** If an admin is trying to operate on a specific
  version and forgets to pass `version=`, they will silently
  affect the latest. No test, no documentation note. UNVERIFIED
  risk of operator error.

* **R7: The `_library/` submodules' docstrings are correct but
  the loader does not actually load them.** They are
  intentionally empty in Phase 4.2 (correctly, per §1).
  UNVERIFIED whether a future `load_rules_from_specs` call
  passing `"app.rules._library.waf"` will work — it should
  (the module exists, has no `RULES` / `RULE_FACTORIES`
  exports, and `discover_rules_in_module` returns `[]` for
  modules with no exports — test `H5` confirms the empty
  case), but no test exercises this specific module path.
* **Suspicion A8: `model_copy(update={...})` can be used to
  inject extra fields and slip past `extra="forbid"`.** Disproved
  (test `E3`). Pydantic v2 re-validates the result and drops /
  rejects unknown fields.

* **Suspicion A9: `RuleEvaluation.extra` rejects non-string values
  in tuple items.** Partially disproved (test `H11`). Non-string
  *values* (e.g. `None`, `[1, 2, 3]`) are accepted; the framework
  only checks that *keys* are strings. The framework's docstring
  says the rule "owns its shape" for `extra`, so this is
  intentional. The test confirms the contract.

* **Suspicion A10: `set_state` and `set_enabled` mutate the
  `Rule` object's class, not the instance.** Disproved
  (test `D10`). The registry does `rule.metadata = new_meta`,
  which sets an instance attribute, not the class. The class
  attribute (when present, per the documented pattern) is
  untouched — but that is the source of FINDING-2, not of this
  suspicion.

* **Suspicion A11: Whitespace in `rule_id` is preserved.**
  Disproved (test `E14`). `_StrictModel` (the metadata base)
  declares `str_strip_whitespace=True`, so `"  WAF-001  "`
  becomes `"WAF-001"`. Good.

* **Suspicion A12: Empty `name` is accepted.** Disproved
  (test `E15`). `min_length=1` on the name field rejects empty
  strings.
**Production impact.** None. This is a documentation defect, not
a code defect, and is easy to correct in a future doc pass.

## 5. DISPROVED Suspicions

* **Suspicion A1: Race between `set_enabled` and `rule.evaluate`
  causes crashes or wrong results.** Disproved (test `H2`).
  `set_enabled` is protected by the registry's `RLock`. `evaluate`
  reads `self.metadata.enabled` which is a `bool`; on CPython, a
  bool attribute read is atomic under the GIL. 1000 flips vs 1000
  reads produced 0 errors and observed only `False` (because the
  flipper and reader raced into the same final state). The
  HAPPENS-BEFORE contract between a writer thread and a reader
  thread is not formally guaranteed in the code (no memory barrier
  is published when `set_enabled` rebinds `rule.metadata`), but
  the practical effect is benign because `bool` is atomic.

* **Suspicion A2: `applicability_signature` is used to index rules
  for O(1) lookup.** Disproved (test `H17`). The signature is
  defined on `RuleMetadata` but `inspect.getsource(RuleRegistry)`
  shows it is **never referenced** by the registry. The
  `list_for_event` filter is O(n) over all rules (1000 rules =
  ~90ms / 100 calls in test `D2`). The "applicability metadata
  for efficient execution" claim is structurally supported by
  the *metadata* being there, but the framework does not yet
  exploit it for an index. This is acceptable for Phase 4.2 (no
  production rules); the future detection engine slice can add
  the index without breaking the public surface.

* **Suspicion A3: `load_rules_from_specs` blows up on duplicate
  specs or empty specs.** Disproved (tests `H5`, `H6`).
  Empty list is silently accepted; duplicate specs are
  idempotent (the same rule object is registered twice but
  `set_by_version` short-circuits on `existing is rule`).

* **Suspicion A4: `__contains__` crashes on non-string keys.**
  Disproved (test `E2`). `__contains__` checks
  `isinstance(rule_id, str)` and returns `False` for non-strings
  without raising.

* **Suspicion A5: `get(None)` and `latest_version(None)` crash.**
  Disproved (test `D14`). They return `None` / `False` / `None`
  gracefully.

* **Suspicion A6: `set_state` accepts a string instead of a
  `RuleState` enum.** Disproved (test `D13`). The registry checks
  `isinstance(new_state, RuleState)` and raises
  `RuleValidationError`.

* **Suspicion A7: Two `SimpleRule` instances built with the same
  `RuleMetadata` are coupled (a lifecycle change to one affects
  the other).** Disproved (test `D5`). The registry always
  builds a *new* `RuleMetadata` via `model_copy(update=...)` and
  rebinds it on the rule instance. The shared input metadata is
  left untouched. Pydantic's frozen-model guarantee combined
  with `model_copy` is doing the right thing.

* **Suspicion A8: `model_copy(update={...})` can be used to
  inject extra fields and slip past `extra="forbid"`.** Disproved
  (test `E3`). Pydantic v2 re-validates the result and drops /
  rejects unknown fields.
constructs (e.g. a reload) will see the class-level original.

### FINDING-3 (MEDIUM): `applicability_signature` does not encode
category; signatures can collide across categories

**Status: FIXED ✅** — `app/rules/types.py`
`RuleMetadata.applicability_signature` now appends
`category.value` to the returned tuple, so a SOURCE_SPECIFIC
rule and a COMMON_BEHAVIORAL rule with identical
`(sources, event_types)` produce different signatures. The
category is included even when `event_types` is empty (e.g.
correlation rules), closing the empty-signature collision as
well. One new regression test added to
`tests/unit/test_rule_metadata.py`:
`test_applicability_signature_is_unique_across_categories`.
Two existing tests updated to assert the new shape:
`test_applicability_signature_is_sorted_deterministic`,
`test_applicability_signature_empty_when_missing_either_side`.
**All 3 pass. Full suite: 231/231 pass (213 unit + 18 integration) in 5.37s.**

**Evidence.** `app/rules/types.py:354-371` builds the signature
from `sources` and `event_types` only:

```python
out: List[str] = []
for s in self.sources:
    for et in self.event_types:
        out.append(f"{s}::{et}")
return tuple(sorted(out))
```

The reproduction (test `H10`):

```text
sig(SOURCE_SPECIFIC, sources=(waf,), event_types=(waf_attack_detected,))
  == ('waf::waf_attack_detected',)
sig(COMMON_BEHAVIORAL, sources=(waf,), event_types=(waf_attack_detected,))
  == ('waf::waf_attack_detected',)
```

Two semantically different rules produce the same signature. The
test `test_applicability_signature_is_sorted_deterministic` only
exercises the same-category case, so the collision is invisible.

**Production impact.** The signature is not currently indexed by
the registry (`H17` confirmed the registry never references
`applicability_signature`), so this is latent. If a future slice
uses the signature as a cache key (e.g. for pre-filtered rule
lists or a Kafka topic name), it will silently conflate
source-specific and common-behavioral rules. Either the signature
should include the category, or the framework should not expose
the signature at all.

### FINDING-4 (LOW): Test count claim in section 11 of the dev
report is wrong

**Status: FIXED ✅** — `docs/PHASE 4/PHASE 4-02/PHASE-04-02-REPORT.md`
Section 11 now reads "the unchanged 102 Phase 4.1 tests" (was
"120"). Section 1, Section 5 (test count table), and
Section 10 (Verification Performed) updated to the post-fix
totals: 213 unit + 18 integration = **231 tests, all passing
in 5.37s** (213 unit + 18 integration). A new Section 12
documents the FINDING-1/2/3/4 follow-up. **No code regression;
`python -m pytest tests/` = 231/231 pass in 5.37s.**

**Evidence.** Section 11 of `PHASE-04-02-REPORT.md` says "the
unchanged **120** Phase 4.1 tests". The actual Phase 4.1 test
count (per `pytest --co -q tests/ -m "not integration"`) is
**102 unit tests** (`test_security_event.py`, `test_uuid7.py`,
`test_config.py`, `test_domain_errors.py`,
`test_simulated_connector.py`, and the 41 `test_logging_scrubber.py`
tests). The review's own count of 203 unit tests = 102 (Phase 4.1
existing) + 101 (Phase 4.2 new), matching the report's own table
in §5. The "120" in §11 is a typo.

**Production impact.** None. This is a documentation defect, not
a code defect, and is easy to correct in a future doc pass.
checks `if enabled and rule.metadata.state is not APPROVED`. It
does not check whether the targeted version is the latest. A
superseded version (e.g. v1) can be re-enabled after v2 is
registered. The reproduction (test `E1` and `E8`):

```text
r.register(WAF-001 v1, APPROVED, enabled=True)
r.register(WAF-001 v2, APPROVED, enabled=True)   # latest = 2
r.set_enabled("WAF-001", False, version=1)
r.set_enabled("WAF-001", True,  version=1)       # <-- re-enable v1
r.list_enabled()         -> [('WAF-001', 1), ('WAF-001', 2)]
r.list_for_event(...)    -> [WAF-001 v1 rule, WAF-001 v2 rule]
```

**Production impact.** The future detection engine will call
`Rule.evaluate` on **both** the deprecated v1 and the latest v2
for every matching event, producing duplicate detections. The
"versioning means we keep history" pattern is violated: a rule
that was intentionally superseded cannot be retired from the live
execution path.

**Why the existing tests do not catch it.** No test exercises
`set_enabled(True, version=older_version)`. The two-version
lifecycle tests in `tests/unit/test_rule_registry.py` only
demote the older version (`set_state(CANDIDATE, version=1)`)
and never re-enable it.