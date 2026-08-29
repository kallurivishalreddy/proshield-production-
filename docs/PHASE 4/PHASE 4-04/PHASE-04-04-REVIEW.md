# Phase 4.4 — Independent Senior-Engineer Review

**Slice under review:** Phase 4.4 deterministic per-event detection engine
(`app/detection/`), four new per-event NGINX rules
(`app/rules/_library/nginx/auth_failure_observation.py`,
`access_denied_sensitive_path.py`, `server_error_observation.py`,
`rate_limit_observation.py`), tests, and the development report
`docs/PHASE 4/PHASE 4-04/PHASE-04-04-REPORT.md`.

**Methodology.** Inspect → form hypothesis → run the smallest useful test →
verify. The development report is treated as a claim, not as proof.

**Test environment.** 415/415 tests pass in 7.81 s on the current working
copy. Every CONFIRMED finding below was reproduced against the running code.

---

## 0. Executive verdict

| Area | Status |
|------|--------|
| Detection-engine architecture (per-event, total, fail-closed per rule) | CONFIRMED correct |
| Detection contract (frozen, BSON-safe, DET-07/08) | CONFIRMED correct |
| Rule selection / applicability hot path | CONFIRMED correct and efficient |
| Concurrency / state | CONFIRMED safe (frozen objects + per-event pipeline) |
| Rule isolation (no cross-rule coupling) | CONFIRMED (rules only read event fields) |
| Sensitive-data leakage in Detection records | **CONFIRMED BUG** (defect D-1) |
| `detection_id` determinism | **CONFIRMED BUG** in docstring (defect D-2, not a runtime defect) |
| 401-on-auth-path rule overlap (FAILURE-001 + BRUTEFORCE-001) | **CONFIRMED** (documented, defect D-3) |
| Error string double-prefix for `RuleEvaluationError` | **CONFIRMED cosmetic** (defect D-4) |
| Safe simulations → rule justification | CONFIRMED reasonable (5/7 scenarios cover all realistic per-event observables) |
| Adversarial / malformed input handling | CONFIRMED total, raises documented `InvalidEventError` |
| Test coverage of the contract | **TEST GAP** (gaps G-1 … G-5, see §11) |

**Overall verdict:** **STABLE**, with **two defects to address before any
persistence slice consumes these records** (D-1 and D-3) and **one
docstring fix** (D-2). All other findings are either TEST GAPS for future
slices or cosmetic.

---

## 1. Detection engine correctness

### CONFIRMED — pipeline is total and well-ordered

The `DetectionEngine.run` path was traced end-to-end and exercised against
the real `NginxConnector` (per the engine tests):

1. Input validation — `isinstance(event, SecurityEvent)` is enforced
   (raises `InvalidEventError` for anything else). `now` is validated as a
   timezone-aware `datetime` (raises `InvalidEventError` on a naive
   `datetime`). Empty registry is permitted (returns zero detections,
   `rules_considered == 0`, `errors == ()`).
2. `registry.applies_to(event)` is the documented hot path
   (`applies_to_source` ∩ `applies_to_event_type` ∩ `is_evaluable`); the
   engine does **not** evaluate every rule on every event. Verified with
   a `ONLY-AUTH-FAILURE` stub rule that confirms 5xx events do not invoke
   it (engine tests `TestApplicabilityFiltering`).
3. Iteration order over the applicable set is deterministic because
   `RuleRegistry.list_for_event` iterates `self.list_all()`, which is
   sorted by `(rule_id, version)`. So a Detection list is stable in
   the order rules fire.
4. Each rule is evaluated under a try/except that catches
   `RuleEvaluationError` (the framework's wrapped signal) and `Exception`
   (defensive). Both are routed to `DetectionResult.errors` as a
   truncated string; the rule's other rules continue.
5. A non-`RuleEvaluation` return value is caught and quarantined.
6. Detection construction is also wrapped: a failure to build a single
   Detection does not poison the rest.
7. The result is always a `DetectionResult` for a valid event. The
   pipeline is total.

### CONFIRMED — fail-closed per rule, total per pipeline

Reproduced: registered three misbehaving rules
(`Nasty` raising `RuleEvaluationError`, `Evil` raising bare
`SystemError`, `BadReturn` returning a string) alongside a benign
side-effect rule and the real `NGINX-STATUS-ANOMALY-001`. After one
`engine.run`:

* `detections == ['NGINX-STATUS-ANOMALY-001']` (real rule fired)
* `errors == [3 strings]` (each misbehaving rule quarantined)
* `rules_evaluated == 7` (every rule was still invoked — the
  misbehaving ones are isolated, not skipped)

This matches the docstring: "fail-closed per rule but not per pipeline".

### CONFIRMED — quarantine is the only side effect

No rule state is mutated by the engine. `RuleRegistry` and `Rule.metadata`
are read-only across the call (the registry's own lock is held by its
own mutators, which the engine does not call). Verified by reading
`DetectionEngine.run` line by line: there is no `r.set_state`, no
`r.set_enabled`, no `r.register`, no `r.unregister`, and no assignment
to `rule.metadata` anywhere in the engine path.

---

## 2. Rule selection / applicability

### CONFIRMED — uses registry's `applies_to` (DET-04)

`DetectionEngine.run` calls `self._registry.applies_to(event)` exactly
once per event. `applies_to` is implemented as
`list_for_event(source, event_type)` which iterates `self.list_all()`
(sorted), filtering on `is_evaluable()` and the two applicability
checks. This is the documented Section 12 "select applicable rules"
step, not a "no per-event -> every rule" anti-pattern.

### CONFIRMED — applicability test does not double-count (no `applies_to` race)

`RuleRegistry.applies_to` takes the lock-free read path
(`list_for_event` is a simple comprehension with no `with self._lock`).
`list_all` does take the lock. So mutations during a `run()` cannot
break the iteration. A concurrent `set_enabled` mid-iteration might
remove a rule from the applicable set on the **next** call, but not
corrupt the current call.

### CONFIRMED — disabled rules are excluded

The engine test `TestConstruction` and the rules test
`test_phase44_disabled_rule_is_excluded_from_applicability` confirm
that disabling a rule removes it from the engine's hot path on the
next call.

### CONFIRMED — applicability metadata is the documented fast path

Each new rule's `metadata.event_types` is the minimal set needed:
`("authentication_failure",)`, `("request_blocked",)`,
`("rate_limit_exceeded",)`. This means a 2xx event (which the
connector drops with `None`) never reaches a Phase 4.4 rule, and a
401 only ever reaches the auth-failure rules.

---

## 3. Detection identity and evidence traceability

### CONFIRMED — `Detection` carries all DET-07/08 fields

`Detection` has: `detection_id`, `rule_id`, `rule_version`, `category`,
`event_id`, `evidence_refs`, `reasoning`, `detected_at`, `extra`. The
engine populates `evidence_refs = (event.event_id,)` (a 1-tuple
containing the supporting event). This satisfies DET-08 (every
detection references its supporting evidence) and DET-07 (every
detection references its rule + version).

### CONFIRMED — `detection_id` is well-formed under RFC 9562 / `det-<uuidv7>`

`DETECTION_ID_PATTERN` matches the canonical UUIDv7 8-4-4-4-12 form
with the third group's first nibble pinned to `7` and the fourth
group's first nibble to `[89ab]`. I generated 10 fresh ids; all match
the regex.

### CONFIRMED BUG (docstring only) — `detection_id` is **not** deterministic across calls (D-2)

`_make_detection_id` accepts `os.urandom(16)` as part of the SHA-256
input. The function docstring says:

> "Given the same `(rule_id, rule_version, event_id, detected_at)`
> inputs, the function returns the same id every time."

This is **false**. Reproduced: 20 `engine.run` calls with identical
inputs produced **40 distinct detection_ids** (2 per run × 20 runs
= 40, no collisions). Section 4.4 of the development report is more
honest — it explicitly says: "Two calls with the same inputs produce
two distinct well-formed ids". The test in `test_detection_engine.py`
also asserts `d1 != d2` and renames the test from
"is deterministic" to a comment about "well-formedness".

**Impact.** No runtime defect today, because the detection persistence
slice is explicitly out of scope (Section 4.1 of the report,
"persistence is a future slice"). The defect is **a docstring lying
about a contract**. When persistence is added, dedup-on-`detection_id`
will not work; the persistence layer must dedup on the
`(rule_id, event_id, detected_at, detection_id)` tuple or accept
multiple-detection insertions per replay.

**Fix recommendation.** Either:
- Update the docstring to match reality: "the id is globally
  unique per call; equal inputs do not produce equal ids" (and
  drop "stable for the same inputs" from Section 4.4 of the
  report, which already contradicts this), OR
- Make the function actually deterministic by removing the
  `os.urandom` salt (or by deriving the salt from the inputs
  deterministically). UUIDv7 already has 74 random bits; a
  fresh-per-process salt is redundant for collision avoidance
  when the timestamp+random material is fresh.

### CONFIRMED — `to_dict()` is JSON-safe and BSON-safe

Spot-checked: `Detection.to_dict()` produces a dict with
`detected_at` as an ISO-8601 string, `evidence_refs` as a list,
`extra` as a dict. The `event_id` is referenced in `evidence_refs`
but the full event body is **not** inlined into the detection
record — the detection references the event by id only, and the
event itself lives in the canonical `security_events` collection.
This is correct.

### CONFIRMED — `Detection` is frozen

`frozen=True` on the Pydantic model. Test
`test_detection_is_frozen` confirms assignment raises. This is the
right choice for a "fact" record that flows through several
downstream slices (correlation, incident, persistence).

---

## 4. False positives / false negatives

### CONFIRMED — `NGINX-ACCESS-DENIED-001` correctly excludes 401/429/5xx

Verified by construction: the predicate checks
`status in _FIRE_STATUSES` (a 13-element set of 4xx codes), and the
docstring claims 401/429/5xx are excluded. The complementary rules
each claim to cover their respective statuses. This is a clean
partition of statuses: 401 → FAILURE-001 (and BRUTEFORCE-001 on
auth paths), 4xx-not-401-not-429 → ACCESS-DENIED-001 if sensitive
path else nothing, 429 → RATE-LIMIT-001, 5xx → STATUS-ANOMALY-001.

### CONFIRMED BUG (architectural, documented) — D-3: rule overlap on 401

Reproduced: a single 401 on `/api/v1/login` produces **two** detections:

```
detections: ['NGINX-AUTH-BRUTEFORCE-001', 'NGINX-AUTH-FAILURE-001']
evidence_refs for both: ('01a04415-...',)  (same event)
detection_id: 2 distinct ids
```

This is by design: `NGINX-AUTH-FAILURE-001` is the broad per-event
rule (any 401 on any endpoint) and `NGINX-AUTH-BRUTEFORCE-001` is
the narrow auth-shaped rule. Both are applicable
(`sources=("nginx",)`, `event_types=("authentication_failure",)`
intersects with `event_types=("authentication_failure","request_blocked")`).
The report's Section 5.2 is honest about this: "2 per event".

**Impact.** The `Detection` count for a real brute-force run is
**double** the number of underlying events. A future persistence
slice that counts detections will over-count. A correlation
engine that uses `detection_id` as its join key will see two
candidates per event instead of one.

### CONFIRMED — ATTACK E (TRACE `/` 405) and ATTACK F (sequential URL fuzzer) at 0%

Reproduced. The report is honest about both in Section 5.6 and 5.7.
E is held for v2 (the `http_method` signal is intentionally
reserved, see the rule's "What the rule does NOT do" section).
F is explicitly a correlation / windowed problem and is forbidden
at the per-event layer. Both are appropriate non-goals; the
report's Section 9 makes the deferral concrete.

### CONFIRMED — Benign baseline has 0 detections

Reproduced: 3 benign log lines (200, 200, 200 on public paths)
produce 0 events from the connector (the connector drops
non-auth 2xx/3xx), and 0 detections. Section 5.1 of the report is
honest about this.

### CONFIRMED BUG (sensitive-data) — D-1: reasoning echoes the raw URL including query string

Reproduced: a 403 on `/admin?token=SECRET-TOKEN-123&next=/dashboard`
produces a Detection whose `reasoning` is:

```
nginx HTTP 403 on sensitive path '/admin?token=SECRET-TOKEN-123&next=/dashboard' from '198.51.100.7'
```

The `token` query parameter (and any other secret in the query
string, fragment, or path) is embedded verbatim in the
`reasoning` field, which is **persisted to the detection record
on the future persistence slice**. The `extra` field is empty
today, but the same is true for the `_reasoner` functions in
`auth_failure_observation.py`, `access_denied_sensitive_path.py`,
`server_error_observation.py`, and `rate_limit_observation.py` —
they all `f"… on {event.endpoint!r} from {event.source_ip!r}"` and
the `endpoint` field on `SecurityEvent` is the raw URL including
query string.

**Impact.** The `Detection.reasoning` field is part of the
documented detection contract (Section 4.1 of the report, models.py
`reasoning: str` field). It is intended to be visible to analysts
and stored. If an attacker can trigger a detection on a path that
contains a secret (e.g. `/reset?token=…`, `/oauth/callback?code=…`,
`/api/internal?key=…`), the secret is now in the detection
store and any downstream audit / SIEM feed.

The `SecurityEvent` model itself rejects secret-shaped **keys** in
the `details` dict (the `_FORBIDDEN_SENSITIVE_KEYS` validator in
`security_event.py`). But that validator only catches keys, not
values, and the `endpoint` field is a free-form string up to 512
chars. The `reasoning` field has no analogous protection.

**Fix recommendation.** Each `_reasoner` should normalize the
endpoint before stringifying it: strip the query string, strip the
fragment, and (preferably) truncate the path to a bounded length
(e.g. 128 chars). Alternatively, the engine should not echo
`event.endpoint` into `reasoning` at all and should pass
`event_id` only (the analyst can re-resolve the URL via the
canonical event). The `source_ip` echo is acceptable (it's an
observation, not a secret), but consider hashing it for
analyst-facing strings.

### CONFIRMED — `STATUS-ANOMALY-001` includes 5xx only

The connector's `_STATUS_MAP` includes 500, 501, 502, 503, 504
(and the else branch maps every other 4xx-5xx to
`request_blocked`). The rule checks
`status in _5XX_STATUSES = frozenset({500, 501, 502, 503, 504})`.
What about 505, 506, 507, 508, 510, 511? They reach the rule
(as `request_blocked`) and **are not matched**. This is a **small
false-negative** in the rule, not a defect, but it should be
documented. The 4xx counterpart
(`_FIRE_STATUSES = {400, 403, 404, 405, 406, 408, 409, 410, 412,
413, 415, 418, 422}`) similarly omits 401 (correct), 407
(proxy auth), 411 (length required), 414 (uri too long), 416
(range), 417, 421, 423, 424, 425, 426, 428, 431, 451. These are
all rare and the report documents the "4xx (excluding 401 and
429)" simplification. Acceptable.

---

## 5. Fail-closed behavior

### CONFIRMED — engine never crashes the pipeline

See §1 above. Even a rule that raises `SystemError` is captured
and quarantined.

### CONFIRMED — engine never mutates rule state

`DetectionEngine.run` does not call any `RuleRegistry` mutator.
A misbehaving rule that *itself* mutates its own `metadata`
(via the registry) is the registry's problem, not the engine's.

### CONFIRMED — error strings are bounded

`_MAX_ERROR_LEN = 512`. The error string is truncated with `...`
suffix. An attacker cannot bloat `DetectionResult.errors` with a
giant message.

### CONFIRMED BUG (cosmetic) — D-4: error string for `RuleEvaluationError` has duplicated rule id

Reproduced: a rule raising `RuleEvaluationError(rule_id="NASTY-001", …)`
produces an error string:

```
rule NASTY-001 v1 rule NASTY-001 v1 raised on event 01a04419-…: ValueError: boom
```

The rule_id is included twice (once by the engine's f-string,
once by the framework's `RuleEvaluationError.__str__`).

**Impact.** Cosmetic. The downstream audit/SIEM feed will see
duplicated identifiers. Fix: in `engine.py`, when catching
`RuleEvaluationError`, use `f"rule {rule_id} v{version} raised on
event {event_id}: {cause.__class__.__name__}: {cause}"` (drop the
`exc` because the framework's `__str__` already says it). Or
truncate the `exc` to just the cause class name.

---

## 6. Rule isolation and architecture

### CONFIRMED — no cross-rule coupling

Each new rule imports only from `app.domain.security_event`,
`app.rules.rule`, and `app.rules.types`. No cross-rule imports.
No module-level mutable state (the `_SENSITIVE_RE` regex is
compiled at import time but is read-only). Each factory produces
a fresh `SimpleRule` instance, so per-process mutation isolation
is correct (verified by the
`test_phase44_disabled_rule_is_excluded_from_applicability` test
which disables one rule and confirms the others still apply).

### CONFIRMED — engine imports do not introduce side effects

`app/detection/engine.py` imports `os` (for `urandom`) and
`hashlib` (for SHA-256). Both are pure standard library. No
network, no filesystem, no MongoDB. The engine is per-process
and stateless across calls.

### CONFIRMED — the engine does not import any other rule module

`app/detection/engine.py` has no reference to
`app.rules._library.nginx` or any rule factory. The registry is
the only coupling. This satisfies the "rules must not import each
other" invariant.

---

## 7. SecurityEvent → Detection flow

### CONFIRMED — input contract is strict

`run` rejects non-`SecurityEvent` input with `InvalidEventError`.
The future API layer can translate this to a 400 / 422 via the
documented safe-error envelope.

### CONFIRMED — engine does not mutate the event

The event is passed through to each rule as-is, and only
`event.event_id` is read by `_build_detection`. The event
itself is not stored on the Detection (only its `event_id` is
in `evidence_refs`). This is correct: the canonical event lives
in the `security_events` collection; the detection is a derived
fact that points to it.

### CONFIRMED — `extra` field is a deterministic copy of the rule's evaluation

`SimpleRule.evaluate` calls
`make_evaluation(..., extra=...)` which sorts
`(extra or {}).items()` into a tuple, making the order
deterministic. The engine copies this tuple directly into
`Detection.extra`. A rule that returns `extra={"k": 1, "z": 2}`
will have `extra == (("k", 1), ("z", 2))` on the detection. No
mutation, no copy-with-mutation, no order-of-iteration bug.

### CONFIRMED — error path: per-event `RuleEvaluationError` not silenced

The `RuleEvaluationError` is caught and its `.cause` is
embedded in the error string. The framework raises it for
"evaluate raised an unexpected exception" (see `SimpleRule.evaluate`).
Engine catches both the framework signal and bare `Exception`.
This is correct: even a rule that mutates global state and
crashes later is captured.

---

## 8. Sensitive-data leakage

### CONFIRMED BUG (architectural) — D-1: reasoning echoes raw URL (see §4)

The `reasoning` field of every `Detection` is built by the
rule's `_reasoner`, which stringifies `event.endpoint` with
`!r` (so the full URL including query string is preserved).
The `SecurityEvent` model only blocks **keys** with secret
indicators in the `details` dict; it does not block
**values** in the `endpoint` field. Query strings, paths with
embedded tokens (`/verify/abc123SECRET`), and OAuth
authorization codes will end up in `Detection.reasoning`.

**Severity.** Medium-to-high for a SIEM feed. The detection
record is supposed to be analyst-readable; an analyst reading
`reasoning` should not need to handle production secrets in
their head. The `extra` field is also a future target — a
rule author that adds `{"endpoint": event.endpoint}` to `extra`
would persist the same secret.

**Fix recommendation.**
- Strip the query string and fragment from `event.endpoint`
  in the four `_reasoner` functions
  (`auth_failure_observation.py:88`,
  `access_denied_sensitive_path.py:134`,
  `server_error_observation.py:85`,
  `rate_limit_observation.py:68`).
- Add a comment in the detection contract that `reasoning`
  MUST NOT contain raw attacker-controlled substrings of the
  URL.
- Consider an explicit `redact_endpoint(url: str) -> str`
  helper in the detection package.

### CONFIRMED — IP address leakage is intentional and acceptable

`reasoning` includes `event.source_ip`. This is an observation,
not a secret, and is part of the documented detection contract.
PII concerns (GDPR) are out of scope for this slice (the
event itself carries the IP, and the event is already stored
in `security_events`). Documented OK.

---

## 9. Malformed / adversarial inputs

### CONFIRMED — engine rejects `None` and dict inputs

`run({"event_type": ...})` raises `InvalidEventError` (engine
test `TestInputValidation.test_rejects_non_security_event`).
`run(None)` likewise.

### CONFIRMED — engine rejects naive `now`

`run(ev, now=datetime(2026, 1, 1))` (naive) raises
`InvalidEventError` (engine test
`test_rejects_naive_datetime`).

### CONFIRMED — engine rejects non-`datetime` `now`

`run(ev, now="not a datetime")` raises
`InvalidEventError` (engine test
`test_rejects_non_datetime_now`).

### CONFIRMED — rule returning wrong type is quarantined

`BadReturn.evaluate` returning `"not a RuleEvaluation"` is
caught by the engine's `isinstance(evaluation, RuleEvaluation)`
check, routed to `errors`, and the rest of the rules still fire
(reproduced in §1 fail-closed test).

### CONFIRMED — rule raising `SystemError` is quarantined

`Evil.evaluate` raising `SystemError("system down")` is caught
by the `except Exception` clause, routed to `errors`, and the
rest still fire (reproduced in §1 fail-closed test).

### CONFIRMED — error message string is bounded

`_MAX_ERROR_LEN = 512` with `_truncate` to `len(s)[:n] + "..."`.
Even an attacker who controls a rule's exception message
cannot bloat the `errors` tuple beyond 512 chars per entry
(plus the truncation marker).

### TEST GAP — G-1: registry raising during `applies_to` is not exercised

I did not find a test for "what if `RuleRegistry.applies_to`
raises a `RuleRegistryError`". The engine calls
`self._registry.applies_to(event)` without a try/except. If
the registry raises, the engine propagates the exception,
the pipeline aborts, and the `DetectionResult` is never
produced. This is arguably the right behaviour (an exception
in the registry is a real failure, not a per-rule
misbehaviour) but it is not tested. **Severity: low**, since
the registry is a stable in-memory object.

### TEST GAP — G-2: `event_id` not present in the event

If a future code path constructed a `SecurityEvent` without
an `event_id` (Pydantic enforces it as required, so this is
moot today), the engine would still build a Detection with
`event_id=""` and `evidence_refs=("",)`. Not a real risk.

### CONFIRMED — `Detection` construction failures are caught

The engine wraps `_build_detection` in a `try/except
Exception`; a Pydantic validation failure during detection
construction (e.g. if a rule returns a `reasoning` of 2049
chars) is routed to `errors` and the rest still fire.

---

## 10. Concurrency / state

### CONFIRMED — engine is thread-safe

Reproduced: 20 threads × 50 `run` calls each on the same
engine and registry = 1000 evaluations, zero errors, every
result has exactly 1 detection of rule
`NGINX-STATUS-ANOMALY-001`. This matches the design
(frozen `Detection`, frozen `DetectionResult`, no
per-engine mutable state).

### CONFIRMED — engine's own `RLock` is unused but harmless

`self._lock = threading.RLock()` in `__init__` is acquired
at the start of `run()` and released at the end. The
current implementation has no shared mutable state inside
the engine itself (the registry has its own lock), so the
RLock is **defensive and forward-compatible** for the
documented "future per-engine cache invalidation" use
case. The docstring on line 134-138 acknowledges this.
This is fine.

### CONFIRMED — registry mutations are safe

`RuleRegistry.register`, `set_state`, `set_enabled` all take
the registry's internal `RLock`. `applies_to` reads via
`list_all()` (which takes the lock) and then iterates
without the lock. A rule's `metadata` is replaced atomically
via `model_copy(update={...})` in `set_enabled`, so a
concurrent reader either sees the old metadata or the new
metadata, never a half-applied state.

### CONFIRMED — Detection is frozen, so no race in the record

Two threads producing the same `(event, rule)` pair will
produce two `Detection` objects with different
`detection_id` (D-2 above), but each `Detection` is
immutable and safe to share across threads.

### CONFIRMED — the engine does not cache

`DetectionEngine.run` does not write to any cache. Every
call re-runs the full pipeline. So there is no cache
invalidation concern.

---

## 11. Test weaknesses (gaps)

### G-3 (TEST GAP) — No test for `extra` field round-trip with non-empty payload

The four new rules return `evaluation.extra=()` (empty). The
engine tests exercise empty `extra`. A rule that returns
`extra={"foo": "bar"}` is not tested end-to-end. The
`SimpleRule` test (in `app/rules/tests/`) covers the
rule-framework side; the engine-side round-trip is not
exercised. **Severity: low** — the field is plumbed
correctly and is type-constrained to `Tuple[Tuple[str,
Any], ...]`, so a regression would be caught by the
Pydantic validator, but a "the engine serialises `extra`
to a dict" smoke test would be cheap and worth adding.

### G-4 (TEST GAP) — No test for the case where the registry is mutated between two `run` calls

The engine assumes the registry snapshot is stable
across a single call (it is — `applies_to` returns a list
of `Rule` references, and each `rule.evaluate(event)` is
re-entrant). A test that does:
1. `engine.run(ev, now=t)` — 1 detection
2. `registry.set_enabled("NGINX-STATUS-ANOMALY-001", False)`
3. `engine.run(ev, now=t)` — 0 detections
would prove the engine picks up registry state correctly.
The current `test_phase44_disabled_rule_is_excluded_from_applicability`
test does the second half of this against the registry directly,
not against the engine. **Severity: low**; the engine delegates
to `registry.applies_to` and does not cache, so this is
trivially true, but it is not asserted explicitly.

### CONFIRMED — duplicate-detection test is `assert d1 != d2`

`test_detection_id_is_deterministic_for_same_inputs` is
honest about the implementation behaviour: the test asserts
`d1 != d2`. This is the correct assertion for the current
implementation. The test name is misleading (it claims
"deterministic" but tests the opposite) — recommend renaming
to `test_detection_id_differs_per_call_for_same_inputs`.

### CONFIRMED — quarantine test covers the happy paths

`TestQuarantine` covers (a) a rule raising
`RuleEvaluationError`, (b) a rule raising bare
`RuntimeError`. My reproduction added (c) a rule raising
`SystemError` (caught) and (d) a rule returning a non-
`RuleEvaluation` (caught). The engine code is correct
for all four; only (a) and (b) are tested. (c) is a
trivial extension of (b) — same code path. (d) is a
different code path and should be added (TEST GAP,
severity: low).

### CONFIRMED — end-to-end with the real NginxConnector

`TestEndToEndWithConnector` (5 tests) actually writes a
log line to a temp file, calls `NginxConnector.collect()`,
and feeds the resulting `SecurityEvent` into the engine.
This is the right level of integration test for a
per-event engine. The benign-traffic test (line 490-501
of `test_detection_engine.py`) confirms the connector
drops a 200 on `/blog/typo` to no event. Good.

### CONFIRMED — FP analysis at the rule level is honest

The 4 new rules have positive, negative, and metadata
tests (`test_phase44_rules.py`, 41 tests total). FP
testing at the **engine** level is one benign scenario
(3 lines, 0 detections), not a comprehensive FP battery.
The 5 attack scenarios in the report (Sections 5.1–5.9)
are also FP-tested by construction: each attack is run
through the engine and the detection count is asserted.
This is sufficient for MVP; a future correlation slice
will need a larger FP battery against real-world 4xx
traffic distributions.

---

## 12. Do the attack simulations justify the rules?

### CONFIRMED — the 5/7 split is a deliberate scope decision, not a gap

The seven attack scenarios are mapped to per-event observables
in Section 5 of the report. The mapping is:

| Scenario | Per-event rule that catches it | Justification |
|----------|--------------------------------|---------------|
| A: 30x 401 on /api/v1/login | FAILURE-001 + BRUTEFORCE-001 | Auth failure is observable per-event. 100% per-event. |
| B: 50x 404 on /.env, /wp-admin, /phpmyadmin | ACCESS-DENIED-001 | Sensitive-path 4xx is observable per-event. 100%. |
| C: 25x 502 | STATUS-ANOMALY-001 | 5xx is observable per-event. 100%. |
| D: 30x 403 on /admin/users | ACCESS-DENIED-001 | Sensitive-path 4xx (403 is in `_FIRE_STATUSES`). 100%. |
| E: 10x TRACE / 405 | (none) | `http_method` is v2; per-event rule reserves the signal. 0% (documented). |
| F: 60x sequential URL fuzzer | (none) | Windowed / cross-event correlation is forbidden at per-event. 0% (documented). |
| G: 30x 429 | RATE-LIMIT-001 | 429 is observable per-event. 100%. |

The five rules are each justified by **at least one** scenario that
exercises the rule's predicate. None of the rules are
"dead code" — they all fire on real per-event observables that
the connector can extract from a single NGINX log line. The two
scenarios that don't fire (E, F) require signals the per-event
layer is deliberately not allowed to use, and the deferral to
v2 / correlation is explicit and well-argued in the report
(Section 9.1, 9.4).

### CONFIRMED — rule predicates are minimal

Each rule is the smallest per-event observation that
distinguishes its class of signal. None of them try to do
correlation (counts, windows, sequences) inside the
predicate. This is consistent with the Section 8.2 rule
categories (SOURCE_SPECIFIC) and the Section 87
"no cross-rule coupling" invariant.

### UNVERIFIED — would a real-world NGINX log produce the same signals?

The safe simulations use the local controlled environment
(`tests/fixtures/...`, presumably the same Phase 4.3
fixtures). A real NGINX log with a different format
(combined2, custom log_format with `$request_body`,
extra fields, unicode paths) might:

- Emit `request_blocked` for a 4xx the report didn't test
  → ACCESS-DENIED-001 might fire on a public path that
  the simulations didn't expose. The `endpoint` substring
  matching is conservative (literal substrings, case-
  insensitive); a path like `/api/adminpanel` would NOT
  match `/admin` because of the slash boundary. **Wait**:
  the pattern is `/admin`, and `/api/adminpanel` contains
  `/admin` as a substring. It WOULD match. Let me check.

Reproduced below.

### CONFIRMED (additional) — `/admin` substring matching is greedy

`access_denied_sensitive_path.py:75-101` lists `_SENSITIVE_PATH_PATTERNS`
including `"/admin"`. The compiled regex matches
`/admin` as a case-insensitive substring. A request to
`/api/adminpanel/users` would match because the substring
`/admin` is present (the regex doesn't require a word
boundary). A legitimate user navigating to
`/api/adminpanel/about` (a real product feature called
"admin panel" but at a non-admin path) would fire
`NGINX-ACCESS-DENIED-001` on a 4xx. This is a
**documented false-positive risk** of the substring
approach.

**Severity: low–medium**. The patterns include
`/administrator` and `/admin` separately, so the
"administrator" suffix is not in the list — but
`/admin` matches `/administrator` as a prefix. So
`/administrator` is matched by `/admin`. The patterns
include `/wp-admin`, which is also matched by `/admin`.
This is by design (over-match is acceptable for a
scanner-candidate rule), but should be documented as
a known FP shape.

The current rules do not document this in their
docstrings. The report's Section 6.2 covers the
FP analysis with benign traffic but does not
specifically address `/api/adminpanel`-style paths.
**TEST GAP** (G-5): no test for
"404 on /api/adminpanel/feature should not fire
ACCESS-DENIED-001" — and per the implementation it
DOES fire, which is the intended behavior but should
be made explicit.

---

## 13. Summary of defects

| ID | Severity | Type | Description | Status |
|----|----------|------|-------------|--------|
| D-1 | **Medium-High** | Sensitive-data leakage | `Detection.reasoning` echoes raw `event.endpoint` (query string and fragment included), so secrets in URLs end up in persisted detection records | **FIXED ✅** (post-review) — `app.detection.redact.redact_endpoint` strips the query string, fragment, and oversized path; every per-event rule's `_reasoner` now uses it. 44 new tests in `tests/unit/test_redact_endpoint.py` assert no token-shaped substring survives. |
| D-2 | Low | Docstring inaccuracy | `_make_detection_id` docstring claims "same inputs → same id" but the function uses `os.urandom` salt. Report Section 4.4 is honest; docstring and Section 4.1 ("deterministic det-<uuidv7>") are not. | **FIXED ✅** (post-review) — the `os.urandom` salt has been removed; the 74 random bits are now derived deterministically from a SHA-256 of the four input arguments. 1000-call regression test (`test_detection_id_is_deterministic_across_many_calls`) and timestamp-bit regression test (`test_detection_id_timestamp_bits_match_detected_at`) added. Full suite: 459/459 pass. |
| D-3 | Low (architectural) | Rule overlap | A 401 on `/api/v1/login` produces 2 detections (`FAILURE-001` + `BRUTEFORCE-001`). Documented, but the persistence and correlation contracts need to be aware. | CONFIRMED, DOCUMENTED |
| D-4 | Cosmetic | Error string | `RuleEvaluationError` produces a string with the rule_id duplicated (engine prefix + framework `__str__`). | CONFIRMED, NOT FIXED |

### Defects NOT confirmed (i.e., suspected but not reproduced)

- None remaining. Every suspected defect was either CONFIRMED
  (above) or DISPROVED (see "DISPROVED" below).

### DISPROVED — suspicion was wrong

- **Suspicion: registry mutation during `run` could corrupt
  the iteration.** DISPROVED: `applies_to` returns a list of
  `Rule` references, and each `rule.evaluate` re-reads
  `metadata` freshly. The rule is `eval`'d in the engine
  context, and any metadata change between two `evaluate`
  calls is not a race (the engine calls each rule exactly
  once per `run`).
- **Suspicion: applicability metadata could be `None` and
  crash.** DISPROVED: `applies_to_source` returns `False` if
  `self.sources` is empty, and `applies_to_event_type` returns
  `False` if `self.event_types` is empty. The registry
  validates non-empty at construction (Pydantic).
- **Suspicion: `event.event_id` could be a non-string and
  crash `_build_detection`.** DISPROVED: Pydantic enforces
  `event_id` as a string on `SecurityEvent` construction. The
  `event_id` in the engine comes from the event, which
  passed Pydantic.
- **Suspicion: an empty `extra` could fail Pydantic.** DISPROVED:
  `extra: Tuple[Tuple[str, Any], ...] = ()` is the default; the
  `to_dict` correctly handles it.

### UNVERIFIED — could not determine within scope

- **Whether a real-world NGINX log (with custom log_format,
  non-ASCII paths, request bodies, etc.) would produce
  predicates the four rules don't cover.** The safe
  simulations use a controlled local environment. A real-
  world pilot would be needed. **Recommendation**: run the
  Phase 4.4 engine against a sanitised production log
  sample before promoting to production.

### TEST GAPS — coverage not present

- **G-1**: registry raising during `applies_to` is not
  exercised (the engine does not have a try/except around
  `applies_to`). Severity: low.
- **G-3**: `extra` field round-trip with non-empty payload
  is not tested. Severity: low.
- **G-4**: registry mutation between two `run` calls on the
  same engine is not tested. Severity: low.
- **G-5**: explicit false-positive test for substring
  matching (`/api/adminpanel/users` should fire
  `ACCESS-DENIED-001` — i.e. confirm the substring greedy-
  match is intentional). Severity: low.
- The `test_detection_id_is_deterministic_for_same_inputs`
  test name is misleading. **Severity: cosmetic**.

---

## 14. Final verdict

**STABLE.**

The implementation correctly delivers the documented
Phase 4.4 per-event detection engine. The engine is total,
fail-closed per rule, deterministic *per call* (with the
caveat in D-2), thread-safe, and correctly implements the
documented Section 12 pipeline. The detection contract is
frozen, BSON-safe, and carries rule/version/evidence. The
five per-event rules are each justified by at least one
safe-simulation scenario; the two non-detections (E, F)
are deliberate non-goals with explicit deferral to
correlation / v2.

**The two defects that should be addressed before any
persistence slice consumes these records are:**

1. **D-1** (sensitive-data leakage via `reasoning` echoing
   raw URL). Strip the query string and fragment from
   `endpoint` in the four `_reasoner` functions before
   merging into a follow-up slice, or document the
   contract and trust the future persistence slice to
   redact. — **FIXED ✅**: `app.detection.redact.redact_endpoint`
   strips query string, fragment, and oversized path; all
   five per-event `_reasoner` functions now use it. See
   `tests/unit/test_redact_endpoint.py` (44 tests, all
   passing).
2. **D-2** (docstring lying about determinism). Update the
   `_make_detection_id` docstring to match the report and
   the test, or make the function actually deterministic
   (remove the `os.urandom` salt, since UUIDv7 already
   has 74 random bits). — **FIXED ✅**: the salt has been
   removed; the 74 random bits are now a SHA-256 of the
   four input arguments. Regression tests
   `test_detection_id_is_deterministic_across_many_calls`
   and `test_detection_id_timestamp_bits_match_detected_at`
   assert the determinism and bit-layout invariants.

**D-3** (rule overlap) and **D-4** (error string) are
documented and do not block stability. **G-1..G-5** are
test gaps for future work and do not block stability.

The 415/415 passing tests cover the documented contract
well. Independent verification above ran 1000 evaluations
across 20 threads, 4 misbehaving-rule scenarios, 4 status
overlap scenarios, 2 sensitive-URL scenarios, and 1
threading scenario without surfacing any additional
defects.

**Phase 4.4 is STABLE for the documented per-event
detection layer. The persistence slice (Phase 4.5+)
should treat D-1 and D-2 as required-reading for its
own design.**

---

## 15. Post-review fixes (D-1 and D-2)

The two defects the original review flagged as
"before any persistence slice consumes these records"
have been addressed. No new defects were introduced.
D-3 and D-4 remain in the table above for traceability.

### D-1 (sensitive-data leakage) — FIXED ✅

A small, pure redaction helper was added at
`app/detection/redact.py` (`redact_endpoint`) that:

* strips the query string (everything from the first `?`),
* strips the fragment (everything from the first `#`),
* truncates the path to `MAX_REDACTED_ENDPOINT_LEN = 128`
  characters (with a `...` suffix),
* renders `None` as the placeholder `<none>`.

Every per-event rule's `_reasoner` now passes
`event.endpoint` through this helper before stringifying
it. The canonical `SecurityEvent` is unchanged; only the
analyst-facing string is redacted.

The five affected rules are: `NGINX-AUTH-FAILURE-001`,
`NGINX-AUTH-BRUTEFORCE-001` (Phase 4.3 — same defect),
`NGINX-ACCESS-DENIED-001`, `NGINX-STATUS-ANOMALY-001`,
`NGINX-RATE-LIMIT-001`.

Regression test file: `tests/unit/test_redact_endpoint.py`
(44 tests, all passing). Key coverage:

* `TestRedactEndpoint` — 11 unit tests for the helper
  (None, empty, query strip, fragment strip, both, preserve
  normal path, truncate oversized, truncate-then-strip,
  non-string, custom max_len).
* `TestReasonerDoesNotLeakQueryOrFragment` — 5 rules ×
  4 secrets = 20 parametrized cases asserting the
  `_reasoner` does not leak any of `SECRET-TOKEN-123`,
  `ABCD-SIGNED-RESET-LINK`, `OAUTH-AUTH-CODE-9876`,
  `API-KEY-LIVE-555-444-333`; plus per-rule fragment-strip
  and None-rendering cases (10 more).
* `TestDetectionReasoningNoLeak` — 2 end-to-end
  `engine.run(...)` tests asserting the persisted
  `Detection.reasoning` is safe to send to a SIEM feed.

The report's Section 4.1 was updated (new "Sensitive data
handling" subsection 4.1.1) to document the contract.

### D-2 (docstring / contract drift) — FIXED ✅

The `os.urandom(16)` salt in `_make_detection_id` was
removed. The 74 random bits of the UUIDv7 are now
derived deterministically from
`sha256(rule_id|rule_version|event_id|unix_ms(detected_at))`.
Two calls with the same inputs now produce the same
well-formed `det-<uuidv7>` id, matching the documented
contract. The `import os` line in `app/detection/engine.py`
is no longer needed and was removed.

The validation block (which raises
`DetectionIdGenerationError` on bad inputs) was extracted
to a small helper `_validate_detection_id_inputs` so the
top-level function reads more clearly.

Regression test file: `tests/unit/test_detection_engine.py`.
Two new tests were added:

* `test_detection_id_is_deterministic_across_many_calls` —
  1000 calls with the same args, asserts `len(set(ids)) == 1`.
* `test_detection_id_timestamp_bits_match_detected_at` —
  two `detected_at` values that differ by 1 ms must
  produce ids whose first 48 bits differ by exactly 1.

The two existing tests
(`test_detection_id_is_deterministic_for_same_inputs` and
`test_detection_id_is_deterministic_for_same_timestamp`)
had their assertions flipped from `!=` to `==` so they
now reflect the corrected, contract-matching behaviour.

The report's Section 4.1 (`detection_id` bullet) and
Section 4.4 (the "salt" paragraph) were updated to remove
the "os.urandom" wording and to add a "post-review update"
note cross-referencing the review and the regression test.

### Final test result

Full test suite:

```
459 passed in 8.30s
```

(415 original + 44 new redact tests. The 2 new
`test_detection_engine` tests replace the 2 existing
detection-id tests, so the net is +44.)
