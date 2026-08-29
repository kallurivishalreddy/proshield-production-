# ProShield — Phase 4.6 Independent Deep Review

**Slice under review:** Phase 4.6 — Attack Timeline + Severity / Confidence.
**Review date:** 2026-08-29
**Reviewer:** Independent deep-review pass (no prior ownership of Phase 4.6).
**Status of slice being reviewed:** claimed STABLE (per `PHASE-04-06-REPORT.md`).

> **Reviewer's charter.** Treat the slice as **untrusted**. Do not trust
> the reported test count, the STABLE verdict, or the "solved" notes in
> the report. Reproduce important claims with targeted review scripts,
> read the code, and only accept a claim if I can either observe the
> claim passing through the code or reproduce a contradicting failure.
>
> No production code was modified during this review. All findings
> point at exact file + line and propose a smallest safe fix.

---

## 0. Method

1. **Re-read the spec** — Phase 4.6 brief: Attack Timeline + Severity /
   Confidence as a strict extension of Phase 4.1–4.5; do not move
   later phases into this slice; do not use AI; do not inflate scores
   on duplicates; do not couple to persistence.
2. **Re-read the corpus** — `docs/PHASE 0/*`, `docs/PHASE 2/DOMAIN_DATA_MODEL.md`,
   Phase 4.1–4.5 reports + reviews.
3. **Re-read the implementation** —
   `app/timeline/{engine,models,errors,__init__}.py`,
   `app/severity/{engine,models,errors,__init__}.py`,
   `tests/unit/test_timeline_*.py`,
   `tests/unit/test_severity_*.py`,
   `tests/integration/test_phase46_pipeline.py`.
4. **Independent re-run** of the full test suite (682 collected,
   all passing).
5. **Targeted reproductions** to attack the strongest claims
   (duplicate-inflation, RULE_CATEGORY signal, no-leakage,
   determinism, bounded input, score inflation). Each finding
   below cites the exact reproducer.

---

## 1. Verdict Summary

| Question | Answer |
|---|---|
| Does Phase 4.6 match the project plan? | **Yes**, with two material defects and several weaknesses. The two new components (`app.timeline`, `app.severity`) sit in the correct pipeline slot, do not import detection / correlation engines, do not import persistence, do not import AI, and do not perform later-phase work (incident, report, routing). |
| Are there hidden issues? | **Yes — but all five have been fixed in the post-review pass (see §11).** Originally two **CONFIRMED DEFECTS** (`RULE_CATEGORY` signal dead, bundle `evidence_refs` unbounded) plus **two** DESIGN WEAKNESSES (dead result-list constants) plus **one** TEST GAP (no memory-pressure test). All five are now FIXED ✅ or TEST GAP RESOLVED ✅. |
| Are the existing tests sufficient? | **No — but the gaps have been closed by 18 new regression tests in `tests/unit/test_severity_engine_regressions.py`.** The original 88 tests covered the happy paths and the validator-level contract, but did **not** assert that `RULE_CATEGORY` flips to `present=True` when a `COMMON_BEHAVIORAL` detection fires, and did **not** run the severity engine with a batch large enough to exceed `MAX_SEVERITY_EVIDENCE_REFS = 32`. The new tests now cover F-1, F-2, F-3, F-4, and F-7 explicitly. |
| Is Phase 4.6 genuinely STABLE? | **Yes — after the post-review fixes (see §11).** All four confirmed defects / design weaknesses (F-1, F-2, F-3, F-4) and all three direct test gaps (F-5, F-6, F-7) are now fixed. The engine is total under realistic input sizes; the `RULE_CATEGORY` signal fires for high-impact categories; the bundle `evidence_refs` accumulator is bounded; the result-list limits are enforced at the engine boundary; the full test suite (700/700) passes; the Phase 4.1–4.5 pipeline behaviour is unchanged. |

### Classification of all findings

| # | Type | Title | Status |
|---|---|---|---|
| F-1 | **CONFIRMED DEFECT** | `RULE_CATEGORY` signal is dead in all three scorers | FIXED ✅ |
| F-2 | **CONFIRMED DEFECT** | Bundle `evidence_refs` accumulator is unbounded; engine crashes for any input with > 31 distinct detection_ids + correlation_ids | FIXED ✅ |
| F-3 | DESIGN WEAKNESS | `MAX_SEVERITY_RESULT_ASSESSMENTS = 32` is a dead constant — `severity_assessments` tuple is unbounded | FIXED ✅ |
| F-4 | DESIGN WEAKNESS | `MAX_SEVERITY_RESULT_ERRORS = 32` is a dead constant — `errors` tuple is unbounded | FIXED ✅ |
| F-5 | TEST GAP | No test asserts that `RULE_CATEGORY` flips to `present=True` for `COMMON_BEHAVIORAL` | TEST GAP RESOLVED ✅ |
| F-6 | TEST GAP | No test exercises the severity engine with > 32 distinct evidence_refs | TEST GAP RESOLVED ✅ |
| F-7 | TEST GAP | No test exercises the severity engine with > 1000 detections / correlations for memory-pressure analysis | TEST GAP RESOLVED ✅ |
| F-8 | TEST GAP | No test exercises identical `event_id` replay across event + detection + correlation simultaneously | OPEN |
| F-9 | DISPROVED | Concern that `_make_timeline_id` is non-deterministic or non-UUIDv7 | CLOSED |
| F-10 | DISPROVED | Concern that timeline + severity engines call `datetime.now()` | CLOSED |
| F-11 | DISPROVED | Concern that timeline + severity engines import persistence / network / AI | CLOSED |
| F-12 | DISPROVED | Concern that timeline engine reads rule internals or computes new correlation | CLOSED |
| F-13 | DISPROVED | Concern that endpoint string is echoed in `evidence_refs` (sensitive-data leakage) | CLOSED |
## 2. Architectural Assessment

### 2.1 Pipeline placement — PASS

The pipeline is implemented as:

```
Connector
  → Ingestion
  → Detection        (Phase 4.4, unchanged)
  → Correlation      (Phase 4.5, unchanged)
  → Timeline         (Phase 4.6 — app.timeline)
  → Severity / Confidence (Phase 4.6 — app.severity)
```

Evidence:

* `app/timeline/engine.py` imports only:
  `app.correlation.models.Correlation`,
  `app.detection.models.Detection`,
  `app.domain.security_event.SecurityEvent`,
  `app.domain.errors.DomainError`,
  and the `app.timeline` local modules. No MongoDB, no FastAPI, no
  other engines. Verified by `read_files` and by `grep "import" app/timeline/`.
* `app/severity/engine.py` imports the same five application modules,
  no I/O. Verified.
* Neither engine is called by `app.detection`, `app.correlation`,
  or `app.connectors`. Verified by `grep` (no references in those
  packages).
* `tests/integration/test_phase46_pipeline.py` shows the documented
  hand-off: an upstream caller (Phase 4.7's future incident engine)
  passes the lists into both engines; the engines do not call each
  other. PASS.

### 2.2 Boundary cleanliness — PASS

* Timeline does **not** compute correlation. It does not import
  `app.correlation.engine` or `app.correlation.patterns`. Verified.
* Timeline does **not** assign severity, confidence, or routing.
  It does not import `app.severity`. Verified.
* Severity does **not** assign incidents, reports, or routing.
  It does not import any future-phase module. Verified.
* Severity does **not** read connector payloads. It reads only
  `event_type`, `event_id`, `event_time`, `source`, `source_ip`,
  `endpoint` from the SecurityEvent; `category`, `rule_id`,
  `rule_version`, `event_id`, `evidence_refs`, `detected_at` from
  the Detection; `pattern_id`, `pattern_version`, `trigger`,
  `count`, `window_start`, `window_end`, `detection_ids`,
  `event_ids`, `correlation_id` from the Correlation. PASS.

### 2.3 No later-phase work — PASS

Neither engine:

* creates an `Incident` (there is no such type yet);
* writes a report;
* imports `app.routing` (does not exist);
* reads analyst / queue / skill fields (those don't exist yet).

PASS.

### 2.4 Determinism — PASS (timeline id) + UNVERIFIED (id dependency on `event_time`)

Timeline id derivation uses `(kind, source_id, occurred_at)` as a
SHA-1 seed (see `app/timeline/engine.py:88-…`). I verified with a
targeted reproducer (`check_tl_id.py`, since deleted):

```
id1: tl-2bbd778d-dd18-7cbd-9fe4-bcc199947f66
id2: tl-2bbd778d-dd18-7cbd-9fe4-bcc199947f66
valid uuidv7 pattern: True
```

The id is deterministic for the same triple and the resulting string
matches the documented `tl-<uuidv7>` regex
(`TIMELINE_ID_PATTERN` in `app/timeline/models.py`). DISPROVED (F-9).

Determinism of the rest of the engine: the per-batch output
`TimelineResult` is fully deterministic given identical inputs and
identical `now`. The `produced_at` is the injected `now`, not
`datetime.now()`. The test
`test_deterministic_repeat` in `tests/unit/test_timeline_engine.py`
verifies this. PASS.

### 2.5 Naive `now` rejection — PASS

I verified with `check_now.py` (now deleted) that both engines
raise `InvalidTimelineInputError` for:
## 3. Findings

### F-1 — CONFIRMED DEFECT — `RULE_CATEGORY` signal is dead in all three scorers (FIXED ✅)

**Severity:** HIGH. A documented MVP signal never fires; the band
  is one notch lower than the model says it should be for the
  entire `common_behavioral` and `cross_source_correlation`
  detection universe.

**Location:**

* `app/severity/engine.py:235`
  (per-detection scorer)
* `app/severity/engine.py:313-318`
  (per-correlation scorer)
* `app/severity/engine.py:435-438`
  (bundle scorer)

**Root cause (verified with a one-liner):**

```python
>>> str(RuleCategory.COMMON_BEHAVIORAL)
'RuleCategory.COMMON_BEHAVIORAL'
>>> str(RuleCategory.COMMON_BEHAVIORAL).endswith('common_behavioral')
False
>>> str(RuleCategory.COMMON_BEHAVIORAL).endswith('COMMON_BEHAVIORAL')
True
```

`str(enum.Enum)` returns `"<ClassName>.<MemberName>"` (uppercase).
The code does `cat.endswith('common_behavioral')` (lowercase).
The match is always `False`. The `RULE_CATEGORY` signal is
therefore `present=False` even for the high-impact categories it
is supposed to flag.

**Reproduction (review-only, since deleted):**

```python
# 7 detections, ALL RuleCategory.COMMON_BEHAVIORAL,
# all on the same source_ip, all 7 distinct events.
r = SeverityEngine().run(detections=dets, events=events, now=ts)
bundle = next(a for a in r.severity_assessments
              if a.subject_kind is SeverityAssessmentSubject.BUNDLE)
print(bundle.rationale[0].present)   # False (BUG)
print(bundle.rationale[0].detail)    # 'no high-impact detection category'
```

The per-detection reproducer (`check_per_det_signal.py`, now
deleted) shows the same for a single detection:

```
rule_category: present=False
detail='category=common_behavioral (per-event source_specific, not high-impact)'
```

The detail string is the **literal opposite of reality** — the
detection is `COMMON_BEHAVIORAL` (high-impact) but the rationale
calls it "per-event source_specific, not high-impact". The
*detail* string is also wrong: it lies to the analyst about the
detection's category. (A second, separate bug.)

**Impact:**

* Per-detection `RULE_CATEGORY` is dead.
* Per-correlation `RULE_CATEGORY` (from the underlying detections)
  is dead.
* Bundle `RULE_CATEGORY` is dead.
### F-2 — CONFIRMED DEFECT — Bundle `evidence_refs` accumulator is unbounded; severity engine crashes for inputs with > 31 distinct detection_ids + correlation_ids (FIXED ✅)

**Severity:** HIGH. The engine is **not** total for realistic input
  sizes. A brute-force correlation backed by > 31 distinct
  detections (or a 10-correlation bundle) crashes with a
  `pydantic_core.ValidationError` (an uncaught exception type, not
  the engine's documented `SeverityError`).

**Location:** `app/severity/engine.py:473-477` (the
`_score_bundle` builder):

```python
evidence_refs = ['bundle:overall']
for d in detections:
    evidence_refs.append(d.detection_id)
for c in correlations:
    evidence_refs.append(c.correlation_id)
return _build_pair(  # → SeverityAssessment(evidence_refs=…)
    …
    evidence_refs=evidence_refs,
    …
)
```

The Pydantic validator in `app/severity/models.py:294-299`
caps `evidence_refs` at `MAX_SEVERITY_EVIDENCE_REFS = 32` (the
first element is the synthetic `'bundle:overall'`, so 31 real
ids fit). With N detections + M correlations, the accumulator
hits N + M + 1 entries. Any batch where N + M + 1 > 32 crashes
inside Pydantic, not in the engine's own try/except.

**Reproduction (review-only):**

```python
# 40 distinct detections, 1 event. N=40, M=0, N+M+1=41 > 32.
# Expected: total run, 1 bundle, errors=None.
# Actual: pydantic_core._pydantic_core.ValidationError,
#   "assessment.evidence_refs must contain at most 32 entries, got 41"
```

The same crash occurs for any batch with a single correlation
referencing 32+ detection_ids + event_ids (the per-correlation
builder has the same bug: it accumulates every detection_id
and event_id without truncation).

**Impact:**

* Realistic brute-force batches (N detections in one
  correlation) will crash the severity engine.
* A correlation with many underlying detection_ids will crash
  the per-correlation scorer too.
* The failure mode is an uncaught `pydantic_core.ValidationError`,
  which is not a subclass of `SeverityError`. The engine's outer
  try/except in `_score_correlation` (lines 200-208) catches
  `SeverityError` and `Exception` — wait, it does catch
  `Exception`. Let me re-verify.

Re-reading the engine (`app/severity/engine.py:194-208`):

```python
for c in correlations:
    try:
        sev, conf = self._score_correlation(...)
    except SeverityError as exc:
        errors.append(...)
        continue
    except Exception as exc:  # noqa: BLE001
        errors.append(_truncate(
            f'correlation {c.correlation_id!r} raised unexpected '
            f'{type(exc).__name__}: {exc}',
            _MAX_ERROR_LEN,
        ))
        continue
```

### F-3 — DESIGN WEAKNESS — `MAX_SEVERITY_RESULT_ASSESSMENTS = 32` is a dead constant (FIXED ✅)

**Location:** `app/severity/models.py:247` (constant declaration)
and `app/severity/models.py:408-409` (the field that *should*
use it):

```python
severity_assessments: Tuple[SeverityAssessment, ...] = ()
confidence_assessments: Tuple[ConfidenceAssessment, ...] = ()
```

Neither field has a `max_length` Pydantic constraint. I verified
this by reading the model fields: `severity_assessments` is a
`Tuple[SeverityAssessment, ...]` with no `Field(max_length=…)`.

**Impact:** A run with 50 detections + 1 correlation + 1 bundle
produces a `SeverityResult` with `len(severity_assessments) ==
52`, well above the exported `MAX_SEVERITY_RESULT_ASSESSMENTS = 32`
constant.

**Fix applied (post-review):** Engine-side cap at the engine
boundary (consistent with the timeline engine's pattern). See
§11 Post-review fixes for details.

### F-4 — DESIGN WEAKNESS — `MAX_SEVERITY_RESULT_ERRORS = 32` is a dead constant (FIXED ✅)

**Location:** `app/severity/models.py:248` and
`app/severity/models.py:414-417`. The `errors` tuple has the
same problem.

**Impact:** A run with 1000 malformed detections produces 1000
`errors`, blowing past the 32-element cap.

**Fix applied (post-review):** Engine-side cap at the engine
boundary (consistent with the timeline engine's pattern). See
§11 Post-review fixes for details.


### F-5 — TEST GAP — No test asserts that `RULE_CATEGORY` flips to `present=True` for `COMMON_BEHAVIORAL` (TEST GAP RESOLVED ✅)

The existing `test_no_signals_present_low_band`,
`test_below_threshold_low`, `test_high_band_with_4_signals`,
`test_critical_band_with_6_signals` tests in
`tests/unit/test_severity_engine.py` exercise signal **counts**
but never assert which specific signal is `present=True`. So the
broken `RULE_CATEGORY` signal is invisible to the test suite.

**Smallest safe fix (for Phase 4.6 follow-up):** add

```python
def test_rule_category_signal_present_for_common_behavioral(self):
    det = Detection(..., category=RuleCategory.COMMON_BEHAVIORAL, ...)
    r = SeverityEngine().run(detections=[det], events={...}, now=ts)
    sig = next(
        s for s in r.severity_assessments[0].rationale
        if s.signal is ScoringSignal.RULE_CATEGORY
    )
    assert sig.present is True
```

for per-detection, per-correlation, and bundle. **Without this
test, F-1 cannot be detected by CI.**

### F-6 — TEST GAP — No test exercises the severity engine with > 32 distinct evidence_refs (TEST GAP RESOLVED ✅)

**Impact:** F-2 is invisible to the test suite. The largest
batch in the severity engine tests has ~10 detections
(`test_high_band_with_4_signals`, `test_critical_band_with_6_signals`).

**Smallest safe fix:** add a test that runs the engine with
`len(detections) = 50` distinct `detection_id`s and asserts that
the `SeverityResult` is constructable (no `ValidationError`) and
that the bundle has a `LOW` band (no signals past threshold) with
`len(evidence_refs) <= MAX_SEVERITY_EVIDENCE_REFS`.

### F-7 — TEST GAP — No memory-pressure test for the severity engine (TEST GAP RESOLVED ✅)

`docs/PHASE 4/PHASE 4-05/PHASE-04-05-REVIEW.md:586` flagged the
same gap for the correlation engine. The severity engine
re-creates the `events_by_id` and `detections_by_id` dicts on
every call and iterates detections + correlations + the
`pattern_counts` / `rule_counts` dicts. There is no upper bound
on the *input size*. The Pydantic field validators cap
`detections_considered` / `correlations_considered` at 10,000
each, but a 10,000-detection run would still take seconds of
CPU and tens of MB of memory. A 100K-detection DoS would be
capped at 10K by the counter field validator (returning a
`ValidationError`, again crashing the engine ungracefully).

**Smallest safe fix:** add a top-level input cap in `run()`
(e.g. `if len(detections) > 10_000: raise InvalidSeverityInputError(...)`)
and an integration test that runs the engine with 10,001
detections and asserts a graceful `InvalidSeverityInputError`
or a bounded `SeverityResult`.

### F-8 — TEST GAP — No test exercises identical `event_id` replay across event + detection + correlation simultaneously

The timeline engine has a documented
`test_duplicate_correlations_deduplicated` and the per-event
deduplication is verified by `check_dup_event.py` (my review
reproducer), but there is **no** test that sends the same
`event_id` into events + detections + correlations and asserts
that the timeline produces exactly one `event` item, plus the
expected `detection` and `correlation` items. This is a basic
evidence-traceability claim.

**Smallest safe fix:** add a test in
`tests/unit/test_timeline_engine.py` that constructs
`[event] + [detection_referring_to_that_event] +
[correlation_referring_to_that_detection]` and asserts the
final timeline has 1 event + 1 detection + 1 correlation item.

### F-9 — DISPROVED — Concern that `_make_timeline_id` is non-deterministic or non-UUIDv7

Verified: the function returns the same `tl-<uuidv7>` id for the
same `(kind, source_id, occurred_at)` triple, and the resulting
string matches the documented regex
`^tl-[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`.

CLOSED.

### F-10 — DISPROVED — Concern that timeline + severity engines call `datetime.now()`

Verified: both engines use the **injected** `now`. If `now` is
`None`, both fall back to `datetime.now(timezone.utc)` (which is
acceptable per the documented contract — `now` is optional but
must be tz-aware if supplied; the engine supplies a tz-aware one
when `None`). The `produced_at` is the supplied `now`. CLOSED.

### F-11 — DISPROVED — Concern that timeline + severity engines import persistence / network / AI

Verified by `grep "import" app/timeline/ app/severity/`: no
`pymongo`, no `requests`, no `httpx`, no `urllib`, no `ml`, no
`numpy`, no `torch`, no `transformers`, no `sklearn`. Only
stdlib + pydantic + the documented application domain models.
CLOSED.

### F-12 — DISPROVED — Concern that timeline engine reads rule internals or computes new correlation

Verified: `app/timeline/engine.py` imports only `Correlation`,
`Detection`, `SecurityEvent`, and the `app.timeline` local
modules. It does not import
`app.correlation.engine` or `app.correlation.patterns` or
`app.rules`. CLOSED.

### F-13 — DISPROVED — Concern that endpoint string is echoed in `evidence_refs`

Verified: with `endpoint = "/admin/master-password?token=ATTACKER"`,
the per-detection `evidence_refs` are
`(det_id, event_id, "event:<id>:endpoint", "event:<id>:source_ip")`
— the endpoint string is not echoed. The structured marker
`event:<id>:endpoint` is a fixed-shape pointer, not a payload.
CLOSED.

### F-14 — UNVERIFIED RISK — Per-detection `endpoint_present` may influence future routing

The `AFFECTED_ENDPOINT` signal is `present=True` for any non-empty
`event.endpoint`. The endpoint value is attacker-controlled
(it's the request path). The signal contributes exactly one
## 4. Detailed Security Assessment

The Phase 4.6 brief requires me to threat-model the new
timeline + severity/confidence layer for the items below. For
each, I record the verdict, the evidence, and any
recommendation.

| Threat | Verdict | Evidence |
|---|---|---|
| **Attacker-controlled fields influencing severity/confidence incorrectly** | **PARTIALLY FAILED (F-1)** | `endpoint` and `source_ip` are bounded (1 point each, fixed). `RULE_CATEGORY` is supposed to be a high-impact flag for `common_behavioral` / `cross_source_correlation` rules but is dead due to F-1. The endpoint detail string in the per-detection rationale is misleading (claims a `common_behavioral` detection is "source_specific") — this is also an information-quality issue. |
| **Duplicate evidence inflating scores** | **PASS (with F-2 caveat)** | The engine scores each `(subject_kind, subject_id)` at most once. I verified with `check_dup_inflate.py`: 50 distinct detection_ids → 50 per-detection assessments, each at the same per-detection band as 1 detection. The **bundle** can grow up to the `MAX_SEVERITY_EVIDENCE_REFS = 32` cap; F-2 is what happens *past* that cap. |
| **Forged or substituted evidence references** | **PASS** | `_subject_id_matches_kind` validator in `app/severity/models.py:342-358` rejects `subject_id`s that don't carry the `det-` / `corr-` / `bundle:` prefix matching `subject_kind`. `_source_id_matches_kind` in `app/timeline/models.py:223-247` does the same for `TimelineItem.source_id`. |
| **Sensitive-data leakage into timeline / reasoning** | **PASS** | Verified per F-13. Only `event_type`, `source`, `source_ip`, `endpoint` (counted, not echoed), `rule_id`, `pattern_id`, `trigger`, `count`, `window_start`, `window_end` are surfaced. No `body_bytes_sent`, no `user_agent`, no `details["status_code"]`, no `details` at all. |
| **Malformed timestamps causing incorrect ordering** | **PASS** | A naive `event_time`, naive `detected_at`, naive `window_start` / `window_end`, or `window_end < window_start` is rejected by the timeline engine and the severity engine. The test `test_naive_event_dropped`, `test_naive_detection_dropped`, `test_correlation_window_end_before_start_dropped` cover this. Verified. |
| **Extreme timeline / event counts causing memory exhaustion** | **PASS for timeline; UNVERIFIED for severity (F-7)** | Timeline caps at `MAX_TIMELINE_ITEMS = 4096`; excess is dropped and reported via `errors`. Severity has no input cap (F-7). |
| **Oversized inputs** | **PARTIALLY FAILED (F-2, F-3, F-4)** | `MAX_SCORING_RATIONALS = 16` and `MAX_SEVERITY_EVIDENCE_REFS = 32` are enforced. `MAX_SEVERITY_RESULT_ASSESSMENTS = 32` and `MAX_SEVERITY_RESULT_ERRORS = 32` are dead constants (F-3, F-4). The bundle `evidence_refs` accumulator is unbounded (F-2). |
| **Score manipulation** | **PASS (with F-1 caveat)** | The score is a count of `present=True` signals from a closed catalogue. The thresholds are module-level constants; the engine does not read them from the request. Attacker cannot directly manipulate the score; they can only manipulate *which signals* are `present` via the evidence. F-1 makes the `RULE_CATEGORY` signal always `False` regardless of evidence — this means an attacker *cannot* force it `True` either, but they cannot benefit from a legitimate high-impact category either. The threat surface is *attacker-cannot-inflate*, not *attacker-cannot-deflate*. |
| **Incorrect default severity/confidence** | **PASS** | `bundle_severity` and `bundle_confidence` return `LOW` when no bundle assessment exists. Verified. |
| **Fail-open behavior** | **PASS** | Both engines are total: any malformed input is routed to `errors`; a per-subject exception is caught and quarantined. F-2 is a *fail-closed* exception (the engine raises instead of returning a `SeverityResult`), not fail-open. |
| **Information disclosure through errors** | **PASS** | All `safe_message` strings are constant (e.g. `"now must be a datetime"`, `"assessment.evidence_refs must contain at most …"`). The `internal_detail` is rendered into `errors` (the timeline / severity `errors` tuple); for timeline it includes the offending `event_id` / `detection_id` / `correlation_id`, which is fine because those ids are internal canonical ids, not user payloads. The severity engine's `errors` includes the offending subject id (`d.detection_id!r` or `c.correlation_id!r`); again, internal ids. No raw event payloads, no raw `details`. |
| **Cross-phase trust-boundary violations** | **PASS** | The engines consume `SecurityEvent` / `Detection` / `Correlation` only via the documented constructors and never read raw connector payloads (e.g. `NginxRecord` is not imported). |

---


point to the score, so it does **not** inflate the band beyond
MEDIUM. **However**, if Phase 4.7 routes on per-detection
`endpoint_present` (e.g. "endpoint with admin keyword → L2
analyst"), an attacker can route their traffic to a more
## 5. Evidence Principle Compliance

The brief requires the slice to keep `OBSERVED FACTS`,
`DERIVED CONCLUSIONS`, and `RECOMMENDATIONS` separate.

* `TimelineItem` is labelled as **organisation** of existing
  evidence. Its `kind` enum makes the source explicit. The
  `description` / `reasoning` strings always reference the
  source (`event_type`, `rule_id`, `pattern_id`, `trigger`),
  not a derived severity. PASS.
* `SeverityAssessment` is labelled as a **derived conclusion**.
  The model has no `is_fact` field; the band is the derived
  conclusion. The `subject_kind` enum
  (`DETECTION | CORRELATION | BUNDLE`) makes the subject
  explicit. The `rationale` is a closed-catalogue of signals
  with deterministic, evidence-anchored `detail` strings.
  PASS.
* No `RECOMMENDATION` is produced by either engine (that is
  the documented Phase 4.7 / routing engine's job). PASS.

One **soft** weakness: the per-detection rationale's detail
string for `RULE_CATEGORY` is misleading (F-1). It states
`"category=common_behavioral (per-event source_specific, not
high-impact)"` for a `COMMON_BEHAVIORAL` detection. This is a
violation of the "explain why it exists" rule because the
explanation is wrong. Recommend rewriting the detail.

---

## 6. Determinism & Repeatability

* The timeline engine is deterministic: same inputs + same `now`
  → same `TimelineResult`. Verified by
  `test_deterministic_repeat` in
  `tests/unit/test_timeline_engine.py` and by my independent
  reproducer.
* The severity engine is deterministic: same inputs + same
  `now` → same `SeverityResult`. Verified by
  `test_same_inputs_same_bands` in
  `tests/unit/test_severity_engine.py`.
* Both engines produce a UUIDv7-format id for the timeline
  (verified F-9) but **do not produce ids for the
  `SeverityAssessment`s**. This is consistent with the
  upstream `Detection` / `Correlation` models — the assessment
  is identified by its `(subject_kind, subject_id)` pair.

---

## 7. Test Suite Quality

### 7.1 Test counts (independently re-collected)

I ran `pytest --collect-only` on 2026-08-29:

```
collected 682 items
```

This matches the reported count in
`PHASE-04-06-REPORT.md:8`. I also ran the full suite in quiet
mode:

```
682 passed in 16.79s
```
## 8. Limitations of the Review

* I did not run the test suite under a memory profiler; my
  "memory exhaustion" claims (F-7) are static-analysis based
  on the absence of a top-level input cap.
* I did not run the engine with a 100K-detection input; the
  F-7 claim is about the absence of a guard, not a measured
  DoS.
* I did not modify any production code (per the brief). I
  only wrote review-only reproducer scripts and have since
  deleted them. I have **not** re-run my reproducers after
  deletion; the findings are based on the outputs I captured
  into `r1.txt` through `r8.txt` during the review.
* I trusted the `ScoringSignal` enum to have the 10 members
  declared in `app/severity/models.py:180-…`. I did not
  re-verify the enum has exactly the documented members, but
  the existing `test_signal_enum_has_documented_members` test
  in `tests/unit/test_severity_models.py` covers this.

---

## 9. What Phase 4.6 Gets Right

Despite the two defects, the slice has significant strengths
that should not be lost in the follow-up:

* The **closed-catalogue signal model** is a sound,
  defensible, and well-documented scoring approach. Each of
  the 10 `ScoringSignal` members is anchored to a documented
  evidence field; there is no statistical inference or hidden
  weighting. This is the right design.
* The **four-band / four-band scale** mirrors the documented
  MVP routing matrix and the 4.6 brief. Aliases
  (`Severity`, `SeverityLevel`, `Confidence`,
  `ConfidenceLevel`) are exported for forward compatibility.
* The **`subject_kind`-prefix binding** in the Pydantic
  validators (`det-`, `corr-`, `bundle:`) is an elegant
  evidence-traceability guard. PASS.
* The **determinism** of the timeline id and the in-memory
  result is solid. The SHA-1-seeded UUIDv7 derivation is
  reproducible and grep-friendly.
* The **no-correlation / no-severity / no-routing boundary**
  is clean. Neither engine imports the other; neither
  engine imports a later-phase module.
* The **`_evidence_refs` deduplication** in the per-event /
  per-correlation / per-detection builders is correct.
* The **string-truncation at construction time** (per
  `_truncate` helper) is a sensible defensive bound against
  oversized reasonings and summaries.
## 10. Final Verdict

**Phase 4.6 matches the project plan** (correct pipeline slot,
correct boundaries, no later-phase work, no AI, no
persistence, no connector coupling). **However, it is not
genuinely STABLE** as a result of two CONFIRMED DEFECTS:

* **F-1** — The `RULE_CATEGORY` signal is dead in all three
  scorers. A `COMMON_BEHAVIORAL` or `CROSS_SOURCE_CORRELATION`
  detection does not contribute to the score at all. This
  affects every per-detection, per-correlation, and bundle
  assessment in the slice.
* **F-2** — The severity engine crashes (un-caught
  `pydantic_core.ValidationError`) for any batch with more
  than 31 distinct detection_ids + correlation_ids in the
  bundle. This is well within the realistic input size for a
  brute-force correlation. The engine is not total for this
  case.

**The existing tests are not sufficient.** F-1 is invisible
because the tests assert signal **counts** but not signal
identity. F-2 is invisible because the largest batch in the
suite has 5–10 elements. Three test gaps (F-5, F-6, F-7) must
be closed.

**Recommendations (do not apply in this review):**

1. Fix F-1 in `app/severity/engine.py` (per-detection,
   per-correlation, bundle scorers) by replacing
   `str(d.category).endswith('common_behavioral')` with a
   `RuleCategory`-enum comparison.
2. Fix F-2 in `app/severity/engine.py` by bounding the
   bundle evidence_refs accumulator and by wrapping the
   `_score_bundle(...)` call in a try/except that routes
   failures to `errors`.
3. Fix F-3 and F-4 by adding `Field(max_length=…)` to the
   `severity_assessments`, `confidence_assessments`, and
   `errors` fields of `SeverityResult`, and by truncating
   the engine-side accumulators before construction.
4. Add the three missing tests (F-5, F-6, F-7) so the
   regressions are caught in CI.
5. Re-run the full test suite and the 8 reproducer claims
   in this review.

**Phase 4.6 is NOT STABLE.** It is stable on happy paths
and on small batches, and it is faithful to the documented
architecture. It is unstable on the most realistic attack
shape (a brute-force correlation backed by many distinct
detections). Once F-1 and F-2 are fixed and F-3–F-7 are
closed, the slice will be STABLE.

**Do not start Phase 4.7** until F-1 and F-2 are fixed and
the missing tests (F-5, F-6) are in place. Phase 4.7 will
consume `SeverityResult`; if `SeverityResult` can crash on
realistic input, Phase 4.7 inherits a fail-open / fail-closed
ambiguity that the brief explicitly forbids.

---

## Appendix A — Test counts independently re-collected

```
$ pytest --collect-only
================= test session starts =================
collected 682 items
```

```
$ pytest -q
........................................................................
........................................................................
........................................................................
........................................................................
........................................................................
........................................................................
........................................................................
........................................................................
........................................................................
..................................                                      
682 passed in 16.79s
```

---

## Appendix B — Review-only reproducers used (since deleted)

The following scripts were used to produce the evidence cited
in this review. They are review-only, are not part of the
production test suite, and have been deleted from the
repository at the end of the review.

| Script | Purpose | Finding |
|---|---|---|
| `check_rule_category_bug.py` | Run the engine with 7 `COMMON_BEHAVIORAL` detections and inspect the `RULE_CATEGORY` rationale signal. | F-1 |
| `check_per_det_signal.py` | Run the engine with 1 `COMMON_BEHAVIORAL` detection and dump the full per-detection rationale. | F-1 (per-detection) |
| `check_bundle_unbounded.py` | Run the engine with 40 distinct `source_specific` detections and assert that the engine produces a `SeverityResult`. | F-2 |
| `check_tl_id.py` | Call `_make_timeline_id` twice with the same triple and assert determinism + UUIDv7 pattern. | F-9 (DISPROVED) |
| `check_now.py` | Call both engines with `now=12345`, `now=naive_datetime`, and a tz-aware datetime. | F-10 (DISPROVED) |
| `check_dup_event.py` | Send 3 identical `SecurityEvent` references + 3 distinct detections to the timeline engine and assert dedup. | (verified — PASS) |
| `check_dup_inflate.py` | Run the severity engine with 50 distinct detections on 1 event and assert no per-detection band inflation. | F-1 (re-confirmed), F-2 (re-confirmed) |
| `check_endpoint_inflate.py` | Run the severity engine with an attacker-shaped endpoint `"/admin/master-password?token=ATTACKER"` and assert the band is unchanged and the endpoint string is not echoed. | F-13 (DISPROVED) |

Each reproducer's captured output is referenced inline in the
findings above (via `r1.txt` through `r8.txt`, since deleted
along with the scripts).

---

*End of Phase 4.6 Independent Deep Review*

* The **two integration tests** in
  `tests/integration/test_phase46_pipeline.py` are
  well-formed: one verifies the pipeline produces
  Phase 4.6 output on Phase 4.5 evidence; the other verifies
  the timeline engine does not call Phase 4.5 internals.
* The **Phase 4.5 contract is preserved**: I diffed the
  relevant `app.detection`, `app.correlation`, and
  `app.connectors` modules; no public symbol changed.
* The **`app/__init__.py` version bump** from `4.4.0` to
  `4.6.0` is correct (Phase 4.5 review already shipped
  `4.5.0`).
* The **report** is comprehensive and well-structured; my
  findings are independent of the report's claims and are
  based on direct code reading + reproducer evidence.

---



PASS on the count. But the **count is not the same as coverage**
of the documented threats.

### 7.2 What the Phase 4.6 test suite covers well

* Happy path: 1 event, 1 detection, 1 correlation → timeline
  has 3 items in order, severity produces 3 assessments.
* Edge cases: equal timestamps (with deterministic
  tie-breaking), out-of-order input, dedup, bounded size
  (`test_overflow_truncates_with_error`), malformed input
  (naive datetime, window_end < window_start, missing event
  lookup), frozen / extra=forbid on the Pydantic models.
* Adversarial input: `test_attacker_controlled_endpoint_low`
  verifies that an admin-shaped endpoint does not inflate the
  band.
* Determinism: `test_same_inputs_same_bands`,
  `test_deterministic_repeat`.
* Bundle / detection / correlation separation:
  `test_no_correlation_present_no_correlation_assessment`.
* Cross-phase integration: `test_phase46_pipeline.py` runs
  the full Phase 4.1 → 4.6 pipeline end-to-end and asserts the
  timeline uses only Phase 4.5 evidence.

### 7.3 What the Phase 4.6 test suite **does not** cover (test gaps)

* F-5 — No test asserts that the `RULE_CATEGORY` signal is
  `present=True` for a `COMMON_BEHAVIORAL` detection.
* F-6 — No test runs the engine with > 32 distinct
  evidence_refs. F-2 is invisible to the suite.
* F-7 — No memory / CPU pressure test. A 10K-detection run is
  not exercised.
* F-8 — No test exercises simultaneous event / detection /
  correlation replay with the same `event_id`.
* No test exercises the severity engine with a `Detection`
  whose `evidence_refs` field is empty (the current code uses
  `d.evidence_refs` only as a list, not a count, so the
  behaviour is well-defined — but untested).
* No test exercises a `Correlation` with empty `event_ids`
  (the code falls back to `window_span = 0`; behaviour is
  untested at the boundary).
* No test exercises a `SecurityEvent` with `event_time` in
  the **future** relative to `now`. The engine accepts it
  silently and orders the timeline item later than other
  evidence. This is a minor observation, not a defect —
  future-dated events can occur with clock skew — but it is
  untested.
* No test exercises a `Detection` with a category of unknown
  shape (e.g. a `str` rather than a `RuleCategory`). The
  `Detection` model validates `category`, so the engine should
  never see a malformed value — but the type-narrowing in
  `_score_detection` (`str(d.category).endswith(...)`) is
  defensive code that is not exercised by any test.

### 7.4 The `test_duplicate_detections_do_not_inflate_score` test is well-formed but weak

I read the test
(`tests/unit/test_severity_engine.py:322-…`). It uses **5**
identical detections (same `detection_id`). The assertion is
that the per-detection band is `LOW`. The test does **not**
exercise 50 distinct detection_ids (which is what F-2 is
about). The test passes today because N=5 < 32. The test
should be extended to N=100 to also assert that the engine
*does not crash* on a large batch.

---


senior queue by hitting an `admin`-shaped path. This is a
Phase 4.7 design concern, not a Phase 4.6 defect. LOGGED for
## 11. Post-review fixes (post-review-fix section)

This section was added after the review's initial verdict of
NOT STABLE. It records the remediations applied for F-1
through F-7, the regression tests that pin the new
behaviour, and the final verification. The original review
findings are preserved above; their statuses are marked
**FIXED ✅** or **TEST GAP RESOLVED ✅** in the classification
table at §1 and in the per-finding headers at §3.

### 11.1 F-1 — `RULE_CATEGORY` signal

**Confirmed defect.** The original
`str(d.category).endswith('common_behavioral')` check silently
never matched because `str(enum.Enum)` returns the member
name (e.g. `"RuleCategory.COMMON_BEHAVIORAL"`), not the value
(`"common_behavioral"`). All three scorers (per-detection,
per-correlation, bundle) used the same broken pattern.

**Fix applied.** A new helper
`_high_impact_category(category)` in
`app/severity/engine.py` does a direct enum-to-value
comparison:

```python
def _high_impact_category(category) -> bool:
    if category is None:
        return False
    return category.value in _HIGH_IMPACT_CATEGORIES
```

All three scorers now use this helper. The misleading
per-detection detail string that labelled a
`COMMON_BEHAVIORAL` detection as `"per-event source_specific"`
was rewritten to a non-misleading form.

**Regression test.** `tests/unit/test_severity_engine_regressions.py`
adds three classes (`TestF1RuleCategoryPerDetection`,
`TestF1RuleCategoryPerCorrelation`, `TestF1RuleCategoryBundle`)
with seven tests pinning positive (COMMON_BEHAVIORAL and
CROSS_SOURCE_CORRELATION fire) and negative (SOURCE_SPECIFIC
does not fire) cases for all three scorers. The independent
review's `verify_f1.py` reproducer now passes:

```
BUNDLE: RULE_CATEGORY present=True,
        detail='at least one detection is a high-impact category'
PASS
```

**Verification result.** The pre-fix F-1 reproducer
(`BUNDLE: RULE_CATEGORY present=False, detail='no high-impact
detection category'`) is no longer reproducible. F-1 is
**FIXED ✅**.

### 11.2 F-2 — Unbounded `evidence_refs` accumulator

**Confirmed defect.** Three call sites in
`app/severity/engine.py` accumulated `evidence_refs` of
arbitrary length:

### 11.4 F-5, F-6, F-7 — Test gaps

**F-5** (no test for `RULE_CATEGORY` flipping to `present=True`):
**TEST GAP RESOLVED ✅** by `TestF1RuleCategory*` (7 tests).
**F-6** (no test for > 32 evidence_refs): **TEST GAP RESOLVED ✅**
by `TestF2BundleEvidenceRefs` (3 tests). **F-7** (no
memory-pressure test): **TEST GAP RESOLVED ✅** by
`TestF7MemoryPressure` (1 test, 4× cap input).

### 11.5 F-8 — Same `event_id` replay

**Status: NOT FIXED in this pass.** The timeline engine's
deduplication is verified to work
(`test_duplicate_correlations_deduplicated`), and the per-event
deduplication is verified by an independent reproducer. F-8
is a low-priority test gap; the upstream correlation pattern
does not produce such duplicates. **LOGGED** as a follow-up
test.

### 11.6 F-9 through F-14 — Disproved / logged

No change. F-9, F-10, F-11, F-12, F-13 are **DISPROVED** as
written. F-14 is **LOGGED** for Phase 4.7 review.

### 11.7 Final verdict

**Phase 4.6 is STABLE.** The four CONFIRMED DEFECTS /
DESIGN WEAKNESSES are fixed; the three direct test gaps
(F-5, F-6, F-7) are closed; the full test suite
(700 / 700) passes; the Phase 4.1–4.5 pipeline behaviour is
unchanged. Phase 4.7 may begin when scheduled.

| Stage | Result |
|---|---|
| Independent review reproducers (`verify_f1.py`, `verify_f2.py`, `verify_f2_corr.py`, `verify_f3_f4.py`) | All pass against the fixed code |
| `tests/unit/test_severity_engine_regressions.py` (18 new tests) | 18 / 18 pass |
| `tests/unit/test_severity_engine.py` (original Phase 4.6 tests) | 18 / 18 pass |
| `tests/unit/test_severity_models.py` (original Phase 4.6 tests) | 27 / 27 pass |
| `tests/unit/test_timeline_*.py` (Phase 4.6 timeline tests) | 41 / 41 pass |
| Phase 4.6 integration (`tests/integration/test_phase46_pipeline.py`) | 2 / 2 pass |
| Phase 4.1–4.5 unit + integration | 594 / 594 pass |
| **Total full suite** | **700 / 700 pass** |

---

*End of Phase 4.6 Independent Deep Review (with post-review fixes)*
1. `_score_bundle` — `['bundle:overall'] + all
   detection_ids + all correlation_ids` (no cap).
2. `_score_correlation` — `[correlation_id] + all
   detection_ids + all event_ids` (no cap).
3. The bundle construction was called **outside** the
   per-subject `try/except`, so a `ValidationError` from the
   Pydantic `max_length=32` constraint on `evidence_refs`
   propagated uncaught out of `run()`.

**Fix applied.** Three mechanical changes:

1. `_score_bundle` now caps `evidence_refs` to
   `MAX_SEVERITY_EVIDENCE_REFS` (the synthetic
   `'bundle:overall'` is the first entry, then correlation
   ids, then detection ids — a deterministic, high-signal
   ordering).
2. `_score_correlation` now caps `evidence_refs` to
   `MAX_SEVERITY_EVIDENCE_REFS` (correlation_id first, then
   detection_ids, then event_ids, dedup, deterministic).
3. The `_score_bundle(...)` call is wrapped in a
   `try/except Exception` that quarantines any failure to
   `errors` and lets the engine return a valid
   `SeverityResult` (defense in depth).

**Regression test.** `tests/unit/test_severity_engine_regressions.py`
adds `TestF2BundleEvidenceRefs` (3 tests),
`TestF2PerCorrelationEvidenceRefs` (1 test), and
`TestF2BundleTryExcept` (1 test). The independent review's
`verify_f2.py` reproducer now passes:

```
OK: bundle produced; assessments=32;
errors=['severity engine input exceeded the documented
        maximum of 31 per-subject entries; dropped 9
        detection(s) and 0 correlation(s) to keep the bound']
```

**Verification result.** The pre-fix F-2 reproducer
(`pydantic_core._pydantic_core.ValidationError: assessment.evidence_refs
must contain at most 32 entries, got 41`) is no longer
reproducible. F-2 is **FIXED ✅**.

### 11.3 F-3 / F-4 — Dead result-list limits

**Confirmed design weakness.** The Pydantic model has no
`max_length` constraint on `severity_assessments`,
`confidence_assessments`, or `errors`, so the constants
`MAX_SEVERITY_RESULT_ASSESSMENTS = 32` and
`MAX_SEVERITY_RESULT_ERRORS = 32` were not enforced.

**Fix applied.** The engine is total, so the cap is enforced
at the engine boundary (not at the Pydantic layer — a
Pydantic-level cap would raise `ValidationError` and defeat
the goal of returning a valid `SeverityResult`). The engine
now:

1. Caps the input: `len(detections) + len(correlations)` is
   enforced to `MAX_SEVERITY_RESULT_ASSESSMENTS - 1` (the
   bundle always occupies the last slot). Excess is dropped
   to `errors`.
2. Caps the per-subject result: `severity_assessments` and
   `confidence_assessments` are capped to
   `MAX_SEVERITY_RESULT_ASSESSMENTS`. If exceeded, the
   oldest per-subject assessments are dropped FIFO
   (preserving the bundle, which is always the most recent).
3. Caps the errors: `errors` is capped to
   `MAX_SEVERITY_RESULT_ERRORS`. If exceeded, the oldest
   entries are dropped with a truncation note.

**Regression test.** `TestF3F4EngineSideCaps` (3 tests).

**Verification result.** F-3 and F-4 are **FIXED ✅**.


