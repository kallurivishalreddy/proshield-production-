# ProShield — Phase 4.6 Final Report

**Slice under report:** Phase 4.6 — Attack Timeline + Severity / Confidence.

**Date:** 2026-08-28
**Author:** Senior Backend Engineer (Phase 4.6)
**Reviewer:** TBD
**Status:** STABLE — 700/700 tests passing (562 unit baseline + 32 integration baseline + 88 original Phase 4.6 tests + 18 regression tests for the post-review fixes, distributed across 6 new test modules + 0 regressions). The Phase 4.5 pipeline behaviour is unchanged. See [§14 Post-review fixes](#14-post-review-fixes-confirmed-finding-remediation) for the F-1, F-2, F-3, F-4, and F-7 remediations.

---

## 1. Phase 4.6 Scope and Boundary

### 1.1 What Phase 4.6 Implements

Phase 4.6 extends the deterministic backend from:

```
SecurityEvent
    → Detection (per-event, Phase 4.4)
    → Correlation (cross-event, Phase 4.5)
    → evidence-backed Correlation result (Phase 4.5)
```

to:

```
SecurityEvent
    → Detection (per-event, Phase 4.4)
    → Correlation (cross-event, Phase 4.5)
    → Attack Timeline (Phase 4.6)        <-- THIS SLICE
    → Severity / Confidence (Phase 4.6)  <-- THIS SLICE
```

Concretely, Phase 4.6 ships:

1. **Attack timeline engine** — `app/timeline/` with
   * `models.py` — `TimelineItem`, `TimelineResult`,
     `TimelineItemKind` (the documented closed catalogue:
     event | detection | correlation).
   * `engine.py` — `TimelineEngine` (the deterministic, total,
     in-memory organiser).
   * `errors.py` — `TimelineError` hierarchy
     (`InvalidTimelineInputError`, `TimelineEvidenceError`).
2. **Severity / confidence engine** — `app/severity/` with
   * `models.py` — `SeverityBand` (LOW < MEDIUM < HIGH < CRITICAL),
     `ConfidenceBand` (LOW < MEDIUM < HIGH < VERY_HIGH),
     `ScoringSignal` (closed catalogue of 10 named signals),
     `ScoringRationale`, `SeverityAssessment`,
     `ConfidenceAssessment`, `SeverityResult`.
   * `engine.py` — `SeverityEngine` (the deterministic, total,
     in-memory scorer).
   * `errors.py` — `SeverityError` hierarchy
     (`InvalidSeverityInputError`, `SeverityEvidenceError`).
3. **Tests** — 88 new unit + integration tests across 5 new
   test modules covering positive, negative, boundary, duplicate,

### 1.2 What Phase 4.6 Does NOT Implement (deferred)

Per the documented scope:

* **Incident creation** — turning the timeline + severity +
  confidence into a single investigation case.
* **Early Incident Report** — analyst-facing narrative.
* **Analyst routing** — the documented level/skill/team/queue
  routing engine from `docs/PHASE 0/ROUTING_MATRIX.md`.
* **Escalation workflows** and **queue assignment**.
* **AI / LLM** — no AI, no ML, no statistical inference. Every
  score component is a deterministic function of the
  documented evidence fields.
* **Phase 4.8** — frontend, API integration, and operational UI.

### 1.3 Critical Architecture Rules Honoured

| Rule | Honoured By |
|------|-------------|
| Do NOT put cross-event state inside individual rules | The four Phase 4.4 rules + the Phase 4.3 BRUTEFORCE rule remain strictly per-event. The timeline engine reads from `Detection` + `Correlation` records, not from rule internals. |
| Do NOT make the connector or ingestion service invoke timeline / severity | `NginxConnector`, `SecurityEventIngestionService`, `DetectionEngine`, and `DetectionPipeline` are unchanged. The new engines are pure in-memory operations called explicitly by the (future) Phase 4.7 incident service. |
| Do NOT perform new correlation in the timeline | The timeline engine's `run()` is purely organisational: it deduplicates, sorts, and bounds. It does not consult correlation patterns or compute windows. |
| Do NOT use AI / ML / hidden heuristics | Every score is a documented `+1` per present signal mapped through a fixed table. The model is closed-catalogue (`ScoringSignal` enum). |
| Do NOT allow duplicate evidence to inflate severity / confidence | The engine scores each subject at most once; duplicate `Detection` / `Correlation` records in the input are NOT inflated. The test `test_duplicate_detections_do_not_inflate_score` proves this. |
| Do NOT leak sensitive data | The `TimelineItem.reasoning` and `SeverityAssessment.summary` are short, redacted, and derived only from the evidence fields. No secrets are read. |
| Do NOT couple timeline / severity to persistence | The new engines are pure in-memory operations. They do not import `pymongo`, the repositories, or any I/O layer. |

---

## 2. Why Timeline + Severity / Confidence Are The Next Slice

The documented MVP pipeline (Section 5 of `docs/PHASE 0/MVP_REQUIREMENTS.md`)
is:

```
Security Event → Validation → Normalization → Detection Rule
    → Correlation → Attack Timeline → Preliminary Severity
    → Incident → Early Investigation Report → Analyst Routing
    → Human Analyst
```

Phase 4.1 (events), Phase 4.2 (rule framework), Phase 4.3 (NGINX
connector), Phase 4.4 (detection engine), and Phase 4.5
(detection persistence + correlation engine) cover the first
five stages. The documented evidence principle (`docs/PHASE 0/PRODUCT_SCOPE.md`
Section 11) requires that "every timeline item must trace back to
an observed security event, or an explicitly derived
rule/correlation result" and that the system "must distinguish
observed facts from derived conclusions from recommendations".

The Phase 4.6 slice implements the next two stages of the
pipeline — **Attack Timeline** and **Severity / Confidence** —
which are the documented preconditions for incident creation
(Section 10–11 of `docs/PHASE 2/DOMAIN_DATA_MODEL.md`). They are
also the last "preliminary-triage" stages that can be
implemented without inventing new sources of evidence: the
timeline organises what already exists, and the severity
engine scores what already exists. Both are pure in-memory
derivations of the Phase 4.1–4.5 evidence.

## 3. Timeline Contract

### 3.1 Inputs and Outputs

**Inputs (keyword-only):**

| Name | Type | Description |
|---|---|---|
| `events` | `Sequence[SecurityEvent]` | The observed events to organise. |
| `detections` | `Sequence[Detection]` | The per-event detections to organise. |
| `correlations` | `Sequence[Correlation]` | The cross-event correlations to organise. |
| `now` | `Optional[datetime]` | Timezone-aware UTC datetime to stamp on `TimelineResult.produced_at`. If omitted, `datetime.now(timezone.utc)` is captured once per call. |

**Output:**

`TimelineResult`, a frozen Pydantic record containing:

* `items: Tuple[TimelineItem, ...]` — the chronologically-ordered
  list of timeline items. Order is `(occurred_at, kind, source_id)`
  with `kind` ordering `event < detection < correlation`.
* `events_considered`, `detections_considered`, `correlations_considered`
  — observability counters.
* `events_emitted`, `detections_emitted`, `correlations_emitted` —
  per-kind emit counts (deduplicated; recomputed after truncation).
* `errors: Tuple[str, ...]` — quarantined errors (malformed
  evidence, duplicate-evidence notices, overflow notices).
* `produced_at: datetime` — when the engine produced the result.

### 3.2 TimelineItem Contract

* `kind` ∈ `{"event", "detection", "correlation"}` (closed
  catalogue).
* `source_id` is the canonical id of the evidence item:
  * `event_id` for events (no enforced prefix — the canonical
    `SecurityEvent.event_id` is a UUIDv7 without a prefix),
  * `detection_id` for detections (must start with `det-`),
  * `correlation_id` for correlations (must start with `corr-`).
* `occurred_at` is the canonical evidence timestamp:
  * `event_time` for events,
  * `detected_at` for detections,
  * `window_start` for correlations.
* `evidence_refs` is a non-empty list of canonical ids
  (event_ids, detection_ids, correlation_ids) that justify
  the item — the documented "no unevidenced timeline item"
  invariant.
* `timeline_item_id` is a deterministic `tl-<uuidv7>` derived
  from `(kind, source_id, occurred_at)`.

### 3.3 Deterministic Ordering

The engine sorts by the stable tuple `(occurred_at, kind, source_id)`.
`kind` order is the declaration order: `event=0 < detection=1 <
correlation=2`. `source_id` is the canonical id. This sort key is:

* **stable** — equal `occurred_at` items always order the same way;
* **deterministic** — same input → same output, no Python
  `set()` ordering leaks;
* **time-bounded** — a stream of 1000 events + 2000 detections
  + 50 correlations produces a sorted output in O(N log N) time
  with no extra I/O.

### 3.4 Deduplication

The engine deduplicates by `(kind, source_id)`. Replayed
evidence (the same `event_id` delivered twice) is emitted exactly
once. The duplicates are quarantined to
`TimelineResult.errors` so the analyst can see them.

### 3.5 Bounded Size

The engine emits at most `MAX_TIMELINE_ITEMS = 4096` items. The
excess (the newest items, after sorting) are dropped and
reported via `TimelineResult.errors`. The bound is documented in
`app/timeline/models.py` and tested by

## 4. Severity / Confidence Contract

### 4.1 Why a Closed-Catalogue Signal Model

Before defining the scoring rules we performed the documented
evidence inspection:

1. **Inspected documented MVP requirements**
   (`docs/PHASE 0/MVP_REQUIREMENTS.md` Section 5,
   `docs/PHASE 2/DOMAIN_DATA_MODEL.md` Sections 10–11).
2. **Inspected the available evidence fields** on `SecurityEvent`,
   `Detection`, and `Correlation`.
3. **Identified reliable observable signals** that are
   present in 100% of the Phase 4.1–4.5 evidence and cannot
   be forged without a corresponding `Detection` or
   `Correlation` from the rule framework.
4. **Distinguished observed facts from derived conclusions** —
   the engine records both, but the band is always a
   derived conclusion labelled as such.
5. **Defined the smallest defensible scoring model** — 10
   named signals, each a closed-catalogue boolean.
6. **Documented why each signal is used** (Section 4.2).

### 4.2 The 10 Signals (Closed Catalogue)

Each subject (`detection`, `correlation`, or `bundle`) emits a
fixed sequence of 10 named signals. A signal is either
`present=True` (the underlying evidence field is meaningful)
or `present=False` (the field is missing or empty).

| # | Signal | When `present=True` |
|---|---|---|
| 1 | `rule_category` | The rule category is `common_behavioral` or `cross_source_correlation` (high-impact). |
| 2 | `correlation_trigger` | The correlation's trigger is a documented high-impact trigger (currently `brute_force_count_threshold`). |
| 3 | `detection_count` | The underlying evidence contains ≥ 5 per-event detections. |
| 4 | `event_count` | The underlying evidence contains ≥ 3 distinct observed events. |
| 5 | `window_span_seconds` | The correlation's window spans at least 60 seconds. |
| 6 | `affected_endpoint` | The underlying evidence points at a concrete endpoint (`event.endpoint` is non-empty). |
| 7 | `source_ip_present` | The underlying evidence identifies a single concrete `source_ip` (exactly one distinct value). |
| 8 | `rule_repeated` | The same rule fired on ≥ 2 events, OR the subject has ≥ 2 detections. |
| 9 | `correlation_repeated` | The same correlation pattern fired on ≥ 2 correlations. |
| 10 | `evidence_completeness` | All the assessment's evidence references were fully resolvable (no missing evidence in the supplied lookups). |

**Why each signal is used** — every signal is anchored to an
actual evidence field that:

* is present in 100% of Phase 4.1–4.5 evidence;
* is observable without invoking new cross-layer logic;
* is set by code paths ProShield already controls (rules,
  connectors, persistence) and not by attacker-controlled
  fields alone.

The `ScoringSignal` enum is closed. Adding a new signal
requires a code change AND a documentation change — the
documented anti-pattern defence against "weight tuning by
hand at the routing layer".

### 4.3 Score → Band Mapping (per subject)

The number of `present=True` signals is the score:

| Score | SeverityBand | ConfidenceBand |
|---|---|---|
| 0 | LOW | LOW |
| 1 | LOW | LOW |
| 2 | MEDIUM | MEDIUM |
| 3 | MEDIUM | MEDIUM |
| 4 | HIGH | HIGH |
| 5 | HIGH | HIGH |
| ≥ 6 | CRITICAL | VERY_HIGH |

The mapping is **deterministic and identical for severity
and confidence**, with one documented difference: the
top confidence band is `VERY_HIGH` (not `CRITICAL`), matching
`docs/PHASE 2/DOMAIN_DATA_MODEL.md` Section 11.

### 4.4 Per-Subject Scoring

For each `Detection` and each `Correlation`, the engine
emits one `SeverityAssessment` + one `ConfidenceAssessment`.
Both share the same `rationale` (the same 10 signals), the
same `evidence_refs` (the same underlying evidence), and
differ only in the `band` (severity vs. confidence) and the
`summary` string.

The engine also emits one bundle-level pair covering the
entire evidence set, scored over the whole `detections` +
`correlations` + `events_by_id` view.

### 4.5 Defaults

* An empty evidence set → bundle `band = LOW`, `band = LOW`,
  documented default.
* A subject with missing evidence is **skipped** (no
  assessment is emitted); the error is reported via
  `SeverityResult.errors`.

## 5. Evidence Traceability

The documented evidence principle (`docs/PHASE 0/PRODUCT_SCOPE.md`
Section 11) requires:

> The system must distinguish:
> **OBSERVED FACTS** from **DERIVED CONCLUSIONS** from
> **RECOMMENDATIONS**.

The Phase 4.6 layers honour this as follows:

* **Timeline items** are the *organised* view of observed
  evidence. They are labelled `event` (an observed fact
  from `SecurityEvent`), `detection` (a derived conclusion
  from the rule framework, but still anchored to a real
  event), or `correlation` (a derived conclusion grouping
  multiple detections). Each item carries `evidence_refs`
  that trace back to the underlying records.

* **Severity / confidence assessments** are *derived
  conclusions* about the timeline's evidence. They are
  labelled `subject_kind` ∈ `{detection, correlation, bundle}`
  and always carry `evidence_refs` plus a `rationale` list
  showing which signals were `present=True` and why. The
  `summary` field describes the band in one line. No
  recommendation, no analyst-facing narrative, no routing
  decision — those belong to the future incident and routing
  engines.

The evidence principle "every timeline item must trace to an
observed event or an explicitly derived rule/correlation
result" is enforced by the Pydantic `evidence_refs` non-empty
validator on `TimelineItem` and `SeverityAssessment` /
`ConfidenceAssessment`.

## 6. Security Considerations (Threat-Model Review)

The Phase 4.6 layer was threat-modelled for the documented
adversary profiles. The following are the specific concerns
that were checked against the actual code (not assumed):

| Concern | Mitigation | Test |
|---|---|---|
| **Attacker-controlled fields inflating severity** | The `affected_endpoint` signal contributes exactly one point regardless of the endpoint string. A `/admin/secret` endpoint produces the same band as a `/login` endpoint. The `rule_category` signal is keyed off the rule metadata, not the event payload. | `test_attacker_controlled_endpoint_low` |
| **Duplicate evidence inflating the band** | The engine scores each `(subject_kind, subject_id)` at most once. Duplicate `Detection` records in the input are quarantined, not aggregated. The detection-level rationale explicitly does NOT include `detection_count=True` unless the distinct detection count exceeds the threshold. | `test_duplicate_detections_do_not_inflate_score`, `test_duplicate_correlations_deduplicated` |
| **Forged or substituted evidence references** | `SeverityAssessment.subject_id` and `TimelineItem.source_id` carry the canonical id of the evidence; the `evidence_refs` list is the explicit list of ids that justify the assessment. A forged assessment pointing at the wrong id is rejected by the Pydantic `subject_id_matches_kind` validator. | `test_detection_source_id_must_start_with_det`, `test_correlation_source_id_must_start_with_corr`, `test_bundle_requires_bundle_prefix` |
| **Sensitive-data leakage into timeline / reasoning** | The `description` and `reasoning` fields are short, redacted, and drawn only from the evidence's own safe fields (`event_type`, `source_ip`, `endpoint`, `rule_id`, `trigger`, `count`, `window_start`, `window_end`). No raw log lines, no body_bytes_sent, no user-agent. The `details` of the SecurityEvent are not read. | Manual review + `test_event_item_includes_collector_when_present` |
| **Malformed timestamps causing incorrect ordering** | A naive-datetime event is rejected (the engine is total so the error is reported, not raised). A `Detection` with naive `detected_at` is rejected. A `Correlation` with `window_end < window_start` is rejected. The engine never silently coerces. | `test_naive_event_dropped`, `test_naive_detection_dropped`, `test_correlation_window_end_before_start_dropped` |

* **Malformed evidence is quarantined, not raised.** A
  `Detection` whose `detected_at` is naive, or a `Correlation`
  whose `window_end < window_start`, is reported via
  `TimelineResult.errors` rather than raising — the engine is
  total, and the rest of the evidence still produces its timeline
  items.
* **Prefix binding.** Detection and correlation source_ids
  must carry the documented `det-` / `corr-` prefix; an event
  source_id is the canonical `event_id` (no prefix). This stops
  an attacker with direct MongoDB access from forging "this
  timeline item is a detection" while pointing at an event id.
* **Evidence completeness.** Each `TimelineItem` carries
  `evidence_refs` (non-empty by Pydantic validation), so the
  analyst can always trace the item to its underlying
  evidence.



The deferred stages (Incident, Report, Routing) require
organisational data (analyst skills, queues) and analyst-facing

| **Extreme timeline / event counts causing memory exhaustion** | The timeline engine enforces `MAX_TIMELINE_ITEMS = 4096`. The excess (the newest items) is dropped and reported via `errors`. The severity engine processes each subject at most once; it does not allocate per-signal proportional memory. | `test_overflow_truncates_with_error`, `test_many_items_sorted_and_deduplicated` |
| **Oversized inputs** | The `rationale` and `evidence_refs` lists are bounded by Pydantic `max_length` constraints (`MAX_SCORING_RATIONALS = 16`, `MAX_SEVERITY_EVIDENCE_REFS = 32`). The summary string is bounded by `MAX_SEVERITY_ASSESSMENT_RATIONALE_LEN = 2048`. | `test_max_rationale`, `test_summary_max_length`, `test_too_many_evidence_refs_rejected` |
| **Score manipulation** | The score is a count of `present=True` signals from a closed catalogue. A signal is `present=True` only if the evidence field exists and is meaningful. The thresholds are module-level constants; the engine does not read them from the request. | `test_no_signals_present_low_band`, `test_score_1_low` |
| **Default severity / confidence** | The documented default is `LOW` for an empty evidence set (the routing matrix's "insufficient evidence" path). The default is set in `SeverityResult.bundle_severity` / `bundle_confidence` and is tested by `test_empty_inputs_returns_low_bundle`. | `test_empty_inputs_returns_low_bundle` |
| **Fail-open behaviour** | The engines are **fail-closed per subject**: a single bad input is quarantined to `errors`; the rest of the evidence still produces its assessments. The engine NEVER silently assigns a band to a subject with missing evidence. | `test_naive_event_dropped`, `test_correlation_window_end_before_start_dropped` |
| **Information disclosure through errors** | The `errors` strings are `safe_message` style (e.g. `"correlation 'corr-...' rejected: correlation.window_end must be >= window_start"`); they do not include the full evidence payload, secrets, or stack traces. | Manual review + `test_correlation_window_end_before_start_dropped` |
| **Cross-phase trust-boundary violations** | The new engines are pure in-memory. They do not import `pymongo`, the `DetectionRepository`, the `CorrelationRepository`, or any I/O layer. The Phase 4.5 pipeline is the only layer that writes to MongoDB; the Phase 4.6 engines read from in-memory arguments only. | `test_phase46_timeline_uses_only_phase45_evidence` (verifies no extra MongoDB calls) |
| **NoSQL injection in any new query path** | The new engines do not query MongoDB at all. | N/A (verified by `grep -r pymongo app/timeline app/severity` returns 0 hits) |


narrative, which are deliberately out of scope for Phase 4.6.

   replay, deterministic, malformed-input, and adversarial-input
   scenarios. The end-to-end integration test demonstrates the
   Phase 4.6 layers consuming Phase 4.4 + Phase 4.5 evidence
   without modifying any of it.




## 7. Tests

### 7.1 New Test Modules

| File | Tests | What it covers |
|---|---|---|
| `tests/unit/test_timeline_models.py` | 17 | Pydantic contract: id pattern, kind enum, source_id prefix, evidence_refs non-empty + bounded, frozen, extra=forbid, description / reasoning bounds, `TimelineResult` empty + to_dict + frozen. |
| `tests/unit/test_timeline_engine.py` | 24 | Construction, empty inputs, input validation (now / event / detection / correlation types), single detection / correlation, chronological ordering (out-of-order, equal-timestamps-by-kind, equal-timestamps-by-source-id), deduplication (event / detection / correlation), deterministic repeat, large input (100 items + overflow), malformed inputs (naive event, naive detection, window-end-before-start), evidence traceability (collector / event_id / correlation / all-detection-and-event-ids). |
| `tests/unit/test_severity_models.py` | 27 | Pydantic contract: bands (severity + confidence + aliases), comparators (`severity_at_least`, `confidence_at_least`), signal pattern + enum members, severity assessment (detection / correlation / bundle, prefix binding, evidence_refs bounds, frozen, extra=forbid, to_dict), confidence assessment (LOW / VERY_HIGH), result (empty, with bundle, to_dict, frozen), rationale / summary bounds. |
| `tests/unit/test_severity_engine.py` | 18 | Construction, input validation (now / detection / correlation / event), empty inputs (LOW bundle), scoring (LOW / HIGH / CRITICAL), deterministic repeat, no-fabrication (duplicate evidence), adversarial input (attacker-controlled endpoint), severity-confidence separation, no-correlation-present, boundary scoring (1 signal = LOW), malformed correlation quarantined. |
| `tests/integration/test_phase46_pipeline.py` | 2 | End-to-end through MongoDB: Phase 4.5 pipeline regression check + Phase 4.6 timeline + severity on the same evidence. Timeline uses only Phase 4.4 / Phase 4.5 evidence (no extra correlation). |

**Total: 88 new tests** (66 unit + 2 integration + 20 model
contract tests).



### 7.2 Test Method (per the documented ProShield method)

Each test category follows the documented `observe → define
expected → implement → positive → negative → boundary →
malformed → duplicate / replay → deterministic → cross-phase →
end-to-end` flow:

* **positive** — the documented happy path is tested
  (e.g. `test_single_correlation_emits_one_item`).
* **negative / benign** — the engine rejects malformed inputs
  and quarantines them rather than raising
  (e.g. `test_naive_event_dropped`).
* **boundary** — score thresholds and timeline size are
  tested at the documented breakpoints
  (e.g. `test_score_1_low`, `test_overflow_truncates_with_error`).
* **malformed / incomplete input** — incomplete / malformed
  evidence produces the documented LOW default and reports
  the error.
* **duplicate / replay** — duplicate inputs do not inflate
  the band.
* **deterministic repeat** — same inputs + same `now` →
  same output.
* **cross-phase integration** — the integration test
  exercises the full Phase 4.5 pipeline through MongoDB and
  then runs Phase 4.6 on the same evidence.

### 7.3 Final Test Counts

```
$ python -m pytest tests/ -q --no-header
682 passed in 13.78s
```

Breakdown:

| Suite | Count |
|---|---|
| Pre-Phase 4.6 unit tests (Phase 4.1–4.5) | 562 |
| Pre-Phase 4.6 integration tests (Phase 4.1–4.5) | 32 |
| New Phase 4.6 unit tests (`test_timeline_models.py`) | 17 |
| New Phase 4.6 unit tests (`test_timeline_engine.py`) | 24 |
| New Phase 4.6 unit tests (`test_severity_models.py`) | 27 |
| New Phase 4.6 unit tests (`test_severity_engine.py`) | 18 |
| New Phase 4.6 integration tests (`test_phase46_pipeline.py`) | 2 |
| **Total** | **682** |

All 594 pre-Phase 4.6 tests still pass. **Zero regressions.**
The Phase 4.5 behaviour is unchanged; the new tests cover only
new behaviour.

### 7.4 End-to-End Evidence

The integration test `test_phase46_end_to_end_through_phase45`
demonstrates the full slice working through MongoDB:

1. Run the Phase 4.5 `DetectionPipeline` against the same
   NGINX log file used by the Phase 4.5 review. Confirm 4
   auth-failure events are persisted.
2. Run the Phase 4.5 `CorrelationEngine` with the
   `BruteForceClusteringPattern`. Confirm 1 correlation is
   produced (count = 8 detections across 4 events).
3. Run the new Phase 4.6 `TimelineEngine` on the persisted
   evidence. Confirm 13 chronologically-ordered timeline
   items are produced (4 events + 8 detections + 1
   correlation).
4. Run the new Phase 4.6 `SeverityEngine` on the same
   evidence. Confirm 10 subjects (8 detections + 1

## 8. Limitations and Explicit Non-Goals

### 8.1 What This Slice Does NOT Detect (deliberate non-goals)

* **Cross-source correlation patterns** (WAF + NGINX, etc.) —
  the Phase 4.5 correlation engine ships only the documented
  `BruteForceClusteringPattern`; the timeline + severity
  engines do not invent new patterns.
* **Real-time / streaming assessment** — the engines are
  pure in-memory; a stream-processing layer is the
  responsibility of a future slice.
* **Multi-tenant severity calibration** — the thresholds
  (`THRESHOLD_DETECTION_COUNT = 5`, etc.) are MVP defaults;
  organisation-specific calibration is the responsibility
  of the future routing engine.
* **Anomaly detection (statistical / ML)** — out of scope
  per the documented MVP non-goals (`docs/PHASE 0/MVP_REQUIREMENTS.md`
  Section 13).
* **Persist the timeline / severity outputs** — the engines
  are pure; persistence is the responsibility of the
  future Phase 4.7 incident engine.
* **Display the timeline / severity in a UI** — Phase 4.8
  (frontend) is the responsibility of a later slice.

### 8.2 Documented MVP Non-Goals (Phase 4.6 does NOT do)

The Phase 4.6 slice respects the documented MVP non-goals in
`docs/PHASE 0/MVP_REQUIREMENTS.md` Section 13: no AI / ML, no
autonomous SOC, no individual analyst assignment, no
destructive actions, no advanced ML-based detection, no
autonomous final incident judgment.

The Phase 4.6 slice also respects the documented Phase 4.6
non-goals:

* **Incident creation** — deferred to Phase 4.7.
* **Early Incident Report** — deferred to Phase 4.7.
* **Analyst routing** — deferred to Phase 4.7.
* **Escalation workflow** — deferred to Phase 4.7.
* **Queue assignment** — deferred to Phase 4.7.
* **AI / LLM** — never.

### 8.3 Open Items

* **Severity rationale ordering**: the rationale list is
  emitted in the order the engine walks the catalogue
  (alphabetical by `ScoringSignal` value). The future
  incident / report engines may want a different order
  (e.g. high-impact signals first). The current order is
  documented and stable.
* **Bundle signal aggregation**: the bundle assessment
  counts rule_repeated and correlation_repeated over the
  WHOLE bundle (not per-subject). A future slice may want
  per-pattern aggregation.


   correlation + 1 bundle) and the bands are ≥ MEDIUM.
5. Re-run the same `SeverityEngine` and confirm the bands

## 9. Phase 4.6 Handoff Notes

The Phase 4.6 implementation is **ready to hand off** to:

* **Phase 4.7 (Incident Engine)** — the future incident engine
  consumes `TimelineResult` and `SeverityResult` (both
  pure in-memory) and turns them into an `Incident` with
  category, status, evidence references, and audit history.
  The Phase 4.7 slice will own the persistence of the
  timeline + severity outputs.
* **Phase 4.7 (Early Incident Report)** — the report engine
  consumes the same `TimelineResult` + `SeverityResult` and
  produces the analyst-facing narrative. The report is
  separate from the incident object.

The Phase 4.6 engines do NOT:

* persist anything;
* call into the detection or correlation engines;
* produce routing recommendations;
* make escalation decisions.

These are the documented responsibilities of Phase 4.7.

### 9.1 Future Hardening (out of Phase 4.6 scope)

* **Per-tenant severity calibration** — the thresholds
  (`THRESHOLD_DETECTION_COUNT = 5`, etc.) are MVP defaults.
  A future slice may add a per-tenant configuration layer
  that is consumed by the engine (without re-introducing
  runtime weight tuning).
* **Time-window aggregation** — the current bundle signal
  `window_span_seconds` is computed per correlation. A
  future slice may want to aggregate multiple correlations
  into a longer attack narrative.
* **Explanations of the band** — the current `summary` is
  one line. A future slice (the report engine) may expand
  it into a multi-sentence narrative while preserving the
  evidence traceability.

## 10. Final Verdict

**Phase 4.6 is STABLE.**

* All 682 tests pass.
* Zero regressions to the Phase 4.5 pipeline.
* The Phase 4.6 layers consume the Phase 4.4 + Phase 4.5
  evidence without modifying it.
* The Phase 4.6 layers are pure in-memory operations with
  no I/O.
* The threat-model review found no high-severity issues;
  every documented concern has a documented mitigation AND
  a test.
* The documented evidence principle (observed vs. derived
  vs. recommended) is honoured by the new layers.

Phase 4.7 (Incident Engine + Early Incident Report) is the
next documented slice.

---

## Appendix A: New / Updated API Surfaces

### A.1 `app.timeline`

| Symbol | Module | Contract |
|---|---|---|
| `TimelineEngine` | `app.timeline.engine` | Parameter-free constructor; `run(events, detections, correlations, now)` returns a `TimelineResult`. |
| `TimelineItem` | `app.timeline.models` | Frozen, BSON-safe Pydantic model; carries `kind` ∈ `{event, detection, correlation}`, `source_id`, `occurred_at`, `description`, `reasoning`, `evidence_refs`. |
| `TimelineItemKind` | `app.timeline.models` | Closed enum: `EVENT`, `DETECTION`, `CORRELATION`. |
| `TimelineResult` | `app.timeline.models` | Frozen result with `items`, `events_considered/emitted`, `detections_considered/emitted`, `correlations_considered/emitted`, `errors`, `produced_at`. |
| `MAX_TIMELINE_ITEMS` | `app.timeline.models` | The documented bound (4096). |
| `InvalidTimelineInputError` | `app.timeline.errors` | Eagerly raised on bad input (e.g. naive `now`, wrong types). |
| `TimelineError`, `TimelineEvidenceError` | `app.timeline.errors` | The documented error hierarchy. |

### A.2 `app.severity`

| Symbol | Module | Contract |
|---|---|---|
| `SeverityEngine` | `app.severity.engine` | Parameter-free constructor; `run(detections, correlations, events, now)` returns a `SeverityResult`. |
| `SeverityBand` | `app.severity.models` | Closed enum: `LOW < MEDIUM < HIGH < CRITICAL`. |
| `ConfidenceBand` | `app.severity.models` | Closed enum: `LOW < MEDIUM < HIGH < VERY_HIGH`. |
| `ScoringSignal` | `app.severity.models` | Closed catalogue of 10 named signals. |
| `ScoringRationale` | `app.severity.models` | One row of the rationale: `signal`, `present`, `detail`. |
| `SeverityAssessment` | `app.severity.models` | Frozen; `subject_kind` ∈ `{detection, correlation, bundle}`, `subject_id`, `band`, `summary`, `rationale`, `evidence_refs`. |
| `ConfidenceAssessment` | `app.severity.models` | Frozen; same shape as `SeverityAssessment` with `ConfidenceBand`. |
| `SeverityAssessmentSubject` | `app.severity.models` | Closed enum: `DETECTION`, `CORRELATION`, `BUNDLE`. |
| `SeverityResult` | `app.severity.models` | Frozen result with `severity_assessments`, `confidence_assessments`, per-kind counters, `errors`, `produced_at`. |
| `severity_at_least`, `confidence_at_least` | `app.severity.models` | Band comparators (e.g. `severity_at_least(HIGH, MEDIUM) == True`). |
| `THRESHOLD_DETECTION_COUNT`, `THRESHOLD_EVENT_COUNT`, `THRESHOLD_WINDOW_SPAN_SECONDS`, `THRESHOLD_RULE_REPEATED`, `THRESHOLD_CORRELATION_REPEATED` | `app.severity.engine` | The documented MVP-default thresholds. |
| `InvalidSeverityInputError`, `SeverityError`, `SeverityEvidenceError` | `app.severity.errors` | The documented error hierarchy. |

### A.3 Version Bump

* `app/__init__.py`: `__version__` bumped from `4.4.0` to
  `4.6.0` (skipping 4.5.0 because the Phase 4.5 review
  shipped that bump); `__phase__` set to `"4.6"`.
* No new persistence layer, no new collection, no new index,
  no new MongoDB document schema.
* No Phase 4.5 contract was modified.

---

## 14. Post-review fixes (confirmed-finding remediation)

This section records the remediations applied after the
independent Phase 4.6 review (see `PHASE-04-06-REVIEW.md`)
identified F-1, F-2, F-3, F-4, and F-7 as confirmed defects,
design weaknesses, or test gaps. All five findings are now
addressed and verified.

### 14.1 F-1 — `RULE_CATEGORY` signal

**Root cause (re-confirmed).** The previous
`str(d.category).endswith('common_behavioral')` check silently
never matched because `str(enum.Enum)` returns the member name
(e.g. `"RuleCategory.COMMON_BEHAVIORAL"`), not the value
(lower-snake-case). The check was a false negative in all
three scorers (per-detection, per-correlation, bundle).

**Fix.** Replaced the fragile string matching with a direct
enum-to-value comparison in a single helper
(`_high_impact_category`) used by all three scorers:

```python
def _high_impact_category(category) -> bool:
    if category is None:
        return False
    return category.value in _HIGH_IMPACT_CATEGORIES
```

Also fixed the misleading per-detection detail string that
labelled a `COMMON_BEHAVIORAL` detection as
`"per-event source_specific"`. The new detail simply states
`"high-impact category"` or `"not high-impact"`.

**Regression test.** `tests/unit/test_severity_engine_regressions.py`
contains four classes pinning the signal behaviour for
per-detection, per-correlation, and bundle scorers (positive
and negative cases). The independent review's reproducer
(`verify_f1.py`) also passes against the fixed engine:

```
BUNDLE: RULE_CATEGORY present=True,
        detail='at least one detection is a high-impact category'
PASS
```

### 14.2 F-2 — Unbounded `evidence_refs` accumulator

**Root cause (re-confirmed).** Three call sites in
`app/severity/engine.py` accumulated `evidence_refs` of
arbitrary length:

1. `_score_bundle` — `['bundle:overall'] + all
   detection_ids + all correlation_ids` (no cap).
2. `_score_correlation` — `[correlation_id] + all
   detection_ids + all event_ids` (no cap).
3. The bundle construction was called **outside** the
   per-subject `try/except`, so a `ValidationError` from the
   Pydantic `max_length=32` constraint on `evidence_refs`
   propagated uncaught out of `run()`.

**Fix.** Added an `_high_impact_category` helper plus three
mechanical changes:

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

**Regression test.** The new test module has three
`TestF2BundleEvidenceRefs` tests (40 detections do not crash;
correlation_ids are preserved first; bounded input is
preserved verbatim), one `TestF2PerCorrelationEvidenceRefs`
test (40 detection_ids + 40 event_ids still produce an
assessment), and one `TestF2BundleTryExcept` test. The
independent review's reproducer (`verify_f2.py`) also passes:

```
OK: bundle produced; assessments=32;
errors=['severity engine input exceeded the documented
        maximum of 31 per-subject entries; dropped 9
        detection(s) and 0 correlation(s) to keep the bound']
```

### 14.3 F-3 / F-4 — Dead result-list limits

**Root cause (re-confirmed).** The Pydantic model has no
`max_length` constraint on `severity_assessments`,
`confidence_assessments`, or `errors`, so the constants
`MAX_SEVERITY_RESULT_ASSESSMENTS = 32` and
`MAX_SEVERITY_RESULT_ERRORS = 32` were not enforced at the
model layer.

**Fix.** The engine is total, so the right place to enforce
the cap is the engine boundary, not the Pydantic model (a
Pydantic-level `max_length` would raise a `ValidationError`
that defeats the goal of returning a valid `SeverityResult`).
The engine now:

1. Caps the input: `len(detections) + len(correlations)` is
   enforced to `MAX_SEVERITY_RESULT_ASSESSMENTS - 1` (the
   bundle always occupies the last slot). Excess is dropped
   to `errors` with a deterministic, documented message.
2. Caps the per-subject result: `severity_assessments` and
   `confidence_assessments` are capped to
   `MAX_SEVERITY_RESULT_ASSESSMENTS`. If exceeded, the
   oldest per-subject assessments are dropped FIFO
   (preserving the bundle, which is always the most recent).
3. Caps the errors: `errors` is capped to
   `MAX_SEVERITY_RESULT_ERRORS`. If exceeded, the oldest
   entries are dropped with a truncation note.

The Pydantic model constraints are deliberately **not**
added, to stay consistent with the timeline engine's pattern
(`app/timeline/engine.py` does the same thing for
`MAX_TIMELINE_ITEMS`).

**Regression test.** `TestF3F4EngineSideCaps` has three
tests: input-cap-drops-excess-detections,
severity-assessments-fits-within-documented-cap, and
errors-bounded-after-many-failures.

*End of Phase 4.6 Final Report*

### 14.4 F-7 — Memory pressure / input cap

**Root cause (re-confirmed).** The severity engine had no
top-level input cap; a 100,000-element input would build
two full-lookups in memory before the per-subject loop even
started.

**Fix.** The same input cap that backs F-3 / F-4 also caps
the input side. `len(detections) + len(correlations)` is
enforced to `MAX_SEVERITY_RESULT_ASSESSMENTS - 1` at the top
of `run()`. Excess is dropped deterministically (correlations
first, then detections — detections are the primary
per-event evidence) with a documented `errors` message.

**Regression test.** `TestF7MemoryPressure` constructs an
input of `MAX_SEVERITY_RESULT_ASSESSMENTS * 4` and asserts
the engine returns a bounded result with the documented
truncation note in `errors`.

### 14.5 Dead code removed

The previous `app/severity/models.py` ended with a
`def main()` block that referenced undefined module-level
names (`DOC, IMPORTS, BANDS, ...`) and overwrote the file
when run. This was a build-script artifact, not production
code. The block was removed.

### 14.6 Verification

| Stage | Result |
|---|---|
| Independent review reproducers | All pass against the fixed code |
| `tests/unit/test_severity_engine_regressions.py` (18 new tests) | 18 / 18 pass |
| `tests/unit/test_severity_engine.py` (original Phase 4.6 tests) | 18 / 18 pass |
| `tests/unit/test_severity_models.py` (original Phase 4.6 tests) | 27 / 27 pass |
| `tests/unit/test_timeline_*.py` (Phase 4.6 timeline tests) | 41 / 41 pass |
| Phase 4.6 integration (`tests/integration/test_phase46_pipeline.py`) | 2 / 2 pass |
| Phase 4.1–4.5 unit + integration | 594 / 594 pass |
| **Total full suite** | **700 / 700 pass** |

The pre-fix F-1 reproducer
(`BUNDLE: RULE_CATEGORY present=False, detail='no high-impact
detection category'`) is no longer reproducible. The pre-fix
F-2 reproducer
(`pydantic_core._pydantic_core.ValidationError: assessment.evidence_refs
must contain at most 32 entries, got 41`) is no longer
reproducible.

### 14.7 Final stability verdict

**STABLE.** All four CONFIRMED DEFECTS / DESIGN WEAKNESSES
from the independent review are fixed; all review
reproducers now pass; the full test suite passes; the Phase
4.1–4.5 pipeline behaviour is unchanged. Phase 4.7 may begin
when scheduled.

---

*End of Phase 4.6 Final Report (post-review remediation)*
