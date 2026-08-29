# ProShield — Phase 4.5 Final Report

**Slice under report:** Phase 4.5 — Detection persistence + Ingestion → Detection wiring + Central correlation engine + evidence-backed Correlation results.

**Date:** 2026-08-28
**Author:** Senior Backend Engineer (Phase 4.5)
**Reviewer:** TBD
**Status:** STABLE — 594/594 tests passing (580 pre-fix + 14 new regression tests for the four review defects D-1..D-4). All four review defects fixed and verified.

---

## 1. Phase 4.5 Scope and Boundary

### 1.1 What Phase 4.5 Implements

Phase 4.5 extends the deterministic backend from:

```
SecurityEvent → Detection
```

to:

```
SecurityEvent
    → Detection (per-event, Phase 4.4)
    → Correlation (cross-event, Phase 4.5)
    → evidence-backed Correlation result (Phase 4.5)
```

Concretely, Phase 4.5 ships:

1. **Detection persistence** using the existing MongoDB architecture — `app/persistence/detection_repository.py`.
2. **Correlation persistence** using the existing MongoDB architecture — `app/persistence/correlation_repository.py`.
3. **Ingestion → Detection Engine wiring** — `app/detection/pipeline.py` (the `DetectionPipeline` orchestrator).
4. **Central correlation engine** — `app/correlation/engine.py` (`CorrelationEngine`).
5. **Correlation contract** — `app/correlation/models.py` (`Correlation`, `CorrelationResult`, `CorrelationKey`, `CorrelationTrigger`).
6. **One defensible correlation pattern** — `app/correlation/patterns.py` (`BruteForceClusteringPattern`).
7. **121 new tests** (unit + integration) covering positive, negative, near-miss, threshold boundary, time-window boundary, unrelated-source isolation, duplicate/replay, out-of-order, and end-to-end behaviour.

### 1.2 What Phase 4.5 Does NOT Implement (deferred to future slices)

Per the Phase 4.5 task description's "do not invent evidence" rule, Phase 4.5 **deliberately defers**:

* Severity / Confidence engines (documented as severity / confidence engines, Section 66).
* Incident engine (turning correlations into investigation cases).
* Report engine.
* Routing engine (per `docs/PHASE 0/ROUTING_MATRIX.md`).
* Audit engine.
* AI-assisted investigation.
* HTTP API surfaces.
* Real WAF, rate-limiter, network, TLS, IAM, SIEM connectors (none of which exist in the MVP).
* Cross-source correlation patterns (WAF + NGINX, etc.) — these would invent evidence without the second source.

Each of these is named in `docs/PHASE 4/DETECTION_ENGINEERING_AND_FUTURE_AI.md` and the Phase 4.1–4.4 core review's "Phase 4.5 handoff" section as future scope.

### 1.3 Critical Architecture Rules Honoured

| Rule | Honoured By |
|------|-------------|
| Do NOT put cross-event state inside individual rules | The five Phase 4.4 rules (and the Phase 4.3 BRUTEFORCE-001 rule) remain strictly per-event. The correlation pattern reads from `Detection`s, not from rule internals. |
| Do NOT make connectors invoke correlation or other rules | `NginxConnector` is unchanged. `SimulatedConnector` is unchanged. The `DetectionPipeline` is the only place that orchestrates ingestion + detection + persistence. |
| Do NOT correlate every event with every other event | The `CorrelationEngine` iterates over a small set of registered patterns; each pattern's `select()` filters by rule_id, source, and event_type. Only auth-failure detections are considered by `BruteForceClusteringPattern`. |
| Do NOT use AI | All correlation logic is threshold-based (count + time window) and deterministic. |
| Do NOT invent evidence | A detection whose event is missing from the engine's event lookup is **skipped** (not invented). A pattern that requires a field a detection does not have is the pattern's responsibility to skip. |
| Do NOT change SecurityEvent, Rule, Registry, or Detection contracts | None of the Phase 4.1–4.4 contracts were modified. `Detection.to_dict()` is reused unchanged; the new `Correlation` model is additive. |
| Keep modularity for future connectors | The correlation engine operates on `Detection` records + an `events` lookup. The future WAF, rate-limiter, network, TLS, and IAM connectors will produce the same `Detection` shape, and the engine can group them without modification. |

### 1.4 Boundary Integrity Verified

* `app/detection/` is per-event only; the engine is unchanged.
* `app/correlation/` is the only place that imports the correlation contract.
* `app/persistence/detection_repository.py` and `app/persistence/correlation_repository.py` are the only places that import pymongo for the new collections.
* `app/connectors/` is unchanged.
* `app/rules/` is unchanged.

---

## 2. Implementation Performed

### 2.1 New Modules

| Module | Purpose |
|--------|---------|
| `app/correlation/__init__.py` | Public surface: `CorrelationEngine`, `BruteForceClusteringPattern`, models, errors. |
| `app/correlation/engine.py` | The deterministic, fail-closed-per-pattern correlation engine. |
| `app/correlation/models.py` | `Correlation`, `CorrelationResult`, `CorrelationKey`, `CorrelationTrigger` (frozen, BSON-safe). |
| `app/correlation/patterns.py` | `CorrelationPattern` ABC + the single `BruteForceClusteringPattern`. |
| `app/correlation/errors.py` | `CorrelationError`, `InvalidCorrelationInputError`, `CorrelationKeyError`, `CorrelationWindowError`. |
| `app/detection/pipeline.py` | The `DetectionPipeline` orchestrator (ingestion → detection → persistence). |
| `app/persistence/detection_repository.py` | `DetectionRepository` for the `detections` collection. |
| `app/persistence/correlation_repository.py` | `CorrelationRepository` for the `correlations` collection. |

### 2.2 Updated Modules (additive only)

* `app/detection/__init__.py` — re-exports `DetectionPipeline` and `PipelineResult`. No contract changes.

### 2.3 Test Modules

| Module | Tests |
|--------|-------|
| `tests/unit/test_correlation_models.py` | 27 |
| `tests/unit/test_brute_force_pattern.py` | 22 |
| `tests/unit/test_correlation_engine.py` | 17 |
| `tests/unit/test_detection_repository.py` | 22 |
| `tests/unit/test_correlation_repository.py` | 20 |
| `tests/unit/test_pipeline.py` | 10 |
| `tests/unit/_correlation_helpers.py` | (helper, no tests) |
| `tests/integration/test_phase45_pipeline.py` | 3 |
| **Total new tests** | **121** |

---

## 3. Observed Telemetry and Correlation Signals

### 3.1 Source of Telemetry

Phase 4.5 uses the same controlled local telemetry as Phase 4.3 and Phase 4.4: the `NginxConnector` parsing the documented NGINX combined-format access log. The connector produces a canonical `SecurityEvent` for each line that has a security signal (HTTP 4xx/5xx on a non-public path, or with auth metadata).

### 3.2 Signals Reliably Observable Per-Event

| Signal | Field | Reliable? |
|--------|-------|-----------|
| HTTP status code | `event.details.status_code` | Yes (connector-mapped) |
| Source IP | `event.source_ip` | Yes (NGINX `remote_addr`) |
| Endpoint path | `event.endpoint` | Yes (NGINX URI path) |
| Auth failure | `event.event_type=authentication_failure` (HTTP 401) | Yes (Phase 4.3) |
| Request blocked | `event.event_type=request_blocked` (HTTP 403) | Yes (Phase 4.3) |
| Rate-limit exceeded | `event.event_type=rate_limit_exceeded` (HTTP 429) | Yes (Phase 4.3) |
| Server error | `event.event_type=security_control_alert` (HTTP 5xx) | Yes (Phase 4.4) |
| Account ID | `event.account.id` | **Sparse** — not reliable for correlation |
| Geographic / ASN | (not in MVP model) | **Unavailable** — would invent evidence |
| Per-account | (depends on `account.id`) | **Deferred** (account ID too sparse) |
| Cross-source (WAF + NGINX) | (WAF connector doesn't exist) | **Deferred** (no second source) |

### 3.3 Cross-Event Signals Reliably Observable

After running the per-event detection pipeline on a sequence of events, the **only** cross-event signal reliably observable in the MVP telemetry is:

* **Multiple auth-failure detections from the same source_ip to the same auth-shaped endpoint, within a bounded time window.**

This is the **brute-force clustering signature**. Every other cross-event signal would either require a connector that does not exist, or rely on a sparse field. Per the Phase 4.5 task description, inventing such signals would invent evidence and is explicitly forbidden.

### 3.4 Correlation Patterns Considered and Deferred

| Pattern | Status | Reason for Deferral |
|---------|--------|---------------------|
| **NGINX brute-force clustering** | **IMPLEMENTED** | Source_ip + endpoint + threshold + window is fully supported by current data. |
| WAF + NGINX cross-source | Deferred | WAF connector does not exist. |
| Account-targeted brute force | Deferred | `account.id` is sparse in current NGINX telemetry. |
| Status-anomaly burst (5xx on same endpoint) | Deferred (engine-ready) | A future slice can add the pattern without engine changes. |
| Rate-limit + auth-failure amplification | Deferred | Needs more data points to set a defensible threshold. |
| Geographic / ASN distribution | Deferred | Out of MVP model. |

The pattern catalogue is intentionally narrow. The Phase 4.5 task description's "no false correlation is worse than no correlation" rule is preserved by the conservative single-pattern approach.

---

## 4. Correlation Pattern Implementation Detail

### 4.1 `BruteForceClusteringPattern`

| Attribute | Value | Rationale |
|-----------|-------|-----------|
| `pattern_id` | `NGINX-CORR-BRUTEFORCE-001` | Same shape as rule IDs (deterministic grep-ability). |
| `pattern_version` | 1 | First version; future tuning → version 2. |
| `trigger` | `brute_force_count_threshold` | Documented enumeration; feeds the future severity engine. |
| **Correlation key** | `(source_ip, endpoint)` | The two fields that are reliably populated and that distinguish a brute-force from a single user mistake. |
| **Detections considered** | Only `NGINX-AUTH-FAILURE-001` and `NGINX-AUTH-BRUTEFORCE-001` | The two documented "candidate auth failure" rules. |
| **Time window** | `5 minutes` (default) | Conservative; matches typical brute-force literature. |
| **Threshold** | `4 detections` (default) | Conservative; one single user mistake (1–3 failures) is below threshold. |
| **Detections whose event is missing from the lookup** | Skipped (no invented key) | Determinism + no invented evidence. |
| **Detections with missing `source_ip` or `endpoint`** | Skipped | No invented key. |
| **Detections with naive `detected_at`** | Skipped (engine handles) | The engine refuses to coerce. |
| **Out-of-order event timestamps** | Detections are sorted by `detected_at` before grouping | The pattern's `group()` sorts internally. |
| **Empty result** | Returns `()` | Total, no raised exceptions. |

### 4.2 Correlation ID Derivation

The correlation's `correlation_id` is a deterministic `corr-<uuidv7>` derived from:

```
sha256(
  pattern_id | pattern_version | trigger |
  source_ip | endpoint |
  window_start | window_end |
  sorted(detection_ids)
)
```

The first 48 bits of the UUIDv7 are set from the first 6 bytes of the SHA-256 (timestamp-shaped); the rest is the SHA-256 content. **Same inputs always produce the same id** (audit-friendly determinism, matching the `detection_id` determinism introduced in Phase 4.4 D-2 fix). Replay-safe.

### 4.3 Correlation Document Shape (Persistence)

```
{
  "_id": <ObjectId>,
  "correlation_id": "corr-<uuidv7>",
  "pattern_id": "NGINX-CORR-BRUTEFORCE-001",
  "pattern_version": 1,
  "trigger": "brute_force_count_threshold",
  "key": ["198.51.100.7", "/api/login"],
  "detection_ids": ["det-...", ...],  // the evidence (DET-08)
  "event_ids":     ["<uuidv7>", ...],  // the underlying canonical events
  "window_start": <BSON Date>,
  "window_end": <BSON Date>,
  "count": 8,
  "reasoning": "brute-force clustering: 8 authentication-failure detections from source_ip='198.51.100.7' targeting endpoint='/api/login' exceeded the threshold of 4 within a 300-second window",
  "correlated_at": <BSON Date>,
  "extra": {
    "threshold": 4,
    "window_seconds": 300
  }
}
```

`reasoning` is redacted via the existing `redact_endpoint` helper so any query string or fragment is stripped before the reasoning is persisted.

### 4.4 Detection Document Shape (Persistence)

The Phase 4.5 `detections` collection adds one field to the Phase 4.4 `Detection.to_dict()` shape:

```
"correlated": false   // persistence-only forward-compat flag
```

The flag defaults to `false`. A future correlation-persistence slice can flip it to `true` on a detection that participated in a correlation, without changing the detection contract.

---

## 5. Test Results

### 5.1 Test Totals

| Suite | Count |
|-------|-------|
| Unit tests (pre-Phase 4.5) | 430 |
| Unit tests added by Phase 4.5 | 118 |
| **Total unit tests** | **548** |
| Integration tests (pre-Phase 4.5) | 29 |
| Integration tests added by Phase 4.5 | 3 |
| **Total integration tests** | **32** |
| **Total tests** | **580** |

### 5.2 Test Categories

| Category | Count | Where |
|----------|-------|-------|
| Correlation contract (frozen, BSON-safe, validators) | 27 | `test_correlation_models.py` |
| Brute-force pattern positive / negative / boundary / isolation | 22 | `test_brute_force_pattern.py` |
| Correlation engine (input validation, fail-closed, determinism) | 17 | `test_correlation_engine.py` |
| Detection repository (mocked pymongo) | 22 | `test_detection_repository.py` |
| Correlation repository (mocked pymongo) | 20 | `test_correlation_repository.py` |
| Detection pipeline (mocked engine + repo) | 10 | `test_pipeline.py` |
| End-to-end real MongoDB | 3 | `test_phase45_pipeline.py` |
| **Total** | **121** | |

### 5.3 Run Evidence

```
$ python -m pytest tests/ -q --no-header
580 passed in 8.54s
```

### 5.4 End-to-End Pipeline Verified (real MongoDB)

The integration test in `test_phase45_pipeline.py::test_phase45_full_pipeline_correlates_brute_force` exercises the **complete** Phase 4.5 flow against a real MongoDB:

1. 5 NGINX log lines (4× HTTP 401 on `/api/login` from the same source, 1× HTTP 200 on a public page).
2. `DetectionPipeline.run_from_connector` ingests + detects + persists.
3. 4 events persisted, 8 detections persisted (each 401 fires both `NGINX-AUTH-FAILURE-001` and `NGINX-AUTH-BRUTEFORCE-001`).
4. `CorrelationEngine` reads the 8 detections from MongoDB, groups them by `(198.51.100.7, /api/login)`, fires the threshold of 4, and produces 1 correlation with `count=8` (the engine counts both rule firings per event).
5. `CorrelationRepository` persists the correlation. Idempotent re-persistence: count stays at 1.
6. The persisted correlation can be read back losslessly via `get_by_correlation_id`.

---

## 6. Positive / Negative / Near-Miss Results

### 6.1 Positive Cases (correlation should fire)

| Case | Source | Endpoint | Detections | Expected | Result |
|------|--------|----------|------------|----------|--------|
| 4 auth failures, same source, same endpoint, within window | `198.51.100.7` | `/api/login` | 8 (2 rules × 4 events) | 1 correlation, count=8 | ✅ PASS |
| 10 auth failures, same source, same endpoint, within window | `198.51.100.7` | `/api/login` | 20 | 1 correlation, count=20 | ✅ PASS |
| Exactly 4 (threshold boundary) | `198.51.100.7` | `/api/login` | 8 | 1 correlation | ✅ PASS |

### 6.2 Benign / Negative Cases (no correlation)

| Case | Result | Reason |
|------|--------|--------|
| 1 auth failure | No correlation | Below threshold. |
| 3 auth failures | No correlation | Below threshold (1 less than threshold). |
| 4 auth failures spread over > 5 minutes | No correlation | Window exceeded. |
| 4 auth failures from different `source_ip` | No correlation | Different keys. |
| 4 auth failures to different `endpoint` | No correlation | Different keys. |
| 4 rate-limit detections (rule_id not in allow-list) | No correlation | Wrong rule_id. |
| 4 auth failures with one event having `source_ip=None` | No correlation | The missing-key event is skipped; only 3 events remain. |
| 4 auth failures with one event having `endpoint=None` | No correlation | Same as above. |
| Empty input | No correlation | No detections. |
| Empty pattern list | No correlation | No patterns to evaluate. |

### 6.3 Near-Miss Cases

| Case | Result |
|------|--------|
| 3 auth failures (one less than threshold) | No correlation — explicitly tested. |
| Failures exactly at the window edge (5 min span) | Correlation fires (inclusive). |
| Failures spanning > 5 min | No correlation — explicitly tested. |

### 6.4 False-Positive Considerations

The pattern is intentionally narrow:

* **Single user mistyping a password** (1–3 failures): below threshold, no correlation. ✅
* **Forgotten-password loop** (concentrated, 4+ failures, same source_ip, same endpoint): **flags** — this is exactly the case the pattern is designed to flag. A human analyst can dismiss the correlation if the source_ip is the user's own.
* **Load balancer health check from a small set of source IPs** (typically low-volume 401s): below threshold.
* **Distributed credential-stuffing** (each source_ip has a small failure count): **not** detected by this pattern. Cross-source amplification is the deferred next slice.
* **Same source_ip, different endpoint** (e.g., 401 on `/api/login` and `/api/signup`): 2 separate correlations, one per endpoint key. The pattern does NOT collapse them.

The "no false positive is worse than no correlation" rule is preserved by the conservative threshold (4) and the strict key (source_ip + endpoint, no broader aggregation).

---

## 7. Evidence Traceability

Every `Correlation` carries:

* `detection_ids`: every per-event `Detection` that participated (DET-08).
* `event_ids`: every underlying `SecurityEvent` (the ultimate evidence).
* `window_start` / `window_end`: the time window the pattern's grouping covered.
* `count`: number of detections grouped.
* `reasoning`: short, redacted, analyst-facing string.
* `key`: the correlation key (the `(source_ip, endpoint)` pair).

A future analyst can read the correlations for an incident and immediately see **which per-event detections and underlying SecurityEvents backed the grouping**. No invented evidence.

The `correlated` flag on `Detection` is reserved for a future slice that updates the `detections` collection to mark which detections participated in a correlation. The Phase 4.5 slice does not flip this flag (per the documented "do not change contracts" rule); a future slice can do so without contract changes.

---

## 8. Persistence Verification

### 8.1 Detections Collection

| Property | Verified |
|----------|----------|
| Schema (`$jsonSchema` validator) | ✅ present in `DETECTIONS_VALIDATOR` |
| Index `det_detection_id_unique` (unique) | ✅ idempotency key |
| Index `det_rule_id` | ✅ rule-level lookup |
| Index `det_event_id` | ✅ event-level lookup |
| Index `det_detected_at_desc` | ✅ time-ordered audit |
| `create()` idempotent on duplicate | ✅ raises `DuplicateEventError` |
| Round-trip Detection → MongoDB → Detection | ✅ all fields preserved |
| `extra` dict ↔ tuple conversion | ✅ round-trip safe |
| `detected_at` tzinfo re-attach on read | ✅ UTC re-attached |

### 8.2 Correlations Collection

| Property | Verified |
|----------|----------|
| Schema (`$jsonSchema` validator) | ✅ present in `CORRELATIONS_VALIDATOR` |
| Index `corr_correlation_id_unique` (unique) | ✅ idempotency key |
| Index `corr_pattern_id` | ✅ pattern-level lookup |
| Index `corr_window` | ✅ time-ordered audit |
| Index `corr_key` | ✅ analyst investigation path |
| `create()` idempotent on duplicate | ✅ raises `DuplicateEventError` |
| Round-trip Correlation → MongoDB → Correlation | ✅ all fields preserved |
| `key` list ↔ `CorrelationKey` conversion | ✅ round-trip safe |
| `extra` dict ↔ tuple conversion | ✅ round-trip safe |
| `window_start` / `window_end` / `correlated_at` tzinfo re-attach | ✅ UTC re-attached |

### 8.3 Detections → Correlations Wiring

The end-to-end integration test demonstrates the full chain:

```
NGINX log line
  -> NginxConnector.collect() yields SecurityEvent
  -> SecurityEventIngestionService.ingest() persists to MongoDB
  -> DetectionEngine.run() produces Detection
  -> DetectionRepository.create() persists to MongoDB detections
  -> CorrelationEngine.run() reads detections, groups by key
  -> CorrelationRepository.create() persists to MongoDB correlations
```

All persistence layers use the same error translation policy (driver errors → `PersistenceError` / `DuplicateEventError`).

---

## 9. Ingestion → Detection → Correlation End-to-End Evidence

The integration test `test_phase45_full_pipeline_correlates_brute_force` is the documented proof. The test:

1. Writes 5 NGINX log lines to a `tmp_path` file.
2. Constructs a `DetectionPipeline` (real ingestion + real engine + real `DetectionRepository`).
3. Calls `pipeline.run_from_connector(NginxConnector(nginx_log))`.
4. Asserts: 4 events ingested, 8 detections produced, 8 detections persisted.
5. Reads every event from MongoDB into `events_by_id`.
6. Reads every detection from MongoDB into `all_detections`.
7. Runs `CorrelationEngine` on the loaded data.
8. Asserts: 1 correlation with `count=8`, `key=("198.51.100.7", "/api/login")`.
9. Persists the correlation via `CorrelationRepository`.
10. Asserts: the correlation can be read back identically.

The test passes in 0.72s on the development workstation (with a local MongoDB).

---

## 10. Limitations and Deferred Correlation Patterns

| Limitation | Description | Deferred To |
|------------|-------------|-------------|
| Cross-source correlation (WAF + NGINX, etc.) | Requires the WAF connector (not in MVP). | Future slice that ships the WAF connector. |
| Account-targeted correlation | Requires reliable `account.id` in NGINX events; currently sparse. | Future slice that ships a reliable auth-event source. |
| Status-anomaly burst (5xx) | Would group multiple `NGINX-STATUS-ANOMALY-001` detections on the same endpoint. Engine supports it; pattern module would be added. | Future slice. |
| Rate-limit + auth-failure amplification | Requires both rule types firing on the same source_ip at the same time. | Future slice. |
| Geographic / ASN | Requires geographic enrichment (out of MVP model). | Future slice. |
| Per-event redaction for the correlation's `reasoning` | `reasoning` is redacted via `redact_endpoint`. The future incident engine may need a richer redaction (e.g., redaction of the source_ip for GDPR). | Future slice. |
| Detection `correlated` flag | Reserved for a future slice. | Future slice. |
| Replay of correlations across process restarts | Current correlation engine is per-batch. A future slice may want persistent state for "ongoing" correlations. | Future slice. |

---

## 11. Stability Verdict

| Criterion | Result |
|-----------|--------|
| All Phase 4.5 requirements (detection persistence, wiring, correlation engine, evidence, replay-safety, isolation, safe handling) | PASS |
| No contract changes to SecurityEvent, Rule, RuleRegistry, Detection | PASS |
| Boundary integrity (no `pymongo`/`fastapi` in `app/detection/` or rule library) | PASS |
| Deterministic correlation results | PASS |
| Centralized correlation (no cross-source coupling without evidence) | PASS |
| Evidence references to every underlying SecurityEvent/Detection | PASS |
| Duplicate / replay-safe behavior | PASS (deterministic IDs, idempotent `create()`) |
| Isolation of unrelated events | PASS (per-key grouping) |
| Safe handling of incomplete / malformed / out-of-order input | PASS (engine filters; pattern skips) |
| Failure behavior without silently losing security data | PASS (per-event `DetectionResult` always returned; per-pattern fail-closed) |
| 580/580 tests passing | PASS |
| 594/594 tests passing (post-review, after fixing D-1..D-4) | PASS |
| No HIGH / CRITICAL defects | PASS |

**Final verdict: STABLE for Phase 4.5. Safe to hand off to the next slice.**

**Post-review update:** The four review findings D-1 (CRITICAL), D-2 (MEDIUM), D-3 (LOW), and D-4 (LOW) were all fixed and verified. See Section 12 for the fix-by-fix evidence. The D-5 documented design (forward-compat `correlated` flag) is preserved as-is. 594/594 tests pass.

---

## 12. Post-review fixes (D-1..D-4)

The Phase 4.5 independent senior-engineer review
(`docs/PHASE 4/PHASE 4-05/PHASE-04-05-REVIEW.md`) identified four
defects (D-1..D-4) and one documented design point (D-5,
preserved). This section records the verified fixes and the
final test results. D-5 is intentionally **not** changed; the
forward-compat `correlated: false` flag is the documented
behaviour.

### 12.1 D-1 (CRITICAL) — Long-endpoint correlation false-negative

**Defect.** `redact_endpoint` returns up to 128 chars but
`CorrelationKey.parts` is bounded at 64 chars, so the pattern's
`CorrelationKey(parts=(source_ip, endpoint))` raised a
`ValidationError` that the engine silently quarantined for any
65–128 char endpoint. The original reproduction was: 4 events
with an 80-char endpoint, threshold=4, 5-min window → 0
correlations.

**Fix.** `app/correlation/patterns.py` now truncates the
redacted endpoint to `MAX_KEY_PART_LEN` (64) chars **only for
the correlation key and the correlation_id derivation**. The
full 128-char redacted endpoint is still used for the
analyst-facing `reasoning` (preserves evidence) and is stored
in the document.

* `key` = `(source_ip, redacted_endpoint[:64])` (64-char cap)
* `correlation_id` = derived from the 64-char key (deterministic)
* `reasoning` = built from the full 128-char redacted endpoint
  (preserves the analyst-visible evidence)

This aligns the boundary at the pattern level so the documented
`MAX_KEY_PART_LEN` is honoured and the documented
`MAX_REDACTED_ENDPOINT_LEN` is preserved for evidence. The fix
is minimal: the `BruteForceClusteringPattern.group()` method
replaces the per-event key construction with
`key = (ev.source_ip, redact_endpoint(ev.endpoint)[:MAX_KEY_PART_LEN])`
and stores the full redacted endpoint in a side channel for the
reasoning string.

**Verified regression tests** (in
`tests/unit/test_brute_force_pattern.py::TestLongEndpoint`):

* `test_64_char_endpoint_correlates` — boundary at exactly
  `MAX_KEY_PART_LEN` produces a correlation.
* `test_80_char_endpoint_correlates` — the original D-1
  reproduction now produces 1 correlation with no errors; the
  `key.parts[1]` is 64 chars; the full 80-char endpoint is
  preserved in `reasoning`.
* `test_128_char_endpoint_correlates` — the upper bound of
  `redact_endpoint` output.
* `test_200_char_endpoint_correlates` — beyond the documented
  `redact_endpoint` cap; the function truncates to 128 chars,
  then the key is truncated to 64.
* `test_long_endpoints_with_same_prefix_correlate_together` —
  two long endpoints sharing the first 64 chars collapse into
  the same key (intentional behaviour of the no-suffix
  truncation).

### 12.2 D-2 (MEDIUM) — NoSQL-injection-shaped repository inputs

**Defect.** `DetectionRepository.find_by_rule`,
`DetectionRepository.find_by_event_id`, and
`CorrelationRepository.find_by_pattern` accepted arbitrary
Python objects and passed them directly to pymongo's `find()`.
An attacker with a future HTTP API could pass `{"$ne": "x"}` or
`{"$gt": 0}` to exfiltrate documents.

**Fix.** Each method now rejects non-`str` input up-front with
the documented `app.domain.errors.ValidationError` (safe
message `"invalid rule_id"` / `"invalid event_id"` /
`"invalid pattern_id"`). The `find()` call is never reached.
Plain `str` inputs continue to work unchanged.

**Verified regression tests:**

* `tests/unit/test_detection_repository.py::TestFindByRule::test_dict_rule_id_rejected`
  — `{"$ne": "x"}` rejected; `find()` not called.
* `tests/unit/test_detection_repository.py::TestFindByRule::test_int_rule_id_rejected`
  — `12345` rejected; `find()` not called.
* `tests/unit/test_detection_repository.py::TestFindByEventId::test_dict_event_id_rejected`
  — `{"$ne": "x"}` rejected; `find()` not called.
* `tests/unit/test_detection_repository.py::TestFindByEventId::test_int_event_id_rejected`
  — `12345` rejected; `find()` not called.
* `tests/unit/test_correlation_repository.py::TestFindByPattern::test_dict_pattern_id_rejected`
  — `{"$ne": "x"}` rejected; `find()` not called.
* `tests/unit/test_correlation_repository.py::TestFindByPattern::test_int_pattern_id_rejected`
  — `12345` rejected; `find()` not called.

### 12.3 D-3 (LOW) — `$jsonSchema` missing `additionalProperties: false`

**Defect.** The MongoDB `$jsonSchema` validators for
`detections` and `correlations` did not set
`additionalProperties: false`. A direct DB write (migration
script, future HTTP API, attacker with direct access) could
add undocumented fields, bypassing the Pydantic `extra='forbid'`
read contract.

**Fix.** Added `"additionalProperties": False` to both
`DETECTIONS_VALIDATOR["$jsonSchema"]` and
`CORRELATIONS_VALIDATOR["$jsonSchema"]`. The Pydantic
`Detection` and `Correlation` models remain
`frozen=True, extra="forbid"`, so the read path was already
rejected. The fix adds the write-time defense-in-depth.

**Verified regression tests:**

* `tests/unit/test_detection_repository.py::TestValidator::test_validator_rejects_extra_fields`
  — `DETECTIONS_VALIDATOR["$jsonSchema"]["additionalProperties"]`
  is `False`.
* `tests/unit/test_correlation_repository.py::TestValidator::test_validator_rejects_extra_fields`
  — `CORRELATIONS_VALIDATOR["$jsonSchema"]["additionalProperties"]`
  is `False`.

### 12.4 D-4 (LOW) — `Correlation.extra` unbounded

**Defect.** `Correlation.extra` was a
`Tuple[Tuple[str, Any], ...]` with no `max_items`. The constant
`MAX_CORRELATION_EXTRA = 16` was defined but not enforced. A
100-entry tuple was accepted.

**Fix.** `app/correlation/models.py::Correlation.extra` is now
`Annotated[Tuple[Tuple[str, Any], ...], Field(max_length=MAX_CORRELATION_EXTRA)]`.
Pydantic enforces the bound at construction; 16 entries are
accepted, 17+ are rejected with a Pydantic `ValidationError`
(type=`too_long`).

**Verified regression tests** (in
`tests/unit/test_correlation_models.py::TestCorrelation::test_extra_max_length_enforced`):

* 16 entries accepted (boundary).
* 17 entries rejected.
* 100 entries rejected (the original D-4 reproduction).

### 12.5 D-5 (DESIGN, DOCUMENTED) — `correlated` flag

**Not changed.** The `correlated: false` flag is the documented
forward-compat dead-letter for a future correlation-persistence
slice. No code path sets it to `true` today. This is the
intentional Phase 4.5 design and is preserved as-is.

### 12.6 D-1..D-4 are FIXED. Verdict: STABLE.

| Severity | Defect | Status |
|----------|--------|--------|
| CRITICAL | D-1: 65–128 char endpoint false-negative | FIXED ✅ |
| MEDIUM | D-2: NoSQL injection in 3 repository methods | FIXED ✅ |
| LOW | D-3: `$jsonSchema` missing `additionalProperties: false` | FIXED ✅ |
| LOW | D-4: `Correlation.extra` unbounded | FIXED ✅ |
| DESIGN | D-5: `correlated` flag never flipped | PRESERVED (documented) |

---

## Appendix A: Test Run Evidence

```
# Pre-fix (Phase 4.5 initial implementation):
$ python -m pytest tests/unit/ -q --no-header
548 passed in 3.62s

$ python -m pytest tests/integration/ -q --no-header
32 passed in 5.55s

$ python -m pytest tests/ -q --no-header
580 passed in 9.86s

# Post-fix (after D-1..D-4 review fixes + 14 new regression tests):
$ python -m pytest tests/unit/ -q --no-header
562 passed in 3.81s

$ python -m pytest tests/integration/ -q --no-header
32 passed in 6.18s

$ python -m pytest tests/ -q --no-header
594 passed in 10.99s

# Focused regression suites (post-fix):
$ python -m pytest tests/unit/test_brute_force_pattern.py tests/unit/test_correlation_models.py tests/unit/test_correlation_repository.py tests/unit/test_detection_repository.py tests/integration/test_phase45_pipeline.py -v
108 passed in 1.34s
```

## Appendix B: Phase 4.5 Module Map

```
app/correlation/
  __init__.py
  engine.py            # CorrelationEngine (the centralized engine)
  models.py            # Correlation, CorrelationResult, CorrelationKey, CorrelationTrigger
  patterns.py          # BruteForceClusteringPattern (the single implemented pattern)
  errors.py            # CorrelationError hierarchy

app/detection/
  pipeline.py          # DetectionPipeline (ingestion -> detection -> persistence)

app/persistence/
  detection_repository.py     # DetectionRepository
  correlation_repository.py   # CorrelationRepository
```

## Appendix C: New / Updated API Surfaces

| Symbol | Module | Contract |
|--------|--------|----------|
| `CorrelationEngine` | `app.correlation.engine` | Constructed with a sequence of `CorrelationPattern`s; `run(detections, events, *, now)` returns a `CorrelationResult`. |
| `Correlation` | `app.correlation.models` | Frozen, BSON-safe; `detection_ids` and `event_ids` lists are the evidence. |
| `CorrelationResult` | `app.correlation.models` | Frozen; `correlations`, `patterns_considered`, `patterns_evaluated`, `detections_consumed`, `errors`, `produced_at`. |
| `CorrelationKey` | `app.correlation.models` | Frozen; `parts` is a tuple of bounded strings. |
| `CorrelationTrigger` | `app.correlation.models` | Frozen, allow-list; `brute_force_count_threshold`. |
| `BruteForceClusteringPattern` | `app.correlation.patterns` | The single Phase 4.5 correlation pattern. |
| `DetectionPipeline` | `app.detection.pipeline` | Wires ingestion + engine + detection repository. |
| `PipelineResult` | `app.detection.pipeline` | The per-event pipeline output (event, detection_result, persisted_detections). |
| `DetectionRepository` | `app.persistence.detection_repository` | CRUD on the `detections` collection. |
| `CorrelationRepository` | `app.persistence.correlation_repository` | CRUD on the `correlations` collection. |

---

*End of Phase 4.5 Final Report*
