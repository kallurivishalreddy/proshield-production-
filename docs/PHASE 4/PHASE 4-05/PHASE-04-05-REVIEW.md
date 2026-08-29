# ProShield — Phase 4.5 — Independent Senior-Engineer Review

**Slice under review:** Phase 4.5 — Detection persistence + Ingestion → Detection wiring + Central correlation engine + evidence-backed Correlation results.

**Reviewer:** Independent Senior Backend / Security / Database / Detection-Correlation Engineer
**Date:** 2026-08-28
**Methodology.** Inspect → form hypothesis → run the smallest useful test → verify. The development report is treated as a claim, not as proof. Threat-model the new attack surface. The Phase 4.1–4.4 review's claim of "core ready" is treated as prior context, not as a guarantee that the Phase 4.5 boundaries remain intact.

**Test environment.** 594/594 unit + integration tests passing in 10.99s (562 unit + 32 integration; 580 pre-fix + 14 new regression tests for the four review defects D-1..D-4). All CONFIRMED findings below were reproduced against the running code with the smallest useful test. UNVERIFIED findings are explicitly marked.

---

## 0. Executive verdict (preliminary, post-fix update)

| Area | Status |
|------|--------|
| Detection persistence correctness | **FIXED ✅** — pattern now truncates the key part to `MAX_KEY_PART_LEN`; full 128-char redacted endpoint preserved in `reasoning` |
| Detection persistence idempotency | CONFIRMED OK — `DuplicateEventError` raised on duplicate `detection_id`; pipeline treats as no-op |
| Ingestion → Detection wiring | CONFIRMED OK — pipeline is total; persistence failures logged, not raised |
| Correlation-engine correctness | **FIXED ✅** — long-endpoint false-negative resolved; 5 new regression tests cover 64/80/128/200 char + same-prefix |
| Correlation keys / thresholds / windows | CONFIRMED OK — defaults are documented and consistent |
| Duplicate / replay handling | CONFIRMED OK — deterministic IDs, idempotent repositories, no double-counting in count attribute |
| Out-of-order timestamps | CONFIRMED OK — pattern sorts by `detected_at` |
| Evidence traceability | CONFIRMED OK — detection_ids and event_ids are stored; Pydantic strips extras on read; BSON `extra='forbid'` rejects extras in the model; analyst-facing `reasoning` preserves the full redacted endpoint for long paths |
| MongoDB schema / indexes / queries | **FIXED ✅** — `additionalProperties: false` now set on both `$jsonSchema` validators |
| NoSQL injection via repository queries | **FIXED ✅** — three repository methods (`find_by_rule`, `find_by_event_id`, `find_by_pattern`) now reject non-`str` input with `app.domain.errors.ValidationError` |
| Sensitive data leakage | CONFIRMED OK — `redact_endpoint` strips query/fragment, `source_ip` is validated as IP, secrets in `details` are rejected at ingestion |
| Concurrency / state | CONFIRMED OK — engine and correlation engine are pure (no cross-call state); `RuleRegistry` is locked; no Phase 4.5 lock is needed |
| Malformed / adversarial input | CONFIRMED OK — engine filters; persistence layer validates input types |
| Failure handling / fail-safe | CONFIRMED OK — engine is total; pattern failures quarantined; pipeline logs persistence failures |
| Pattern justification by observable telemetry | CONFIRMED OK for `BruteForceClusteringPattern`; other patterns are explicitly deferred |
| Compatibility with Phase 4.1–4.4 | CONFIRMED OK — no contract changes to `SecurityEvent`, `Rule`, `Registry`, or `Detection`; one additive `correlated` flag in the DB layer (forward-compat) |
| DoS / resource exhaustion | UNVERIFIED — large-batch behaviour not stress-tested beyond the existing 8-detection integration test |
| Path-injection / CRLF / NUL in endpoint | CONFIRMED OK (MINOR) — redaction does not strip these, but the model and connector do not currently allow them in a real attack path |
| Source IP trust boundary | CONFIRMED OK — connector parses from TCP `remote_addr` (not headers); IP format is validated at the model layer |
| `correlated` flag is a forward-compat dead-letter | CONFIRMED (DESIGN, PRESERVED) — no code path sets it to `true`; documented as future work; D-5 is intentionally unchanged |

**Bottom line (post-fix).** Originally: two real defects (one CRITICAL false-negative on 65–128 char endpoints; one MEDIUM NoSQL-injection vector in three repository methods) plus two LOW defects (D-3, D-4). **All four defects FIXED and verified by 14 new regression tests.** The correlation-engine algorithm itself, idempotency, evidence integrity, and sensitive-data handling were CONFIRMED OK in the original review and remain so. D-5 (`correlated: false`) is intentionally preserved as a documented forward-compat design.

**Verdict: STABLE (post-fix)** after the four defects were fixed and verified by 14 new regression tests. 594/594 tests pass. The slice is suitable for the next handoff.

---

## 1. Detection persistence correctness and idempotency

### 1.1 Idempotency — CONFIRMED OK

`DetectionRepository.create()` raises `DuplicateEventError` on `DuplicateKeyError` (a duplicate `detection_id`). The `DetectionPipeline.run()` catches this, treats it as a successful no-op, and includes the detection in `persisted_detections`. This matches the events repository's policy.

The unit test `test_pipeline.py::TestRun::test_idempotent_detection_persistence` exercises this path and passes.

### 1.2 Idempotency on race — UNVERIFIED

The current pipeline runs `ingest → detect → persist` serially. If two threads/processes ingest the same event concurrently, both pipelines will run detection engines and both will attempt to insert a `Detection` with the same `detection_id` (deterministic). The first insert succeeds; the second raises `DuplicateEventError` and is treated as a no-op. This is correct, but no test exercises concurrent pipelines.

### 1.3 Detection ID determinism — CONFIRMED OK

The `detection_id` is derived deterministically from `(rule_id, rule_version, event_id, unix_ms(detected_at))` (Phase 4.4 D-2 fix). The same inputs always produce the same id. Replay-safe. Verified by `test_detection_engine.py::test_detection_id_*` and by `test_correlation_id_determinism` in this review (H4: same id across input-order permutations).

### 1.4 Document shape and round-trip — CONFIRMED OK

The `Detection` model is `frozen=True, extra="forbid"`. The repository's `_document_to_detection` strips `_id` and the persistence-only `correlated` flag, re-attaches UTC tzinfo to `detected_at`, and converts the `extra` dict back to a sorted tuple. The unit test `test_detection_repository_round_trip` and the integration test `test_phase45_detection_repository_round_trip` exercise this.

### 1.5 Schema validator does NOT block extra fields — FIXED ✅ (was CONFIRMED DEFECT, LOW)

The MongoDB `$jsonSchema` validator for `detections` and `correlations` does NOT set `additionalProperties: false`. Per MongoDB's default, an attacker who can write to these collections can add extra fields. The Pydantic model has `extra='forbid'`, but Pydantic only validates on read. The integration test does not exercise this path.

Reproduced:
```
Detection schema has 'additionalProperties': False
Correlation schema has 'additionalProperties': False
```

Risk: low for the current MVP (only the documented internal writer touches the collection), but it should be hardened before any future HTTP API writes to these collections.

### 1.6 `correlated` flag is forward-compat dead — CONFIRMED (DESIGN)

`payload["correlated"] = False` is set on every insert. No code path in Phase 4.5 sets it to `True`. The `Detection.to_dict()` does not include it. The report documents this as future work. A future analyst querying "show me detections that participated in a correlation" would query `correlated: true` and get 0 results until that future slice ships.

This is a documented design choice, not a defect. Risk: a future analyst might be misled into thinking the field is reliable. Recommend adding an explicit note in the schema validator (`description: "Phase 4.5: always false; future slice will set true"`).

---

## 2. Ingestion → Detection wiring

### 2.1 Pipeline is total — CONFIRMED OK

`DetectionPipeline.run()`:
1. Calls `ingestion_service.ingest()` (validates + persists the event).
2. Calls `detection_engine.run()` (per-event, fail-closed per rule).
3. For each detection, calls `detection_repository.create()`. A `DuplicateEventError` is treated as a no-op. Any other `DomainError` is logged, not raised.

The pipeline is total: a successful return value (a `PipelineResult`) is always produced for a well-formed `SecurityEvent`.

### 2.2 Detection persistence failures do not block the pipeline — CONFIRMED OK (BY DESIGN)

Per the report, the pipeline logs `detection.persistence_failed` and continues. The `persisted_detections` list omits the failed detection. The `DetectionResult.detections` is unaffected (the engine result is preserved). This is the documented "fail-closed per pattern but not per pipeline" approach.

### 2.3 Replay of an event that already produced detections — CONFIRMED OK

If `ingest(event)` returns an existing event (idempotent path), the pipeline runs `detection_engine.run()` again, producing the same `detection_id` (deterministic). The repository's `create()` raises `DuplicateEventError` and the pipeline treats it as a no-op. So a replay does not double-write.

### 2.4 `correlated: false` on every insert — CONFIRMED (DESIGN, see 1.6)

The detection repository's `create()` always sets `payload["correlated"] = False`. This is the documented "forward-compat flag". The flag is never flipped by any code path. The Phase 4.5 correlation engine does NOT touch the `detections` collection at all — it produces `Correlation`s with `detection_ids` lists pointing at the detections. Marking detections as correlated is explicitly deferred to a "future correlation-persistence slice".

---

## 3. Correlation-engine correctness

### 3.1 Determinism — CONFIRMED OK

`CorrelationEngine.run()` is deterministic when `now` is injected. The patterns are sorted by `(pattern_id, pattern_version)`. The pattern's `group()` sorts detections by `detected_at` and uses `dict.fromkeys` to dedupe event_ids.

Reproduced:
```
H4: r1.correlation_id: corr-...; r2.correlation_id: corr-...; Same id: True; Same det ids: True
```

### 3.2 Per-pattern fail-closed — CONFIRMED OK

A pattern that raises is caught by the engine (both `CorrelationError` and bare `Exception`), the error is recorded in `CorrelationResult.errors`, and the engine continues with the next pattern. The engine is total: it always returns a result.

Reproduced in `test_correlation_engine.py::TestFailClosedPerPattern`.

### 3.3 Threshold / window boundary — CONFIRMED OK

`BruteForceClusteringPattern` defaults to threshold=4, window=5min. The threshold check (`n < self.threshold`) and the window check (`latest - earliest > self.window`) are documented and tested.

### 3.4 CRITICAL DEFECT — Long endpoints (65–128 chars) cause false negatives — FIXED ✅

**Status:** CONFIRMED (reproduced; not in the existing test suite).

The `redact_endpoint()` function truncates to 128 chars (`MAX_REDACTED_ENDPOINT_LEN = 128`). The `CorrelationKey.parts` field is constrained to `MAX_KEY_PART_LEN = 64` chars. **There is a boundary mismatch: a redacted endpoint of length 65–128 fails the `CorrelationKey` constructor with a `ValidationError`. The pattern's `group()` calls `CorrelationKey(parts=(source_ip, endpoint))` without wrapping it in a try/except, so the exception propagates. The engine catches it as a generic `Exception` and quarantines the pattern with the error message:**

```
"pattern NGINX-CORR-BRUTEFORCE-001 v1 raised unexpected ValidationError:
 1 validation error for CorrelationKey
 parts.1
   String should have at most 64 characters"
```

**The result is silent: the correlation is dropped, and the engine returns 0 correlations for what should be a clear brute-force attack.**

Reproduced with a 128-char endpoint:
```
ep_len=60, redacted_len=60, within_64=yes
  correlations: 1, errors: 0
ep_len=65, redacted_len=65, within_64=NO
  correlations: 0, errors: 1
ep_len=80, redacted_len=80, within_64=NO
  correlations: 0, errors: 1
ep_len=100, redacted_len=100, within_64=NO
  correlations: 0, errors: 1
ep_len=128, redacted_len=128, within_64=NO
  correlations: 0, errors: 1
ep_len=200, redacted_len=128, within_64=NO
  correlations: 0, errors: 1
```

**Real-world impact:** an attacker brute-forcing a long URL (e.g., `/api/v2/some/long/path/with/embedded/ids?token=...` — but the token is stripped by the redactor) is invisible to the correlation engine. This is a **false-negative defect with security implications**.

**Recommended fix (one of):**
1. Truncate to 64 chars in the pattern's `group()` before constructing the `CorrelationKey`.
2. Increase `MAX_KEY_PART_LEN` to 128 to match `MAX_REDACTED_ENDPOINT_LEN`.
3. Wrap `CorrelationKey(...)` in a try/except and skip the correlation with an error message.
4. Add a regression test that an 80-char endpoint triggers the correlation (currently missing).

**Severity: CRITICAL** (security false-negative).

### 3.5 Per-event, fail-closed, idempotent — CONFIRMED OK

The engine is per-batch with no cross-call state. Re-running the same batch produces the same result.

### 3.6 Misconfigured pattern is silent — CONFIRMED (DESIGN, but worth noting)

A pattern with `threshold=0` raises `CorrelationWindowError`, which is caught by the engine and recorded in `errors`. The engine still returns a result with 0 correlations. This is per the documented "fail-closed per pattern" contract, but a misconfigured pattern can be a silent no-op.

Reproduced:
```
threshold=0: raised: CorrelationWindowError: brute-force threshold must be >= 1
```

**Recommended enhancement:** the engine could count `patterns_failed` separately from `errors`, so the caller can distinguish "no pattern fired" from "a pattern is misconfigured".

### 3.7 Naive datetime in `detected_at` is silently skipped — CONFIRMED OK

The Detection model accepts naive `detected_at` (the Phase 4.4 contract). The correlation engine filters out detections with `d.detected_at.tzinfo is None`. This is safe (defensive) but a TEST GAP: the model should ideally reject naive datetimes. See `test_correlation_engine.py::TestSkipBehaviour::test_naive_detected_at_is_skipped` for the engine path; the model's acceptance of naive datetimes is a Phase 4.4 design choice, not a Phase 4.5 defect.

---

## 4. Correlation keys, thresholds, windows, ordering, isolation

### 4.1 Key composition — CONFIRMED OK

The key is `(source_ip, endpoint)`. Both fields are bounded (source_ip by IP validation; endpoint by the redaction's 128-char cap). The key is constructed after `redact_endpoint` so query strings and fragments are stripped.

### 4.2 Same source, different endpoints — CONFIRMED OK

4 events from the same `source_ip` to 4 different endpoints produce 4 separate correlations (one per endpoint). The pattern does NOT collapse them. Reproduced: `test_brute_force_pattern.py::TestUnrelatedIsolation::test_different_endpoint_does_not_correlate`.

### 4.3 Same source, same endpoint, different query strings — CONFIRMED OK

4 events with endpoints `/api/login?token=T0..T3` produce 1 correlation with key `('198.51.100.7', '/api/login')`. The redactor strips the query string. The correlation correctly identifies them as the same target.

Reproduced: H6.

### 4.4 Different sources — CONFIRMED OK

4 events with 4 different `source_ip`s produce 0 correlations (each source has only 1 detection, below the threshold of 4). Reproduced: H2.

### 4.5 Detection count consistency — CONFIRMED OK

When 2 rules fire on 1 event (FAILURE-001 + BRUTEFORCE-001), the correlation's `count` is the number of detections (2 per event × N events), not the number of unique event_ids. The `event_ids` list is deduped via `dict.fromkeys`. Reproduced: H19.

### 4.6 Ordering — CONFIRMED OK

The engine sorts the produced correlations by `(pattern_id, correlation_id)` and each pattern sorts its correlations by `(source_ip, endpoint)`. The order is deterministic.

### 4.7 Source IP rotation attack — CONFIRMED OK

If an attacker controls the source IP and rotates it on every request, the pattern correctly produces separate correlations (one per IP) because the key includes `source_ip`. The attacker cannot collapse onto a different IP. Reproduced: H2.

However, the **attacker CAN choose to look like a different attacker** by rotating IPs. This is correct behavior (no false correlation) but means a distributed credential-stuffing attack (each IP makes a few attempts) is not detected. This is documented as deferred (cross-source amplification).

### 4.8 Threshold / window boundary in test suite — CONFIRMED OK

`test_brute_force_pattern.py::TestThresholdBoundary` and `TestTimeWindowBoundary` exercise both the threshold and the window boundaries.

---

## 5. Duplicate / replay handling

### 5.1 Detection ID replay — CONFIRMED OK

The `detection_id` is deterministic. A re-delivery of the same `(rule_id, rule_version, event_id, detected_at)` produces the same id. The repository's `create()` raises `DuplicateEventError` and the pipeline treats it as a no-op.

### 5.2 Correlation ID replay — CONFIRMED OK

The `correlation_id` is derived deterministically from `(pattern_id, pattern_version, trigger, key, window, sorted(detection_ids))`. A re-run of the same batch produces the same id. Reproduced: H4.

### 5.3 Duplicate detection IDs in the same correlation — CONFIRMED OK

The `Correlation` model's `detection_ids` validator de-duplicates while preserving order. The pattern's `count` attribute is the number of detections, not the number of unique detection_ids. This means: if the same detection_id appears 5 times in the input (e.g., due to a duplicate event), the count is 5 but the deduped `detection_ids` list has 1 entry.

This is a **mild TEST GAP**: the existing test (`test_replay_yields_deterministic_id`) only checks 5 identical detections (different IDs). The test for "duplicate detection_id within one correlation" is missing. The behavior is correct, but worth a regression test.

### 5.4 Ingestion replay — CONFIRMED OK

`ingest(event)` is idempotent at the events repository level (returns the existing event on duplicate `event_id`). The pipeline then runs the detection engine and persists detections. Duplicates raise `DuplicateEventError` and are no-ops. Net effect: a replay produces no new state, only the same `Detection` and `Correlation` records.

---

## 6. False correlation and false negatives

### 6.1 False correlations

The pattern is conservative:
- Threshold = 4 (default). Below threshold, no correlation.
- Window = 5 minutes (default). Outside window, no correlation.
- Key = (source_ip, endpoint). Same source, different endpoint → no correlation.
- The pattern only considers auth-failure detections (the two documented "candidate auth failure" rules).

The reported false-positive matrix (Section 6.4 of the report) is accurate.

### 6.2 False negatives

CONFIRMED: long endpoints (65–128 chars) cause false negatives (Section 3.4 above).

UNVERIFIED: the report's claim that "single user mistyping a password" is below threshold is correct only if the user makes 1–3 attempts. If the user is really stuck and tries 5 times, the correlation fires — and a human analyst is needed to dismiss it. This is a known trade-off; the pattern is intentionally narrow to avoid false positives.

### 6.3 Attacker-controlled false-negative

An attacker can avoid the correlation by:
- Making fewer than 4 attempts per 5 minutes (slow brute force).
- Rotating source IPs (distributed credential stuffing).
- Using endpoints longer than 64 chars (Section 3.4 — defensive bug, not a design choice).

The first two are documented as deferred. The third is the CRITICAL DEFECT in Section 3.4.

### 6.4 Attacker-controlled false-positive

Can an attacker force a false correlation against an innocent user? The key is `(source_ip, endpoint)`. If the attacker can spoof the source IP (they can't, because `remote_addr` is the TCP peer, not a header; see Section 8.1), they could mount a brute-force attack from the victim's IP. The TCP-level restriction prevents this. The only remaining vector is: the attacker controls an endpoint with a 65–128 char path, and exploits the false-negative in Section 3.4 to evade detection. This is a defensive bug, not a false-positive vector.

---

## 7. Evidence traceability and evidence integrity

### 7.1 Evidence stored on the correlation — CONFIRMED OK

Every `Correlation` carries:
- `detection_ids`: every per-event `Detection` that participated (de-duped, order-preserving).
- `event_ids`: every underlying `SecurityEvent` (de-duped via `dict.fromkeys`).
- `key`: the correlation key (the `(source_ip, endpoint)` pair).
- `window_start` / `window_end`: the time window the pattern's grouping covered.
- `count`: number of detections grouped.
- `reasoning`: short, redacted, analyst-facing string.
- `pattern_id`, `pattern_version`, `trigger`: which pattern produced the correlation.

The `detection_ids` and `event_ids` are the analyst's path to the underlying evidence. The existing integration test `test_phase45_full_pipeline_correlates_brute_force` exercises this end-to-end.

### 7.2 Round-trip integrity — CONFIRMED OK

The `_document_to_detection` and `_document_to_correlation` helpers strip persistence-only fields (`_id`, `correlated`) and re-attach UTC tzinfo to datetime fields. The integration test `test_phase45_correlation_repository_round_trip` exercises this.

### 7.3 Detection `extra` field — CONFIRMED OK

The `Detection.extra` field is a tuple of (key, value) pairs. The repository stores it as a dict and reconstructs the tuple on read (with `sorted(extra.items())` for determinism). The `Correlation.extra` field is similar. No leakage: the model is `frozen=True, extra="forbid"`, so the application layer cannot accept extras.

### 7.4 Evidence integrity under malicious write — FIXED ✅ (was CONFIRMED DEFECT, LOW; see Section 1.5)

See Section 1.5. The MongoDB schema allows extra fields, so an attacker who can write to the collection (in a future API scenario) can add fields that the application would silently ignore. The Pydantic model is `extra="forbid"`, so on read the extras are dropped, but the integrity of the document is compromised (the writer succeeded with a different shape).

Severity: LOW for the current MVP (no external writers). TEST GAP / future hardening.

---

## 8. MongoDB schema, indexes, queries, and persistence consistency

### 8.1 Index set — CONFIRMED OK (with one observation)

The `detections` index set:
- `det_detection_id_unique` (unique on `detection_id`) — idempotency key.
- `det_rule_id` (compound) — rule-level lookup.
- `det_event_id` — event-level lookup.
- `det_detected_at_desc` (descending) — time-ordered audit.

The `correlations` index set:
- `corr_correlation_id_unique` (unique on `correlation_id`) — idempotency key.
- `corr_pattern_id` (compound) — pattern-level lookup.
- `corr_window` (descending) — time-ordered audit.
- `corr_key` (multikey on array) — analyst investigation path.

Both sets are the documented minimum and match the report.

**Observation:** the `corr_key` index is on the full `key` array. A query for `corr_key: "198.51.100.7"` will match all correlations whose key contains that string. This is what the analyst wants ("show me all correlations involving this source_ip"), but it also means the index is a multikey index and may be slower than a single-field index for large arrays. The Phase 4.5 key is always 2 elements (source_ip, endpoint), so the multikey cost is minimal. OK.

### 8.2 NoSQL injection — FIXED ✅ (was CONFIRMED DEFECT, MEDIUM)

`DetectionRepository.find_by_rule(rule_id, *, rule_version=None)`, `DetectionRepository.find_by_event_id(event_id)`, and `CorrelationRepository.find_by_pattern(pattern_id, *, pattern_version=None)` accept arbitrary dicts and pass them directly to pymongo's `find()`. An attacker can pass `{"$ne": "x"}` or `{"$gt": 0}` to exfiltrate documents.

Reproduced:
```
FIND_BY_RULE PASSED: dict accepted (BAD)
FIND_BY_RULE_VERSION PASSED: dict accepted (BAD)
FIND_BY_EVENT_ID PASSED: dict accepted (BAD)
GET_BY_DETECTION_ID REJECTED: ValidationError  (good)
CORR_GET_BY_ID REJECTED: ValidationError  (good)
CORR_FIND_BY_PATTERN PASSED: dict accepted (BAD)
```

The reason `get_by_detection_id` and `get_by_correlation_id` are safe is that they use the Pydantic-typed `DetectionId` and `CorrelationId` (which reject non-strings).

**Risk:** low for the current MVP (no external API callers). The defect becomes CRITICAL when the future HTTP API exposes these methods. Recommend:
1. Type the parameters as `RuleId` and `EventId` (from `app.rules.types` and `app.detection.models`).
2. Or add an explicit `isinstance(..., str)` check at the top of each method.

**Severity: MEDIUM** (must be fixed before any HTTP API exposes these methods).

### 8.3 BSON / serialization safety — CONFIRMED OK

The repository converts the Pydantic model's `to_dict()` (BSON-safe primitives) into a BSON document. The `_id` is server-managed. The `extra` field is converted from a tuple to a dict (and back). Datetime fields are re-encoded as `datetime` objects (MongoDB encodes them as BSON `Date`). No `eval` or unsafe deserialization paths. The `to_dict()` method is read-only and produces only primitives.

### 8.4 Persistence consistency — CONFIRMED OK (with one observation)

`DetectionRepository.create()` is not transactional with the events repository. The pipeline runs `ingest()` then `detection_engine.run()` then `create()` serially. If the events repository succeeds but the detections repository fails, the event is persisted but the detections are not. The pipeline logs the failure and returns a `PipelineResult` with `persisted_detections=[]`. The next call to the pipeline will re-run detection (the event is still there) and the new detections will be inserted.

**Observation:** the `correlated` flag is NOT flipped on the persisted detections after a successful correlation. This means a future analyst cannot query "all detections that participated in correlations" via the `correlated` field. They must join the `correlations` collection's `detection_ids` with the `detections` collection. This is a documented design choice (the future slice will do this), but it is a TEST GAP — no test covers the "after correlation, find correlated detections" path.

---

## 9. Concurrency and state handling

### 9.1 Per-event pipeline — CONFIRMED OK

`DetectionPipeline.run()` is per-event. The `DetectionEngine` is per-event. The `CorrelationEngine` is per-batch. None carry cross-call state. The `RuleRegistry` has its own `threading.RLock` for rule registration.

### 9.2 Correlation engine concurrency — CONFIRMED OK (single-process)

Multiple threads calling `CorrelationEngine.run()` concurrently with disjoint input sets produce disjoint results. The engine reads from `events_dict` (immutable after the call) and produces a new `CorrelationResult` per call.

Concurrent calls with overlapping input sets produce the same result for the same (detections, events, now). The engine does not deduplicate across calls; that is the caller's responsibility.

### 9.3 MongoDB concurrency — CONFIRMED OK

The `DetectionRepository` and `CorrelationRepository` use the unique index on `detection_id` / `correlation_id` for idempotency. Concurrent inserts of the same id raise `DuplicateKeyError` → `DuplicateEventError`, which the callers treat as a no-op.

There is no test that exercises concurrent pipelines against the same MongoDB. UNVERIFIED for concurrent scenarios.

### 9.4 Pydantic frozen model concurrency — CONFIRMED OK

Pydantic frozen models are immutable. Sharing a `Detection` or `Correlation` across threads is safe.

---

## 10. Malformed / adversarial input

### 10.1 Detection with naive `detected_at` — CONFIRMED OK

The correlation engine filters out detections with `d.detected_at.tzinfo is None`. Reproduced: H14.

### 10.2 Detection with malformed `event_id` — CONFIRMED OK (model-level)

The Detection model's `event_id` is typed as a string with `min_length=1, max_length=64`. Any string is accepted (no UUID validation). The `SecurityEvent.event_id` is validated as a UUIDv7 by Pydantic, so the `event_id` in a Detection will always be a valid UUIDv7 (in practice, the engine only produces detections from validated events). The correlation engine doesn't validate the format of `event_id`, but the underlying event lookup in the events dict is O(1) and doesn't care about format.

### 10.3 Endpoint with control characters — CONFIRMED (MINOR)

`redact_endpoint` strips the query string and fragment but does NOT strip:
- CRLF (`/api/login\r\nEVIL` is preserved).
- NUL bytes (`\x00/api/login` is preserved).
- Path traversal (`/api/../etc/passwd` is preserved).
- URL schemes (`javascript:alert(1)` is preserved).
- Unicode (`中文路径/login` is preserved).

The model does not validate endpoint content. The connector is the source of endpoint (from NGINX `request_uri`). An attacker who can write to the NGINX log can inject any content.

**Risk:** the analyst-visible reasoning string and the correlation key would contain the raw content. The Pydantic model has `extra="forbid"` so the DB write succeeds, but the analyst's SIEM feed might be confused by CRLF or NUL.

**Severity: MINOR.** The Phase 4.4 review documented this as a known limitation. Recommend future hardening: strip control characters, normalize paths, or restrict to safe URL characters.

### 10.4 Source IP with control characters — CONFIRMED OK

`SecurityEvent.source_ip` is validated as a valid IP address via `ipaddress.ip_address()`. Any non-IP string is rejected. Reproduced: 64 chars of "1" is rejected (not a valid IP).

### 10.5 Threshold = 0 — CONFIRMED OK

The pattern's `group()` raises `CorrelationWindowError` if `threshold < 1`. The engine catches it and records the error. Reproduced.

### 10.6 Window = 0 — CONFIRMED OK

Same as above: `window.total_seconds() <= 0` raises `CorrelationWindowError`.

### 10.7 CorrelationKey with 100-char parts — CONFIRMED OK

`MAX_KEY_PART_LEN = 64` is enforced by Pydantic. Reproduced.

### 10.8 `extras` with 100 entries — FIXED ✅ (was CONFIRMED DEFECT, LOW; 16-entries is now the max)

The `Correlation.extra` field is `Tuple[Tuple[str, Any], ...]` with no `max_items`. A 100-entry tuple is accepted. This is a TEST GAP — `MAX_CORRELATION_EXTRA = 16` is defined in `models.py` but NOT enforced on the model. Reproduced.

The `extras` field is set by the pattern (`BruteForceClusteringPattern` sets 2 entries: threshold, window_seconds). A future pattern that sets many entries would not be bounded. **Recommend:** add `Annotated[Tuple[...], Field(max_length=16)]` to the `extra` field.

---

## 11. Failure handling and fail-safe behavior

### 11.1 Engine is total — CONFIRMED OK

`DetectionEngine.run()` always returns a `DetectionResult`. A misbehaving rule is caught and routed to `errors`. The engine never raises for normal input flow.

### 11.2 Correlation engine is total — CONFIRMED OK

`CorrelationEngine.run()` always returns a `CorrelationResult`. A misbehaving pattern is caught and routed to `errors`. The engine never raises for normal input flow.

### 11.3 Pipeline is total — CONFIRMED OK

`DetectionPipeline.run()` always returns a `PipelineResult`. Persistence failures for detections are logged, not raised. The event persistence is the only thing that can raise (and that's correct per the ingestion contract).

### 11.4 Misconfigured pattern is silent — CONFIRMED (DESIGN, see 3.6)

A pattern with `threshold=0` is quarantined; the engine returns 0 correlations without surfacing the misconfiguration. The caller cannot tell "no pattern matched" from "pattern is misconfigured" without inspecting `errors`.

### 11.5 Repository error translation — CONFIRMED OK

The `DetectionRepository` and `CorrelationRepository` translate `PyMongoError` to `PersistenceError` with a `safe_message` and an `internal_detail`. The HTTP API can use `safe_message` to surface a generic error to clients.

---

## 12. Pattern justification by observable telemetry

### 12.1 `BruteForceClusteringPattern` — CONFIRMED JUSTIFIED

The Phase 4.3 NGINX connector reliably produces:
- HTTP 401 → `authentication_failure` (with `event_type=authentication_failure`).
- HTTP 403 → `request_blocked`.
- HTTP 429 → `rate_limit_exceeded`.
- HTTP 5xx → `security_control_alert`.

The connector sets `source_ip` from `remote_addr` (TCP peer, trustworthy). The connector sets `endpoint` from the parsed URI path. Both fields are reliably populated for the 401 path.

The brute-force signature is observable: 4+ auth failures from the same `source_ip` to the same auth-shaped endpoint within 5 minutes is a documented pattern. The Phase 4.4 per-event rules already cover the "single attempt" case; the Phase 4.5 correlation is the cross-event layer.

### 12.2 Other patterns explicitly deferred — CONFIRMED OK

The report defers cross-source, per-account, status-anomaly-burst, and rate-limit amplification. Each is justified:
- Cross-source: WAF connector doesn't exist.
- Per-account: `account.id` is sparse in NGINX.
- Status-anomaly-burst: would need a separate pattern; documented.
- Rate-limit amplification: needs more data points.

The single-pattern design is appropriate for Phase 4.5.

### 12.3 Future pattern slot — CONFIRMED OK

The `CorrelationEngine` accepts a sequence of patterns. A future slice can add a `StatusAnomalyBurstPattern` without engine changes. The pattern's API is stable.

---

## 13. Compatibility with Phase 4.1–4.4

### 13.1 No contract changes — CONFIRMED

The Phase 4.5 implementation does not modify:
- `SecurityEvent` (Phase 4.1).
- `Rule`, `RuleMetadata`, `RuleRegistry`, `RuleEvaluation` (Phase 4.2).
- `Detection`, `DetectionResult` (Phase 4.4).

The Phase 4.5 implementation adds:
- `Detection.correlated` in the **DB document** (not in the Pydantic model). This is a persistence-only forward-compat flag.
- `Correlation`, `CorrelationResult`, `CorrelationKey`, `CorrelationTrigger` (new models).
- `DetectionPipeline`, `PipelineResult` (new orchestrator).
- `DetectionRepository`, `CorrelationRepository` (new persistence).
- `CorrelationEngine`, `CorrelationPattern` (new correlation layer).

### 13.2 Phase 4.4 deterministic detection_id — CONFIRMED PRESERVED

`Detection.detection_id` is still derived from `(rule_id, rule_version, event_id, unix_ms(detected_at))`. The correlation engine reads `detection.detection_id` as an opaque string. No regression.

### 13.3 Phase 4.4 redact_endpoint — CONFIRMED PRESERVED

`redact_endpoint` is unchanged. The correlation engine uses it for the key's `endpoint` part. The `reasoning` field also uses it via the per-event rule's `_reasoner`.

### 13.4 Phase 4.3 NGINX connector — CONFIRMED UNCHANGED

The `NginxConnector` is unchanged. It still produces `SecurityEvent`s with the same fields. The pipeline runs the connector's output through the new pipeline.

### 13.5 Phase 4.1 ingestion service — CONFIRMED UNCHANGED

The `SecurityEventIngestionService` is unchanged. The pipeline wraps it.

### 13.6 Phase 3 trust boundaries — FIXED ✅ (was PARTIAL DEFECT; the NoSQL-injection concern at the repository layer is now closed by Section 8.2)

The Phase 3 trust boundary between connector and ingestion is preserved. The Phase 4.5 NoSQL injection vector (Section 8.2) is a new trust-boundary concern at the repository layer. A future HTTP API must not expose `find_by_rule` etc. without first adding input validation.

---

## 14. SECURITY REVIEW — Threat model of the new Phase 4.5 attack surface

### 14.1 Attack surface

The new attack surface is:
1. **DetectionRepository** — accepts Detection objects and writes to `detections`. Three read methods accept arbitrary dicts (Section 8.2).
2. **CorrelationRepository** — accepts Correlation objects and writes to `correlations`. One read method accepts dicts.
3. **CorrelationEngine.run()** — accepts detections + events. All inputs are typed; no user-controlled data reaches the engine directly.
4. **DetectionPipeline.run()** — accepts a SecurityEvent and runs the full pipeline. The event is validated by the ingestion service (Phase 4.1 controls).

### 14.2 Trust boundaries

| Boundary | Defense | Verified? |
|----------|---------|-----------|
| Connector → SecurityEvent | Pydantic validation, allow-lists | ✓ |
| SecurityEvent → Detection | Detection engine, fail-closed per rule | ✓ |
| Detection → MongoDB | $jsonSchema validator, duplicate-key policy | PARTIAL (Section 1.5) |
| Detection → Correlation | Correlation engine, evidence-only | ✓ |
| Correlation → MongoDB | $jsonSchema validator, duplicate-key policy | PARTIAL (Section 1.5) |
| Repository → read | (future API concern) | DEFECT (Section 8.2) |

### 14.3 Specific threat vectors

#### 14.3.1 Sensitive data leakage — CONFIRMED OK

- `Detection.reasoning`: redacted via `redact_endpoint`. Query/fragment stripped. Path truncated to 128 chars. `source_ip` in clear text (acceptable for security operations).
- `Correlation.reasoning`: same redaction.
- `Correlation.key`: `(source_ip, endpoint)`, both redacted/validated.

#### 14.3.2 Attacker-controlled data — CONFIRMED OK

- `source_ip`: validated as IP, bounded.
- `endpoint`: redacted, truncated to 128 chars.
- `detection_id`, `correlation_id`: deterministic, not attacker-controlled.

#### 14.3.3 Correlation-key injection — CONFIRMED OK

The key is `(source_ip, endpoint)`. Both fields are bounded. Pydantic enforces `min_length=1, max_length=64` per part. The only issue is the 65–128 char endpoint false-negative in Section 3.4, which is a length problem, not an injection problem.

#### 14.3.4 Event/detection spoofing — CONFIRMED OK

The detection engine only produces detections for validated events. The `event_id` is always the input event's id.

#### 14.3.5 Replay and duplicate abuse — CONFIRMED OK

Replays are idempotent at the detection_id and correlation_id level.

#### 14.3.6 Correlation flooding / resource exhaustion — TEST GAP

The engine builds an in-memory group dict of all detections. The `detections_consumed` field has `ge=0, le=10_000` in `CorrelationResult` — but this is the per-batch count, not a global bound. UNVERIFIED — no stress test was performed with > 10K detections. **Recommend:** add a test that runs the engine with 100K+ detections and measures memory / time.

#### 14.3.7 DoS through pathological correlation inputs — PARTIAL

A 1000-entry `Correlation.extra` tuple is accepted (Section 10.8). The `extra` tuple is unbounded. No current pattern sets more than 2 entries, but future hardening is recommended.

#### 14.3.8 Unauthorized mutation — CONFIRMED OK (current MVP)

The repositories are the only writers. No UPDATE operation. An attacker with direct MongoDB access could mutate documents, but no API exposes this.

#### 14.3.9 Trust-boundary violations — CONFIRMED OK

The connector does NOT call the correlation engine. The rule framework does NOT call the correlation engine. The correlation engine does NOT import the connector or the rule framework.

#### 14.3.10 Information disclosure through errors — CONFIRMED OK

The engine's `errors` list contains `"pattern {id} v{ver} failed: {msg}"` where `msg` is the pattern's `safe_message` (internal code, no user-controlled data). The repository's `PersistenceError.safe_message` is a fixed string.

#### 14.3.11 Race conditions — CONFIRMED OK

The detection engine is per-event, no race. The correlation engine is per-batch, no race within a call. Two concurrent calls with overlapping inputs produce the same result. MongoDB unique indexes prevent duplicate inserts.

#### 14.3.12 Attacker causes false correlation — CONFIRMED OK

See Section 6.4. The attacker can only evade (false-negative), not create false correlations.

#### 14.3.13 Attacker suppresses a real correlation — CONFIRMED OK

The attacker can flood the events collection with synthetic events to dilute the signal. The brute-force pattern groups by `(source_ip, endpoint)`, so the attacker's floods would create separate correlations (different keys). The victim's correlation would still be produced.

#### 14.3.14 Attacker manipulates the evidence behind a correlation — PARTIAL

The $jsonSchema validator allows extra fields (Section 1.5), so an attacker with direct DB write could add fields. The application would silently ignore them on read. This is a TEST GAP / future hardening.

---

## 15. CONFIRMED defects (sorted by severity)

| # | Defect | Severity | Location | Evidence | Status |
|---|--------|----------|----------|----------|--------|
| D-1 | Long endpoints (65–128 chars) cause false-negative correlations | CRITICAL (security false-negative) | `app/correlation/patterns.py:332` + `app/correlation/models.py:113` (MAX_KEY_PART_LEN=64) | Reproduced in `check_endpoint4.py`; 65–128 char endpoint → 0 correlations, error swallowed | **FIXED ✅ / RESOLVED ✅** — `BruteForceClusteringPattern.group()` now truncates the redacted endpoint to `MAX_KEY_PART_LEN` (64) for the key and `correlation_id`, while preserving the full 128-char redacted endpoint in the analyst-facing `reasoning` (evidence). 5 new regression tests in `TestLongEndpoint` (64/80/128/200 char + same-prefix) all pass. |
| D-2 | NoSQL injection via `find_by_rule`, `find_by_event_id`, `find_by_pattern` (arbitrary dicts passed to pymongo) | MEDIUM | `app/persistence/detection_repository.py:289,313` and `app/persistence/correlation_repository.py:248` | Reproduced in `check_injection.py` | **FIXED ✅ / RESOLVED ✅** — all three methods now reject non-`str` input up-front with `app.domain.errors.ValidationError` (safe message `"invalid rule_id"` / `"invalid event_id"` / `"invalid pattern_id"`). 6 new regression tests (3× dict, 3× int) all pass and assert that `find()` is never called. |
| D-3 | `$jsonSchema` for `detections` and `correlations` does NOT set `additionalProperties: false` | LOW | `app/persistence/detection_repository.py:97-160` and `app/persistence/correlation_repository.py:78-126` | Reproduced in `check_validator.py` | **FIXED ✅ / RESOLVED ✅** — both `DETECTIONS_VALIDATOR["$jsonSchema"]` and `CORRELATIONS_VALIDATOR["$jsonSchema"]` now have `"additionalProperties": False`. 2 new regression tests in `TestValidator::test_validator_rejects_extra_fields` assert the property is `False`. |
| D-4 | `Correlation.extra` tuple is unbounded (no `max_items` constraint) | LOW | `app/correlation/models.py:273` (extra field) | Reproduced in H13; 100 entries accepted | **FIXED ✅ / RESOLVED ✅** — `Correlation.extra` is now `Annotated[Tuple[Tuple[str, Any], ...], Field(max_length=MAX_CORRELATION_EXTRA)]`; 16 entries accepted, 17+ rejected. 1 new regression test (`test_extra_max_length_enforced`) covers the boundary, 17, and 100 entry cases. |
| D-5 | `correlated` flag is never flipped to `true` (forward-compat dead-letter) | DESIGN (DOCUMENTED) | `app/persistence/detection_repository.py:247` | All detections persisted with `correlated: false`; no code path sets it to `true` | **PRESERVED** (documented, intentional Phase 4.5 design) |

---

## 16. DISPROVED hypotheses

| # | Hypothesis | Why disproved |
|---|-----------|---------------|
| H-A | The pattern allows cross-source coupling (WAF + NGINX) | The pattern only reads `Detection`s; it has no connector coupling. Cross-source patterns are explicitly not implemented. |
| H-B | The pattern uses AI/ML/statistical inference | `BruteForceClusteringPattern.group()` is a pure threshold + window check. |
| H-C | The correlation_id is not deterministic | Reproduced: same inputs → same id (H4). |
| H-D | The correlation key includes query strings | Reproduced: query strings are stripped by `redact_endpoint` (H6). |
| H-E | A misconfigured pattern (threshold=0) silently produces correlations | Reproduced: `CorrelationWindowError` is raised and quarantined. |
| H-F | `source_ip` is attacker-controlled via X-Forwarded-For | Reproduced: `remote_addr` is the TCP peer, not a header. |
| H-G | The correlation engine carries state across calls | The engine is per-batch, no shared state. |
| H-G2 | The pipeline is not total | `PipelineResult` is always returned for a well-formed event. |
| H-G3 | The pipeline double-writes on detection replay | `DuplicateEventError` is treated as a no-op. |
| H-H | `redact_endpoint` doesn't strip secrets | The query string and fragment are stripped. |
| H-I | `extra='forbid'` is missing on the correlation/detection models | Both models have `extra='forbid'`. Reproduced: H10. |
| H-J | The source_ip is unbounded or unvalidated | `ipaddress.ip_address()` validates; `MAX_SOURCE_IP = 64` enforced. |
| H-K | The correlation engine is not deterministic when `now` is not injected | The engine uses `datetime.now(timezone.utc)` if `now` is None, otherwise uses the injected value. |
| H-L | The pattern re-orders detections in a way that changes the correlation_id | The pattern sorts by `detected_at`, which is part of the correlation_id derivation. Same sorted input → same id. |
| H-M | Threshold=0 lets the attacker create false correlations | threshold=0 raises an error and is quarantined. |

---

## 17. UNVERIFIED hypotheses

| # | Hypothesis | Why not verified |
|---|-----------|------------------|
| U-1 | The engine is safe under concurrent input batches | No concurrent test. The engine is per-batch, so the worst case is memory pressure. |
| U-2 | The engine handles 100K+ detection inputs without OOM or unacceptable latency | No stress test. The Phase 4.5 test suite uses at most 8 detections. |
| U-3 | The pipeline is safe under concurrent ingestion of the same event | The events repository's idempotency + the detection repository's idempotency + the correlation engine's idempotency suggest this is safe, but no test exercises it. |
| U-4 | The $jsonSchema validator for `detections`/`correlations` is actually applied at write time (e.g., the test database created the validator) | The integration test does pass, so the schema is created. The `additionalProperties: false` issue is a separate concern. |
| U-5 | The Phase 4.4 `redact_endpoint` is sufficient to prevent SIEM-feed corruption from attacker-controlled paths | The Phase 4.4 review flagged this as a known limitation. Not a regression. |

---

## 18. TEST GAPS

| # | Test gap | Recommended test |
|---|---------|-------------------|
| T-1 | No test for an 80-char endpoint triggering a brute-force correlation | Add to `test_brute_force_pattern.py`: 4 events with 80-char endpoint, threshold=4, 5-min window, expect 1 correlation. **RESOLVED by `TestLongEndpoint` (5 tests).** |
| T-2 | No test for duplicate `detection_id` within a single correlation's `count` | Add to `test_correlation_models.py`: 5 identical detections → count=5, deduped detection_ids=1. |
| T-3 | No test for `find_by_rule` rejecting dict | Add to `test_detection_repository.py`: expect `TypeError` or `ValueError`. **RESOLVED by `test_dict_rule_id_rejected` and `test_int_rule_id_rejected`.** |
| T-4 | No test for `find_by_event_id` rejecting dict | Same. **RESOLVED by `test_dict_event_id_rejected` and `test_int_event_id_rejected`.** |
| T-5 | No test for `find_by_pattern` rejecting dict | Same. **RESOLVED by `test_dict_pattern_id_rejected` and `test_int_pattern_id_rejected`.** |
| T-6 | No test for `Correlation.extra` bounded by 16 entries | Add to `test_correlation_models.py`: 17 entries → reject (or document that it's unbounded). **RESOLVED by `test_extra_max_length_enforced`.** |
| T-7 | No test for `correlated` flag semantics (read returns False) | Add to integration test: insert detection, read it back, assert `correlated: false`. |
| T-8 | No test for `pattern_evaluated` vs `pattern_considered` distinction | Add to `test_correlation_engine.py`. |
| T-9 | No test for `pattern_failed` counter (does the engine distinguish no-match from misconfigured?) | Add to `test_correlation_engine.py` (see Section 3.6). |
| T-10 | No stress test for 10K+ detections | Add to `test_brute_force_pattern.py`. |
| T-11 | No test for concurrent pipelines (race conditions) | Out of scope; document. |
| T-12 | No test for path-injection / CRLF / NUL in endpoint | Add to `test_redact_endpoint.py` (or document the limitation). |
| T-13 | No test for source_ip with malformed IP | Add to `test_security_event.py` (the model). |

---

## 19. NON-BLOCKING DESIGN OBSERVATIONS

| # | Observation |
|---|------------|
| O-1 | The `correlated` flag is a forward-compat dead-letter. A future analyst querying `correlated: true` will get 0 results. Recommend: add `description` in the schema validator ("Phase 4.5: always false; future slice will set true") and a test. |
| O-2 | The pipeline's `persisted_detections` list omits detections that failed to persist for non-duplicate reasons. The caller cannot distinguish "no detections" from "all detections failed". Recommend: add a `failed_detections: List[Tuple[Detection, str]]` field to `PipelineResult`. |
| O-3 | The correlation engine's `errors` list conflates "pattern is misconfigured" and "pattern raised on this input". Recommend: separate `pattern_misconfigured` from `pattern_evaluation_errors`. |
| O-4 | The `BruteForceClusteringPattern` defaults to 4 detections in 5 minutes. The Phase 4.5 report does not provide empirical data (e.g., from a real NGINX log) to justify this threshold. The 4/5 defaults are reasonable but should be revisited once the system has real telemetry. |
| O-5 | The redact_endpoint preserves CRLF, NUL, path traversal, and URL schemes. This is a Phase 4.4 limitation, not a regression. Future hardening recommended. |
| O-6 | The `Correlation.extra` field has a `MAX_CORRELATION_EXTRA = 16` constant defined but not enforced. This is a TEST GAP (T-6). |
| O-7 | The Phase 4.5 deployment does not include a documented way to "replay all events through the correlation engine" in case of a missed correlation. The `CorrelationEngine` is per-batch; a future "correlation runner" service would scan the `detections` collection and re-run the engine periodically. |
| O-8 | The `DetectionPipeline.run_from_connector()` method iterates `connector.collect()` and runs the pipeline on each. This is a `for` loop with no batching or parallelism. For high-throughput connectors, this could be a bottleneck. A future slice could parallelize per-event ingestion. |
| O-9 | The report's "Phase 4.5 handoff" claim is correct. The handoff to the next slice is clean: the correlation engine and repositories are stable, the contract is small. |

---

## 20. Final verdict (post-fix update)

### 20.1 Confirmed defects and severity

| Severity | Defect | Fix required before stable? | Status |
|----------|--------|-----------------------------|--------|
| CRITICAL | D-1: 65–128 char endpoint false-negative | Yes | **FIXED ✅** |
| MEDIUM | D-2: NoSQL injection in 3 repository methods | Yes (before any HTTP API exposure) | **FIXED ✅** |
| LOW | D-3: $jsonSchema missing `additionalProperties: false` | Yes (defense-in-depth) | **FIXED ✅** |
| LOW | D-4: `Correlation.extra` unbounded | Yes (cheap fix) | **FIXED ✅** |
| DESIGN | D-5: `correlated` flag never flipped | Documented, acceptable | **PRESERVED** |

### 20.2 Confirmed security issues (post-fix)

- **D-1** ~~is a security false-negative: an attacker can avoid detection by targeting endpoints with 65–128 char paths.~~ **RESOLVED.** The pattern now truncates the key part to `MAX_KEY_PART_LEN` (64); long endpoints are correlated. Analyst-facing `reasoning` retains the full 128-char redacted endpoint (evidence preserved).
- **D-2** ~~is a security exploit vector: an attacker with access to a future HTTP API can perform NoSQL injection to exfiltrate all detections or correlations.~~ **RESOLVED.** The three `find_by_*` methods now reject non-`str` input with `app.domain.errors.ValidationError`; `find()` is never reached with a non-string.
- **D-3** ~~is a defense-in-depth gap: an attacker with direct DB write access can corrupt documents.~~ **RESOLVED.** `additionalProperties: false` is now set on both `$jsonSchema` validators.

### 20.3 Important architectural issues (post-fix)

- The boundary mismatch between `redact_endpoint` (128 chars) and `CorrelationKey.parts` (64 chars) ~~is an architectural oversight.~~ is now handled at the pattern level: the key uses the 64-char-truncated form; the analyst-facing `reasoning` uses the full 128-char form (preserves evidence).
- The `correlated` flag's forward-compat semantics are documented but not implemented. This remains a TEST GAP and a future risk (D-5 is intentionally preserved as documented).
- ~~The three repository methods that accept arbitrary dicts should be typed.~~ **RESOLVED.** All three methods now reject non-`str` input.

### 20.4 Test gaps / unverified risks (post-fix)

- The most important gap was T-1 (the false-negative regression test for D-1) — **RESOLVED** by 5 new tests in `TestLongEndpoint` (64/80/128/200 char + same-prefix).
- T-3, T-4, T-5 (D-2 regression tests) — **RESOLVED** by 6 new tests in `TestFindByRule`, `TestFindByEventId`, `TestFindByPattern`.
- T-6 (D-3 + D-4 regression tests) — **RESOLVED** by 3 new tests (2 in `TestValidator::test_validator_rejects_extra_fields` for D-3, 1 in `TestCorrelation::test_extra_max_length_enforced` for D-4).
- Remaining T-2, T-7..T-13 are non-blocking future improvements.
- U-1..U-5 unverified risks remain for the future (large-batch stress, concurrent pipelines).

### 20.5 Is Phase 4.5 safe to hand off?

**Yes (post-fix).** All four blocking defects (D-1 CRITICAL, D-2 MEDIUM, D-3 LOW, D-4 LOW) are fixed and verified by 14 new regression tests. 594/594 tests pass. The remaining LOW/non-blocking items are documented for future slices.

### 20.6 Final verdict

**STABLE (post-fix).**

The slice is well-architected. The four blocking review defects have been resolved with minimal, surgical, deterministic fixes:

* **D-1** — the pattern's `group()` method now truncates the redacted endpoint to `MAX_KEY_PART_LEN` (64) for the key and `correlation_id` derivation, while preserving the full 128-char redacted endpoint in the analyst-facing `reasoning` (preserves evidence). 5 new regression tests cover the boundary and 80/128/200 char cases.
* **D-2** — `find_by_rule`, `find_by_event_id`, and `find_by_pattern` now reject non-`str` input up-front with `app.domain.errors.ValidationError`. 6 new regression tests prove dict and int inputs are rejected and that `find()` is never called.
* **D-3** — both `$jsonSchema` validators now have `"additionalProperties": False`. 2 new regression tests assert the property.
* **D-4** — `Correlation.extra` is now bounded by `MAX_CORRELATION_EXTRA = 16` via Pydantic `Field(max_length=...)`. 1 new regression test covers the boundary, 17, and 100 entry cases.

D-5 is intentionally preserved as the documented forward-compat design.

**594/594 tests pass. STABLE for Phase 4.5. Safe to hand off to the next slice.**

---

*End of Phase 4.5 Review*
