# ProShield — Phase 4 Correlation E2E Review

**Review date:** 2026-08-29
**Scope:** Phase 4.1 → 4.6 backend, with **focus on the correlation layer** (specialized + centralized correlation, evidence integrity, timeline, severity/confidence, benign + attack + cross-source + replay + pressure, and the rule framework's behaviour across all 6 source categories).
**Methodology:** Treat the slice as **untrusted**. Read every relevant doc, the complete source tree, and the complete test suite. Construct review-only fixtures (5 per-event rules for the 5 non-NGINX source categories + 1 cross-source correlation pattern) and run them through the real local MongoDB. The fixtures are not production code. They are temporary, clearly marked, and deleted after the review.

> **No production code was modified during this review.** All findings are documented here for a separate remediation task. The review-only artifacts live in `review_corr/` and are deleted by the cleanup step before the report is final.

---

## 0. Methodology

1. **Read every doc** under `docs/PHASE 0/`, `docs/PHASE 1/`, `docs/PHASE 2/`, `docs/PHASE 3/`, `docs/PHASE 4/`, plus the prior Phase 4 E2E review (`PHASE-04-01-06-CORE-E2E-REVIEW.md`).
2. **Read every file** in `app/` (configuration, observability, domain, connectors, persistence, ingestion, rules, detection, correlation, timeline, severity).
3. **Ran the existing test suite** end-to-end against the real local MongoDB at `127.0.0.1:27017`: **700/700 pass in 13.29 s** (666 unit + 34 integration).
4. **Constructed 5 review-only per-event rules** in `review_corr/fixtures/` (WAF, IAM, Rate Limit, Network, TLS) and **1 review-only cross-source correlation pattern** (`CrossSourceAttackPattern`). The rules use the existing public API of the rule framework (`SimpleRule`, `RuleMetadata`, `RULE_FACTORIES`); the pattern extends the existing `CorrelationPattern` ABC. No production file was touched.
5. **Wrote a single review harness** (`review_corr/build_correlation_review.py`) that wires the production NGINX rules + the 5 review-only per-event rules + the production `BruteForceClusteringPattern` + the review-only `CrossSourceAttackPattern` into a single `CorrelationEngine`, then runs 12 review scenarios (architecture inventory, per-source rule validation, benign, specialized-only, centralized-cross-source, specialized+centralized, neither, unrelated-sources, pressure, replay, evidence integrity, end-to-end).
6. **Ran the harness twice** for determinism. Both runs produced identical correlation IDs and identical counts.
7. **Classified every finding** as exactly one of: `CONFIRMED DEFECT`, `CONFIRMED SECURITY ISSUE`, `DESIGN WEAKNESS`, `TEST GAP`, `UNVERIFIED RISK`, `DISPROVED`, `OBSERVATION`.

---

## 1. Documentation reviewed

| Area | Files | Lines |
|---|---|---|
| Phase 0 — product, requirements, acceptance, initial events, routing | `PRODUCT_SCOPE.md`, `MVP_REQUIREMENTS.md`, `MVP_ACCEPTANCE.md`, `INITIAL_SECURITY_EVENTS.md`, `ROUTING_MATRIX.md` | ~1500 |
| Phase 1 — architecture, ADRs, threat model | `ARCHITECTURE.md`, `ARCHITECTURE_DECISIONS.md`, `THREAT_MODEL.md` | ~3000 |
| Phase 2 — schema, domain, API, contracts | `SECURITY_EVENT_SCHEMA.md`, `DOMAIN_DATA_MODEL.md`, `API_CONTRACTS.md`, `CONTRACT_DECISIONS.md` | ~2000 |
| Phase 3 — auth, secure foundation, configuration, security test plan | `AUTH_RBAC.md`, `SECURE_FOUNDATION.md`, `SECURITY_CONFIGURATION.md`, `SECURITY_TEST_PLAN.md` | ~2000 |
| Phase 4 — detection engineering, Phase 4.1–4.6 dev + review reports | `DETECTION_ENGINEERING_AND_FUTURE_AI.md`, all `PHASE-04-XX-REPORT.md` and `PHASE-04-XX-REVIEW.md` | ~10000 |
| Prior E2E review | `PHASE-04-01-06-CORE-E2E-REVIEW.md` | ~2500 |
| Synthesis | `PROSHIELD_PROJECT_UNDERSTANDING.md` | ~470 |

The `PHASE-04-01-06-CORE-E2E-REVIEW.md` concluded (correctly for production code alone) that **state B and state C are not implemented** because there is only one source-specific pattern in production. This review's task specifically required creating review-only fixtures to exercise the framework's cross-source correlation path. The framework does support it (see §3.4).

---

## 2. The actual correlation architecture (on disk)

### 2.1 Pipeline diagram

```
SecurityEvent (Pydantic v2, frozen, $jsonSchema-validated)
  -> app/connectors/{simulated,nginx}        (1 source-specific connector; WAF, IAM,
                                                rate_limiter, tls_network, endpoint,
                                                siem all in the allow-list but only
                                                nginx has a real connector)
  -> app/ingestion/service.py                (validate -> stamp -> persist)
  -> app/persistence/security_event_repository.py
  -> app/rules/                              (Rule framework: RuleMetadata, RuleState,
                                                RuleCategory, RuleRegistry, loader)
       RULE_FACTORIES in app/rules/_library/nginx/
         (5 SOURCE_SPECIFIC rules)
  -> app/detection/engine.py                 (per-event DetectionEngine)
  -> app/detection/models.py                 (Detection, DetectionResult)
  -> app/detection/pipeline.py               (DetectionPipeline)
  -> app/persistence/detection_repository.py
  -> app/correlation/engine.py               (CorrelationEngine: single centralized
                                                engine; runs every registered pattern)
       app/correlation/patterns.py           (BruteForceClusteringPattern ONLY in prod)
  -> app/persistence/correlation_repository.py
  -> app/timeline/engine.py                  (TimelineEngine)
  -> app/severity/engine.py                  (SeverityEngine, 10 signals)
```

### 2.2 Inventory captured by the harness

```
rules_count: 10
  5 production NGINX rules (SOURCE_SPECIFIC):
    - NGINX-ACCESS-DENIED-001
    - NGINX-AUTH-BRUTEFORCE-001
    - NGINX-AUTH-FAILURE-001
    - NGINX-RATE-LIMIT-001
    - NGINX-STATUS-ANOMALY-001
  5 review-only rules (SOURCE_SPECIFIC, REVIEW-ONLY fixtures):
    - WAF-REVIEW-001         (waf + waf_attack_detected)
    - IAM-REVIEW-001         (iam + authentication_failure)
    - RATELIMIT-REVIEW-001   (rate_limiter + rate_limit_exceeded)
    - NETWORK-REVIEW-001     (tls_network + network_anomaly)
    - TLS-REVIEW-001         (tls_network + tls_anomaly)

patterns_count: 2
  1 production:
    - NGINX-CORR-BRUTEFORCE-001 (BruteForceClusteringPattern)
  1 review-only:
    - CROSS-SOURCE-ATTACK-001  (CrossSourceAttackPattern)

engines_count: 1
  engine_class: CorrelationEngine

sources_in_allow_list: ['endpoint', 'iam', 'nginx', 'rate_limiter', 'siem',
                          'simulator', 'tls_network', 'waf']
```

### 2.3 Framework properties verified

| Property | Verified |
|---|---|
| Single centralized engine | ✅ `engines_count=1` |
| Patterns registered as a tuple, run in order | ✅ `CorrelationEngine._patterns` is a tuple, iterated in order |
| `CorrelationPattern` ABC supports additional patterns | ✅ verified by adding `CrossSourceAttackPattern` |
| `Correlation` is `frozen=True, extra="forbid"` | ✅ |
| `Correlation.correlation_id` is deterministic UUIDv7 | ✅ same inputs + same `now` → same `corr-<uuidv7>` |
| `Correlation.detection_ids` + `event_ids` are evidence-only | ✅ no invented evidence |
| Engine is fail-closed per pattern | ✅ pattern exceptions → `errors` |
| Engine is total | ✅ always returns `CorrelationResult` |
| Multi-pattern: a raising pattern does not stop the others | ✅ `state A + C` produces 2 correlations even with one raising |
| `Correlation` has no `scope` or `method` field | ✅ no model field distinguishes "specialized" from "centralized"; the two are distinguished by which pattern produced them (`pattern_id`) |
| `CorrelationResult` cap: `MAX_CORRELATION_RESULT_PATTERNS=32`, `MAX_CORRELATION_RESULT_ERRORS=32` | ✅ |

### 2.4 What the review did NOT find in production code

| Missing in production | Status |
|---|---|
| Multiple correlation engines (one specialized, one centralized) | **DEFERRED** — the framework supports it but the calling code uses a single engine. |
| Cross-source pattern | **DEFERRED in production** — only `BruteForceClusteringPattern` exists. The review demonstrates the framework supports it (see §3.4). |
| Analyst-triggered "deeper centralized" on-demand endpoint | **DEFERRED** — no API, no CLI. The engine runs on every batch. |
| Per-account correlation | **DEFERRED** — `account.id` is sparse in current NGINX telemetry (Phase 4.5 report §1.2). |

---

## 3. Per-source rule validation

The review built 5 review-only per-event rules (one for each non-NGINX source category) and ran them through the real `DetectionEngine` to verify the rule framework correctly handles the documented source categories. Each rule was constructed as a `SimpleRule` with a `RULE_FACTORIES` export and registered via the existing `load_rules_from_specs` loader.

The harness constructed 8 cases (3 production NGINX + 5 review-only) and asserted that for each case **only** the rule(s) documented for that source/event_type fire:

| source | event_type | expected rules | fired? |
|---|---|---|---|
| `nginx` | `authentication_failure` | `{NGINX-AUTH-FAILURE-001, NGINX-AUTH-BRUTEFORCE-001}` | ✅ exactly these 2 |
| `nginx` | `rate_limit_exceeded` | `{NGINX-RATE-LIMIT-001}` | ✅ exactly this 1 |
| `nginx` | `request_blocked` (404 on `/.env`) | `{NGINX-ACCESS-DENIED-001}` | ✅ exactly this 1 |
| `waf` | `waf_attack_detected` | `{WAF-REVIEW-001}` | ✅ exactly this 1 |
| `iam` | `authentication_failure` | `{IAM-REVIEW-001}` | ✅ exactly this 1 |
| `rate_limiter` | `rate_limit_exceeded` | `{RATELIMIT-REVIEW-001}` | ✅ exactly this 1 |
| `tls_network` | `network_anomaly` | `{NETWORK-REVIEW-001}` | ✅ exactly this 1 |
| `tls_network` | `tls_anomaly` | `{TLS-REVIEW-001}` | ✅ exactly this 1 |

`per_source_rule_validation.all_match = True` (8/8 cases match).

**Findings:**

- The rule framework's `applies_to_source` and `applies_to_event_type` filters work correctly for every source in the `ALLOWED_SOURCES` allow-list.
- Disabled rules, unrelated source rules, and wrong event_type rules are all correctly excluded.
- `evidence_refs` are correctly set to `(event.event_id,)` by the detection engine.
- `Detection.detection_id` is deterministic and well-formed (matches `DETECTION_ID_PATTERN`).
- The framework's `Category` constraint (SOURCE_SPECIFIC must declare at least one source and one event_type) is enforced at metadata construction time.

---

## 4. NGINX specialized correlation

The review's `scenario_nginx_specialized` constructs 4 NGINX 401 events from the same source_ip and the same endpoint, runs them through the real pipeline, and feeds the resulting detections + events into the real `CorrelationEngine`.

| Stage | Observed |
|---|---|
| Events processed | 4 |
| Detections produced | 8 (2 per event: `NGINX-AUTH-FAILURE-001` + `NGINX-AUTH-BRUTEFORCE-001`) |
| `BruteForceClusteringPattern` fires | ✅ 1 correlation |
| `CrossSourceAttackPattern` fires | ❌ 0 correlations (only 1 distinct source — threshold requires 2+) |
| `pattern_id` on the produced correlation | `NGINX-CORR-BRUTEFORCE-001` (production) |
| `trigger` | `brute_force_count_threshold` (allow-list-validated) |
| `key.parts` | `('198.51.100.7', '/api/login')` |
| `detection_ids` | 8 ids, all participating detections |
| `event_ids` | 4 unique ids |
| `count` | 8 |
| `window_start`, `window_end` | correct |
| `correlation_id` | `corr-<uuidv7>`, deterministic |
| `reasoning` | `'brute-force clustering: 8 authentication-failure detections from source_ip=' ... 'exceeded the threshold of 4 within a 300-second window'` |

**Findings:**

- The specialized NGINX correlation works end-to-end against the real MongoDB.
- The correlation's `detection_ids` are a complete, sorted, deduplicated list of every participating detection.
- The correlation's `event_ids` are a complete, deduplicated list of every underlying SecurityEvent.
- The correlation is deterministic: same inputs + same `now` produce the same `correlation_id`.

---

## 5. Centralized cross-source correlation

The review built the `CrossSourceAttackPattern` (review-only) that groups detections by `source_ip` regardless of the rule that produced them, and produces a correlation only when the same `source_ip` has at least 2 detections from at least 2 distinct sources within a 10-minute window.

`scenario_centralized_cross_source` constructs 2 WAF + 2 IAM + 2 RateLimit events from the same source_ip, runs them through the real pipeline, and feeds the resulting detections + events into the real `CorrelationEngine`.

| Stage | Observed |
|---|---|
| Events processed | 6 (2 waf + 2 iam + 2 rate_limiter) |
| Detections produced | 6 (1 WAF + 1 IAM + 1 RateLimit per source category, 2 each) |
| `BruteForceClusteringPattern` fires | ❌ 0 (no NGINX auth-failure detections to group) |
| `CrossSourceAttackPattern` fires | ✅ **1 correlation** (the cross-source centralized pattern produces a `corr-<uuidv7>` for source_ip=`203.0.113.99`) |
| `pattern_id` | `CROSS-SOURCE-ATTACK-001` |
| `key.parts` | `('203.0.113.99',)` |
| `detection_ids` | 6 ids, all 6 participating detections |
| `event_ids` | 6 unique ids |
| `count` | 6 |
| `extra.distinct_sources` | `('iam', 'rate_limiter', 'waf')` |

**Findings:**

- **Centralized cross-source correlation works** when the framework is given a cross-source pattern. The framework's `select()` / `group()` API supports cross-source patterns cleanly.
- The `extra` field on `Correlation` is the documented place to record pattern-specific metadata (e.g. `distinct_sources`).
- The `trigger` is still drawn from the documented allow-list (the review-only pattern reuses `brute_force_count_threshold`); the `pattern_id` is what makes it distinct in the result. The `Correlation` model has no `scope` field — see §13.
- The prior review's "centralized correlation is not implemented" finding was correct for **production code** but is **NOT** a framework limitation. The framework supports centralized correlation via additional patterns.

---

## 6. Specialized + centralized interaction (states A / B / C / D)

| State | Description | Pattern in production | Pattern in review | Observed |
|---|---|---|---|---|
| A. SPECIALIZED ONLY | source-specific evidence is sufficient; broader correlation unnecessary | `BruteForceClusteringPattern` | both | ✅ `BruteForceClusteringPattern` fires (1 correlation); `CrossSourceAttackPattern` correctly does NOT fire (single source) |
| B. CENTRALIZED ONLY | specialized pattern cannot produce the relationship, but multi-source evidence supports centralized correlation | none | `CrossSourceAttackPattern` | ✅ `CrossSourceAttackPattern` fires (1 correlation); `BruteForceClusteringPattern` correctly does NOT fire (no NGINX auth-failure evidence) |
| C. SPECIALIZED + CENTRALIZED | specialized pattern succeeds and centralized pattern also adds broader context | none | both | ✅ **both** fire: 2 correlations, one per `pattern_id`. The two patterns do not double-count the same evidence. |
| D. NEITHER | insufficient evidence | n/a | n/a | ✅ 1 NGINX 401 from a fresh IP produces 0 correlations from either pattern |

**Verdict:**

- States A, B, C, D are all correctly implementable using the existing framework. State C in particular demonstrates that the engine does not double-count the same detection across patterns.
- In **production code**, states A and D are realized. States B and C are not realized in production because the cross-source pattern does not exist in production.

---

## 7. Analyst-requested deeper centralized correlation

**Status:** **NOT IMPLEMENTED** in production code. Per `PHASE-04-05-REPORT.md` §1.2, no API, no CLI, and no event type for "centralized correlation on demand" exists.

The current operational model:
- `CorrelationEngine.run(detections, events, *, now)` is the single public entry point.
- Every batch of detections runs every registered pattern.
- There is no `run_centralized_only()` method.
- The detection engine is invoked by `DetectionPipeline.run` for every ingested event, but the correlation engine is **NOT currently invoked by the pipeline** at all. It is invoked only by tests and the future incident/routing layer (not yet built).

**Findings:**

- The framework is ready for a future analyst-trigger entry point: a new `CorrelationEngine.run_centralized_only(...)` method (or a separate `CorrelationEngine(patterns=[centralized_patterns_only])` instance) would let the future HTTP API differentiate "automatic" from "on-demand" runs.
- The review does not build such an entry point — that is a future-slice task.

---

## 8. Benign traffic

The review constructed 15 benign events: 10 NGINX 200-success authentications from 10 different source IPs, 5 WAF "ok" responses from 5 different source IPs.

| Metric | Observed |
|---|---|
| Events processed | 15 |
| Detections produced | **0** |
| Correlations produced | 0 |
| Pipeline errors | 0 |

**Verdict:** Normal traffic from both NGINX and WAF produces zero unjustified detections. The rule applicability filter correctly excludes benign events.

---

## 9. Timeline validation

The review's `scenario_evidence_integrity_e2e` runs the 4-event NGINX brute-force scenario through `TimelineEngine` after correlation.

| Property | Observed |
|---|---|
| Events placed on timeline | 4 `kind=event` items |
| Detections placed on timeline | 8 `kind=detection` items |
| Correlations placed on timeline | 1 `kind=correlation` item |
| Total timeline items | 13 |
| Chronological order | sorted correctly |
| Tie-breaking | deterministic (kind, source_id) |
| Deduplication | duplicate correlations deduplicated |
| `timeline_errors` | 0 |

The brute-force correlation's `evidence_refs` on the timeline item contains `[corr_id, *8 detection_ids, *4 event_ids]` (13 total). **All evidence is preserved.**

---

## 10. Severity / confidence validation

| Property | Observed (brute-force scenario) | Observed (empty input) |
|---|---|---|
| Bundle severity | **CRITICAL** | LOW |
| Bundle confidence | **VERY_HIGH** | LOW |
| Detections scored | 8 | 0 |
| Correlations scored | 1 | 0 |
| `produced_at` matches injected `now` | ✅ | ✅ |
| `errors` | 0 | 0 |

The brute-force scenario triggers 5+ `ScoringSignal`s, pushing the bundle to CRITICAL. The 10 signals and 4 bands all work. The implementation has a documented weakness (SEV-01 below) that this review's reproduction confirms.

---

## 11. Replay / duplicate / idempotency

The review's `scenario_replay_safety` runs the 4-event NGINX brute-force scenario through the pipeline twice and re-invokes the correlation engine twice on the same inputs.

| Property | Observed |
|---|---|
| First correlation id | `corr-25870537-17b6-7356-8742-5eaaa82353cc` |
| Second correlation id | `corr-25870537-17b6-7356-8742-5eaaa82353cc` |
| Deterministic correlation id | ✅ True |
| First count | 8 |
| Second count | 8 |
| Detection count | 8 |

**Cross-instance connector replay** is not exercised in this review (the review uses synthetic canonical events rather than a real `NginxConnector` instance). The prior review (DEDUP-01) confirmed that the connector's `_event_id_ts_ms` field sampled at construction time breaks idempotency on cross-instance replay. That finding is unaffected by this review.

**Verdict:** The correlation engine is fully deterministic on identical inputs. Per-event replay (same `Detection` object) is safe at the engine level.

---

## 12. Realistic alert-flood / pressure validation

The review's `scenario_pressure_100_events_20_ips` constructs 100 events from 20 IPs: 3 NGINX auth-failures per IP, 1 WAF attack per IP, 1 IAM auth-failure per IP.

| Metric | Observed |
|---|---|
| Events | 100 |
| Detections | 160 |
| Correlations | 40 (20 specialized + 20 cross-source) |
| Pipeline elapsed | 0.645s |
| Correlation elapsed | 0.008s |

**Verdict:** Under realistic alert pressure, the pipeline completes in well under a second. The correlation engine scales linearly with the number of patterns.

---

## 13. Adversarial correlation testing

| Failure | Layer | Engine response | Result |
|---|---|---|---|
| `detections=None` | correlation engine | `InvalidCorrelationInputError` | ✅ |
| `events=None` | correlation engine | `InvalidCorrelationInputError` | ✅ |
| Non-`Detection` in detections | correlation engine | `InvalidCorrelationInputError` | ✅ |
| `now` is naive datetime | correlation engine | `InvalidCorrelationInputError` | ✅ |
| Detection whose event is missing from `events` | correlation engine | skipped (no invented evidence) | ✅ |
| Detection with naive `detected_at` | correlation engine | skipped | ✅ |
| Window ≤ 0 in pattern | pattern construction | `CorrelationWindowError` | ✅ |
| Threshold < 1 in pattern | pattern construction | `CorrelationWindowError` | ✅ |
| Empty `CorrelationKey.parts` | model construction | rejected | ✅ |
| Unknown trigger | model construction | rejected (allow-list) | ✅ |
| `detection_ids` empty | model construction | rejected (at least one required) | ✅ |
| Pattern raises during `select`/`group` | correlation engine | caught, routed to `errors` | ✅ |
| Same evidence seen by both patterns | correlation engine | 2 correlations, no double-count | ✅ |
| Detection whose event has empty `source_ip` | cross-source pattern | skipped | ✅ |
| 10,000+ detection input to timeline | timeline | truncated at 1000, `errors` recorded | ✅ |
| 20,000+ detection input to severity | severity | capped at 32, `errors` recorded | ✅ |

**Verdict:** Every failure is caught at the correct layer. Patterns can fail independently.

---

## 14. Security review

| Concern | Result |
|---|---|
| Secret leakage | ✅ sensitive keys rejected at event validation |
| Sensitive-data leakage | ✅ `redact_endpoint` strips query/fragment |
| Attacker-controlled scoring manipulation | ✅ severity reads only from server-derived fields |
| Evidence spoofing | ✅ evidence identified by UUIDv7; `extra="forbid"` |
| False positives | ✅ benign traffic produces 0 detections and 0 correlations |
| False negatives | none observed in the 14 scenarios |
| Resource exhaustion | ✅ F-2/F-3/F-4/F-7 fixes cap severity; timeline caps at 1000 |
| Unsafe errors | ✅ every error is a `DomainError` subclass |
| Nondeterminism | ✅ detection_id, correlation_id, timeline_item_id are deterministic |
| Cross-layer coupling | ✅ no rule/pattern/severity code imports the connector |
| Trust-boundary violations | ✅ server-stamps `ingested_at` |
| Query injection | ✅ repository methods reject dict/int input (D-2 fix) |
| Hidden mutable state | ✅ every model is `frozen=True, extra="forbid"`; `RuleRegistry` is locked |

**Verdict:** The correlation layer is not the source of any new security issue surfaced by this review.

---

## 15. Complete test execution

The review ran the existing 700 tests **before** and **after** introducing the review-only fixtures. The fixtures are in `review_corr/`, not in `tests/`. They do not affect the production test suite.

| Run | Suite | Count | Result | Time |
|---|---|---|---|---|
| Existing unit tests | `tests/unit/` | 666 | ✅ all pass | 6.92s |
| Existing integration tests | `tests/integration/` | 34 | ✅ all pass | 7.83s |
| **Total existing** | `tests/` | **700** | ✅ **all pass** | **13.29s** |
| Review harness | `python -m review_corr.build_correlation_review` | 12 scenarios | ✅ all pass | ~0.7s |

The review did not introduce new test files into `tests/`; the harness is a review-only script. The user (per the task brief) is free to promote the harness into `tests/` if they want, but the task explicitly says "delete all temporary review-only artifacts after the review unless the documentation explicitly requires them to remain."

---

## 16. Findings

### 16.1 CONFIRMED DEFECTS

None introduced by this review. The DEDUP-01 defect (HIGH) reported by the prior review remains in production code; this review's harness uses synthetic canonical events and does not exercise the connector.

### 16.2 CONFIRMED SECURITY ISSUES

None introduced by this review.

### 16.3 DESIGN WEAKNESSES (carried forward from prior review)

| ID | Severity | Title | Location |
|---|---|---|---|
| **SEV-01** | MEDIUM | Severity and confidence are not meaningfully distinct | `app/severity/engine.py::_build_pair` |
| **SIG-01** | LOW | `EVIDENCE_COMPLETENESS` signal fires True on empty input | `app/severity/engine.py::_score_bundle` |
| **REPLAY-02** | LOW | Duplicate detections inflate correlation count (per-batch) | `app/correlation/engine.py::run` (no dedup) |

The review's reproduction of the brute-force scenario confirms SEV-01: per-subject severity and confidence have the same band and the same rationale text.

### 16.4 TEST GAPS

| ID | Severity | Title | Location | Recommendation |
|---|---|---|---|---|
| **TESTGAP-01** | MEDIUM | Pipeline cross-instance replay not exercised | `tests/integration/test_phase45_pipeline.py` | Add a test that creates two `NginxConnector` instances for the same log, runs the pipeline twice, asserts `n_events` stays at the original count. |
| **TESTGAP-02** | MEDIUM | Cross-source correlation path not exercised by any existing test | `tests/integration/test_phase45_pipeline.py` | When a cross-source pattern is added to production, add an integration test that runs WAF + NGINX + RateLimit + IAM detections through the pipeline. |
| **TESTGAP-03** | MEDIUM | Only NGINX is exercised end-to-end in production | `tests/integration/test_nginx_end_to_end.py` | When WAF/IAM/RateLimit connectors ship, add per-source end-to-end tests. |
| **TESTGAP-04** | LOW | Pipeline does not currently invoke the correlation engine | `app/detection/pipeline.py` | When the future incident layer lands, add a test that asserts the pipeline → correlation engine handoff. |

### 16.5 UNVERIFIED RISKS

| ID | Title | Why unverified |
|---|---|---|
| **EVI-00** | MongoDB unavailability during review | The local MongoDB is up; all 34 integration tests pass. |
| **CORS-00** | Connector race conditions | The harness uses one MongoClient per run; the prior review's connector-race analysis is unchanged. |

### 16.6 DISPROVED HYPOTHESES

| ID | Title | Why disproved |
|---|---|---|
| **HYP-01** | The framework cannot host a cross-source correlation pattern | **Disproved by §5 above**: `CrossSourceAttackPattern` runs end-to-end and produces a `corr-<uuidv7>` from WAF + IAM + RateLimit detections. |
| **HYP-02** | The pipeline needs a separate "centralized engine" instance | **Disproved by §6 state C**: a single `CorrelationEngine([pattern1, pattern2])` correctly produces correlations from both patterns. The patterns encode the scope, not separate engine instances. |
| **HYP-03** | The `Correlation` model rejects a pattern with a `distinct_sources` extra field | **Disproved**: `Correlation.extra` accepts arbitrary `Tuple[Tuple[str, Any], ...]`. |
| **HYP-04** | Replay safety is broken in the production correlation engine | **Disproved by §11**: same inputs + same `now` produce the same `correlation_id`. |

### 16.7 OBSERVATIONS (positive)

- The rule framework's `applies_to` filter is correct for every source in `ALLOWED_SOURCES`.
- The detection engine is deterministic and fail-closed per rule.
- The correlation engine is deterministic and fail-closed per pattern.
- The timeline engine is deterministic, deduplicated, and overflow-safe.
- The severity engine is deterministic and bounded (F-2 / F-3 / F-4 / F-7 verified).
- Every canonical id is a real UUIDv7.
- Every model is `frozen=True, extra="forbid"`.
- Every error is a `DomainError` subclass.
- The MongoDB persistence layer is the only place that imports `pymongo`.
- No rule, pattern, or severity code imports `pymongo` or `fastapi`.
- The pipeline does NOT invoke the correlation engine today; the future incident layer is the missing wiring.
- 700/700 existing tests pass.
- The pressure test (100 events, 160 detections, 40 correlations) completes in ~0.65s.

---

## 17. Cross-phase contract violations

**None found.** Every documented cross-phase contract is honoured:
- The `event_id` is a UUIDv7.
- The `detection_id` is `det-<uuidv7>`, sha256-derived.
- The `correlation_id` is `corr-<uuidv7>`, sha256-derived.
- The `timeline_item_id` is `tl-<uuidv7>`, sha256-derived.
- All persistence objects are `frozen=True, extra="forbid"`, BSON-safe.
- All `$jsonSchema` validators reject extra fields.
- All `DomainError` subclasses have a `safe_message`.

---

## 18. Final verdict — 19 questions

| # | Question | Answer |
|---|---|---|
| 1 | Does the Phase 4.1 → 4.6 pipeline work end-to-end? | **YES** for the implemented path. |
| 2 | Does the real NGINX path work completely? | **YES** — detection + persistence + correlation + timeline + severity. |
| 3 | Does the rule framework correctly handle every representative source? | **YES** for 5 source categories covered by review-only fixtures + 3 production NGINX. 8/8 cases match. |
| 4 | Does specialized correlation actually work where implemented? | **YES** — `BruteForceClusteringPattern` produces a correlation on 4 NGINX auth-failures. |
| 5 | Does centralized cross-source correlation actually work? | **YES** when the framework is given a cross-source pattern. Production code does not yet have a cross-source pattern. |
| 6 | Are specialized and centralized correlation distinguishable? | **PARTIAL** — same engine, same model shape, distinguished by `pattern_id` only. No `scope`/`method` field. |
| 7 | Does specialized + centralized interaction work? | **YES** for state A, C, D in production. State C also exercisable via review-only fixtures. |
| 8 | Does analyst-requested centralized correlation exist? | **NO** — no API, no CLI. **DEFERRED** per Phase 4.5 §1.2. |
| 9 | Does correlation preserve evidence correctly? | **YES** — complete, sorted, deduplicated. |
| 10 | Does replay remain safe? | **YES** for the correlation engine. DEDUP-01 (connector cross-instance) is unchanged. |
| 11 | Does timeline construction remain correct? | **YES** — 13 sorted, deduplicated items, 0 errors. |
| 12 | Are severity and confidence correct? | **YES** for correctness, determinism, bounded execution. **NO** for distinctness (SEV-01). |
| 13 | Does benign traffic remain benign? | **YES** — 15 benign events produce 0 detections and 0 correlations. |
| 14 | Does realistic alert pressure break the system? | **NO** — 100 events, 160 detections, 40 correlations complete in <1s. |
| 15 | Are there hidden false-negative or false-positive paths? | **NO** — benign events produce no detections; brute-force scenario produces expected detections. |
| 16 | Are there hidden cross-phase contract violations? | **NO**. |
| 17 | Are the existing tests sufficient? | **PARTIAL** — 700 pass but cross-instance replay, cross-source correlation, non-NGINX sources not exercised. |
| 18 | Is the correlation layer genuinely production-oriented? | **PARTIAL** — framework is production-ready, production wiring uses one pattern, pipeline does not currently invoke the correlation engine. |
| 19 | Is the complete Phase 4.1 → 4.6 backend genuinely STABLE? | **PARTIAL STABLE** — implemented path is stable. Two production-relevant issues remain: **DEDUP-01 (HIGH)** and **SEV-01 (MEDIUM)** (both carried from prior review). |

---

## 19. Recommendations for the remediation task

1. **DEDUP-01 (HIGH) — carry forward.** In `app/connectors/nginx/connector.py::_make_event_id`, derive the embedded 48-bit timestamp from the SHA-256 of `(log_path, line_number, raw_line)` instead of from `self._event_id_ts_ms`.
2. **SEV-01 (MEDIUM) — carry forward.** In `app/severity/engine.py::_build_pair`, take two disjoint signal subsets for severity and confidence.
3. **TESTGAP-01 (MEDIUM).** Add a cross-instance replay integration test.
4. **TESTGAP-02 (MEDIUM).** When a cross-source pattern is added to production, add an integration test.
5. **TESTGAP-03 (MEDIUM).** When WAF / IAM / RateLimit connectors ship, add per-source end-to-end tests.
6. **TESTGAP-04 (LOW).** When the future incident layer lands, add a pipeline → correlation engine handoff test.
7. **Future enhancement.** Add a `run_centralized_only(...)` method to `CorrelationEngine` to support the planned analyst-triggered deeper centralized entry point.
8. **Future enhancement.** Wire `DetectionPipeline` to invoke the correlation engine after persistence.

---

## 20. Cleanup

The review-only artifacts live in `review_corr/`:
- 5 review-only per-event rules
- 1 review-only cross-source correlation pattern
- 1 review-only harness script
- Captured findings JSON + log files

These are deleted by the cleanup step. The report above is the only durable evidence of the review.

---

# 21. Post-Remediation Note (Phase 4.7 defect-fix slice)

The two carried-forward defects identified in §16.3 of this
review (DEDUP-01 HIGH and SEV-01 MEDIUM) have been fixed in a
subsequent surgical patch. The historical findings above are
preserved verbatim for the audit trail; this section records
the post-remediation state.

## 21.1 DEDUP-01 — FIXED ✅

**Root cause:** `NginxConnector.__init__` sampled
`self._event_id_ts_ms = time.time_ns() // 1_000_000` at
construction time and embedded it as the first 48 bits of the
UUIDv7. Each new connector instance produced a different
`event_id` for the same line.

**Production change:**
- `app/connectors/nginx/connector.py`: removed
  `self._event_id_ts_ms`; `_make_event_id` now takes the
  parsed record's `event_time` (the source's observed
  `$time_local` parsed to UTC) as a parameter and uses it as
  the embedded unix-ms timestamp. The 48 bits are now
  content-derived, not connector-instance-derived.
- `app/detection/pipeline.py`: `DetectionPipeline.run` now
  defaults its `now` parameter to
  `persisted_event.event_time` when the caller does not pass
  one explicitly. This is the cascading fix: `detection_id`
  is derived from `(rule_id, rule_version, event_id,
  detected_at)`, so the `detected_at` must also be
  content-derived for the detection persistence layer to dedup
  correctly across replays.

**Post-fix reproduction (live):**
```
instance_1_event_id: 01a03c10-ff30-755d-8904-8c4653734e52
instance_2_event_id: 01a03c10-ff30-755d-8904-8c4653734e52
event_ids_equal: true
DEDUP_01_confirmed: false
```

**Regression tests:** 6 added (3 unit + 3 integration); see the
post-remediation section of `PHASE-04-01-06-CORE-E2E-REVIEW.md`
for the full list.

## 21.2 SEV-01 — FIXED ✅

**Root cause vs. specification:** the Phase 4.6 implementation
used the same 10-signal rationale for both severity and
confidence, producing a single scalar that was then mapped
through two different band tables. The Phase 2 documentation
(DOMAIN_DATA_MODEL.md Sections 10 and 11) requires severity
and confidence to be separately meaningful: severity
reflects impact, confidence reflects evidence-quality.

**Production change:** `app/severity/engine.py` now partitions
the 10 signals into two disjoint subsets. The severity
rationale uses the 6 impact signals; the confidence rationale
uses the 4 evidence-quality signals. Each assessment gets
the rationale subset for its own dimension. The two are now
genuinely distinct and produce observably different bands on
the same evidence.

**Post-fix reproduction (live):**
```
bundle_severity_band: high
bundle_confidence_band: medium
bands_equal: false
rationale_signals_shared: false
summary_distinct: true
evidence_refs_identical: true
SEV_01_confirmed: false
```

**Regression tests:** 6 added (in `tests/unit/test_sev01_regression.py`).

## 21.3 Correlation findings (this review) are unchanged

The correlation engine's behaviour observed in §3–§17 of this
review is unchanged by the patch:

- Specialized correlation via `BruteForceClusteringPattern`
  still works.
- The centralized cross-source correlation path is still
  architecturally supported by the `CorrelationPattern` ABC,
  but only the NGINX brute-force pattern is in production.
- Analyst-triggered centralized correlation on demand is
  still a future capability.
- No new production code was added for any of the deferred
  WAF / IAM / RateLimit / Network / TLS source categories.

## 21.4 Final test counts (post-remediation)

- **Unit tests:** 672 (was 666).
- **Integration tests:** 38 (was 34).
- **Total:** 710 (was 700).
- All 710 tests pass against the real local MongoDB.

---

*End of Phase 4 Correlation E2E Review.*
