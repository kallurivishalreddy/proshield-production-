# ProShield — Final Core Backend Review
# Phase 4.1 → 4.4

**Reviewer:** Independent Senior Backend / Security / Detection-System Auditor  
**Date:** 2026-08-28  
**Scope:** Complete integrated Phase 4.1–4.4 system (SecurityEvent → ingestion → MongoDB → Rule Framework / Registry → NGINX connector → Detection Engine → Detection)

---

## Executive Summary

| Verdict | **CORE READY** — Phase 4.1–4.4 is safe to hand off to Phase 4.5 |
|---------|------------------------------------------------------------------|
| Overall architecture | Sound — clear boundaries, deterministic per-event pipeline, fail-closed |
| Security posture | Strong — sensitive data rejection, secret scrubbing, no raw payload logging |
| Test coverage | 459/459 passing (430 unit + 29 integration) |
| Cross-phase contracts | Consistent — all boundaries verified |
| Critical defects | **NONE** |
| Non-blocking findings | 6 (documented below) |

The integrated backend correctly implements the documented pipeline:
```
SecurityEvent → ingestion → MongoDB → Rule Registry → NGINX connector → Detection Engine → Detection
```

All Phase 4.1–4.4 requirements are satisfied. The system is ready for Phase 4.5 (detection persistence + correlation engine).

---

## 1. Cross-Phase Findings

### 1.1 Contract Verification: SecurityEvent Model (Phase 4.1) ↔ Connectors (Phase 4.3) ↔ Detection (Phase 4.4)

| Contract Element | Phase 4.1 Spec | Phase 4.3 Implementation | Phase 4.4 Consumption | Status |
|------------------|----------------|--------------------------|----------------------|--------|
| `event_id` | UUIDv7, server-stamped if missing | Connector derives deterministic UUIDv7 from SHA-1(log_path:line:raw_line) + per-instance frozen timestamp | Detection engine uses as `evidence_refs` and `target_event_id` | CONSISTENT |
| `source` | Must be in `ALLOWED_SOURCES` | Hardcoded `"nginx"` in connector | Rules filter by `source` in applicability | CONSISTENT |
| `event_type` | Must be in `ALLOWED_EVENT_TYPES` | Mapping produces canonical types: `authentication_failure`, `request_blocked`, `rate_limit_exceeded`, `authentication_success` | Rules filter by `event_type` in applicability | CONSISTENT |
| `source_ip` | Bounded string | Parsed from `remote_addr` | Used in `reasoning` string (PII noted) | CONSISTENT |
| `endpoint` | Raw URL, bounded | Parsed from `path` | **Redacted** in `reasoning` via `redact_endpoint()` (D-1 fix) | CONSISTENT (post-fix) |
| `details` | JSON-shaped, bounded, sensitive keys rejected | Populates `http_method`, `status_code`, `protocol`, `body_bytes_sent`, `referer`, `user_agent`, `log_line_number` | Rules read `status_code` from details | CONSISTENT |
| `provenance` | Collector + source_event_id | `collector="nginx"`, `source_event_id=SHA-1(log_path:line:raw_line)` | Preserved through ingestion; available for correlation | CONSISTENT |
| `ingested_at` | Server-stamped by ingestion service | Connector sets to `event_time` (overwritten by service) | Not used by detection engine | CONSISTENT |
| `asset` / `destination` | Optional | Propagated from connector constructor | Not used by detection engine | CONSISTENT |

**No cross-phase contract mismatches found.** The canonical `SecurityEvent` is the single source of truth across all phases.

### 1.2 Ingestion Service (Phase 4.1) ↔ Connector (Phase 4.3) ↔ Rule Registry (Phase 4.2) ↔ Detection Engine (Phase 4.4)

| Boundary | Contract | Verified |
|----------|----------|----------|
| Connector → Ingestion | `collect()` yields `SecurityEvent`; ingestion stamps `ingested_at`, generates `event_id` if missing | Integration tests pass |
| Ingestion → MongoDB | `to_canonical_dict()` produces BSON-safe dict; `$jsonSchema` validator enforces bounds | Integration tests pass |
| MongoDB → Rule Registry | Repository `find_by_canonical_identity` uses `(source, source_event_id)` | Integration tests pass |
| Rule Registry → Detection Engine | `registry.applies_to(event)` returns evaluable rules; engine calls `rule.evaluate(event)` | Unit + integration tests pass |
| Detection Engine → Detection | Produces frozen `Detection` with `detection_id` (det-<uuidv7>), `rule_id`, `rule_version`, `evidence_refs`, `reasoning`, `detected_at` | Unit tests pass |

### 1.3 Cross-Phase Audit Follow-Ups (from Phase 4.1 Review)

| Finding | Original Claim | Re-verification Result |
|---------|----------------|------------------------|
| C-1: Logging scrubber leaks `Authorization: Bearer <token>` | Scrubber misses Bearer tokens | **DISPROVED** — Scrubber correctly redacts `Bearer` via `_FORBIDDEN_SUBSTRINGS` and `_redact_key_equals_value` |
| C-2: `account.id` / `device.id` accept empty strings | Missing `min_length=1` on nested IDs | **DISPROVED** — Both have `StringConstraints(min_length=1, ...)` |

Both cross-phase findings from the Phase 4.1 review are **false positives**. No code changes required.

---

## 2. End-to-End Test Evidence

### 2.1 Complete Pipeline Tests (Integration)

All 29 integration tests pass against real MongoDB:

| Test Module | Tests | Coverage |
|-------------|-------|----------|
| `test_ingestion_service.py` | 6 | Ingestion idempotency, conflict detection, server-side stamping, connector ingestion |
| `test_nginx_ingestion.py` | 7 | NGINX connector → ingestion → MongoDB round-trip |
| `test_nginx_end_to_end.py` | 4 | Connector → SecurityEvent → Rule applicability + evaluation (BRUTEFORCE rule) |
| `test_security_event_repository.py` | 12 | CRUD, dedup, conflict, indexes, canonical identity lookup |
| `test_persistence_failures.py` | 1 | Connection failure handling |

**Key end-to-end scenarios verified:**
- Brute-force log (401 on `/api/v1/login`) → 2 detections (FAILURE-001 + BRUTEFORCE-001)
- Directory enumeration (404 on `/.env`) → 1 detection (ACCESS-DENIED-001)
- 5xx burst (502 on `/api/orders/1`) → 1 detection (STATUS-ANOMALY-001)
- 429 burst (429 on `/api/items`) → 1 detection (RATE-LIMIT-001)
- 404 on public path (`/blog/typo`) → 0 detections

### 2.2 Unit Test Coverage

| Module | Tests | Key Areas |
|--------|-------|-----------|
| `test_detection_engine.py` | 33 | Construction, input validation, per-scenario detections, contract, quarantine, applicability, E2E with connector |
| `test_phase44_rules.py` | 32 | All 4 new rules: positive, negative, edge, metadata, loader, lifecycle |
| `test_nginx_rule.py` | 20 | Phase 4.3 BRUTEFORCE rule: positive, negative, metadata, applicability, registry |
| `test_nginx_connector.py` | 29 | File I/O, stats, health, source_event_id determinism, parse errors, strict mode |
| `test_nginx_mapping.py` | 24 | Status→event_type mapping, auth success conditions, envelope canonicality |
| `test_nginx_parser.py` | 28 | Combined format parsing, bounds, malformed rejection, error message safety |
| `test_rule_registry.py` | 34 | Registration, versioning, lifecycle, applicability, superseded guard |
| `test_rule_loader.py` | 10 | Discovery, factory/instance merge, error handling |
| `test_rule_evaluation.py` | 10 | RuleEvaluation contract, bounds, frozen |
| `test_redact_endpoint.py` | 44 | Redaction helper + 5 rules × 4 secrets + fragment/None cases + 2 E2E |

**Total: 459 tests passing.**

---

## 3. Security Findings

### 3.1 Sensitive Data Handling

| Vector | Risk | Mitigation | Status |
|--------|------|------------|--------|
| `SecurityEvent.details` | Passwords, tokens, keys in open-ended dict | Pydantic validator rejects forbidden key names (`_reject_sensitive_keys`) at construction | **ENFORCED** |
| `Detection.reasoning` | Raw endpoint with query string (`?token=SECRET`) | `redact_endpoint()` strips query, fragment, truncates path (D-1 fix) | **FIXED** (44 regression tests) |
| `SecurityEvent.endpoint` (canonical) | Raw URL preserved for analysts | Unchanged — only `reasoning` is redacted; canonical event retains full endpoint | **BY DESIGN** |
| `source_ip` in `reasoning` | PII / GDPR concern | Documented as out-of-scope for per-event layer; correlation/routing layer will handle | **DOCUMENTED** (not a 4.4 blocker) |
| Logging | Accidental secret emission | Structured JSON logging + scrubber (`_scrub`): redacts URI userinfo, `KEY=VALUE` for sensitive keys, global forbidden substrings | **ENFORCED** |
| Error messages | Attacker-controlled bytes in exceptions | Parser/connector errors never include raw line; engine errors only include rule_id, version, exception type/message | **ENFORCED** |

### 3.2 Trust Boundaries

| Boundary | Verification |
|----------|--------------|
| **Collector → Trusted Processing** (Boundary 2) | Ingestion service is sole entry point; validates, stamps, persists; connectors cannot bypass |
| **Detection Engine → Rules** | Engine only calls `Rule.evaluate(event)`; rules cannot access DB, network, other rules |
| **Persistence** | Only `app/persistence/` imports `pymongo`; detection/rules/connector/ingestion do not |
| **No Cross-Source Coupling** | NGINX connector imports no rule modules; rules import no connector modules |

### 3.3 Authorization / RBAC

Phase 4.1–4.4 correctly **defers** authentication, RBAC, and object-level authorization to Phase 3+ slices. No auth surface exists in the current codebase (by design).

---

## 4. Architecture Findings

### 4.1 Boundary Integrity

| Boundary | Rule | Verified |
|----------|------|----------|
| `app/detection/` | No `pymongo`, `fastapi`, network, connector imports | PASS |
| `app/rules/_library/nginx/` | No `pymongo`, `fastapi`, network, connector imports | PASS |
| `app/connectors/nginx/` | No rule framework, detection engine imports | PASS |
| `app/ingestion/` | No detection engine imports; does not call engine | PASS |
| `app/persistence/` | Only place with `pymongo` imports | PASS |

### 4.2 Rule Framework Architecture

| Property | Implementation | Status |
|----------|----------------|--------|
| **Single source of truth** | `RuleRegistry` is authoritative for rule state, enabled flag, versioning | PASS |
| **Candidate → Approved → Enabled funnel** | Registry enforces: CANDIDATE cannot be enabled; only APPROVED+enabled are evaluable | PASS |
| **Applicability hot path** | `registry.applies_to(event)` filters by source+event_type; engine only evaluates applicable rules | PASS |
| **Deterministic iteration** | `list_all()` sorted by `(rule_id, version)`; detection order stable | PASS |
| **Versioning** | New version supersedes old; superseded version cannot be re-enabled (guard) | PASS |
| **Rule isolation** | Rules only read `SecurityEvent` fields; no cross-rule state | PASS |

### 4.3 Detection Engine Architecture

| Property | Implementation | Status |
|----------|----------------|--------|
| **Per-event only** | No cross-event state, no windows, no counting | PASS |
| **Deterministic** | Same `(event, now, registry)` → same `DetectionResult`; `now` captured once per call | PASS |
| **Fail-closed per rule** | Catches `RuleEvaluationError` + bare `Exception`; quarantines to `errors`; other rules continue | PASS |
| **Total pipeline** | Always returns `DetectionResult` for valid `SecurityEvent`; never raises under normal conditions | PASS |
| **Frozen models** | `Detection`, `DetectionResult` are `frozen=True, extra="forbid"` | PASS |
| **BSON/JSON safe** | `to_dict()` produces only primitive types; `datetime` → ISO string; `extra` → dict | PASS |

### 4.4 NGINX Connector Architecture

| Property | Implementation | Status |
|----------|----------------|--------|
| **Pure parsing** | `parser.py`: no I/O, no globals, no time, no logging | PASS |
| **Observation-only mapping** | `mapping.py`: status→event_type only; no detection logic | PASS |
| **Deterministic IDs** | `source_event_id` = SHA-1(log_path:line:raw_line); `event_id` = UUIDv7 from frozen timestamp + SHA-1 | PASS |
| **Error handling** | Per-line parse errors counted, skipped; file-level errors surfaced via stats/health | PASS |
| **Health probe** | Reports `status=degraded` + `connector_errors>=1` for missing file; idempotent | PASS |

---

## 5. Confirmed Defects and Severity

| ID | Defect | Severity | Status | Evidence |
|----|--------|----------|--------|----------|
| **D-1** | `Detection.reasoning` leaked raw endpoint with query string (secrets) | **HIGH** (pre-fix) | **FIXED** | `redact_endpoint()` added; 44 regression tests in `test_redact_endpoint.py` |
| **D-2** | `detection_id` docstring claimed determinism but implementation used `os.urandom` salt | **MEDIUM** (doc drift) | **FIXED** | SHA-256 of `(rule_id, rule_version, event_id, ts_ms)`; 2 new regression tests |
| **D-3** | Rule overlap: 401 on auth path fires both `NGINX-AUTH-FAILURE-001` and `NGINX-AUTH-BRUTEFORCE-001` | **LOW** (architectural) | **DOCUMENTED** | Per-event layer intentionally emits both; correlation engine will deduplicate |
| **D-4** | `RuleEvaluationError.__str__` includes rule_id twice (engine prefixes it again) | **COSMETIC** | **NOT FIXED** | Does not affect correctness; trivial to fix in Phase 4.5+ |

**No HIGH/CRITICAL defects remain unfixed.**

---

## 6. Important Remaining Risks (Non-Blocking)

| Risk | Description | Phase to Address |
|------|-------------|------------------|
| **R-1: `source_ip` in `reasoning` is PII** | Detection reasoning includes `source_ip` (e.g., `from '198.51.100.77'`). GDPR may require redaction. | Phase 4.5+ (correlation/routing layer) |
| **R-2: `Detection.extra` permits arbitrary `Any`** | `extra: Tuple[Tuple[str, Any], ...]` — future rule could put non-BSON-safe values (e.g., `datetime` objects). Current rules don't use it. | Phase 4.5 (persistence validator) |
| **R-3: `detection_id` timestamp is derivable** | First 48 bits of `det-<uuidv7>` encode `detected_at` (Unix ms). UUIDv7 property, not a bug. | Documented; no fix needed |
| **R-4: Per-instance connector replay only** | `event_id` determinism only holds within same connector instance (frozen timestamp). Cross-instance replay gets new `event_id` (bypasses dedup). Documented as per-instance contract. | Phase 4.5+ (if cross-instance replay needed) |
| **R-5: Test gaps (G-1..G-5 from Phase 4.4 review)** | G-1: Registry raise during `applies_to`; G-2: Missing `event_id` handling; G-3: Non-empty `extra` round-trip; G-4: Registry mutation between runs; G-5: Substring greedy-match FP test. All low severity. | Phase 4.5+ |
| **R-6: 200 OK on auth endpoint without user** | Connector emits no event for 2xx without `remote_user` on auth path. Legitimate successful auth without user (e.g., token in header) would not generate `authentication_success`. | Future connector enhancement |

**None of these risks block Phase 4.5.** They are documented, understood, and deferred to appropriate future slices.

---

## 7. Phase 4.5 Handoff Readiness

### What Phase 4.5 Receives

| Component | State | Notes |
|-----------|-------|-------|
| **SecurityEvent model** | Complete, frozen, validated | Canonical envelope; sensitive key rejection; UUIDv7 IDs |
| **Ingestion Service** | Complete, idempotent, server-stamped | `ingest()`, `ingest_from_connector()`; Duplicate/Conflict errors |
| **MongoDB Repository** | Complete, schema + indexes | `create()`, `get_by_event_id()`, `find_by_canonical_identity()`, `count()` |
| **NGINX Connector** | Complete, deterministic, observable | `collect()`, `health()`, stats; 5 production rules registered |
| **Rule Framework** | Complete, governed, fast applicability | `RuleRegistry`, `load_rules_from_specs`, lifecycle, versioning |
| **Detection Engine** | Complete, per-event, deterministic, fail-closed | `DetectionEngine.run()`, `Detection`, `DetectionResult` |
| **5 NGINX Rules** | All `SOURCE_SPECIFIC`, `APPROVED`, `enabled=True` | BRUTEFORCE-001, FAILURE-001, ACCESS-DENIED-001, STATUS-ANOMALY-001, RATE-LIMIT-001 |
| **Test Suite** | 459/459 passing | Unit + integration against real MongoDB |

### What Phase 4.5 Must Implement (per documented deferral)

1. **Detection persistence** — Store `Detection` records (BSON-safe `to_dict()` ready)
2. **Correlation engine** — Windowed counting, grouping across events (D-3 overlap resolution)
3. **Severity / Confidence engines** — Not in per-event layer (Section 66)
4. **Incident engine** — Turn correlated detections into investigation cases
5. **Report / Routing engines** — Per ROUTING_MATRIX.md
6. **Ingestion → Detection wiring** — Connect `ingest_from_connector` output to `DetectionEngine.run`

### Required Reading for Phase 4.5 Team

- `docs/PHASE 4/PHASE 4-04/PHASE-04-04-REVIEW.md` — Defects D-1, D-2 (fixed), D-3, D-4; Test gaps G-1..G-5
- `docs/PHASE 4/DETECTION_ENGINEERING_AND_FUTURE_AI.md` — Sections 8, 9, 12, 13, 18, 66
- `app/detection/redact.py` — Single source of truth for endpoint redaction
- `app/detection/engine.py:_make_detection_id` — Deterministic UUIDv7 construction

---

## 8. Final Verdict

### CORE READY

**Phase 4.1–4.4 is safe to hand off to Phase 4.5.**

| Criterion | Result |
|-----------|--------|
| All MVP requirements (FR-01 through FR-06 scope) satisfied for phases in scope | PASS |
| No scope violations (no correlation, severity, incident, routing, AI, persistence) | PASS |
| Cross-phase contracts consistent (SecurityEvent, provenance, IDs, registry, engine) | PASS |
| Security boundaries intact (no secret leakage, trust boundaries enforced) | PASS |
| Deterministic per-event detection engine with fail-closed rule evaluation | PASS |
| 5 production NGINX rules derived from safe-simulation telemetry, fully tested | PASS |
| 459/459 tests passing (unit + integration against real MongoDB) | PASS |
| All critical defects fixed (D-1, D-2); remaining defects documented non-blocking | PASS |
| Architecture clean: no hidden dependencies, no cross-layer coupling | PASS |

**Recommendation:** Proceed to Phase 4.5 (Detection Persistence + Correlation Engine + Ingestion-Detection Wiring).

---

## Appendix: Test Run Evidence

```
$ python -m pytest tests/unit/ -q
430 passed in 2.39s

$ python -m pytest tests/integration/ -q
29 passed in 5.52s

$ python -m pytest tests/ -q
459 passed in 7.91s
```

---

*End of Phase 4.1–4.4 Core Backend Review*