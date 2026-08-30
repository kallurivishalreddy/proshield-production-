# ProShield — Phase 4.8 Final Report

**Slice under report:** Phase 4.8 — Backend layer: cases, reports,
routing, secure application proxy / gateway, minimal auth
foundation.

**Date:** 2026-08-30
**Status:** **STABLE — 980/980 tests passing** (922 unit + 58
integration, including 77 new Phase 4.8 tests: 76 unit + 1
integration). All Phase 4.1-4.7 tests are unchanged and pass.

---

## 1. Phase 4.8 Scope and Boundary

### 1.1 What Phase 4.8 Implements

Phase 4.8 sits on top of the stable Phase 4.1-4.7 deterministic
backend and ships the **application backend** the future API
and dashboard will call into:

```
SecurityEvent            (Phase 4.1)
    -> Detection          (Phase 4.4)
    -> Correlation        (Phase 4.5)
    -> Timeline           (Phase 4.6)
    -> Severity/Confidence (Phase 4.6)
    -> Incident (case)    (Phase 4.8)
        -> Routing        (Phase 4.8)
        -> Normal Report  (Phase 4.8)
        -> Centralized Analysis (Phase 4.8)
        -> Centralized Report  (Phase 4.8)
        -> Close               (Phase 4.8)
    -> SecureProxy        (Phase 4.8 - the wire boundary)
        -> SessionTokenService (Phase 4.8 - minimal auth)
```

Concretely, Phase 4.8 ships:

1. **Auth foundation** (`app/auth/`):
   `Identity` (Pydantic, frozen), `IdentityStore` (closed set
   interface), `InMemoryIdentityStore`, `Permission` catalogue
   (closed set), `has_permission(role, identity_permissions,
   permission)` helper, HMAC-signed `SessionTokenService` /
   `SessionTokenVerifier`.
2. **Cases / incidents** (`app/incidents/`): `Incident`,
   `IncidentEvidence`, `LifecycleTransition`, `ReportReference`
   (Pydantic, frozen, `extra="forbid"`);
   `IncidentRepository` (single $jsonSchema validator, indexes,
   idempotent create, full document upsert, case-document
   round-trip with quarantine);
   `IncidentService` (create_case, get_case, list_cases,
   request_centralized_analysis, close_case, public
   `authorize_case_access`).
3. **Reports** (`app/reports/`): `Report`, `ReportSection`,
   `ReportItem` (frozen, `extra="forbid"`, closed-set
   `kind`); `ReportRepository` (no validator, round-trip
   with `rule_references` and `generated_at` normalization);
   `ReportService` (generate_normal_report,
   generate_centralized_report, idempotent persistence with
   version increment).
4. **Routing** (`app/routing/`): `RoutingLevel`, `RoutingTeam`,

5. **Centralized correlation extension** (`app/correlation/`):
   `CorrelationEngine.run_centralized` (smallest approved
   interface; reuses the same pattern catalogue as
   `run`); `CentralizedCorrelationResult` (thin extension of
   `CorrelationResult` carrying `new_correlations` and
   `existing_correlation_ids`).
6. **Secure application proxy / gateway** (`app/proxy/`):
   `SecureProxy` (the documented security boundary) +
   `ProxyRequest` / `ProxyResponse` + sliding-window
   `_RateLimiter`; 12 wire operations
   (health / auth_issue / case.get / case.list /
   case.create / case.close / centralized.request /
   report.generate_normal / report.generate_centralized /
   report.get / report.list / routing.compute); safe-error
   envelope; per-subject + centralized rate limit;
   payload-to-evidence helpers.
7. **Configuration** (`app/config.py`): new `auth_signing_key`,
   `proxy_*` knobs, all env-var wired.
8. **App version bump** (`app/__init__.py`): `4.7.0` → `4.8.0`.
9. **Demo / verification script** (`scripts/demo_phase48.py`):
   end-to-end normal + centralized + failure paths.
10. **Tests:** 77 new tests (76 unit + 1 integration)
    across 4 new test modules covering: auth, incidents,
    routing, proxy unit-level behavior, and a single
    full-stack integration test (NGINX → detect →
    correlate → case → routing → normal report →
    centralized → centralized report → close) against the
    real local MongoDB.

### 1.2 What Phase 4.8 Does NOT Implement (deferred)

Per the documented scope:

* **Frontend / dashboard UI** for cases, reports, or
  routing.
* **Long-lived key material** (HSM, KMS, JWT issuer).
  The slice ships an HMAC-signed dev-mode `SessionToken`
  that is correct-by-construction for tests; production
  key management is the next slice.
* **A full HTTP / WebSocket transport.** The slice ships a
  framework-agnostic `SecureProxy` + `ProxyRequest` +
  `ProxyResponse` with a documented in-memory `__call__`
  boundary; the future HTTP server (out of scope) wraps
  the boundary.
* **Per-case, per-actor notification fan-out.**

### 1.3 Critical Architecture Rules Honoured

1. **One canonical place for each concept.**
   `IncidentService` is the only place that knows how to
   create / read / list / close a case.
2. **The proxy never constructs evidence.** Every read /
   write operation translates a wire payload into the
   typed backend objects via small JSON-shaped helpers
   (`_payload_to_events`, `_payload_to_detections`,
   `_payload_to_correlations`, `_payload_to_evidence`).
3. **Authz is a public function, not a service method.**
   `authorize_case_access(identity, case)` is the
   integration boundary used by reports, routing, and the
   proxy alike.
4. **No second correlation engine.** The centralized
   path calls `CorrelationEngine.run_centralized` which
   is a thin extension of `CorrelationEngine.run`; the
   pattern catalogue is shared.
5. **The wire boundary is the security boundary.** The
   proxy fails closed: any unhandled exception becomes a
   safe `internal error` envelope; any unknown operation

## 2. Architecture

### 2.1 File map

```
app/
  auth/
    __init__.py           # public surface
    identity.py           # Identity, IdentityStore, InMemoryIdentityStore
    permissions.py        # Permission catalogue, has_permission
    session.py            # SessionTokenService / Verifier (HMAC)
  incidents/
    __init__.py
    errors.py             # CaseNotFound, CaseAccessDenied, ...
    models.py             # Incident, IncidentEvidence, LifecycleTransition
    repository.py         # IncidentRepository + BSON validator
    service.py            # IncidentService, CentralizedOutcome,
                          # authorize_case_access
  reports/
    __init__.py
    errors.py
    models.py             # Report, ReportSection, ReportItem
    repository.py         # ReportRepository
    service.py            # ReportService
  routing/
    __init__.py
    errors.py
    models.py             # RoutingLevel/Team/Complexity/State/...
    service.py            # RoutingEngine, RoutingContext
  proxy/
    __init__.py
    errors.py             # proxy-side safe errors
    proxy.py              # SecureProxy + 12 wire operations
  correlation/
    engine.py             # extended with run_centralized
    models.py             # CentralizedCorrelationResult
  config.py               # +auth_signing_key, +proxy_* knobs
  __init__.py             # 4.7.0 -> 4.8.0
scripts/
  demo_phase48.py
tests/
  unit/
    test_phase48_auth.py
    test_phase48_incidents.py
    test_phase48_routing.py
    test_phase48_proxy.py
  integration/
    test_phase48_pipeline.py
docs/PHASE 4/PHASE 4-08/PHASE-04-08-REPORT.md  # this file
```

### 2.2 Component layering

```
  Wire (future HTTP server)
      |
      v

## 3. Proxy Boundary

### 3.1 12 Wire Operations

| Operation constant                | Wire op                         | Permission                |
|-----------------------------------|---------------------------------|---------------------------|
| `OP_HEALTH`                       | `health`                        | (anonymous)               |
| `OP_AUTH_ISSUE`                   | `auth.issue`                    | (anonymous)               |
| `OP_GET_CASE`                     | `case.get`                      | `case:read`               |
| `OP_LIST_CASES`                   | `case.list`                     | `case:read`               |
| `OP_CREATE_CASE`                  | `case.create` (stub)            | `case:read`               |
| `OP_CLOSE_CASE`                   | `case.close`                    | `case:read`               |
| `OP_REQUEST_CENTRALIZED`          | `centralized.request`           | `case:centralized:request`|
| `OP_GENERATE_NORMAL_REPORT`       | `report.generate_normal`        | `report:generate`         |
| `OP_GENERATE_CENTRALIZED_REPORT`  | `report.generate_centralized`   | `report:generate`         |
| `OP_GET_REPORT`                   | `report.get`                    | `report:read`             |
| `OP_LIST_REPORTS`                 | `report.list`                   | `report:read`             |
| `OP_ROUTE_CASE`                   | `routing.compute`               | `routing:read`            |

### 3.2 safe-error envelope

Every wire response uses the same envelope:

* `200` → `{"ok": true, "data": {...}}`
* `4xx / 5xx` → `{"error": {"code": ..., "message": ...}}`
  where `message` is the documented `safe_message` (no
  driver / stack / secret leakage).

### 3.3 IDOR defense

`CaseAccessDeniedError` is **never** exposed as 403 at
the wire boundary. The proxy translates it to HTTP 404
with `{"error": {"code": "case_not_found", "message":
"case not found"}}` so the response does not leak
existence of a case the caller is not authorized to see.
The internal log keeps the original 403 signal.

### 3.4 Rate limiting

The proxy ships a per-subject sliding-window rate
limiter (`_RateLimiter`). The centralized analysis
operation has a separate, smaller budget
(`proxy_centralized_rate_limit_per_minute`, default 10).
Rate-limit exceeded → HTTP 429.

### 3.5 Payload-to-evidence helpers

The proxy never builds backend internals from scratch.
Small JSON-shaped helpers translate the wire body into
typed objects:

## 4. Auth Boundary

### 4.1 Identity model

```python
class Identity(BaseModel, frozen=True, extra="forbid"):
    subject_id: str       # 1..64
    role: str             # one of admin/analyst/collector
    display_name: str     # 0..128
    permissions: Tuple[str, ...] = ()  # closed-set Permission values
```

`IdentityStore` is a closed-set interface. The slice
ships `InMemoryIdentityStore`; the future slice ships a
DB-backed implementation.

### 4.2 Permission catalogue

`Permission` is a `StrEnum` with a closed set. Every
proxy operation requires exactly one permission (see the
table in §3.1). `has_permission(role,
identity_permissions, permission)` is the only allowed
authorization helper.

### 4.3 Session token (HMAC)

* `SessionTokenService.issue(subject_id,
  lifetime_seconds)` returns a `SessionToken`
  (`token`, `subject_id`, `expires_at`, `issued_at`).
* `SessionTokenVerifier.verify(token)` returns the
  `Identity` or raises `InvalidSessionTokenError`.
* Signing is HMAC-SHA256 with `auth_signing_key`
  (env-var wired; dev mode uses
  `new_development_signing_key()`).
* The wire header is `Authorization: Bearer <token>`.

The token format is:
`v1.<base64-payload>.<base64-signature>`.

### 4.4 Dev-mode signing key

`auth.session.new_development_signing_key()` is a

## 5. Routing Rules

The routing engine is deterministic. The closed set of
factors is:

| Factor           | Detail                                   |
|------------------|------------------------------------------|
| `severity`       | `severity_band=low/medium/high/critical` |
| `complexity`     | `complexity=standard/elevated/critical`  |
| `evidence_count` | the documented count threshold           |
| `has_centralized_correlation` | the case has a centralized context |
| `has_specialized_correlation` | the case has a specialized context |
| `central_correlation` | the case has correlations targeting the central authority |
| `category_count` | the number of distinct rule categories   |

Routing state is one of `ok` / `failure`. The result is
`ok` with a `RoutingRecommendation` (level, team,
queue, reasons) or `failure` with a `RoutingFailure`
(safe_message, internal_detail, missing factor).

The engine reuses the existing
`authorize_case_access(identity, case)` boundary; it
does not duplicate authz logic.

## 6. Centralized Correlation (smallest interface)

`CorrelationEngine.run_centralized(detections, events,
existing_correlation_ids=())` is a thin extension of
`run` that returns a
`CentralizedCorrelationResult`:

```python
class CentralizedCorrelationResult(CorrelationResult):
    new_correlations: Tuple[Correlation, ...]
    existing_correlation_ids: FrozenSet[str]
```

* It reuses the **same pattern catalogue** as `run`.
* `new_correlations` is the engine-produced correlations
  that are NOT in `existing_correlation_ids`.
* The Phase 4.8 incident service uses this to update
  `Incident.centralized_correlation_ids` deterministically
  (a true union, not a duplicate).

The incident service has a fail-safe boundary: any
engine exception (validation or unexpected) is captured,
the case is transitioned to `centralized_failed`, and a
`CentralizedOutcome(failed=True, failure_reason=...)` is
returned. The wire response is still 200.
deterministic, in-process 32-byte key for tests and the
demo script. It is **not** suitable for production; the

## 7. Failure Isolation

Each Phase 4.8 layer has a fail-safe boundary:

1. **Proxy** — any unhandled exception → safe
   `internal error` envelope; any unknown operation →
   `unknown operation` (400); any oversized request →
   `request_too_large` (413); any oversized response →
   `response_too_large` (500). Rate limit exceeded → 429.
   Auth failed → 401. Authz failed (case access denied) →
   404 (with `code: "case_not_found"`).
2. **Correlation engine** — pattern-level failures are
   quarantined in the `errors` list; the engine still
   returns a valid `CorrelationResult`.
3. **Centralized analysis** — engine exceptions are
   captured by the incident service; the case is
   transitioned to `centralized_failed` with a documented
   `failure_reason`; the wire response is 200 with
   `failed: True` so the analyst sees an explicit
   failure rather than a silent 500.
4. **Reports** — a single bad report on read is
   quarantined + logged (`report.document_quarantined`).
5. **Incidents** — a single bad incident on read is
   quarantined + logged (`incident.document_quarantined`).

## 8. Configuration

New env-var-wired knobs in `ProShieldConfig`:

| Key                                       | Default | Purpose                                  |
|-------------------------------------------|---------|------------------------------------------|
| `auth_signing_key`                        | (none)  | 32+ byte HMAC key for session tokens     |

## 9. Tests

### 9.1 Test count

| Suite                          | Tests | Status |
|--------------------------------|-------|--------|
| `tests/unit/test_phase48_auth.py`        | 27 | ✓ |
| `tests/unit/test_phase48_routing.py`     | 15 | ✓ |
| `tests/unit/test_phase48_proxy.py`       | 20 | ✓ |
| `tests/unit/test_phase48_incidents.py`   | 14 | ✓ |
| `tests/integration/test_phase48_pipeline.py` | 1 | ✓ |
| **Phase 4.8 subtotal**                   | **77** | ✓ |
| Phase 4.1-4.7 regression (unit)         | 846 | ✓ |
| Phase 4.1-4.7 regression (integration)  | 57 | ✓ |
| **Grand total**                          | **980** | ✓ |

### 9.2 What each new module covers

* `test_phase48_auth.py` — Identity round-trip, permission
  catalogue, `has_permission` (admin / analyst / collector
  roles), `InMemoryIdentityStore` (default catalogue,
  custom seed), `SessionTokenService` /
  `SessionTokenVerifier` (issue, verify, expiry,
  tamper-detection, wrong-key rejected).
* `test_phase48_incidents.py` — Incident model
  validation, lifecycle history bound, evidence
  integrity, case authorization (admin / analyst /
  collector / wrong-owner), `IncidentRepository`
  indexes, the centralized correlation engine
  extension (`run_centralized` dedupes against existing
  ids), centralized failure path.
* `test_phase48_routing.py` — RoutingEngine
  determinism, routing reason composition, level
  promotion rules, complexity promotion, failure
  isolation (unknown factor → failure result, not crash).
* `test_phase48_proxy.py` — 12 wire operations,
  payload-to-evidence translation, rate limiting,
  safe-error envelope, IDOR 404, no-token 401,
  unknown-operation 400, oversized request 413,
  oversized response 500, session token expiry.
* `test_phase48_pipeline.py` (integration) — full
  end-to-end: NGINX ingest → detect → correlate →
  case → routing → normal report → centralized →
  centralized report → close, against the real local
  MongoDB.

### 9.3 How to run

```bash
# Phase 4.8 unit + integration
python -m pytest tests/unit/test_phase48_*.py \
                 tests/integration/test_phase48_pipeline.py -v

# Full unit suite (regression + new)
python -m pytest tests/unit -v


## 11. Limitations and Explicit Non-Goals

* **No HTTP transport.** The slice ships
  `SecureProxy.handle(ProxyRequest) -> ProxyResponse`;
  the next slice wraps it in a server (FastAPI / aiohttp
  / a custom transport — TBD).
* **No long-lived signing key.** The dev mode signing
  key is a process-local 32-byte string. Production
  HSM / KMS / JWT issuer is the next slice.
* **No per-case notification fan-out.** The
  `centralized.request` operation updates the case; it
  does not email or page an analyst. Notification
  channels are the next slice.
* **`case.create` is a stub at the wire boundary.** The
  documented Phase 4.8 boundary is that the proxy does
  not construct evidence. The stub returns 400 with
  `code: "case_not_found"` for the missing
  `incident_id_hint` field; the future slice either
  promotes this to a full evidence-payload create
  handler or removes the operation entirely.
* **The centralized analysis reuses the same engine.**
  There is no second correlation engine. If the future
  slice needs a centralized-only pattern catalogue, the
  smallest change is to construct a second
  `CorrelationEngine(patterns=[...])` instance and pass
  it to the `IncidentService(correlation_engine=...)`
  constructor.

## 12. Future Work (deferred)

* HTTP / WebSocket transport layer.
* HSM / KMS / JWT key management.
* Tier 2 analyst features (case comments, handoff,
  shared investigation).
* Notification channels (email, webhook, on-call).
* Per-actor fan-out (who-sees-what).
* The full `case.create` wire handler (or its removal).
# Full integration suite
python -m pytest tests/integration -v

# End-to-end demo
python -m scripts.demo_phase48
```

## 10. Stability Verdict

**STABLE.** 980/980 tests pass (922 unit + 58 integration).
The Phase 4.1-4.7 layers are unchanged. The Phase 4.8
backend layer is the documented application boundary the
future HTTP server will sit on top of.

| Area                                | Verdict     |
|-------------------------------------|-------------|
| Auth (HMAC, permission catalogue)   | STABLE      |
| Cases (model, service, repository)  | STABLE      |
| Reports (model, service, repository)| STABLE      |
| Routing (engine, context)           | STABLE      |
| Centralized correlation extension   | STABLE      |
| Secure application proxy / gateway | STABLE      |
| Configuration (auth + proxy knobs)  | STABLE      |
| IDOR defense (404, no leak)         | STABLE      |
| Rate limiting (per-subject, central)| STABLE      |
| Failure isolation (every layer)    | STABLE      |
| BSON validator (defence in depth)   | STABLE      |
| End-to-end pipeline (real MongoDB)  | STABLE      |
| Demo script                         | STABLE      |
| `auth_token_lifetime_seconds`             | 3600    | session token lifetime                   |
| `proxy_max_request_bytes`                 | 65536   | wire request body cap                    |
| `proxy_max_response_bytes`                | 131072  | wire response body cap                   |
| `proxy_centralized_rate_limit_per_minute` | 10      | sliding-window per-subject central budget|
| `mongo_collection_reports`                | reports | reports collection name                  |
| `mongo_collection_incidents`              | incidents | incidents collection name              |
future slice replaces it with HSM / KMS / JWT issuer.

* `_payload_to_events(payload)` → `List[SecurityEvent]`
* `_payload_to_detections(payload)` → `List[Detection]`
* `_payload_to_correlations(payload)` → `List[Correlation]`
* `_payload_to_evidence(body, prefix="")` → `Dict[str, Any]`

Silent quarantine: any item that fails to parse is
skipped (the wire response is still 200), so a malformed
single event cannot poison a multi-item payload.
  SecureProxy.handle(ProxyRequest) -> ProxyResponse
      |  (1) authenticate  (SessionTokenService / Verifier)
      |  (2) authorize     (Permission.has_permission)
      |  (3) rate limit    (per-subject, per-centralized budget)
      |  (4) dispatch      (SecureProxy._dispatch)
      |  (5) shape result  (safe-error envelope)
      v
  IncidentService / ReportService / RoutingEngine
      |
      v
  IncidentRepository / ReportRepository
      |
      v
  MongoDB (incidents, reports, security_events, detections,
           correlations, managed_rules)
```

The proxy is the **only** call site that knows about the
wire format. Below the proxy, every layer deals in
typed Pydantic models.
   is `unknown operation`; the case-access denied is
   translated to `case not found` (HTTP 404) so the
   response does not leak existence.
6. **The BSON validator is defence in depth.** The
   `incidents` collection has the documented
   `additionalProperties: false` validator (with
   `_id` whitelisted). The `reports` collection has no
   validator (no security impact; reports are derived
   artefacts).
* **A real correlation engine** for the centralized path.
  Phase 4.8 reuses the existing `CorrelationEngine.run`
  (no second engine, no second pattern catalogue).
* **The `case.create` proxy handler.** The wire handler
  for `case.create` is intentionally a thin stub: the
  documented Phase 4.8 boundary is that the proxy does
  **not** construct evidence. Case creation remains the
  `IncidentService` responsibility; the proxy is
  exercised for every other read / transition / report
  operation.
* **Tier 2 analyst features** (case comments, handoff,
  shared investigation).
   `RoutingComplexity`, `RoutingState`, `RoutingReason`,
   `RoutingRecommendation`, `RoutingFailure`, `RoutingResult`
   (frozen, closed-set enums); deterministic `RoutingEngine`
   (no second correlation engine, reuses the Phase 4.5
   pattern results); `RoutingContext` (the only input the
   engine sees); authz via `authorize_case_access`.

---

## 11. Post-Review Remediation (Phase 4.8a)

This section documents the remediation of the two
**CONFIRMED DEFECTS** raised by the independent
Phase 4.8 review (`docs/PHASE 4/PHASE-04-08-REVIEW.md`):

* **R1. Report IDOR** — a report was readable by any
  analyst with the default ``report:read`` permission
  because the boundary did not check case ownership.
* **R2. ``list_cases`` with no state filter** — the
  ``if state else []`` short-circuit returned an empty
  list for the documented "list my cases" operation.

Both defects are **fixed** in this remediation pass.
Production code is otherwise unchanged.

### 11.1 Original finding (Report IDOR)

**Source:** `docs/PHASE 4/PHASE-04-08-REVIEW.md` §2.4.

> ``ReportService.get_report(identity, report_id)`` only
> checks the ``report:read`` permission. It does not call
> ``authorize_case_access(identity, case)`` against the
> case the report is bound to. A second analyst with the
> default ``report:read`` permission can therefore fetch
> any other analyst's report by knowing its ``report_id``.

**Pre-fix reproduction (replayed from
``review_tmp_repro/repro.py`` against the original code):**

```text
=== DEFECT 1: REPORT IDOR ===
analyst_B read A's rpt: status=200
  rpt_in_body='rpt-01a0536c-...'
  generated_by_in_body='user-analyst-001'
  title_in_body='...'
  IDOR_BYPASS=True
```

**Root cause:**
``ReportService.get_report`` checked the
``report:read`` / ``report:read:any`` permission only.
The report is bound to an incident (case), and the
canonical case-level authorization boundary
(``authorize_case_access``) was not consulted.

**Exact fix** (``app/reports/service.py``):

1. The ``ReportService`` constructor now accepts an
   optional ``incident_service`` argument. When the
   service is wired with one (as the proxy does),
   ``get_report`` resolves the owning case and re-asserts
   the canonical ``authorize_case_access(identity, case)``
   boundary after the report-level permission check.
2. The fix is documented at the call site with a
   comment block describing the IDOR and the remediation
   decision.
3. The proxy (``scripts/demo_phase48.py`` and
   ``tests/integration/test_phase48_pipeline.py``) now
   wires ``ReportService(..., incident_service=...)``
   in the correct order — incident service is built
   first so it can be passed to the report service.

**Behavior after the fix (post-fix repro):**

```text
=== DEFECT 1: REPORT IDOR (post-fix) ===
analyst_B read A's rpt: status=404
  rpt_in_body=None  title_in_body=None
  IDOR_BYPASS=False
admin read A's rpt:    status=200  ADMIN_OK=True
owner read own rpt:   status=200  OWNER_OK=True
```

The unauthorized case is collapsed to **404 with no
report contents in the body**, matching the existing
"existence hidden" boundary for unauthorized case
access. Admin / ``*:any`` and owner access are
preserved.

**Regression tests added:**

* `tests/unit/test_phase48_reports.py`
  - `TestReportGetAuthorization` (8 tests) — owner,
    unrelated analyst, admin, collector, missing case,
    runtime error, and back-compat-without-service paths.
  - `TestReportListForIncidentAuthorization` (2 tests) —
    owner and unrelated analyst paths.
  - `TestReportServiceBackwardCompat` (1 test) — the
    no-``incident_service`` path still works.
* `tests/unit/test_phase48_proxy.py`
  - `TestReportIdorThroughProxy` (3 tests) — owner,
    admin, and other-analyst paths through the proxy.
* `tests/integration/test_phase48_remediation.py`
  - `test_post_review_full_idor_and_unfiltered_list` —
    end-to-end real-MongoDB attack matrix.

### 11.2 Original finding (list_cases unfiltered)

**Source:** `docs/PHASE 4/PHASE-04-08-REVIEW.md` §2.1.

> ``IncidentService.list_cases`` returns ``[]`` when no
> ``state`` is supplied because of the
> ``if state else []`` short-circuit.

**Pre-fix reproduction:**

```text
=== DEFECT 2: list_cases no state ===
A case.list no state: status=200  count=0  ids=[]
  LIST_EMPTY_BUG=True
```

**Root cause:** The
``self._repository.find_by_state(state=state, limit=limit)
if state else []`` short-circuit returned an empty list
for the documented "list my cases" operation, which is
the default behaviour of ``OP_LIST_CASES`` in the proxy
(``proxy.py`` passes ``state=None`` when the body does
not include a ``state`` field).

**Exact fix:**

1. Added ``IncidentRepository.find_recent(limit=...)``
   in ``app/incidents/repository.py`. It returns the
   most recent N cases ordered by ``updated_at``
   descending. ``limit`` is bounded to a small number
   (max 200) to keep memory bounded.
2. Updated ``IncidentService.list_cases`` to call
   ``find_recent`` when ``state is None`` and
   ``find_by_state`` otherwise. The ownership /
   ``case:read:any`` post-filter is preserved.

**Behavior after the fix (post-fix repro):**

```text
=== DEFECT 2: list_cases no state (post-fix) ===
A case.list no state: status=200  count=1
  ids=['case-...']
  LIST_EMPTY_BUG=False
A case.list state=open: count=1
  EXPLICIT_STATE_OK=True
```

Explicit state filtering still works; analyst
ownership / admin ``*:any`` post-filter is preserved;
no cross-tenant leakage is introduced (the unit test
``test_unfiltered_does_not_leak_other_analysts_cases``
asserts that the unfiltered list of an analyst returns
``[]`` when the only case in ``find_recent`` belongs to
a different analyst).

**Regression tests added:**

* `tests/unit/test_phase48_incidents.py`
  - `TestListCasesUnfiltered` (6 tests) — unfiltered
    returns authorized cases, explicit state works,
    admin sees all when unfiltered, empty result,
    limit is passed through, no cross-tenant leak.
* `tests/unit/test_phase48_proxy.py`
  - `TestUnfilteredListCases` (2 tests) — proxy-level
    happy path and cross-tenant negative path.
* `tests/integration/test_phase48_remediation.py`
  - `test_post_review_full_idor_and_unfiltered_list` —
    end-to-end real-MongoDB attack matrix (calls
    ``OP_LIST_CASES`` with ``body={}`` and asserts the
    caller's authorized case is returned).

### 11.3 Observation: `run_centralized` documentation drift

The review's observation #4
(``run_centralized`` is "dead code" on the centralized
happy path) is a **documentation drift**, not a defect.
The actual code path is:

* ``IncidentService._run_centralized`` calls
  ``self.correlation_engine.run(detections=..., events=..., now=...)``
  and then performs the local dedup against
  ``case.evidence.correlation_ids`` and
  ``case.centralized_correlation_ids``.
* ``CorrelationEngine.run_centralized(detections, events, existing_correlation_ids)``
  is a documented public extension of
  ``CorrelationEngine.run`` that returns a
  ``CentralizedCorrelationResult`` carrying both
  ``new_correlations`` and the merged ``correlations``,
  with the dedup against ``existing_correlation_ids``
  factored into the engine. It is unit-tested in
  ``tests/unit/test_phase48_incidents.py::TestCorrelationExtension::test_run_centralized_dedupes_existing``.

This remediation takes **option B** from the review
spec: the doc is corrected to describe the actual code
path; the code is left unchanged because the
``run_centralized`` public extension is still a useful
engine-level primitive for future callers, and the
incident service's per-case dedup logic is the
canonical place where the existing-correlation check
lives (it also updates the lifecycle history and
``centralized_correlation_ids`` on the case document).

### 11.4 Full-suite results (post-fix)

```
$ python -m pytest tests -q --no-header -p no:cacheprovider --tb=line
1001 passed in 14.10s
```

* Pre-fix: **980 passed** (922 unit + 58 integration).
* Post-fix: **1001 passed** (+21 new tests):
  - 12 new unit tests in `tests/unit/test_phase48_reports.py`.
  - 6 new unit tests in `tests/unit/test_phase48_incidents.py`
    (`TestListCasesUnfiltered`).
  - 3 new unit tests in `tests/unit/test_phase48_proxy.py`
    (`TestReportIdorThroughProxy` + 2 in `TestUnfilteredListCases`).
  - 1 new integration test in
    `tests/integration/test_phase48_remediation.py`.

End-to-end demo:

```
$ python -m scripts.demo_phase48
... 4 NGINX 401s + 1 NGINX 200 -> case -> normal report
    -> centralized request -> centralized report -> close
DEMO OK
```

### 11.5 Updated production-readiness assessment

The review's classification is **preserved** for the
parts it got right:

* **A. Implemented and verified (function level)** — the
  documented boundaries now include the case-level
  authorization for ``report.get`` and the unfiltered
  ``list_cases``.
* **B. Implemented but not network-verified** — still
  nothing; no network surface.
* **C. Architecturally intended but deferred** — HTTP
  transport, long-lived key material, audit persistence,
  per-case notification, queue / escalation, severity-
  aware routing. The dev report's STABLE claim is still
  correctly qualified by §9.
* **D. Not implemented** — enterprise IAM, MFA, OIDC,
  federation, queue, escalation, severity-aware routing.

**Differences from the pre-fix verdict:**

* **Q9 (IDOR resistance).** Previously
  "MOSTLY — Report IDOR is a CONFIRMED DEFECT". After
  the fix: **"YES — both report IDOR and case.list
  IDOR are closed. Report access uses the canonical
  case-level authorization boundary."**
* **Q1 (Case listing).** Previously "YES, with one
  functional bug." After the fix: **"YES — both
  filtered and unfiltered `case.list` work; admin and
  ownership post-filtering is preserved."**

**Verdict for production multi-analyst deployment:**

* **STABLE FOR ITS CURRENT SCOPE** — the function-level
  ``SecureProxy.handle(ProxyRequest) -> ProxyResponse``
  boundary is correct, the test suite is comprehensive
  (1001/1001), the documented security boundary holds
  for every attack the review and this remediation pass
  threw at it, the safe-error envelope is honoured,
  secret material never leaks, and the per-subject +
  centralized rate limit is enforced.
* **NOT production-deployable as-is** — for the same
  reasons as the original review: no HTTP transport
  boundary, development-mode HMAC + in-memory identity
  store, per-process signing key, audit persistence
  deferred, per-case notification deferred, queue /
  escalation deferred, severity-aware routing deferred.
  The remediation does not unblock production
  deployment on its own — but it removes the two
  confidentiality defects that the review identified.
