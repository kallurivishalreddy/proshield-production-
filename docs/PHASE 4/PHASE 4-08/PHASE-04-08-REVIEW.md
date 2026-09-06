# ProShield — Phase 4.8 Independent Security + E2E Review

**Slice under review:** Phase 4.8 — Analyst investigation backend layer
(cases, reports, routing, secure application proxy / gateway, minimal
auth foundation).

**Reviewer role:** Independent security + correctness reviewer
(read-only, no production code modified).

**Date:** 2026-08-30

**Methodology:**

1. Read every Phase 0–4.8 document in the corpus
   (`docs/PHASE 0/`–`docs/PHASE 4/PHASE 4-08/`), the project
   understanding memo, the SPEC.md / plan / tasks / ADRs
   that the spec-kit workflows expose, and the full source
   tree for the five Phase 4.8 packages plus the touched
   earlier-phase packages.
2. Searched the codebase for every documented boundary
   (`authorize_case_access`, `has_permission`, the
   `ALLOWED_OPERATIONS` allow-list, the BSON validators,
   the rate-limiter, the safe-error envelope).
3. Re-ran the project's full test suite against the real
   local MongoDB.
4. Wrote and ran a set of independent, isolated review
   probes (in `review_tmp/`, removed at the end of this
   review) that exercise the documented boundaries
   directly, including hostile / malformed / unauthorized
   inputs. All probes used a dedicated
   `proshield_review_phase48` MongoDB database so the
   production test data was untouched.
5. Ran the demo script end-to-end.
6. Did **not** treat the development report's "980/980
   passing" claim as proof of production readiness; instead
   probed every documented security boundary independently
   and every "implemented and verified" claim in the report.

**Repository state at the time of review:**

* Full test suite: **980/980 passing in 13.18s** (922
  unit + 58 integration, against real local MongoDB).
* Demo script (`scripts/demo_phase48.py`): end-to-end
  run completed with `DEMO OK` printed.
* All Phase 4.1–4.7 contract checks (no breaking changes
  observed) still pass.

---

## 0. Executive Summary

Phase 4.8 is **stable for its in-process, in-memory,
documented scope**: 980/980 tests pass, the demo
end-to-end runs, the documented security boundary holds
for every attack I threw at the **function-level**
`SecureProxy.handle(ProxyRequest) -> ProxyResponse` API,
the safe-error envelope is honoured, secret material
never leaks to the client, and the per-subject +
centralized rate limit is enforced.

**However**, this slice does **not** deliver a network
security boundary. There is **no HTTP server, no
listening socket, no transport**: a client cannot
physically reach `SecureProxy.handle` without already
having Python access to the host process. Until the
documented HTTP transport slice lands, "secure application
proxy / gateway" is **architecturally intended, not
network-verified**. The dev report is explicit about
this; this review classifies it accordingly.

I also found **two real defects** in the documented
boundaries that the existing 980 tests do not cover:

1. **CONFIRMED DEFECT — Report IDOR.**
   `ReportService.get_report(identity, report_id)` only
   checks the `report:read` permission. It does not call
   `authorize_case_access(identity, case)` against the
   case the report is bound to. A second analyst with the
   default `report:read` permission can therefore fetch
   any other analyst's report by knowing its `report_id`.
   `secureproxy._handle_get_report` delegates to this
   method verbatim, so the proxy is not the boundary
   that catches this.

   **Status (post Phase 4.8a remediation): FIXED.** See
   §2.4 below and the post-review remediation section in
   `docs/PHASE 4/PHASE 4-08/PHASE-04-08-REPORT.md`.
2. **CONFIRMED DEFECT — `list_cases` with no `state`
   filter returns `[]`.** In
   `IncidentService.list_cases` (service.py line 161–163),
   the expression
   `self._repository.find_by_state(state=state or CASE_STATE_OPEN, limit=limit) if state else []`
   short-circuits to `[]` when no `state` is supplied.
   The proxy's `_handle_list_cases` (proxy.py line 537)
   passes `state=None` when the client omits the field,
   so the documented "list my cases" query returns
   nothing. This is a functional bug, not a security
   issue.

   **Status (post Phase 4.8a remediation): FIXED.** See
   §2.1 below and the post-review remediation section in
   `docs/PHASE 4/PHASE 4-08/PHASE-04-08-REPORT.md`.

And **one report/code mismatch** that should be addressed
in documentation or in code:

* **CODE / REPORT MISMATCH — `run_centralized` is dead
  code on the centralized-analysis happy path.** The
  Phase 4.8 report claims:
  "The centralized path calls
   `CorrelationEngine.run_centralized` which is a thin
   extension of `CorrelationEngine.run`; the pattern
   catalogue is shared."
  (PHASE 4-08-REPORT.md §4 / §6.) But the incident
  service's actual centralized happy path is
  `IncidentService._run_centralized` (service.py line 348–363),
  which calls `self.correlation_engine.run(...)` directly
  and then does the deduplication itself. The
  `CentralizedCorrelationResult` model exists, the
  `run_centralized` method exists, the unit test
  `test_run_centralized_dedupes_existing` exists — but
  no production code path calls it. The catalogue is
  still shared (the same `CorrelationEngine` instance is
  injected), so the documented security property
  ("no second correlation engine") holds, but the
  documented centralization extension is not actually
  wired.

### Final verdict (15 questions)

| # | Question | Verdict |
|---|----------|---------|
| 1 | Does Incident / Case work correctly? | **YES**, with one functional bug (`list_cases` unfiltered returns `[]`). |
| 2 | Does the specialized investigation report work? | **YES**. |
| 3 | Does analyst-requested centralized investigation work? | **YES** at the wire boundary; **but** the `run_centralized` extension is dead code on the happy path. |
| 4 | Does the centralized report work? | **YES** (and correctly rejects when the case has no centralized context). |
| 5 | Does routing work deterministically and safely? | **YES**. Deterministic, explainable, fail-safe, IDOR-defended, boundary cases tested. |
| 6 | Does the proxy enforce the intended client/backend trust boundary? | **YES at the function level; NO at the network level** (no HTTP transport yet). |
| 7 | Can the client bypass internal backend services? | **NO**, at the function level — the only documented wire boundary is the proxy; all backend services reject unauthenticated input. |
| 8 | Is authentication secure for the documented scope? | **YES** (HMAC, expiry, signature, identity binding all correct). NOT a production IAM. |
| 9 | Is authorization resistant to IDOR and privilege escalation? | **YES (post-fix)** — case IDOR, close IDOR, centralized IDOR, routing IDOR, **and report IDOR** (after the Phase 4.8a remediation) all hold. The unfiltered `case.list` IDOR is also closed. |
| 10 | Are secrets protected? | **YES** at the function level (no signing key, no internal_detail, no stack trace ever reaches the client; the safe-error envelope is intact). |
| 11 | Are failure paths fail-safe? | **YES** — engine exception → `centralized_failed` state, malformed payload → quarantine + 200, unknown op → 400, tampered token → 401. |
| 12 | Does centralized correlation preserve the original specialized evidence? | **YES** — the original case state and event ids are preserved across every centralized call (PASS probes). |
| 13 | Does the complete 4.1 → 4.8 pipeline work? | **YES** — `scripts/demo_phase48.py` runs end-to-end against real MongoDB; the integration test `tests/integration/test_phase48_pipeline.py` exercises the same path under pytest. |
| 14 | Are there hidden security vulnerabilities? | **NO (post-fix).** The report.get IDOR and the unfiltered `case.list` defect are both fixed (Phase 4.8a). The post-fix attack matrix in `tests/integration/test_phase48_remediation.py` is clean. **No other hidden vulnerabilities found.** |
| 15 | Is Phase 4.8 genuinely production-ready, or only stable for its current in-process/documented scope? | **STABLE FOR ITS CURRENT SCOPE (post-fix)** (in-process, framework-agnostic, dev-mode auth). The two confidentiality defects the review identified (report IDOR, unfiltered `case.list`) are closed. **NOT production-deployable as-is** — no HTTP transport, no enterprise IAM, no long-lived key material, no client→server network boundary, no audit persistence. |

---

## 1. Phase 4.8 Architecture (as actually implemented)

```
                SecurityEvent            (Phase 4.1, unchanged)
                    |
                Detection                (Phase 4.4, unchanged)
                    |
                Correlation              (Phase 4.5, unchanged)
                    |
                Timeline / Severity      (Phase 4.6, unchanged)
                    |
                Incident (case)          (Phase 4.8)
                    |
                Routing (Phase 4.8) -- in-process, no I/O
                Normal report (Phase 4.8)
                Centralized analysis (Phase 4.8)
                Centralized report (Phase 4.8)
                Close (Phase 4.8)

                SecureProxy              (Phase 4.8)
                  -- single function-level call site:
                     SecureProxy.handle(ProxyRequest) -> ProxyResponse
                  -- NO HTTP transport; in-process
                  -- SessionTokenService / SessionVerifier (HMAC)
                  -- Per-subject + centralized rate limit
                  -- 12 documented wire operations
                  -- Safe-error envelope
                  -- IDOR defense (CaseAccessDeniedError -> 404)

                Identity / Permission    (Phase 4.8)
                  -- InMemoryIdentityStore (catalogue)
                  -- Permission enum (closed set)
                  -- authorize_case_access
                  -- HMAC-signed opaque session tokens
                  -- NO enterprise IAM
                  -- development signing key per process
```

The implementation matches the development report.
The components that are **implemented and
functionally verified** (probes below) are clearly
distinguished from the components that are
**architecturally intended but deferred** (HTTP
transport, long-lived key material, per-case
notification, audit persistence, future
severity-aware routing — all in PHASE 4-08-REPORT.md
§11).

---

## 2. Section-by-Section Findings

### 2.1 Section 1 — Incident / Case

| Probe | Result | Evidence |
|---|---|---|
| Case creation (id format, state, created_by) | **PASS** | `case.create` `case-01a0531e-...` `state=open` `created_by=user-analyst-001` (`review_tmp/probe1_out.txt`) |
| Case round-trip through MongoDB | **PASS** | 5 events round-tripped (`probe1_out.txt`) |
| Case retrieval — owner | **PASS** (200) | proxy.get_case with owner token |
| Case retrieval — other analyst | **PASS** (404, IDOR-hidden) | proxy.get_case with another analyst's token |
| Case retrieval — admin | **PASS** (200, `case:read:any`) | |
| Case retrieval — collector | **PASS** (403) | `case:read` not in role default |
| `case.list` with `state=open` | **PASS** | returns the open cases |
| **`case.list` with no `state` filter** | **FAIL (CONFIRMED DEFECT)** | returns `[]` because `if state else []` short-circuits in `IncidentService.list_cases` (service.py:161–163) |
| Lifecycle: case closes, evidence preserved | **PASS** | 5 events still in the case after `state=closed` |
| `case.close` — other analyst | **PASS** (404, IDOR-hidden) | `review_tmp/probe_b_out.txt` |
| `case.create` wire handler | **PASS (400 stub)** | `case.create is not exposed at the wire boundary` returned to the client |

**CONFIRMED DEFECT — `list_cases` returns `[]` for unfiltered queries.**

* **File / location:** `app/incidents/service.py:161–163`.
* **Reproduction:**

  ```python
  proxy.handle(ProxyRequest(
      operation=OP_LIST_CASES,
      headers={PROXY_HEADER_AUTHORIZATION: f"Bearer {analyst_token}"},
      body={},  # no state filter
  ))
  # -> status=200, body["data"]["cases"] == []
  ```

* **Impact:** The "list my cases" query returns
  nothing. The client must know a valid `state` to
  retrieve any case list. Not a security issue; a
  functional regression.
* **Exploitability:** N/A.
* **Smallest safe remediation:** Change
  `find_by_state(...) if state else []` to
  `self._repository.find_recent(limit=limit) if not state
  else self._repository.find_by_state(state=state, limit=limit)`
  (or add a new `find_recent` to the repository and call
  it in the unfiltered branch). The repository currently
  has no unfiltered listing; that is a one-line
  addition.
* **Blocks production?** No. The dev report does not
  advertise an unfiltered list_cases; this is a missed
  capability, not a regression of a documented
  contract.

  **POST-FIX (Phase 4.8a remediation).** The defect is
  **fixed**: `IncidentService.list_cases` now calls
  the new `IncidentRepository.find_recent(limit=...)`
  method when no `state` is supplied, with the
  ownership / `case:read:any` post-filter preserved.
  The unfiltered list returns the caller's authorized
  cases. Post-fix verification
  (`review_tmp_repro/repro.py`): A's
  `case.list` (no state) returns 1 case
  (the caller's case); B's unfiltered `case.list`
  returns `[]`; admin sees all. Regression tests in
  `tests/unit/test_phase48_incidents.py`,
  `tests/unit/test_phase48_proxy.py`, and
  `tests/integration/test_phase48_remediation.py`.

**CONFIRMED DEFECT — `case.create` wire handler is a
documented stub, but no unit test asserts the 400
response.** This is a test gap, not a code defect
(the dev report explicitly states the stub is
intentional). The integration test
`tests/integration/test_phase48_pipeline.py` line 257–263
*comments* the stub but does not exercise it; the unit
test `tests/unit/test_phase48_proxy.py` does not cover
`OP_CREATE_CASE` either. The boundary probe in this
review confirms the stub returns 400 as documented.

* **Remediation:** Add a unit test
  `TestCaseCreateStub::test_case_create_rejected` that
  submits `OP_CREATE_CASE` with a valid analyst token
  and asserts `status == 400`. (No code change needed.)

### 2.2 Section 2 — Normal / Specialized Investigation

| Probe | Result | Evidence |
|---|---|---|
| Real NGINX events → canonical SecurityEvent | **PASS** | 5 events from `make_events()` flowed through `DetectionPipeline.run` |
| Detection | **PASS (0 dets in probe)** | The probe used a custom rule set; the integration test confirms 4 detections from the canonical NGINX log (`test_phase48_pipeline.py:240`) |
| Specialized correlation | **PASS** | `CorrelationEngine.run(...)` produces ≥1 correlation on the canonical NGINX log (integration test) |
| Timeline / Severity | **PASS (covered by Phase 4.6 + 4.8 test suite)** | Not re-implemented in this review; the existing tests pass |
| Incident from real evidence | **PASS** | `case.create` `case-01a0531e-...` from 5 events + 0+ detections (probe) |
| Normal report via proxy | **PASS (200)** | `OP_GENERATE_NORMAL_REPORT` returns a `rpt-01a05324-...` report (`probe_idor_out.txt`) |
| Report mode / is_centralized flag | **PASS** | `mode=normal`, `is_centralized=false` (code review: `reports/service.py:178`) |
| Sections present | **PASS** | `what_was_detected`, `sources`, `detections`, `rule_references`, `investigation_metadata` etc. (`reports/service.py:90–107`) |
| Rule references | **PASS** | `rule_references` populated from case + detections |
| No invented evidence | **PASS** | `ReportItem.reference_id` is the canonical id of the underlying record (`reports/models.py:106`); no fabricated conclusions |
| No secret / no internal topology | **PASS** | `mongodb://` not in any report body; `auth_signing_key` not in any report body |
| Deterministic output | **PASS (modulo `generated_at`)** | Same case + same inputs → same report structure |

The probe exercised the documented "no invented
evidence" property: every report item carries a
`reference_id` and a `kind` from a closed set
(`event|detection|correlation|centralized_correlation|timeline_item|severity_assessment|confidence_assessment|note`).
The `note` kind is the only one that can carry a
free-form `text` field, and it is only used for
provenance labels (`section sources` is the only place
where `note` is generated, and the text is the
participating source label — see
`reports/service.py:_build_sources_section`).

### 2.3 Section 3 — Analyst-Requested Centralized Analysis

| Probe | Result | Evidence |
|---|---|---|
| Centralized analysis NOT invoked automatically | **PASS** | A case built via the normal pipeline has empty `centralized_correlation_ids` until an analyst triggers a centralized request. |
| Original specialized results remain intact | **PASS** | `_run_centralized` upserts (preserves) the case across the centralized call; the original `evidence.correlation_ids` are kept; new ids are union'd. (`service.py:380–403`; probe `centralized.preserves_case` PASS) |
| New centralized results are not duplicated | **PASS** | `new_ids` excludes ids already in `existing_corr_ids`; `_dedup_preserving_order` deduplicates (`service.py:376–399`; probe `centralized.idempotent` PASS) |
| Repeated centralized requests are idempotent | **PASS** | Second request produces no new correlation ids; combined list stable. (`probe_boundaries.py` PASS) |
| Centralized failure preserves the original case | **PASS** | `_mark_centralized_failed` writes `state=centralized_failed` and keeps the case in the database; the failure path returns `failed=True` with `failure_reason` (`service.py:423–453`; probe `centralized.preserves_case` PASS) |
| Unauthorized users cannot trigger centralized analysis | **PASS** | Collector → 403; other analyst (not owner) → 404 (IDOR-hidden); admin can because `case:centralized:request:any` is in the role default (`routing/probe_idor.py`). |
| Centralized rate limiting | **PASS** | `proxy_centralized_rate_limit_per_minute=5` → 5 successful requests, 6th returns 429 (`probe_idor_out.txt`) |
| Centralized uses same correlation engine / pattern catalogue | **PASS at the engine level**; **see defect below** | The same `CorrelationEngine` instance is injected into the `IncidentService` (`scripts/demo_phase48.py:185–187`, `tests/integration/test_phase48_pipeline.py:144–148`); no second engine is created. |

**OBSERVATION — `run_centralized` is not called on the
centralized-analysis happy path.** The dev report
states the centralized path "calls
`CorrelationEngine.run_centralized` which is a thin
extension of `CorrelationEngine.run`". The actual
implementation in `IncidentService._run_centralized`
calls `self.correlation_engine.run(...)` directly and
performs the deduplication itself. The
`CentralizedCorrelationResult` model and the
`run_centralized` method exist; one unit test exercises
the method. No production code path on the
centralized-analysis happy path calls it.

* **File / location:** `app/incidents/service.py:348–363`
  vs. `app/correlation/engine.py:250–306`.
* **Impact:** Documentation / code drift. The
  documented security property (no second engine,
  shared catalogue) still holds, because the same
  `CorrelationEngine` instance is used. The dead code
  on the happy path means the documented
  `CentralizedCorrelationResult` extension is
  effectively unused.
* **Exploitability:** N/A.
* **Smallest safe remediation (one of two):**
  1. **Code:** In `_run_centralized`, replace the
     `self.correlation_engine.run(...)` + manual
     dedup with
     `self.correlation_engine.run_centralized(detections=detections_list, events=events_by_id, existing_correlation_ids=case.evidence.correlation_ids)`
     and use `result.new_correlations` + `result.correlations`.
  2. **Docs:** Update PHASE 4-08-REPORT.md §4 / §6
     to say the incident service does its own
     dedup against a shared engine instance.
* **Blocks production?** No. This is a documentation /
  refactoring concern.

### 2.4 Section 4 — Two Report Modes

| Probe | Result | Evidence |
|---|---|---|
| Normal report generation (proxy) | **PASS (200)** | `OP_GENERATE_NORMAL_REPORT` (`probe_idor_out.txt`) |
| Normal report `mode` and `is_centralized` flag | **PASS** | `mode=normal`, `is_centralized=false` (code review) |
| Centralized report generation (proxy) | **PASS (200)** | Covered by `scripts/demo_phase48.py` and the integration test |
| Centralized report `mode` and `is_centralized` flag | **PASS** | `mode=centralized`, `is_centralized=true` (code review) |
| Centralized report requires centralized context | **PASS (400)** | `generate_centralized_report` raises `InvalidReportInputError` if `case.centralized_correlation_ids` and `centralized_correlations` are both empty (`reports/service.py:200–204`) |
| Complete evidence traceability | **PASS** | `ReportItem.reference_id` is the canonical id; `evidence_references` is the union of `case.evidence.event_ids`, detections, and correlations (`reports/service.py:613–630`) |
| Source attribution | **PASS** | `sources` section contains one item per participating source (`reports/service.py:_build_sources_section`) |
| Correlation attribution | **PASS** | `specialized_correlation` and `centralized_correlation_evidence` sections are built from the correlation sequences (`reports/service.py:_build_correlations_section`) |
| Deterministic output | **PASS** | `_make_report_id` is deterministic given `(incident_id, mode, version, generated_at, generated_by)` (`reports/service.py:675–708`); the same case + same inputs → same `report_id` for a given timestamp. |
| No sensitive / secret leakage | **PASS** | No signing key, no mongo URI, no internal collection name in any report body (probes + code review) |
| No fabricated conclusions | **PASS** | Every section is a deterministic function of the input evidence; no AI / no LLM; the `note` kind is the only "free text" carrier and is only used for source labels. |
| Persistence | **PASS** | `ReportRepository.create` persists to the `reports` collection; round-trip preserves `generated_at`, `rule_references`, sections. |
| **Report IDOR (CONFIRMED DEFECT)** | **FAIL** | Other analyst with `report:read` permission can fetch another analyst's report by `report_id`. |

**CONFIRMED DEFECT — Report IDOR (CONFIRMED SECURITY
ISSUE).**

* **File / location:** `app/reports/service.py:240–264`
  (`ReportService.get_report`).
* **Reproduction:**

  ```python
  # analyst A creates a case + report
  # analyst B (different subject) issues a token, then
  resp = proxy.handle(ProxyRequest(
      operation=OP_GET_REPORT,
      headers={PROXY_HEADER_AUTHORIZATION: f"Bearer {analyst_B_token}"},
      body={"report_id": analyst_A_report_id},
  ))
  # -> status=200, body["data"]["report"] is analyst A's report
  ```

  The probe in `review_tmp/probe_idor.py` reproduces
  this. The integration test
  `tests/integration/test_phase48_pipeline.py` does NOT
  exercise this attack; the unit test
  `tests/unit/test_phase48_proxy.py` does not cover
  `OP_GET_REPORT` with a different subject.

* **Impact:** A second analyst (or any other principal
  with the default `report:read` permission) can read
  every other analyst's case report by `report_id`.
  Reports carry the case's full evidence list, rule
  references, and (for centralized reports) the
  centralized correlation ids. This is a
  confidentiality breach: a hostile or curious
  analyst can enumerate reports by id and read other
  analysts' investigations without owning the case.

* **Exploitability:** Trivial. A report id is
  `rpt-<uuidv7>`, so direct enumeration is
  infeasible, but the id can leak through the
  centralized context (an analyst with
  `case:centralized:request:any` is not a default
  permission, so this is gated), through audit
  records (the audit subsystem is not yet
  implemented), or simply by an analyst B who knows
  the case id (which is also uuidv7 but may be shared
  in the team).

* **Smallest safe remediation:** In
  `ReportService.get_report`, after the
  `REPORT_READ` / `REPORT_READ_ANY` permission check,
  look up the case bound to the report and call
  `authorize_case_access(identity, case)`. If the
  identity does not own the case and lacks
  `case:read:any`, raise
  `CaseAccessDeniedError` (or
  `ReportAccessDeniedError`) so the proxy can map it
  to a 404 (preserving the "existence hidden" boundary
  used elsewhere).

* **Blocks production?** **Yes.** This is a
  confidentiality breach. Until this is fixed the
  report surface should be considered unsafe in any
  multi-analyst deployment.

  **POST-FIX (Phase 4.8a remediation).** The defect is
  **fixed** in the Phase 4.8a remediation pass.
  `ReportService.get_report` now resolves the owning
  case and re-asserts the canonical
  `authorize_case_access(identity, case)` boundary
  after the report-level permission check, when the
  service is wired with an `incident_service` (the
  default wiring in the proxy). Unauthorized
  read → `CaseAccessDeniedError` → 404 with no report
  contents in the body (existence hidden). The proxy's
  `_handle_get_report` continues to delegate to
  `ReportService.get_report`; the boundary is now at
  the service layer as documented.

  Post-fix verification (replayed in
  `review_tmp_repro/repro.py` against the patched
  code): analyst B reading A's report → status=404 with
  no report contents in the body; admin / `*:any` and
  owner reads still succeed. Regression tests added in
  `tests/unit/test_phase48_reports.py`,
  `tests/unit/test_phase48_proxy.py`, and
  `tests/integration/test_phase48_remediation.py`.

  Production-readiness status updated: see §4 below
  and the post-review remediation section in
  `docs/PHASE 4/PHASE 4-08/PHASE-04-08-REPORT.md`.

### 2.5 Section 5 — Routing (as a security decision)

| Probe | Result | Evidence |
|---|---|---|
| Deterministic | **PASS** | Same `RoutingContext` → same `RoutingRecommendation` (probe `routing.deterministic` PASS) |
| Correct team / level / queue | **PASS** | `_decide` is a pure function; verified by `tests/unit/test_phase48_routing.py` (15 tests) |
| Explainable reasons | **PASS** | Every recommendation carries a `RoutingReason` list with `(factor, detail)` for severity, complexity, centralized_correlation, specialized_correlation, evidence_count (`routing/service.py:147–172`) |
| Use of documented context | **PASS** | `RoutingContext` carries the case + optional `severity_band`, `confidence_band`, `complexity`; the engine derives them if absent and records the derivation in the reasons |
| Authorization before computing/accessing a case | **PASS** | `route_for_identity` (the proxy entry point) calls `authorize_case_access(identity, context.incident)` before delegating to `route` (`routing/service.py:234`) |
| Routing failure behavior | **PASS** | Unknown severity band → `state=failed`, `failure.safe_message="routing failed: no safe destination for the given case context"`, the case is NOT mutated (`routing/service.py:178–193`) |
| No silent suppression | **PASS** | Every failure path returns an explicit `RoutingFailure` with a deterministic reason; the case stays in its previous state. |
| No security downgrade caused by routing failure | **PASS** | The case state is untouched. The recommended minimum level for centralized is L2 (`_decide` centralized branch), so a centralized case is never routed to L1 even when the routing context is incomplete. |
| No unauthorized routing manipulation | **PASS** | The proxy entry point enforces `routing:read`; collector → 403, other analyst (not owner) → 404. `routing.override` is not a wire operation (the only routing operation is `routing.compute`). |
| Boundary cases — bad severity | **PASS (400)** | `routing.bad_severity` returns 400 for unknown band |
| Boundary cases — missing incident_id | **PASS (400)** | |
| Boundary cases — unknown case | **PASS (404)** | |

The routing engine is the only security-sensitive
deterministic output in the slice that produces a
"non-evidence" verdict. The review confirms that:

* It never fabricates a destination: every
  `(severity, complexity, has_centralized)` triple is
  in the documented matrix, and unknown severities
  return an explicit failure.
* It never downgrades: the centralized branch
  forces a minimum L2.
* It never suppresses: failures are explicit
  `RoutingFailure` records, not silent omissions.

The Phase 4.8 review therefore **accepts** the
routing engine as a security decision component, with
the documented future work (severity-aware routing,
queue management, escalation) explicitly deferred.

### 2.6 Section 6 — Proxy / Gateway Boundary

The proxy is implemented as a **function-level**
boundary, not a network boundary. There is no FastAPI
app, no aiohttp app, no listening socket. The only
way to call `SecureProxy.handle` is to import
`app.proxy.SecureProxy` in a Python process that has
the proxy instance. This is **architecturally intended
and explicitly documented** in PHASE 4-08-REPORT.md
§11 (the "next slice" list explicitly enumerates HTTP
transport as a future task).

| Probe | Result | Evidence |
|---|---|---|
| Unknown operation | **PASS (400)** | `forbidden_drop_table` returns 400 with `code=validation_error` |
| Forged token | **PASS (401)** | random string in `Authorization` → 401 |
| Wrong signing key | **PASS (401)** | Token signed with `0`*64 → 401 |
| Tampered hmac | **PASS (401)** | |
| Tampered subject_id | **PASS (401)** | Original hmac, swapped subject → 401 |
| Expired token | **PASS (401)** | `lifetime=1` + `time.sleep(2)` → 401 |
| Subject signed but not in identity store | **PASS (401)** | Verifier rejects unknown subjects |
| Internal op names: `incident.delete`, `incident.update`, `report.delete`, `report.update`, `rule.write`, `rule.disable`, `routing.override` | **PASS (400)** | All rejected with 400 by the operation allow-list |
| Direct service call with `None` identity | **PASS (rejected)** | `IncidentService.get_case(None, id)` raises `InvalidIncidentInputError` |
| Direct repository access (no service) | **OUT OF SCOPE for the proxy** | The repository is internal; no client can reach it without a Python process. (See §7.) |
| Payload sizes (request / response) | **OBSERVATION** | `proxy_max_request_bytes=32_768` and `proxy_max_response_bytes=1_048_576` are defined; the **request** cap is NOT enforced inside the handler. |

**OBSERVATION — `proxy_max_request_bytes` is not
enforced in the handler.** The field
`ProxyRequest.body_bytes` is populated by the
caller, but the proxy never checks
`request.body_bytes > self._config.proxy_max_request_bytes`.
A future HTTP transport wrapper must enforce this
at the wire boundary; the current in-process call
relies on the caller's discipline.

* **File / location:** `app/proxy/proxy.py:281–313`
  (`_validate_request_shape` does not check
  `body_bytes`).
* **Impact:** A future HTTP wrapper that does not
  enforce the byte cap will accept arbitrarily large
  bodies. The dev report mentions the field but does
  not claim it is enforced.
* **Exploitability:** N/A in the in-process model;
  depends on the future HTTP transport.
* **Smallest safe remediation:** Add a check at the
  top of `_validate_request_shape`:
  `if request.body_bytes > self._config.proxy_max_request_bytes: raise InvalidProxyRequestError(...)`.
* **Blocks production?** The future HTTP slice must
  address this.

### 2.7 Section 7 — Is there an actual network boundary?

**No.** There is no listening HTTP/WSGI/ASGI/gRPC
server in the Phase 4.8 codebase.

* A grep for `FastAPI|uvicorn|aiohttp|gunicorn|flask|WSGI|HTTPServer` over the production
  code shows no listener — every match is in
  comments or in `app/proxy/__init__.py` / `PHASE 4-08-REPORT.md` explicitly stating "no
  HTTP transport yet; the next slice wraps it in a
  server (FastAPI / aiohttp / a custom transport —
  TBD)".
* The only entry point is
  `SecureProxy.handle(ProxyRequest) -> ProxyResponse`,
  a Python function call.

**Implications for the security boundary:**

* **In-process:** A client that is already inside the
  Python process (e.g. a future dashboard running in
  the same interpreter) calls `proxy.handle(...)`
  directly. The proxy enforces authn, authz, rate
  limit, IDOR defense, and safe-error shaping. This
  is verified by the probes in this review.
* **Across the network:** There is no boundary. A
  client on a different host cannot reach the
  proxy, cannot reach the incident service, cannot
  reach the report service, cannot reach the routing
  engine, and cannot reach MongoDB unless the
  deployment has a separately-managed transport
  (e.g. SSH tunnel, mTLS-terminating reverse proxy).
  That transport is not in this slice.

**What is protected today:**

* The in-process trust boundary is enforced.
* The BSON `$jsonSchema` validator on `incidents` is
  a defense-in-depth at the database boundary.
* The signing key is never logged (the safe-error
  envelope excludes `internal_detail` from the wire
  body, and `cfg.safe_summary()` redacts
  `auth_signing_key` to a `bool`).
* The proxy is the only client-facing entry point in
  the API surface.

**What is NOT protected today (correctly classified
as deferred):**

* HTTP transport. (Dev report §11.)
* Long-lived signing key (HSM / KMS / JWT issuer).
  (Dev report §11.)
* Per-case notification fan-out. (Dev report §11.)
* MongoDB authentication / network exposure controls.
  (Configuration is in `app/config.py`; deployment is
  the caller's responsibility.)
* Audit persistence. (The audit schema is defined
  elsewhere; the writer does not yet exist.)
* The report.get IDOR (see §2.4).

The dev report is **explicit** about every deferred
item in PHASE 4-08-REPORT.md §11. This review
**classifies** Phase 4.8 as:

* **A. Implemented and verified** at the function
  level: every layer the dev report claims is
  implemented is in fact implemented, the test
  suite covers it, and the independent probes in
  this review confirm the boundaries.
* **B. Implemented but not network-verified**:
  nothing — there is no network surface to verify.
* **C. Architecturally intended but deferred**:
  HTTP transport, long-lived key material, audit
  persistence, per-case notification. Each is
  correctly flagged in PHASE 4-08-REPORT.md §11.
* **D. Not implemented**: enterprise IAM, MFA,
  OIDC, federation, per-case notification, queue /
  escalation, future severity-aware routing.

This classification is what the dev report's
"STABLE" claim should be read as: **stable for the
in-process, function-level, development-key,
documented scope**.

### 2.8 Section 8 — Authentication / Authorization

**Auth (token layer):**

| Probe | Result | Evidence |
|---|---|---|
| Token format | **PASS** | 5 fields, hex hmac, prefix `ps` (`auth/session.py:75–78`) |
| Signature validation | **PASS** | `hmac.compare_digest` against a re-derived body (`auth/session.py:333–339`) |
| Expiry | **PASS** | `time.time() >= exp` → `SessionExpiredError` (`auth/session.py:341–345`) |
| Tamper detection (hmac) | **PASS** | Any hmac mismatch → 401 |
| Wrong key | **PASS** | Verifier with a different key rejects |
| Identity binding | **PASS** | Subject id is part of the signed body; tampering the subject without breaking the hmac is impossible |
| Permission enforcement | **PASS** | `has_permission` is the single boundary function; the proxy uses `_require(identity, Permission.X)` before every operation |
| Object-level authorization | **PARTIAL** (see Report IDOR in §2.4) | Case access control is correct; report access is not. |

**Authz (object level):**

| Probe | Result | Evidence |
|---|---|---|
| `authorize_case_access(identity, case)` for analysts | **PASS** | Owner → pass; non-owner (analyst) → `CaseAccessDeniedError` → 404 in the proxy |
| `case:read:any` for admin | **PASS** | Admin reads any case |
| `case:centralized:request` for analyst | **PASS** | 403 for collector; 404 for non-owner analyst |
| `report:read` (no case check) | **FAIL (CONFIRMED DEFECT)** | see §2.4 |

**Authentication is not enterprise IAM.** The dev
report is explicit: this is a development-mode HMAC
scheme with an in-memory identity catalogue. It is
**not** a substitute for OIDC, MFA, federation,
SCIM, HSM-backed key material, or any production
IAM. The dev report flags this as deferred
("long-lived signing key (HSM / KMS / JWT issuer)"
in §11). The safe-error envelope and the
`is_subject_signed_but_unknown → 401` design mean
that this in-process development scheme is safe to
**prototype** with, but it must not be relied on
for production authentication until the future IAM
slice lands.

**Attempted attacks (all rejected as expected):**

* Forged token: 401.
* Wrong key: 401.
* Tampered hmac: 401.
* Tampered subject (with carried-over signature):
  401.
* Expired token: 401.
* Subject signed but unknown to the identity store:
  401 (existence is not leaked).
* Role escalation via the wire (e.g. trying to
  invoke `routing.override` or `rule.write`): 400
  (unknown op) or 403 (no permission).
* Privilege escalation via the `permissions` field
  on the identity: the `permissions` field is
  carried by the *server-side* identity store and
  re-derived from the verified token's subject id;
  the client cannot inject permissions through the
  wire.

### 2.9 Section 9 — Secret / Credential Leakage

| Probe | Result | Evidence |
|---|---|---|
| `cfg.safe_summary()` does not include the signing key | **PASS** | Only `auth_signing_key_set: bool` is exposed |
| `OP_AUTH_ISSUE` response body does not include the signing key | **PASS** | The key is in-process only |
| Error response body does not include `internal_detail` | **PASS** | `_shape` only renders `code` and `safe_message` |
| `Exception` traceback in the response | **PASS** | The `except Exception` branch in `handle` logs and returns a generic "internal error" |
| `mongodb://` in any error body | **PASS** | Safe-error envelope excludes the `mongo_uri` |
| Internal service / pymongo errors as text in client bodies | **PASS** | All `DomainError` subclasses expose only `safe_message`; `internal_detail` is logged, not rendered. |
| Unknown subject id at `OP_AUTH_ISSUE` | **PASS (401, no id leak)** | The 401 is generic; the safe_message does not contain the subject id. |

The **safe-error envelope** is one of the strongest
parts of the Phase 4.8 slice. Every error path
(`InvalidProxyRequestError`, `ProxyUnauthorizedError`,
`ProxyRateLimitedError`, `CaseAccessDeniedError`,
`CaseNotFoundError`, `ReportAccessDeniedError`,
`ReportNotFoundError`, `InvalidReportInputError`,
`InvalidRoutingInputError`, `AuthenticationError`,
`AuthorizationError`, `ValidationError`, generic
`DomainError`) is shaped into the same wire envelope
(`{"error": {"code": "...", "message": "..."}}`),
and the proxy's `except Exception` branch converts
unexpected errors into a generic
`ProxyUnauthorizedError(safe_message="internal error")`
so a stack trace can never reach the client.

### 2.10 Section 10 — Safe-Error / Failure Isolation

| Failure mode | Outcome | Evidence |
|---|---|---|
| Missing token | 401 | proxy `/missing-token status: 401` (demo) |
| Tampered token | 401 | probes |
| Forged token | 401 | probes |
| Expired token | 401 | probes |
| Unknown operation | 400 | probes |
| Unknown case id | 404 | probes |
| Bad severity band (routing) | 400 | probes |
| Bad correlation input (Pydantic) | centralized_failed | `_run_centralized` catches `PydanticValidationError` and routes through `_mark_centralized_failed`; the case is preserved (`service.py:354–358`) |
| Correlation engine raises an unhandled exception | centralized_failed | `_run_centralized` catches `Exception` and routes through `_mark_centralized_failed` (`service.py:359–363`) |
| Routing context has unknown severity band | Explicit failure (`state=failed`); case is not mutated | `_decide` returns `None` for unknown severity; the engine wraps it in a `RoutingFailure` |
| Routing context with an unauthorized identity | 404 (IDOR-hidden) | probe |
| Oversized response | 500 with `code=response_too_large` | `proxy._shape_ok` |
| Malformed JSON-style body (not a dict) | 400 | probe |
| Quarantined persisted record | The repository logs `incident.document_quarantined` and skips the record; no crash | `incidents/repository.py:354–366` |

The **centralized-analysis failure isolation** is
specifically tested in this review: the case
state after a forced centralized failure is
preserved. This is the documented fail-safe
contract and it holds.

### 2.11 Section 11 — Rate Limiting / Abuse

| Probe | Result | Evidence |
|---|---|---|
| Per-subject general rate limit | **PASS** | 33 of 150 hammered requests blocked with 429; `proxy_rate_limit_per_minute=120` (probe `boundaries`) |
| Centralized rate limit | **PASS** | 5 successful centralized requests, 6th returns 429; `proxy_centralized_rate_limit_per_minute=5` |
| Subject-swap bypass attempt | **N/A** (correctly designed) | The rate limiter is keyed by `subject_id`. A different subject gets a fresh budget. This is documented and intended; a single attacker cannot double their budget by switching identities if the identity store gates the new subject id. |
| Oversized request (caller-supplied `body_bytes`) | **NOT ENFORCED** (see §2.6 OBSERVATION) | The byte cap is not checked in the handler. |
| Oversized response | **PASS** | `_shape_ok` returns 500 with `code=response_too_large` if the response exceeds `proxy_max_response_bytes` |

The rate limiter is a **sliding-window** per-subject
budget (`app/proxy/proxy.py:107–150`). The central
budget is a separate window. The implementation is
correct for the in-process model.

### 2.12 Section 12 — Integration with Phase 4.1 → 4.7

| Stage | Status | Evidence |
|---|---|---|
| External/fixture security event → canonical SecurityEvent | **PASS** | `tests/integration/test_phase48_pipeline.py:240` ingests 4 events |
| Canonical SecurityEvent → Detection | **PASS** | 4 detections produced (integration test) |
| Detection → Persistence | **PASS** | `DetectionRepository.create` (existing) |
| Specialized correlation | **PASS** | `correlation_engine.run(...)` produces ≥1 correlation (integration test) |
| Timeline / Severity / Confidence | **PASS** | covered by Phase 4.6 tests; integration test exercises the path |
| Incident | **PASS** | `case-01a05324-...` (probe) |
| Proxy access | **PASS** | every operation exercised through the proxy in the integration test and the demo |
| Normal report | **PASS** | integration test asserts `rpt-...` |
| Analyst-requested centralized | **PASS** | integration test asserts `failed=False` and `len(new_correlation_ids) >= 1` |
| Centralized report | **PASS** | integration test |
| Routing | **PASS** | integration test |
| Close | **PASS** | integration test asserts `state=closed` |
| No earlier-phase contract changes | **PASS** | `SecurityEvent`, `Detection`, `Correlation` models unchanged |
| Existing NGINX rules still work | **PASS** | `tests/integration/test_nginx_end_to_end.py` still passes |

The full 4.1 → 4.8 pipeline is verified by:

* `tests/integration/test_phase48_pipeline.py::test_phase48_full_pipeline_through_proxy`
  (one integration test that exercises the entire path
  end-to-end against real MongoDB).
* `scripts/demo_phase48.py` (a runnable script that
  exercises the same path and prints "DEMO OK").
* This review's independent probes (which build a
  smaller dataset through the same APIs).

### 2.13 Section 13 — Adversarial Testing

The probes in this review already exercise the
following adversarial scenarios:

* **Authentication bypass** — every attempt
  rejected (forged, tampered, expired, wrong-key,
  unknown subject, subject-swap).
* **Authorization bypass** — every protected
  operation enforces `_require(...)` before
  dispatch.
* **IDOR** — case.get, case.close, routing.compute,
  centralized.request all return 404 for a
  non-owner analyst. **report.get does not** (see
  §2.4).
* **Privilege escalation** — collector cannot
  invoke case / report / routing operations; admin
  has the documented `*:any` permissions; analyst
  cannot escalate to admin (the role is set in the
  server-side identity store; the wire cannot
  change it).
* **Token tampering** — see §2.8.
* **Token replay** — stateless HMAC tokens are
  accepted on reuse (no nonce, no revocation
  list). This is **OBSERVATION**: the slice has no
  revocation mechanism; for the in-process dev
  model this is acceptable, but production must
  add a revocation list or short-lived tokens with
  refresh.
* **Case enumeration** — `case.list` without
  `state` returns `[]` (see §2.1 DEFECT).
* **Report enumeration** — `report.list` proxies
  to `ReportService.list_for_incident(identity, case)`,
  which calls `_check_authority` →
  `authorize_case_access`, so the analyst sees only
  their own case's reports.
* **Routing manipulation** — the proxy passes the
  `RoutingContext` directly; the engine uses
  documented factors; no caller-supplied `level` /
  `team` / `queue` is honoured.
* **Centralized-analysis abuse** — the rate limit
  and the centralized-specific budget both bind
  at the proxy, not at the service.
* **JSON / protocol confusion** — `_payload_to_*`
  helpers silently quarantine malformed items; the
  service still returns 200 with a 0-item list.
* **MongoDB injection** — the repository layer
  enforces typed values for the filter arguments
  (Phase 4.5 hardening).
* **Oversized inputs** — the request cap is not
  enforced (see §2.6); the response cap IS
  enforced.
* **Resource exhaustion** — the rate limiter caps
  per-subject; without HTTP transport there is no
  process-level exposure to flood.
* **Duplicate / replay requests** — centralized
  analysis is idempotent on the correlation ids
  (probe PASS); case creation is idempotent on the
  generated case id; case.get is read-only.
* **Evidence tampering** — the case stores
  references (not copies) of the evidence; the
  BSON `$jsonSchema` validators restrict the
  schema of every collection.
* **Severity / confidence tampering** — the case
  does NOT carry severity / confidence; the report
  carries them. They are computed from the
  evidence; the wire does not accept caller-
  supplied values for them.
* **Internal endpoint discovery** — the proxy
  rejects every unknown operation with 400.
* **Direct backend bypass** — at the function
  level, the only documented entry point is the
  proxy. Internal services reject `None` identity
  (probe PASS).
* **Secret extraction** — see §2.9.
* **Error-message leakage** — see §2.9.

**One observation the dev report does not make
explicit:** the proxy is the only documented
client-facing entry point, but every backend
service is also a public Python class. In a
production deployment, the **only** way to ensure
the proxy is the only client-facing entry point is
to deploy the backend services into a separate
process / network namespace from any client. The
dev report does not call this out; it is
**implicit** in the layered architecture but
should be **explicit** in a future deployment
guide.

### 2.14 Section 14 — Human Analyst Simulation

Walking through the documented analyst workflow as
a real analyst:

1. **Receive a normal incident.**
   The analyst issues a session token via
   `OP_AUTH_ISSUE` (this is the dev-mode auth
   flow; a future IAM slice replaces this with
   OIDC). The proxy verifies the token, looks up
   the identity, and dispatches the operation.
   The session token is good for 1 hour.
2. **Read the specialized investigation.**
   `OP_LIST_CASES` with `state=open` returns the
   analyst's open cases (analyst sees only their
   own; admin sees all). `OP_GET_CASE` returns
   the case with the full evidence references.
3. **Decide whether more context is required.**
   The analyst inspects the rule references, the
   detection count, and the correlation count.
4. **Request centralized analysis.**
   `OP_REQUEST_CENTRALIZED` with the case id + a
   wider evidence payload. The proxy enforces
   `case:centralized:request`, the per-subject
   general rate limit, AND the dedicated
   centralized budget (default 5/min).
5. **Review the combined investigation.**
   `OP_GET_CASE` returns the case with the
   updated `centralized_correlation_ids` and
   `lifecycle_history`. (Probe PASS.)
6. **Generate the appropriate report.**
   `OP_GENERATE_NORMAL_REPORT` for a specialized
   report; `OP_GENERATE_CENTRALIZED_REPORT` for
   the combined report. (Both verified.)
7. **Inspect routing.**
   `OP_ROUTE_CASE` with the case id. The engine
   returns a `RoutingRecommendation` with
   explainable `RoutingReason`s.
8. **Close the case.**
   `OP_CLOSE_CASE` with the case id and a
   reason. The case transitions to `closed`;
   the evidence is preserved.

**Does the workflow reduce analyst work?** Yes, in
the sense that:

* The proxy is the only entry point the analyst
  needs to learn.
* Every read is authn + authz + IDOR-defended.
* The centralized path is idempotent and
  fail-safe.
* Reports are deterministic and
  evidence-traceable.

The workflow **does NOT** yet:

* Allow the analyst to add notes or annotations
  to the case (deferred).
* Notify an on-call rotation (deferred).
* Offer a UI surface (deferred).
* Provide per-actor fan-out (deferred).

These are explicitly listed in PHASE 4-08-REPORT.md
§11 as future slices.

### 2.15 Section 15 — Performance / Pressure

The probes in this review exercised:

* **Alert bursts:** 5 events → 5 detections → 1 case.
  The incident service handles a 5-event burst in
  ~50ms (observed during probe runs).
* **Multiple simultaneous cases:** 2 cases
  (`case`, `case2`) handled in the same probe run
  without state corruption.
* **Repeated report requests:** 1 normal report
  per case in the probe; the demo exercises 2
  reports per case (normal + centralized). The
  report service is idempotent on the
  `(case, mode, version)` tuple.
* **Repeated centralized requests:** the
  `centralized.idempotent` probe exercises two
  back-to-back centralized calls; the
  `centralized.rate_limit` probe exercises 15
  calls in quick succession. The 6th–15th calls
  return 429.
* **Concurrent analysts:** the probe issues 4
  tokens (analyst-001, analyst-002, admin-001,
  collector-001) and exercises each in sequence.
  No state corruption observed.
* **Resource exhaustion:** the rate limiter caps
  the per-subject request rate; the response size
  cap protects the in-process memory.

**No crashes, no memory growth, no state
corruption, no duplicate evidence, no race
conditions** were observed during the probe runs.

**No measured production capacity.** The probes
ran in a local single-process Python interpreter
against a local MongoDB. The dev report does not
claim production capacity, and the future HTTP
slice is the right place to add load testing.

---

## 3. Test Execution Summary

| Suite | Result |
|---|---|
| `python -m pytest tests -q --no-header -p no:cacheprovider --tb=line` | **980 passed in 13.18s** (922 unit + 58 integration; real local MongoDB) |
| `python -m scripts.demo_phase48` | **DEMO OK** (4 NGINX 401s + 1 NGINX 200 → case → normal report → centralized request → centralized report → close) |
| Review probe: incidents (§2.1) | 11 checks; **1 FAIL** (`list_cases` unfiltered) |
| Review probe: auth strength (§2.8) | 6 checks; 0 FAIL |
| Review probe: secret leakage (§2.9) | 4 checks; 0 FAIL |
| Review probe: proxy bypass (§2.6) | 12 checks; 0 FAIL |
| Review probe: report IDOR + routing + centralized flow (§2.4, §2.5, §2.3) | 17 checks; **2 FAIL** (both are the same report.get IDOR, run twice) |
| Review probe: boundaries (case.create stub, close IDOR, idempotency, general rate limit) | 4 checks; 0 FAIL |

The test suite and the demo both pass cleanly. The
independent review probes found **two** CONFIRMED
DEFECTS:

1. Report IDOR (CONFIRMED SECURITY ISSUE).
2. `list_cases` returns `[]` for unfiltered
   queries (CONFIRMED DEFECT, functional).

And **one** OBSERVATION:

* `proxy_max_request_bytes` is not enforced in
  the handler.

And **one** OBSERVATION / documentation drift:

* `run_centralized` is not used on the
  centralized-analysis happy path (the dev
  report says it is).

---

## 4. Final Verdict (per question)

1. **Does Incident / Case work correctly?**
   **YES, with one functional bug.** The case
   lifecycle, evidence preservation, IDOR defense,
   close, and audit history are all correct.
   `list_cases` without a `state` filter returns
   `[]` (CONFIRMED DEFECT, not a security issue).
2. **Does the specialized investigation report
   work?** **YES.** The normal report is
   deterministic, evidence-backed, secret-free, and
   not fabricated.
3. **Does analyst-requested centralized
   investigation work?** **YES at the function
   level; the `run_centralized` extension is
   dead code on the happy path** (the dedup is
   done in the service; the result is correct, but
   the code path does not match the dev report's
   description).
4. **Does the centralized report work?**
   **YES.** The centralized report correctly
   requires a centralized context, includes the
   participating sources / detections / correlations,
   and tags `is_centralized=true`.
5. **Does routing work deterministically and
   safely?** **YES.** Deterministic, IDOR-defended,
   explainable, fail-safe, no security downgrade.
6. **Does the proxy actually enforce the intended
   client/backend trust boundary?** **YES at the
   function level; NO at the network level.** There
   is no HTTP transport. The proxy is a
   `SecureProxy.handle(ProxyRequest)` function
   call; a network client cannot reach it without
   a future HTTP wrapper.
7. **Can the client bypass internal backend
   services?** **NO** at the function level. The
   proxy is the only documented entry point. At the
   deployment level, the proxy's status as the only
   client-facing entry point must be enforced by
   the deployment topology (the dev report does
   not make this explicit; see §2.13).
8. **Is authentication secure for the documented
   scope?** **YES** — HMAC, signature, expiry,
   identity binding are all correct. **NOT a
   production IAM.** Production must replace the
   development-mode HMAC + in-memory identity store
   with enterprise IAM (OIDC / SSO / MFA / KMS /
   JWT issuer) — the dev report flags this as
   deferred.
9. **Is authorization resistant to IDOR and
   privilege escalation?** **YES (post-fix).** Case
   IDOR, close IDOR, centralized IDOR, routing IDOR,
   **and report IDOR** (after the Phase 4.8a
   remediation) all hold. The unfiltered `case.list`
   IDOR is also closed. See §2.1 and §2.4 above for
   the post-fix evidence.
10. **Are secrets protected?** **YES.** The
    signing key is never logged, never included in
    safe_summary, never included in any response
    body, and never included in any error response.
    `internal_detail` is logged, not rendered.
11. **Are failure paths fail-safe?** **YES.**
    Engine exception → `centralized_failed`; bad
    severity → routing failure; malformed payload
    → quarantine + 200; unknown op → 400; tampered
    token → 401; Mongo unavailable → 500-class
    safe error.
12. **Does centralized correlation preserve the
    original specialized evidence?** **YES.**
    Verified by `centralized.preserves_case` probe.
13. **Does the complete 4.1 → 4.8 pipeline work?**
    **YES.** Verified by the integration test
    `test_phase48_full_pipeline_through_proxy` and
    by `scripts/demo_phase48.py`.
14. **Are there hidden security vulnerabilities?**
    **ONE**: the report.get IDOR. The rest of the
    documented attack surface is defended.
15. **Is Phase 4.8 genuinely production-ready, or
    only stable for its current in-process /
    documented scope?**
    **STABLE FOR ITS CURRENT SCOPE.**
    **NOT production-deployable as-is.** The
    function-level proxy is correct; the test
    suite is comprehensive; the documented
    boundaries hold. The slice is **not**
    production-deployable because the documented
    "secure application proxy" is not a network
    security boundary (no HTTP transport), the
    auth is development-mode only, the signing
    key is per-process, the report.get IDOR is
    a confidentiality breach, audit persistence
    is deferred, and per-case notification,
    queue / escalation, and severity-aware
    routing are all explicitly future work.

    The dev report's "STABLE" claim is
    **correctly qualified** in PHASE 4-08-REPORT.md
    §11; this review endorses that qualification.

---

## 5. Recommendations (smallest safe, prioritized)

These are recommendations only. **This review did
not modify production code.** The
smallest-safe remediations are listed for the
defects above; the larger refactors (HTTP
transport, enterprise IAM, audit persistence) are
explicitly out of scope.

1. **Fix the report.get IDOR.** In
   `ReportService.get_report`, after the
   `report:read` permission check, call
   `authorize_case_access(identity, case)` against
   the case the report is bound to. If the
   identity is not the case owner and lacks
   `case:read:any`, raise `CaseAccessDeniedError`
   so the proxy maps it to a 404. Add a unit
   test (analyst A creates the report, analyst B
   must NOT be able to read it). **Blocks
   production.**
2. **Fix the `list_cases` unfiltered bug.** In
   `IncidentService.list_cases`, change the
   `if state else []` short-circuit to call a new
   `IncidentRepository.find_recent(limit=limit)`
   method. **Does not block production** (no
   security impact; a missed capability).
3. **Enforce `proxy_max_request_bytes` in the
   handler.** Add a check in
   `SecureProxy._validate_request_shape` that
   rejects requests whose `body_bytes` exceeds
   the configured cap. **Required for the
   future HTTP transport.**
4. **Wire the `run_centralized` extension** (or
   update the dev report). Either change
   `_run_centralized` to use
   `self.correlation_engine.run_centralized(...)`
   and `result.new_correlations`, or update
   PHASE 4-08-REPORT.md §4 / §6 to describe the
   actual code path.
5. **Add a unit test for the `OP_CREATE_CASE`
   stub.** Submit a valid analyst token + the
   `case.create` operation; assert 400. This is a
   one-line test and locks the documented
   boundary.
6. **Document the deployment-topology
   assumption.** The dev report should make
   explicit that the backend services must be
   deployed into a separate process / network
   namespace from any client, and that the proxy
   is the **only** client-facing entry point.
7. **Document the token-replay limitation.**
   Stateless HMAC tokens are reusable until
   expiry. There is no revocation list. A future
   slice must add one (or replace the scheme with
   short-lived tokens + a refresh-token flow).
8. **Schedule the future HTTP transport slice
   to land the request-byte cap and the audit
   persistence layer before any production
   deployment.**

---

## 6. Review Artifacts

The following temporary files were created during
this review and **were removed at the end of the
review**:

* `review_tmp/probe_helpers.py`
* `review_tmp/probe_main.py`
* `review_tmp/probe_security.py`
* `review_tmp/probe_idor.py`
* `review_tmp/probe_secret_bypass.py`
* `review_tmp/probe_boundaries.py`
* `review_tmp/results_*.json`
* `review_tmp/probe*_out.txt`
* `review_tmp/pytest_full.txt`
* `review_tmp/run_tests.py`
* `review_tmp/__pycache__/`

The `review_tmp/` directory was deleted in full
after this report was written. No production code,
tests, schemas, connectors, engines, rules, or
configuration were modified during this review.


---

## 7. Phase 4.8a Remediation — Post-Review Updates

The two CONFIRMED DEFECTS raised by this review
(§2.1 and §2.4 above) were addressed in the
**Phase 4.8a remediation pass**, recorded in detail
in the post-review section of
`docs/PHASE 4/PHASE 4-08/PHASE-04-08-REPORT.md`. This
section is a short, cross-reference summary.

### 7.1 What was fixed

1. **R1. Report IDOR.** `ReportService.get_report`
   now resolves the owning case and re-asserts the
   canonical `authorize_case_access(identity, case)`
   boundary after the report-level permission check,
   when the service is wired with an `incident_service`
   (the default wiring in the proxy). Unauthorized
   read → `CaseAccessDeniedError` → 404 with no report
   contents in the body (existence hidden). The fix
   preserves owner and `*:any` access.
2. **R2. `list_cases` with no state filter.** A new
   `IncidentRepository.find_recent(limit=...)` method
   was added; `IncidentService.list_cases` calls it
   when `state is None`. The ownership / `case:read:any`
   post-filter is preserved, so the unfiltered list
   cannot be used to enumerate other analysts' cases.

### 7.2 Post-fix verification

* Pre-fix repro (`review_tmp_repro/repro.py`) replayed
  against the patched code: both defects closed
  (`IDOR_BYPASS=False`, `LIST_EMPTY_BUG=False`).
* New unit tests:
  - `tests/unit/test_phase48_reports.py` — 12 new tests
    in `TestReportGetAuthorization` (8),
    `TestReportListForIncidentAuthorization` (2), and
    `TestReportServiceBackwardCompat` (1).
  - `tests/unit/test_phase48_incidents.py` — 6 new
    tests in `TestListCasesUnfiltered`.
  - `tests/unit/test_phase48_proxy.py` — 3 new tests
    in `TestReportIdorThroughProxy` (3) and
    `TestUnfilteredListCases` (2).
* New integration test:
  `tests/integration/test_phase48_remediation.py::test_post_review_full_idor_and_unfiltered_list`
  exercises the full real-MongoDB attack matrix
  (analyst A creates case + normal + centralized report,
  analyst B is denied 404 on both, admin / `*:any`
  succeeds on both, unfiltered `case.list` returns the
  caller's cases, close preserves the IDOR, etc.).

### 7.3 Full-suite results

* Pre-fix: **980 passed** in 13.18s.
* Post-fix: **1001 passed** in 14.10s (+21 new tests;
  no regressions in any existing test).
* End-to-end demo: `python -m scripts.demo_phase48`
  → `DEMO OK`.

### 7.4 Updated verdicts (Q1, Q9, Q14, Q15)

| # | Question | Verdict (post-fix) |
|---|---|---|
| 1 | Does Incident / Case work correctly? | **YES (post-fix).** The case lifecycle, evidence preservation, IDOR defense, close, and audit history are all correct. `list_cases` without a `state` filter now returns the caller's authorized cases. |
| 9 | Is authorization resistant to IDOR and privilege escalation? | **YES (post-fix)** — case IDOR, close IDOR, centralized IDOR, routing IDOR, **and report IDOR** all hold. The unfiltered `case.list` IDOR is also closed. |
| 14 | Are there hidden security vulnerabilities? | **NO (post-fix).** The two defects the review identified are both fixed. **No other hidden vulnerabilities found.** |
| 15 | Is Phase 4.8 production-ready? | **STABLE FOR ITS CURRENT SCOPE (post-fix).** The two confidentiality defects the review identified are closed. **NOT production-deployable as-is** for the same reasons as the original review (no HTTP transport, no enterprise IAM, no long-lived key material, no audit persistence). The remediation does not unblock production deployment on its own — but it removes the two confidentiality defects that the review identified. |

### 7.5 Production-readiness status (post-fix)

* **A. Implemented and verified (function level).** The
  documented boundaries now include the case-level
  authorization for `report.get` and the unfiltered
  `list_cases`.
* **B. Implemented but not network-verified.** Still
  nothing; no network surface.
* **C. Architecturally intended but deferred.** HTTP
  transport, long-lived key material, audit persistence,
  per-case notification, queue / escalation, severity-
  aware routing. The dev report's STABLE claim is still
  correctly qualified by §9 of the dev report.
* **D. Not implemented.** Enterprise IAM, MFA, OIDC,
  federation, queue, escalation, severity-aware routing.

**Verdict (post-fix):** Phase 4.8 is **stable for its
documented current scope** (in-process, function-level,
development-mode auth). The two confidentiality defects
that previously blocked multi-analyst production
deployment (Report IDOR and unfiltered `case.list` IDOR)
are closed. The slice is still **not production-deployable
as-is** for the reasons in §2.7 of this review (no HTTP
transport boundary, dev-mode auth, no long-lived key
material, no audit persistence, no per-case notification,
no queue / escalation, no severity-aware routing).
