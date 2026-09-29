# PROSHIELD — FINAL FULL-SYSTEM BASELINE AUDIT (independent round, 2026-09-18)

**Auditor role:** independent Principal Security Architect / SOC / Detection /
Correlation / AppSec / Adversarial / QA / Production-readiness / SOC-analyst
round. This report does not rely on any prior AI report's conclusions; every
material claim below was re-verified against the CURRENT working tree, CURRENT
tests, CURRENT MongoDB, CURRENT backend/ingress composition and the CURRENT
React build in this session.

**Repository tested:** `c:\Users\k.vishal reddy\Downloads\proshield rule based mvp`,
branch `main`, git HEAD `f674f09` (checkpoint before Gemini frontend
integration) PLUS the uncommitted working tree that IS the product (capability
patch, Phase 5.1, Phase 5.2, all `app/capabilities`, `app/sources/*`,
`app/pipeline/*`, `app/notifications`, `app/observability/health.py`,
`app/persistence/human_ids.py`, `app/persistence/telemetry.py`,
`app/reports/exporter.py`, `app/severity/enrichment.py`,
`frontend/src_upgraded_gemini` → `frontend/soc/index.html`, all
`scripts/verify_*` / `scripts/audit_*` / `scripts/browser_verify_*`, all
`tests/unit/test_phase5*` + `test_capability_patch` +
`test_detection_fidelity_managed_rules`).

**Authoritative architecture baseline:** `docs/PHASE 5(V3)/PHASE 5.0/
PHASE-05-00-V3-ARCHITECTURE-FREEZE.md` (freeze, 37 invariants), `docs/PHASE
5(V3)/PHASE-05-V3-IMPLEMENTATION-MASTER-PLAN.md`, `docs/PHASE 5(V3)/PHASE
5.2/PHASE-05-02-FINAL-BASELINE.md` (owner baseline — treated as a claim, not
truth), `docs/PHASE 5(V3)/PHASE 5.2/PHASE 5.2 IMPLEMENTATION REPORT.md`,
`docs/PHASE 5(V3)/PHASE 5.2/PHASE-05-02-OWNER-RECONCILIATION-AND-PATCH-REPORT.md`.

**Runtime tested:** Windows, Python 3.13.3, pymongo 4.16.0, MongoDB 8.0.13 on
127.0.0.1:27017, analyst plane `scripts/proxy_server.py` (SecureProxy),
ingress plane `scripts/ingress_server.py` (InboundIngressProxy), React 19.2.6 /
Vite 7.3.2 / TS 5.9.3 build `frontend/soc/index.html` (1,200,989 bytes, sha256
`7e2cb4ed…`, react root present, legacy `PSAPI` marker absent), real Chromium
via Playwright (`scripts/browser_verify_phase52.py`).

> Note on frontend bytes/hash: the on-disk build differs from the hash recorded
> in the owner baseline (`31fcaeee…`, 1,200,496 B @ 2026-09-17). The tree (incl.
> `frontend/soc/index.html`) is uncommitted working-tree state; the build was
> regenerated at some point after the owner's capture. Identity was re-proven
> in THIS session (react root present, legacy markers absent, 39/39 Chromium
> checks against the served artifact), so this is a build-freshness delta, not
> a substitution finding.

---

## 1. Executive summary

The composed system — Source → Ingress → Canonical Event → Capability-owned
Detection → Capability Correlation → Case → Analyst workflow → explicit Central
Correlation — **works end-to-end on live MongoDB through the real two-plane
composition**, preserves Source ≠ Capability, preserves server-derived
provenance, correlates ACROSS multiple source instances inside one capability,
keeps original evidence immutable under central analysis, enforces
authorization across primary AND alternate routes, survives restart, and tells
the truth in the React UI.

No blocker, high, or architectural defect was found in the implemented scope.
One **MEDIUM, non-blocking lifecycle-governance observation** is recorded
(FINAL-OBS-01: a DISABLED capability refuses NEW source bindings but does not
stop ingest on already-bound ENABLED sources — binding-time enforcement only;
no architecture-freeze text requires ingest-time capability-state gating, so
this is classified as observation/limitation, NOT a defect, and NO patch was
made). Role-separated (analyst-operated) triage of pipeline-created cases
remains Phase-5.4-owned (R-2, acknowledged in the baseline, re-verified here:
analyst 404 / admin 200 on all nine routes) — the single envelope constraint
on the release verdict.

- **Architectural verdict: ARCHITECTURE CONFORMS WITH NON-BLOCKING
  IMPLEMENTATION ISSUES** (the one issue is the documented R-2 analyst
  envelope + FINAL-OBS-01 limitation; no invariant is broken).
- **Implementation/release verdict: READY WITH NON-BLOCKING ISSUES**
  (single-operator, admin-operated, localhost, local-MongoDB baseline; NOT
  ready for role-separated analyst operation until Phase 5.4).

## 2. What was exercised (methodology, condensed)

- Full unit suite (1492 passed), full integration suite (114 passed), shipped
  gates `verify_phase52_pipeline` (51/51), `verify_phase52_live` (14/14),
  `audit_fresh_db` (42/42 per last full read; re-run tail truncated by runner
  cap but earlier full read in this session showed 42/42), Chromium
  `browser_verify_phase52` (39/39, real Chromium against the real build).
- Three NEW independent probes written in this session (kept in repo):
  - `scripts/_final_probe_f1.py` — **26/26**: 3 NGINX sources → distinct ids;
    5 NGINX rules owned `cap-nginx`, no `conn-*` fabrication; benign → 0
    detections; unknown `tls_anomaly` → accepted, retained, queryable, 0
    detections; 6-event attack across 3 sources → capability correlation with
    ≥2 source instances + `capability_ids==[cap-nginx]`; detections carry
    `cap-nginx`+source; replay/tamper 401; forged `capability_id` ignored AND
    not persisted; disabled/retired 409; analyst `case.list` shape ok;
    collector `source.list`/`event.list` 403; explicit `case.centralized`
    succeeds, evidence preserved, original events untouched; malformed →
    `validation_error`.
  - `scripts/_final_probe_f2.py` — **29/29**: WAF planned binding refused; WAF
    legacy row quarantined `requires_verification` and cannot validate; NGINX
    claiming simulator refused; token source-swap 401/403; disabled blocks
    ingest 409; correlation + case + timeline; analyst pipeline-case 404
    (R-2) while `event/detection/correlation.list` allowed; admin note/ack;
    report generate + markdown export; deep health healthy; `created_by` mass
    assignment ignored; migration dry-run safe; oversized rejected; identical
    redelivery idempotent vs same-id-different-content `conflict_event`;
    10-thread concurrent registrations unique; restart preserves counts +
    post-restart reads work.
  - `scripts/_final_probe_f3.py` — **25/25**: capability registry (6 = 2 live
    + 4 planned, no subconnectors, get/list_sources/list_rules/audit);
    analyst read allowed / write denied; disable `cap-nginx` refuses NEW
    bindings (400/409) and re-enable restores them; rule disable → specific
    rule silent, re-enable → fires; rotation yields new value AND old unused
    token stays valid (rotation≠revocation, as documented); unknown
    capability rejected; oversized/nested handled.
- Prior-round fixes (AUD-CL-01…05 per memory `audit-2026-09-18`) were
  independently re-verified rather than trusted: benign→0 detections (F1),
  observed endpoint/asset preserved (correlation keys on `/login`, not webhook
  URL), `validation_error` truthfulness (F1/F2 malformed classes), rule
  `capability_id` ownership incl. backfill (F1/F3), all green.

## 3. Architecture conformance matrix (freeze invariants, observed)

| Invariant | Observed |
|---|---|
| 1. One capability → many sources | 3 NGINX sources bound `cap-nginx`, distinct ids/credentials (F1) |
| 2. No subconnectors | none in models/registry/UI (F3) |
| 3–5. Source instance / token identity / analyst separation | `sit-` HMAC per-source tokens; analyst session `ps.` never accepted at ingress (replay/tamper/swap all 401/403, F1/F2) |
| 6–7. Source resolves to capability; capability is responsibility layer | deterministic `SourceType→cap-*` map + live-registry validation; rules/patterns owned by capability (F1/F3) |
| 8–9. No executable config; UI never the implementation | bounded `field_map` w/ exec-expression rejection; wizard calls real ops (Chromium 39/39) |
| 10. New capability immediately selectable | re-enable restores binding (F3) |
| 11–14. Event≠Detection≠Correlation≠Case≠threat | separate collections/models/ops; unmatched events visible w/o invented severity (F1) |
| 15–17. Derived results + traceable evidence | detection→rule/version, correlation→detection/event ids, case→evidence union (F1/F2) |
| 18–23. Human authority | R-2 boundary: analyst owns own cases; pipeline cases admin-only until 5.4 (documented) |
| 24–30. Lifecycle/temp-vs-durable | no auto-training; central analysis non-destructive (F1); retirement preserves history (pipeline 51/51 §7) |
| 31–37. AI boundaries | 5.3 HOLD: honest disabled previews, no backend calls (baseline §13, unmodified) |
| Trust boundaries (§8) | ingress HMAC+lifecycle+replay+size/rate; proxy closed permission catalogue; collector read-denied (F1/F2) |

The 35-question invariant checklist (§55 of the tasking) is answered: YES on
1–2, NO (correctly) on 3–4, YES on 5–11, YES on 12–13 (proven ≥2 sources in one
correlation), YES on 14–17, YES on 18 (distinct objects), PARTIAL on 19
(admin yes / analyst-on-pipeline-cases no → 5.4), YES on 20–21, DOCUMENTED on
22 (rotation≠revocation), YES on 23 + PARTIAL on 24 (source lifecycle fully
gated; capability-disable gates binding, FINAL-OBS-01 for ingest), YES on
25–31, DOCUMENTED-GAP on 32 (unknown = retained telemetry + `unmatched`
analyst surface, no separate object — adequate for the implemented scope),
YES on 33–35.

## 4. Confirmed findings

### FINAL-OBS-01 — DISABLED capability does not stop ingest on already-bound sources (MEDIUM, observation/limitation, NOT patched)

- **Observed:** `capability.disable(cap-nginx)` → 200; NEW `source.register`
  nginx → 400/409 (correct); but an already-ENABLED source bound before the
  disable ingests 200 and its event is persisted with `capability_id:
  cap-nginx` (F3 INFO line, deterministic re-verified).
- **Root cause:** binding validation (`validate_capability_binding`,
  `BINDABLE_CAPABILITY_STATUSES={active}`) runs at REGISTRATION time;
  `InboundIngressProxy._handle_ingest` gates on SOURCE state (ENABLED),
  token integrity, and `requires_verification` quarantine — it never consults
  live capability STATUS (`app/sources/ingress.py::_handle_ingest`,
  `app/sources/service.py::_resolve_binding`).
- **Why not a defect:** no freeze/master-plan/baseline text requires
  ingest-time capability-state gating; every documented lifecycle gate is
  source-scoped (baseline §2: "enforces ENABLED state (409 disabled / 410
  retired), capability-binding quarantine (409)"). Detection fidelity is
  unaffected (capability-id resolution still authoritative; rules still match
  the stamped owner). The conservative reading is that capability disable =
  stop-new-bindings administrative control, with source disable/retire as the
  ingestion kill-switch (which IS enforced: 409/410).
- **Impact if a deployment assumes otherwise:** telemetry keeps flowing under
  a disabled capability until each source is disabled — operational surprise,
  not a trust bypass (provenance stays truthful; no impersonation enabled).
- **Recommendation (Phase 5.4/5.5, non-blocking):** either (a) gate ingest on
  live capability status (409 `capability_disabled`), or (b) document that
  capability-disable is binding-administrative only and add a
  disable-capability-cascades/deactivates-sources operator. A regression test
  exists already (`scripts/_final_probe_f3.py` INFO + PASS lines).

### Dismissed / false-positive candidates (tested, NOT findings)

- Correlation key lacking `capability_id` (AUD-CL-06 in memory): the shipped
  single-pattern key is `(source_ip, redacted_endpoint)` but every
  `Correlation` carries derived `capability_ids` and case lineage is checked
  per-member (F1/F2); with one live NGINX family no cross-capability
  collision is reachable. Kept as future-hygiene note, not a finding.
- Analyst pipeline-case 404: by-design ownership (R-2/Phase 5.4), fail-closed
  on all nine routes + reuse route; NOT an IDOR.
- Rotation leaving old unused tokens valid: DOCUMENTED contract
  (`5.2-07`, baseline §3); verified rotation≠revocation (F3). Not a finding.
- `case.list` for analyst returning 200 with 0 rows: correct ownership
  windowing, not a leak.
- F1 probe's first-run 21/26: probe bugs (non-UUID event ids, wire-shape
  `source_token` vs `token`, `event.list` omitting `provenance`), NOT product
  bugs — corrected in-probe, final 26/26.
- F2 probe's interim note/health shape mismatches: probe used `note` instead
  of documented `body`, and `data.status` instead of `data.health.status` —
  corrected in-probe, final 29/29.

## 5. Security data / evidence integrity (live trace, F1 DB)

`src-…-final-nginx-{a,b,c}` (3 distinct instances, `cap-nginx` v1,
`nginx-access-default`) → per-source `sit-` tokens → ingress 200 →
`security_events` (provenance `source_instance_id` + `capability_id:
cap-nginx`, observed `/login` preserved) → `NGINX-AUTH-FAILURE-001` et al
(predicate-evaluated, benign/unknown silent) → `detections` (`rule_id/version`
+ `capability_id: cap-nginx` + `source_instance_id`) → brute-force pattern
(key `(source_ip, /login)`, ≥2 source instances) → `correlations`
(`capability_ids: [cap-nginx]`, real detection/event ids) → auto-case
(deterministic id, evidence union) → `timeline.build_for_incident` →
admin note/ack → `report.generate_normal` + markdown export →
`case.centralized` (explicit, authorized, evidence-preserving) → original
`security_events` byte-identical. Full identifier chains are in the dropped
throwaway DBs by design; the gates above assert each link.

## 6. Patches applied in this round

**NONE to product code.** All confirmed prior defects were already fixed in
the tree and re-verified; the single new observation (FINAL-OBS-01) is
documented-limitation class and deliberately left unpatched per the patching
rule (no speculative/architecture-changing patch without an authoritative
requirement). Probe scripts only: `_final_probe_f1.py` (event-id UUID +
wire-shape corrections), `_final_probe_f2.py` (`body` + `health` shape +
frozen-config `replace()`), `_final_probe_f3.py` (none needed post-write).
Full regression re-run AFTER all probe edits: unit 1492, integration 114,
pipeline 51/51, live 14/14, browser 39/39, F1 26/26, F2 29/29, F3 25/25.

## 7. Remaining known issues / deferred (all non-blocking for this envelope)

- R-2 (analyst vs pipeline cases → Phase 5.4); R-3 notification metadata;
  R-4 structured `case_resolutions`; R-5 catalogue nits; R-6 approved
  deferrals (token-id hashing, no revocation list, inert mapping transform,
  closed `source_type` enum); R-7 legacy-hygiene; R-8 dirty-tree process note;
  `5.2-PRE-01` family (pre-existing detection-fidelity, already addressed by
  AUD-CL-01 for the shipped library); AUD-CL-04 (SystemExit boot-guard
  cosmetics) and AUD-CL-06 (correlation-key hygiene) open as before.
- Phase 5.3 (learning/lab/Guide) HOLD respected; 5.4–5.9 untouched.

## 8. Final verdicts

- **A. ARCHITECTURAL VERDICT: ARCHITECTURE CONFORMS WITH NON-BLOCKING
  IMPLEMENTATION ISSUES.**
- **B. IMPLEMENTATION / RELEASE VERDICT: READY WITH NON-BLOCKING ISSUES**
  (single-operator admin-operated localhost baseline on local MongoDB; analyst
  role-separated operation explicitly excluded pending Phase 5.4).

Finite testing cannot warrant "bug-free"; what the evidence DOES support:
all tested architectural invariants passed; no known architectural
contradiction remains; capability/source ownership correct; capability
correlation spans sources; central correlation explicit + non-destructive;
provenance preserved; authorization enforced incl. alternate routes;
persistence/restart sound; frontend truthful; detection fidelity acceptable
(benign/unknown silent, no broad false positives); all critical live
workflows passed.
