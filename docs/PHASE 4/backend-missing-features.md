# ProShield — Backend Missing Features (Gemini Frontend Integration Phase)

**Phase 4 — Gemini frontend ↔ existing backend integration**
**Status: DISCOVERY ONLY — IMPLEMENTATION DEFERRED (see rule below)**

> **IMPLEMENTATION DEFERRED: YES** — for every entry in this document.
> This phase wires the Gemini frontend to the CURRENT backend and documents
> every backend capability the approved UX requires but the backend does not
> provide. No backend behaviour was changed in this phase.

**Method.** Every Gemini page, modal and action was traced
frontend → state → API client (`frontend/src_upgraded_gemini/src/services/api.ts`,
a TypeScript port of the existing `frontend/js/services/api.js`) → HTTP
`POST /api/proxy` → `SecureProxy.handle(ProxyRequest)` → service → repository →
response → rendering, against the frozen wire contract
(`docs/PHASE 4/PROSHIELD-FINAL-FRONTEND-BACKEND-CONTRACT.md`). A feature is
only classified as a gap when the wire operation genuinely does not exist or
does not return the field.

**Classification legend**

- `SPEC REQUIRED` — required for the approved UX to be truthful; blocks or materially limits the product spec.
- `DESIGN REQUIRED` — the approved Gemini design assumes it.
- `JUSTIFIED ENHANCEMENT` — usable today, materially better with it.
- `VISUAL ONLY` — presentation concern; no backend change needed.
- `BACKEND GAP` — confirmed missing backend capability.
- `NOT CURRENTLY REQUIRED` — demo/preview affordance; do not implement.

**Severity legend**: P0 blocks core operation · P1 materially limits an important workflow · P2 degraded but usable · P3 enhancement.

---

## 1. Case lifecycle transitions other than close

- **Feature:** Acknowledge / Investigate case state transitions.
- **Frontend expectation:** Incidents queue has an `Ack` quick-action and the
  case lifecycle rail shows OPEN → ACKNOWLEDGED → INVESTIGATING → CLOSED
  (`IncidentsPage.tsx` `handleQuickAcknowledge`, `CaseDetailPage.tsx`
  `lifecycleStates`).
- **Frontend location:** `frontend/src_upgraded_gemini/src/components/pages/IncidentsPage.tsx`, `CaseDetailPage.tsx`.
- **API operation currently used:** none possible — the wire declares only
  `case.close` (+ `case.create` boundary).
- **Current API behavior:** no operation exists for acknowledge/investigate.
- **Current backend behavior:** `IncidentService` supports open→close only.
- **Gap:** no `case.acknowledge` / `case.investigate` wire operation.
- **Why the UI requires it:** the approved design treats acknowledgement as the
  first analyst action of triage; today the button must refuse.
- **Owner:** incident domain service + `IncidentLifecycleState` + proxy handler.
- **Impact:** UI now shows a truthful "not supported by backend" warning and
  leaves state unchanged (no false success). Analysts cannot record triage.
- **Severity:** P1.
- **Evidence:** wiring test — Ack click produces local warning toast; backend
  `case.list` still returns `state: "open"`.
- **Recommended direction:** add lifecycle transitions with actor/role +
  reason to the incident service and expose `case.acknowledge` /
  `case.investigate` on the proxy, mirroring `case.close`.
- **Implementation deferred: YES.**

## 2. Case human-readable identifiers

- **Feature:** `CASE-01`, `DET-01`, `CORR-01`, `SRC-01`, `RULE-01` primary ids.
- **Frontend expectation:** all primary views lead with human ids; technical
  UUIDs stay secondary/copyable (`HumanIdTag`).
- **Frontend location:** `src/services/adapters.ts` (`assignHumanIds` — derived
  client-side from stable `created_at`/`detected_at`/`correlated_at` ordering).
- **API operation currently used:** `case.list`, `detection.list`,
  `correlation.list`, `source.list`, `rule.list`.
- **Current backend behavior:** returns only `case-<uuid7>`, `det-<uuid7>`,
  `corr-<uuid7>`, `src-<uuid7>-<suffix>`, `<RULE_ID>` ids.
- **Gap:** no stable, persisted human-id field in any wire response.
- **Why the UI requires it:** analyst-facing identity per the approved design
  (spec: "human-readable IDs should be primary").
- **Owner:** persistence/domain layer for each entity (creation-time assignment
  would be authoritative); today the derivation is a client-side convention.
- **Impact:** ids are deterministic only while the underlying set/order is
  stable; a new case inserted earlier shifts numbering. Truthfulness is
  preserved (technical id remains attached and copyable), but cross-session
  references to `CASE-xx` are fragile.
- **Severity:** P2.
- **Evidence:** adapter code + the frozen contract's ID formats section
  (no human-id format defined).
- **Recommended direction:** assign human ids at entity creation
  (per-collection counter) and return them in every wire view.
- **Implementation deferred: YES.**

## 3. Case attacker / target / source attribution

- **Frontend expectation:** Incidents and Case Detail show attacker IP,
  attacker country, target asset, owning source.
- **Frontend location:** `IncidentsPage.tsx` (Source / Attacker / Target
  columns), `OverviewPage.tsx` hero banner, `CaseDetailPage.tsx`.
- **API operation currently used:** `case.list` / `case.get`
  (`Incident.to_dict()`).
- **Current backend behavior:** `Incident` carries title/summary/state/evidence
  ids/severity/confidence/lifecycle/reports — no attacker, target, or source
  attribution.
- **Gap:** wire contract exposes no attribution fields.
- **Why the UI requires it:** triage columns of the approved design.
- **Owner:** incident assembly (Phase 4.8 case creation) + response serializer.
- **Impact:** UI derives attacker/target ONLY from the first correlation's
  `key.parts` (real backend data) and renders "—"/"not attributed" otherwise;
  source attribution renders "—" always.
- **Severity:** P1 (core triage data).
- **Evidence:** `Incident.to_dict()` field list; adapters deriving
  `attackerIp` from `correlation.key[0]`.
- **Recommended direction:** persist attacker/target/source attribution in the
  incident evidence at case assembly and expose it in `to_dict()`.
- **Implementation deferred: YES.**

## 4. Case analyst notes

- **Frontend expectation:** Case Detail notes tab; analyst can add notes.
- **Frontend location:** `CaseDetailPage.tsx` notes tab, `SocContext.addCaseNote`.
- **API operation currently used:** none.
- **Current backend behavior:** no notes concept on the wire.
- **Gap:** no `case.note.add` / notes list in `case.get`.
- **Why the UI requires it:** investigation continuity.
- **Owner:** incidents service + new notes persistence + proxy handler.
- **Impact:** UI keeps the note locally, visibly tagged "(not persisted)" with
  a warning toast — no fabricated persistence.
- **Severity:** P2.
- **Evidence:** adding a note produces the truthful non-persistence warning.
- **Recommended direction:** notes as append-only evidence records with
  author/role, returned in `case.get`.
- **Implementation deferred: YES.**

## 5. Detection severity and source attribution

- **Frontend expectation:** Detections page shows severity badge, source
  column, severity filter.
- **Frontend location:** `DetectionsPage.tsx`, adapters (`Detection.severity = null`).
- **API operation currently used:** `detection.list` / `detection.get`
  (`Detection.to_dict()`).
- **Current backend behavior:** `Detection` carries `rule_id/version/category/
  event_id/evidence_refs/reasoning/detected_at/extra` — no severity, no source.
- **Gap:** severity and source not on the detection wire view.
- **Why the UI requires it:** severity-ranked detection triage.
- **Owner:** severity engine (compose per-detection band) + detection
  serializer; source via the event's provenance.
- **Impact:** UI renders `UNRATED` badges truthfully and disables severity
  filtering effectiveness.
- **Severity:** P2.
- **Evidence:** `Detection.to_dict()`; UI showing UNRATED for all detections.
- **Recommended direction:** compose severity at detection persistence and
  include `source_id` from the event's provenance.
- **Implementation deferred: YES.**

## 6. Correlation severity / confidence score

- **Frontend expectation:** Correlations cards show a 0–100 confidence score.
- **Frontend location:** `CorrelationsPage.tsx`, `CaseDetailPage.tsx` correlations tab.
- **API operation currently used:** `correlation.list` / `correlation.get`.
- **Current backend behavior:** `Correlation.to_dict()` has no confidence.
- **Gap:** confidence not exposed (case-level `confidence` band exists; per-correlation does not).
- **Owner:** correlation serializer / severity-confidence engine.
- **Impact:** UI renders "Confidence: —" with an explanatory tooltip.
- **Severity:** P2.
- **Evidence:** rendered "—" on live UI.
- **Recommended direction:** expose an authoritative confidence value or omit the design element.
- **Implementation deferred: YES.**

## 7. Correlation pattern catalogue operation

- **Frontend expectation:** Correlations page lists all correlation clusters.
- **Frontend location:** `SocContext.refreshAll` (`KNOWN_CORRELATION_PATTERN_ID`).
- **API operation currently used:** `correlation.list` (requires `pattern_id`;
  unfiltered returns `[]` by documented invariant) + `correlation.list_for_incident` per case.
- **Current backend behavior:** no operation lists the registered correlation
  patterns (`NGINX-CORR-BRUTEFORCE-001`, …).
- **Gap:** the pattern id cannot be discovered on the wire; the frontend
  hardcodes the single known id from `app/correlation/patterns.py`.
- **Owner:** correlation read service + proxy.
- **Impact:** any future pattern added to the backend would be invisible to the
  UI until the constant is updated (per-case listing mitigates for
  case-bound correlations).
- **Severity:** P2.
- **Evidence:** `correlation.list` unfiltered returns `[]` (contract §5.1).
- **Recommended direction:** add `correlation.list_patterns` or allow
  unfiltered `correlation.list` with a bounded limit.
- **Implementation deferred: YES.**

## 8. Deep health / subsystem observability

- **Frontend expectation:** Health page shows per-subsystem status, latency,
  throughput, uptime, diagnostics and remediation.
- **Frontend location:** `HealthPage.tsx`, `adapters.adaptHealth`.
- **API operation currently used:** `health` (liveness only, no auth, documented).
- **Current backend behavior:** returns `{status: "ok"}`; does NOT probe
  MongoDB/registry/ingress (documented deferral in the contract §10).
- **Gap:** no deep health wire operation.
- **Owner:** observability layer + proxy.
- **Impact:** the Health page truthfully renders (a) the real liveness probe
  with measured round-trip latency and (b) real per-source state derived from
  `source.list` health (`ok|degraded|unknown|disabled|retired`). Invented
  subsystem metrics (uptime %, throughput) were removed from the UI.
- **Severity:** P1 (the page's core value depends on it).
- **Evidence:** contract §10 "does NOT check MongoDB / registry / sources".
- **Recommended direction:** `system.health.deep` returning per-subsystem
  status/latency/last-error (Mongo, rule registry, correlation service,
  ingress replay store, per-source ingress health).
- **Implementation deferred: YES.**

## 9. Per-source ingest telemetry

- **Frontend expectation:** Sources page shows events/sec, 24h ingest volume,
  latency per source.
- **Frontend location:** `SourcesPage.tsx` (renders "—" with tooltip).
- **API operation currently used:** `source.list` (`SourceInstanceView.health`).
- **Current backend behavior:** health view has `status`, `last_received_at`,
  `last_validation_at`, `last_error` — no counters.
- **Gap:** no ingest counters on the wire.
- **Owner:** ingress/observability (counters at the ingress boundary).
- **Impact:** metrics render "—"; no fabrication.
- **Severity:** P2.
- **Recommended direction:** aggregate per-source event counts/latency at ingress; expose in `SourceInstanceView`.
- **Implementation deferred: YES.**

## 10. Sigma / YARA-L / CEL rule authoring

- **Frontend expectation:** AddRuleModal offers Sigma/YARA-L/CEL DSL editing.
- **Frontend location:** `AddRuleModal.tsx` (DSL selector removed; truthful notice shown).
- **API operation currently used:** `rule.create` (structured definition:
  `conditions`, `actions: alert|log|block_remediation`).
- **Current backend behavior:** strict structured `RuleDefinition` only; no DSL compiler.
- **Gap:** no Sigma/YARA-L/CEL parsing/validation/compilation.
- **Owner:** rules engine.
- **Impact:** the modal now explains the backend accepts structured condition
  JSON only and creates CANDIDATE rules truthfully; Sigma text cannot be
  submitted (it would be rejected — the UI prevents the guaranteed failure).
- **Severity:** P2.
- **Recommended direction:** either a Sigma→structured-conditions compiler
  gated by the research-to-rule governance flow, or removal of the DSL
  framing from the approved design.
- **Implementation deferred: YES.**

## 11. Correlation → case creation

- **Frontend expectation:** Correlations page implies "open/create case from cluster".
- **API operation currently used:** `case.create` — **always 400 by design**
  (Phase 4.8 boundary; the proxy never constructs evidence).
- **Current backend behavior:** cases are only created by the internal
  pipeline (correlation → incident assembly), not via the wire.
- **Gap:** none to fix blindly — this is a deliberate boundary. If the product
  wants analyst-created cases from clusters, that is a spec change.
- **Classification:** `SPEC REQUIRED` (decision) / `DEFERRED BY DESIGN`.
- **Severity:** P2 (workflow limitation, honest UI).
- **Recommended direction:** a future `case.create_from_correlation` with an
  evidence-payload schema, per the boundary note in contract §3.6.
- **Implementation deferred: YES.**

## 12. Notification feed

- **Frontend expectation:** TopBar notification tray with unread badges.
- **Frontend location:** `TopBar.tsx`, `SocContext.notifications` (always empty).
- **API operation currently used:** none.
- **Gap:** no notification/feed operation on the wire.
- **Owner:** new notification domain + persistence + proxy.
- **Impact:** tray renders a truthful empty state; no demo notifications.
- **Severity:** P3 / `JUSTIFIED ENHANCEMENT`.
- **Implementation deferred: YES.**

## 13. Global (cross-case) timeline

- **Frontend expectation:** standalone Timeline page across all activity.
- **Frontend location:** `TimelinePage.tsx` (per-case builder + case selector).
- **API operation currently used:** `timeline.build_for_incident` (per-incident only).
- **Gap:** no global/bounded timeline query (`since`/`until`/`kind` filters are
  documented as not exposed).
- **Owner:** timeline engine + read service + proxy.
- **Impact:** UI aggregates per-case timelines client-side; a case selector
  makes the per-case scope explicit.
- **Severity:** P2.
- **Implementation deferred: YES.**

## 14. Report export formats

- **Frontend expectation:** report download (design shows Markdown/PDF-style export).
- **API operation currently used:** `report.export` (JSON only; PDF/CSV return
  documented 400).
- **Gap:** no PDF/CSV/Markdown rendering backend-side.
- **Owner:** reports service.
- **Impact:** UI downloads the real backend JSON artifact and labels the
  button ".JSON (backend artifact)"; no client-fabricated documents.
- **Severity:** P3.
- **Implementation deferred: YES.**

## 15. Overview time-series aggregates

- **Frontend expectation:** hourly threat-velocity chart.
- **API operation currently used:** `overview.summary` (4 counters) + client-side
  bucketing of `detection.list` timestamps.
- **Gap:** no time-series aggregate operation (bounded, indexed).
- **Owner:** overview service.
- **Impact:** chart is real-data-derived client-side; acceptable at MVP data
  volumes, would need server aggregation at scale.
- **Severity:** P3.
- **Implementation deferred: YES.**

## 16. Explicitly NOT backend requirements

| Gemini affordance | Classification | Decision |
|---|---|---|
| `DesignBattleDeliverable` page (design spec) | `VISUAL ONLY` | Kept as design documentation surface; renders no operational data. |
| `ErrorSimulationSandbox` modal | `NOT CURRENTLY REQUIRED` | Kept as a UI-training tool; it renders the documented error envelope semantics and never fakes success states. |
| Demo capability catalog (Okta/AWS/CrowdStrike/…) | `BACKEND GAP` (visual lie) | **Removed from production data.** Capabilities now derive only from `source.list_types`. |
| Fake ingest-rate indicators ("8,420 eps"), fake analyst ("Sarah Chen"), fake health backlog ("SRC-05 … 88%") | `VISUAL ONLY` / removed | Replaced with real session identity, real data counts, real health state. |

---

## Summary table

| # | Feature | Class | Severity | Status |
|---|---|---|---|---|
| 1 | Case acknowledge/investigate transitions | SPEC REQUIRED / BACKEND GAP | P1 | DEFERRED |
| 2 | Human-readable entity IDs | JUSTIFIED ENHANCEMENT | P2 | DEFERRED |
| 3 | Case attacker/target/source attribution | SPEC REQUIRED / BACKEND GAP | P1 | DEFERRED |
| 4 | Case analyst notes | JUSTIFIED ENHANCEMENT | P2 | DEFERRED |
| 5 | Detection severity + source attribution | BACKEND GAP | P2 | DEFERRED |
| 6 | Correlation confidence score | BACKEND GAP | P2 | DEFERRED |
| 7 | Correlation pattern catalogue op | BACKEND GAP | P2 | DEFERRED |
| 8 | Deep health / subsystem observability | SPEC REQUIRED / BACKEND GAP | P1 | DEFERRED |
| 9 | Per-source ingest telemetry | BACKEND GAP | P2 | DEFERRED |
| 10 | Sigma/YARA-L/CEL rule authoring | DESIGN REQUIRED / BACKEND GAP | P2 | DEFERRED |
| 11 | Analyst case creation from correlation | SPEC REQUIRED (decision) | P2 | DEFERRED (deliberate boundary) |
| 12 | Notification feed | JUSTIFIED ENHANCEMENT | P3 | DEFERRED |
| 13 | Global timeline query | BACKEND GAP | P2 | DEFERRED |
| 14 | Report export formats (PDF/CSV) | JUSTIFIED ENHANCEMENT | P3 | DEFERRED |
| 15 | Overview time-series aggregates | JUSTIFIED ENHANCEMENT | P3 | DEFERRED |
