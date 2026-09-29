# ProShield — Backend Capability Patch Report

**Phase:** Implementation + verification of the 15 documented backend capability gaps
**Repository:** authoritative main ProShield repo (`main`)
**Date:** 2026-09-07
**Baseline:** `f674f09` ("checkpoint before Gemini frontend integration")
**Companion documents:**
- `docs/PHASE 4/backend-missing-features.md` (the discovery report this patch implements)
- `docs/PHASE 4/PHASE-A-GAP-MATRIX.md` (independent re-confirmation matrix)
- `docs/PHASE 4/PROSHIELD-FINAL-FRONTEND-BACKEND-CONTRACT.md` (frozen contract; additive ops listed in §Addendum)

---

## 0. Executive verdict

**B. READY WITH EXPLICIT LIMITATIONS.**

All 15 documented gaps were independently re-confirmed against the current
repository (Phase A matrix), implemented at their owning layer, and verified
through four independent evidence channels:

1. **Automated tests** — 1373 passed / 0 failed / 0 skipped
   (baseline 1313 → +60 new capability tests). Full suite re-run after all
   changes: `1373 passed, 1 warning in 27.43s`.
2. **Fresh-database audit** — dedicated `proshield_patch_audit` DB, dropped
   and rebuilt from scratch: **23/23 checks passed**
   (validators present on every collection incl. the 3 new ones, unique
   indexes verified, malformed direct writes rejected at the DB boundary,
   human-id counters monotonic + concurrent-unique 25/25).
3. **Live HTTP stack** (real MongoDB `proshield` DB, analyst `:8088` +
   ingress `:8089`): **43/43 wire checks passed**, then a full server
   restart and **9/9 restart-persistence checks passed**.
4. **Real browser (Playwright)** — complete analyst journey with
   screenshots, zero unexpected console errors, responsive at 1440/768/390.

The limitations are explicit and non-blocking; they are listed in §6.

---

## 1. Findings and final statuses

| ID | Capability | Root cause (confirmed) | Fix (owning layer) | Final status |
|----|-----------|------------------------|--------------------|--------------|
| 1 | Case acknowledge/investigate | `IncidentLifecycleState` closed set had no triage states; no wire ops | New states + documented transition matrix in `IncidentService` (409 `CaseStateConflictError` on invalid/repeated), wire ops `case.acknowledge` / `case.investigate`; validator enum extended | **RESOLVED** |
| 2 | Stable human-readable IDs | No persisted id; UI derived ids client-side from row ordering | `app/persistence/human_ids.py` — atomic mongo `counters` collection (`find_one_and_update $inc`), memory fallback; assigned at create/upsert in incident/detection/correlation/source repositories; `human_id` on every wire view. Format `CASE-000001` etc. | **RESOLVED** |
| 3 | Case attacker/target/source attribution | `Incident` carried no attribution | `CaseAttribution` composed at case assembly from correlation key parts + event/detection provenance, provenance string records derivation; `None` when underivable (never fabricated) | **RESOLVED** |
| 4 | Analyst case notes | No notes concept | Append-only `CaseNote` (author, role, UTC timestamp, bounded body) embedded on the case; `case.note.add` op; `case.get` returns notes; no cross-case leakage possible (embedded) | **RESOLVED** |
| 5 | Detection severity + source attribution | `SeverityEngine` existed but its per-detection assessment was never composed into persisted detections; provenance pointer not carried | `app/severity/enrichment.py` composed in `DetectionPipeline.run` before persistence (severity band via the real engine, `source_instance_id` from event provenance); model + validator + wire updated | **RESOLVED** |
| 6 | Correlation confidence | Same — engine never applied at persistence | `enrich_correlation` composed in `CorrelationRepository.create` (single choke point for every creation path); band persisted; wire exposes `confidence` | **RESOLVED** |
| 7 | Correlation pattern catalogue | Pattern ids undiscoverable on the wire; frontend hardcoded the one id it knew | `PATTERN_CATALOGUE` registration in `app/correlation/patterns.py`, `describe_registered_patterns()`, `CorrelationReadService.list_patterns()`, wire op `correlation.list_patterns`; frontend fetches per-pattern | **RESOLVED** |
| 8 | Deep health / subsystem observability | `health` was liveness-only (documented deferral) | `app/observability/health.py` `DeepHealthService` — 8 probes (database, persistence collections, rule registry, incident/detection/correlation subsystems, source registry, ingress telemetry) with the closed status set healthy/degraded/unavailable/not_configured and per-probe latency; wire op `system.health.deep`; dead dependency → UNAVAILABLE (verified) | **RESOLVED** |
| 9 | Per-source ingest telemetry | `SourceInstanceHealth.received_count/rejected_count` existed but nothing incremented them | `app/persistence/telemetry.py` `SourceTelemetryStore` (atomic `$inc`, unique per-source doc, `received/accepted/rejected/errors/last_event_at/last_error`), hooked into `InboundIngressProxy._handle_ingest` (fresh hooks incl. replay-rejections and per-event validation failures), merged into `source.list` as `ingest_telemetry` | **RESOLVED** |
| 10 | Sigma/YARA-L/CEL rule authoring | Gemini design offered DSL editors; **no authoritative ProShield spec mentions Sigma/YARA-L/CEL** (grep over `docs/` confirms) | Per the mission rule ("do not blindly create parsers for languages the project does not require"): structured rule authoring is the spec'd path and is now proven live end-to-end — operator-authored `rule.create` → `rule.enable` → real ingress event → real detection produced by the new rule (`DET-000085`, severity composed) → `rule.disable`. UI already truthful. | **NOT REQUIRED — SPEC PROVES OTHERWISE** (structured authoring verified RESOLVED-equivalent) |
| 11 | Analyst case creation from correlation | `case.create` always 400 (Phase 4.8 boundary); internal assembly existed | New `case.create_from_correlation`: proxy resolves the correlation + member detections/events **from persistence** (never from the payload; missing evidence skipped), calls the same idempotent internal assembly (deterministic cluster→case id); response states `created: true/false` | **RESOLVED** |
| 12 | Notification feed | No notification domain | New `app/notifications/` package (models + repository with validator/indexes + service); incident service emits via an injected sink on **real** state changes (created/acknowledged/investigating/closed/note_added); ops `notification.list` / `notification.mark_read` / `notification.unread_count`; audience-role scoping; UI tray consumes the real feed | **RESOLVED** |
| 13 | Global timeline query | Only per-incident op shipped | `TimelineReadService.global_query` — bounded per-kind fetch (events/detections/correlations), merged newest-first, since/until/kind filters, offset/limit pagination; wire op `timeline.global_query` | **RESOLVED** |
| 14 | Report export formats | `report.export` rejected anything but JSON | `app/reports/exporter.py` renders the REAL persisted report: **Markdown** (full Unicode), **CSV** (RFC 4180, UTF-8 BOM, full Unicode), **PDF** (dependency-free multi-page PDF 1.4). Wire response: `content_base64` + `media_type` + `file_extension` (+ `content_text` for md/csv) | **RESOLVED** (PDF has one documented Unicode limitation, §6) |
| 15 | Overview time-series aggregates | No aggregate op; UI bucketed client-side | `OverviewReadService.timeseries` over a new bounded indexed query `DetectionRepository.find_since`; UTC hour buckets, explicit zero buckets, severity split, bounded (≤5000 rows, truncated flag); wire op `overview.timeseries`; UI chart consumes the server series | **RESOLVED** |

**TOTAL: 14 implemented (RESOLVED) · 0 partially · 0 unresolved · 1 not required
(gap 10 — spec decision, with its structured-authoring path verified live).**

---

## 2. Files changed / created

### Created (backend)
| File | Purpose |
|---|---|
| `app/persistence/human_ids.py` | Gap 2: atomic human-id allocator |
| `app/persistence/telemetry.py` | Gap 9: per-source ingest counters (validator + indexes) |
| `app/severity/enrichment.py` | Gaps 5+6: severity/confidence composition helpers |
| `app/notifications/__init__.py` / `models.py` / `repository.py` / `service.py` | Gap 12: notification feed domain |
| `app/observability/health.py` | Gap 8: deep health service |
| `app/reports/exporter.py` | Gap 14: markdown/csv/pdf renderers |
| `docs/PHASE 4/PHASE-A-GAP-MATRIX.md` | Phase-A confirmation matrix |
| `docs/PHASE 4/PROSHIELD-BACKEND-CAPABILITY-PATCH-REPORT.md` | This report |
| `scripts/audit_fresh_db.py` | Fresh-DB audit harness |
| `scripts/verify_live_capability.py` | 43-check live wire harness |
| `scripts/verify_restart_persistence.py` | Post-restart persistence probe |
| `scripts/verify_rule_live.py` | Operator-rule detection-path harness |
| `scripts/create_browser_case.py` | Pipeline case factory for the browser journey |
| `scripts/restart_audit_stack.ps1` | Two-plane restart helper (8088/8089) |
| `tests/unit/test_capability_patch.py` | 56 regression tests across all gaps |

### Modified (backend)
`app/incidents/models.py` (states, CaseNote, CaseAttribution, human_id),
`app/incidents/service.py` (acknowledge/investigate/add_note, attribution
composition, notification sink),
`app/incidents/repository.py` (validator, allocator),
`app/incidents/errors.py` (`CaseStateConflictError` 409),
`app/detection/models.py` (severity, source_instance_id, human_id),
`app/detection/pipeline.py` (enrichment hook),
`app/correlation/models.py` (confidence, human_id),
`app/persistence/detection_repository.py`, `app/persistence/correlation_repository.py`
(validators, allocators, composition, quarantine-safe round-trips),
`app/persistence/security_event_repository.py` (**pre-existing bug fix**: bounded
reads now quarantine poisoned legacy documents instead of crashing — documented
repository policy),
`app/persistence/bootstrap.py` (counters/notifications/telemetry preparation),
`app/sources/models.py` (human_id + view), `app/sources/repository.py` (allocator),
`app/sources/ingress.py` (telemetry hooks),
`app/correlation/patterns.py` (pattern catalogue),
`app/correlation/service.py` (`list_patterns`),
`app/overview/service.py` (`timeseries`),
`app/timeline/service.py` (`global_query`),
`app/proxy/proxy.py` (11 new ops, dispatch, handlers, telemetry merge, export
formats), `app/proxy/__init__.py` (op exports),
`scripts/proxy_server.py` (wiring: notification service + sink, telemetry store,
deep health, FakeCollection `find_one_and_update`/`list_indexes`),
`scripts/ingress_server.py` (telemetry recorder wiring).

### Modified (frontend `frontend/src_upgraded_gemini/`)
`src/services/backend.ts` (new raw fields + 14 typed ops),
`src/services/adapters.ts` (backend human ids with legacy fallback, attribution,
persisted notes, detection severity/source, correlation confidence band, source
telemetry, `adaptDeepHealth`),
`src/types/soc.ts` (field additions),
`src/context/SocContext.tsx` (real acknowledge/investigate/note ops, real
notification feed + mark-read, deep health merge, pattern discovery, server
time-series state),
`src/components/pages/{CorrelationsPage,SourcesPage,OverviewPage}.tsx`
(truthful rendering of the new data),
`src/data/mockData.ts` (design-preview fixture type alignment only).

### Database changes
| Collection | Change |
|---|---|
| `incidents` | validator: state enum + `acknowledged`/`investigating`, new optional `human_id` / `attribution` / `notes` |
| `detections` | validator: optional `severity` / `source_instance_id` / `human_id` |
| `correlations` | validator: optional `confidence` / `human_id` |
| `source_instances` | validator: optional `human_id` |
| `notifications` (new) | `$jsonSchema` validator + unique `ntf_notification_id_unique` + 4 query indexes |
| `source_telemetry` (new) | `$jsonSchema` validator + unique `tel_source_instance_id_unique` + recency index |
| `counters` (new) | one doc per entity kind; uniqueness via native `_id` |

All applied idempotently by the single startup hook
(`app/persistence/bootstrap.py`) on both planes — verified against a
freshly created database (23/23).

### API operations added (11)
`case.acknowledge` · `case.investigate` · `case.note.add` ·
`case.create_from_correlation` · `correlation.list_patterns` ·
`system.health.deep` · `notification.list` · `notification.mark_read` ·
`notification.unread_count` · `timeline.global_query` · `overview.timeseries`
— plus `report.export` extended (`markdown`/`csv`/`pdf`) and `source.list`
extended (`ingest_telemetry`). All routed through `SecureProxy.handle` with
authentication enforced (verified 401 unauthenticated for every new op).

---

## 3. Evidence index

| Evidence | Artifact | Result |
|---|---|---|
| Full automated suite (final) | `pytest_final.txt` | **1373 passed**, 0 failed, 0 skipped, 1 deprecation warning |
| Fresh-DB audit | `audit_out.txt` + `scripts/audit_fresh_db.py` | **23/23** (validators, unique indexes, malformed-write rejection, human-id monotonicity + 25/25 concurrent uniqueness) |
| Live wire verification | `live_verify_out.txt` | **43/43** (see §4) |
| Restart persistence | `restart_verify_out.txt` | **9/9** |
| Operator rule in detection path | `rule_live_out.txt` | **5/5** |
| Browser journey | `journey-0*.png` screenshots | §5 |
| Unit capability tests | `tests/unit/test_capability_patch.py` | 56 passed |

## 4. Live pipeline verification (real MongoDB `proshield` DB, HTTP only)

`scripts/verify_live_capability.py` — 43/43:
1. **External source lifecycle** (admin): `source.register` (SRC-000009, human id
   assigned) → `configure` (push) → `validate` → `enable` → `issue_token`.
2. **Real ingress**: 6 events POSTed to `:8089` with single-use tokens → 6
   accepted; token replay correctly rejected (D-1); identical re-delivery
   idempotent; conflicting-content replay rejected (`conflict_event`, T02);
   malformed event rejected.
3. **Detection**: ≥12 new detections each carrying composed severity,
   `source_instance_id` and `DET-0000xx`.
4. **Correlation**: brute-force cluster produced for the run's attacker IP with
   persisted confidence band + `CORR-0000xx`; `correlation.list_patterns`
   serves the live catalogue.
5. **Case**: pipeline-opened case with `CASE-000003`, attribution
   `attacker=203.0.113.96, target=audit-simulator.local/events` with
   provenance; full lifecycle open→acknowledged→investigating→closed
   exercised on the wire incl. 409 on repeated acknowledge; note persisted
   with Unicode; `case.get` shows notes + history.
6. **Notifications**: unread counts real, list/mark-read persisted.
7. **Global timeline**: ordered newest-first, kind filter, pagination.
8. **Overview time-series**: 6 UTC-hour buckets, real counts.
9. **Deep health**: all 8 subsystems healthy, statuses truthful.
10. **Reports**: generate_normal (and truthful 400 refusal of
    generate_centralized when no centralized context), exports
    markdown (10,128 B) / csv (9,995 B) / pdf (12,734 B, `%PDF-1.4` … `%%EOF`),
    unknown format → 400.
11. **Telemetry**: `received=9 accepted=6 rejected=2 errors=1` on the run's
    source — matching the exact event mix offered.

## 5. Browser verification (Playwright, real stack, admin + analyst)

Journey: login (real `auth.issue`) → Overview (real hero case, server
time-series chart) → Incidents queue (`Ack` quick-action → backend state
ACKNOWLEDGED) → Case Detail lifecycle rail (acknowledge → investigating,
each click a real wire op with success toast) → Analyst Notes (post note →
`Analyst Notes (4)`, **survives hard reload**) → Detections (**0 UNRATED**;
backend `DET-0000xx` ids; severity bands) → Correlations (real
`Confidence: LOW` bands; legacy rows truthfully "—") → Sources (real
"6 accepted / 1 rejected" counters; "no telemetry yet" for silent sources) →
Health (all 8 deep subsystem rows) → Notifications tray (real kinds
`case.acknowledged` / `case.note_added` / `case.closed`…, Mark-all-read →
backend persisted, Mongo-verified `read=23/23`).
Screenshots: `journey-01..08*.png`. Responsive: no horizontal overflow at
1440 / 768 / 390 px. Console: zero errors during the journey (the only
historical 401s are the stale-session boot rejections before login).

## 6. Explicit limitations (non-blocking)

1. **PDF export Unicode**: the dependency-free PDF writer uses the built-in
   Helvetica font (Latin-1); characters outside Latin-1 are visibly
   transliterated to `?`. Full-fidelity Unicode lives in the Markdown/CSV
   exports. Fixing properly requires an embedded Unicode font (dependency
   decision deferred).
2. **Legacy rows**: entities created before this patch keep `human_id=""` /
   no severity / no confidence; the wire renders `null` and the UI shows
   "—"/UNRATED rather than back-filling fabricated values. All new records
   are fully populated (verified).
3. **Analyst visibility of pipeline cases**: cases auto-opened by the
   ingress pipeline are owned by the internal pipeline subject and are
   hidden from analysts by the documented object-level authz (IDOR
   defence). Admins see them. This is pre-existing designed behaviour,
   not a regression; a sharing/assignment feature is future work.
4. **Sigma/YARA-L/CEL**: intentionally not implemented (no authoritative
   spec requires them; see §1 gap 10).
5. **`generate_centralized` truthful refusal**: refuses with 400 when a
   case carries no centralized context — documented behaviour, surfaced
   as such (not a bug).
6. **`received` counter semantics**: counts events offered per ingest
   batch; reset/redeploy of the ingress does not erase history (persisted).

## 7. Adversarial tests executed (summary)

restart (×2 planes, data survived) · browser reload (session + data) ·
duplicate acknowledge (409) · acknowledge closed case (409) · unknown case
(404) · empty note body (400) · note limit (409) · unknown notification
(404) · unknown notification kind (400) · duplicate event (idempotent) ·
conflicting-content replay (rejected) · malformed event (rejected) ·
single-use token replay (rejected) · unauthorized new ops (401) · unknown
export format (400) · empty dataset timeline/timeseries (explicit zeros) ·
kind-filtered timeline · concurrent human-id allocation (25/25 unique) ·
probe-failure health (UNAVAILABLE, never green) · memory-backend health
(DEGRADED, never silently green) · poisoned legacy event document
(quarantined, read path survives).

---

## 8. Reproduction

```powershell
# automated suite (MongoDB on 127.0.0.1:27017 required for integration)
python -m pytest -q

# fresh-DB audit
python scripts/audit_fresh_db.py

# live two-plane stack against the `proshield` database
powershell -File scripts/restart_audit_stack.ps1

# live verifications
python scripts/verify_live_capability.py
python scripts/verify_restart_persistence.py   # after a restart
python scripts/verify_rule_live.py
```
