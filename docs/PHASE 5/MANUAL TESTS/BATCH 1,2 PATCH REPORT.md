# ProShield Batch 1 & 2 Patch Report

**Campaign:** Manual validation Batch 1 & Batch 2 (T01–T30)
**Scope of this document:** forensic investigation of the supplied Batch 1/2
findings (T04, T22, T28 + the supplied UI/integration observations), the
minimal fixes for the defects that were reproduced and proven, and the full
regression + live evidence that validates them.
**Product version:** unchanged — **1.0.3** (no version bump, no 1.3.1, no 1.4).

---

## Scope

Investigated (in the order of the task brief):

| # | Finding | Result |
|---|---|---|
| 1 | Old connector artifact (`app/connectors/**`) | LEGACY / COMPATIBILITY CODE (not on the live path) — left untouched |
| 2 | Capability → Source → Rule UI semantics | EXPECTED (truthful, server-authoritative) — verified live |
| 3 | Capabilities UI "Phase 5.1 live" labels | CONFIRMED (stale/misleading) — presentation patched |
| 4 | Timestamp display (incl. "Indian local time") | **CONFIRMED (current requirement) — IST display**; patched, plus a second proven defect on the same path (offset-less canonical strings were read as host-local). Canonical storage untouched |
| 5 | Retire / archive behaviour | EXPECTED (soft-delete) + FUTURE-PHASE GAP (Evidence Archive = Phase 5.6) |
| 6 | Frontend stale state / refresh | CONFIRMED (partial): no refetch on navigation / external change — read path patched minimally |
| 7 | T04 (ingress/source architecture, T04-FE-01/-ARCH-01/-02/-03) | Mostly EXPECTED; one UI refresh defect confirmed (see #6) |
| 8 | T22 (invalid timestamp) | **CONFIRMED BUG** — fabricated `event_time` for non-timestamps |
| 9 | T28 (case evidence completeness) | **CONFIRMED BUG** (+ a second, worse defect: cross-cluster evidence contamination) |
| 10 | Other T01–T30 records | The T01–T30 record files are **not present in this working tree**; only the findings supplied in the task brief could be investigated. Every id has an explicit disposition in **## T01–T30 Test Disposition** (unavailable ones marked *ORIGINAL TEST RECORD UNAVAILABLE — NOT RECONSTRUCTED*) |

**Not invented / not patched:** every observation that could not be reproduced
as a *current* product defect is recorded below with its evidence and its
classification, and was deliberately left unpatched.

---

## Environment

* **Repository:** `proshield rule based mvp` @ commit `f674f09`
  ("checkpoint before Gemini frontend integration"), branch `main`.
* **T01–T30 records:** searched the repository and `docs/**` for the Batch 1/2
  test records (ids `T01`…`T30`, `T04-FE-01`, `T04-ARCH-*`, `MANUAL TESTS`,
  `Batch 1/2`). **They do not exist in this working tree** (the only `T22`
  occurrence is an unrelated threat-model section id in
  `docs/PHASE 1/THREAT_MODEL.md`; the only `/t28-ui-retrieval` evidence is
  *data* left by the earlier manual session inside MongoDB). No missing result
  was invented: this report investigates exactly the findings supplied in the
  task brief.
* **Runtime under test (live):** the *installed product* — Windows service
  `ProShieldService`, install dir `C:\inetpub\ProShield`, data dir
  `C:\ProgramData\ProShield`, version 1.0.3 (`install-info.json`), analyst
  plane `http://127.0.0.1:8088`, ingress plane `http://127.0.0.1:8089`,
  MongoDB `127.0.0.1:27017` (8.0.13), database `proshield`.
* **Browser:** Chromium via Playwright MCP (viewport 1440×900).
* **Repo-launched verification stack:** the same shipped bundles
  (`scripts._build_mongo_backend` / `scripts._build_mongo_ingress`), used for
  the patched-code live runs (the installed copy cannot be patched without a
  redeploy, which this task explicitly forbids: no version/release change).
* **Frontend:** `frontend/src_upgraded_gemini` (React 19 + Vite 7 +
  `vite-plugin-singlefile`) built to the committed single-file artifact
  `frontend/soc/index.html`, served by the analyst plane at
  `/static/soc/index.html` (the documented authoritative UI). The installer
  packages only `frontend/login.html` + `frontend/soc/index.html`; live
  `/static/index.html` returns **404** (the legacy vanilla shell is not shipped).
* **IST verification environment:** Node `v24.20.0` with the project's own
  `esbuild` (a Vite dependency) used to bundle and execute the real
  `src/utils/format.ts` inside the regression test; `zoneinfo("Asia/Kolkata")`
  (Python 3.13) used as the *independent* reference implementation for the
  browser comparisons. The host clock happens to be IST (UTC+05:30), which is
  why the offset-less-value defect (Finding 4 / `B12-TIME-02`) could be proven by
  difference — the display must not depend on the host timezone.
* **Verification stack for the patched bundle (this task's live runs):** repo
  planes `scripts.proxy_server` on `:8188` and `scripts.ingress_server` on
  `:8189`, database `proshield_ist_verify`, credentials seeded with
  `--seed-credentials`, launched detached (WMI) so the run survives tool-terminal
  recycling.

---

## T01–T30 Test Disposition

The Batch 1/2 record files are **not present in this working tree** (searched
`docs/**` and the whole repository for `T01`…`T30`, `T04-FE-01`, `T04-ARCH-*`,
`MANUAL TESTS`). No missing result was invented: ids without a supplied record
are marked exactly as required, and the ids that *were* supplied (T04, T22, T28
plus the UI/integration observations) are fully investigated in the Finding
Register.

| Test | Observation | Reproduction | Classification | Patch | Validation | Deferred Item |
|---|---|---|---|---|---|---|
| T01 | *ORIGINAL TEST RECORD UNAVAILABLE — NOT RECONSTRUCTED* | — | INCONCLUSIVE (no record) | none | — | record retrieval |
| T02 | *ORIGINAL TEST RECORD UNAVAILABLE — NOT RECONSTRUCTED* | — | INCONCLUSIVE (no record) | none | — | record retrieval |
| T03 | *ORIGINAL TEST RECORD UNAVAILABLE — NOT RECONSTRUCTED* | — | INCONCLUSIVE (no record) | none | — | record retrieval |
| **T04** | 8089 = live ingress plane; unauthenticated `source.ingest` → 401; NGINX connector registered but no runtime construction path; `connection_type`+`endpoint` vs `log_path` | Live: `scripts/repro_batch12_live` → `ingress /health` 200 (`supported_operations=[source.health, source.ingest]`), unauth ingest **401** `source_identity_token_error`; `app/connectors/**` has no live construction path | T04 = **EXPECTED** (two-plane boundary); T04-ARCH-01 = **FUTURE-PHASE GAP** (5.6); T04-ARCH-02/03 = **LEGACY / DEAD ARTIFACT**; T04-FE-01 = **CONFIRMED BUG → PATCHED** | yes (T04-FE-01 Reload only) | live 401 + Reload before/after screenshots | Evidence Archive (5.6); connector retirement = register **D-A** |
| T05 | *ORIGINAL TEST RECORD UNAVAILABLE — NOT RECONSTRUCTED* | — | INCONCLUSIVE (no record) | none | — | record retrieval |
| T06 | *ORIGINAL TEST RECORD UNAVAILABLE — NOT RECONSTRUCTED* | — | INCONCLUSIVE (no record) | none | — | record retrieval |
| T07 | *ORIGINAL TEST RECORD UNAVAILABLE — NOT RECONSTRUCTED* | — | INCONCLUSIVE (no record) | none | — | record retrieval |
| T08 | *ORIGINAL TEST RECORD UNAVAILABLE — NOT RECONSTRUCTED* | — | INCONCLUSIVE (no record) | none | — | record retrieval |
| T09 | *ORIGINAL TEST RECORD UNAVAILABLE — NOT RECONSTRUCTED* | — | INCONCLUSIVE (no record) | none | — | record retrieval |
| T10 | *ORIGINAL TEST RECORD UNAVAILABLE — NOT RECONSTRUCTED* | — | INCONCLUSIVE (no record) | none | — | record retrieval |
| T11 | *ORIGINAL TEST RECORD UNAVAILABLE — NOT RECONSTRUCTED* | — | INCONCLUSIVE (no record) | none | — | record retrieval |
| T12 | *ORIGINAL TEST RECORD UNAVAILABLE — NOT RECONSTRUCTED* | — | INCONCLUSIVE (no record) | none | — | record retrieval |
| T13 | *ORIGINAL TEST RECORD UNAVAILABLE — NOT RECONSTRUCTED* | — | INCONCLUSIVE (no record) | none | — | record retrieval |
| T14 | *ORIGINAL TEST RECORD UNAVAILABLE — NOT RECONSTRUCTED* | — | INCONCLUSIVE (no record) | none | — | record retrieval |
| T15 | *ORIGINAL TEST RECORD UNAVAILABLE — NOT RECONSTRUCTED* | — | INCONCLUSIVE (no record) | none | — | record retrieval |
| T16 | *ORIGINAL TEST RECORD UNAVAILABLE — NOT RECONSTRUCTED* | — | INCONCLUSIVE (no record) | none | — | record retrieval |
| T17 | *ORIGINAL TEST RECORD UNAVAILABLE — NOT RECONSTRUCTED* | — | INCONCLUSIVE (no record) | none | — | record retrieval |
| T18 | *ORIGINAL TEST RECORD UNAVAILABLE — NOT RECONSTRUCTED* | — | INCONCLUSIVE (no record) | none | — | record retrieval |
| T19 | *ORIGINAL TEST RECORD UNAVAILABLE — NOT RECONSTRUCTED* | — | INCONCLUSIVE (no record) | none | — | record retrieval |
| T20 | *ORIGINAL TEST RECORD UNAVAILABLE — NOT RECONSTRUCTED* | — | INCONCLUSIVE (no record) | none | — | record retrieval |
| T21 | *ORIGINAL TEST RECORD UNAVAILABLE — NOT RECONSTRUCTED* | — | INCONCLUSIVE (no record) | none | — | record retrieval |
| **T22** | Invalid/missing canonical `event_time`; original record INCONCLUSIVE because the old test used the non-canonical key `timestamp` | Live 14-variant matrix on the canonical field (`scripts/repro_batch12_live`) | **CONFIRMED BUG → PATCHED / VERIFIED** | yes (`app/sources/ingress.py`) | 5 valid forms normalise to one UTC instant; invalid string / malformed / impossible date / int / list / null / missing / future **all** refused `validation_error`; `ingested_at` stays distinct; 15→22 regression tests green | none |
| T23 | *ORIGINAL TEST RECORD UNAVAILABLE — NOT RECONSTRUCTED* | — | INCONCLUSIVE (no record) | none | — | record retrieval |
| T24 | *ORIGINAL TEST RECORD UNAVAILABLE — NOT RECONSTRUCTED* | — | INCONCLUSIVE (no record) | none | — | record retrieval |
| T25 | *ORIGINAL TEST RECORD UNAVAILABLE — NOT RECONSTRUCTED* | — | INCONCLUSIVE (no record) | none | — | record retrieval |
| T26 | *ORIGINAL TEST RECORD UNAVAILABLE — NOT RECONSTRUCTED* | — | INCONCLUSIVE (no record) | none | — | record retrieval |
| T27 | *ORIGINAL TEST RECORD UNAVAILABLE — NOT RECONSTRUCTED* | — | INCONCLUSIVE (no record) | none | — | record retrieval |
| **T28** | Case evidence incomplete: correlation complete, case held 1 event + 1 detection + 1 correlation | Live threshold-exact 4-event cluster; MongoDB + wire + browser | **CONFIRMED BUG (two defects) → PATCHED / VERIFIED** | yes (`app/incidents/service.py`, `app/pipeline/service.py`) | correlation 4/4 → case **4e/4d/1c** → timeline **9**; two-cluster disjointness; browser `4e 4d 1c`, `Timeline (9)`, `Detections (4)` | none |
| T29 | *ORIGINAL TEST RECORD UNAVAILABLE — NOT RECONSTRUCTED* | — | INCONCLUSIVE (no record) | none | — | record retrieval |
| T30 | *ORIGINAL TEST RECORD UNAVAILABLE — NOT RECONSTRUCTED* | — | INCONCLUSIVE (no record) | none | — | record retrieval |
| Supplied obs. — IST timestamps | UI was UTC-only; IST display is a **current** requirement | Live audit of every user-visible surface + independent conversion (`scripts/_ist_live_probe.py`) | **CONFIRMED BUG/REQUIREMENT → PATCHED / VERIFIED** (+ 2nd defect: offset-less canonical strings read as host-local) | yes (`utils/format.ts` + 11 components + rebuilt bundle) | 22 IST regression tests; live ms-exact matches on 5 surfaces; 4 screenshots | none — **not** deferred |
| Supplied obs. — stale state | In-session views did not reflect backend changes | Live: ingest while the SPA was open | **CONFIRMED BUG → PATCHED / VERIFIED** | yes (`TopBar.tsx` Reload) | badge `2` → click → `3`; reload + restart persistence | live auto-sync = register **D-B** |
| Supplied obs. — retire/archive | Retired objects stay visible in operational views | Live retire of `SRC-000002` | **EXPECTED** (soft delete) + **FUTURE-PHASE GAP** (5.6) | none | 410 ingest / 409 token / history preserved / restart-stable | register **D-C** |
| Supplied obs. — capability/source/rule | Fear that a capability rule is implied to belong to one source | Live capability detail + Sources tab | **EXPECTED** (server-authoritative; `cap-nginx` → 1 source, 5 rules, 1 pattern) | none | browser + 51/51 pipeline | — |
| Supplied obs. — phase wording | `Phase 5.1 live` / "ships in Phase 5.2" | Static + live header | **CONFIRMED (presentation) → PATCHED / VERIFIED** | yes (`CapabilitiesPage.tsx`) | live header `6 from backend` + `live registry` | seeded planned-capability copy = register **D-D** |
| Supplied obs. — old connector | Concern the legacy connector layer is executed | Import/construction/API/NGINX/frontend trace | **LEGACY / DEAD ARTIFACT** | none (documented) | bundle scan `CONNECTOR_REGISTRY` 0 / `log_path` 0; ingestion runs via SourceInstance/Ingress | register **D-A** |
---

## Finding Register

### T28 — Case evidence completeness (CONFIRMED BUG, evidence integrity)

| Field | Value |
|---|---|
| **ID** | T28 (case evidence completeness) + `B12-EVIDENCE-01` (cross-cluster contamination) |
| **Source/Test** | Manual Batch 2 test T28, reproduced against the live installed product |
| **Observed behaviour** | 4 accepted events → 4 detections → 1 correlation (complete: 4 detection ids / 4 event ids) → the auto-opened case held **1 event + 1 detection + 1 correlation**; the per-case timeline therefore showed 3 items instead of 9 |
| **Reproduction** | `python -m scripts.repro_batch12_live --skip-t22` against the live installed product (analyst `:8088`, ingress `:8089`, DB `proshield`). Output (verbatim): `ingest 4 auth-failure events -> http=200 accepted=4`; `correlation -> corr-7a0c0096-…` `detection_ids=4 event_ids=4`, `correlation covers all 4 accepted events: True`; `case -> case-7cb0d907-…` `evidence.event_ids = 1`, `evidence.detection_ids = 1`; `CASE EVIDENCE COMPLETE (4 events / all detections / correlation): False`; `timeline items for the case -> 3 {'event': 1, 'correlation': 1, 'detection': 1}`; `wire case.get evidence -> events=1 detections=1 correlations=1` |
| **Evidence** | Live Mongo state (installed product, DB `proshield`): `case-7cb0d907…` (CASE-000005) evidence = 1 event / 1 detection / 1 correlation while `corr-7a0c0096…` = 4 detections / 4 events. UI: case list row `CASE-000005 … 1e 1d 1c`; case workspace `Evidence Summary 1e • 1d • 1c`, tabs `Timeline (3)`, `Detections (0)`, `Correlations (1)` |
| **Classification** | **CONFIRMED BUG** (current-scope: the case-evidence composition path) |
| **Patch decision** | PATCH (minimal, both defects) |
| **Files changed** | `app/incidents/service.py`, `app/pipeline/service.py`, `tests/integration/test_batch12_evidence_and_timestamps.py` (new), `tests/unit/test_phase52_owner_patches.py`, `tests/unit/test_capability_patch.py` |
| **Tests added/updated** | NEW `tests/integration/test_batch12_evidence_and_timestamps.py::TestT28CaseEvidence::test_threshold_exact_cluster_case_holds_full_evidence` (4 accepted events → case ⊇ 4 events + 4 detections + the correlation; timeline ≥ 4 events / ≥ 4 detections / ≥ 1 correlation) and `::test_two_clusters_do_not_contaminate_each_others_case` (two clusters in one window → disjoint case evidence, no cross-references) |
| **Validation result** | 15/15 new Batch-1/2 tests pass; full regression + live runs in the sections below |

**Root cause.** Two defects on the same composition path.

**(D1 create path)** `IncidentService.create_case_for_correlation` composed the
case from *only* the triggering `events=[event]` / `detections=[…]` and never
absorbed the correlation row's own evidence catalogue (`event_ids` /
`detection_ids`). The *reuse* path has done so since the V2-02 fix, so a cluster
that *exactly* meets the threshold (`DEFAULT_BRUTEFORCE_THRESHOLD = 4`,
`app/correlation/patterns.py`) — i.e. one whose case is created on its last event
and never re-visited — stayed frozen at 1 event + 1 detection.

**(D2 contamination)** `LivePipeline.process` (`app/pipeline/service.py`) opened
a case for **every** correlation in the engine result while handing each of them
the *current* event and its detections:
`for corr in correlations: self._open_case_for_correlation(persisted_event, corr, new_detections)`.
The engine result contains every cluster active in the 5-minute window, so
unrelated clusters' cases absorbed foreign evidence. Reproduced live:
`case-76ba8f7c…` (T22 cluster, `corr-d69bfd46`) ended with **18** detections =
its own 10 + 4 from `corr-28d0ca3d` + 4 from `corr-7a0c0096`; `case-71899a20…`
held 8 = its own 4 + 4 from the second cluster; the same detection id appeared
in two different cases' evidence (which is also why the live UI linked
`DET-000032` to `CASE-000003` while the backend listed it under `CASE-000005`).

#### Patch detail (D1) — `app/incidents/service.py`

`IncidentService.create_case` gained two optional, id-only evidence parameters
(`extra_event_ids`, `extra_detection_ids`); the ids are merged with
`_dedup_preserving_order` into the case's `IncidentEvidence`. On the create path
`create_case_for_correlation` now passes the correlation's own catalogue:

```python
extra_event_ids=tuple(getattr(correlation, "event_ids", ())),
extra_detection_ids=tuple(getattr(correlation, "detection_ids", ())),
```

Both paths (create and reuse) now compose the identical evidence set — the same
set the wire `case.create_from_correlation` handler already resolved, and the
set the reuse path has composed since the V2-02 fix. Detection/correlation
semantics are untouched: the correlation row remains the authoritative evidence
catalogue.

#### Patch detail (D2) — `app/pipeline/service.py`

```python
member_event_ids = tuple(getattr(correlation, "event_ids", ()) or ())
belongs = event.event_id in member_event_ids
return self._incident_service.create_case_for_correlation(
    identity=self._case_identity,
    correlation=correlation,
    events=[event] if belongs else [],
    detections=list(detections) if belongs else [],
)
```

Every correlation still opens (or reuses) its case — the automatic
correlation→case contract is unchanged — but an event's evidence only ever
enters the case of the cluster the event is a member of. With (D1) in place the
case of *every* cluster is complete from its own catalogue, so nothing is lost
for clusters that do not own the trigger event.

#### Behaviour consequence that had to be reconciled (documented, not hidden)

The wire flag `created` on `case.create_from_correlation` is derived as
`case.created_at == case.updated_at`. While the create path opened an
*incomplete* case, a re-run of the same correlation always had new evidence to
merge, so `updated_at` moved and the flag read `False`. Now the first call
already composes the complete evidence, so a re-run is a true no-op: same case
id, same evidence, **no mutation** (exactly what V2-02 requires — "a pure
re-delivery keeps the stored document untouched, preserving `updated_at`
stability"), and the timestamps stay equal so the heuristic reads `True`. Two
unit tests asserted that flag as a proxy for idempotency
(`test_phase52_owner_patches.py::TestCreateFromCorrelationOwnership::test_owner_can_still_reuse_its_own_case`,
`test_capability_patch.py::TestCapabilityWireOps::test_case_create_from_correlation_wire`);
they now assert the actual idempotency contract (stable case id, stable
evidence, no duplicate case) with the semantics documented inline. No handler
or API shape changed.

---
### T22 — Invalid / missing canonical `event_time` (CONFIRMED BUG)

| Field | Value |
|---|---|
| **ID** | T22 (invalid timestamp), retested on the canonical field `event_time` |
| **Source/Test** | Manual Batch 1 test T22 (recorded INCONCLUSIVE), re-investigated end-to-end |
| **Observed behaviour (pre-patch, live installed product)** | 14-variant matrix through the live ingress: malformed strings were refused, but `event_time: 1234567890` (int), `["…"]` (list), `null` and a payload with **no** canonical timestamp at all (only the non-canonical key `timestamp: "not-a-real-timestamp"` — the exact shape the manual test used) were **ACCEPTED** with `event_time` stamped from the server receive clock: every such row persisted `event_time == ingested_at` (e.g. `event_time=2026-09-27T13:08:18.852000+00:00 ingested_at=2026-09-27T13:08:18.853000+00:00`) |
| **Reproduction** | `python -m scripts.repro_batch12_live` (live `:8088` / `:8089`, DB `proshield`) — full matrix printed by the probe; see `batch12_live_after.txt` for the patched run |
| **Evidence** | Live read-back: `[ACCEPTED] wrong type (int) … event_time=…13:08:18.852000 ingested_at=…13:08:18.853000`; `[ACCEPTED] null …`; `[ACCEPTED] missing …`; `[ACCEPTED] T22 as reported (non-canonical 'timestamp' only) …` |
| **Classification** | **CONFIRMED BUG** (canonical-event truthfulness at the trusted ingress boundary) |
| **Root cause** | `app/sources/ingress.py::InboundIngressProxy._build_security_event_inner` parsed a *string* `event_time` (rejecting malformed values) but fell through to `et = datetime.now(timezone.utc)` for **every non-string value** — `None`, a number, a list, or a missing key. The canonical model declares `event_time` **required** and Phase 2 defines it as "when the *source says* the event occurred", explicitly distinct from `ingested_at` ("when ProShield received it") because the difference reveals source delay / network delay / buffering (`SECURITY_EVENT_SCHEMA` §5.2, §16; `CONTRACT_DECISIONS`). Stamping the receive clock fabricated the source's observation time, collapsed the two timestamps into one and made the fabricated value indistinguishable from a genuine observation. `event_type` (also required) is already refused when missing, so the fallback was an inconsistency, not a designed convenience |
| **Patch decision** | PATCH (minimal: the fallback is now the same documented per-event `validation_error` refusal the malformed-string path already used) |
| **Files changed** | `app/sources/ingress.py`; test fixtures that relied on the lenient fallback: `tests/unit/test_phase52_sources.py` (wire payload now carries the required canonical instant) |
| **Tests added/updated** | NEW `tests/integration/test_batch12_evidence_and_timestamps.py::TestT22EventTimeContract`: `test_valid_instants_are_accepted_and_normalised_to_utc` (parametrised over `Z`, `+00:00`, `+05:30` (IST offset), `-08:00` — all persist the *same* UTC instant), `test_non_timestamp_event_time_is_rejected_per_event` (invalid string / malformed / impossible date / int / list / null / missing), `test_non_canonical_timestamp_key_is_not_an_observation_time` (the literal manual shape), `test_future_dated_event_time_is_rejected` |
| **Validation result** | post-patch live matrix: all 4 valid variants accepted and normalised to one UTC instant; naive accepted as UTC; every non-timestamp and the `timestamp`-only payload **refused** with `validation_error`; 15/15 new tests pass; suite in *Full Regression Results* |

**Deliberately unchanged (documented interpretation, not a defect).**
A timestamp *string* that carries no UTC offset (e.g. `2026-09-27T13:14:21`) is
still interpreted as UTC. The canonical contract requires the stored value to
carry a timezone — which the ingress now guarantees by normalising — and the
receive-time ordering guard refuses an offset-less value that would land more
than 60 s in the future (proved by `test_future_dated_event_time_is_rejected`).
Refusing offset-less senders outright would change the ingest contract for
legitimate producers, so it is recorded as a residual rather than patched.

**Not patched from the earlier T22 attempt.** The original manual test sent the
non-canonical key `timestamp` (not `event_time`). ProShield correctly ignores
unknown keys; the defect was never "the ignored key", it was the fabricated
`event_time` that the missing canonical field produced — which is what the patch
now refuses (the same payload is rejected with
`event_time missing or not a timestamp`).

---

### Finding 1 — "Old connector artifact" (`app/connectors/**`) — LEGACY / COMPATIBILITY CODE

| Field | Value |
|---|---|
| **ID** | `B12-LEGACY-01` |
| **Observed behaviour** | `app/connectors/` (connector ABC, `NginxConnector`, `SimulatedConnector`, nginx parser/mapping) is the Phase-4.1–4.5 pull-connector layer, i.e. the pre-`SourceInstance` architecture |
| **Investigation (real imports / runtime construction / API / NGINX)** | (1) **Imports:** the *only* backend importer is `app/ingestion/service.py`, which imports `SecurityEventConnector`, `SimulatedConnector`, `NginxConnector` to build the module-level `CONNECTOR_REGISTRY` dict — a name→class catalogue. (2) **Runtime construction:** `NginxConnector(...)` / `CONNECTOR_REGISTRY` are constructed **only** by tests, demo scripts (`demo_phase47/48`, `live_smoke`, `demo_security_workflow`) and `DetectionPipeline.run_from_connector` (never called by either live plane); the live ingest path is `InboundIngressProxy._build_security_event` (wire payload + registered `SourceInstance` → canonical event → `SecurityEventIngestionService.ingest`). (3) **No API**: no wire operation constructs or names a connector; `source.register` validates a `source_type` against the `SourceType` enum, never a connector class. (4) **Not required** for source registration, validation, ingestion or NGINX runtime: the NGINX-specific config in the connector is a local `log_path` (file-tail pull), while the shipped source contract is `connection_type` + `endpoint` (push) — `log_path` appears **only** in `app/connectors/nginx/*` and demo scripts, never in `app/sources/**`, `scripts/*_server.py`, `deploy/**`, `service/**` or the frontend. (5) **Frontend:** zero references (`frontend/**` never mentions `connectors`, `log_path` or `CONNECTOR_REGISTRY`). (6) **NGINX ingestion today is push:** an NGINX exporter/sidecar POSTs to `:8089` with a source-identity token → canonical event → detection → correlation → case (proved end-to-end, see *Live Pipeline Results*) |
| **Classification** | **LEGACY / DEAD-ON-THE-LIVE-PATH ARTIFACT** (compatibility code kept for the Phase-4 test/demo surface; already documented as such in `docs/PHASE 4/PROSHIELD-DEEPTEST-ISSUES-V2.md`, "What Add Source actually is") |
| **Patch decision** | **NO PATCH.** Removal is outside this patch's scope (Batch 1/2 defects only) and the package is still imported by product code (the ingestion service's registry) plus the shipped test/demo suite, so deleting it would be an unproven, unrelated refactor. Recorded as legacy with the evidence above |
| **T04-ARCH-02 / -03 consequence** | The NGINX connector has **no runtime construction path in the live architecture** (T04-ARCH-02), and the `connection_type`+`endpoint` vs `log_path` difference (T04-ARCH-03) is a *legacy-vs-current contract* difference with **no runtime resolution of `log_path` anywhere** — it therefore cannot cause incorrect behaviour and is not patched |
| **UI check (no legacy mechanism is called)** | Built bundle scan (`frontend/soc/index.html`): **`CONNECTOR_REGISTRY` 0 occurrences, `log_path` 0 occurrences**, and 27 occurrences of the *word* "connector" that are all truthful labels or backend-served fields (e.g. `supported_connector_types` from `source.list`, "live connector family (nginx)" on the capability Health tab, "connector (source_type)" on a source). No current UI surface calls, constructs or configures the legacy connector mechanism |

### Finding 2 — Capability / Source / Rule UI semantics — EXPECTED (verified live)

| Field | Value |
|---|---|
| **ID** | `B12-CAP-01` |
| **Observed behaviour** | The UI must render `Capability → Sources` and `Capability → Rules` and must never imply that a capability-owned rule belongs to a single source instance |
| **Investigation** | Live browser (patched stack, DB `proshield_batch12_live`): Capabilities page shows `cap-nginx · CAP-000001`, `active`, `Sources: 1`, `5 rules · 1 patterns`, `Impl: nginx`; planned families show `Sources: 0`, `0 rules · 0 patterns`, `planned · no live impl`. Sources page shows `SRC-000001 … NGINX Access & Security Gateway [cap-nginx v1]` with a server-authoritative binding panel (`capability_id cap-nginx`, `capability_version 1`, `mapping_profile_id nginx-access-default`, `binding_status bound`, `capability_bound_at …`) and separate ingest counters. Rules own `rule.capability_id` (served by `rule.list`/`rule.get`), never a source instance. Backend contract in the same run: `source.register` refuses an unknown capability (`400`, no invented owner) and the ingress derives `capability_id` from the authenticated source (never from the payload) |
| **Classification** | **EXPECTED (truthful, server-authoritative)** |
| **Patch decision** | NO PATCH |

### Finding 3 — Capabilities UI phase wording — CONFIRMED (presentation) → PATCHED

| Field | Value |
|---|---|
| **ID** | `B12-UI-LABEL-01` |
| **Observed behaviour** | The Capabilities header carried the badge `Phase 5.1 live`, and the Health tab said "…capability→source binding **ships in Phase 5.2**" — in a shipped 1.0.3 product in which 5.2 binding is already live (proved by the Sources page above) |
| **Reproduction** | Live installed product (pre-patch): header badge `Phase 5.1 live`; live patched stack (post-patch): `live registry` |
| **Classification** | **CONFIRMED (presentation/truthfulness defect, current scope)** — it presents an internal roadmap phase as the product's status, and one sentence describes a *shipped* feature as future work |
| **Patch decision** | PATCH (presentation only): badge → `live registry`; Health-tab sentence → "Runtime connector health is reported per source instance (see Sources); a capability owns the implementation, its source instances own the runtime state." |
| **Files changed** | `frontend/src_upgraded_gemini/src/components/pages/CapabilitiesPage.tsx` (+ rebuilt `frontend/soc/index.html`) |
| **Validation** | `npm run typecheck` clean; `npm run build` OK; live browser shows `6 from backend` + `live registry` and no `Phase 5.1` text |
| **Residual (not patched)** | The *seeded* planned-capability descriptions still read "…no connector implementation ships in 5.1." Those strings are persisted data created by the capability seed (`app/capabilities/seeds.py`, create-missing-only); they are truthful in substance and rewriting persisted seed copy is outside a minimal Batch-1/2 patch |




### Finding 4 — Timestamp display: **IST is a CURRENT requirement** — CONFIRMED BUG → PATCHED / VERIFIED

| Field | Value |
|---|---|
| **ID** | `B12-TIME-01` |
| **Observed behaviour** | All user-visible timestamps are UTC-native: `format.ts` renders `… UTC` suffixes (`Last Seen 13:44:22 UTC`), and ISO surfaces render offset-carrying values (`2026-09-27T13:43:42+00:00` in the case timeline, `2026-09-27T13:44:22.624000+00:00` on detections) |
| **Investigation** | Searched every UI surface (overview, cases, case detail, detections, correlations, timeline, sources, rules, capabilities, health, reports, notifications) and every spec (`docs/**` for IST / local time / timezone / localized display). **No document requires local (IST) presentation**; the frontend's own documented contract is "All rendering is UTC to match the backend's UTC-native timestamps" (`frontend/src_upgraded_gemini/src/utils/format.ts`), and the canonical model stores UTC (`_timestamps_must_be_utc`). Live check: the values displayed for the probe cluster match the stored canonical `event_time` / `detected_at` instants exactly (no shift, no rewriting of stored data) |
| **Classification** | **CONFIRMED BUG (current requirement: user-facing timestamps must display in IST, UTC+05:30)** — the UI was UTC-only, so the requirement was unmet |
| **Patch decision** | PATCH (display only). Canonical storage, `event_time` semantics and every wire value are unchanged |

#### Patch detail (Finding 4 / `B12-TIME-01`)

`frontend/src_upgraded_gemini/src/utils/format.ts` now exposes timezone-aware IST
helpers built on `Intl.DateTimeFormat(..., { timeZone: 'Asia/Kolkata',
hourCycle: 'h23' })` + `formatToParts` — **no manual +05:30 arithmetic on
strings**, so calendar roll-over, offset-carrying inputs and midnight are all
handled by the engine:

* `formatIstDate` / `formatIstTime` / `formatIstDateTime` (`… IST`),
* `formatIstTimestamp` → `YYYY-MM-DD HH:MM:SS.mmm IST` (millisecond precision
  preserved for the forensic surfaces that previously showed the raw ISO value),
* `formatIstHourMinute` for hour-bucket labels,
* the UTC helpers are retained for canonical/technical views.

Wired surfaces (11 components): Cases list (`Last Activity`), Case detail
(`First Seen` / `Last Seen`, timeline rows, detection rows, analyst notes,
payload-drawer subtitle), Timeline page, Detections page, Sources page (`Last
event`, audit rows), Health page (`Tested:`), Capabilities page
(`created` / `last updated` / `retired at`), Overview page (hour buckets +
`Peak … at 19:30 IST`), Top bar notifications, Report modal, Attack-graph
`First/Last Match`. The forensic **payload drawer** keeps the stored canonical
values verbatim (localising evidence would make it differ from MongoDB) — that
is deliberate and asserted by a test.

#### Second defect found on the same path — offset-less canonical values read as host-local

`app/persistence/telemetry.py` serialises the source-telemetry recency field
with `isoformat()` on a **naive** BSON date, so the wire carries
`"2026-09-27T15:08:15.491000"` (no offset). JavaScript parses an offset-less
date-time as **host-local**, so the Health page rendered
`Tested: 2026-09-27 15:08:15.491 IST` — the UTC wall clock relabelled, 5 h 30 m
away from the true instant. The canonical contract is that persisted timestamps
are UTC, so `parse()` now normalises an offset-less ISO date-time to UTC before
parsing (single, minimal change at the one place every helper parses through).
Re-verified live after the rebuild: `Tested: 2026-09-27 20:38:15.491 IST`
(`screenshots/ist-health-tested.png`).

#### Live proof (all values compared against canonical MongoDB values converted by an independent implementation, `zoneinfo`, in `scripts/_ist_live_probe.py`)

| Surface | Canonical (MongoDB, UTC) | Rendered by the patched UI |
|---|---|---|
| Cases list `Last Activity` (CASE-000002) | `2026-09-27 15:08:15.660` | `20:38:15 IST` + `2026-09-27` |
| Case detail `First Seen` / `Last Seen` | `15:08:15.660` / `15:08:15.660` | `20:38:15 IST` / `20:38:15 IST` |
| Timeline event rows (×4) | `15:07:35…38.000` | `20:37:35.000 / 20:37:36.000 / 20:37:37.000 / 20:37:38.000 IST` |
| Timeline detection rows (×4) | `15:08:15.494 / .530 / .567 / .620` | `20:38:15.494 / .530 / .567 / .620 IST` (ms-exact) |
| Timeline correlation row | `window_start 15:08:15.494` (documented: correlation items use `window_start`) | `20:38:15.494 IST` |
| Detections tab (DET-000006…9) | `15:08:15.494 / .530 / .567 / .620` | `2026-09-27 20:38:15.494 / .530 / .567 / .620 IST` |
| Sources `Last event` | `15:08:15.491` (offset-less) | `2026-09-27 20:38:15.491 IST` |
| Health `Tested:` (source row) | `15:08:15.491` (offset-less) | `2026-09-27 20:38:15.491 IST` (was `15:08:15.491 IST` pre-fix) |
| Capability Health tab `created`/`last updated` | `14:59:47.165` | `2026-09-27 20:29:47.165 IST` |
| Overview buckets / `Peak` | backend UTC hour starts | `13:30 … 20:30 IST`, `Peak: 9 signals/hr at 20:30 IST` |

Audit points 1–10 of the requirement: stored MongoDB values stay UTC (verified by
direct reads of `security_events`, `detections`, `correlations`, `incidents`,
`capabilities`); wire values stay canonical; conversion is timezone-aware (no
string arithmetic); seconds/ms preserved; midnight roll-over correct
(`18:29:59Z → 23:59:59 IST`, `18:30:00Z → 00:00:00 IST`, no `24:00`);
offset-carrying inputs (`+05:30`, `-08:00`, `Z`) convert to the identical
instant; `event_time` and `ingested_at` remain distinct; every displayed value
re-parses (in Python) to the exact stored instant.

### Finding 5 — Retire / archive behaviour — EXPECTED (soft delete) + FUTURE-PHASE GAP (Evidence Archive)

| Field | Value |
|---|---|
| **ID** | `B12-RETIRE-01` |
| **Observed behaviour** | Retiring an object changes its persistence state, but the retired object remains visible in the operational UI |

### Finding 6 / T04-FE-01 — Frontend stale state — CONFIRMED (read-path gap) → PATCHED

| Field | Value |
|---|---|
| **ID** | `B12-UI-STALE-01` (T04-FE-01) |
| **Observed behaviour** | Backend state changed by another actor (ingress ingestion / the pipeline) was not visible in an already-open analyst session; the testers reported needing a logout/login or a restart |
| **Reproduction** | Live: with the SPA session open (data loaded at login → 2 cases), a 4-event cluster was ingested through the real ingress listener, so the backend held a 3rd case. SPA-navigating to *Incidents/Cases* kept the sidebar badge at **"2"** and listed no `203.0.113.151` row (stale React state; no refetch on navigation). A **browser reload** re-read everything correctly — the state is never fabricated, it is simply not re-read on demand; two pages (Capabilities, Timeline) even ship their own Reload button while the rest do not |
| **Cause** | Missing refetch trigger (read path): `SocContext.refreshAll()` runs at boot and after the app's *own* mutations only. **Not** API caching (POST), **not** a proxy cache, **not** a backend in-memory registry (Mongo is authoritative and answers every read correctly — verified by fetching `/api/proxy` from the page itself while the UI was stale) |
| **Classification** | **CONFIRMED (current-scope UI defect: an open session cannot reach authoritative state without a full reload)** |
| **Patch decision** | PATCH (minimal, additive): a top-bar **Reload** control wired to the existing `refreshAll()` (spinner while in flight, honest toast "Reloaded from backend"). No polling/auto-refresh was invented and no local state is faked |
| **Files changed** | `frontend/src_upgraded_gemini/src/components/layout/TopBar.tsx` (+ rebuilt `frontend/soc/index.html`) |
| **Validation** | Live browser: (before) badge stayed `2`, new case absent; (after one click) badge `3` and the new case `CASE-000003 · 203.0.113.151 · /probe/t28-83cc54 · 4e 4d 1c` appeared, matching the backend exactly (screenshot `batch12_after_reload_case_appears.png`) |

### Finding 7 — T04 (ingress / source architecture) — EXPECTED (verified live)

| Field | Value |
|---|---|
| **ID** | T04 / `B12-T04-*` |
| **Observed behaviour** | 8089 is the live ingress plane; an unauthenticated `source.ingest` returns 401; the NGINX connector is registered but has no runtime construction path |
| **Investigation (live)** | `analyst /health → 200 {"status":"ok","backend_kind":"mongo"}`; `ingress /api/ingress/health → 200 {"ok":true,… "supported_operations":["source.health","source.ingest"]}`; `POST /api/ingress {"operation":"source.ingest","events":[]}` with no token → **401** `source_identity_token_error` (identical pre- and post-patch); the ingress plane serves no frontend and the analyst plane never accepts raw telemetry. T04-ARCH-01 (operational vs evidence/archive separation) = future phase 5.6 (Finding 5); T04-ARCH-02/03 = legacy artifact (Finding 1) |
| **Classification** | **EXPECTED** (documented two-plane boundary), with the UI-refresh part tracked as Finding 6 |
| **Patch decision** | NO PATCH beyond Finding 6 |

| **Investigation** | (a) *Architecture contract:* source lifecycle `REGISTERED→CONFIGURED→VALIDATED→ENABLED⇄DISABLED→RETIRED`, where "`retire` is the soft-delete boundary that **preserves every historical record**" (`app/sources/models.py`); capabilities/rules have the same retire/archive semantics. (b) *Implementation + live:* retiring `SRC-000002` in the browser flipped the card to `RETIRED` / `lifecycle: retired`, disabled token issuance and rotation and displayed "RETIRED – credentials can no longer be issued or rotated. Historical provenance is preserved."; retired-source ingest returns **410** and token issuance **409** (proved by `scripts.verify_phase52_pipeline.py` 51/51, including "historical events/capability provenance preserved after retire"); the retired state survived a **service restart** (re-checked in the browser). (c) *Phase scope:* the analyst-context-preserving **Evidence Archive** is its own future phase — "PHASE 5.6 — SECURITY EVIDENCE ARCHIVE" (`docs/PHASE 5(V3)/PHASE-05-V3-IMPLEMENTATION-MASTER-PLAN.md` §23: new `security_evidence` collection + promotion/quality services + `evidence.*` ops) |
| **Classification** | Current behaviour = **EXPECTED** (truthful soft delete with preserved history; the retired state is displayed, not hidden). "Retired objects must leave operational views into a separate Evidence Archive" = **FUTURE-PHASE GAP** (5.6), not a Batch-1/2 defect |
| **Patch decision** | NO PATCH (implementing the archive is explicitly out of scope) |

---

## Confirmed Defects

| ID | Defect | Root cause (proven) | Fixed in |
|---|---|---|---|
| `B12-T28-D1` | Case opened for a threshold-exact cluster held only 1 event + 1 detection | `create_case_for_correlation` composed evidence from the trigger event only; the create path never absorbed the correlation's own catalogue | `app/incidents/service.py` |
| `B12-T28-D2` | Cross-cluster evidence contamination (one detection id inside two cases) | `LivePipeline.process` handed the current event/detections to **every** correlation in the engine window | `app/pipeline/service.py` |
| `B12-T22-01` | `event_time` fabricated from the server clock for missing/null/wrongly-typed values (and for the non-canonical `timestamp` payload) | ingress validation treated a non-timestamp as "missing" and stamped the receive clock | `app/sources/ingress.py` |
| `B12-TIME-01` | UI timestamps were UTC-only (the current IST requirement was unmet) | `utils/format.ts` rendered UTC parts and labelled surfaces `UTC` | `frontend/.../utils/format.ts` + 11 components (+ rebuilt bundle) |
| `B12-TIME-02` | Offset-less canonical values rendered 5 h 30 m off, labelled IST | JS parses offset-less date-times as host-local; the backend telemetry view emits naive `isoformat()` | same file (single `parse()` normalisation) |
| `B12-UI-STALE-01` | An open SPA session could not reach authoritative backend state without a full reload | `refreshAll()` ran at boot / after the app's own mutations only; no user-reachable refetch in the shell | `frontend/.../layout/TopBar.tsx` (Reload control) |
| `B12-UI-LABEL-01` | Capability page showed stale internal phase wording (`Phase 5.1 live`, "ships in Phase 5.2") | hard-coded roadmap copy in the React page | `frontend/.../pages/CapabilitiesPage.tsx` |

No item was patched without a reproduction, and no reproduction was patched that
this register does not list.

## Patched and Verified

| Patch | Focused tests | Full regression | Live pipeline | Live browser |
|---|---|---|---|---|
| T28 D1 + D2 | `tests/integration/test_batch12_evidence_and_timestamps.py` (T28 classes) | green | `verify_phase52_pipeline` **51/51**; `repro_batch12_live` → case **4/4/1** | `4e 4d 1c`, `Timeline (9)`, `Detections (4)`, `Correlations (1)` |
| T22 | same file (T22 matrix) | green | 14-variant live matrix — every refusal `validation_error`, valid forms normalise to one UTC instant | — (wire level) |
| IST display (T1 + T2) | `test_batch12_ist_display.py` — **22 tests** | green | probe + shipped pipeline | ms-exact on Cases / Case detail / Timeline / Detections / Sources / Health / Capabilities / Overview; 4 screenshots |
| Stale state | `tests/unit/test_frontend_ui_regression.py` + build | green | — | badge `2` → **Reload** → `3`; survives browser reload and service restart |
| Phase wording | static assertions + typecheck | green | — | header `6 from backend` + `live registry` |

## Expected / Non-Defects

| Item | Why it is not a defect |
|---|---|
| Capability → Source → Rule presentation | Server-authoritative and truthful: a capability owns rules/patterns, each source instance owns its runtime state. Live: `cap-nginx` (1 source, 5 rules, 1 pattern), `cap-simulator` (0 sources), 4 planned families; the Health tab states the ownership contract explicitly |
| Retired objects still visible in operational views | Documented lifecycle is soft delete with preserved history; retired sources refuse ingest (**410**) and token issuance (**409**) |
| Correlation timeline item timestamp | The engine documents that correlation items are placed at `window_start` (not `correlated_at`); the rendered value matches `window_start` exactly |
| Payload drawer showing canonical UTC values | It is the immutable evidence/technical view; localising it would make it disagree with MongoDB (asserted by test) |
| `app/connectors/**` | No live construction path, no active API, no frontend reference (bundle scan), not required by registration/validation/ingestion/NGINX runtime |
| Legacy `frontend/index.html` + `frontend/js/**` shell | Not packaged (install dir holds only `frontend/login.html` + `frontend/soc/index.html`); live `/static/index.html` → **404**; the React bundle is the authoritative UI |
| `verify_windows_stack` "case opened automatically - 0 case(s)" | Harness expectation mismatch — cases are pipeline-owned and `case.list` is ownership-scoped (admin 5 / analyst 0), identical before and after the patch |
| Planned-capability seed copy "ships in 5.1" | Persisted registry data for *planned* families (no implementation); truthful in substance → deferred polish (**D-D**) |
## Inconclusive Findings

| Item | Status |
|---|---|
| T01–T03, T05–T21, T23–T27, T29, T30 | **ORIGINAL TEST RECORD UNAVAILABLE — NOT RECONSTRUCTED** (record files absent from the working tree). No result invented |
| Notifications timestamp surface (live) | Render path patched and statically asserted (`TopBar.tsx` uses `formatIstTimestamp`), but the fresh verification database held **0** notifications, so no live row existed to compare. Not a defect — coverage gap recorded (**D-E**) |
| T22 "invalid timestamp" as originally recorded | The original test used the non-canonical key `timestamp`; re-tested on the canonical `event_time` (now a confirmed, patched defect). The original phrasing is superseded, never patched from |

## Future-Phase Gaps

| Item | Evidence | Left untouched because |
|---|---|---|
| Evidence Archive — retired/archived objects leave operational views; evidence promotion/quality | Master plan §23 "PHASE 5.6 — SECURITY EVIDENCE ARCHIVE": new `security_evidence` collection, promotion/quality services, `evidence.*` ops | Implementing a future phase as a Batch-1/2 patch is explicitly forbidden |
| T04-ARCH-01 operational vs evidence separation | same phase | same |
| Phase-gated automatic/live UI synchronization | no roadmap commitment found | not a defect; recorded as improvement **D-B** |

## Legacy / Deferred Retirement

| Artifact | Why it is legacy | Why it is not deleted here |
|---|---|---|
| `app/connectors/**` (`NginxConnector`, `connection_type`/`endpoint` vs `log_path`) | The live architecture is Capability → Source instances → capability-owned rules. The connector layer has **no runtime construction path**: no export path from the API handlers, not referenced by source registration/validation/ingestion, not used by the NGINX path (which runs through `SourceInstance` + the ingress plane), and the built UI never calls it (`CONNECTOR_REGISTRY` 0 / `log_path` 0 occurrences in `frontend/soc/index.html`) | Removal needs its own dependency/runtime-retirement proof — a separate architectural decision (register **D-A**); deleting on sight is what the brief forbids |
| `frontend/index.html` + `frontend/js/**` (vanilla shell) | Superseded by the React single-file bundle; not packaged by the installer; live 404 | Cosmetic cleanup outside the defect-patch scope (register **D-F**) |
| `desktop/status.html` `toLocaleTimeString()` | Local desktop-shell clock label, not a security timestamp | Out of scope; recorded for completeness |

## Deferred / Future Improvements Register

| ID | Area | Current classification | Current behaviour | Why not patched now | Desired future behaviour | Target phase (roadmap) | Risk / impact | Trigger to revisit |
|---|---|---|---|---|---|---|---|---|
| **D-A** | Architecture — legacy connector retirement | LEGACY / DEAD ARTIFACT | Layer present, unused on the live path | Needs a separate dependency/runtime-retirement proof; not a Batch-1/2 defect | Delete with proof, or document explicitly as a compatibility shim | not scheduled | low today (dead code); medium if it silently drifts | an authorised architecture-cleanup task |
| **D-B** | UI — automatic / live synchronization (polling, SSE, WebSocket) | FUTURE IMPROVEMENT | Explicit **Reload** (validated in this task) is the only refresh mechanism | The brief forbids implementing automatic sync here | Views that update without a manual reload | not scheduled | low–medium (an analyst may read stale state until Reload) | operators request live views / an auto-refresh contract is defined |
| **D-C** | Evidence Archive separation | FUTURE-PHASE GAP | Soft delete; retired objects stay in operational views with truthful state | Phase 5.6 feature, explicitly out of scope | Retired/archived objects move to the Evidence Archive with promotion semantics | **Phase 5.6** (master plan §23) | medium (operational noise) | when Phase 5.6 starts |
| **D-D** | Capability registry copy ("no connector implementation ships in 5.1") | PRESENTATION POLISH | Persisted seed copy shown for *planned* families | Changing persisted registry data needs a migration; the substance is truthful | Phase-neutral wording ("no live implementation") | with the next registry/seed revision | very low | next capability-seed revision |
| **D-E** | Verification coverage — notifications / reports timestamp surfaces | TEST COVERAGE GAP | Patched + statically asserted; no live data existed in the verification DB | Nothing to fix; simply no notification was produced | A scenario that persists a notification before comparing | next regression cycle | very low | next Batch testing round |
| **D-F** | Repo hygiene — legacy vanilla shell (`frontend/index.html`, `frontend/js/**`) | LEGACY / DEAD ARTIFACT | Not served by the installed product | Cosmetic cleanup outside the defect-patch scope | Remove or archive the shell | not scheduled | very low | next repo-hygiene task |
| **D-G** | Harness expectations — `test_phase48_remediation.py`, `verify_windows_stack.py` | **TEST / ENVIRONMENT ERROR → RESOLVED in the harness (see "Harness Fixes")** | All three defects fixed in test/tooling code; product untouched | — | — | — | FIXED (this task) | closed |
<!--D-H-->

> **UTC → IST is deliberately absent from this register:** IST display is a
> *current* requirement and was patched and verified in this task (Finding 4).

<!--B-->

## Focused Test Results

| Command | Result |
|---|---|
| `python -m pytest tests/unit -q` (pre-patch baseline) | 1578 passed, 5 failed — all five traced to the intended contract change (2 tests asserted the old incomplete-evidence / idempotency-flag proxy; 3 fixture payloads omitted the now-required canonical `event_time`) |
| `python -m pytest tests/unit -q` (post-patch) | **all green** |
| `python -m pytest tests/integration/test_batch12_evidence_and_timestamps.py -q` (NEW, real Mongo) | **15 passed** in 6.36 s — T28 completeness, T28 cross-cluster contamination guard, T22 matrix (parametrised offsets + every refusal case) |
| `python -m scripts.repro_batch12_live --skip-t22` (live installed product, pre-patch) | T28 defect reproduced: case `1e/1d/1c`, timeline 3 items, wire `case.get` 1/1/1 |
| `python -m scripts.repro_batch12_live` (live patched stack `:8188`/`:8189`, DB `proshield_batch12_live`) | T22 matrix correct (Finding T22); T28 **CASE EVIDENCE COMPLETE: True**, timeline **9 items {event 4, detection 4, correlation 1}**, wire `case.get` **4/4/1** |
| `python -m pytest tests/integration/test_batch12_ist_display.py -q` (**NEW**) | **22 passed** in ~1.5 s — IST conversions for known UTC instants (midnight roll-over, offsets, ms, microseconds), invalid-input passthrough, instant-identity re-parse, offset-less-as-UTC, source-wiring sweep, built-bundle check |
| `python -m pytest tests/unit tests/integration/test_batch12_evidence_and_timestamps.py tests/integration/test_batch12_ist_display.py -q` (focused, patched tree) | **1617 passed** |
| `python -m scripts.repro_batch12_live --analyst :8188 --ingress :8189 --db proshield_ist_verify` (final live run) | T04 auth boundary 401; T22 all refusals correct; T28 **4e/4d/1c**, timeline 9, wire 4/4/1 |
| `npm run typecheck` / `npm run build` (after the IST patch) | **clean** / **OK** — `frontend/soc/index.html` `1,202.75 kB` |

## Full Regression Results

| Suite | Command | Result |
|---|---|---|
| Unit + integration (complete) | `python -m pytest -q` (final run, patched tree incl. the new IST suite **and the HF-1 harness fix**) | **1746 passed, 0 failed** (95.8 s) |
| Previously failing test (now green) | `tests/integration/test_phase48_remediation.py::test_post_review_full_idor_and_unfiltered_list` | **PASS** — the `KeyError: 'PROSHIELD_MONGO_URI'` was a harness defect (HF-1) and is fixed; see **Harness Fixes** |
| Fresh-database tests | `tests/integration/test_v2_patch_revalidation.py`, `test_phase51_capabilities_mongo.py`, `test_phase52_sources_mongo.py`, `tests/integration/test_batch12_evidence_and_timestamps.py` (each drops/recreates its own DB) | green |
| Live HTTP boundary tests | `tests/integration/test_strix_ingress_wire.py`, `test_v2_patch_revalidation.py`, `test_batch12_evidence_and_timestamps.py` (shipped FastAPI apps + real Mongo) | green |
| Source auth/trust, lifecycle, adversarial | `tests/unit/test_phase49_trust.py`, `test_phase49_ingress.py`, `test_phase52_*.py`, `tests/integration/test_phase49b_remediation.py` | green (replay / tamper / mismatch / state / rate-limit refusals unchanged) |
| Detection / correlation / case / timeline / restart | `tests/unit/test_detection_*`, `test_correlation_*`, `test_timeline_*`, `test_phase48_*`, `tests/integration/test_phase45…410_*`, `test_phase51/52_*_mongo.py` | green |
| Frontend typecheck | `npm run typecheck` (`frontend/src_upgraded_gemini`) | **clean** (`tsc --noEmit`, no output) — run before and after the IST patch |
| Frontend production build | `npm run build` | **OK** — 72 modules, `frontend/soc/index.html` regenerated (`1,202.75 kB`; the IST code is present in the served bundle — verified by HTTP fetch: `HAS_IST=True`) |
| IST display regression | `tests/integration/test_batch12_ist_display.py` | **22 passed** (real `format.ts` bundled with esbuild and executed in Node) |
| Playwright / Chromium | live browser session against the **patched repo stack** (`:8188`) — see next section | green |
| Windows runtime / deployment | packaged supervisor stack (`verify_windows_stack --start-console`) | same profile as before the patch (see Live Pipeline §C) |



## Live Pipeline Results

**A. Shipped chained live verification (patched code, fresh DB).**
`python -m scripts.verify_phase52_pipeline.py` → **51/51 checks passed**: source registration with server-derived capability binding (`cap-nginx`, `nginx-access-default`), configure/validate/enable, per-source credential, ingress token authentication, canonical event stamped with `capability_id`/`source_instance_id`, a forged payload `capability_id` ignored, no cross-source impersonation, replay/tamper 401, a 4-event burst producing `NGINX-AUTH-FAILURE-001` detections with provenance, benign telemetry producing **no** detection, correlation with derived `capability_ids`, **a case opened**, capability lineage on the case, disabled/retired source → token issuance 409 / ingest **410**, and historical provenance preserved after retirement.

**B. Live end-to-end pipeline on the patched repo stack (real HTTP + Mongo).**
`scripts/repro_batch12_live.py` against `:8188`/`:8189`, DB `proshield_batch12_live`:

1. unauthenticated `source.ingest` → **401**;
2. `source.register` → `configure` → `validate` → `enable` → `issue_token` → ingress accepts a 4-event batch (4 canonical events persisted);
3. detection: 4 × `NGINX-AUTH-FAILURE-001` v1, each carrying its `event_id`;
4. correlation: `corr-d8e114ca-1238-7344-a886-c39ccd35dd7e`, key `('203.0.113.96','/probe/t28-4c33b8')`, count 4, **4 detection ids / 4 event ids**;
5. case: `case-340a4990-615a-7d83-b5d7-895538d39c0c` with **4 events + 4 detections + 1 correlation** (complete);
6. timeline: **9 items {event 4, detection 4, correlation 1}**; wire `case.get` = 4/4/1; wire `timeline.build_for_incident` = 9 items;
7. attribution and timestamps verified on every record (source instance + derived capability, UTC instants).

**C. Packaged Windows runtime (supervisor console mode = the same code the SCM runs).**
`python -m scripts.verify_windows_stack --install-dir <repo> --data-dir <fresh> --analyst-port 8288 --ingress-port 8289 --start-console --dev-credentials --checks stack,gateway,desktop,workflow` → **26 passed, 0 failed** (before the harness fixes: 19 passed / 1 failed).
PASS: supervisor readiness; both planes' health; `/api/meta`; DB reachable behind auth; authoritative UI served (`SPA root=True`, defers to `/api/proxy`); desktop shell version/planes/UI-origin/no-DB-credentials; `auth.issue` admin+analyst; full source lifecycle; token issuance; capability registry; ingress accept (11 events); detection engine (35 detections, provenance retained); correlation (`NGINX-CORR-BRUTEFORCE-001`, count 8 for the burst key); **case opened automatically (admin, `case:read:any`) — 6 cases**; **pipeline-owned case is IDOR-hidden from an analyst session — HTTP 404**; `case.get`; timeline/evidence (24 items); explicit central correlation; analyst overview; plane separation.
The former FAIL (`case opened automatically - 0 case(s)`) was a harness defect (**HF-3**), fixed in the tool — **case authorization was not weakened**; it is now positively asserted instead.

**D. Installed-product checks.**
`python -m scripts.verify_windows_stack --data-dir C:\ProgramData\ProShield --checks stack,gateway,desktop` → **10 passed, 0 failed**;
`… --checks workflow` → **15 passed, 0 failed** (before the harness fix, this reported "no credentials found in proshield.env" — a harness defect **HF-2**, because on this layout `secrets/proshield.env` is ACL-restricted by design while the documented operator file `config/initial-credentials.txt` supplies the same credentials; that readable fallback is now used).


**E. Final live re-run after the IST patch (this task's closing verification).**
`python -m scripts.verify_phase52_pipeline.py` → **51/51 checks passed**
(same shipped chained contract as §A, executed against the patched tree).
`python -m scripts.repro_batch12_live --analyst http://127.0.0.1:8188
--ingress http://127.0.0.1:8189 --db proshield_ist_verify` → analyst `/health`
200; ingress health op 200 (`supported_operations=[source.health, source.ingest]`);
**unauthenticated `source.ingest` → 401**; T22 matrix (5 valid forms → one UTC
instant; 9 refusals with `validation_error`); T28 **4 events → 4 detections →
correlation 4/4 → case 4 events + 4 detections + 1 correlation → timeline 9
items → wire `case.get` 4/4/1 → wire timeline 9 items**;
`CASE EVIDENCE COMPLETE (4 events / all detections / correlation): True`.
`scripts/_ist_live_probe.py` then printed the canonical MongoDB instants and the
independently computed IST strings that the browser comparison used (Finding 4).

---

## Playwright / Live Browser Results

Real Chromium session (viewport 1440×900) driven against the **patched** stack at
`http://127.0.0.1:8188/static/soc/index.html` (fresh DB), with a matching
pre-patch session against the **installed product** at `:8088`.

| Workflow | Pre-patch (installed product) | Post-patch (repo stack) |
|---|---|---|
| Login (`auth.issue` via the LoginGate) | ✅ | ✅ (stale-session `401`s on first load, then a clean gate → login; expected fail-closed behaviour) |
| Cases list, threshold-exact cluster | row `CASE-000005 … 1e 1d 1c` | row `CASE-000002 … **4e 4d 1c**` (+ the T22 cluster case `5e 5d 1c`, i.e. **no foreign evidence**) |
| Case workspace | `Evidence Summary 1e • 1d • 1c`; tabs `Timeline (3)`, `Detections (0)`, `Correlations (1)` | `Evidence Summary **4e • 4d • 1c**`; tabs `Timeline (9)`, `**Detections (4)**`, `Correlations (1)` |
| Timeline / evidence | 3 items | `Chronological Evidence Chain (9 entries)`: 4 EVENT + 4 DETECTION + 1 CORRELATION, each with its real ids, rule id/version and UTC offsets |
| Capabilities view | header `Phase 5.1 live`; Health tab promised 5.2 binding | header `6 from backend` + **`live registry`**; no `Phase 5.1` text; `cap-nginx` shows `Sources: 1`, `5 rules · 1 patterns` |
| Source view / binding | bound source with capability panel | `SRC-000001 … [cap-nginx v1]`, `binding_status bound`, `mapping_profile_id nginx-access-default`, ingest counters |
| Source lifecycle | — | Retire → card `RETIRED` / `lifecycle: retired`, token issue/rotate disabled, "Historical provenance is preserved" |
| Refresh / stale state | (cause) in-session views did not refetch | **Reload** control present; with a new backend case created mid-session the badge stayed `2`, and after one click it became **`3`** with the new case visible (`4e 4d 1c`); re-verified after the IST rebuild (state refreshed, values unchanged) |
| Browser reload / service restart | reload re-reads authoritative state | after a browser reload (new bundle) the session was restored and every value re-read from the backend; after restarting both planes: cases intact, `SRC-000002` still `RETIRED` |
| **Timestamps — IST (Cases)** | `Last Activity` column read `… UTC` | `20:38:15 IST` + date `2026-09-27` for `CASE-000002` (`4e 4d 1c`), matching canonical `15:08:15.660 UTC` → IST |
| **Timestamps — IST (Case detail)** | `First Seen` / `Last Seen` `… UTC` | `20:38:15 IST` / `20:38:15 IST`; tabs `Timeline (9)`, `Detections (4)`, `Correlations (1)` |
| **Timestamps — IST (Timeline, ms)** | raw ISO offsets | `2026-09-27 20:37:35.000 … 20:37:38.000 IST` (4 EVENT), `20:38:15.494 / .530 / .567 / .620 IST` (4 DETECTION), `20:38:15.494 IST` (1 CORRELATION, = documented `window_start`) — ms-exact against Mongo |
| **Timestamps — IST (Detections tab)** | raw ISO | `DET-000009 … .620 IST`, `DET-000008 … .567 IST`, `DET-000007 … .530 IST`, `DET-000006 … .494 IST` |
| **Timestamps — IST (Sources)** | `Last event: <naive ISO>` | `Last event: 2026-09-27 20:38:15.491 IST` (offset-less canonical value → correct instant after the `parse()` fix) |
| **Timestamps — IST (Health)** | `Tested: 2026-09-27 15:08:15.491 IST` (wrong: UTC wall clock labelled IST) | `Tested: 2026-09-27 20:38:15.491 IST` **after the fix**; liveness/subsystem rows `20:42:55.xxx IST` |
| **Timestamps — IST (Capabilities)** | no timezone / raw ISO | `created: 2026-09-27 20:29:47.165 IST · last updated: … IST` |
| **Timestamps — IST (Overview)** | `at 14:00 UTC` | buckets `13:30 … 20:30 IST`, `Peak: 9 signals/hr at 20:30 IST` |
| Timestamps — canonical evidence | offset-carrying ISO | unchanged: the payload drawer still shows the stored canonical values verbatim |

Screenshots (in `docs/PHASE 5/MANUAL TESTS/screenshots/`):
`batch12_before_case_list_1e1d1c.png` (pre-patch, 1e/1d/1c),
`batch12_after_case_list_4e4d1c.png`, `batch12_after_case_detail.png`,
`batch12_after_case_workspace.png`, `batch12_after_reload_case_appears.png`,
`batch12-after-capabilities-live-registry.png`, and for the IST patch:
`ist-case-timeline-evidence.png`, `ist-cases-last-activity.png`,
`ist-sources-last-event.png`, `ist-health-tested.png`.

## Files Changed

Batch 1/2 patch hunks (each hunk carries a `Batch 1/2` comment so it is
identifiable inside the already-dirty files):

| File | Change |
|---|---|
| `app/incidents/service.py` | `create_case` gains optional id-only evidence parameters (`extra_event_ids`/`extra_detection_ids`, merged with `_dedup_preserving_order`); `create_case_for_correlation` passes the correlation's evidence catalogue on the **create** path (T28 D1) |
| `app/pipeline/service.py` | `_open_case_for_correlation` passes the trigger event/detections only to the correlation the event belongs to (T28 D2 — cross-cluster contamination) |
| `app/sources/ingress.py` | a missing/null/wrongly-typed canonical `event_time` is refused per event with the documented `validation_error` instead of being stamped from the server receive clock (T22) |
| `frontend/src_upgraded_gemini/src/components/layout/TopBar.tsx` | new top-bar **Reload** control wired to `refreshAll()` (Finding 6 / T04-FE-01) |
| `frontend/src_upgraded_gemini/src/components/pages/CapabilitiesPage.tsx` | badge `Phase 5.1 live` → `live registry`; Health-tab sentence no longer claims 5.2 binding is future work (Finding 3) |
| `frontend/soc/index.html` | rebuilt single-file bundle (72 modules, `1,202.75 kB`) served at `/static/soc/index.html`; carries the IST conversion (`HAS_IST=True` on the live HTTP fetch) |
| `frontend/src_upgraded_gemini/src/utils/format.ts` | **IST display layer** (B12-TIME-01): `formatIstDate/Time/DateTime/Timestamp/HourMinute` via `Intl.DateTimeFormat(..., {timeZone:'Asia/Kolkata', hourCycle:'h23'})` + `formatToParts`; UTC helpers retained for canonical views; `parse()` normalises an **offset-less** ISO date-time to UTC (B12-TIME-02) |
| `frontend/.../pages/IncidentsPage.tsx`, `CaseDetailPage.tsx`, `TimelinePage.tsx`, `DetectionsPage.tsx`, `SourcesPage.tsx`, `HealthPage.tsx`, `CapabilitiesPage.tsx`, `OverviewPage.tsx`, `frontend/.../layout/TopBar.tsx`, `frontend/.../investigation/ReportGeneratorModal.tsx`, `frontend/.../investigation/AttackGraphTopology.tsx` | IST wiring of every user-visible timestamp surface (import + render only; no data or sorting semantics changed — sorts still run on canonical ISO strings) |
| `tests/integration/test_batch12_evidence_and_timestamps.py` | **NEW** — 15 regression tests (T28 completeness, T28 contamination guard, T22 matrix) |
| `tests/integration/test_batch12_ist_display.py` | **NEW** — 22 regression tests for the IST requirement (real `format.ts` bundled with esbuild and executed in Node; known-instant conversions, midnight roll-over, offsets, ms/microseconds, invalid input, offset-less-as-UTC, instant identity, source-wiring sweep, built-bundle check) |
| `scripts/_ist_live_probe.py` | **NEW** — live verification probe: prints canonical MongoDB instants + independently computed (`zoneinfo`) IST strings for the browser comparison |
| `tests/unit/test_phase52_sources.py` | wire fixture carries the required canonical `event_time` (its payload previously relied on the removed fallback) |
| `tests/unit/test_phase52_owner_patches.py` | asserts the corrected evidence contract and the real idempotency contract |
| `tests/unit/test_capability_patch.py` | same, for the wire `case.create_from_correlation` test |
| `scripts/repro_batch12_live.py` | **NEW** — the live reproduction/verification probe used for T04/T22/T28 evidence |
| `docs/PHASE 5/MANUAL TESTS/BATCH 1,2 PATCH REPORT.md` + `screenshots/*.png` | this report and its browser evidence |
| `tests/integration/test_phase48_remediation.py` | **harness fix HF-1** — resolve `PROSHIELD_MONGO_URI` into a module constant at import time so the intentional root-`conftest.py` scrub cannot invalidate the test (scrub not weakened) |
| `scripts/verify_windows_stack.py` | **harness fixes HF-2/HF-3/HF-4** — documented credential-file fallback + truthful credential failure message + `creds.get()`; case workflow observed with the `case:read:any` session and a new positive IDOR assertion; `--analyst-port`/`--ingress-port` persisted into `proshield.json` before starting the supervisor |
| Root-level investigation scripts | removed: `_acl_cred_probe.py`, `_report_index.py`, `_run_tests_wmi.ps1`, `_run_winverify_wmi.ps1`, `_boot_smoke_stack.ps1` and temporary output files |

> The three backend files were *already* modified in this working tree before this
> task (`git status` shows them as `M` for the pre-existing capability / 5.1 / 5.2
> work); only the hunks described above were added by this patch, and each is
> annotated with a `Batch 1/2` comment.

## Files Intentionally NOT Changed

| File / area | Why |
|---|---|
| `app/connectors/**` (legacy connector layer) | legacy / dead-on-the-live-path artifact; still imported by the ingestion service's registry and used by the shipped test/demo suite → removal would be an unproven, unrelated refactor |
| `app/capabilities/seeds.py` and the persisted capability rows | seeded phase wording is truthful in substance; rewriting persisted registry copy is not a minimal Batch-1/2 fix (register **D-D**) |
| `app/persistence/**` (schemas, validators, indexes) | no schema change was required |
| `app/correlation/**`, `app/detection/**`, `app/rules/**`, `app/auth/**`, `app/proxy/**`, `app/sources/{models,trust,registry,service,repository}.py` | detection / correlation / authentication / source-trust / capability-ownership semantics are unchanged by design; the two T28 defects, the T22 defect and the IST defects live entirely in the composition / validation / display paths patched above |
| Evidence Archive / `evidence.*` ops (Phase 5.6) | future phase — implementing it is forbidden in this task (register **D-C**) |
| `app/persistence/telemetry.py` (and other naive `isoformat()` serialisations) | the wire shape was deliberately left unchanged — the display layer now interprets offset-less values as UTC, which satisfies the IST requirement without altering any stored or transmitted value |
| `frontend/src_upgraded_gemini/src/components/modals/TechnicalPayloadDrawer.tsx` | canonical evidence view: must keep showing the stored values verbatim |
| `frontend/index.html`, `frontend/js/**`, `desktop/status.html` | legacy shell / desktop clock label — not on the product path (register **D-F**); `desktop/status.html` is a local clock, not a security timestamp |
| `app/connectors/**` (legacy connector layer) | LEGACY / DEAD ARTIFACT — no live construction path, no API/frontend reference, not required by registration/validation/ingestion/NGINX (register **D-A**) |
| Version identifiers (`1.0.3`, `deploy/version.json`, docs) | explicitly forbidden; no 1.3.1, no 1.4, no packaging |
| `tests/integration/test_phase48_remediation.py`, root `conftest.py` | the test was fixed (HF-1) so it no longer depends on the scrubbed environment; the scrub itself is **kept unchanged** because it protects every other test |


## Harness Fixes (Pre-Release Failure Confirmation)

Three failures reported in the earlier revision of this report were investigated
from a controlled environment. **None is a product defect**; all three were
reproduced, root-caused, and fixed **in test / verification tooling only** — no
product code was modified (proved by the file-write audit at the end of this section).

### HF-1 — `test_phase48_remediation.py` → `KeyError: 'PROSHIELD_MONGO_URI'`

| Field | Value |
|---|---|
| **Exact root cause** | The test reads `os.environ["PROSHIELD_MONGO_URI"]` **at call time** (in `_drop_db()` and `_config()`), while its `os.environ.setdefault(...)` runs at **import** time. The root `conftest.py` declares an `autouse` fixture whose sole purpose is to `monkeypatch.delenv` every ambient `PROSHIELD_*` variable (so a developer machine cannot silently change what a test observes). The fixture runs after module import, so the `setdefault` value is removed again before the test body executes. |
| **A. Product defect?** | No — the exception is raised inside the test's own `_drop_db()`; no product path is involved. |
| **B. Test/harness defect?** | **Yes.** The test relied on mutable process state that the repository intentionally scrubs. |
| **C. Environment issue?** | Contributing only: the module depended on ambient/`setdefault` state instead of a self-owned constant. |
| **D. Outdated assertion?** | No — the assertion is valid; the *access pattern* is wrong. |
| **Controlled reproduction** | (a) Working tree: `python -m pytest tests/integration/test_phase48_remediation.py -q` → **1 failed**, `KeyError` (0.72 s). (b) **Clean checkout of HEAD** (`git worktree add --detach _head_check HEAD`; HEAD's `conftest.py` has **no** scrub) → the same command → **1 passed** (3.89 s). |
| **Smallest correct harness fix** | Keep the scrub (it protects every other test) and stop depending on process env: capture the resolved URI once at import into a module constant and use it throughout. |
| **Patch decision** | **PATCH THE TEST** (~5 lines). The scrub was **not** weakened. |
| **Files changed** | `tests/integration/test_phase48_remediation.py` |
| **Tests before / after** | before: **1 failed** (working tree) / **1 passed** (clean HEAD) → after: **1 passed** (working tree) |
| **Legitimate at release?** | **No — now fixed.** |

### HF-2 — `verify_windows_stack --checks workflow` → "no credentials found in proshield.env"

| Field | Value |
|---|---|
| **Exact root cause** | `read_credentials()` consulted only `load_secrets()`, i.e. `secrets/proshield.env`. On the installed layout that file is **ACL'd to `SYSTEM` + `Administrators` only** — verified with `icacls` and at the Python level (`read_text()` → `PermissionError [Errno 13]`; `load_secrets()` → `{}`). That ACL is the **documented, intended** control (the file holds the cross-plane HMAC signing keys). The installation *also* writes the operator-facing `config/initial-credentials.txt` — `docs/WINDOWS_DEPLOYMENT.md` explicitly says a non-elevated user must read the credentials there — and that file is readable (`config` is `Users:(M)`) and carries the same subject credentials. |
| **A. Product defect?** | No. The credential split and ACL are correct and documented; the installed planes authenticate fine (`auth.issue` 200). |
| **B. Test/harness defect?** | **Yes.** The tool documented an installed-stack verification path but implemented only half of the documented credential resolution. |
| **C. Environment issue?** | Yes, and it is the *designed* environment: a non-elevated operator. |
| **D. Outdated assertion?** | Partly — the expectation ("the workflow check can run against an installed stack") is right; the resolution logic was incomplete. |
| **Controlled reproduction** | `_acl_cred_probe.py` → `load_secrets() keys : []`, `subject-cred present : False`, `direct read : PermissionError`, `initial-credentials : ['admin','analyst','collector','internal']`. Harness before the fix: `[FAIL] security workflow - no credentials found in proshield.env`. |
| **Smallest correct harness fix** | Add the documented fallback (parse `paths.initial_credentials_file` when the secrets file yields no subject credentials), make the failure message truthful, and use `creds.get()` so a partial mapping cannot raise. **No ACL, permission or product behaviour was altered.** |
| **Patch decision** | **PATCH THE HARNESS.** |
| **Files changed** | `scripts/verify_windows_stack.py` |
| **Tests before / after** | before: installed `--checks workflow` → **FAIL** (credentials) → after: **15 passed, 0 failed** (`auth.issue admin + analyst` PASS) |
### HF-3 — `verify_windows_stack --checks workflow` → "case opened automatically - 0 case(s)"

| Field | Value |
|---|---|
| **Exact root cause** | The check listed and read cases with the **analyst** session. Auto cases are created by the SYSTEM pipeline identity (`created_by=pipeline`) and the case surface is **deliberately ownership-scoped**: an analyst holds `case:read` but not `case:read:any`, so `case.list` returns only own cases (0) and `case.get` is IDOR-hidden. This is mandated by OWNER-52-01 / V2-02 and mirrored in `app/proxy/proxy.py`, `app/incidents/service.py` (`_authorize_case_access`) and `scripts/final_rehearsal.py`, which already documents: "pipeline-owned cases carry created_by=pipeline, so the analyst role … is correctly denied by the IDOR boundary; use the admin session". |
| **A. Product defect?** | **No.** Relaxing it would be a security regression (IDOR by design). |
| **B. Test/harness defect?** | **Yes.** The harness asserted a capability the authorization model intentionally denies to an analyst. |
| **C. Environment issue?** | No. |
| **D. Outdated assertion?** | The assertion ("an automatic case must exist") is valid; the **session** used to observe it was wrong. |
| **Controlled reproduction** | `case.list` against the **unpatched** installed product: **admin → 5 cases, owners=['pipeline']** vs **analyst → 0 cases**; identical on the patched stack. Harness: `[FAIL] case opened automatically - 0 case(s)`. |
| **Smallest correct harness fix** | Observe the case with the session that legitimately holds `case:read:any` (**admin**) — for `case.list`, and for `case.get` / `timeline.build_for_incident` / `case.centralized` on a pipeline-owned case — and **strengthen** the check by asserting the analyst session is still denied (HTTP 403/404). |
| **Patch decision** | **PATCH THE HARNESS** and add a positive assertion for the ownership boundary. **Case authorization was NOT weakened** — it is now explicitly verified. |
| **Files changed** | `scripts/verify_windows_stack.py` (`check_workflow`) |
| **Tests before / after** | before: `[FAIL] case opened automatically - 0 case(s)` → after: `[PASS] case opened automatically (admin, case:read:any) - 6 case(s)` **and** `[PASS] pipeline-owned case is IDOR-hidden from an analyst session - HTTP 404` |
| **Legitimate at release?** | **No — now fixed**, and the replacement assertion is strictly stronger than the original. |

### HF-4 (found while fixing HF-3) — `--analyst-port/--ingress-port` did not move the supervised planes

| Field | Value |
|---|---|
| **Exact root cause** | With `--start-console` the supervisor reads its listen ports from `<data_root>/config/proshield.json`; the CLI flags changed only the **client** URLs. A self-contained run therefore silently bound the default ports (8088/8089). On a machine already running the installed product this collided: the planes exited with code 3 in a restart loop and readiness reported `[FAIL] supervisor reached readiness - analyst plane never answered`. |
| **A/B/C/D.** | No product defect (the supervisor correctly honours its settings file). **Harness/tooling defect** — a flag that changed only half of a documented flow. |
| **Controlled reproduction** | `_harness_win_data/logs/verify-console.log`: `analyst plane launched … port=8088`, `exited with code 3`, `restarting (attempt 3…7)`; harness: `[FAIL] supervisor reached readiness`. |
| **Smallest correct harness fix** | When `--start-console` is combined with an explicit port differing from the settings file, persist the requested ports (`service.settings.write_default_settings`, whose `to_json()` is secret-free by construction) **before** launching the supervisor, and use the same object for the client URLs. |
| **Patch decision** | **PATCH THE HARNESS.** |
| **Files changed** | `scripts/verify_windows_stack.py` (`main`, plus the `write_default_settings` / `dataclasses.replace` imports) |
| **Tests before / after** | before: `--analyst-port 8388 --ingress-port 8389 --start-console` → **FAIL at readiness** → after: same invocation on `8288/8289` → **26 passed, 0 failed** |
| **Legitimate at release?** | **No — now fixed.** It made the documented self-contained verification unusable on any machine with a live installation. |

### Harness-fix verification (all executed after the fixes)

| Check | Result |
|---|---|
| Focused (`tests/unit` + both Batch-1/2 suites + the fixed test) | **1621 passed, 0 failed** (63.8 s) |
| **Full regression** (`python -m pytest -q tests`) | **1746 passed, 0 failed** (95.8 s) — previously 1745 passed / 1 failed |
| Windows acceptance, fresh data root + dedicated ports, `--start-console` | **26 passed, 0 failed** (previously 19 passed / 1 failed) |
| Windows acceptance, installed data root, `--checks stack,gateway,desktop` | **10 passed, 0 failed** |
| **Installed-stack `--checks workflow`** (the reported HF-2 / HF-3 case) | **15 passed, 0 failed** (previously FAIL on credentials + 0 cases) |
| Live pipeline smoke (`verify_phase52_pipeline.py`) | **51/51 checks passed** |
| Playwright / Chromium smoke (patched repo stack `:8188`) | login → Cases (`4e 4d 1c`, `20:38:15 IST`) → case detail (`First/Last Seen 20:38:15 IST`, `Timeline (9)`, `Detections (4)`) → timeline 9 items, ms-exact IST |
| Frontend production build (UI source untouched) | **OK** — bundle unchanged (`1,202,750` B, `20:42:29`) |
| **No product change** | newest file under `app/**`, `service/**`, `deploy/**`, `desktop/**`, `frontend/**` is `20:42:29` (previous task); this task wrote only `tests/integration/test_phase48_remediation.py` (`21:29:19`) and `scripts/verify_windows_stack.py` (`21:32:48`) |

**Rules honoured:** product version unchanged (**1.0.3**); no `1.3.1` / `1.4`;
nothing packaged; **no database dropped or cleaned** — the fixed test drops only
its own dedicated `proshield_test_phase48_remediation` DB, the pipeline smoke uses
a throwaway `proshield_p52_pipe_*` DB, and the installed `proshield` DB was only
read from / ingested into; the installed product on `:8088`/`:8089` was left
running and otherwise untouched.

## Remaining Issues

1. **`case.create_from_correlation` `created` flag semantics** (minor, no UI consumer): it is the documented timestamps heuristic `created_at == updated_at`. Because the create path now composes complete evidence, a *re-run* of the same correlation is a true no-op and the flag reads `True` even though the case was reused. Recorded here; the idempotency contract itself (stable case id, no duplicate case, no mutation) is asserted by tests.
2. **Offset-less wire timestamps** — the frontend now interprets an offset-less ISO date-time as **UTC** (the canonical contract), which is what the `B12-TIME-02` fix required. On the backend side `app/persistence/telemetry.py` (and similar naive `isoformat()` serialisation points) still emit values without an explicit offset; adding an explicit offset there would be a wire-shape change and was deliberately left alone (the display layer is now correct either way).
3. **Seeded planned-capability copy** still mentions "ships in 5.1" (persisted registry data, truthful in substance) — register **D-D**.
4. **Notifications / reports timestamp surfaces** were patched and statically asserted but could not be exercised with live data in the fresh verification database (0 notifications) — register **D-E**.
5. **Installed product still runs the previous bundle** (1.0.3, unpatched UI) — the patched IST UI is verified on the repo-launched stack at `:8188`/`:8189`. Deploying the patched bundle to `C:\inetpub\ProShield` requires a release/packaging action, which this task forbids (no version change, no packaging).
6. **No open harness failure remains.** All three reported failures (HF-1…HF-3) plus one adjacent tooling defect found during the investigation (HF-4) were fixed in test/tooling code and re-verified; nothing is left in the register as "pre-existing, therefore ignored".

## Future Items Not Patched

Every intentionally untouched item now has a row in **## Deferred / Future
Improvements Register** (D-A … D-G): automatic/live UI synchronization (**D-B**),
the Evidence Archive / operational-vs-evidence separation (**D-C**), legacy
connector retirement (**D-A**), legacy vanilla-shell removal (**D-F**), seeded
planned-capability copy (**D-D**), notification/report live coverage (**D-E**),
and the pre-existing harness/environment expectations (**D-G**).

**UTC → IST is not in this list and not in the register:** it is a *current*
requirement, patched and verified in this task (Finding 4).

## Final Assessment

* **Every confirmed defect was fixed and independently re-verified.**
  * **T28 (case evidence completeness)** — root cause proven with live Mongo and
    browser evidence (two defects: incomplete create path, cross-cluster
    contamination). After the patch: correlation 4/4 → case **4e/4d/1c** →
    timeline **9 items**; a second cluster in the same window stays disjoint;
    proven in MongoDB, over the wire (`case.get`, `timeline.build_for_incident`)
    and in the live browser (`4e 4d 1c`, `Timeline (9)`, `Detections (4)`),
    including across a service restart.
  * **T22 (invalid/missing canonical timestamp)** — root cause proven live; after
    the patch every non-timestamp (int/list/null/missing, and the exact
    non-canonical `timestamp` payload the manual test used) is refused per event
    with `validation_error`; valid offsets normalise to one UTC instant; a
    future-dated value remains refused.
  * **Finding 4 (IST display — current requirement)** — the requirement was
    unmet (UI was UTC-only) and is now patched: timezone-aware IST conversion at a
    single display layer, wired into every user-visible timestamp surface,
    **while canonical storage, `event_time` semantics and every wire value stayed
    UTC**. Live proof: all ten surfaces were compared against canonical MongoDB
    values converted by an *independent* implementation (`zoneinfo`), with
    millisecond-exact matches on the case timeline/detections (`.494/.530/.567/.620`).
    A **second defect found during that verification** (offset-less canonical
    values read as host-local, rendering the UTC wall clock labelled IST — 5 h 30 m
    off) was fixed in the same parse layer and re-verified in the browser.
    Four screenshots recorded.
  * **Finding 6 / T04-FE-01 (stale UI)** — root cause proven (missing refetch
    trigger, not caching or a backend registry); after the patch one click on
    **Reload** took an open session from `2` to the authoritative `3` cases with
    the new case visible. No local state is faked.
  * **Finding 3 (stale phase wording)** — presentation patch verified in the live
    bundle.
* **Nothing unproven was patched.** Findings 1, 2, 5, 7 and the retired-object
  observation are recorded with their evidence and classified EXPECTED / LEGACY /
  FUTURE-PHASE GAP; the harness failures are classified TEST/ENVIRONMENT ERROR
  with pre-existence proofs (including an experiment on the *unpatched* installed
  product). Every id without a supplied record is marked
  *ORIGINAL TEST RECORD UNAVAILABLE — NOT RECONSTRUCTED*.
* **Architecture preserved.** No detection, correlation, authentication,
  source-trust, capability/source-ownership or persistence-semantics change; no
  new collections, no new wire operations, no version change, no packaging. The
  T28/T22 fixes move the system *towards* its own documented contract; the IST
  patch touches presentation only.
* **Regression status (final run, after the harness fixes):** `python -m pytest -q` → **1746 passed, 0 failed** — the previous 1745/1 with the single harness defect fixed (**HF-1**). Focused Batch-1/2 suite: **1621 passed**; IST suite alone: **22 passed**; shipped chained live verification: **51/51**; Windows acceptance: **26 passed / 0 failed** (fresh data root) and **10 + 15 passed / 0 failed** (installed data root, read-only + workflow); typecheck clean; production build OK; the live browser workflow (login → cases → case detail → timeline → detections → sources → capabilities → health → overview → reload → browser reload) passes with IST values matching the database. The installed product on `:8088`/`:8089` was left running and untouched (patched-code verification ran on the repo stack at `:8188`/`:8189`, because redeploying the installed copy would require a release action this task forbids).
* **Harness defects are fixed, not ignored.** All three reported failures were reproduced, root-caused, classified and repaired **in test/tooling code** — `tests/integration/test_phase48_remediation.py` (**HF-1**) and `scripts/verify_windows_stack.py` (**HF-2**, **HF-3**, plus the adjacent **HF-4** found during the investigation). No product code was touched (file-write audit in *Harness Fixes*), no ACL or case authorization was weakened, and the ownership boundary is now positively asserted rather than assumed.
* **Not claimed:** ProShield is **not** asserted to be bug-free. What is asserted is that 100 % of the supplied and investigated Batch 1/2 findings were
  classified, that every confirmed current-scope product defect was patched and
  independently re-verified, that no unproven finding was patched, that no
  unrelated architecture was changed, that every intentionally deferred item
  is documented with a rationale and a future destination (D-A … D-F), and that
  no test failure of any kind remains open or unexplained.

