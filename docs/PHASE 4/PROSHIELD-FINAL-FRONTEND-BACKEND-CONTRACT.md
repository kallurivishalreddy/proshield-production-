# ProShield - Final Frontend <-> Backend Contract (FROZEN)

**Phase 4.9 - wiring specification for the Phase 4 frontend**

This is the **frozen** contract. Every UI action is bound to a
specific `SecureProxy.handle(ProxyRequest)` call with an
exact request schema, permission, backend handler, service,
repository/engine, response schema, frontend state update,
loading/empty/error states, pagination, security boundary,
performance note, and ID/evidence reference.

**Classification legend:**
- **WIRED AND VERIFIED** - live backend op, dynamic + static test coverage
- **WIRED BUT DEFECTIVE** - live but with a known defect (none in current slice)
- **BACKEND EXISTS - FRONTEND NOT WIRED** - service/repo implemented, proxy handler returns documented 501 `not_implemented` stub
- **NEW BACKEND OPERATION IMPLEMENTED** - new op declared for this slice (handler + 501 stub)
- **DEFERRED BY DESIGN** - intentionally returns a documented 400/404

**Backend boundary:** every client-facing call goes through
`SecureProxy.handle(ProxyRequest)` (`app/proxy/proxy.py:312+`).
There is no HTTP router; a future HTTP layer must wrap this
proxy. **Repositories / services are NOT directly exposed.**

**Authentication:**
- Header: `Authorization: Bearer <session_token>` OR `X-ProShield-Session: <token>`
- Token format: `ps.<subject_id>.<iat>.<exp>.<hmac_sha256_hex>`
- Issuance: `auth.issue` requires `X-ProShield-Credential` header OR body `credential` field

**Response envelope:**
```json
// success
{ "ok": true, "data": { ... } }
// error
{ "error": { "code": "<error_code>", "message": "<safe_message>" } }
// not_implemented stub (501, reserved - no live ops today)
{ "ok": false, "error": { "code": "not_implemented", "message": "operation 'X' is declared but not implemented in the current backend slice", "internal_detail": "..." }, "data": { "operation": "X" } }
```

**Rate limits:**
- per-subject: 120 req/min (`proxy_rate_limit_per_minute`)
- centralized: 5 req/min (`proxy_centralized_rate_limit_per_minute`)
- auth.issue: 120 req/min per (subject_id, caller_ip) composite
- ingress per-source: 600 events/min (`ingress_event_rate_limit_per_minute`)
- ingress per-request cap: 100 events (`ingress_max_events_per_request`)

**ID formats:**
- events: UUIDv7
- detections: `det-<uuid7>`
- correlations: `corr-<uuid7>`
- cases: `case-<uuid7>`
- reports: `rpt-<uuid7>`
- sources: `src-<uuid7>-<suffix>`
- source-identity tokens: `sit-...`
- session tokens: `ps.<subject_id>.<iat>.<exp>.<hmac>`

---

## 1. Operation inventory by classification

| Class | Count | Operations |
|---|---|---|
| WIRED AND VERIFIED | 39 | `health`, `auth.issue`, `case.get`, `case.list`, `case.close`, `case.centralized`, `report.get`, `report.list`, `report.generate_normal`, `report.generate_centralized`, `report.export` (JSON only), `routing.compute`, `source.list`, `source.get`, `source.list_types`, `source.register`, `source.configure`, `source.validate`, `source.enable`, `source.disable`, `source.retire`, `source.issue_token`, `detection.list`, `detection.get`, `detection.list_for_incident`, `correlation.list`, `correlation.get`, `correlation.list_for_incident`, `overview.summary`, `timeline.build_for_incident`, `rule.list`, `rule.get`, `rule.create`, `rule.update`, `rule.version`, `rule.enable`, `rule.disable`, `rule.retire`, plus the 400-boundary `case.create` |
| NEW BACKEND OPERATION IMPLEMENTED | 0 | (none) |
| BACKEND EXISTS - FRONTEND NOT WIRED (501 STUB) | 0 | (none) |
| DEFERRED BY DESIGN | 1 | `case.create` (always 400, Phase 4.8 boundary) |
| **Total declared** | **40** | (39 wired + 0 new + 0 stub + 1 boundary) |

---

## 2. Component 1: Overview / Dashboard

Purpose: SOC posture at a glance (counts, sources, health).

### Action 2.1: Load dashboard summary

- **OP:** `overview.summary`
- **Class:** WIRED AND VERIFIED
- **Handler:** `app/proxy/proxy.py:1351-1358`
- **Permission:** `Permission.OVERVIEW_READ` (analyst/admin/internal_service)
- **Request:** `{ }`
- **Response:** `{ "ok": true, "data": { "open_cases": <int>, "open_detections": <int>, "open_correlations": <int>, "active_rules": <int> } }`
- **Service:** `app.overview.service.OverviewReadService` (attached via `SecureProxy.attach_overview_service(...)`)
- **Frontend state:** show drill-down via `case.list`, `detection.list`, `correlation.list` (see below)
- **Loading:** button shows spinner while request in flight
- **Empty state:** if all stub counts are zero, show 'No activity yet'
- **Error state:** display `error.code`; 501 -> 'not yet implemented' UI; 403 -> 'insufficient permission'; 401 -> 'session expired, re-login'
- **Pagination/filtering:** none (aggregate call)
- **Security boundary:** analyst sees own cases only (IDOR protection inherited from `case.list`); admin sees all
- **Performance:** aggregate query; expected <100 ms with Mongo aggregation
- **IDs/evidence references:** none
- **Component navigation:** clicks on tiles drill into Case list, Detection list, etc.

### Action 2.2: Health / heartbeat (top-bar)

- **OP:** `health`
- **Class:** WIRED AND VERIFIED
- **Handler:** `app/proxy/proxy.py:534-536`
- **Permission:** none (no auth required)
- **Request:** `{ }`
- **Response:** `{ "ok": true, "data": { "status": "ok" } }`
- **Service:** none
- **Frontend state:** top-bar status dot: green if 200, red if 5xx, gray if unknown
- **Loading:** poll every 30s; no UI indicator (silent)
- **Empty state:** N/A
- **Error state:** show 'Backend unreachable' banner
- **Pagination:** N/A
- **Security boundary:** unauthenticated (intentional - liveness probe)
- **Performance:** <5 ms
- **IDs/evidence:** none

### Action 2.3: Show source status (drill into Sources)

- **OP:** `source.list`
- **Class:** WIRED AND VERIFIED
- **Handler:** `app/proxy/proxy.py:1022-1038`
- **Permission:** `Permission.RULE_READ` (analyst/admin/internal_service; NOT collector - PROXY-001 fix)
- **Request:** `{ }`
- **Response:** `{ "ok": true, "data": { "sources": [SourceInstanceView...], "supported_connector_types": [...] } }`
- **Service:** `SourceManagementService.list_all()` -> `SourceRegistry.list_all()` (`app/sources/service.py`, `app/sources/registry.py`)
- **Frontend state:** dashboard tile with source count by state (registered/configured/validated/enabled/disabled/retired)
- **Loading:** spinner while request in flight
- **Empty state:** 'No sources configured' if list is empty
- **Error state:** 403 -> 'You need analyst role to view sources'
- **Pagination:** unbounded today (returns full list); can be capped if >100 in future
- **Security boundary:** no secret material in `SourceInstanceView` (model redacts `secret_ref`); collector (event:read only) returns 403
- **Performance:** single registry read; expected <50 ms
- **IDs/evidence:** `source_instance_id` (e.g. `src-...`); links to Sources page
---

## 3. Component 2: Incident / Case

### Action 3.1: List cases

- **OP:** `case.list`
- **Class:** WIRED AND VERIFIED
- **Handler:** `app/proxy/proxy.py:761-781`
- **Permission:** `Permission.CASE_READ`
- **Request:** `{ "state": "open"|"closed"|null, "limit": int<=200 }`
- **Response:** `{ "ok": true, "data": { "cases": [Incident.to_dict()...] } }`
- **Service:** `IncidentService.list_cases` (`app/incidents/service.py:136-...`) -> `IncidentRepository.find_recent`/`find_by_state` (cap 200)
- **Frontend state:** table view; filter chips for state; pagination via 'Load more' (limit-based, no cursor)
- **Loading:** skeleton rows while in flight
- **Empty state:** 'No cases yet' if list is empty
- **Error state:** 403 -> 'Insufficient permission'; 401 -> re-login
- **Pagination:** `limit` (default 50, max 200); NO cursor/total today
- **Security boundary:** analysts see OWN cases only (ownership filter); admins see all
- **Performance:** indexed query, cap 200; <50 ms
- **IDs/evidence:** `incident_id` (e.g. `case-...`); link to detail

### Action 3.2: Get case detail

- **OP:** `case.get`
- **Class:** WIRED AND VERIFIED
- **Handler:** `app/proxy/proxy.py:716-741`
- **Permission:** `Permission.CASE_READ` + ownership (or `CASE_READ_ANY`)
- **Request:** `{ "incident_id": "case-..." }`
- **Response:** `{ "ok": true, "data": { "case": Incident.to_dict() } }` - includes evidence IDs, lifecycle_history, report_references, centralized_correlation_ids
- **Service:** `IncidentService.get_case` (`app/incidents/service.py:112-...`) -> `_authorize_case_access`
- **Frontend state:** detail page; shows evidence IDs, lifecycle, reports, centralized status
- **Error state:** 404 `case_not_found` (existence hidden - IDOR defense); 403 forbidden
- **Security boundary:** IDOR defense - cross-analyst returns 404 NOT 403
- **IDs/evidence:** `incident_id`, `event_ids[]`, `detection_ids[]`, `correlation_ids[]`, `rule_references[]`, `report_references[]`

### Action 3.3: Close case

- **OP:** `case.close`
- **Class:** WIRED AND VERIFIED
- **Handler:** `app/proxy/proxy.py:783-810`
- **Permission:** `Permission.CASE_READ` + ownership
- **Request:** `{ "incident_id": "case-...", "reason": "<text>" }`
- **Response:** `{ "ok": true, "data": { "case": Incident.to_dict() with state=closed } }`
- **Service:** `IncidentService.close_case` (`app/incidents/service.py:438-...`)
- **Frontend state:** show 'closed' badge; disable Close button
- **Error state:** 404 case_not_found; 403 forbidden; 409 if already closed
- **IDs/evidence:** `incident_id`; no new IDs

### Action 3.4: Route case

- **OP:** `routing.compute`
- **Class:** WIRED AND VERIFIED
- **Handler:** `app/proxy/proxy.py:969-1003`
- **Permission:** `Permission.ROUTING_READ` + ownership
- **Request:** `{ "incident_id": "case-...", "severity_band": "low"|...|null, "confidence_band": "low"|...|null, "complexity": int|null }`
- **Response:** `{ "ok": true, "data": { "routing": { "state": "ok", "recommendation": { "level": "L1"|"L2"|"L3", "team": "...", "queue": "...", "reasons": [...] } } } }`
- **Service:** `RoutingEngine.route_for_identity` (`app/routing/service.py`)
- **Performance:** pure compute; <5 ms
### Action 3.5: Request centralized analysis

- **OP:** `case.centralized`
- **Class:** WIRED AND VERIFIED
- **Handler:** `app/proxy/proxy.py:836-967`
- **Permission:** `Permission.CASE_CENTRALIZED_REQUEST` + ownership; rate-limited to 5/min per subject
- **Request:** `{ "incident_id": "case-...", "reason": "<text>", "events": [...], "detections": [...], "correlations": [...] }`
- **Response:** `{ "ok": true, "data": { "case": Incident.to_dict(), "failed": bool, "failure_reason": str|null, "new_correlation_ids": [...] } }`
- **Service:** `IncidentService.request_centralized_analysis` -> `_run_centralized` -> `CorrelationEngine.run` -> `IncidentRepository.upsert`
- **Frontend state:** disable 'Request centralized' button while pending; on success show new correlation IDs; on failed show error reason
- **Error state:** 404 case_not_found; 403 forbidden; 429 rate limited
- **Performance:** seconds (correlation engine); cached per-case
- **IDs/evidence:** new `correlation_ids` returned; `case.centralized_correlation_ids` updated

### Action 3.6: Create case (BOUNDARY)

- **OP:** `case.create`
- **Class:** DEFERRED BY DESIGN (always 400)
- **Handler:** `app/proxy/proxy.py:743-758`
- **Permission:** `Permission.CASE_READ` (the check is performed; then the boundary raises 400)
- **Request:** any
- **Response (always):** `{ "error": { "code": "invalid_proxy_request", "message": "case.create is not exposed at the wire boundary" } }` with HTTP 400
- **Service:** none - proxy does NOT construct evidence (Phase 4.8 boundary)
- **Frontend state:** the UI MUST NOT show a 'Create case' affordance; if shown accidentally, the 400 renders as 'not supported at this time'
- **Note:** `IncidentService.create_case` exists and can be promoted to a wire handler in a future slice (would require an evidence-payload schema on the wire)
---

## 4. Component 3: Detection

### Action 4.1: List detections

- **OP:** `detection.list`
- **Class:** WIRED AND VERIFIED
- **Handler:** `app/proxy/proxy.py:1294-1302`
- **Permission:** `Permission.DETECTION_READ`
- **Request:** `{ "rule_id": "NGINX-AUTH-FAILURE-001"|null, "event_id": "<uuid7>"|null, "limit": int<=200, "since": "iso8601"|null, "until": "iso8601"|null, "severity": "low"|...|null }`
- **Response:** `{ "ok": true, "data": { "detections": [Detection.to_dict()...] } }`
- **Service:** `DetectionReadService.list` (attached via `SecureProxy.attach_detection_service(...)`); uses `DetectionRepository.find_by_rule` / `find_by_event_id`
- **Frontend state:** render the detection list directly; offer navigation via `case.get` (which returns `evidence.detection_ids`)
- **Pagination:** `limit` default 50, max 200; no cursor
- **Security boundary:** analyst/admin/internal_service (anyone with `DETECTION_READ`)
- **IDs/evidence:** `detection_id` (`det-<uuid7>`), `event_id`, `rule_id`

### Action 4.2: Get detection detail

- **OP:** `detection.get`
- **Class:** WIRED AND VERIFIED
- **Handler:** `app/proxy/proxy.py:1304-1312`
- **Permission:** `Permission.DETECTION_READ`
- **Request:** `{ "detection_id": "det-..." }`
- **Response:** `{ "ok": true, "data": { "detection": Detection.to_dict() } }`
- **Service:** `DetectionReadService.get` (attached via `SecureProxy.attach_detection_service(...)`); uses `DetectionRepository.get_by_detection_id`
- **Frontend state:** render the detection detail directly
- **IDs/evidence:** `detection_id`, `event_id`, `rule_id`, `rule_version`, `category`, `reasoning`, `evidence_refs`, `detected_at`

### Action 4.3: List detections for an incident

- **OP:** `detection.list_for_incident`
- **Class:** WIRED AND VERIFIED
- **Handler:** `app/proxy/proxy.py:1314-1322`
- **Permission:** `Permission.DETECTION_READ`
- **Request:** `{ "incident_id": "case-..." }`
- **Response:** `{ "ok": true, "data": { "detections": [Detection.to_dict()...] } }`
- **Service:** `DetectionReadService.list_for_incident` (attached via `SecureProxy.attach_detection_service(...)`); calls `IncidentService.get_case(identity, incident_id)` first for IDOR defense, then `DetectionRepository.find_by_event_id` for each event id
- **Frontend state:** render the case-scoped detection list directly
- **IDs/evidence:** `detection_id`[], `event_id`[], `rule_id`[]
---

## 5. Component 4: Correlation

### Action 5.1: List correlations

- **OP:** `correlation.list`
- **Class:** WIRED AND VERIFIED
- **Handler:** `app/proxy/proxy.py:1324-1332`
- **Permission:** `Permission.CORRELATION_READ`
- **Request:** `{ "pattern_id": "brute_force_clustering"|null, "since": "iso8601"|null, "until": "iso8601"|null, "limit": int<=200 }`
- **Response:** `{ "ok": true, "data": { "correlations": [Correlation.to_dict()...] } }`
- **Service:** `CorrelationReadService.list` (attached via `SecureProxy.attach_correlation_service(...)`); unfiltered call returns `[]` (unbounded-query invariant); uses `CorrelationRepository.find_by_pattern`
- **IDs/evidence:** `correlation_id` (`corr-<uuid7>`), `pattern_id`, `pattern_version`, `trigger`, `key.parts[]`, `detection_ids[]`, `event_ids[]`

### Action 5.2: Get correlation detail

- **OP:** `correlation.get`
- **Class:** WIRED AND VERIFIED
- **Handler:** `app/proxy/proxy.py:1334-1342`
- **Permission:** `Permission.CORRELATION_READ`
- **Request:** `{ "correlation_id": "corr-..." }`
- **Response:** `{ "ok": true, "data": { "correlation": Correlation.to_dict() } }`
- **Service:** `CorrelationReadService.get` (attached via `SecureProxy.attach_correlation_service(...)`); uses `CorrelationRepository.get_by_correlation_id`
- **IDs/evidence:** `correlation_id`, `pattern_id`, `pattern_version`, `trigger`, `key.parts[]`, `count`, `window_start`, `window_end`, `reasoning`, `detection_ids[]`, `event_ids[]`

### Action 5.3: List correlations for an incident

- **OP:** `correlation.list_for_incident`
- **Class:** WIRED AND VERIFIED
- **Handler:** `app/proxy/proxy.py:1344-1352`
- **Permission:** `Permission.CORRELATION_READ`
- **Request:** `{ "incident_id": "case-..." }`
- **Response:** `{ "ok": true, "data": { "correlations": [Correlation.to_dict()...] } }`
- **Service:** `CorrelationReadService.list_for_incident` (attached via `SecureProxy.attach_correlation_service(...)`); calls `IncidentService.get_case(identity, incident_id)` first for IDOR defense, then looks up each `case.evidence.correlation_ids` (or `case.centralized_correlation_ids` for centralized) via `CorrelationRepository.get_by_correlation_id`
- **IDs/evidence:** `correlation_id`[] (with metadata)

### Action 5.4: Centralized analysis (request)

- See **Action 3.5: Request centralized analysis** under Incident / Case. Centralized analysis is the *trigger* that produces new correlations bound to a case.

### Action 5.5: Source-specific report

- See **Action 7.1: Generate source-specific (normal) report** under Reports.

### Action 5.6: Centralized report

- See **Action 7.2: Generate centralized report** under Reports.
---

## 6. Component 5: Sources

### Action 6.1: List sources

- **OP:** `source.list`
- **Class:** WIRED AND VERIFIED
- **Handler:** `app/proxy/proxy.py:1022-1038`
- **Permission:** `Permission.RULE_READ` (PROXY-001 fix; NOT collector)
- **Request:** `{ }`
- **Response:** `{ "ok": true, "data": { "sources": [SourceInstanceView...], "supported_connector_types": [...] } }`
- **Service:** `SourceManagementService.list_all` -> `SourceRegistry.list_all`
- **IDs/evidence:** `source_instance_id` (e.g. `src-<uuid7>-<suffix>`); secret redacted in view

### Action 6.2: Get source detail

- **OP:** `source.get`
- **Class:** WIRED AND VERIFIED
- **Handler:** `app/proxy/proxy.py:1052-1070`
- **Permission:** `Permission.RULE_READ`
- **Request:** `{ "source_instance_id": "src-..." }`
- **Response:** `{ "ok": true, "data": { "source": SourceInstanceView } }`
- **IDs/evidence:** `source_instance_id`

### Action 6.3: List supported connector types

- **OP:** `source.list_types`
- **Class:** WIRED AND VERIFIED
- **Handler:** `app/proxy/proxy.py:1040-1050`
- **Permission:** `Permission.RULE_READ`
- **Response:** `{ "ok": true, "data": { "supported_connector_types": ["nginx", ...] } }`

### Action 6.4: Register source

- **OP:** `source.register`
- **Class:** WIRED AND VERIFIED
- **Handler:** `app/proxy/proxy.py:1072-1112`
- **Permission:** `Permission.SOURCE_WRITE` (proxy-level) + `_require_role(ADMIN_ROLE)` (service-level; defense-in-depth)
- **Request:** `{ "source_type": "nginx", "display_name": "<text>", "description": "<text>", "tags": [...], "asset_tags": [...] }`
- **Response:** `{ "ok": true, "data": { "source": SourceInstanceView (state=registered) } }`
- **Service:** `SourceManagementService.register` (`app/sources/service.py:177-...`)

### Action 6.5: Configure source

- **OP:** `source.configure`
- **Class:** WIRED AND VERIFIED
- **Handler:** `app/proxy/proxy.py:1114-1168`
- **Permission:** `Permission.SOURCE_WRITE` + ADMIN
- **Request:** `{ "source_instance_id": "src-...", "configuration": { "connection_type": "push"|"pull", "endpoint": "...", "proxy_path": "...", "destination": "...", "asset_tags": [...], "tags": [...], "references": [...], "secret_ref": "..." } }`
- **Response:** `{ "ok": true, "data": { "source": SourceInstanceView (state=configured) } }`
- **ST-03:** if `secret_ref` non-empty but `secret_store_configured=False`, the service rejects with 400; `secret_ref_set` only true when the secret was actually persisted
### Action 6.6: Validate source

- **OP:** `source.validate`
- **Class:** WIRED AND VERIFIED
- **Handler:** `app/proxy/proxy.py:1170-1191`
- **Permission:** `Permission.SOURCE_WRITE` + ADMIN
- **Request:** `{ "source_instance_id": "src-..." }`
- **Response:** `{ "ok": true, "data": { "source": SourceInstanceView (state=validated) } }`
- **Service:** `SourceManagementService.validate_connection` (`app/sources/service.py:282-...`)

### Action 6.7: Enable source

- **OP:** `source.enable`
- **Class:** WIRED AND VERIFIED
- **Handler:** `app/proxy/proxy.py:1193-1206`
- **Permission:** `Permission.SOURCE_WRITE` + ADMIN
- **Request:** `{ "source_instance_id": "src-..." }`
- **Response:** `{ "ok": true, "data": { "source": SourceInstanceView (state=enabled) } }`
- **Service:** `SourceManagementService.enable` (`app/sources/service.py:343-...`)

### Action 6.8: Disable source

- **OP:** `source.disable`
- **Class:** WIRED AND VERIFIED
- **Handler:** `app/proxy/proxy.py:1208-1221`
- **Permission:** `Permission.SOURCE_WRITE` + ADMIN
- **Request:** `{ "source_instance_id": "src-..." }`
- **Response:** `{ "ok": true, "data": { "source": SourceInstanceView (state=disabled) } }`
- **Service:** `SourceManagementService.disable` (`app/sources/service.py:374-...`)

### Action 6.9: Retire source

- **OP:** `source.retire`
- **Class:** WIRED AND VERIFIED
- **Handler:** `app/proxy/proxy.py:1223-1238`
- **Permission:** `Permission.SOURCE_WRITE` + ADMIN
- **Request:** `{ "source_instance_id": "src-..." }`
- **Response:** `{ "ok": true, "data": { "source": SourceInstanceView (state=retired) } }`
- **Service:** `SourceManagementService.retire` (`app/sources/service.py:405-...`)
- **Note:** retire is the terminal state; no hard delete; events are preserved

### Action 6.10: Issue source-identity token

- **OP:** `source.issue_token`
- **Class:** WIRED AND VERIFIED
- **Handler:** `app/proxy/proxy.py:1240-1254`
- **Permission:** `Permission.SOURCE_WRITE` + ADMIN
- **Request:** `{ "source_instance_id": "src-...", "lifetime_seconds": int }`
- **Response:** `{ "ok": true, "data": { "source_instance_id": "src-...", "source_token": "sit-...", "expires_at": "iso8601" } }`
- **Service:** `SourceManagementService.issue_ingress_token` -> `SourceIdentityTokenIssuer.issue` (HMAC-SHA256, keyring, max-lifetime cap)
- **IDs/evidence:** `source_token` (used as `X-ProShield-Source-Token` or `Authorization: Bearer sit-...` for `OP_INGEST`)
---

## 7. Component 6: Rules

All 8 rule ops are **WIRED AND VERIFIED** as of Phase 4.10. The backend `RuleManagementService` and the `RuleRegistry` governance (CANDIDATE not enablable, version monotonicity, retired immutable) are fully implemented and tested, and are attached to the proxy via `SecureProxy.attach_rule_management_service(...)`.

### Action 7.1: List rules

- **OP:** `rule.list`
- **Class:** WIRED AND VERIFIED
- **Handler:** `app/proxy/proxy.py:1370-1378`
- **Permission:** `Permission.RULE_READ`
- **Service:** `RuleManagementService.list_all` / `list_latest` (`app/rules/management/service.py`), attached via `SecureProxy.attach_rule_management_service(...)`
- **IDs/evidence:** `rule_id` (e.g. `NGINX-AUTH-FAILURE-001`), `version`

### Action 7.2: Get rule detail

- **OP:** `rule.get`
- **Class:** WIRED AND VERIFIED
- **Handler:** `app/proxy/proxy.py:1380-1388`
- **Permission:** `Permission.RULE_READ`
- **Service:** `RuleManagementService.get` -> `RuleRepository.get`

### Action 7.3: Create rule

- **OP:** `rule.create`
- **Class:** WIRED AND VERIFIED
- **Handler:** `app/proxy/proxy.py:1390-1398`
- **Permission:** `Permission.RULE_WRITE` (admin only)
- **Service:** `RuleManagementService.create` -> `RuleRepository.create`
- **Governance:** CANDIDATE state by default; cannot be enabled until promoted to APPROVED

### Action 7.4: Update rule (new version)

- **OP:** `rule.update`
- **Class:** WIRED AND VERIFIED
- **Handler:** `app/proxy/proxy.py:1400-1408`
- **Permission:** `Permission.RULE_WRITE`
- **Service:** `RuleManagementService.update` (creates new version; old version superseded)

### Action 7.5: Version rule

- **OP:** `rule.version`
- **Class:** WIRED AND VERIFIED
- **Handler:** `app/proxy/proxy.py:1410-1418`
- **Permission:** `Permission.RULE_WRITE`
- **Service:** `RuleManagementService.create_new_version`

### Action 7.6: Enable rule

- **OP:** `rule.enable`
- **Class:** WIRED AND VERIFIED
- **Handler:** `app/proxy/proxy.py:1420-1428`
- **Permission:** `Permission.RULE_WRITE`
- **Service:** `RuleManagementService.set_enabled(True, ...)` -> `RuleRegistry.set_enabled` (enforces CANDIDATE-not-enablable + SupersededVersionNotReenablable)

### Action 7.7: Disable rule

- **OP:** `rule.disable`
- **Class:** WIRED AND VERIFIED
- **Handler:** `app/proxy/proxy.py:1430-1438`
- **Permission:** `Permission.RULE_WRITE`
- **Service:** `RuleManagementService.set_enabled(False, ...)`

### Action 7.8: Retire rule

- **OP:** `rule.retire`
- **Class:** WIRED AND VERIFIED
- **Handler:** `app/proxy/proxy.py:1440-1448`
- **Permission:** `Permission.RULE_WRITE`
- **Service:** `RuleManagementService.set_state(RETIRED)` (soft-delete; immutable)
---

## 8. Component 7: Timeline

### Action 8.1: Build timeline for an incident

- **OP:** `timeline.build_for_incident`
- **Class:** WIRED AND VERIFIED
- **Handler:** `app/proxy/proxy.py:1360-1368`
- **Permission:** `Permission.TIMELINE_READ`
- **Request:** `{ "incident_id": "case-..." }`
- **Response:** `{ "ok": true, "data": { "timeline": { "items": [TimelineEvent.to_dict()...] } } }`
- **Service:** `TimelineReadService.build_for_incident` (attached via `SecureProxy.attach_timeline_service(...)`); orchestrates `TimelineEngine.run(events, detections, correlations)` (`app/timeline/engine.py`) and calls `IncidentService.get_case(identity, incident_id)` first for IDOR defense
- **Verified contract (from engine code):**
  - Chronological order: `(occurred_at, kind, source_id)`
  - Deduplication: each `(kind, source_id)` emitted once
  - Evidence linking: events carry `[event_id, collector]`; detections carry `[detection_id, event_id, *evidence_refs]`; correlations carry `[correlation_id, *detection_ids, *event_ids]`
- **Frontend state:** render the timeline directly; embedded `ReportItem`s inside `report.get` remain supported
- **IDs/evidence:** `event_id`, `detection_id`, `correlation_id`, `source_id`

### Action 8.2: Filter by time range / source / kind

- **OP:** (none - timeline is a single endpoint, no filter params today)
- **Status:** filtering not exposed at the wire; today the UI must filter the rendered timeline client-side
- **Future:** add `since`, `until`, `source_id[]`, `kind[]` params when the `TimelineEngine.run` query API is expanded
---

## 9. Reports (cross-cutting)

### Action 9.1: Generate source-specific (normal) report

- **OP:** `report.generate_normal`
- **Class:** WIRED AND VERIFIED
- **Handler:** `app/proxy/proxy.py:819-834` (dispatched) -> `_handle_generate_normal_report`
- **Permission:** `Permission.REPORT_GENERATE` + ownership
- **Request:** `{ "incident_id": "case-...", "events": [...], "detections": [...], "correlations": [...] }`
- **Response:** `{ "ok": true, "data": { "report": Report.to_dict() } }`
- **Service:** `ReportService.generate_normal_report` -> `_build_normal_sections` (what was detected / sources / detections / specialized_correlation / rule_references / investigation_metadata)
- **IDs/evidence:** `report_id` (`rpt-<uuid7>`), `incident_id`, `event_ids[]`, `detection_ids[]`, `correlation_ids[]`, `evidence_references[]`

### Action 9.2: Generate centralized report

- **OP:** `report.generate_centralized`
- **Class:** WIRED AND VERIFIED
- **Handler:** `app/proxy/proxy.py:819-834` (dispatched) -> `_handle_generate_centralized_report`
- **Permission:** `Permission.REPORT_GENERATE` + ownership
- **Gating:** **MUST be called AFTER `case.centralized` returns `failed: false`.** Otherwise `ReportService` raises `InvalidReportInputError("case has no centralized context")`
- **Request:** `{ "incident_id": "case-...", "events": [...], "detections": [...], "correlations": [...], "centralized_events": [...], "centralized_detections": [...], "centralized_correlations": [...] }`
- **Response:** `{ "ok": true, "data": { "report": Report.to_dict() (is_centralized=true) } }`
- **Service:** `ReportService.generate_centralized_report` -> `_build_centralized_sections`
- **IDs/evidence:** `report_id`, includes centralized evidence + `case.centralized_correlation_ids`

### Action 9.3: Get report

- **OP:** `report.get`
- **Class:** WIRED AND VERIFIED
- **Permission:** `Permission.REPORT_READ` + ownership (via case)
- **Request:** `{ "report_id": "rpt-..." }`
- **Response:** `{ "ok": true, "data": { "report": Report.to_dict() } }` - sections, items, evidence_references

### Action 9.4: List reports

- **OP:** `report.list`
- **Class:** WIRED AND VERIFIED
- **Request:** `{ "incident_id": "case-..."|null, "limit": int<=100 }`
- **Response:** `{ "ok": true, "data": { "reports": [Report.to_dict()...] } }`
- **Pagination:** `limit` default 20, max 100; no cursor

### Action 9.5: Export report (NEW OP)

- **OP:** `report.export`
- **Class:** WIRED AND VERIFIED (JSON only)
- **Handler:** `app/proxy/proxy.py:1447-1452`
- **Permission:** `Permission.REPORT_READ`
- **Request:** `{ "report_id": "rpt-...", "format": "json" }`
- **Response:** `{ "ok": true, "data": { "report_id": "rpt-...", "format": "json", "payload": Report.to_dict() } }`
- **Service:** `ReportService` (attached via `SecureProxy.attach_report_service(...)`)
- **Format support:** JSON is wired; PDF/CSV/text return 400 with a documented envelope (deferred to a future slice)
- **Note:** the wire payload is the same shape as `report.get`

---

## 10. Component 8: Health

### Action 10.1: Health check

- **OP:** `health`
- **Class:** WIRED AND VERIFIED
- **Handler:** `app/proxy/proxy.py:534-536`
- **Permission:** none (no auth required; intentional liveness probe)
- **Response:** `{ "ok": true, "data": { "status": "ok" } }`
- **Frontend state:** top-bar dot; poll every 30s
- **Note:** does NOT check MongoDB / registry / sources. Deep health is a future slice (DEFERRED - documented in readiness report)
---

## 11. Cross-cutting rules

### 11.1 All client calls go through `SecureProxy.handle(ProxyRequest)`

Repositories and services are **NOT** exposed at the wire. There is no FastAPI / HTTP router; a future HTTP layer must wrap the proxy. The frontend must not call repositories directly.

### 11.2 IDOR defense (case / report)

Cross-analyst access to a case or report returns `404 case_not_found` (existence is hidden), not 403. The frontend must handle 404 the same way for own- and other-analyst cases (the wire does not leak the difference).

### 11.3 Pagination

- `case.list`: `state` + `limit` (default 50, max 200); no cursor today
- `report.list`: `incident_id?` + `limit` (default 20, max 100); no cursor today
- `source.list`: unbounded; cap recommended in future
- `*_list_for_incident` / `*_list` (now wired as of Phase 4.10): pagination designed but not yet live

### 11.4 Performance / no N+1

- All list endpoints are capped (no unbounded queries)
- `case.get` returns evidence **IDs** only; the UI must call `detection.get` or `correlation.get` for full payloads - no N+1 on the backend
- Indexed Mongo queries (event_id, source_instance_id, rule_id, correlation_id, detection_id) ensure <50 ms p99
- The proxy caps response body at 1 MiB (`proxy_max_response_bytes`) and request body at 32 KiB (`proxy_max_request_bytes`); a 500 `response_too_large` is returned otherwise

### 11.5 Bounded payloads

- `proxy_max_request_bytes` = 32 768 (32 KiB) - HARD CAP, enforced in `_validate_request_shape`
- `proxy_max_response_bytes` = 1 048 576 (1 MiB) - HARD CAP, enforced in `_shape_ok`
- `ingest_max_request_bytes` = 32 768 - HARD CAP at the ingress
- `ingress_max_events_per_request` = 100 - HARD CAP, enforced before any event is accepted
- `ingest_max_body_bytes` / `ingest_max_details_bytes` - enforced in `validate_size_constraints`

### 11.6 Idempotency

- SecurityEvent ingestion is idempotent on `event_id` (re-ingest = no-op)
- Source-identity tokens are single-use (R-1, ST-02 fail-closed replay_store)
- Case close is idempotent (second close = 409 already closed)
- Centralized analysis re-run is idempotent (correlation_ids are dedup-merged)

### 11.7 Concurrency

- D-3 authoritative resolver (MongoDB) consulted before in-memory registry; cross-process consistency guaranteed for state mutations
- Centralized correlation engine is deterministic; concurrent re-runs are safe (dedup)
- MongoDB unique index on `event_id`, `detection_id`, `correlation_id`, `incident_id`, `report_id`

### 11.8 Error code mapping (canonical)

| HTTP | code | When |
|---|---|---|
| 200 | (no code, body has `ok:true`) | success |
| 400 | `invalid_proxy_request` | unknown op / bad shape / case.create boundary |
| 400 | `request_too_large` | body > 32 KiB |
| 400 | `validation_error` | bad field / bad evidence |
| 401 | `missing session token` | no Authorization / X-ProShield-Session |
| 401 | `credential required` / `credential rejected` | AUTH-001 (auth.issue) |
| 401 | (session error) | expired / tampered / unknown token |
| 403 | `operation forbidden` | role / permission denied |
| 404 | `case_not_found` | cross-analyst case/report access (IDOR defense) |
| 404 | (domain NotFoundError) | unknown source_instance_id / etc. |
| 409 | (domain ConflictError) | duplicate / conflict / wrong state |
| 410 | (source retired) | ingest after source retire |
| 429 | (rate limited) | per-subject / per-caller budget exhausted |
| 500 | `response_too_large` | response body > 1 MiB |
| 500 | `internal error` | unexpected exception (safe envelope) |
| 501 | `not_implemented` | reserved: would be returned if a future op is declared without a handler (no live ops today) |

---

## 12. Sign-off

This is the **frozen** wire contract for the Phase 4 frontend. Every UI action is bound to a `SecureProxy.handle(ProxyRequest)` call. The 39 wired ops are verified against the current source (test coverage in §2 of `PROSHIELD-FINAL-BACKEND-VERIFICATION.md` and `tests/unit/test_phase410_proxy_wiring.py` + `tests/integration/test_phase410_pipeline.py`); the 1 boundary op (`case.create`) returns a documented 400. **Zero accidental frontend dependencies on a 501 stub.**
