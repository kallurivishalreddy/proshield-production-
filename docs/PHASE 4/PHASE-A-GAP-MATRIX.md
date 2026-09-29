# Phase A — Confirmed Gap Matrix (verified against current main @ f674f09)

| ID | Feature | Frontend op used | Backend wire op | Service | Repository | Persistence | Confirmed state | Root cause | Owning layer | Patch? |
|----|---------|------------------|-----------------|---------|-----------|-------------|-----------------|------------|--------------|--------|
| 1 | Case acknowledge/investigate | Ack button refuses (no op) | none (`case.close` only) | `IncidentService` open→close only; `IncidentLifecycleState` has NO acknowledged/investigating | n/a | lifecycle_history exists | MISSING | lifecycle closed-set never included analyst triage states | incidents models+service+proxy | YES |
| 2 | Human-readable IDs | client-side `assignHumanIds` derivation | none | none | none | no persisted human id | MISSING (client-derived) | ids derived from created_at ordering in adapters.ts | persistence (creation-time assignment) | YES |
| 3 | Case attribution | derives attacker from correlation key[0] | none | `Incident` carries no attribution | none | none | MISSING | attribution never composed at case assembly | incident assembly + serializer | YES |
| 4 | Case notes | local-only note, "(not persisted)" | none | none | none | none | MISSING | no notes concept | incidents service + new embedded notes + proxy | YES |
| 5 | Detection severity + source | UNRATED badges | `detection.list` has no severity/source | `Detection` has neither; SeverityEngine exists but not applied at persistence | DetectionRepository persists raw | none | MISSING (engine exists unused) | severity composition never wired into pipeline | detection pipeline (has event) + model + validator | YES |
| 6 | Correlation confidence | "Confidence: —" | none | `Correlation` has no confidence; SeverityEngine._score_correlation exists unused | CorrelationRepository persists raw | none | MISSING | per-correlation assessment never composed/persisted | correlation persistence (severity engine) | YES |
| 7 | Pattern catalogue op | frontend hardcodes KNOWN_CORRELATION_PATTERN_ID | none | `correlation.list` requires pattern_id | n/a | n/a | MISSING | no discovery op | correlation service + proxy | YES |
| 8 | Deep health | liveness only | `health` → `{status:ok}` | none | none | none | MISSING | contract §10 documents deferral | new observability health service + proxy | YES |
| 9 | Per-source telemetry | "—" metrics | none | `SourceInstanceHealth.received_count/rejected_count` EXIST but never updated (always 0) | SourceRepository has no counter update | none | PARTIAL (dead fields) | counters defined but no ingress hook | ingress boundary + new telemetry store + source.list merge | YES |
| 10 | Sigma/YARA-L/CEL | modal truthful (structured only) | `rule.create` structured works | RuleManagementService structured only | managed_rules | yes | NOT REQUIRED (no authoritative spec mentions Sigma/YARA/CEL; structured authoring IS the spec'd path — verify it fires live) | design-only affordance | — | VERIFY + DOCUMENT |
| 11 | Case-from-correlation | button implies it | `case.create` always 400 (boundary) | internal `create_case_for_correlation` exists + idempotent | incidents | yes | MISSING wire op (internal capability exists) | deliberate Phase 4.8 boundary; analyst path never exposed | incident service (reuse) + new proxy op with server-side evidence resolution | YES |
| 12 | Notification feed | empty tray | none | none | none | none | MISSING | no notification domain | new notifications package + sink hooks | YES |
| 13 | Global timeline | per-case only | `timeline.build_for_incident` | TimelineReadService per-case | repos have bounded finds | yes | MISSING | only per-incident op shipped | timeline service + proxy | YES |
| 14 | Report exports | JSON only, PDF/CSV → 400 | `report.export` rejects non-json | ReportService builds JSON only | reports | yes | PARTIAL (json works) | no exporters written | reports exporter + proxy | YES |
| 15 | Overview time-series | client-side bucketing | none | OverviewReadService returns 4 counters | detection repo has no time query | yes | MISSING | no aggregate op | overview service + detection repo query + proxy | YES |

Key architectural facts confirmed:
- `SecureProxy.handle(ProxyRequest)` is THE wire boundary; ops dispatched in `_dispatch`; ALLOWED_OPERATIONS set must be extended.
- `IncidentRepository.create` idempotent on duplicate `incident_id`; validator `$jsonSchema` with `additionalProperties: False` on incidents/security_events.
- `detection_id` is content-derived (stable on replay) → new default fields must not alter id derivation.
- `SeverityEngine` already implements `_score_detection`/`_score_correlation`/`_score_bundle` — the documented composition layer.
- `SourceInstanceHealth.received_count/rejected_count` exist but nothing increments them.
- `FakeCollection` (memory backend) supports $match/$sort/$group/$limit — new mongo queries must work on both.
- Permission model: CASE_READ/CASE_READ_ANY/REPORT_*/RULE_*/SOURCE_*/... (no acknowledge-specific permission; reuse CASE_READ + role check mirrors close_case).
