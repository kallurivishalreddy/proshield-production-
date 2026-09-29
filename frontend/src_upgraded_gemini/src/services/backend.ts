/**
 * Typed operation wrappers + raw backend response types for the
 * frozen ProShield wire contract (see
 * `docs/PHASE 4/PROSHIELD-FINAL-FRONTEND-BACKEND-CONTRACT.md`).
 *
 * These wrappers expose ONLY operations the backend actually wires.
 * No operation here is invented; anything the Gemini design needs
 * beyond this list is recorded in `docs/PHASE 4/backend-missing-features.md`.
 */
import { callOrThrow } from "./api";

// ---------------------------------------------------------------- raw shapes

export interface RawIncident {
  incident_id: string;
  human_id: string | null;
  title: string;
  summary: string;
  state: string;
  evidence: {
    event_ids: string[];
    detection_ids: string[];
    correlation_ids: string[];
    rule_references: { rule_id: string; rule_version: number }[];
  };
  severity: string | null;
  confidence: string | null;
  attribution: {
    attacker: string | null;
    target: string | null;
    source_instance_id: string | null;
    provenance: string | null;
  } | null;
  notes: {
    note_id: string;
    author_subject_id: string;
    author_role: string;
    body: string;
    created_at: string;
  }[];
  rule_references: { rule_id: string; rule_version: number }[];
  lifecycle_history: {
    from_state: string | null;
    to_state: string;
    actor_subject_id: string;
    actor_role: string;
    reason: string;
    transitioned_at: string;
  }[];
  report_references: { report_id: string; mode: string; generated_at: string }[];
  centralized_correlation_ids: string[];
  centralized_reasoning: string;
  centralized_failed: boolean;
  centralized_failure_reason: string;
  created_by: string;
  created_at: string;
  updated_at: string;
}

export interface RawDetection {
  detection_id: string;
  human_id: string | null;
  rule_id: string;
  rule_version: number;
  category: string;
  event_id: string;
  evidence_refs: string[];
  reasoning: string;
  severity: string | null;
  source_instance_id: string | null;
  detected_at: string;
  extra: Record<string, unknown>;
}

export interface RawCorrelation {
  correlation_id: string;
  human_id: string | null;
  pattern_id: string;
  pattern_version: number;
  trigger: string;
  key: string[];
  detection_ids: string[];
  event_ids: string[];
  window_start: string;
  window_end: string;
  count: number;
  reasoning: string;
  confidence: string | null;
  correlated_at: string;
  extra: Record<string, unknown>;
}

export interface RawSource {
  source_instance_id: string;
  human_id: string | null;
  source_type: string;
  source: string;
  display_name: string;
  description: string;
  configuration: Record<string, unknown>;
  state: string;
  created_by: string;
  created_at: string;
  updated_by: string;
  updated_at: string;
  last_validation_at: string | null;
  tags: string[];
  asset_tags: string[];
  retired_at: string | null;
  health: {
    state: string;
    status: "ok" | "degraded" | "unknown" | "disabled" | "retired";
    last_received_at: string | null;
    last_validation_at: string | null;
    last_error?: { code?: string; message?: string } | string | null;
  };
  ingest_telemetry: {
    source_instance_id: string;
    received: number;
    accepted: number;
    rejected: number;
    errors: number;
    last_event_at: string | null;
    last_error: string | null;
    last_error_at: string | null;
  } | null;
  // ---- Phase 5.2 Source Architecture 2.0 -------------------------------
  // Server-authoritative capability binding. ``capability_id`` is ``null``
  // for an unbound / quarantined row — it is never a fabricated value and
  // the UI must render that absence truthfully rather than inventing an
  // owner. ``capability_binding_status`` is one of
  // ``bound`` / ``unbound`` / ``requires_verification``.
  capability_id: string | null;
  capability_version: number | null;
  mapping_profile_id: string | null;
  capability_binding_status: string;
  capability_bound_at: string | null;
}

/** One append-only source audit record (Phase 5.2 ``source_audit``). */
export interface RawSourceAuditRecord {
  action: string;
  actor: string;
  source_instance_id: string;
  human_id: string | null;
  capability_id: string | null;
  reason: string | null;
  before: Record<string, unknown>;
  after: Record<string, unknown>;
  changed_fields: string[];
  at: string;
}

/** The Phase 5.2 migration report (dry-run and applied share this shape). */
export interface RawMigrationReport {
  dry_run: boolean;
  migration_version: number;
  sources: {
    scanned: number;
    already_bound: number;
    bound: number;
    quarantined: number;
    unchanged: number;
  };
  rules: {
    scanned: number;
    already_bound: number;
    bound: number;
    ambiguous: number;
  };
  documents_modified: number;
  audit_records_written: number;
  registry_reloaded: number;
  source_changes: {
    source_instance_id: string;
    human_id: string | null;
    source_type: string;
    outcome: string;
    capability_id: string | null;
    capability_version: number | null;
    mapping_profile_id: string | null;
    reason: string;
  }[];
  rule_changes: {
    rule_id: string;
    rule_version: number;
    sources: string[];
    outcome: string;
    capability_id: string | null;
    reason: string;
  }[];
  audit_trail?: RawSourceAuditRecord[];
}

export interface RawRule {
  rule_id: string;
  version: number;
  name: string;
  description: string;
  category: string;
  type: string;
  state: string;
  enabled: boolean;
  severity: string;
  sources: string[];
  /**
   * Phase 5.2 capability ownership, served by `rule.list` / `rule.get`.
   * `null` is the honest "no single capability owns this rule" state
   * (legacy or cross-source) — never a fabricated `conn-*` id.
   */
  capability_id?: string | null;
  event_types: string[];
  tags: string[];
  references: string[];
  combinator: string;
  conditions: Record<string, unknown> | null;
  scope: string[];
  evidence_requirements: string[];
  thresholds: Record<string, number>;
  window_seconds: number | null;
  created_by?: string;
  created_at?: string;
}

export interface RawTimelineItem {
  timeline_item_id: string;
  kind: string;
  source_id: string;
  occurred_at: string;
  description: string;
  reasoning: string;
  evidence_refs: string[];
}

export interface RawReport {
  report_id: string;
  incident_id: string;
  mode: string;
  version: number;
  title: string;
  sections: {
    title: string;
    items: { kind: string; reference_id: string; title: string; text: string }[];
  }[];
  generated_by: string;
  generated_at: string;
  evidence_references: string[];
  rule_references: { rule_id: string; rule_version: number }[];
  is_centralized: boolean;
  centralized_correlation_ids: string[];
}

export interface RawCapability {
  capability_id: string;
  human_id: string | null;
  name: string;
  description: string;
  responsibility: string;
  implementation_ref: string;
  version: number;
  status: string;
  configuration_schema: Record<string, unknown>;
  mapping_profiles: { profile_id: string; source_type: string; field_map: Record<string, string> }[];
  rule_ids: string[];
  pattern_ids: string[];
  source_count?: number | null;
  created_by: string;
  created_at: string;
  updated_by: string;
  updated_at: string;
  retired_at: string | null;
  archived_at: string | null;
}

export interface RawOverviewSummary {
  open_cases: number;
  open_detections: number;
  open_correlations: number;
  active_rules: number;
}

// ---------------------------------------------------------------- operations

export const ops = {
  health: () => callOrThrow("health", {}),
  overviewSummary: () => callOrThrow<RawOverviewSummary>("overview.summary", {}),

  listCases: (state?: "open" | "closed", limit = 200) =>
    callOrThrow<{ cases: RawIncident[] }>("case.list", { state, limit }),
  getCase: (incidentId: string) =>
    callOrThrow<{ case: RawIncident }>("case.get", { incident_id: incidentId }),
  closeCase: (incidentId: string, reason: string) =>
    callOrThrow<{ case: RawIncident }>("case.close", { incident_id: incidentId, reason }),
  centralized: (incidentId: string, reason: string) =>
    callOrThrow<{
      case: RawIncident;
      failed: boolean;
      failure_reason: string | null;
      new_correlation_ids: string[];
    }>("case.centralized", { incident_id: incidentId, reason }),

  listDetections: (limit = 200) =>
    callOrThrow<{ detections: RawDetection[] }>("detection.list", { limit }),
  listDetectionsForIncident: (incidentId: string) =>
    callOrThrow<{ detections: RawDetection[] }>("detection.list_for_incident", {
      incident_id: incidentId,
    }),

  listCorrelationsByPattern: (patternId: string, limit = 200) =>
    callOrThrow<{ correlations: RawCorrelation[] }>("correlation.list", {
      pattern_id: patternId,
      limit,
    }),
  listCorrelationsForIncident: (incidentId: string) =>
    callOrThrow<{ correlations: RawCorrelation[] }>("correlation.list_for_incident", {
      incident_id: incidentId,
    }),

  listSources: () =>
    callOrThrow<{ sources: RawSource[]; supported_connector_types: string[] }>("source.list", {}),
  listSourceTypes: () =>
    callOrThrow<{ supported_connector_types: string[] }>("source.list_types", {}),
  registerSource: (body: {
    source_type: string;
    display_name: string;
    description?: string;
    tags?: string[];
    asset_tags?: string[];
    // Phase 5.2: optional explicit capability binding. When omitted the
    // backend resolves the capability deterministically from source_type —
    // the client can never *choose* an arbitrary capability for a new
    // source, it can only request one the server then validates.
    capability_id?: string;
    mapping_profile_id?: string;
  }) => callOrThrow<{ source: RawSource }>("source.register", body),
  configureSource: (sourceInstanceId: string, configuration: Record<string, unknown>) =>
    callOrThrow<{ source: RawSource }>("source.configure", {
      source_instance_id: sourceInstanceId,
      configuration,
    }),
  validateSource: (sourceInstanceId: string) =>
    callOrThrow<{ source: RawSource }>("source.validate", { source_instance_id: sourceInstanceId }),
  enableSource: (sourceInstanceId: string) =>
    callOrThrow<{ source: RawSource }>("source.enable", { source_instance_id: sourceInstanceId }),
  disableSource: (sourceInstanceId: string) =>
    callOrThrow<{ source: RawSource }>("source.disable", { source_instance_id: sourceInstanceId }),
  retireSource: (sourceInstanceId: string) =>
    callOrThrow<{ source: RawSource }>("source.retire", { source_instance_id: sourceInstanceId }),
  issueSourceToken: (sourceInstanceId: string, lifetimeSeconds = 3600) =>
    callOrThrow<{ source_instance_id: string; source_token: string; expires_at: string }>(
      "source.issue_token",
      { source_instance_id: sourceInstanceId, lifetime_seconds: lifetimeSeconds }
    ),

  // ---------------- Phase 5.2 Source Architecture 2.0 ----------------
  // Real SecureProxy source.* operations. Every call below maps 1:1 to
  // app/proxy/proxy.py OP_SOURCE_* dispatch; there is no client-side
  // capability authority anywhere in this file.
  bindSourceCapability: (
    sourceInstanceId: string,
    capabilityId: string,
    mappingProfileId?: string | null
  ) =>
    callOrThrow<{ source: RawSource }>("source.bind_capability", {
      source_instance_id: sourceInstanceId,
      capability_id: capabilityId,
      ...(mappingProfileId ? { mapping_profile_id: mappingProfileId } : {}),
    }),
  rotateSourceToken: (sourceInstanceId: string) =>
    callOrThrow<{ source_instance_id: string; source_token: string; rotated: boolean }>(
      "source.rotate_token",
      { source_instance_id: sourceInstanceId }
    ),
  sourceAudit: (sourceInstanceId: string, limit = 50) =>
    callOrThrow<{ source_instance_id: string; audit: RawSourceAuditRecord[] }>(
      "source.audit",
      { source_instance_id: sourceInstanceId, limit }
    ),
  sourceMigrationStatus: () =>
    callOrThrow<RawMigrationReport>("source.migration_status", {}),
  sourceMigrate: (dryRun = true, includeRules = true) =>
    callOrThrow<RawMigrationReport>("source.migrate", {
      dry_run: dryRun,
      include_rules: includeRules,
    }),

  listRules: () => callOrThrow<{ rules: RawRule[] }>("rule.list", { latest_only: true }),
  getRule: (ruleId: string) => callOrThrow<{ rule: RawRule }>("rule.get", { rule_id: ruleId }),
  createRule: (body: Record<string, unknown>) => callOrThrow<{ rule: RawRule }>("rule.create", body),
  enableRule: (ruleId: string) => callOrThrow<{ rule: RawRule }>("rule.enable", { rule_id: ruleId }),
  disableRule: (ruleId: string) =>
    callOrThrow<{ rule: RawRule }>("rule.disable", { rule_id: ruleId }),
  retireRule: (ruleId: string) => callOrThrow<{ rule: RawRule }>("rule.retire", { rule_id: ruleId }),

  // ---------------- Phase 5.1 Capability Registry ----------------
  // Real SecureProxy capability.* operations. No fake APIs: every call
  // below maps 1:1 to app/proxy/proxy.py OP_CAPABILITY_* dispatch.
  listCapabilities: (status?: string, limit = 200) =>
    callOrThrow<{ capabilities: RawCapability[]; count: number }>("capability.list", { status, limit }),
  getCapability: (capabilityId: string) =>
    callOrThrow<{ capability: RawCapability }>("capability.get", { capability_id: capabilityId }),
  createCapability: (body: {
    capability_id: string;
    name: string;
    description?: string;
    responsibility?: string;
    implementation_ref?: string;
    version?: number;
    status?: string;
    configuration_schema?: Record<string, unknown>;
    mapping_profiles?: { profile_id: string; source_type: string; field_map: Record<string, string> }[];
  }) => callOrThrow<{ capability: RawCapability }>("capability.create", body),
  updateCapability: (body: {
    capability_id: string;
    name?: string;
    description?: string;
    responsibility?: string;
    configuration_schema?: Record<string, unknown>;
    mapping_profiles?: { profile_id: string; source_type: string; field_map: Record<string, string> }[];
    version?: number;
  }) => callOrThrow<{ capability: RawCapability }>("capability.update", body),
  capabilityLifecycle: (action: 'enable' | 'disable' | 'deprecate' | 'retire' | 'archive', capabilityId: string) =>
    // capability.enable / capability.disable / capability.deprecate /
    // capability.retire / capability.archive (one wire op per lifecycle action)
    callOrThrow<{ capability: RawCapability }>(`capability.${action}`, { capability_id: capabilityId }),
  listCapabilitySources: (capabilityId: string, limit = 50) =>
    callOrThrow<{ capability_id: string; sources: RawSource[]; count: number }>(
      "capability.list_sources", { capability_id: capabilityId, limit }),
  listCapabilityRules: (capabilityId: string, limit = 50) =>
    callOrThrow<{ capability_id: string; rules: RawRule[]; count: number }>(
      "capability.list_rules", { capability_id: capabilityId, limit }),
  listCapabilityPatterns: (capabilityId: string) =>
    callOrThrow<{ capability_id: string; patterns: { pattern_id: string; pattern_version: number; trigger: string; threshold?: number; window_seconds?: number }[]; count: number }>(
      "capability.list_patterns", { capability_id: capabilityId }),

  // §18.27 persisted audit trail (append-only, newest first).
  listCapabilityAudit: (capabilityId: string, limit = 50) =>
    callOrThrow<{ capability_id: string; records: { action: string; actor: string; capability_id: string; human_id?: string | null; before?: Record<string, unknown> | null; after?: Record<string, unknown> | null; changed_fields?: string[]; at: string }[]; count: number }>(
      "capability.audit", { capability_id: capabilityId, limit }),

  // The live handler returns the TimelineResult directly: data.items
  // (not nested under a "timeline" key).
  timelineForIncident: (incidentId: string) =>
    callOrThrow<{ items: RawTimelineItem[] }>("timeline.build_for_incident", {
      incident_id: incidentId,
    }),

  // NOTE: the live handler REQUIRES incident_id (the frozen contract's
  // `incident_id?` is optional only on paper) — reports are fetched
  // per-case by the client.
  listReports: (incidentId: string, limit = 100) =>
    callOrThrow<{ reports: RawReport[] }>("report.list", { incident_id: incidentId, limit }),
  generateNormalReport: (incidentId: string, title: string) =>
    callOrThrow<{ report: RawReport }>("report.generate_normal", { incident_id: incidentId, title }),
  generateCentralizedReport: (incidentId: string, title: string) =>
    callOrThrow<{ report: RawReport }>("report.generate_centralized", {
      incident_id: incidentId,
      title,
    }),
  getReport: (reportId: string) =>
    callOrThrow<{ report: RawReport }>("report.get", { report_id: reportId }),
  exportReport: (reportId: string) =>
    callOrThrow<{ report_id: string; format: string; payload: RawReport }>("report.export", {
      report_id: reportId,
      format: "json",
    }),
  exportReportAs: (
    reportId: string,
    format: "json" | "markdown" | "csv" | "pdf"
  ) =>
    callOrThrow<{
      report_id: string;
      format: string;
      media_type: string;
      file_extension: string;
      content_base64: string;
      content_bytes: number;
      content_text: string | null;
    }>("report.export", { report_id: reportId, format }),

  // ---------------- capability patch ops (gaps 1-15) ----------------
  acknowledgeCase: (incidentId: string, reason = "") =>
    callOrThrow<{ case: RawIncident }>("case.acknowledge", {
      incident_id: incidentId,
      reason,
    }),
  investigateCase: (incidentId: string, reason = "") =>
    callOrThrow<{ case: RawIncident }>("case.investigate", {
      incident_id: incidentId,
      reason,
    }),
  addCaseNote: (incidentId: string, body: string) =>
    callOrThrow<{ case: RawIncident; note: RawIncident["notes"][number] | null }>(
      "case.note.add",
      { incident_id: incidentId, body }
    ),
  createCaseFromCorrelation: (correlationId: string, title?: string) =>
    callOrThrow<{
      case: RawIncident;
      correlation_id: string;
      created: boolean;
      evidence_resolved: { events: number; detections: number };
    }>("case.create_from_correlation", {
      correlation_id: correlationId,
      title,
    }),
  listCorrelationPatterns: () =>
    callOrThrow<{
      patterns: {
        pattern_id: string;
        pattern_version: number;
        trigger: string;
        threshold?: number;
        window_seconds?: number;
      }[];
    }>("correlation.list_patterns", {}),
  deepHealth: () =>
    callOrThrow<{
      health: {
        status: string;
        backend_kind: string;
        checked_at: string;
        subsystems: {
          name: string;
          status: string;
          detail: string;
          latency_ms: number;
          [k: string]: unknown;
        }[];
      };
    }>("system.health.deep", {}),
  listNotifications: (unreadOnly = false, limit = 50) =>
    callOrThrow<{
      notifications: {
        notification_id: string;
        kind: string;
        incident_id: string | null;
        human_id: string | null;
        title: string;
        detail: string | null;
        actor_subject_id: string | null;
        read: boolean;
        created_at: string;
      }[];
      count: number;
    }>("notification.list", { unread_only: unreadOnly, limit }),
  markNotificationRead: (notificationId: string) =>
    callOrThrow<{ notification: { notification_id: string; read: boolean } }>(
      "notification.mark_read",
      { notification_id: notificationId }
    ),
  unreadNotificationCount: () =>
    callOrThrow<{ unread_count: number }>("notification.unread_count", {}),
  globalTimeline: (body: {
    since?: string;
    until?: string;
    kinds?: string[];
    limit?: number;
    offset?: number;
  } = {}) =>
    callOrThrow<{
      items: {
        kind: string;
        timestamp: string;
        item_id: string;
        human_id?: string | null;
        title: string;
        source?: string;
        detail: Record<string, unknown>;
      }[];
      total_returned: number;
      total_matched: number;
      truncated: boolean;
      offset: number;
      limit: number;
    }>("timeline.global_query", body),
  overviewTimeseries: (hours = 24) =>
    callOrThrow<{
      bucket: string;
      hours: number;
      since: string;
      until: string;
      series: {
        bucket: string;
        detections: number;
        critical: number;
        high: number;
        medium: number;
        low: number;
        unrated: number;
      }[];
      truncated: boolean;
    }>("overview.timeseries", { hours }),
};


