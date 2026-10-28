/**
 * Backend → Gemini view-model adapters.
 *
 * Truth rules enforced here:
 * - A field the backend does not supply is `null` / `undefined` / `""` —
 *   never a fabricated value.
 * - Human-readable ids (CASE-01, DET-01, CORR-01, SRC-01, RULE-01) are
 *   derived client-side from stable backend ordering (created_at /
 *   detected_at / correlated_at ascending). The backend wire contract has
 *   no human-id field today; this is a documented backend gap, not a
 *   data fabrication (the technical id remains attached as internalUuid).
 * - attacker/target attribution for cases/correlations is derived ONLY
 *   from the real correlation `key.parts` (source_ip, endpoint_key)
 *   produced by the backend's brute-force clustering pattern.
 */
import type {
  RawCapability,
  RawCorrelation,
  RawDetection,
  RawIncident,
  RawReport,
  RawRule,
  RawSource,
  RawTimelineItem,
} from "./backend";
import type {
  Case,
  Capability,
  Correlation,
  Detection,
  HealthSubsystem,
  Report,
  Rule,
  SourceInstance,
  TimelineEvent,
} from "../types/soc";

function pad(n: number): string {
  return n < 10 ? `0${n}` : `${n}`;
}

function assignHumanIds<T>(items: T[], prefix: string, keyOf: (item: T) => string): Map<T, string> {
  const sorted = [...items].sort((a, b) => {
    const ka = keyOf(a) || "";
    const kb = keyOf(b) || "";
    if (ka === kb) return 0;
    return ka < kb ? -1 : 1;
  });
  const map = new Map<T, string>();
  sorted.forEach((item, idx) => map.set(item, `${prefix}-${pad(idx + 1)}`));
  return map;
}

function normalizeSeverity(s: string | null | undefined): string | null {
  if (!s) return null;
  const up = s.toUpperCase();
  if (["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"].includes(up)) return up;
  return null;
}

function mapCaseState(state: string): Case["status"] {
  switch (state) {
    case "open":
      return "OPEN";
    case "closed":
      return "CLOSED";
    case "acknowledged":
      return "ACKNOWLEDGED";
    case "investigating":
      return "INVESTIGATING";
    default:
      return "OPEN";
  }
}

export interface AdaptedData {
  cases: Case[];
  detections: Detection[];
  correlations: Correlation[];
  caseIdByHumanId: Map<string, string>;
  humanIdByCorrelationId: Map<string, string>;
  humanIdByDetectionId: Map<string, string>;
  caseOfDetection: Map<string, string>;
  caseOfCorrelation: Map<string, string>;
  centralizedCorrIds: Set<string>;
}

export function adaptBackendData(input: {
  incidents: RawIncident[];
  detections: RawDetection[];
  correlations: RawCorrelation[];
}): AdaptedData {
  const { incidents, detections, correlations } = input;

  // Capability patch gap 2: the backend now assigns PERSISTED human ids
  // (CASE-000001 …) at entity creation. The client-side derivation is
  // kept ONLY as a fallback for legacy rows created before the
  // allocator existed — when both exist the backend id always wins.
  const caseHuman = assignHumanIds(incidents, "CASE", (i) => i.created_at);
  const detHuman = assignHumanIds(detections, "DET", (d) => d.detected_at);
  const corrHuman = assignHumanIds(correlations, "CORR", (c) => c.correlated_at);
  for (const inc of incidents) {
    if (inc.human_id) caseHuman.set(inc, inc.human_id);
  }
  for (const det of detections) {
    if (det.human_id) detHuman.set(det, det.human_id);
  }
  for (const corr of correlations) {
    if (corr.human_id) corrHuman.set(corr, corr.human_id);
  }

  const humanIdByDetectionId = new Map<string, string>();
  detHuman.forEach((humanId, det) => humanIdByDetectionId.set(det.detection_id, humanId));
  const humanIdByCorrelationId = new Map<string, string>();
  corrHuman.forEach((humanId, corr) => humanIdByCorrelationId.set(corr.correlation_id, humanId));

  const caseIdByHumanId = new Map<string, string>();
  const humanIdByCaseId = new Map<string, string>();
  caseHuman.forEach((humanId, inc) => {
    caseIdByHumanId.set(humanId, inc.incident_id);
    humanIdByCaseId.set(inc.incident_id, humanId);
  });

  const caseOfCorrelation = new Map<string, string>();
  const caseOfDetection = new Map<string, string>();
  for (const inc of incidents) {
    const humanId = humanIdByCaseId.get(inc.incident_id);
    if (!humanId) continue;
    for (const cid of inc.evidence.correlation_ids) {
      if (!caseOfCorrelation.has(cid)) caseOfCorrelation.set(cid, humanId);
    }
    for (const did of inc.evidence.detection_ids) {
      if (!caseOfDetection.has(did)) caseOfDetection.set(did, humanId);
    }
  }

  const centralizedCorrIds = new Set<string>();
  for (const inc of incidents) {
    for (const cid of inc.centralized_correlation_ids) centralizedCorrIds.add(cid);
  }

  const cases: Case[] = incidents.map((inc) => {
    const humanId = caseHuman.get(inc) as string;
    // Capability patch gap 3: the backend composes the attribution at
    // case assembly (with provenance). The correlation-key derivation
    // below is only the legacy fallback.
    let attackerIp: string | null = inc.attribution?.attacker ?? null;
    let targetAsset: string | null = inc.attribution?.target ?? null;
    const sourceInstanceId = inc.attribution?.source_instance_id ?? null;
    const attributionProvenance = inc.attribution?.provenance ?? null;
    if (!attackerIp || !targetAsset) {
      for (const cid of inc.evidence.correlation_ids) {
        const corr = correlations.find((c) => c.correlation_id === cid);
        if (corr && corr.key && corr.key.length > 0) {
          if (!attackerIp) attackerIp = corr.key[0] || null;
          if (!targetAsset && corr.key.length > 1) targetAsset = corr.key[1] || null;
          break;
        }
      }
    }
    const caseNotes = (inc.notes || []).map((n) => ({
      id: n.note_id,
      author: n.author_subject_id,
      timestamp: n.created_at,
      text: n.body,
      persisted: true,
    }));
    return {
      humanId,
      internalUuid: inc.incident_id,
      title: inc.title,
      description: inc.summary || "",
      severity: normalizeSeverity(inc.severity) as Case["severity"],
      status: mapCaseState(inc.state),
      sourceId: sourceInstanceId || "",
      sourceName: sourceInstanceId || "",
      attackerIp: attackerIp || "",
      attackerCountry: "",
      targetAsset: targetAsset || "",
      firstSeen: inc.created_at,
      lastSeen: inc.updated_at,
      eventCount: inc.evidence.event_ids.length,
      detectionCount: inc.evidence.detection_ids.length,
      correlationCount: inc.evidence.correlation_ids.length,
      mitreTactics: [],
      notes: caseNotes,
      attributionProvenance: attributionProvenance || undefined,
      isCorrelated: inc.evidence.correlation_ids.length > 0,
      centralizedAnalysisDone: inc.centralized_correlation_ids.length > 0,
      closureNotes:
        inc.state === "closed"
          ? inc.lifecycle_history
              .filter((h) => h.to_state === "closed")
              .map((h) => h.reason)
              .join(" ") || undefined
          : undefined,
      closedAt:
        inc.state === "closed"
          ? inc.lifecycle_history
              .filter((h) => h.to_state === "closed")
              .map((h) => h.transitioned_at)[0]
          : undefined,
    };
  });

  return {
    cases,
    detections: [],
    correlations: [],
    caseIdByHumanId,
    humanIdByCorrelationId,
    humanIdByDetectionId,
    caseOfDetection,
    caseOfCorrelation,
    centralizedCorrIds,
  };
}

/** Build Detection view models from raw detections + reference maps. */
export function buildDetectionViews(
  raws: RawDetection[],
  refs: {
    humanIdByDetectionId: Map<string, string>;
    caseOfDetection: Map<string, string>;
  }
): Detection[] {
  return raws.map((det) => {
    const matchedFields: { field: string; value: string }[] = [];
    if (det.extra && typeof det.extra === "object") {
      for (const [k, v] of Object.entries(det.extra)) {
        if (v !== null && typeof v !== "object") {
          matchedFields.push({ field: k, value: String(v) });
        }
      }
    }
    return {
      // Capability patch gaps 2+5: backend-assigned human id, the
      // SeverityEngine-composed severity band and the ingesting
      // source's provenance pointer — all persisted backend state.
      humanId: det.human_id || refs.humanIdByDetectionId.get(det.detection_id) || det.detection_id,
      internalUuid: det.detection_id,
      title: det.reasoning || det.rule_id,
      ruleId: det.rule_id,
      ruleName: det.rule_id,
      eventId: det.event_id || "",
      capabilityId: det.capability_id || "",
      sourceId: det.source_instance_id || "",
      sourceName: det.source_instance_id || "",
      severity: normalizeSeverity(det.severity) as Detection["severity"],
      timestamp: det.detected_at,
      firstSeen: det.detected_at,
      lastSeen: det.detected_at,
      evidenceSummary: det.reasoning || "",
      rawPayload: {
        detection_id: det.detection_id,
        rule_id: det.rule_id,
        rule_version: det.rule_version,
        category: det.category,
        event_id: det.event_id,
        capability_id: det.capability_id,
        source_instance_id: det.source_instance_id,
        evidence_refs: det.evidence_refs,
        reasoning: det.reasoning,
        extra: det.extra,
      },
      caseId: refs.caseOfDetection.get(det.detection_id),
      correlationId: undefined,
      matchedFields,
      attackerIp: undefined,
      targetAsset: undefined,
    };
  });
}

/** Build Correlation view models from raw correlations + reference maps. */
export function buildCorrelationViews(
  raws: RawCorrelation[],
  refs: {
    humanIdByCorrelationId: Map<string, string>;
    humanIdByDetectionId: Map<string, string>;
    caseOfCorrelation: Map<string, string>;
    centralizedCorrIds: Set<string>;
  }
): Correlation[] {
  return raws.map((corr) => {
    return {
      humanId: refs.humanIdByCorrelationId.get(corr.correlation_id) || corr.correlation_id,
      internalUuid: corr.correlation_id,
      title: `${corr.pattern_id} (${corr.key.join(" · ")})`,
      pattern: corr.pattern_id,
      severity: null as Correlation["severity"],
      sourceId: "",
      sourceName: "",
      attacker: corr.key[0] || "",
      target: corr.key[1] || "",
      timeWindow: `${corr.window_start} → ${corr.window_end}`,
      detectionCount: corr.count,
      eventCount: corr.event_ids.length,
      detectionIds: corr.detection_ids
        .map((did) => refs.humanIdByDetectionId.get(did))
        .filter((x): x is string => !!x),
      caseId: refs.caseOfCorrelation.get(corr.correlation_id) || "",
      description: corr.reasoning || "",
      confidenceScore: null as Correlation["confidenceScore"],
      confidenceBand: (corr.confidence || null) as Correlation["confidenceBand"],
      centralizedAnalysisRan: refs.centralizedCorrIds.has(corr.correlation_id),
      crossSourceRelationships: [],
    };
  });
}

/** Attach correlation membership onto already-built detection views. */
export function linkDetectionsToCorrelations(detections: Detection[], correlations: RawCorrelation[], humanIdByCorrelationId: Map<string, string>): void {
  const corrOfDetection = new Map<string, string>();
  for (const corr of correlations) {
    for (const did of corr.detection_ids) {
      if (!corrOfDetection.has(did)) corrOfDetection.set(did, corr.correlation_id);
    }
  }
  for (const det of detections) {
    const cid = corrOfDetection.get(det.internalUuid);
    if (cid) det.correlationId = humanIdByCorrelationId.get(cid);
  }
}

export function adaptSources(
  raw: RawSource[],
  capabilities?: Capability[]
): SourceInstance[] {
  const human = assignHumanIds(raw, "SRC", (s) => s.created_at);
  const nameById = new Map<string, string>();
  // Phase 5.2: the friendly label is resolved from the REAL capability
  // registry rows (snake_case `capability_id` / `name`), not from a legacy
  // connector-chip shape.
  for (const c of capabilities || []) nameById.set(c.capability_id, c.name);
  return raw.map((s) => {
    const lastError = s.health?.last_error;
    const errorDetails =
      lastError && typeof lastError === "object" && lastError.message
        ? {
            code: 0,
            message: String(lastError.message),
            suggestion: "Review the source configuration and validate the connection.",
            timestamp: s.health.last_received_at || s.updated_at,
          }
        : undefined;
    const config = s.configuration || {};
    const endpoint = typeof config.endpoint === "string" ? config.endpoint : "";
    // ---- Phase 5.2 capability binding (server-authoritative) -------------
    // The backend is the ONLY source of truth here. An unbound or
    // quarantined row reports an empty capability id and the truthful
    // binding status; the UI must never invent a `conn-*` pseudo-capability
    // that does not exist in the capability registry.
    const bindingStatus: SourceInstance["capabilityBindingStatus"] =
      s.capability_binding_status === "bound"
        ? "bound"
        : s.capability_binding_status === "requires_verification"
        ? "requires_verification"
        : "unbound";
    const capabilityId = s.capability_id || "";
    return {
      // Capability patch gap 2: the backend-assigned human id wins;
      // the client-side derivation is only the legacy-row fallback.
      humanId: s.human_id || (human.get(s) as string),
      internalUuid: s.source_instance_id,
      name: s.display_name,
      description: s.description || "",
      capabilityId,
      capabilityVersion: s.capability_version ?? null,
      mappingProfileId: s.mapping_profile_id ?? null,
      capabilityBindingStatus: bindingStatus,
      capabilityBoundAt: s.capability_bound_at ?? null,
      capabilityName: capabilityId ? nameById.get(capabilityId) || capabilityId : "",
      endpoint,
      tags: s.tags || [],
      status:
        s.state === "enabled"
          ? ("ENABLED" as const)
          : s.state === "retired"
          ? ("RETIRED" as const)
          : ("DISABLED" as const),
      lifecycleState: s.state,
      validationState: s.last_validation_at ? "VALID" : "PENDING",
      ingestToken: "",
      tokenCreated: s.last_validation_at || "",
      // The backend refuses token issuance unless the source is VALIDATED
      // or ENABLED *and* bound. The UI mirrors that so the button state is
      // truthful instead of offering an action that will 409.
      tokenIssuable:
        bindingStatus === "bound" &&
        (s.state === "validated" || s.state === "enabled"),
      eventsPerSec: 0,
      lastActivity: s.ingest_telemetry?.last_event_at || s.health?.last_received_at || "",
      // Capability patch gap 9: truthful per-source ingest telemetry
      // maintained at the ingress boundary (accepted/rejected/errors
      // counters + last error). Null = no telemetry recorded yet.
      ingestTelemetry: s.ingest_telemetry
        ? {
            received: s.ingest_telemetry.received,
            accepted: s.ingest_telemetry.accepted,
            rejected: s.ingest_telemetry.rejected,
            errors: s.ingest_telemetry.errors,
            lastEventAt: s.ingest_telemetry.last_event_at,
            lastError: s.ingest_telemetry.last_error,
          }
        : null,
      errorDetails,
      metrics: {
        totalEvents24h: null as unknown as number,
        detections24h: null as unknown as number,
        latencyMs: null as unknown as number,
      },
    };
  });
}

export function adaptRules(
  raw: RawRule[],
  detections: Detection[],
  capabilities: Capability[] = []
): Rule[] {
  const human = assignHumanIds(raw, "RULE", (r) => r.rule_id);
  // Phase 5.2: a rule's owner is the capability id the BACKEND resolved
  // (`rule.capability_id`), resolved here to its registry display name. The
  // previous `conn-${sources[0]}` pseudo-id was an invention no capability
  // ever held — it is never emitted again.
  const nameById = new Map(capabilities.map((c) => [c.capability_id, c.name]));
  return raw.map((r) => {
    const affected = detections.filter((d) => d.ruleId === r.rule_id).length;
    let lifecycleStatus: Rule["lifecycleStatus"];
    if (r.state === "retired") lifecycleStatus = "RETIRED";
    else if (r.state === "candidate") lifecycleStatus = "TESTING";
    else if (r.enabled) lifecycleStatus = "ACTIVE";
    else lifecycleStatus = "DISABLED";
    const thr = (r.thresholds && typeof r.thresholds === "object"
      ? r.thresholds
      : {}) as Record<string, number>;
    const capabilityId = r.capability_id ?? "";
    return {
      humanId: human.get(r) as string,
      internalUuid: r.rule_id,
      name: r.name || r.rule_id,
      description: r.description || "",
      severity: normalizeSeverity(r.severity) as Rule["severity"],
      capabilityId,
      // Empty when the backend reported no capability owner (legacy or
      // cross-source rule). The UI shows its real `sources[]` scope instead
      // of inventing a capability.
      capabilityName: capabilityId ? nameById.get(capabilityId) || capabilityId : "",
      scope: r.sources || [],
      logicCode: r.conditions ? JSON.stringify(r.conditions, null, 2) : "",
      dslType: undefined,
      lifecycleStatus,
      lastModified: r.created_at || "",
      affectedDetectionsCount: affected,
      author: r.created_by || "",
      thresholds:
        r.window_seconds != null
          ? { count: Number(thr["threshold"] ?? thr["count"] ?? 0), timeframeSec: r.window_seconds }
          : undefined,
    };
  });
}

const KIND_TYPE_MAP: Record<string, TimelineEvent["type"]> = {
  event: "EVENT",
  detection: "DETECTION",
  correlation: "CORRELATION",
};

export function adaptTimelineItems(raw: RawTimelineItem[], caseHumanId?: string): TimelineEvent[] {
  return raw.map((item) => ({
    id: item.timeline_item_id,
    humanId: caseHumanId,
    timestamp: item.occurred_at,
    type: KIND_TYPE_MAP[item.kind] || "EVENT",
    title: item.description || item.kind,
    severity: null as TimelineEvent["severity"],
    sourceName: item.source_id || "",
    shortExplanation: item.reasoning || item.description || "",
    caseId: caseHumanId,
    rawPayload: {
      timeline_item_id: item.timeline_item_id,
      kind: item.kind,
      source_id: item.source_id,
      evidence_refs: item.evidence_refs,
    },
  }));
}

export function adaptReports(raw: RawReport[]): Report[] {
  return raw.map((r) => ({
    id: r.report_id,
    humanId: r.report_id,
    title: r.title,
    type: r.is_centralized ? "CENTRALIZED_ANALYSIS" : "CASE_SUMMARY",
    caseId: r.incident_id,
    generatedAt: r.generated_at,
    author: r.generated_by,
    summary:
      r.sections
        .flatMap((s) => s.items.map((i) => i.text))
        .slice(0, 3)
        .join(" ") || "",
    findings: r.sections.flatMap((s) => s.items.map((i) => i.text)),
    recommendations: [],
    mitreMatrix: [],
    isCentralized: r.is_centralized,
    raw: r,
  }));
}

/** Phase 5.1: the REAL Capability Registry from capability.list/get.
 *  No derivation from source.list_types, no static catalog, no fake rows.
 *  rule_ids/pattern_ids/source_count arrive as derived backend views. */
export function adaptCapabilities(raw: RawCapability[]): Capability[] {
  return (raw || []).map((c) => ({
    capability_id: c.capability_id,
    human_id: c.human_id ?? null,
    name: c.name,
    description: c.description ?? "",
    responsibility: c.responsibility ?? "",
    implementation_ref: (c.implementation_ref === 'nginx' || c.implementation_ref === 'simulator')
      ? c.implementation_ref
      : 'planned',
    version: c.version,
    status: c.status as Capability['status'],
    configuration_schema: c.configuration_schema ?? {},
    mapping_profiles: (c.mapping_profiles ?? []).map((p) => ({
      profile_id: p.profile_id,
      source_type: p.source_type,
      field_map: { ...(p.field_map ?? {}) },
    })),
    rule_ids: [...(c.rule_ids ?? [])],
    pattern_ids: [...(c.pattern_ids ?? [])],
    source_count: c.source_count ?? null,
    created_by: c.created_by,
    created_at: c.created_at,
    updated_by: c.updated_by,
    updated_at: c.updated_at,
    retired_at: c.retired_at ?? null,
    archived_at: c.archived_at ?? null,
  }));
}

/** Capability patch gap 8: render the backend's truthful per-subsystem
 *  deep health (healthy / degraded / unavailable / not_configured).
 *  A dead dependency arrives as UNAVAILABLE — never translated into a
 *  green row client-side. */
export function adaptDeepHealth(
  report: {
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
  } | null
): HealthSubsystem[] {
  if (!report || !Array.isArray(report.subsystems)) return [];
  return report.subsystems.map((s) => {
    const status =
      s.status === "healthy" ? "HEALTHY" as const
      : s.status === "degraded" ? "WARNING" as const
      : s.status === "unavailable" ? "CRITICAL" as const
      : "UNKNOWN" as const;
    const broken = s.status === "unavailable" || s.status === "degraded";
    return {
      id: `sub-deep-${s.name}`,
      name: `Subsystem: ${s.name.replace(/_/g, " ")}`,
      category: "SYSTEM" as any,
      status,
      latencyMs: s.latency_ms ?? 0,
      throughput: "—",
      uptime: "—",
      whatIsWrong: broken ? s.detail : undefined,
      severityExplanation: broken
        ? `The backend reports this subsystem as ${s.status.toUpperCase()}.`
        : undefined,
      affectedComponents: broken ? [s.name] : undefined,
      remediationAction:
        s.status === "unavailable"
          ? "Check the backend logs; a failed probe means the subsystem is NOT healthy."
          : undefined,
      lastTested: report.checked_at,
    };
  });
}

export function adaptHealth(
  liveness: { ok: boolean; latencyMs: number | null },
  sources: SourceInstance[]
): HealthSubsystem[] {
  const subs: HealthSubsystem[] = [
    {
      id: "sub-api",
      name: "Backend API Liveness (SecureProxy)",
      category: "API",
      status: liveness.ok ? "HEALTHY" : "CRITICAL",
      latencyMs: liveness.latencyMs ?? 0,
      throughput: "—",
      uptime: "—",
      lastTested: new Date().toISOString(),
    },
  ];
  for (const s of sources) {
    if (s.status === "RETIRED") continue;
    subs.push({
      id: `sub-src-${s.internalUuid}`,
      name: `Source: ${s.name} (${s.humanId})`,
      category: "INGEST",
      status: s.status === "ENABLED" ? "HEALTHY" : "WARNING",
      latencyMs: 0,
      throughput: s.lastActivity ? `last event ${s.lastActivity}` : "no events received",
      uptime: "—",
      whatIsWrong:
        s.status === "ENABLED" ? undefined : `Source instance is not enabled (state: ${s.status}).`,
      severityExplanation:
        s.status === "ENABLED"
          ? undefined
          : "No telemetry is accepted from this source while it is not enabled.",
      affectedComponents: s.status === "ENABLED" ? undefined : [s.humanId],
      remediationAction:
        s.status === "ENABLED"
          ? undefined
          : "Enable the source instance once configuration is validated.",
      lastTested: s.lastActivity || "never",
    });
  }
  return subs;
}
