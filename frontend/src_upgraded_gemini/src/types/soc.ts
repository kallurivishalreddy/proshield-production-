export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFORMATIONAL';

export type CaseStatus = 'OPEN' | 'ACKNOWLEDGED' | 'INVESTIGATING' | 'CLOSED';

export type ResolutionReason = 
  | 'TRUE_POSITIVE' 
  | 'BENIGN_TRUE_POSITIVE' 
  | 'FALSE_POSITIVE' 
  | 'DUPLICATE' 
  | 'TEST_DRILL';

export interface Case {
  humanId: string; // e.g. CASE-01 (client-side derivation; backend has no human-id field today)
  internalUuid: string; // backend incident_id (case-<uuid7>)
  title: string;
  description: string;
  /** Backend composes a case-level severity band; null = not composed (render "—", never fabricate). */
  severity: Severity | null;
  status: CaseStatus;
  sourceId: string; // '' — backend does not attribute cases to sources
  sourceName: string; // '' — backend does not attribute cases to sources
  attackerIp: string; // derived from real correlation key parts; '' when unknown
  attackerCountry: string; // '' — backend does not supply geo data
  attackerHost?: string;
  targetAsset: string; // derived from real correlation key parts; '' when unknown
  targetUser?: string;
  firstSeen: string;
  lastSeen: string;
  eventCount: number;
  detectionCount: number;
  correlationCount: number;
  mitreTactics: string[];
  assignedAnalyst?: {
    name: string;
    avatar: string;
    role: string;
  };
  notes: {
    id: string;
    author: string;
    timestamp: string;
    text: string;
    /** true only for notes persisted by the backend. */
    persisted?: boolean;
  }[];
  /** Capability patch gap 3: how the backend derived the attribution
   *  (empty when underivable — never fabricated). */
  attributionProvenance?: string;
  closureReason?: ResolutionReason;
  closureNotes?: string;
  closedAt?: string;
  closedBy?: string;
  isCorrelated: boolean;
  centralizedAnalysisDone?: boolean;
}

export interface Detection {
  humanId: string; // e.g. DET-01
  internalUuid: string;
  title: string;
  ruleId: string; // RULE-01
  ruleName: string;
  eventId: string; // canonical SecurityEvent.event_id
  capabilityId: string; // server-derived provenance.capability_id
  sourceId: string; // source_instance_id
  sourceName: string; // source_instance_id
  /** Backend detections carry no severity — always null today. */
  severity: Severity | null;
  timestamp: string;
  firstSeen: string;
  lastSeen: string;
  evidenceSummary: string;
  rawPayload: Record<string, any>;
  caseId?: string; // CASE-01
  correlationId?: string; // CORR-01
  matchedFields: { field: string; value: string }[];
  attackerIp?: string;
  targetAsset?: string;
}

export interface Correlation {
  humanId: string; // e.g. CORR-01
  internalUuid: string;
  title: string;
  pattern: string;
  /** Backend correlations carry no severity — always null today. */
  severity: Severity | null;
  sourceId: string; // '' — backend correlations do not carry source attribution
  sourceName: string; // ''
  attacker: string;
  target: string;
  timeWindow: string;
  detectionCount: number;
  eventCount: number;
  detectionIds: string[]; // ['DET-01', 'DET-02']
  caseId: string; // CASE-01
  description: string;
  /** Backend does not expose a correlation confidence score — null (render "—"). */
  confidenceScore: number | null;
  /** Capability patch gap 6: the backend-composed ConfidenceBand
   *  (low / medium / high / very_high), persisted with the
   *  correlation. Null when the record predates the patch. */
  confidenceBand: string | null;
  centralizedAnalysisRan: boolean;
  crossSourceRelationships: {
    source: string;
    target: string;
    relation: string;
  }[];
}

export type TimelineEventType = 'EVENT' | 'DETECTION' | 'CORRELATION' | 'CASE_ACTION' | 'ANALYST_NOTE';

export interface TimelineEvent {
  id: string;
  humanId?: string;
  timestamp: string;
  type: TimelineEventType;
  title: string;
  /** Backend timeline items carry no severity — null today. */
  severity: Severity | null;
  sourceName: string;
  shortExplanation: string;
  actor?: string;
  caseId?: string;
  rawPayload?: Record<string, any>;
  mitreTechnique?: string;
}

export interface Capability {
  capability_id: string;
  human_id: string | null;
  name: string;
  description: string;
  responsibility: string;
  implementation_ref: 'nginx' | 'simulator' | 'planned';
  version: number;
  status: 'active' | 'disabled' | 'deprecated' | 'retired' | 'planned' | 'archived';
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

export interface ConnectorCapability {
  id: string; // conn-nginx
  name: string; // NGINX Web Gateway
  /** Derived from the real `source.list_types` catalogue; no static capability catalog exists. */
  category: 'WEB' | 'IDENTITY' | 'CLOUD' | 'ENDPOINT' | 'NETWORK' | 'DATABASE' | 'OTHER';
  description: string;
  version: string;
  supportedProtocols: string[];
  icon: string;
  activeSourceCount: number;
}

export interface SourceInstance {
  humanId: string; // e.g. SRC-01
  internalUuid: string;
  name: string;
  description: string;
  /** Phase 5.2: the REAL capability id (``cap-nginx``) returned by the
   *  backend, or ``''`` when the source has no verified binding. This is
   *  never a client-side invention: an unbound/quarantined source honestly
   *  reports no capability rather than a fabricated ``conn-*`` id. */
  capabilityId: string;
  /** The real capability version the binding was made against (null when
   *  unbound). */
  capabilityVersion: number | null;
  /** The mapping profile resolved from the capability (null when none). */
  mappingProfileId: string | null;
  /** Server-authoritative binding status. ``requires_verification`` means
   *  the source is QUARANTINED: the legacy migration could not resolve an
   *  owner, so ingestion is blocked until an administrator binds one. */
  capabilityBindingStatus: 'bound' | 'unbound' | 'requires_verification';
  capabilityBoundAt: string | null;
  /** Human-friendly capability label resolved from the capability registry
   *  (falls back to the capability id; empty when unbound). */
  capabilityName: string;
  endpoint: string;
  tags: string[];
  status: 'ENABLED' | 'DISABLED' | 'ERROR' | 'RETIRED';
  /** The backend lifecycle state as persisted (registered / configured /
   *  validated / enabled / disabled / retired). Displayed truthfully so an
   *  analyst can see exactly where a source is in the frozen lifecycle. */
  lifecycleState: string;
  validationState: 'VALID' | 'PENDING' | 'INVALID';
  /** NEVER a real token: the backend only returns a token once, at
   *  issuance/rotation time, and it is never re-served by ``source.list``.
   *  Always ``''`` here — the UI shows token *state*, not token material. */
  ingestToken: string;
  tokenCreated: string;
  /** Truthful token/credential state derived from the persisted source. */
  tokenIssuable: boolean;
  eventsPerSec: number;
  lastActivity: string;
  /** Capability patch gap 9: truthful per-source ingest telemetry
   *  from the ingress boundary (null = no telemetry recorded yet). */
  ingestTelemetry?: {
    received: number;
    accepted: number;
    rejected: number;
    errors: number;
    lastEventAt: string | null;
    lastError: string | null;
  } | null;
  errorDetails?: {
    code: number;
    message: string;
    suggestion: string;
    timestamp: string;
  };
  metrics: {
    /** null = the backend does not provide this telemetry (render "—"). */
    totalEvents24h: number | null;
    detections24h: number | null;
    latencyMs: number | null;
  };
}

export interface Rule {
  humanId: string; // e.g. RULE-01
  internalUuid: string;
  name: string;
  description: string;
  severity: Severity | null;
  capabilityId: string;
  capabilityName: string;
  scope: string[];
  logicCode: string;
  /** The backend has no Sigma/YARA-L/CEL DSL — undefined today (documented gap). */
  dslType?: 'SIGMA' | 'YARA_L' | 'CEL';
  lifecycleStatus: 'ACTIVE' | 'TESTING' | 'DISABLED' | 'RETIRED';
  lastModified: string;
  affectedDetectionsCount: number;
  author: string;
  thresholds?: {
    count: number;
    timeframeSec: number;
  };
}

export interface HealthSubsystem {
  id: string;
  name: string;
  category: 'INGEST' | 'PROCESSING' | 'STORAGE' | 'API' | 'ANALYTICS' | 'SYSTEM';
  status: 'HEALTHY' | 'WARNING' | 'CRITICAL' | 'UNKNOWN';
  latencyMs: number;
  throughput: string;
  uptime: string;
  whatIsWrong?: string;
  severityExplanation?: string;
  affectedComponents?: string[];
  remediationAction?: string;
  lastTested: string;
}

export interface Report {
  id: string;
  humanId: string; // REPORT-01
  title: string;
  type: 'CASE_SUMMARY' | 'CENTRALIZED_ANALYSIS' | 'EXECUTIVE_BRIEF';
  caseId: string;
  generatedAt: string;
  author: string;
  summary: string;
  findings: string[];
  recommendations: string[];
  mitreMatrix: string[];
  isCentralized: boolean;
  /** The raw backend Report.to_dict() payload (sections/evidence refs). */
  raw?: any;
}

export interface SocNotification {
  id: string;
  title: string;
  description: string;
  timestamp: string;
  read: boolean;
  /** null = no severity is claimed (e.g. ADR-037 unknown activity). */
  severity: Severity | null;
  linkPage: string;
  targetId?: string;
}
