import React, { createContext, useContext, useState, useEffect, useCallback, ReactNode } from 'react';
import type {
  Case,
  Capability,
  CaseStatus,
  ResolutionReason,
  Detection,
  Correlation,
  TimelineEvent,
  SourceInstance,
  ConnectorCapability,
  Rule,
  HealthSubsystem,
  Report,
  SocNotification
} from '../types/soc';
import { ops, RawCapability, RawCorrelation, RawDetection, RawIncident, RawReport, RawSource } from '../services/backend';
import {
  adaptBackendData,
  adaptCapabilities,
  adaptDeepHealth,
  adaptHealth,
  adaptReports,
  adaptRules,
  adaptSources,
  adaptTimelineItems,
  buildCorrelationViews,
  buildDetectionViews,
  linkDetectionsToCorrelations,
} from '../services/adapters';
import * as api from '../services/api';

export type PageId =
  | 'overview'
  | 'incidents'
  | 'case-detail'
  | 'detections'
  | 'correlations'
  | 'timeline'
  | 'sources'
  | 'rules'
  | 'health'
  | 'capabilities'
  | 'evidence'
  | 'datasets'
  | 'learning'
  | 'guide'
  | 'design-spec';

export interface ToastMessage {
  id: string;
  type: 'success' | 'info' | 'warning' | 'error';
  title: string;
  message: string;
}

/**
 * Boot state of the integration shell.
 * - loading: restoring session / loading backend data
 * - anon: no session; login required
 * - ready: authenticated and data loaded
 * - error: authenticated but backend data load failed (truthful error state)
 */
export type BootState = 'loading' | 'anon' | 'ready' | 'error';

export type CentralizedResult = {
  ok: boolean;
  failed: boolean;
  failureReason: string | null;
  newCorrelationCount: number;
  error?: string;
};

export type ReportResult = { ok: boolean; report?: Report; error?: string };

export interface SocContextType {
  currentPage: PageId;
  setCurrentPage: (page: PageId) => void;
  selectedCaseId: string;
  setSelectedCaseId: (id: string) => void;
  selectedDetectionId: string | null;
  setSelectedDetectionId: (id: string | null) => void;
  selectedCorrelationId: string | null;
  setSelectedCorrelationId: (id: string | null) => void;
  selectedSourceId: string | null;
  setSelectedSourceId: (id: string | null) => void;
  selectedRuleId: string | null;
  setSelectedRuleId: (id: string | null) => void;

  // Auth / boot
  bootState: BootState;
  user: api.SessionUser | null;
  bootError: string | null;
  login: (subjectId: string, credential: string) => Promise<{ ok: boolean; error?: string }>;
  logout: () => void;
  refreshAll: () => Promise<void>;

  // Data (all loaded from the real backend)
  cases: Case[];
  detections: Detection[];
  correlations: Correlation[];
  timelineEvents: TimelineEvent[];
  sources: SourceInstance[];
  capabilities: ConnectorCapability[];
  registryCapabilities: Capability[];
  capabilityDetail: Capability | null;
  capabilityLoading: boolean;
  capabilityError: string | null;
  selectedCapabilityId: string | null;
  setSelectedCapabilityId: (id: string | null) => void;
  loadCapabilities: () => Promise<void>;
  loadCapabilityDetail: (capabilityId: string) => Promise<Capability | null>;
  createCapability: (body: {
    capability_id: string;
    name: string;
    description?: string;
    responsibility?: string;
    implementation_ref?: string;
    version?: number;
    status?: string;
  }) => Promise<{ ok: boolean; capability?: Capability; error?: string }>;
  updateCapability: (capabilityId: string, body: {
    description?: string;
    responsibility?: string;
    version?: number;
  }) => Promise<{ ok: boolean; capability?: Capability; error?: string }>;
  capabilityAction: (action: 'enable' | 'disable' | 'deprecate' | 'retire' | 'archive', capabilityId: string) => Promise<boolean>;
  capabilitySources: { capability_id: string; sources: unknown[]; count: number } | null;
  capabilityRules: { capability_id: string; rules: unknown[]; count: number } | null;
  capabilityPatterns: { capability_id: string; patterns: { pattern_id: string; pattern_version: number; trigger: string }[]; count: number } | null;
  /** §18.27 persisted audit trail for the selected capability. */
  capabilityAudit: { capability_id: string; records: { action: string; actor: string; capability_id: string; human_id?: string | null; before?: Record<string, unknown> | null; after?: Record<string, unknown> | null; changed_fields?: string[]; at: string }[]; count: number } | null;
  /** True once the relations fetch for the selected capability has completed (5.1-03). */
  capabilityRelationsLoaded: boolean;
  loadCapabilityRelations: (capabilityId: string) => Promise<void>;
  rules: Rule[];
  healthSubsystems: HealthSubsystem[];
  reports: Report[];
  notifications: SocNotification[];
  /** Capability patch gap 15: server-computed hourly aggregates. */
  overviewSeries: {
    bucket: string;
    detections: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    unrated: number;
  }[];

  // Filters and global controls
  globalTimeRange: '15m' | '1h' | '24h' | '7d' | '30d';
  setGlobalTimeRange: (range: '15m' | '1h' | '24h' | '7d' | '30d') => void;
  tableDensity: 'comfortable' | 'compact';
  setTableDensity: (density: 'comfortable' | 'compact') => void;

  // Modals & Drawers
  isOmniSearchOpen: boolean;
  setOmniSearchOpen: (open: boolean) => void;
  isAddSourceModalOpen: boolean;
  setAddSourceModalOpen: (open: boolean) => void;
  isAddRuleModalOpen: boolean;
  setAddRuleModalOpen: (open: boolean) => void;
  isCloseCaseModalOpen: boolean;
  setCloseCaseModalOpen: (open: boolean) => void;
  isCentralizedAnalysisModalOpen: boolean;
  setCentralizedAnalysisModalOpen: (open: boolean) => void;
  isReportModalOpen: boolean;
  setReportModalOpen: (open: boolean) => void;
  isErrorSandboxOpen: boolean;
  setErrorSandboxOpen: (open: boolean) => void;
  activeErrorScenario: {
    code: number;
    title: string;
    message: string;
    suggestion: string;
    actionLabel?: string;
    actionTarget?: () => void;
  } | null;

  // Payload drawer
  isPayloadDrawerOpen: boolean;
  payloadDrawerData: {
    title: string;
    subtitle: string;
    humanId?: string;
    internalUuid?: string;
    payload: Record<string, any>;
  } | null;
  openPayloadDrawer: (data: {
    title: string;
    subtitle: string;
    humanId?: string;
    internalUuid?: string;
    payload: Record<string, any>;
  }) => void;
  closePayloadDrawer: () => void;

  // Actions
  navigate: (page: PageId, targetId?: string) => void;
  updateCaseStatus: (caseId: string, newStatus: CaseStatus, reason?: ResolutionReason, notes?: string) => Promise<boolean>;
  addCaseNote: (caseId: string, text: string) => void;
  addSource: (
    newSource: Partial<SourceInstance> & {
      sourceType: string;
      endpoint?: string;
      capabilityId?: string;
      mappingProfileId?: string | null;
      enable?: boolean;
    }
  ) => Promise<{
    ok: boolean;
    token: string | null;
    sourceInstanceId: string | null;
    error: string | null;
  }>;
  toggleSourceStatus: (sourceId: string) => Promise<boolean>;
  rotateSourceToken: (sourceId: string) => Promise<string | null>;
  retireSource: (sourceId: string) => Promise<boolean>;
  // ---- Phase 5.2 source architecture actions --------------------------
  issueSourceToken: (sourceId: string) => Promise<string | null>;
  bindSourceCapability: (
    sourceId: string,
    capabilityId: string,
    mappingProfileId?: string | null
  ) => Promise<boolean>;
  loadSourceAudit: (
    sourceId: string,
    limit?: number
  ) => Promise<{ source_instance_id: string; audit: any[] } | null>;
  loadSourceMigrationStatus: () => Promise<any | null>;
  runSourceMigration: (dryRun: boolean) => Promise<any | null>;
  addRule: (newRule: Partial<Rule>) => Promise<boolean>;
  toggleRuleStatus: (ruleId: string) => Promise<boolean>;
  retireRule: (ruleId: string) => Promise<boolean>;
  runCentralizedAnalysis: (caseId: string, reason?: string) => Promise<CentralizedResult>;
  generateReport: (report: Partial<Report> & { caseId: string }) => Promise<ReportResult>;
  exportReportJson: (reportId: string) => Promise<void>;
  loadCaseTimeline: (caseId: string) => Promise<void>;
  triggerErrorScenario: (code: number) => void;
  resolveHealthSubsystem: (id: string) => Promise<void>;
  markAllNotificationsRead: () => void;

  // Toasts
  toasts: ToastMessage[];
  addToast: (type: 'success' | 'info' | 'warning' | 'error', title: string, message: string) => void;
  removeToast: (id: string) => void;
}

const SocContext = createContext<SocContextType | undefined>(undefined);

/**
 * The ONLY known correlation pattern id in the current backend
 * (app/correlation/patterns.py). The wire contract has no
 * "list correlation patterns" operation, so the id cannot be
 * discovered at runtime — documented backend gap.
 */
const KNOWN_CORRELATION_PATTERN_ID = 'NGINX-CORR-BRUTEFORCE-001';

let toastSeq = 0;

export const SocProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [bootState, setBootState] = useState<BootState>('loading');
  const [user, setUser] = useState<api.SessionUser | null>(() => api.getSessionUser());
  const [bootError, setBootError] = useState<string | null>(null);

  const [currentPage, setCurrentPage] = useState<PageId>('overview');
  const [selectedCaseId, setSelectedCaseId] = useState<string>('');
  const [selectedDetectionId, setSelectedDetectionId] = useState<string | null>(null);
  const [selectedCorrelationId, setSelectedCorrelationId] = useState<string | null>(null);
  const [selectedSourceId, setSelectedSourceId] = useState<string | null>(null);
  const [selectedRuleId, setSelectedRuleId] = useState<string | null>(null);

  const [globalTimeRange, setGlobalTimeRange] = useState<'15m' | '1h' | '24h' | '7d' | '30d'>('24h');
  const [tableDensity, setTableDensity] = useState<'comfortable' | 'compact'>('comfortable');

  // Real backend data
  const [cases, setCases] = useState<Case[]>([]);
  const [detections, setDetections] = useState<Detection[]>([]);
  const [correlations, setCorrelations] = useState<Correlation[]>([]);
  const [timelineEvents, setTimelineEvents] = useState<TimelineEvent[]>([]);
  const [sources, setSources] = useState<SourceInstance[]>([]);
  const [capabilities, setCapabilities] = useState<ConnectorCapability[]>([]);
  // Phase 5.1: the REAL Capability Registry (capability.list/get).
  const [registryCapabilities, setRegistryCapabilities] = useState<Capability[]>([]);
  const [capabilityDetail, setCapabilityDetail] = useState<Capability | null>(null);
  const [capabilityLoading, setCapabilityLoading] = useState(false);
  const [capabilityError, setCapabilityError] = useState<string | null>(null);
  const [selectedCapabilityId, setSelectedCapabilityId] = useState<string | null>(null);
  const [capabilitySources, setCapabilitySources] = useState<{ capability_id: string; sources: unknown[]; count: number } | null>(null);
  const [capabilityRules, setCapabilityRules] = useState<{ capability_id: string; rules: unknown[]; count: number } | null>(null);
  const [capabilityPatterns, setCapabilityPatterns] = useState<{ capability_id: string; patterns: { pattern_id: string; pattern_version: number; trigger: string }[]; count: number } | null>(null);
  const [capabilityAudit, setCapabilityAudit] = useState<{ capability_id: string; records: { action: string; actor: string; capability_id: string; human_id?: string | null; before?: Record<string, unknown> | null; after?: Record<string, unknown> | null; changed_fields?: string[]; at: string }[]; count: number } | null>(null);
  const [capabilityRelationsLoaded, setCapabilityRelationsLoaded] = useState(false);
  const [rules, setRules] = useState<Rule[]>([]);
  const [healthSubsystems, setHealthSubsystems] = useState<HealthSubsystem[]>([]);
  const [reports, setReports] = useState<Report[]>([]);
  // The backend has no notification feed operation — the tray renders a
  // truthful empty state instead of demo notifications.
  const [notifications, setNotifications] = useState<SocNotification[]>([]);
  // Capability patch gaps 8 + 15: backend deep health + server-side
  // hourly aggregates.
  const [overviewSeries, setOverviewSeries] = useState<
    { bucket: string; detections: number; critical: number; high: number; medium: number; low: number; unrated: number }[]
  >([]);

  // Modals state
  const [isOmniSearchOpen, setOmniSearchOpen] = useState(false);
  const [isAddSourceModalOpen, setAddSourceModalOpen] = useState(false);
  const [isAddRuleModalOpen, setAddRuleModalOpen] = useState(false);
  const [isCloseCaseModalOpen, setCloseCaseModalOpen] = useState(false);
  const [isCentralizedAnalysisModalOpen, setCentralizedAnalysisModalOpen] = useState(false);
  const [isReportModalOpen, setReportModalOpen] = useState(false);
  const [isErrorSandboxOpen, setErrorSandboxOpen] = useState(false);
  const [activeErrorScenario, setActiveErrorScenario] = useState<{
    code: number;
    title: string;
    message: string;
    suggestion: string;
    actionLabel?: string;
    actionTarget?: () => void;
  } | null>(null);

  // Payload drawer
  const [isPayloadDrawerOpen, setPayloadDrawerOpen] = useState(false);
  const [payloadDrawerData, setPayloadDrawerData] = useState<{
    title: string;
    subtitle: string;
    humanId?: string;
    internalUuid?: string;
    payload: Record<string, any>;
  } | null>(null);

  const [toasts, setToasts] = useState<ToastMessage[]>([]);

  // ---------------------------------------------------------------- toasts
  const addToast = useCallback((type: ToastMessage['type'], title: string, message: string) => {
    const id = `toast-${++toastSeq}`;
    setToasts(prev => [...prev, { id, type, title, message }]);
    setTimeout(() => {
      setToasts(prev => prev.filter(t => t.id !== id));
    }, 6000);
  }, []);

  const removeToast = useCallback((id: string) => {
    setToasts(prev => prev.filter(t => t.id !== id));
  }, []);

  const describeError = (err: unknown): string => {
    if (err instanceof api.ProxyCallError) {
      return `${err.message} (HTTP ${err.status}, code: ${err.code})`;
    }
    if (err instanceof Error) return err.message;
    return String(err);
  };

  // ---------------------------------------------------------------- data load
  /** Resolve a human id (CASE-000001) or technical id to the live
   *  incident record. Capability patch gap 2: the human id is now a
   *  persisted backend field, so resolution is exact — no positional
   *  guessing. */
  const resolveIncident = useCallback(async (caseHumanId: string) => {
    const casesRes = await ops.listCases(undefined, 200);
    const all = casesRes.cases || [];
    return (
      all.find(c => c.human_id === caseHumanId) ||
      all.find(c => c.incident_id === caseHumanId)
    );
  }, []);

  const refreshAll = useCallback(async () => {
    const [casesRes, detRes, corrRes, srcRes, ruleRes, capRes, summaryRes, patternsRes, notifRes, deepRes, seriesRes] = await Promise.all([
      ops.listCases(undefined, 200),
      ops.listDetections(200),
      ops.listCorrelationsByPattern(KNOWN_CORRELATION_PATTERN_ID, 200),
      ops.listSources(),
      ops.listRules(),
      // Phase 5.1: the REAL Capability Registry (never derived client-side).
      ops.listCapabilities(undefined, 200).catch(() => null),
      ops.overviewSummary().catch(() => null),
      // Capability patch gap 7: the pattern catalogue is discovered on
      // the wire — never hardcoded.
      ops.listCorrelationPatterns().catch(() => null),
      // Capability patch gap 12: the real backend notification feed.
      ops.listNotifications(false, 50).catch(() => null),
      // Capability patch gap 8: deep per-subsystem health.
      ops.deepHealth().catch(() => null),
      // Capability patch gap 15: server-side hourly aggregates.
      ops.overviewTimeseries(8).catch(() => null),
    ]);
    const rawCases: RawIncident[] = casesRes.cases || [];
    const rawDetections: RawDetection[] = detRes.detections || [];
    let rawCorrelations: RawCorrelation[] = [...(corrRes.correlations || [])];
    const rawSources: RawSource[] = srcRes.sources || [];
    const rawRules = ruleRes.rules || [];

    // Gap 7: fetch correlations for EVERY registered pattern (bounded).
    {
      const seen = new Set(rawCorrelations.map(c => c.correlation_id));
      const patternIds = (patternsRes?.patterns || [])
        .map(p => p.pattern_id)
        .filter((id: string) => id !== KNOWN_CORRELATION_PATTERN_ID)
        .slice(0, 8);
      for (const pid of patternIds) {
        try {
          const res = await ops.listCorrelationsByPattern(pid, 200);
          for (const c of res.correlations || []) {
            if (!seen.has(c.correlation_id)) {
              seen.add(c.correlation_id);
              rawCorrelations.push(c);
            }
          }
        } catch {
          // per-pattern listing is best-effort
        }
      }
    }

    // Gap 12: map the real backend notification feed.
    {
      const rawNotifs = notifRes?.notifications || [];
      setNotifications(rawNotifs.map(n => ({
        id: n.notification_id,
        title: n.human_id ? `${n.kind} — ${n.human_id}` : n.kind,
        description: n.detail || n.title || '',
        timestamp: n.created_at,
        read: n.read,
        severity: (
          n.kind.includes('failed') ? 'HIGH' :
          n.kind.includes('closed') ? 'MEDIUM' :
          n.kind.includes('created') ? 'CRITICAL' : 'MEDIUM'
        ) as any,
        linkPage: n.incident_id ? 'incidents' : 'overview',
        targetId: n.human_id || n.incident_id || undefined,
      })));
    }

    // Gap 15: server-computed hourly aggregates.
    if (seriesRes?.series) setOverviewSeries(seriesRes.series);

    // report.list requires incident_id on the live wire — fetch per case
    // (bounded), merging by report_id.
    const reportById = new Map<string, RawReport>();
    for (const inc of rawCases.slice(0, 20)) {
      try {
        const repRes = await ops.listReports(inc.incident_id, 100);
        for (const rep of repRes.reports || []) {
          if (!reportById.has(rep.report_id)) reportById.set(rep.report_id, rep);
        }
      } catch {
        // per-case report listing is best-effort
      }
    }
    const rawReports: RawReport[] = Array.from(reportById.values());

    // Correlations that belong to cases but were produced under other
    // pattern ids (e.g. centralized analysis) are fetched per-case.
    const seen = new Set(rawCorrelations.map(c => c.correlation_id));
    for (const inc of rawCases.slice(0, 20)) {
      try {
        const perCase = await ops.listCorrelationsForIncident(inc.incident_id);
        for (const c of perCase.correlations || []) {
          if (!seen.has(c.correlation_id)) {
            seen.add(c.correlation_id);
            rawCorrelations.push(c);
          }
        }
      } catch {
        // per-case lookup is best-effort; pattern-listed correlations remain
      }
    }

    const adapted = adaptBackendData({ incidents: rawCases, detections: rawDetections, correlations: rawCorrelations });
    const detViews = buildDetectionViews(rawDetections, {
      humanIdByDetectionId: adapted.humanIdByDetectionId,
      caseOfDetection: adapted.caseOfDetection,
    });
    linkDetectionsToCorrelations(detViews, rawCorrelations, adapted.humanIdByCorrelationId);
    const corrViews = buildCorrelationViews(rawCorrelations, {
      humanIdByCorrelationId: adapted.humanIdByCorrelationId,
      humanIdByDetectionId: adapted.humanIdByDetectionId,
      caseOfCorrelation: adapted.caseOfCorrelation,
      centralizedCorrIds: adapted.centralizedCorrIds,
    });
    // Phase 5.2: the capability registry is loaded BEFORE adapting sources so
    // each source resolves its friendly capability label from the REAL
    // registry instead of being handed a fabricated `conn-*` identifier.
    const rawCapList: RawCapability[] =
      (capRes as { capabilities?: RawCapability[] } | null)?.capabilities || [];
    const registryCapViews = adaptCapabilities(rawCapList);
    const srcViews = adaptSources(rawSources, registryCapViews);
    const ruleViews = adaptRules(rawRules, detViews, registryCapViews);
    const reportViews = adaptReports(rawReports);

    // Legacy connector-type chips: derived from the real supported connector
    // types. Phase 5.2 counts a chip's sources by their REAL server-derived
    // capability (matched through the capability's implementation_ref)
    // rather than by a pseudo `conn-*` id that no source ever holds.
    const capViews: ConnectorCapability[] = (srcRes.supported_connector_types || []).map((t: string) => ({
      id: `conn-${t}`,
      name: t,
      category: 'OTHER' as any,
      description: `Supported backend connector type: ${t}`,
      version: '—',
      supportedProtocols: [],
      icon: 'Cpu',
      activeSourceCount: srcViews.filter(
        s =>
          s.capabilityBindingStatus === 'bound' &&
          registryCapViews.find(c => c.capability_id === s.capabilityId)?.implementation_ref === t
      ).length,
    }));

    setCases(adapted.cases);
    setDetections(detViews);
    setCorrelations(corrViews);
    setSources(srcViews);
    setCapabilities(capViews);
    // Phase 5.1/5.2: real registry rows (capability.list) alongside the
    // legacy connector-type chips so Sources/Rules pickers keep working.
    setRegistryCapabilities(registryCapViews);
    setCapabilityError(
      rawCapList.length === 0 ? 'The backend capability registry is empty.' : null
    );
    setRules(ruleViews);
    setReports(reportViews);

    // health: real liveness probe + real per-source health rows +
    // real per-subsystem deep health (capability patch gap 8)
    const liveness = await api.healthCheck();
    setHealthSubsystems([
      ...adaptHealth(liveness, srcViews),
      ...adaptDeepHealth(deepRes?.health || null),
    ]);

    setSelectedCaseId(prev => prev || adapted.cases[0]?.humanId || '');

    if (summaryRes) {
      // overview.summary cross-check: surfaces backend aggregates in devtools
      console.debug('overview.summary', summaryRes);
    }
  }, []);

  // Timeline is per-incident on the wire. `caseId` may be a human id
  // (CASE-xx) or a technical id; it is resolved against fresh case data.
  const loadCaseTimeline = useCallback(async (caseId: string) => {
    try {
      // Capability patch gap 2: exact persisted human-id resolution.
      const inc = await resolveIncident(caseId);
      if (!inc) {
        setTimelineEvents([]);
        addToast('warning', 'Timeline unavailable', `No case found for ${caseId}.`);
        return;
      }
      const t = await ops.timelineForIncident(inc.incident_id);
      // AUD-02 fix: stamp each timeline event with the resolved case's
      // persisted human id so CaseDetailPage's linkage filter
      // (t.humanId === currentCase.humanId) can actually match. Without
      // this, the case-detail Timeline tab always rendered 0 items even
      // when the backend returned a full timeline.
      setTimelineEvents(adaptTimelineItems(t.items || [], inc.human_id || caseId));
    } catch (e) {
      addToast('error', 'Timeline load failed', describeError(e));
    }
  }, [addToast, resolveIncident]);

  // ---------------------------------------------------------------- boot
  useEffect(() => {
    let cancelled = false;
    (async () => {
      if (!api.getSessionToken()) {
        if (!cancelled) setBootState('anon');
        return;
      }
      try {
        await refreshAll();
        if (!cancelled) {
          setBootState('ready');
          setBootError(null);
        }
      } catch (e) {
        if (!cancelled) {
          const msg = describeError(e);
          if (e instanceof api.ProxyCallError && (e.status === 401 || e.status === 403)) {
            api.logout();
            setUser(null);
            setBootState('anon');
          } else {
            setBootError(msg);
            setBootState('error');
          }
        }
      }
    })();
    return () => { cancelled = true; };
  }, [refreshAll]);

  const login = useCallback(async (subjectId: string, credential: string) => {
    const r = await api.authIssue(subjectId, credential);
    if (r.ok && r.data) {
      setUser(api.getSessionUser());
      try {
        await refreshAll();
        setBootState('ready');
        setBootError(null);
        addToast('success', 'Signed in', `Welcome, ${r.data.subject_id} (${r.data.role})`);
        return { ok: true };
      } catch (e) {
        const msg = describeError(e);
        setBootError(msg);
        setBootState('error');
        return { ok: false, error: msg };
      }
    }
    return { ok: false, error: r.error?.message || 'Sign-in failed' };
  }, [refreshAll, addToast]);

  const logout = useCallback(() => {
    api.logout();
    setUser(null);
    setCases([]); setDetections([]); setCorrelations([]); setTimelineEvents([]);
    setSources([]); setCapabilities([]); setRules([]); setReports([]);
    setHealthSubsystems([]);
    setBootState('anon');
  }, []);

  // ---------------------------------------------------------------- navigation
  const navigate = useCallback((page: PageId, targetId?: string) => {
    setCurrentPage(page);
    if (targetId) {
      if (page === 'case-detail') setSelectedCaseId(targetId);
      if (page === 'detections') setSelectedDetectionId(targetId);
      if (page === 'correlations') setSelectedCorrelationId(targetId);
      if (page === 'sources') setSelectedSourceId(targetId);
      if (page === 'rules') setSelectedRuleId(targetId);
    }
  }, []);

  const openPayloadDrawer = useCallback((data: {
    title: string; subtitle: string; humanId?: string; internalUuid?: string; payload: Record<string, any>;
  }) => {
    setPayloadDrawerData(data);
    setPayloadDrawerOpen(true);
  }, []);

  const closePayloadDrawer = useCallback(() => setPayloadDrawerOpen(false), []);

  // ---------------------------------------------------------------- case actions
  const updateCaseStatus = useCallback(async (
    caseHumanId: string,
    newStatus: CaseStatus,
    reason?: ResolutionReason,
    notes?: string
  ): Promise<boolean> => {
    try {
      const inc = await resolveIncident(caseHumanId);
      if (!inc) throw new Error(`case ${caseHumanId} not found`);
      const reasonText = [reason, notes].filter(Boolean).join(': ') || notes || '';
      if (newStatus === 'CLOSED') {
        const res = await ops.closeCase(inc.incident_id, reasonText || 'closed by analyst');
        addToast('success', 'Case closed', `${caseHumanId} closed. Backend state: ${res.case.state}.`);
        await refreshAll();
        return true;
      }
      if (newStatus === 'ACKNOWLEDGED') {
        // Capability patch gap 1: real wire operation.
        const res = await ops.acknowledgeCase(inc.incident_id, reasonText || 'case acknowledged');
        addToast('success', 'Case acknowledged', `${caseHumanId} acknowledged on the backend (state: ${res.case.state}).`);
        await refreshAll();
        return true;
      }
      if (newStatus === 'INVESTIGATING') {
        // Capability patch gap 1: real wire operation.
        const res = await ops.investigateCase(inc.incident_id, reasonText || 'investigation started');
        addToast('success', 'Investigation started', `${caseHumanId} is now investigating on the backend (state: ${res.case.state}).`);
        await refreshAll();
        return true;
      }
      addToast('warning', 'Unsupported transition', `State ${newStatus} has no backend wire operation. The case state was NOT changed.`);
      return false;
    } catch (e) {
      addToast('error', `${newStatus.toLowerCase()} failed`, describeError(e));
      return false;
    }
  }, [addToast, refreshAll, resolveIncident]);

  const addCaseNote = useCallback(async (caseHumanId: string, text: string): Promise<boolean> => {
    // Capability patch gap 4: real persisted, append-only backend note
    // (author + role + timestamp recorded server-side).
    try {
      const inc = await resolveIncident(caseHumanId);
      if (!inc) throw new Error(`case ${caseHumanId} not found`);
      const res = await ops.addCaseNote(inc.incident_id, text);
      addToast(
        'success',
        'Note persisted',
        `Note stored on the backend for ${caseHumanId} (author: ${res.case?.notes?.slice(-1)[0]?.author_subject_id || user?.subject_id || 'unknown'}).`
      );
      await refreshAll();
      return true;
    } catch (e) {
      addToast('error', 'Add note failed', describeError(e));
      return false;
    }
  }, [addToast, refreshAll, resolveIncident, user]);

  // ---------------------------------------------------------------- source actions
  const addSource = useCallback(async (
    newSource: Partial<SourceInstance> & {
      sourceType: string;
      endpoint?: string;
      /** Phase 5.2: optional explicit capability binding. */
      capabilityId?: string;
      mappingProfileId?: string | null;
      /** When false the wizard stops after VALIDATED and enables later. */
      enable?: boolean;
    }
  ): Promise<{ ok: boolean; token: string | null; sourceInstanceId: string | null; error: string | null }> => {
    let sid: string | null = null;
    try {
      // 1. register. Phase 5.2: when the analyst picked a capability in the
      //    wizard it is sent explicitly so the binding is auditable and
      //    intentional rather than only implicitly resolved. The backend
      //    still validates it — a client can never *choose* an arbitrary
      //    capability, only request one the server then accepts or rejects.
      const tags = (newSource.tags || [])
        .map(t => t.toUpperCase().replace(/[^A-Z0-9_-]/g, '_'))
        .filter(Boolean);
      const reg = await ops.registerSource({
        source_type: newSource.sourceType,
        display_name: newSource.name || 'Unnamed source',
        description: newSource.description || undefined,
        tags: tags.length ? Array.from(new Set(tags)).sort() : undefined,
        ...(newSource.capabilityId ? { capability_id: newSource.capabilityId } : {}),
        ...(newSource.mappingProfileId
          ? { mapping_profile_id: newSource.mappingProfileId }
          : {}),
      });
      sid = reg.source.source_instance_id;
      // 2. configure (endpoint mapping) if an endpoint was supplied
      if (newSource.endpoint) {
        await ops.configureSource(sid, {
          connection_type: 'push',
          endpoint: newSource.endpoint,
        });
      }
      // 3. validate
      await ops.validateSource(sid);
      if (newSource.enable === false) {
        await refreshAll();
        return { ok: true, token: null, sourceInstanceId: sid, error: null };
      }
      // 4. enable
      await ops.enableSource(sid);
      // 5. issue the first single-use ingest token. SECURITY: the token is
      //    returned to the caller and rendered only inside the wizard's
      //    dismissible credential panel. It is never placed in a toast,
      //    because toast text is retained in the DOM and visible to anyone
      //    looking at the screen (or a screenshot).
      const tok = await ops.issueSourceToken(sid, 3600);
      await refreshAll();
      return { ok: true, token: tok.source_token, sourceInstanceId: sid, error: null };
    } catch (e) {
      const msg = describeError(e);
      addToast('error', 'Source creation failed', msg);
      await refreshAll();
      return { ok: false, token: null, sourceInstanceId: sid, error: msg };
    }
  }, [addToast, refreshAll]);

  const sourceIdFor = useCallback((sourceHumanId: string): string | null => {
    const src = sources.find(s => s.humanId === sourceHumanId);
    return src ? src.internalUuid : null;
  }, [sources]);

  const toggleSourceStatus = useCallback(async (sourceHumanId: string): Promise<boolean> => {
    const sid = sourceIdFor(sourceHumanId);
    const src = sources.find(s => s.humanId === sourceHumanId);
    if (!sid || !src) {
      addToast('error', 'Source not found', `No source ${sourceHumanId} in the loaded backend data.`);
      return false;
    }
    try {
      if (src.status === 'ENABLED') {
        await ops.disableSource(sid);
        addToast('success', 'Source disabled', `${sourceHumanId} disabled on the backend.`);
      } else {
        await ops.enableSource(sid);
        addToast('success', 'Source enabled', `${sourceHumanId} enabled on the backend.`);
      }
      await refreshAll();
      return true;
    } catch (e) {
      addToast('error', 'Source state change failed', describeError(e));
      return false;
    }
  }, [sourceIdFor, sources, addToast, refreshAll]);

  const rotateSourceToken = useCallback(async (sourceHumanId: string): Promise<string | null> => {
    const sid = sourceIdFor(sourceHumanId);
    if (!sid) {
      addToast('error', 'Source not found', `No source ${sourceHumanId}.`);
      return null;
    }
    try {
      // Phase 5.2: rotation is its OWN audited operation
      // (``source.rotate_token``), not a re-issue. The backend refuses
      // rotation unless the source is bound and VALIDATED/ENABLED, so the
      // caller gets a truthful 409 rather than a silent downgrade.
      const tok = await ops.rotateSourceToken(sid);
      // SECURITY: the token material is deliberately NOT echoed into a
      // toast. Toast history is renderable, screenshot-able and copyable by
      // anyone at the screen; a bearer credential must only be surfaced in
      // the explicit, dismissible credential panel so the analyst chooses
      // when to view/copy it.
      return tok.source_token;
    } catch (e) {
      addToast('error', 'Token rotation failed', describeError(e));
      return null;
    }
  }, [sourceIdFor, addToast]);

  const issueSourceToken = useCallback(async (sourceHumanId: string): Promise<string | null> => {
    const sid = sourceIdFor(sourceHumanId);
    if (!sid) {
      addToast('error', 'Source not found', `No source ${sourceHumanId}.`);
      return null;
    }
    try {
      const tok = await ops.issueSourceToken(sid, 3600);
      return tok.source_token;
    } catch (e) {
      addToast('error', 'Token issuance failed', describeError(e));
      return null;
    }
  }, [sourceIdFor, addToast]);

  // ------------------------------------------------ Phase 5.2 source actions
  const bindSourceCapability = useCallback(
    async (sourceHumanId: string, capabilityId: string, mappingProfileId?: string | null): Promise<boolean> => {
      const sid = sourceIdFor(sourceHumanId);
      if (!sid) {
        addToast('error', 'Source not found', `No source ${sourceHumanId}.`);
        return false;
      }
      try {
        await ops.bindSourceCapability(sid, capabilityId, mappingProfileId);
        addToast(
          'success',
          'Capability bound',
          `${sourceHumanId} is now bound to ${capabilityId}.`
        );
        await refreshAll();
        return true;
      } catch (e) {
        // 400 (unknown/planned capability, undeclared profile),
        // 404 (unknown source), 409 (duplicate / retired) all land here
        // with the backend's own safe message.
        addToast('error', 'Capability binding failed', describeError(e));
        return false;
      }
    },
    [sourceIdFor, addToast, refreshAll]
  );

  const loadSourceAudit = useCallback(async (sourceHumanId: string, limit = 50) => {
    const sid = sourceIdFor(sourceHumanId);
    if (!sid) return null;
    try {
      return await ops.sourceAudit(sid, limit);
    } catch (e) {
      addToast('error', 'Audit load failed', describeError(e));
      return null;
    }
  }, [sourceIdFor, addToast]);

  const loadSourceMigrationStatus = useCallback(async () => {
    try {
      return await ops.sourceMigrationStatus();
    } catch (e) {
      addToast('error', 'Migration status failed', describeError(e));
      return null;
    }
  }, [addToast]);

  const runSourceMigration = useCallback(async (dryRun: boolean) => {
    try {
      const report = await ops.sourceMigrate(dryRun, true);
      addToast(
        'success',
        dryRun ? 'Migration dry-run complete' : 'Migration applied',
        `scanned ${report.sources.scanned} · bound ${report.sources.bound} · quarantined ${report.sources.quarantined} · rule changes ${report.rules.bound}`
      );
      if (!dryRun) await refreshAll();
      return report;
    } catch (e) {
      addToast('error', 'Migration failed', describeError(e));
      return null;
    }
  }, [addToast, refreshAll]);

  const retireSource = useCallback(async (sourceHumanId: string): Promise<boolean> => {
    const sid = sourceIdFor(sourceHumanId);
    if (!sid) {
      addToast('error', 'Source not found', `No source ${sourceHumanId}.`);
      return false;
    }
    try {
      await ops.retireSource(sid);
      addToast('success', 'Source retired', `${sourceHumanId} retired (terminal state).`);
      await refreshAll();
      return true;
    } catch (e) {
      addToast('error', 'Retire failed', describeError(e));
      return false;
    }
  }, [sourceIdFor, addToast, refreshAll]);

  // ---------------------------------------------------------------- rule actions
  const addRule = useCallback(async (newRule: Partial<Rule>): Promise<boolean> => {
    try {
      // The backend rule engine accepts STRUCTURED definitions only
      // (conditions + closed action set). Sigma / YARA-L / CEL free-text
      // authoring is NOT supported — surfaced truthfully to the analyst.
      const ruleId = (newRule.name || 'ANALYST-RULE')
        .toUpperCase()
        .replace(/[^A-Z0-9]+/g, '-')
        .replace(/^-+|-+$/g, '')
        .slice(0, 48) || 'ANALYST-RULE';
      const payload: Record<string, unknown> = {
        rule_id: `${ruleId}-${Date.now().toString(36).toUpperCase()}`,
        version: 1,
        name: newRule.name || 'Analyst rule',
        description: newRule.description || '',
        category: 'observation',
        type: 'per_event',
        state: 'candidate',
        enabled: false,
        severity: (newRule.severity || 'MEDIUM').toLowerCase(),
        sources: [],
        actions: ['alert'],
      };
      // logicCode is expected to be structured JSON conditions; Sigma text
      // cannot be compiled by this backend and is documented as a gap.
      if (newRule.logicCode && newRule.logicCode.trim().startsWith('{')) {
        try {
          payload.conditions = JSON.parse(newRule.logicCode);
        } catch {
          throw new Error('Logic JSON could not be parsed — the backend only accepts structured condition JSON, not Sigma/YARA-L/CEL.');
        }
      }
      await ops.createRule(payload);
      addToast(
        'success',
        'Rule created (CANDIDATE)',
        `${payload.name as string} created in CANDIDATE state. It must be promoted to APPROVED and enabled via the backend governance flow before it can fire.`
      );
      await refreshAll();
      return true;
    } catch (e) {
      addToast('error', 'Rule creation failed', describeError(e));
      return false;
    }
  }, [addToast, refreshAll]);

  const ruleIdFor = useCallback((ruleHumanId: string): string | null => {
    const rule = rules.find(r => r.humanId === ruleHumanId);
    return rule ? rule.internalUuid : null;
  }, [rules]);

  const toggleRuleStatus = useCallback(async (ruleHumanId: string): Promise<boolean> => {
    const rid = ruleIdFor(ruleHumanId);
    const rule = rules.find(r => r.humanId === ruleHumanId);
    if (!rid || !rule) {
      addToast('error', 'Rule not found', `No rule ${ruleHumanId}.`);
      return false;
    }
    try {
      if (rule.lifecycleStatus === 'ACTIVE' || rule.lifecycleStatus === 'DISABLED') {
        if (rule.lifecycleStatus === 'ACTIVE') {
          await ops.disableRule(rid);
          addToast('success', 'Rule disabled', `${ruleHumanId} disabled on the backend.`);
        } else {
          await ops.enableRule(rid);
          addToast('success', 'Rule enabled', `${ruleHumanId} enabled on the backend.`);
        }
      } else {
        addToast(
          'warning',
          'Transition not permitted by backend governance',
          `Rule ${ruleHumanId} is in ${rule.lifecycleStatus} state. The backend forbids enabling CANDIDATE rules and mutating RETIRED rules.`
        );
        return false;
      }
      await refreshAll();
      return true;
    } catch (e) {
      addToast('error', 'Rule state change failed', describeError(e));
      return false;
    }
  }, [ruleIdFor, rules, addToast, refreshAll]);

  const retireRule = useCallback(async (ruleHumanId: string): Promise<boolean> => {
    const rid = ruleIdFor(ruleHumanId);
    if (!rid) {
      addToast('error', 'Rule not found', `No rule ${ruleHumanId}.`);
      return false;
    }
    try {
      await ops.retireRule(rid);
      addToast('success', 'Rule retired', `${ruleHumanId} retired (immutable).`);
      await refreshAll();
      return true;
    } catch (e) {
      addToast('error', 'Rule retire failed', describeError(e));
      return false;
    }
  }, [ruleIdFor, addToast, refreshAll]);

  // ---------------------------------------------------------------- analysis
  const runCentralizedAnalysis = useCallback(async (caseHumanId: string, reason?: string): Promise<CentralizedResult> => {
    try {
      const casesRes = await ops.listCases(undefined, 200);
      const all = casesRes.cases || [];
      const sorted = [...all].sort((a, b) => a.created_at.localeCompare(b.created_at));
      const inc = caseHumanId.startsWith('CASE-')
        ? sorted[parseInt(caseHumanId.replace('CASE-', ''), 10) - 1]
        : all.find(c => c.incident_id === caseHumanId);
      if (!inc) throw new Error(`case ${caseHumanId} not found`);
      // The backend resolves the case's REAL persisted evidence itself;
      // the UI deliberately sends only the intent, never fabricated evidence.
      const res = await ops.centralized(inc.incident_id, reason || 'Requested from centralized analysis UI');
      await refreshAll();
      return {
        ok: true,
        failed: !!res.failed,
        failureReason: res.failure_reason ?? null,
        newCorrelationCount: (res.new_correlation_ids || []).length,
      };
    } catch (e) {
      const msg = describeError(e);
      addToast('error', 'Centralized analysis failed', msg);
      return { ok: false, failed: false, failureReason: null, newCorrelationCount: 0, error: msg };
    }
  }, [addToast, refreshAll]);

  // ---------------------------------------------------------------- reports
  const generateReport = useCallback(async (req: Partial<Report> & { caseId: string }): Promise<ReportResult> => {
    try {
      const casesRes = await ops.listCases(undefined, 200);
      const all = casesRes.cases || [];
      const sorted = [...all].sort((a, b) => a.created_at.localeCompare(b.created_at));
      const inc = req.caseId.startsWith('CASE-')
        ? sorted[parseInt(req.caseId.replace('CASE-', ''), 10) - 1]
        : all.find(c => c.incident_id === req.caseId);
      if (!inc) throw new Error(`case ${req.caseId} not found`);
      const title = req.title || `Report for ${req.caseId}`;
      // centralized reports require a prior successful centralized run
      const res = req.isCentralized
        ? await ops.generateCentralizedReport(inc.incident_id, title)
        : await ops.generateNormalReport(inc.incident_id, title);
      const [view] = adaptReports([res.report]);
      addToast('success', 'Report generated', `${view.humanId} persisted on the backend (${res.report.report_id}).`);
      await refreshAll();
      return { ok: true, report: view };
    } catch (e) {
      const msg = describeError(e);
      addToast('error', 'Report generation failed', msg);
      return { ok: false, error: msg };
    }
  }, [addToast, refreshAll]);

  const exportReportJson = useCallback(async (reportId: string) => {
    try {
      const exp = await ops.exportReport(reportId);
      const blob = new Blob([JSON.stringify(exp.payload, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${reportId}.json`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      addToast('success', 'Report exported', `${reportId} exported as backend-generated JSON.`);
    } catch (e) {
      addToast('error', 'Report export failed', describeError(e));
    }
  }, [addToast]);

  // ---------------------------------------------------------------- error sandbox / misc
  const triggerErrorScenario = useCallback((code: number) => {
    let title = 'Operation Failed';
    let message = 'An unexpected platform error occurred.';
    let suggestion = 'Please retry the action or check system health.';
    let actionLabel: string | undefined = undefined;
    let actionTarget: (() => void) | undefined = undefined;
    switch (code) {
      case 400:
        title = '400 Bad Request — Validation Failure';
        message = 'The request payload was rejected by the backend validation layer.';
        suggestion = 'Verify the field formats and constraints, then retry.';
        break;
      case 401:
        title = '401 Unauthorized — Session Expired';
        message = 'Your session token is missing, expired, or invalid.';
        suggestion = 'Sign in again to obtain a fresh session token.';
        actionLabel = 'Sign In';
        break;
      case 403:
        title = '403 Forbidden — Insufficient Permissions';
        message = 'Your role does not hold the permission required for this operation.';
        suggestion = 'Contact an administrator to request the required role.';
        break;
      case 404:
        title = '404 Not Found';
        message = 'The requested object does not exist (or you are not authorized to see it).';
        suggestion = 'Refresh your data to synchronize with the backend state.';
        actionLabel = 'Go to Incidents';
        actionTarget = () => navigate('incidents');
        break;
      case 409:
        title = '409 Conflict — State Conflict';
        message = 'The operation conflicts with the current backend state.';
        suggestion = 'Refresh the record and retry with a valid transition.';
        actionLabel = 'Go to Sources';
        actionTarget = () => navigate('sources');
        break;
      case 429:
        title = '429 Rate Limited';
        message = 'The per-subject request budget on the SecureProxy was exhausted.';
        suggestion = 'Wait for the rate-limit window to reset, then retry.';
        actionLabel = 'Inspect Health';
        actionTarget = () => navigate('health');
        break;
      case 500:
      default:
        title = '500 Internal Server Error';
        message = 'The backend encountered an unexpected error while handling the operation.';
        suggestion = 'Check the backend logs; no client data was changed by the failed call.';
        actionLabel = 'View System Diagnostics';
        actionTarget = () => navigate('health');
        break;
    }
    setActiveErrorScenario({ code, title, message, suggestion, actionLabel, actionTarget });
    setErrorSandboxOpen(true);
  }, [navigate]);

  const resolveHealthSubsystem = useCallback(async (_id: string) => {
    // There is no backend "resolve subsystem" operation. The truthful
    // action is to re-probe real state; the display reflects the result.
    const liveness = await api.healthCheck();
    setHealthSubsystems(prev => prev.map(sub => sub.id === 'sub-api' ? {
      ...sub,
      status: liveness.ok ? ('HEALTHY' as const) : ('CRITICAL' as const),
      latencyMs: liveness.latencyMs ?? sub.latencyMs,
      lastTested: new Date().toISOString(),
    } : sub));
    addToast(
      liveness.ok ? 'success' : 'error',
      'Health re-probed',
      liveness.ok
        ? `Backend liveness OK (${liveness.latencyMs}ms round-trip).`
        : 'Backend liveness probe FAILED. No subsystem was force-marked healthy.'
    );
  }, [addToast]);

  // ---------------------------------------------------------------- Phase 5.1 capabilities
  const loadCapabilities = useCallback(async () => {
    setCapabilityLoading(true);
    setCapabilityError(null);
    try {
      const res = await ops.listCapabilities(undefined, 200);
      setRegistryCapabilities(adaptCapabilities(res.capabilities || []));
      if ((res.capabilities || []).length === 0) setCapabilityError('The backend capability registry is empty.');
    } catch (e) {
      setCapabilityError(describeError(e));
    } finally {
      setCapabilityLoading(false);
    }
  }, []);

  const loadCapabilityDetail = useCallback(async (capabilityId: string) => {
    setCapabilityLoading(true);
    setCapabilityError(null);
    try {
      const res = await ops.getCapability(capabilityId);
      const adapted = adaptCapabilities([res.capability])[0] ?? null;
      setCapabilityDetail(adapted);
      setSelectedCapabilityId(capabilityId);
      return adapted;
    } catch (e) {
      setCapabilityError(describeError(e));
      return null;
    } finally {
      setCapabilityLoading(false);
    }
  }, []);

  const loadCapabilityRelations = useCallback(async (capabilityId: string) => {
    // 5.1-03: the page must not render empty rule_ids/pattern_ids while the
    // relations fetch is still in flight — the loaded flag is only set to
    // true after all relation reads for THIS capability have returned.
    setCapabilityRelationsLoaded(false);
    try {
      const [s, r, p, a] = await Promise.all([
        ops.listCapabilitySources(capabilityId, 50).catch(() => null),
        ops.listCapabilityRules(capabilityId, 50).catch(() => null),
        ops.listCapabilityPatterns(capabilityId).catch(() => null),
        ops.listCapabilityAudit(capabilityId).catch(() => null),
      ]);
      setCapabilitySources(s);
      setCapabilityRules(r);
      setCapabilityPatterns(p);
      setCapabilityAudit(a);
      setCapabilityRelationsLoaded(true);
    } catch {
      // individual relation failures surface on the page, not as toasts
      setCapabilityRelationsLoaded(true);
    }
  }, []);

  const createCapability = useCallback(async (body: {
    capability_id: string;
    name: string;
    description?: string;
    responsibility?: string;
    implementation_ref?: string;
    version?: number;
    status?: string;
  }) => {
    try {
      const res = await ops.createCapability(body);
      const adapted = adaptCapabilities([res.capability])[0];
      await loadCapabilities();
      setCapabilityDetail(adapted ?? null);
      setSelectedCapabilityId(adapted?.capability_id ?? null);
      addToast('success', 'Capability created', `${adapted?.capability_id} (${adapted?.human_id ?? 'no human id'}) persisted.`);
      return { ok: true as const, capability: adapted };
    } catch (e) {
      const msg = describeError(e);
      addToast('error', 'Create capability failed', msg);
      return { ok: false as const, error: msg };
    }
  }, [addToast, loadCapabilities]);

  const updateCapability = useCallback(async (capabilityId: string, body: {
    description?: string;
    responsibility?: string;
    version?: number;
  }) => {
    try {
      const res = await ops.updateCapability({ capability_id: capabilityId, ...body });
      const adapted = adaptCapabilities([res.capability])[0];
      await loadCapabilities();
      setCapabilityDetail(adapted ?? null);
      addToast('success', 'Capability updated', `${capabilityId} now v${adapted?.version}.`);
      return { ok: true as const, capability: adapted };
    } catch (e) {
      const msg = describeError(e);
      addToast('error', 'Update capability failed', msg);
      return { ok: false as const, error: msg };
    }
  }, [addToast, loadCapabilities]);

  const capabilityAction = useCallback(async (
    action: 'enable' | 'disable' | 'deprecate' | 'retire' | 'archive',
    capabilityId: string,
  ): Promise<boolean> => {
    try {
      const res = await ops.capabilityLifecycle(action, capabilityId);
      const adapted = adaptCapabilities([res.capability])[0];
      await loadCapabilities();
      setCapabilityDetail(adapted ?? null);
      addToast('success', `Capability ${action}d`, `${capabilityId} is now ${adapted?.status}.`);
      return true;
    } catch (e) {
      addToast('error', `Capability ${action} failed`, describeError(e));
      return false;
    }
  }, [addToast, loadCapabilities]);

  const markAllNotificationsRead = useCallback(async () => {
    // Capability patch gap 12: mark-read is a REAL backend operation —
    // one mark per unread notification; failures surface truthfully.
    const unread = notifications.filter(n => !n.read);
    let ok = 0;
    for (const n of unread) {
      try {
        await ops.markNotificationRead(n.id);
        ok += 1;
      } catch {
        // truthful: a failed mark stays unread on the next refresh
      }
    }
    if (unread.length > 0) {
      addToast(
        ok === unread.length ? 'success' : 'warning',
        'Notifications marked read',
        `${ok}/${unread.length} marked read on the backend.`
      );
    }
    try {
      const res = await ops.listNotifications(false, 50);
      setNotifications((res.notifications || []).map(nn => ({
        id: nn.notification_id,
        title: nn.human_id ? `${nn.kind} — ${nn.human_id}` : nn.kind,
        description: nn.detail || nn.title || '',
        timestamp: nn.created_at,
        read: nn.read,
        severity: (
          nn.kind.includes('failed') ? 'HIGH' :
          nn.kind.includes('closed') ? 'MEDIUM' :
          nn.kind.includes('created') ? 'CRITICAL' : 'MEDIUM'
        ) as any,
        linkPage: nn.incident_id ? 'incidents' : 'overview',
        targetId: nn.human_id || nn.incident_id || undefined,
      })));
    } catch {
      // keep current view; refreshAll will reconcile
    }
  }, [notifications, addToast]);

    return (
    <SocContext.Provider
      value={{
        currentPage,
        setCurrentPage,
        selectedCaseId,
        setSelectedCaseId,
        selectedDetectionId,
        setSelectedDetectionId,
        selectedCorrelationId,
        setSelectedCorrelationId,
        selectedSourceId,
        setSelectedSourceId,
        selectedRuleId,
        setSelectedRuleId,
        bootState,
        user,
        bootError,
        login,
        logout,
        refreshAll,
        cases,
        detections,
        correlations,
        timelineEvents,
        sources,
        capabilities,
        registryCapabilities,
        capabilityDetail,
        capabilityLoading,
        capabilityError,
        selectedCapabilityId,
        setSelectedCapabilityId,
        loadCapabilities,
        loadCapabilityDetail,
        createCapability,
        updateCapability,
        capabilityAction,
        capabilitySources,
        capabilityRules,
        capabilityPatterns,
        capabilityAudit,
        capabilityRelationsLoaded,
        loadCapabilityRelations,
        rules,
        healthSubsystems,
        reports,
        notifications,
        overviewSeries,
        globalTimeRange,
        setGlobalTimeRange,
        tableDensity,
        setTableDensity,
        isOmniSearchOpen,
        setOmniSearchOpen,
        isAddSourceModalOpen,
        setAddSourceModalOpen,
        isAddRuleModalOpen,
        setAddRuleModalOpen,
        isCloseCaseModalOpen,
        setCloseCaseModalOpen,
        isCentralizedAnalysisModalOpen,
        setCentralizedAnalysisModalOpen,
        isReportModalOpen,
        setReportModalOpen,
        isErrorSandboxOpen,
        setErrorSandboxOpen,
        activeErrorScenario,
        isPayloadDrawerOpen,
        payloadDrawerData,
        openPayloadDrawer,
        closePayloadDrawer,
        navigate,
        updateCaseStatus,
        addCaseNote,
        addSource,
        toggleSourceStatus,
        rotateSourceToken,
        retireSource,
        issueSourceToken,
        bindSourceCapability,
        loadSourceAudit,
        loadSourceMigrationStatus,
        runSourceMigration,
        addRule,
        toggleRuleStatus,
        retireRule,
        runCentralizedAnalysis,
        generateReport,
        exportReportJson,
        loadCaseTimeline,
        triggerErrorScenario,
        resolveHealthSubsystem,
        markAllNotificationsRead,
        toasts,
        addToast,
        removeToast
      }}
    >
      {children}
    </SocContext.Provider>
  );
};

export const useSoc = () => {
  const context = useContext(SocContext);
  if (!context) {
    throw new Error('useSoc must be used within a SocProvider');
  }
  return context;
};









