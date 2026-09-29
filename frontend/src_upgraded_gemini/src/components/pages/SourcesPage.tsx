import React, { useState } from 'react';
import {
  Plus,
  Search,
  RotateCcw,
  AlertTriangle,
  Archive,
  Terminal,
  Activity,
  Layers,
  X,
  KeyRound,
  ShieldAlert,
  ChevronDown,
  ChevronRight,
  Copy,
  Database,
  Link2
} from 'lucide-react';
import { useSoc } from '../../context/SocContext';
import { StatusBadge } from '../common/StatusBadge';
import { HumanIdTag } from '../common/HumanIdTag';
import { CopyableText } from '../common/CopyableText';
import { formatIstTimestamp } from '../../utils/format';

export const SourcesPage: React.FC = () => {
  const {
    sources,
    registryCapabilities,
    setAddSourceModalOpen,
    toggleSourceStatus,
    rotateSourceToken,
    issueSourceToken,
    bindSourceCapability,
    retireSource,
    loadSourceAudit,
    loadSourceMigrationStatus,
    runSourceMigration,
    openPayloadDrawer,
    triggerErrorScenario
  } = useSoc();

  // Phase 5.2 (5.2-R-04): a source may be bound to a capability whose
  // connector is still `planned` — the deterministic legacy backfill maps
  // waf/iam/rate_limit/network to exactly that. The binding is real and must
  // be shown, but such a source has no live connector, so its parked state is
  // labelled distinctly rather than looking like a runnable `bound` source.
  const implByCapabilityId = new Map(
    registryCapabilities.map(c => [c.capability_id, c.implementation_ref])
  );

  const [searchQuery, setSearchQuery] = useState('');
  const [capabilityFilter, setCapabilityFilter] = useState<string>('ALL');
  // The just-minted credential. Held in component state only (never a toast,
  // never localStorage) and rendered inside a dismissible panel.
  const [tokenPanel, setTokenPanel] = useState<{ humanId: string; token: string; kind: string } | null>(null);
  const [tokenBusy, setTokenBusy] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [auditBySource, setAuditBySource] = useState<Record<string, any[] | 'loading' | 'error'>>({});
  const [bindOpen, setBindOpen] = useState<string | null>(null);
  const [bindChoice, setBindChoice] = useState<string>('');
  const [bindBusy, setBindBusy] = useState<string | null>(null);
  const [migration, setMigration] = useState<any | null>(null);
  const [migrationBusy, setMigrationBusy] = useState(false);

  const copyToken = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      setCopied(false);
    }
  };

  const handleIssueToken = async (humanId: string) => {
    setTokenBusy(humanId);
    const t = await issueSourceToken(humanId);
    setTokenBusy(null);
    if (t) setTokenPanel({ humanId, token: t, kind: 'issued' });
  };

  const handleRotateToken = async (humanId: string) => {
    setTokenBusy(humanId);
    const t = await rotateSourceToken(humanId);
    setTokenBusy(null);
    if (t) setTokenPanel({ humanId, token: t, kind: 'rotated' });
  };

  const handleBind = async (humanId: string) => {
    if (!bindChoice) return;
    setBindBusy(humanId);
    const ok = await bindSourceCapability(humanId, bindChoice);
    setBindBusy(null);
    if (ok) {
      setBindOpen(null);
      setBindChoice('');
    }
  };

  const toggleAudit = async (humanId: string) => {
    if (expanded === humanId) {
      setExpanded(null);
      return;
    }
    setExpanded(humanId);
    setAuditBySource(prev => ({ ...prev, [humanId]: 'loading' }));
    const res = await loadSourceAudit(humanId, 50);
    setAuditBySource(prev => ({
      ...prev,
      [humanId]: res && Array.isArray(res.audit) ? res.audit : 'error'
    }));
  };

  const doMigration = async (dryRun: boolean) => {
    setMigrationBusy(true);
    const res = await runSourceMigration(dryRun);
    setMigrationBusy(false);
    if (res) setMigration(res);
  };

  const loadMigration = async () => {
    setMigrationBusy(true);
    const res = await loadSourceMigrationStatus();
    setMigrationBusy(false);
    if (res) setMigration(res);
  };

  // Bindable capabilities: the exact rule the backend enforces (active, real
  // connector implementation). A quarantined source can only be given an
  // owner the backend would actually accept.
  const bindableCaps = registryCapabilities.filter(
    c => c.status === 'active' && c.implementation_ref !== 'planned'
  );

  const filteredSources = sources.filter(s => {
    const q = searchQuery.toLowerCase().trim();
    const matchesSearch =
      !q ||
      s.humanId.toLowerCase().includes(q) ||
      s.name.toLowerCase().includes(q) ||
      s.description.toLowerCase().includes(q) ||
      s.endpoint.toLowerCase().includes(q) ||
      s.capabilityId.toLowerCase().includes(q) ||
      s.tags.some(t => t.toLowerCase().includes(q));

    // Phase 5.2 fix: filter on the REAL capability id. The previous
    // implementation compared a source's `cap-*` id against the legacy
    // connector chip ids (`conn-*`), so this filter could never match.
    const matchesCap =
      capabilityFilter === 'ALL' ||
      (capabilityFilter === '__UNBOUND__'
        ? !s.capabilityId
        : s.capabilityId === capabilityFilter);

    return matchesSearch && matchesCap;
  });

  return (
    <div className="space-y-6 pb-12 animate-in fade-in duration-200">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-2 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-lg font-bold font-mono tracking-tight text-slate-100">
              TELEMETRY SOURCES & CONNECTOR DRIVERS
            </h1>
            <span className="text-xs font-mono px-2 py-0.5 rounded-full bg-emerald-950 text-emerald-300 border border-emerald-800">
              {sources.length} Configured Sources
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-0.5">
            One capability supports many source instances. Select a capability to see its instances.
          </p>
        </div>

        {/* Primary Action: Add Source */}
        <button
          data-testid="add-source-btn"
          onClick={() => setAddSourceModalOpen(true)}
          className="flex items-center gap-2 px-4 py-2 rounded-lg bg-slate-100 hover:bg-white text-slate-900 font-mono font-semibold text-xs transition-colors"
        >
          <Plus className="w-4 h-4" />
          <span>Add source</span>
        </button>
      </div>

      {/* Conceptual Architecture Summary Banner */}
      <div className="p-4 rounded-xl bg-[#101623] border border-slate-700 text-xs">
        <div className="flex items-center gap-2 font-mono font-semibold text-slate-200 mb-1">
          <Layers className="w-4 h-4 text-slate-300" />
          <span>Capability → Source instances</span>
        </div>
        <p className="text-slate-300 leading-relaxed font-sans">
          A reusable capability (for example NGINX) can support several running source instances. Each instance keeps its own token and ingest endpoint.
        </p>
      </div>

      {/* Phase 5.2: legacy capability-binding migration (deterministic, idempotent) */}
      <div className="p-4 rounded-xl bg-[#0F1420] border border-slate-800 text-xs space-y-2" data-testid="migration-panel">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2 font-mono font-semibold text-slate-200">
            <Database className="w-4 h-4 text-slate-300" />
            <span>Legacy capability-binding migration</span>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <button
              data-testid="migration-status-btn"
              disabled={migrationBusy}
              onClick={loadMigration}
              className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 disabled:opacity-40 text-slate-200 border border-slate-700 font-mono text-[11px]"
            >
              Check status
            </button>
            <button
              data-testid="migration-dry-run-btn"
              disabled={migrationBusy}
              onClick={() => doMigration(true)}
              className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 disabled:opacity-40 text-amber-200 border border-slate-700 font-mono text-[11px]"
            >
              Dry run
            </button>
            <button
              data-testid="migration-apply-btn"
              disabled={migrationBusy}
              onClick={() => doMigration(false)}
              className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 disabled:opacity-40 text-emerald-200 border border-slate-700 font-mono text-[11px]"
            >
              Apply
            </button>
          </div>
        </div>
        <p className="text-slate-400 font-sans">
          Backfills a capability binding onto legacy source instances. The mapping is fixed
          (nginx → cap-nginx, simulator → cap-simulator, planned connectors → their planned
          capability). A source whose type cannot be resolved is QUARANTINED, never guessed.
        </p>
        {migration ? (
          <pre
            data-testid="migration-result"
            className="p-2.5 rounded bg-slate-950 border border-slate-800 text-[10px] font-mono text-slate-300 overflow-x-auto max-h-56"
          >
            {JSON.stringify(migration, null, 2)}
          </pre>
        ) : (
          <p className="text-[11px] text-slate-500 font-mono">
            No migration result loaded yet. Dry run is safe — it writes nothing.
          </p>
        )}
      </div>

      {/* Phase 5.2: the just-minted source credential. Displayed ONCE here, in
          an explicit dismissible panel - never in a toast (toast history is
          retained in the DOM) and never persisted to browser storage. */}
      {tokenPanel && (
        <div
          data-testid="token-panel"
          className="p-4 rounded-xl bg-amber-950/25 border border-amber-500/40 space-y-2"
        >
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex items-center gap-2 text-amber-300 font-mono text-xs font-bold">
              <KeyRound className="w-4 h-4" />
              <span>
                Source credential {tokenPanel.kind} for {tokenPanel.humanId} - copy it now
              </span>
            </div>
            <button
              data-testid="token-panel-close"
              onClick={() => setTokenPanel(null)}
              className="text-amber-200 hover:text-white"
              aria-label="Dismiss credential"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <code
              data-testid="token-value"
              className="flex-1 min-w-0 px-2.5 py-2 rounded bg-slate-950 border border-slate-700 text-[11px] font-mono text-emerald-300 break-all"
            >
              {tokenPanel.token}
            </code>
            <button
              data-testid="token-copy"
              onClick={() => copyToken(tokenPanel.token)}
              className="shrink-0 flex items-center gap-1 px-2.5 py-2 rounded bg-slate-800 hover:bg-slate-700 border border-slate-600 text-cyan-300 font-mono text-[11px]"
            >
              <Copy className="w-3.5 h-3.5" />
              {copied ? 'Copied' : 'Copy'}
            </button>
          </div>
          <p className="text-[10px] text-amber-200/80 font-sans">
            This is the only time the backend returns this credential: it is single-use and
            <code> source.list</code> never re-serves it. Dismissing this panel discards it from
            the browser.
          </p>
        </div>
      )}

      {/* Filter and Search Bar */}
      <div className="p-3.5 rounded-xl bg-[#0F1420] border border-slate-800 flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3">
        <div className="relative flex-1">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            data-testid="source-search"
            value={searchQuery}
            onChange={e => setSearchQuery(e.target.value)}
            placeholder="Search source instances by ID, name, capability, tag, or endpoint..."
            className="w-full pl-9 pr-8 py-2 rounded-lg bg-slate-900 border border-slate-700 text-xs text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-emerald-500 font-mono"
          />
          {searchQuery && (
            <button
              onClick={() => setSearchQuery('')}
              className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-400 hover:text-white"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          )}
        </div>

        <select
          data-testid="capability-filter"
          value={capabilityFilter}
          onChange={e => setCapabilityFilter(e.target.value)}
          aria-label="Filter by Capability"
          className="px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-xs text-slate-200 focus:outline-none font-mono"
        >
          <option value="ALL">All capabilities</option>
          <option value="__UNBOUND__">No capability (unbound / quarantined)</option>
          {registryCapabilities.map(cap => (
            <option key={cap.capability_id} value={cap.capability_id}>
              {cap.name} ({cap.capability_id})
            </option>
          ))}
        </select>
      </div>

      {/* Source Instances Cards List */}
      <div className="space-y-4">
        {filteredSources.length === 0 && (
          <div
            data-testid="sources-empty"
            className="p-8 rounded-xl bg-[#0F1420] border border-slate-800 text-center space-y-2"
          >
            <Layers className="w-6 h-6 text-slate-600 mx-auto" />
            <p className="text-sm font-mono text-slate-300">
              {sources.length === 0
                ? 'No source instances exist yet.'
                : 'No source instance matches the current search or capability filter.'}
            </p>
            <p className="text-xs text-slate-500 font-sans">
              {sources.length === 0
                ? 'Add a source to bind a capability to a running instance and obtain its ingest credential.'
                : 'Clear the search box or set the capability filter back to "All capabilities".'}
            </p>
          </div>
        )}
        {filteredSources.map(src => (
          <div
            key={src.humanId}
            data-testid={`source-card-${src.humanId}`}
            data-capability-id={src.capabilityId || ''}
            data-binding-status={src.capabilityBindingStatus}
            data-lifecycle-state={src.lifecycleState}
            className={`p-5 rounded-xl bg-[#0F1420] border transition-all shadow-xl space-y-4 ${
              src.capabilityBindingStatus !== 'bound'
                ? 'border-amber-500/50 hover:border-amber-500'
                : src.status === 'ERROR' || src.errorDetails
                ? 'border-amber-500/50 hover:border-amber-500'
                : 'border-slate-800 hover:border-emerald-500/40'
            }`}
          >
            {/* Source Card Header */}
            <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3 pb-3 border-b border-slate-800">
              <div className="flex flex-wrap items-center gap-2.5">
                <HumanIdTag humanId={src.humanId} internalUuid={src.internalUuid} size="lg" />
                <StatusBadge status={src.status} size="md" />
                <span
                  data-testid={`source-capability-${src.humanId}`}
                  className={`text-xs font-mono px-2 py-0.5 rounded border ${
                    src.capabilityBindingStatus === 'bound'
                      ? 'bg-slate-800 border-slate-700 text-slate-300'
                      : 'bg-amber-950/40 border-amber-500/50 text-amber-300'
                  }`}
                >
                  {src.capabilityBindingStatus === 'bound'
                    ? `${src.capabilityName || src.capabilityId} [${
                        src.capabilityId
                      } v${src.capabilityVersion ?? '?'}]`
                    : src.capabilityBindingStatus === 'requires_verification'
                    ? 'NO CAPABILITY - REQUIRES VERIFICATION'
                    : 'NO CAPABILITY BOUND'}
                </span>
                <span
                  className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-slate-400 uppercase"
                  title="Lifecycle state persisted by the backend"
                  data-testid={`source-lifecycle-${src.humanId}`}
                >
                  lifecycle: {src.lifecycleState}
                </span>
                <h3 className="text-base font-bold text-slate-100 font-mono">
                  {src.name}
                </h3>
              </div>

              <div className="flex items-center gap-3 text-xs font-mono">
                <div className="flex items-center gap-1.5 text-slate-400">
                  <Activity className="w-3.5 h-3.5" />
                  {/* Per-second ingest rate is not exposed by the backend (documented gap) */}
                  <span>Last event: {src.lastActivity ? formatIstTimestamp(src.lastActivity) : 'never'}</span>
                </div>
              </div>
            </div>

            {/* Description & Tags */}
            <div className="space-y-2">
              <p className="text-xs text-slate-300 leading-relaxed font-sans">
                {src.description}
              </p>
              <div className="flex flex-wrap gap-1.5">
                {src.tags.map(tag => (
                  <span
                    key={tag}
                    className="text-[11px] font-mono px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-slate-400"
                  >
                    #{tag}
                  </span>
                ))}
              </div>
            </div>

            {/* Phase 5.2: capability binding (server-authoritative) */}
            <div className="p-3.5 rounded-lg bg-[#0A0D15] border border-slate-800/80 text-xs space-y-2">
              <div className="flex items-center gap-2 font-mono text-[11px] text-slate-300">
                <Link2 className="w-3.5 h-3.5 text-cyan-400" />
                <span>Capability binding (server-authoritative)</span>
              </div>
              <dl className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-x-3 gap-y-1 font-mono text-[10px]">
                <dt className="text-slate-500">capability_id</dt>
                <dd className="text-cyan-300 break-all" data-testid={`source-cap-id-${src.humanId}`}>
                  {src.capabilityId || '(none)'}
                </dd>
                <dt className="text-slate-500">capability_version</dt>
                <dd className="text-slate-200">
                  {src.capabilityVersion != null ? src.capabilityVersion : '(none)'}
                </dd>
                <dt className="text-slate-500">mapping_profile_id</dt>
                <dd className="text-slate-200 break-all">{src.mappingProfileId || '(none)'}</dd>
                <dt className="text-slate-500">binding_status</dt>
                <dd
                  data-testid={`source-binding-status-${src.humanId}`}
                  className={
                    src.capabilityBindingStatus !== 'bound' ||
                    implByCapabilityId.get(src.capabilityId) === 'planned'
                      ? 'text-amber-300'
                      : 'text-emerald-300'
                  }
                >
                  {src.capabilityBindingStatus}
                  {src.capabilityBindingStatus === 'bound' &&
                    implByCapabilityId.get(src.capabilityId) === 'planned' && (
                      ' — parked: no live connector'
                    )}
                </dd>
                <dt className="text-slate-500">capability_bound_at</dt>
                <dd className="text-slate-400 break-all">{src.capabilityBoundAt || '(never)'}</dd>
              </dl>

              {src.capabilityBindingStatus !== 'bound' && (
                <div
                  className="p-2.5 rounded-lg bg-amber-950/30 border border-amber-500/40 space-y-2"
                  data-testid={`quarantine-${src.humanId}`}
                >
                  <div className="flex items-center gap-2 text-amber-300 font-bold font-mono">
                    <ShieldAlert className="w-4 h-4 text-amber-400" />
                    <span>
                      {src.capabilityBindingStatus === 'requires_verification'
                        ? 'QUARANTINED - no capability could be verified'
                        : 'UNBOUND - no capability owns this instance'}
                    </span>
                  </div>
                  <p className="text-slate-300 font-sans">
                    This instance cannot ingest telemetry until an administrator binds it to a
                    capability. ProShield did not invent an owner for it.
                  </p>
                  {bindOpen === src.humanId ? (
                    <div className="flex flex-wrap items-center gap-2">
                      <select
                        data-testid={`bind-select-${src.humanId}`}
                        value={bindChoice}
                        onChange={e => setBindChoice(e.target.value)}
                        aria-label="Capability to bind"
                        className="px-2 py-1 rounded bg-slate-950 border border-slate-700 text-slate-100 font-mono text-[11px]"
                      >
                        <option value="">Select a capability...</option>
                        {bindableCaps.map(c => (
                          <option key={c.capability_id} value={c.capability_id}>
                            {c.name} ({c.capability_id})
                          </option>
                        ))}
                      </select>
                      <button
                        data-testid={`bind-confirm-${src.humanId}`}
                        disabled={!bindChoice || bindBusy === src.humanId}
                        onClick={() => handleBind(src.humanId)}
                        className="px-2.5 py-1 rounded bg-emerald-600 hover:bg-emerald-500 disabled:bg-slate-800 disabled:text-slate-600 text-white font-mono text-[11px] font-semibold"
                      >
                        {bindBusy === src.humanId ? 'Binding...' : 'Bind capability'}
                      </button>
                      <button
                        onClick={() => {
                          setBindOpen(null);
                          setBindChoice('');
                        }}
                        className="px-2 py-1 rounded text-slate-400 hover:text-white font-mono text-[11px]"
                      >
                        Cancel
                      </button>
                    </div>
                  ) : (
                    <button
                      data-testid={`bind-open-${src.humanId}`}
                      onClick={() => {
                        setBindOpen(src.humanId);
                        setBindChoice('');
                      }}
                      className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-amber-200 border border-slate-700 font-mono text-[11px]"
                    >
                      Bind capability
                    </button>
                  )}
                </div>
              )}
            </div>

            {/* Ingress Endpoint & Bearer Token Management */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-3 p-3.5 rounded-lg bg-[#0A0D15] border border-slate-800/80 font-mono text-xs">
              <div className="space-y-1 min-w-0">
                <span className="text-[10px] text-slate-500 uppercase block">Ingress URI Endpoint:</span>
                <CopyableText text={src.endpoint} label="Ingress Endpoint" className="max-w-full" />
              </div>

              <div className="space-y-1.5">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="text-[10px] text-slate-500 uppercase">
                    Source credential (single-use sit- token):
                  </span>
                  <div className="flex items-center gap-2">
                    <button
                      data-testid={`issue-token-${src.humanId}`}
                      disabled={
                        !src.tokenIssuable || src.lifecycleState === 'retired' || tokenBusy === src.humanId
                      }
                      onClick={() => handleIssueToken(src.humanId)}
                      title="Mint a new single-use source-identity credential (source.issue_token). Shown once in the credential panel."
                      className="text-[10px] text-cyan-400 hover:text-cyan-300 disabled:text-slate-600 disabled:cursor-not-allowed flex items-center gap-1"
                    >
                      <KeyRound className="w-3 h-3" />
                      <span>{tokenBusy === src.humanId ? 'Working...' : 'Issue token'}</span>
                    </button>
                    <button
                      data-testid={`rotate-token-${src.humanId}`}
                      disabled={
                        !src.tokenIssuable || src.lifecycleState === 'retired' || tokenBusy === src.humanId
                      }
                      onClick={() => handleRotateToken(src.humanId)}
                      title="Rotate the source credential (source.rotate_token). A fresh single-use credential is issued and audited; unused outstanding credentials are NOT revoked in this phase (no revocation list) - each dies on first use or expiry. A retired source cannot rotate."
                      className="text-[10px] text-cyan-400 hover:text-cyan-300 disabled:text-slate-600 disabled:cursor-not-allowed flex items-center gap-1"
                    >
                      <RotateCcw className="w-3 h-3" />
                      <span>Rotate token</span>
                    </button>
                  </div>
                </div>

                {/* Truthful credential state. Tokens are single-use and are
                    never re-served by source.list, so the UI reports state
                    (issuable / blocked / retired), never token material. */}
                <div
                  data-testid={`token-state-${src.humanId}`}
                  data-token-issuable={String(src.tokenIssuable)}
                  className={`text-[10px] font-mono px-2 py-1 rounded border ${
                    src.lifecycleState === 'retired'
                      ? 'bg-slate-900 border-slate-800 text-slate-500'
                      : src.capabilityBindingStatus !== 'bound' || !src.tokenIssuable
                      ? 'bg-amber-950/30 border-amber-500/40 text-amber-300'
                      : 'bg-emerald-950/30 border-emerald-700/50 text-emerald-300'
                  }`}
                >
                  {src.lifecycleState === 'retired'
                    ? 'RETIRED - credentials can no longer be issued or rotated. Historical provenance is preserved.'
                    : src.capabilityBindingStatus !== 'bound'
                    ? 'BLOCKED - bind a capability before a credential can exist.'
                    : src.tokenIssuable
                    ? `ISSUABLE - last credential issued: ${src.tokenCreated || 'never'}`
                    : `NOT ISSUABLE in lifecycle state "${src.lifecycleState}".`}
                </div>
                <p className="text-[10px] text-slate-600">
                  Token material is never re-served by <code>source.list</code>. It is displayed
                  once, in the credential panel, at issue/rotate time.
                </p>
              </div>
            </div>

            {/* Ingestion Diagnostics & Backpressure Warning */}
            {src.errorDetails && (
              <div className="p-3 rounded-lg bg-amber-950/30 border border-amber-500/40 text-xs font-mono space-y-2">
                <div className="flex items-center gap-2 text-amber-300 font-bold">
                  <AlertTriangle className="w-4 h-4 text-amber-400" />
                  <span>Telemetry Buffer Alert [HTTP {src.errorDetails.code}]</span>
                </div>
                <p className="text-slate-300 font-sans text-xs">{src.errorDetails.message}</p>
                <div className="flex items-center justify-between pt-1 text-[11px] text-amber-400">
                  <span>Remediation: {src.errorDetails.suggestion}</span>
                  <button
                    onClick={() => triggerErrorScenario(429)}
                    className="text-cyan-300 underline font-bold"
                  >
                    Diagnose in Sandbox
                  </button>
                </div>
              </div>
            )}

            {/* Operational Actions */}
            <div className="flex flex-wrap items-center justify-between gap-3 pt-2 border-t border-slate-800/80 font-mono text-xs">
              <div className="flex items-center gap-3 text-slate-400 text-[11px]">
                {src.ingestTelemetry ? (
                  <span
                    title="Per-source ingest counters maintained at the ingress boundary (capability patch: accepted / rejected / errors)"
                  >
                    Ingest: <strong className="text-slate-200">{src.ingestTelemetry.accepted} accepted</strong>
                    {' / '}
                    <strong className={src.ingestTelemetry.rejected > 0 ? 'text-amber-300' : 'text-slate-400'}>
                      {src.ingestTelemetry.rejected} rejected
                    </strong>
                    {src.ingestTelemetry.errors > 0 && (
                      <>
                        {' / '}
                        <strong className="text-red-300">{src.ingestTelemetry.errors} errors</strong>
                      </>
                    )}
                  </span>
                ) : src.metrics.totalEvents24h != null ? (
                  <span>24h Ingest: <strong className="text-slate-200">{(src.metrics.totalEvents24h / 1000000).toFixed(1)}M events</strong></span>
                ) : (
                  <span title="No ingest telemetry has been recorded for this source yet">Ingest: <strong className="text-slate-500">no telemetry yet</strong></span>
                )}
              </div>

              <div className="flex items-center gap-2">
                <button
                  onClick={() =>
                    openPayloadDrawer({
                      title: `Source Stream Telemetry: ${src.name}`,
                      subtitle: `${src.humanId} • Endpoint: ${src.endpoint}`,
                      humanId: src.humanId,
                      internalUuid: src.internalUuid,
                      payload: {
                        source_id: src.humanId,
                        capability: src.capabilityName,
                        status: src.status,
                        endpoint: src.endpoint,
                        metrics: src.metrics,
                        tags: src.tags,
                        token_created: src.tokenCreated
                      }
                    })
                  }
                  className="flex items-center gap-1 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-slate-700 text-xs transition-colors"
                >
                  <Terminal className="w-3.5 h-3.5" />
                  <span>Inspect Stream</span>
                </button>

                <button
                  data-testid={`audit-toggle-${src.humanId}`}
                  onClick={() => toggleAudit(src.humanId)}
                  className="flex items-center gap-1 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs transition-colors"
                  title="Load this source's server-side audit trail (migration, binding, lifecycle, token) from source.audit"
                >
                  {expanded === src.humanId ? (
                    <ChevronDown className="w-3.5 h-3.5" />
                  ) : (
                    <ChevronRight className="w-3.5 h-3.5" />
                  )}
                  <span>Audit</span>
                </button>

                <button
                  data-testid={`toggle-source-${src.humanId}`}
                  disabled={src.lifecycleState === 'retired'}
                  onClick={() => toggleSourceStatus(src.humanId)}
                  title={
                    src.lifecycleState === 'retired'
                      ? 'A retired source can no longer be enabled or disabled.'
                      : 'Enable or disable this source instance on the backend.'
                  }
                  className={`px-3 py-1 rounded text-xs font-bold transition-colors border disabled:bg-slate-900 disabled:text-slate-600 disabled:border-slate-800 disabled:cursor-not-allowed ${
                    src.status === 'ENABLED'
                      ? 'bg-slate-800 text-amber-300 border-slate-700 hover:bg-amber-950/60 hover:border-amber-500'
                      : 'bg-emerald-600 text-white border-emerald-500 hover:bg-emerald-500'
                  }`}
                >
                  {src.status === 'ENABLED' ? 'Disable Source' : 'Enable Source'}
                </button>

                <button
                  data-testid={`retire-source-${src.humanId}`}
                  disabled={src.lifecycleState === 'retired'}
                  onClick={() => retireSource(src.humanId)}
                  className="p-1.5 rounded text-slate-500 hover:text-rose-400 hover:bg-slate-800 disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
                  title={
                    src.lifecycleState === 'retired'
                      ? 'This source is already retired.'
                      : 'Retire Source Instance - stops ingestion and future credential issuance. Historical provenance is kept.'
                  }
                >
                  <Archive className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>

            {/* Phase 5.2: server-side audit trail (read-only, backend truth) */}
            {expanded === src.humanId && (
              <div
                data-testid={`audit-panel-${src.humanId}`}
                className="p-3 rounded-lg bg-[#0A0D15] border border-slate-800/80 text-xs space-y-2"
              >
                <div className="flex items-center justify-between">
                  <span className="font-mono text-[11px] text-slate-300">
                    Backend audit trail ({Array.isArray(auditBySource[src.humanId]) ? (auditBySource[src.humanId] as any[]).length : 0} entries)
                  </span>
                  <button
                    onClick={() => setExpanded(null)}
                    className="text-slate-400 hover:text-white"
                    aria-label="Close audit trail"
                  >
                    <X className="w-3.5 h-3.5" />
                  </button>
                </div>
                {auditBySource[src.humanId] === 'loading' ? (
                  <p className="text-slate-400 font-mono text-[11px]">Loading audit trail...</p>
                ) : auditBySource[src.humanId] === 'error' ? (
                  <p className="text-rose-300 font-mono text-[11px]" role="alert">
                    The backend did not return an audit trail for this source.
                  </p>
                ) : (auditBySource[src.humanId] as any[])?.length ? (
                  <ul className="space-y-1 max-h-64 overflow-y-auto">
                    {(auditBySource[src.humanId] as any[]).map((a: any, i: number) => (
                      <li
                        key={i}
                        className="flex flex-wrap items-baseline gap-2 font-mono text-[10px] border-b border-slate-800/60 pb-1"
                      >
                        <span className="text-cyan-300">{a.action || a.event || a.kind || 'entry'}</span>
                        <span className="text-slate-500">{(a.at || a.timestamp || a.created_at) ? formatIstTimestamp(a.at || a.timestamp || a.created_at) : ''}</span>
                        <span className="text-slate-400">{a.actor_subject_id || a.actor || ''}</span>
                        <span className="text-slate-500 break-all">
                          {a.detail ? JSON.stringify(a.detail) : a.metadata ? JSON.stringify(a.metadata) : ''}
                        </span>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p className="text-slate-400 font-mono text-[11px]">
                    No audit entries were returned for this source (empty, not fabricated).
                  </p>
                )}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
};
