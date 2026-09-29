import React, { useEffect, useMemo, useState } from 'react';
import { Layers, Search, CheckCircle, PauseCircle, Archive, Plus, RefreshCw, Eye } from 'lucide-react';
import { useSoc } from '../../context/SocContext';
import type { Capability } from '../../types/soc';
import { formatIstTimestamp } from '../../utils/format';

/**
 * Phase 5.1 Capability Management — authoritative React implementation.
 *
 * Wiring (all REAL, no fake APIs):
 *   SecureProxy capability.list/get/create/update/enable/disable/
 *   deprecate/retire/archive/list_sources/list_rules/list_patterns
 *   → src/services/api.ts callOrThrow → src/services/backend.ts ops.*
 *   → SocContext registryCapabilities/capabilityDetail (+ relations)
 *   → this page. One Capability → many Sources/Rules/Patterns.
 *   No subconnector. implementation_ref is allowlisted server-side.
 */
export const CapabilitiesPage: React.FC = () => {
  const soc = useSoc();
  const {
    registryCapabilities, capabilityDetail, capabilityLoading, capabilityError,
    selectedCapabilityId, loadCapabilities, loadCapabilityDetail, loadCapabilityRelations,
    createCapability, updateCapability, capabilityAction,
    capabilitySources, capabilityRules, capabilityPatterns, capabilityAudit,
    capabilityRelationsLoaded, sources, user,
  } = soc;
  const isAdmin = (user?.role || '').toLowerCase() === 'admin';
  const [q, setQ] = useState('');
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [tab, setTab] = useState<'overview' | 'sources' | 'rules' | 'patterns' | 'health' | 'versions'>('overview');

  // legacy preview hooks removed: Phase 5.1 wires the real registry only
  const [creating, setCreating] = useState(false);
  const [formId, setFormId] = useState('');
  const [formName, setFormName] = useState('');
  const [formDesc, setFormDesc] = useState('');
  const [formResp, setFormResp] = useState('');
  const [formImpl, setFormImpl] = useState('planned');
  const [formError, setFormError] = useState<string | null>(null);
  const [editDesc, setEditDesc] = useState('');
  const [editResp, setEditResp] = useState('');
  const [editVersion, setEditVersion] = useState('');
  const [editing, setEditing] = useState(false);

  useEffect(() => {
    if (registryCapabilities.length === 0) void loadCapabilities();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    if (capabilityDetail) {
      setEditDesc(capabilityDetail.description || '');
      setEditResp(capabilityDetail.responsibility || '');
      setEditVersion(String((capabilityDetail.version || 1) + 1));
    }
  }, [capabilityDetail]);

  const rows = useMemo(() => {
    const needle = q.toLowerCase().trim();
    return registryCapabilities.filter((c) => {
      if (statusFilter !== 'all' && c.status !== statusFilter) return false;
      if (!needle) return true;
      return [c.capability_id, c.human_id || '', c.name, c.description || '', c.implementation_ref].join(' ').toLowerCase().includes(needle);
    });
  }, [registryCapabilities, q, statusFilter]);

  // 5.1-01: planned capabilities can NEVER be disabled — the backend now
  // refuses that transition (409) because it persisted a model-invalid state.
  // The UI only offers transitions the backend will accept.
  const lifecycleFor = (c: Capability): ('enable' | 'disable' | 'deprecate' | 'retire' | 'archive')[] => {
    switch (c.status) {
      case 'active': return ['disable', 'deprecate', 'retire'];
      case 'disabled': return ['enable', 'deprecate', 'retire'];
      case 'deprecated': return ['enable', 'disable', 'retire'];
      case 'planned': return ['retire'];
      case 'retired': return ['archive'];
      default: return [];
    }
  };

  const switchTab = async (t: typeof tab) => {
    setTab(t);
    if (selectedCapabilityId && t !== 'overview') await loadCapabilityRelations(selectedCapabilityId);
  };

  const openDetail = async (id: string) => {
    setTab('overview');
    await loadCapabilityDetail(id);
    await loadCapabilityRelations(id);
  };

  const submitCreate = async () => {
    setFormError(null);
    const r = await createCapability({
      capability_id: formId.trim().toLowerCase(),
      name: formName.trim(),
      description: formDesc.trim(),
      responsibility: formResp.trim(),
      implementation_ref: formImpl,
      status: formImpl === 'planned' ? 'planned' : 'active',
    });
    if (!r.ok) { setFormError(r.error || 'Create failed'); return; }
    setCreating(false);
    setFormId(''); setFormName(''); setFormDesc(''); setFormResp(''); setFormImpl('planned');
    if (r.capability) await loadCapabilityRelations(r.capability.capability_id);
  };

  const submitEdit = async () => {
    if (!capabilityDetail) return;
    setFormError(null);
    const v = parseInt(editVersion, 10);
    const r = await updateCapability(capabilityDetail.capability_id, {
      description: editDesc,
      responsibility: editResp,
      version: Number.isFinite(v) ? v : undefined,
    });
    if (!r.ok) { setFormError(r.error || 'Update failed'); return; }
    setEditing(false);
  };

  const act = async (action: 'enable' | 'disable' | 'deprecate' | 'retire' | 'archive', c: Capability) => {
    const ok = await capabilityAction(action, c.capability_id);
    if (ok) await loadCapabilityRelations(c.capability_id);
  };

  return (
    <div className="space-y-5 pb-12">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-2 border-b border-slate-800">
        <div>
          <div className="flex flex-wrap items-center gap-2">
            <h1 className="text-lg font-semibold tracking-tight text-slate-100">Capabilities</h1>
            <span className="text-[11px] font-mono px-2 py-0.5 rounded-full bg-slate-800 text-slate-200 border border-slate-700">
              {registryCapabilities.length} from backend
            </span>
            <span className="text-[11px] font-mono px-2 py-0.5 rounded-full bg-emerald-950 text-emerald-300 border border-emerald-800">
              live registry
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1 max-w-3xl">
            A capability is a reusable implementation and responsibility. One capability supports many source instances,
            rules and correlation patterns. Planned rows are declared families with no live implementation.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => void loadCapabilities()}
            className="flex items-center gap-2 px-3 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 font-mono text-xs border border-slate-700"
          >
            <RefreshCw className="w-4 h-4" />
            <span>Reload</span>
          </button>
          {isAdmin && (
            <button
              type="button"
              onClick={() => { setFormError(null); setCreating(true); }}
              className="flex items-center gap-2 px-4 py-2 rounded-lg bg-slate-100 hover:bg-white text-slate-900 font-mono font-semibold text-xs"
            >
              <Plus className="w-4 h-4" />
              <span>Create capability</span>
            </button>
          )}
        </div>
      </div>

      {!isAdmin && (
        <div className="p-3 rounded-xl bg-[#0F1420] border border-slate-800 text-xs text-slate-400">
          Read-only view: lifecycle changes require an admin session (capability:write). You can inspect list, detail and relationship views.
        </div>
      )}

      <div className="p-3.5 rounded-xl bg-[#0F1420] border border-slate-800 flex flex-col sm:flex-row gap-2">
        <div className="relative flex-1">
          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Search capabilities by id, human id, name, description, implementation..."
            aria-label="Search capabilities"
            className="w-full pl-9 pr-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-xs text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-slate-500"
          />
        </div>
        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
          aria-label="Filter by status"
          className="px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-xs text-slate-100"
        >
          {['all', 'active', 'disabled', 'deprecated', 'planned', 'retired', 'archived'].map((s) => (
            <option key={s} value={s}>{s === 'all' ? 'All statuses' : s}</option>
          ))}
        </select>
      </div>

      {capabilityLoading && registryCapabilities.length === 0 ? (
        <div className="p-8 rounded-xl bg-[#0F1420] border border-slate-800 text-center">
          <p className="text-sm text-slate-200 font-medium">Loading capabilities…</p>
          <p className="text-xs text-slate-500 mt-1">Reading capability.list from the backend.</p>
        </div>
      ) : capabilityError && registryCapabilities.length === 0 ? (
        <div className="p-8 rounded-xl bg-[#0F1420] border border-rose-800 text-center" role="alert">
          <p className="text-sm text-rose-200 font-medium">Capabilities unavailable</p>
          <p className="text-xs text-rose-300/80 mt-1">{capabilityError}</p>
          <button type="button" onClick={() => void loadCapabilities()} className="mt-3 px-3 py-1.5 rounded-lg bg-slate-800 text-xs text-slate-200 border border-slate-700">Retry</button>
        </div>
      ) : rows.length === 0 ? (
        <div className="p-8 rounded-xl bg-[#0F1420] border border-slate-800 text-center">
          <Layers className="w-6 h-6 text-slate-500 mx-auto mb-2" />
          <p className="text-sm text-slate-200 font-medium">No capabilities found</p>
          <p className="text-xs text-slate-500 mt-1">The backend capability catalogue is empty or the search has no matches.</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {rows.map((c) => {
            const attached = sources.filter((s) => s.capabilityId === c.capability_id || s.capabilityName === c.implementation_ref);
            const live = c.implementation_ref !== 'planned';
            return (
              <section key={c.capability_id} aria-label={`Capability ${c.name}`} className="p-4 rounded-xl bg-[#0F1420] border border-slate-800 space-y-3">
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <h2 className="text-sm font-semibold text-slate-100">{c.name}</h2>
                    <p className="text-[11px] font-mono text-slate-500">{c.capability_id}{c.human_id ? ` · ${c.human_id}` : ''}</p>
                    <p className="text-xs text-slate-400 mt-1">{c.description}</p>
                  </div>
                  <span className={`text-[10px] font-mono px-2 py-0.5 rounded border ${c.status === 'active' ? 'bg-emerald-950 text-emerald-300 border-emerald-800' : c.status === 'planned' ? 'bg-slate-800 text-slate-400 border-slate-700' : 'bg-amber-950 text-amber-300 border-amber-800'}`}>
                    {c.status}{live ? '' : ' · no live impl'}
                  </span>
                </div>
                <dl className="grid grid-cols-3 gap-2 text-[11px] font-mono">
                  <div className="p-2 rounded bg-slate-900 border border-slate-800">
                    <dt className="text-slate-500">Sources</dt>
                    <dd className="text-slate-100 text-sm font-semibold">{c.source_count ?? attached.length}</dd>
                  </div>
                  <div className="p-2 rounded bg-slate-900 border border-slate-800">
                    <dt className="text-slate-500">Version</dt>
                    <dd className="text-slate-200">v{c.version}</dd>
                  </div>
                  <div className="p-2 rounded bg-slate-900 border border-slate-800">
                    <dt className="text-slate-500">Impl</dt>
                    <dd className="text-slate-200">{c.implementation_ref}</dd>
                  </div>
                </dl>
                <p className="text-[11px] font-mono text-slate-400">{(c.rule_ids || []).length} rules · {(c.pattern_ids || []).length} patterns</p>
                <div className="flex flex-wrap gap-2 pt-1 border-t border-slate-800/80">
                  <button
                    type="button"
                    onClick={() => void openDetail(c.capability_id)}
                    className="flex items-center gap-1 px-2.5 py-1 rounded bg-slate-100 text-slate-900 text-[11px] font-mono font-semibold"
                  >
                    <Eye className="w-3.5 h-3.5" />
                    <span>{selectedCapabilityId === c.capability_id ? 'Selected' : 'Open'}</span>
                  </button>
                  {isAdmin && lifecycleFor(c).map((a) => (
                    <button
                      key={a}
                      type="button"
                      title={`capability.${a}`}
                      onClick={() => void act(a, c)}
                      className="flex items-center gap-1 px-2.5 py-1 rounded bg-slate-900 hover:bg-slate-800 text-slate-200 border border-slate-700 text-[11px] font-mono"
                    >
                      {a === 'enable' ? <CheckCircle className="w-3.5 h-3.5" /> : a === 'disable' ? <PauseCircle className="w-3.5 h-3.5" /> : <Archive className="w-3.5 h-3.5" />}
                      <span>{a[0].toUpperCase() + a.slice(1)}</span>
                    </button>
                  ))}
                </div>
              </section>
            );
          })}
        </div>
      )}
      {creating && (
        <div className="p-4 rounded-xl bg-[#0F1420] border border-slate-700 space-y-3" role="dialog" aria-label="Create capability">
          <h2 className="text-sm font-semibold text-slate-100">Create capability</h2>
          <p className="text-[11px] font-mono text-slate-500">{'ID pattern cap-<slug> (lowercase, digits, hyphens). implementation_ref is allowlisted; code uploads are not supported.'}</p>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
            <input value={formId} onChange={(e) => setFormId(e.target.value)} placeholder="cap-my-family" aria-label="capability_id" className="px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-xs text-slate-100" />
            <input value={formName} onChange={(e) => setFormName(e.target.value)} placeholder="Display name" aria-label="name" className="px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-xs text-slate-100" />
            <input value={formDesc} onChange={(e) => setFormDesc(e.target.value)} placeholder="Description" aria-label="description" className="px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-xs text-slate-100 sm:col-span-2" />
            <input value={formResp} onChange={(e) => setFormResp(e.target.value)} placeholder="Responsibility (what this capability owns)" aria-label="responsibility" className="px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-xs text-slate-100 sm:col-span-2" />
            <select value={formImpl} onChange={(e) => setFormImpl(e.target.value)} aria-label="implementation_ref" className="px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-xs text-slate-100">
              {['planned', 'nginx', 'simulator'].map((v) => <option key={v} value={v}>{v}</option>)}
            </select>
          </div>
          {formError && <p className="text-[11px] font-mono text-rose-300" role="alert">{formError}</p>}
          <div className="flex gap-2">
            <button type="button" onClick={() => void submitCreate()} className="px-4 py-1.5 rounded-lg bg-slate-100 text-slate-900 text-xs font-semibold">Create</button>
            <button type="button" onClick={() => setCreating(false)} className="px-4 py-1.5 rounded-lg bg-slate-800 text-slate-200 text-xs border border-slate-700">Cancel</button>
          </div>
        </div>
      )}
      {capabilityDetail && (
        <div className="p-4 rounded-xl bg-[#0F1420] border border-slate-700 space-y-3" aria-label={`Capability detail ${capabilityDetail.name}`}>
          <div className="flex items-start justify-between gap-3">
            <div>
              <h2 className="text-sm font-semibold text-slate-100">{capabilityDetail.name}</h2>
              <p className="text-[11px] font-mono text-slate-500">{capabilityDetail.capability_id}{capabilityDetail.human_id ? ` · ${capabilityDetail.human_id}` : ''} · {capabilityDetail.status} · v{capabilityDetail.version} · impl={capabilityDetail.implementation_ref}</p>
              <p className="text-xs text-slate-400 mt-1">{capabilityDetail.description || '—'}</p>
              {capabilityDetail.responsibility && <p className="text-[11px] font-mono text-slate-500 mt-1">Owns: {capabilityDetail.responsibility}</p>}
            </div>
            {isAdmin && (
              <div className="flex flex-wrap gap-2 justify-end">
                <button type="button" onClick={() => setEditing(!editing)} className="px-2.5 py-1 rounded bg-slate-800 text-slate-200 border border-slate-700 text-[11px] font-mono">Edit</button>
                {lifecycleFor(capabilityDetail).map((a) => (
                  <button key={a} type="button" title={`capability.${a}`} onClick={() => void act(a, capabilityDetail)} className="px-2.5 py-1 rounded bg-slate-900 text-slate-200 border border-slate-700 text-[11px] font-mono">{a}</button>
                ))}
              </div>
            )}
          </div>
          {editing && isAdmin && (
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
              <input value={editDesc} onChange={(e) => setEditDesc(e.target.value)} aria-label="description" placeholder="Description" className="px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-xs text-slate-100" />
              <input value={editResp} onChange={(e) => setEditResp(e.target.value)} aria-label="responsibility" placeholder="Responsibility" className="px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-xs text-slate-100" />
              <input value={editVersion} onChange={(e) => setEditVersion(e.target.value)} aria-label="version" placeholder="version (must increase)" inputMode="numeric" className="px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-xs text-slate-100" />
              <div className="sm:col-span-3 flex gap-2">
                <button type="button" onClick={() => void submitEdit()} className="px-4 py-1.5 rounded-lg bg-slate-100 text-slate-900 text-xs font-semibold">Save</button>
                <button type="button" onClick={() => setEditing(false)} className="px-4 py-1.5 rounded-lg bg-slate-800 text-slate-200 text-xs border border-slate-700">Cancel</button>
              </div>
              {formError && <p className="text-[11px] font-mono text-rose-300 sm:col-span-3" role="alert">{formError}</p>}
            </div>
          )}
          <div className="flex gap-2 flex-wrap">
            {(['overview', 'sources', 'rules', 'patterns', 'health', 'versions'] as const).map((t) => (
              <button key={t} type="button" onClick={() => void switchTab(t)} className={`px-3 py-1 rounded text-[11px] font-mono border ${tab === t ? 'bg-slate-100 text-slate-900 border-slate-100' : 'bg-slate-900 text-slate-300 border-slate-700'}`}>{t[0].toUpperCase() + t.slice(1)}</button>
            ))}
          </div>
          {tab === 'overview' && (
            capabilityRelationsLoaded ? (
              <pre className="text-[11px] font-mono text-slate-300 whitespace-pre-wrap">rule_ids: {JSON.stringify(capabilityDetail.rule_ids || [])}{'\n'}pattern_ids: {JSON.stringify(capabilityDetail.pattern_ids || [])}{'\n'}mapping_profiles: {JSON.stringify(capabilityDetail.mapping_profiles || [])}</pre>
            ) : (
              /* 5.1-03: never render empty rule_ids while the relations
                 fetch is in flight — an empty array would falsely claim
                 "no rules attached". */
              <pre className="text-[11px] font-mono text-slate-400 whitespace-pre-wrap">Loading derived relations from capability.get…</pre>
            )
          )}
          {tab === 'sources' && (
            <div className="text-[11px] font-mono text-slate-300">
              {(capabilitySources?.sources || []).length === 0
                ? (capabilityDetail.implementation_ref === 'planned'
                  ? 'No sources attached. Planned capabilities own no live sources — this empty view is the correct backend state.'
                  : 'No sources attached. The backend view is truthfully empty.')
                : `${capabilitySources?.count} source(s): ` + (capabilitySources?.sources as { source_instance_id?: string }[]).map((s) => s.source_instance_id).join(', ')}
            </div>
          )}
          {tab === 'rules' && (
            <div className="text-[11px] font-mono text-slate-300">
              {(capabilityRules?.rules || []).length === 0
                ? (capabilityDetail.implementation_ref === 'planned'
                  ? 'No rules attached. Planned capabilities own no live rules — this empty view is the correct backend state.'
                  : 'No rules attached. The backend view is truthfully empty.')
                : `${capabilityRules?.count} rule(s): ` + (capabilityRules?.rules as { rule_id?: string }[]).map((r) => r.rule_id).join(', ')}
            </div>
          )}
          {tab === 'patterns' && (
            <div className="text-[11px] font-mono text-slate-300">
              {(capabilityPatterns?.patterns || []).length === 0
                ? (capabilityDetail.implementation_ref === 'planned'
                  ? 'No patterns attached. Planned capabilities own no live patterns — this empty view is the correct backend state.'
                  : 'No patterns attached. The backend view is truthfully empty.')
                : `${capabilityPatterns?.count} pattern(s): ` + (capabilityPatterns?.patterns || []).map((p) => p.pattern_id).join(', ')}
            </div>
          )}
          {tab === 'health' && (
            /* §18.19 Health tab: truthful per-capability health facts.
               Phase 5.1 has no per-capability runtime probe — connector
               health belongs to the source instances (5.2 binding), so
               this view reports only what the backend truly knows. */
            <div className="text-[11px] font-mono text-slate-300 space-y-1">
              <p>implementation: {capabilityDetail.implementation_ref === 'planned'
                ? 'planned — no live connector implementation exists for this family'
                : `live connector family (${capabilityDetail.implementation_ref})`}</p>
              <p>lifecycle status: {capabilityDetail.status}</p>
              <p>derived coverage: {(capabilityDetail.rule_ids || []).length} rule(s), {(capabilityDetail.pattern_ids || []).length} pattern(s){capabilityDetail.source_count != null ? `, ${capabilityDetail.source_count} source instance(s)` : ''}</p>
              <p>created: {formatIstTimestamp(capabilityDetail.created_at)} · last updated: {formatIstTimestamp(capabilityDetail.updated_at)}</p>
              {capabilityDetail.retired_at && <p>retired at: {formatIstTimestamp(capabilityDetail.retired_at)}</p>}
              {capabilityDetail.archived_at && <p>archived at: {capabilityDetail.archived_at}</p>}
              <p className="text-slate-500">Runtime connector health is reported per source instance (see Sources); a capability owns the implementation, its source instances own the runtime state.</p>
            </div>
          )}
          {tab === 'versions' && (
            /* §18.19 Versions tab: current version + §18.27 audit trail.
               All data is read from the persisted capability_audit
               collection via capability.audit — nothing is fabricated. */
            <div className="text-[11px] font-mono text-slate-300 space-y-1">
              <p>current version: v{capabilityDetail.version} · created_by {capabilityDetail.created_by || '—'} · updated_by {capabilityDetail.updated_by || '—'}</p>
              {!capabilityAudit || capabilityAudit.capability_id !== selectedCapabilityId ? (
                <p className="text-slate-400">Loading audit trail from capability.audit…</p>
              ) : capabilityAudit.records.length === 0 ? (
                <p className="text-slate-400">No audit records for this capability — the trail is truthfully empty.</p>
              ) : (
                <div className="space-y-1">
                  {capabilityAudit.records.map((r, i) => (
                    <p key={i} className="text-slate-300">
                      {r.at} · {r.action} · by {r.actor}{r.after && typeof r.after.version === 'number' ? ` · v${r.after.version}` : ''}{r.changed_fields && r.changed_fields.length ? ` · changed: ${r.changed_fields.join(', ')}` : ''}
                    </p>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
};
