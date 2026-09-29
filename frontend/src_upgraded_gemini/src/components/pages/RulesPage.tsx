import React, { useState } from 'react';
import {
  Plus,
  Search,
  Code,
  Archive,
  Terminal,
  X
} from 'lucide-react';
import { useSoc } from '../../context/SocContext';
import { Severity } from '../../types/soc';
import { SeverityBadge } from '../common/SeverityBadge';
import { StatusBadge } from '../common/StatusBadge';
import { HumanIdTag } from '../common/HumanIdTag';

export const RulesPage: React.FC = () => {
  const {
    rules,
    registryCapabilities,
    setAddRuleModalOpen,
    toggleRuleStatus,
    retireRule,
    openPayloadDrawer,
    navigate
  } = useSoc();

  const [searchQuery, setSearchQuery] = useState('');
  const [selectedCapabilityFilter, setSelectedCapabilityFilter] = useState<string>('ALL');
  const [severityFilter, setSeverityFilter] = useState<Severity | 'ALL'>('ALL');

  const filteredRules = rules.filter(r => {
    const q = searchQuery.toLowerCase().trim();
    const matchesSearch =
      !q ||
      r.humanId.toLowerCase().includes(q) ||
      r.name.toLowerCase().includes(q) ||
      r.description.toLowerCase().includes(q) ||
      r.capabilityName.toLowerCase().includes(q);

    const matchesCap = selectedCapabilityFilter === 'ALL' || r.capabilityId === selectedCapabilityFilter;
    const matchesSev = severityFilter === 'ALL' || r.severity === severityFilter;

    return matchesSearch && matchesCap && matchesSev;
  });

  return (
    <div className="space-y-6 pb-12 animate-in fade-in duration-200">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-2 border-b border-slate-800">
        <div>
          <div className="flex flex-wrap items-center gap-2">
            <h1 className="text-lg font-semibold tracking-tight text-slate-100">
              Rules
            </h1>
            <span className="text-[11px] font-mono px-2 py-0.5 rounded-full bg-slate-800 text-slate-200 border border-slate-700">
              {rules.length} rules
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Enabled rules evaluate incoming telemetry. New rules start as candidates.
          </p>
        </div>

        {/* Primary Action */}
        <button
          onClick={() => setAddRuleModalOpen(true)}
          className="flex items-center gap-2 px-4 py-2 rounded-lg bg-slate-100 hover:bg-white text-slate-900 font-mono font-semibold text-xs transition-colors"
        >
          <Plus className="w-4 h-4" />
          <span>Create rule</span>
        </button>
      </div>

      {/* Filter and Search Bar */}
      <div className="p-3.5 rounded-xl bg-[#0F1420] border border-slate-800 flex flex-col lg:flex-row items-stretch lg:items-center justify-between gap-3">
        <div className="relative flex-1">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={searchQuery}
            onChange={e => setSearchQuery(e.target.value)}
            placeholder="Search rules by ID, rule name, purpose description, or connector..."
            className="w-full pl-9 pr-8 py-2 rounded-lg bg-slate-900 border border-slate-700 text-xs text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-sky-500 font-mono"
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

        <div className="flex flex-wrap items-center gap-2 text-xs font-mono">
          <select
            value={selectedCapabilityFilter}
            onChange={e => setSelectedCapabilityFilter(e.target.value)}
            className="px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-xs text-slate-200 focus:outline-none font-mono"
          >
            <option value="ALL">All Capabilities</option>
            {registryCapabilities.map(cap => (
              <option key={cap.capability_id} value={cap.capability_id}>
                {cap.name}
              </option>
            ))}
          </select>

          <select
            value={severityFilter}
            onChange={e => setSeverityFilter(e.target.value as any)}
            className="px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-xs text-slate-200 focus:outline-none font-mono"
          >
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>
        </div>
      </div>

      {/* Rules List */}
      <div className="space-y-4">
        {filteredRules.map(rule => (
          <div
            key={rule.humanId}
            className="p-5 rounded-xl bg-[#0F1420] border border-slate-800 hover:border-sky-500/40 transition-all shadow-xl space-y-4"
          >
            {/* Top Row: Identity, Severity, Lifecycle */}
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-800">
              <div className="flex flex-wrap items-center gap-2.5">
                <HumanIdTag humanId={rule.humanId} internalUuid={rule.internalUuid} size="lg" />
                <SeverityBadge severity={rule.severity} size="md" />
                <StatusBadge status={rule.lifecycleStatus} size="md" />
                <span
                  className="text-xs font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300"
                  title="The backend evaluates structured condition definitions; no Sigma/YARA-L/CEL compilation exists (documented gap)"
                >
                  {rule.dslType ? `${rule.dslType} DSL` : 'STRUCTURED (backend engine)'}
                </span>
                <h3 className="text-base font-bold text-slate-100 font-mono">
                  {rule.name}
                </h3>
              </div>

              <div className="flex items-center gap-2 text-xs font-mono text-slate-400">
                <span>Scope:</span>
                <span
                  className="text-slate-200 font-semibold"
                  data-testid={`rule-scope-${rule.humanId}`}
                  data-capability-id={rule.capabilityId}
                >
                  {rule.capabilityName
                    ? rule.capabilityName
                    : rule.scope.length > 0
                      ? `${rule.scope.join(", ")} — no capability owner`
                      : "NO CAPABILITY OWNER"}
                </span>
              </div>
            </div>

            {/* Purpose Description */}
            <div className="space-y-1">
              <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-sky-400">
                Rule Purpose & Threat Detection Rationale:
              </span>
              <p className="text-xs text-slate-300 leading-relaxed font-sans">
                {rule.description}
              </p>
            </div>

            {/* Scope Tags & Author */}
            <div className="flex flex-wrap items-center justify-between gap-2 p-3 rounded-lg bg-[#0A0D15] border border-slate-800/80 font-mono text-xs text-slate-400">
              <div className="flex items-center gap-2">
                <span>Active Bound Sources:</span>
                {rule.scope.length === 0 ? (
                  <span className="text-slate-500">All connector instances</span>
                ) : (
                  rule.scope.map(s => (
                    <span key={s} className="px-1.5 py-0.5 rounded bg-slate-800 text-cyan-300">
                      {s}
                    </span>
                  ))
                )}
              </div>

              <div>
                <span>Author: <strong className="text-slate-200">{rule.author}</strong></span>
              </div>
            </div>

            {/* Detection Logic Preview */}
            <div className="p-3 rounded-lg bg-[#070A10] border border-slate-800/80 space-y-1.5 font-mono text-xs">
              <div className="flex items-center justify-between text-slate-400 text-[10px]">
                <span className="font-bold flex items-center gap-1 text-slate-300">
                  <Code className="w-3 h-3 text-cyan-400" /> Detection Definition ({rule.dslType || 'backend structured conditions'})
                </span>
                <span>Last compiled: {rule.lastModified}</span>
              </div>
              <pre className="text-cyan-200 text-[11px] leading-relaxed max-h-32 overflow-y-auto whitespace-pre-wrap select-text">
                {rule.logicCode}
              </pre>
            </div>

            {/* Operational Actions */}
            <div className="flex flex-wrap items-center justify-between gap-3 pt-2 border-t border-slate-800/80 font-mono text-xs">
              <div className="flex items-center gap-2 text-slate-400 text-[11px]">
                <span>Historical Matches:</span>
                <button
                  onClick={() => navigate('detections')}
                  className="text-amber-400 hover:underline font-bold"
                >
                  {rule.affectedDetectionsCount} detections triggered
                </button>
              </div>

              <div className="flex items-center gap-2">
                <button
                  onClick={() =>
                    openPayloadDrawer({
                      title: `Detection Rule Logic: ${rule.name}`,
                      subtitle: `${rule.humanId} • DSL: ${rule.dslType}`,
                      humanId: rule.humanId,
                      internalUuid: rule.internalUuid,
                      payload: {
                        rule_id: rule.humanId,
                        name: rule.name,
                        severity: rule.severity,
                        status: rule.lifecycleStatus,
                        dsl: rule.dslType,
                        logic: rule.logicCode,
                        scope: rule.scope,
                        author: rule.author
                      }
                    })
                  }
                  className="flex items-center gap-1 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-slate-700 text-xs transition-colors"
                >
                  <Terminal className="w-3.5 h-3.5" />
                  <span>Inspect Code</span>
                </button>

                <button
                  onClick={() => toggleRuleStatus(rule.humanId)}
                  className={`px-3 py-1 rounded text-xs font-bold transition-colors border ${
                    rule.lifecycleStatus === 'ACTIVE'
                      ? 'bg-slate-800 text-amber-300 border-slate-700 hover:bg-amber-950/60'
                      : 'bg-emerald-600 text-white border-emerald-500 hover:bg-emerald-500'
                  }`}
                >
                  {rule.lifecycleStatus === 'ACTIVE' ? 'Disable Rule' : 'Activate Rule'}
                </button>

                <button
                  onClick={() => retireRule(rule.humanId)}
                  className="p-1.5 rounded text-slate-500 hover:text-rose-400 hover:bg-slate-800 transition-colors"
                  title="Retire Rule"
                >
                  <Archive className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
