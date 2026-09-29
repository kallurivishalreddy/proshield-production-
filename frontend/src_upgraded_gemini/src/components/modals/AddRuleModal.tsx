import React, { useState } from 'react';
import { X, Sliders, CheckCircle, Code } from 'lucide-react';
import { useSoc } from '../../context/SocContext';
import { Severity } from '../../types/soc';

export const AddRuleModal: React.FC = () => {
  const {
    isAddRuleModalOpen,
    setAddRuleModalOpen,
    capabilities,
    sources,
    addRule
  } = useSoc();

  const [capabilityId, setCapabilityId] = useState('conn-nginx');
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [severity, setSeverity] = useState<Severity>('HIGH');
  // NOTE: the current backend rule engine accepts STRUCTURED condition
  // definitions only. Sigma / YARA-L / CEL free-text authoring has no
  // compiler on the backend — the DSL selector was removed and the truth
  // is shown to the analyst (documented backend gap).
  const [selectedSources, setSelectedSources] = useState<string[]>([]);
  const [logicCode, setLogicCode] = useState(`{
  "combinator": "and",
  "conditions": []
}`);
  const [submitting, setSubmitting] = useState(false);

  if (!isAddRuleModalOpen) return null;

  const selectedCapability = capabilities.find(c => c.id === capabilityId);
  const applicableSources = sources.filter(s => s.capabilityId === capabilityId);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim() || submitting) return;

    setSubmitting(true);
    const ok = await addRule({
      name,
      description: description || 'Automated detection rule triggered on telemetry stream.',
      severity,
      capabilityId,
      capabilityName: selectedCapability?.name || 'ALL SOURCES',
      scope: selectedSources,
      dslType: undefined, // no DSL compilation exists on the backend today
      logicCode
    });
    setSubmitting(false);
    if (ok) {
      setAddRuleModalOpen(false);
      setName('');
      setDescription('');
    }
  };

  const toggleSourceSelection = (sourceId: string) => {
    setSelectedSources(prev =>
      prev.includes(sourceId)
        ? prev.filter(id => id !== sourceId)
        : [...prev, sourceId]
    );
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-in fade-in duration-200">
      <div className="relative w-full max-w-3xl rounded-xl bg-[#0F1420] border border-slate-700 shadow-2xl overflow-hidden max-h-[90vh] flex flex-col">
        {/* Header */}
        <div className="flex items-center justify-between p-4 border-b border-slate-800 bg-[#0A0D15]">
          <div className="flex items-center gap-2.5">
            <div className="p-1.5 rounded bg-sky-950 text-sky-400 border border-sky-500/30">
              <Sliders className="w-4 h-4" />
            </div>
            <div>
              <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-sky-400">
                SECURITY DETECTION CONTROLS
              </span>
              <h3 className="text-sm font-bold text-slate-100 font-mono">
                CREATE DETECTION RULE FOR EXISTING CAPABILITY
              </h3>
            </div>
          </div>
          <button
            onClick={() => setAddRuleModalOpen(false)}
            className="p-1 rounded text-slate-400 hover:text-white transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Scrollable Form Body */}
        <form onSubmit={handleSubmit} className="p-5 space-y-4 text-xs overflow-y-auto flex-1">
          {/* 1. Connector Capability Selection */}
          <div>
            <label className="block text-xs font-semibold text-slate-300 mb-1 font-mono uppercase tracking-wider">
              1. Target Connector Capability Scope *
            </label>
            <select
              value={capabilityId}
              onChange={e => setCapabilityId(e.target.value)}
              className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-slate-100 focus:outline-none focus:border-cyan-500 font-mono text-xs"
            >
              {capabilities.map(cap => (
                <option key={cap.id} value={cap.id}>
                  {cap.name} ({cap.category}) — {cap.version}
                </option>
              ))}
            </select>
          </div>

          {/* 2. Rule Identity & Purpose */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <div>
              <label className="block text-xs font-semibold text-slate-300 mb-1 font-mono uppercase tracking-wider">
                2. Rule Name (Human Facing) *
              </label>
              <input
                type="text"
                required
                value={name}
                onChange={e => setName(e.target.value)}
                placeholder="e.g., NGINX URI Path Traversal Scan"
                className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-cyan-500 font-sans text-xs"
              />
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-300 mb-1 font-mono uppercase tracking-wider">
                Severity Rating *
              </label>
              <select
                value={severity}
                onChange={e => setSeverity(e.target.value as Severity)}
                className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-slate-100 focus:outline-none focus:border-cyan-500 font-mono text-xs"
              >
                <option value="CRITICAL">CRITICAL — Immediate Pager Alert</option>
                <option value="HIGH">HIGH — SOC Queue Priority</option>
                <option value="MEDIUM">MEDIUM — Triage Attention</option>
                <option value="LOW">LOW — Audit / Correlation Only</option>
                <option value="INFORMATIONAL">INFORMATIONAL — Context</option>
              </select>
            </div>
          </div>

          <div>
            <label className="block text-xs font-semibold text-slate-300 mb-1 font-mono uppercase tracking-wider">
              3. Analyst Plain-Language Purpose Description *
            </label>
            <textarea
              rows={2}
              required
              value={description}
              onChange={e => setDescription(e.target.value)}
              placeholder="Detect repeated probe patterns targeting sensitive administrative endpoints that may indicate reconnaissance before an exploit."
              className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-cyan-500 font-sans text-xs"
            />
          </div>

          {/* 4. Source Instance Scope Binding */}
          <div>
            <label className="block text-xs font-semibold text-slate-300 mb-1 font-mono uppercase tracking-wider">
              4. Apply to Source Instances ({applicableSources.length} Available)
            </label>
            <div className="flex flex-wrap gap-2 p-2.5 rounded-lg bg-slate-900/80 border border-slate-800">
              {applicableSources.length === 0 ? (
                <span className="text-slate-500 text-xs">No active source instances using this connector capability yet. Will apply globally upon deployment.</span>
              ) : (
                applicableSources.map(s => (
                  <button
                    key={s.humanId}
                    type="button"
                    onClick={() => toggleSourceSelection(s.humanId)}
                    className={`px-2.5 py-1 rounded font-mono text-xs transition-colors border ${
                      selectedSources.includes(s.humanId)
                        ? 'bg-cyan-950/80 border-cyan-500 text-cyan-200'
                        : 'bg-slate-800 border-slate-700 text-slate-400 hover:border-slate-600'
                    }`}
                  >
                    {s.humanId} — {s.name}
                  </button>
                ))
              )}
            </div>
          </div>

          {/* 5. Logic Definition Editor */}
          <div>
            <div className="flex items-center justify-between mb-1">
              <label className="text-xs font-semibold text-slate-300 font-mono uppercase tracking-wider flex items-center gap-1.5">
                <Code className="w-3.5 h-3.5 text-cyan-400" />
                <span>5. Detection Logic DSL</span>
              </label>
              <span
                className="text-[10px] font-mono text-amber-300/90"
                title="The current backend accepts structured condition JSON only. Sigma/YARA-L/CEL compilation is a documented backend gap."
              >
                ⚠ Sigma/YARA-L/CEL not compiled by backend
              </span>
            </div>
            <textarea
              rows={6}
              value={logicCode}
              onChange={e => setLogicCode(e.target.value)}
              className="w-full px-3 py-2 rounded-lg bg-[#070A10] border border-slate-800 text-cyan-200 font-mono text-xs focus:outline-none focus:border-cyan-500 leading-relaxed"
            />
          </div>

          {/* Footer Actions */}
          <div className="flex items-center justify-between pt-3 border-t border-slate-800">
            <span className="text-[11px] font-mono text-slate-500">
              New rules start in <span className="text-amber-300 font-bold">CANDIDATE</span> state
              (backend governance: promote to APPROVED before enabling)
            </span>
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => setAddRuleModalOpen(false)}
                className="px-3.5 py-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 font-mono text-xs transition-colors"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={submitting}
                className="flex items-center gap-1.5 px-4 py-1.5 rounded-lg bg-slate-100 hover:bg-white disabled:bg-slate-800 disabled:text-slate-600 text-slate-900 font-mono font-semibold text-xs transition-colors"
              >
                <CheckCircle className="w-3.5 h-3.5" />
                <span>{submitting ? 'Saving...' : 'Save'}</span>
              </button>
            </div>
          </div>
        </form>
      </div>
    </div>
  );
};
