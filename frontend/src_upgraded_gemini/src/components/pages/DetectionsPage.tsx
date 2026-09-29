import React, { useState } from 'react';
import {
  Search,
  Radio,
  Sliders,
  Terminal,
  ArrowRight,
  X
} from 'lucide-react';
import { useSoc } from '../../context/SocContext';
import { Severity } from '../../types/soc';
import { SeverityBadge } from '../common/SeverityBadge';
import { HumanIdTag } from '../common/HumanIdTag';
import { formatIstTimestamp } from '../../utils/format';

export const DetectionsPage: React.FC = () => {
  const {
    detections,
    navigate,
    openPayloadDrawer
  } = useSoc();

  const [searchQuery, setSearchQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState<Severity | 'ALL'>('ALL');
  const [sourceFilter, setSourceFilter] = useState<string>('ALL');

  const sourcesList = Array.from(new Set(detections.map(d => d.sourceId)));

  const filteredDetections = detections.filter(d => {
    const q = searchQuery.toLowerCase().trim();
    const matchesSearch =
      !q ||
      d.humanId.toLowerCase().includes(q) ||
      d.title.toLowerCase().includes(q) ||
      d.ruleName.toLowerCase().includes(q) ||
      d.evidenceSummary.toLowerCase().includes(q) ||
      (d.attackerIp && d.attackerIp.toLowerCase().includes(q));

    const matchesSeverity = severityFilter === 'ALL' || d.severity === severityFilter;
    const matchesSource = sourceFilter === 'ALL' || d.sourceId === sourceFilter;

    return matchesSearch && matchesSeverity && matchesSource;
  });

  return (
    <div className="space-y-4 pb-12 animate-in fade-in duration-200">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-2 border-b border-slate-800">
        <div>
          <div className="flex flex-wrap items-center gap-2">
            <h1 className="text-lg font-semibold tracking-tight text-slate-100">
              Detections
            </h1>
            <span className="text-[11px] font-mono px-2 py-0.5 rounded-full bg-slate-800 text-slate-200 border border-slate-700">
              {filteredDetections.length} shown
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Source event → detection → correlation → case. Select a detection to inspect its rule and evidence.
          </p>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="p-3.5 rounded-xl bg-[#0F1420] border border-slate-800 flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3">
        <div className="relative flex-1">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={searchQuery}
            onChange={e => setSearchQuery(e.target.value)}
            placeholder="Search detections by ID, rule name, IP, evidence string..."
            className="w-full pl-9 pr-8 py-2 rounded-lg bg-slate-900 border border-slate-700 text-xs text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-amber-500 font-mono"
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

        <div className="flex items-center gap-2 text-xs font-mono">
          <select
            value={severityFilter}
            onChange={e => setSeverityFilter(e.target.value as any)}
            className="px-2.5 py-2 rounded-lg bg-slate-900 border border-slate-700 text-xs text-slate-200 focus:outline-none font-mono"
          >
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>

          <select
            value={sourceFilter}
            onChange={e => setSourceFilter(e.target.value)}
            className="px-2.5 py-2 rounded-lg bg-slate-900 border border-slate-700 text-xs text-slate-200 focus:outline-none font-mono"
          >
            <option value="ALL">All Sources</option>
            {sourcesList.map(s => (
              <option key={s} value={s}>{s}</option>
            ))}
          </select>
        </div>
      </div>

      {/* Detection Cards List */}
      <div className="space-y-3">
        {filteredDetections.length > 60 && (
          <div className="p-2.5 rounded-lg bg-slate-900/70 border border-slate-800 text-[11px] font-mono text-slate-400">
            Showing the first 60 of {filteredDetections.length} matching detections — refine the
            search/filters to narrow the set (render-cap protects browser performance).
          </div>
        )}
        {filteredDetections.length === 0 ? (
          <div className="p-12 text-center rounded-xl bg-[#0F1420] border border-slate-800 text-slate-500">
            <Radio className="w-8 h-8 mx-auto text-slate-600 mb-2" />
            <p className="text-sm">No detections matched your filters.</p>
          </div>
        ) : (
          // Render cap: the backend list op is capped at 200; rendering all
          // cards at once is a DOM-performance hazard, so show the first 60
          // and tell the analyst how to narrow the set.
          filteredDetections.slice(0, 60).map(det => (
            <div
              key={det.humanId}
              className="p-4 rounded-xl bg-[#0F1420] border border-slate-800 hover:border-amber-500/40 transition-all shadow-md space-y-3"
            >
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                <div className="flex items-center gap-2.5">
                  <HumanIdTag humanId={det.humanId} internalUuid={det.internalUuid} size="md" />
                  <SeverityBadge severity={det.severity} size="sm" />
                  <h3 className="text-sm font-bold text-slate-100 font-mono">
                    {det.title}
                  </h3>
                </div>

                <div className="flex items-center gap-2 text-xs font-mono text-slate-400">
                  <span>Timestamp:</span>
                  <span className="text-slate-200">{formatIstTimestamp(det.timestamp)}</span>
                </div>
              </div>

              {/* Evidence Text */}
              <p className="text-xs text-slate-300 leading-relaxed bg-[#0A0D15] p-3 rounded-lg border border-slate-800/80">
                {det.evidenceSummary}
              </p>

              {/* Matched Fields Tags */}
              <div className="flex flex-wrap gap-2 text-xs font-mono">
                {det.matchedFields.map((field, idx) => (
                  <span
                    key={idx}
                    className="px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-slate-300"
                  >
                    <span className="text-amber-400 font-semibold">{field.field}:</span> {field.value}
                  </span>
                ))}
              </div>

              {/* Pivot Navigation Links & Actions */}
              <div className="flex flex-wrap items-center justify-between gap-3 pt-3 border-t border-slate-800/80 text-xs font-mono">
                <div className="flex flex-wrap items-center gap-3 text-slate-400">
                  <div className="flex items-center gap-1.5">
                    <Sliders className="w-3.5 h-3.5 text-sky-400" />
                    <span>Rule:</span>
                    <button
                      onClick={() => navigate('rules', det.ruleId)}
                      className="text-sky-300 hover:underline font-bold"
                    >
                      {det.ruleName} ({det.ruleId})
                    </button>
                  </div>

                  <span>•</span>

                  <div>
                    <span>Source:</span>{' '}
                    {det.sourceName ? (
                      <strong className="text-cyan-300">{det.sourceName} ({det.sourceId})</strong>
                    ) : (
                      <span className="text-slate-500" title="Backend detections do not carry source attribution (documented gap)">not attributed</span>
                    )}
                  </div>

                  {det.caseId && (
                    <>
                      <span>•</span>
                      <div className="flex items-center gap-1">
                        <span>Case:</span>
                        <HumanIdTag humanId={det.caseId} size="sm" />
                      </div>
                    </>
                  )}
                </div>

                <div className="flex items-center gap-2">
                  <button
                    onClick={() =>
                      openPayloadDrawer({
                        title: det.title,
                        subtitle: `${det.humanId} • Rule: ${det.ruleName}`,
                        humanId: det.humanId,
                        internalUuid: det.internalUuid,
                        payload: det.rawPayload
                      })
                    }
                    className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-slate-700 text-xs transition-colors"
                  >
                    <Terminal className="w-3.5 h-3.5" />
                    <span>Inspect Raw Log</span>
                  </button>

                  {det.caseId && (
                    <button
                      onClick={() => navigate('case-detail', det.caseId)}
                      className="flex items-center gap-1 px-3 py-1 rounded bg-amber-600 hover:bg-amber-500 text-white font-bold text-xs transition-colors shadow-[0_0_10px_rgba(245,158,11,0.3)]"
                    >
                      <span>Investigate Case</span>
                      <ArrowRight className="w-3.5 h-3.5" />
                    </button>
                  )}
                </div>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
};
