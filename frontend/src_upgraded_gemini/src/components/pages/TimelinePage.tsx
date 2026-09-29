import React, { useEffect, useState } from 'react';
import {
  Search,
  Terminal,
  Activity,
  Radio,
  Network,
  Shield,
  MessageSquare,
  RefreshCw,
  X
} from 'lucide-react';
import { useSoc } from '../../context/SocContext';
import { TimelineEventType } from '../../types/soc';
import { SeverityBadge } from '../common/SeverityBadge';
import { HumanIdTag } from '../common/HumanIdTag';
import { formatIstTimestamp } from '../../utils/format';

export const TimelinePage: React.FC = () => {
  const {
    timelineEvents,
    openPayloadDrawer,
    cases,
    selectedCaseId,
    setSelectedCaseId,
    loadCaseTimeline,
    refreshAll
  } = useSoc();

  const [searchQuery, setSearchQuery] = useState('');
  const [selectedType, setSelectedType] = useState<TimelineEventType | 'ALL'>('ALL');
  const [loading, setLoading] = useState(false);

  // The timeline wire operation is per-incident: build the timeline of the
  // selected (or first) case from real backend evidence on mount/switch.
  useEffect(() => {
    let cancelled = false;
    (async () => {
      setLoading(true);
      await loadCaseTimeline(selectedCaseId || '');
      if (!cancelled) setLoading(false);
    })();
    return () => { cancelled = true; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedCaseId]);

  const filteredEvents = timelineEvents.filter(evt => {
    const q = searchQuery.toLowerCase().trim();
    const matchesSearch =
      !q ||
      evt.title.toLowerCase().includes(q) ||
      evt.shortExplanation.toLowerCase().includes(q) ||
      evt.sourceName.toLowerCase().includes(q) ||
      (evt.humanId && evt.humanId.toLowerCase().includes(q)) ||
      (evt.actor && evt.actor.toLowerCase().includes(q));

    const matchesType = selectedType === 'ALL' || evt.type === selectedType;

    return matchesSearch && matchesType;
  });

  const getTypeIcon = (type: TimelineEventType) => {
    switch (type) {
      case 'DETECTION':
        return <Radio className="w-4 h-4 text-amber-400" />;
      case 'CORRELATION':
        return <Network className="w-4 h-4 text-purple-400" />;
      case 'CASE_ACTION':
        return <Shield className="w-4 h-4 text-cyan-400" />;
      case 'ANALYST_NOTE':
        return <MessageSquare className="w-4 h-4 text-emerald-400" />;
      case 'EVENT':
      default:
        return <Activity className="w-4 h-4 text-slate-400" />;
    }
  };

  const getTypeBadge = (type: TimelineEventType) => {
    switch (type) {
      case 'DETECTION':
        return 'bg-amber-950/60 border-amber-800 text-amber-300';
      case 'CORRELATION':
        return 'bg-purple-950/60 border-purple-800 text-purple-300';
      case 'CASE_ACTION':
        return 'bg-cyan-950/60 border-cyan-800 text-cyan-300';
      case 'ANALYST_NOTE':
        return 'bg-emerald-950/60 border-emerald-800 text-emerald-300';
      case 'EVENT':
      default:
        return 'bg-slate-800 border-slate-700 text-slate-300';
    }
  };

  return (
    <div className="space-y-4 pb-12 animate-in fade-in duration-200">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-2 border-b border-slate-800">
        <div>
          <div className="flex flex-wrap items-center gap-2">
            <h1 className="text-lg font-semibold tracking-tight text-slate-100">
              Timeline
            </h1>
            <span className="text-xs font-mono px-2 py-0.5 rounded-full bg-cyan-950 text-cyan-300 border border-cyan-800">
              {filteredEvents.length} Events
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-0.5">
            Progressive chronological reconstruction across telemetry events, rule triggers, correlations, and analyst actions.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <select
            value={selectedCaseId}
            onChange={e => setSelectedCaseId(e.target.value)}
            className="px-2.5 py-1.5 rounded-lg bg-slate-900 border border-slate-700 text-slate-200 text-xs font-mono focus:outline-none focus:border-cyan-500"
            aria-label="Timeline case"
          >
            {cases.length === 0 && <option value="">No cases on backend</option>}
            {cases.map(c => (
              <option key={c.humanId} value={c.humanId}>
                {c.humanId} — {c.title.slice(0, 40)}
              </option>
            ))}
          </select>
          <button
            onClick={() => { refreshAll(); loadCaseTimeline(selectedCaseId || ''); }}
            title="Rebuild timeline from backend"
            className="p-2 rounded-lg bg-slate-900 border border-slate-700 text-cyan-300 hover:bg-slate-800 transition-colors"
          >
            <RefreshCw className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {loading && (
        <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800 text-xs font-mono text-cyan-300">
          Building timeline on the backend (timeline.build_for_incident)…
        </div>
      )}

      {!loading && filteredEvents.length === 0 && (
        <div className="p-6 rounded-xl bg-[#0F1420] border border-slate-800 text-center text-xs font-mono text-slate-400">
          No timeline items were returned by the backend for this case. Timelines are built from
          each case's persisted evidence — cases without evidence produce empty timelines.
        </div>
      )}

      {/* Filter and Search Bar */}
      <div className="p-3.5 rounded-xl bg-[#0F1420] border border-slate-800 flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3">
        <div className="relative flex-1">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={searchQuery}
            onChange={e => setSearchQuery(e.target.value)}
            placeholder="Search timeline by keyword, IP, rule, actor, or case ID..."
            className="w-full pl-9 pr-8 py-2 rounded-lg bg-slate-900 border border-slate-700 text-xs text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
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

        {/* Type Filter Pills */}
        <div className="flex items-center rounded-lg bg-slate-900 border border-slate-700 p-0.5 text-xs font-mono">
          {(['ALL', 'EVENT', 'DETECTION', 'CORRELATION', 'CASE_ACTION', 'ANALYST_NOTE'] as const).map(t => (
            <button
              key={t}
              onClick={() => setSelectedType(t)}
              className={`px-2 py-1 rounded transition-colors ${
                selectedType === t
                  ? 'bg-slate-800 text-cyan-300 font-bold'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              {t === 'ALL' ? 'All' : t.replace('_', ' ')}
            </button>
          ))}
        </div>
      </div>

      {/* Timeline Stream */}
      <div className="relative pl-6 space-y-4 before:absolute before:left-2.5 before:top-3 before:bottom-3 before:w-0.5 before:bg-slate-800">
        {filteredEvents.map(evt => (
          <div
            key={evt.id}
            className="relative p-4 rounded-xl bg-[#0F1420] border border-slate-800 hover:border-cyan-500/40 transition-all shadow-md group"
          >
            {/* Dot Node on Line */}
            <div className="absolute -left-[27px] top-4 w-3.5 h-3.5 rounded-full bg-[#0C1019] border-2 border-cyan-400 shadow-[0_0_8px_rgba(6,182,212,0.6)]" />

            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-2">
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-mono text-cyan-300 text-xs font-bold">
                  {formatIstTimestamp(evt.timestamp)}
                </span>
                <span className={`text-[10px] font-mono px-2 py-0.5 rounded border ${getTypeBadge(evt.type)} flex items-center gap-1`}>
                  {getTypeIcon(evt.type)}
                  <span>{evt.type.replace('_', ' ')}</span>
                </span>
                <SeverityBadge severity={evt.severity} size="sm" />
                {evt.humanId && (
                  <HumanIdTag humanId={evt.humanId} size="sm" />
                )}
              </div>

              <div className="flex items-center gap-2 text-xs font-mono text-slate-400">
                <span>Source:</span>
                <span className="text-slate-200 font-semibold">{evt.sourceName}</span>
              </div>
            </div>

            {/* Title & Explanation */}
            <div className="space-y-1">
              <h3 className="text-xs font-bold text-slate-100 font-mono">
                {evt.title}
              </h3>
              <p className="text-xs text-slate-300 leading-relaxed font-sans">
                {evt.shortExplanation}
              </p>
            </div>

            {/* Secondary Metadata & Inspect Drawer Trigger */}
            <div className="mt-3 pt-2 border-t border-slate-800/80 flex flex-wrap items-center justify-between gap-2 text-[11px] font-mono text-slate-400">
              <div className="flex items-center gap-3">
                {evt.actor && (
                  <span>Actor: <strong className="text-slate-200">{evt.actor}</strong></span>
                )}
                {evt.mitreTechnique && (
                  <span className="text-cyan-400">MITRE: {evt.mitreTechnique}</span>
                )}
              </div>

              <button
                onClick={() =>
                  openPayloadDrawer({
                    title: evt.title,
                    subtitle: `${evt.sourceName} • ${formatIstTimestamp(evt.timestamp)}`,
                    humanId: evt.humanId,
                    payload: evt.rawPayload || {
                      event_id: evt.id,
                      source: evt.sourceName,
                      actor: evt.actor,
                      type: evt.type,
                      severity: evt.severity,
                      explanation: evt.shortExplanation
                    }
                  })
                }
                className="flex items-center gap-1 text-cyan-400 hover:text-cyan-300 transition-colors"
              >
                <Terminal className="w-3.5 h-3.5" />
                <span>Inspect Technical Payload</span>
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
