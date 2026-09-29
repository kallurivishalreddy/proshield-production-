import React, { useState } from 'react';
import {
  Search,
  ArrowUpDown,
  ArrowRight,
  X
} from 'lucide-react';
import { useSoc } from '../../context/SocContext';
import { Severity, CaseStatus } from '../../types/soc';
import { SeverityBadge } from '../common/SeverityBadge';
import { StatusBadge } from '../common/StatusBadge';
import { HumanIdTag } from '../common/HumanIdTag';
import { DensityToggle } from '../common/DensityToggle';
import { formatIstTime, formatIstDate } from '../../utils/format';

export const IncidentsPage: React.FC = () => {
  const {
    cases,
    navigate,
    tableDensity,
    updateCaseStatus,
    setCloseCaseModalOpen,
    setSelectedCaseId
  } = useSoc();

  const [searchQuery, setSearchQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState<Severity | 'ALL'>('ALL');
  const [statusFilter, setStatusFilter] = useState<CaseStatus | 'ALL' | 'ACTIVE'>('ACTIVE');
  const [sourceFilter, setSourceFilter] = useState<string>('ALL');
  const [sortBy, setSortBy] = useState<'severity' | 'lastActivity' | 'events'>('severity');

  // Filter logic
  const filteredCases = cases.filter(c => {
    const q = searchQuery.toLowerCase().trim();
    const matchesSearch =
      !q ||
      c.humanId.toLowerCase().includes(q) ||
      c.title.toLowerCase().includes(q) ||
      c.attackerIp.toLowerCase().includes(q) ||
      c.targetAsset.toLowerCase().includes(q) ||
      c.description.toLowerCase().includes(q);

    const matchesSeverity = severityFilter === 'ALL' || c.severity === severityFilter;
    const matchesStatus =
      statusFilter === 'ALL'
        ? true
        : statusFilter === 'ACTIVE'
        ? c.status !== 'CLOSED'
        : c.status === statusFilter;

    const matchesSource = sourceFilter === 'ALL' || c.sourceId === sourceFilter;

    return matchesSearch && matchesSeverity && matchesStatus && matchesSource;
  });

  // Sorting
  const severityRank: Record<Severity, number> = {
    CRITICAL: 4,
    HIGH: 3,
    MEDIUM: 2,
    LOW: 1,
    INFORMATIONAL: 0
  };

  const sortedCases = [...filteredCases].sort((a, b) => {
    if (sortBy === 'severity') {
      // unrated cases (severity === null) sort lowest
      const diff = (severityRank[b.severity as Severity] ?? -1) - (severityRank[a.severity as Severity] ?? -1);
      if (diff !== 0) return diff;
      return b.lastSeen.localeCompare(a.lastSeen);
    }
    if (sortBy === 'events') {
      return b.eventCount - a.eventCount;
    }
    return b.lastSeen.localeCompare(a.lastSeen);
  });

  const allSources = Array.from(new Set(cases.map(c => c.sourceId)));

  const handleQuickAcknowledge = (e: React.MouseEvent, caseId: string) => {
    e.stopPropagation();
    updateCaseStatus(caseId, 'ACKNOWLEDGED');
  };

  const handleQuickClose = (e: React.MouseEvent, caseId: string) => {
    e.stopPropagation();
    setSelectedCaseId(caseId);
    setCloseCaseModalOpen(true);
  };

  return (
    <div className="space-y-4 pb-12 animate-in fade-in duration-200">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-2 border-b border-slate-800">
        <div>
          <div className="flex flex-wrap items-center gap-2">
            <h1 className="text-lg font-semibold tracking-tight text-slate-100">
              Cases
            </h1>
            <span className="text-[11px] font-mono px-2 py-0.5 rounded-full bg-slate-800 text-slate-200 border border-slate-700">
              {sortedCases.length} shown
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Open a case to review evidence, timeline, notes, and resolution.
          </p>
        </div>

        {/* Right: Density & Fast Refresh */}
        <div className="flex items-center gap-3">
          <DensityToggle />
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="p-3.5 rounded-xl bg-[#0F1420] border border-slate-800 space-y-3">
        <div className="flex flex-col lg:flex-row items-stretch lg:items-center justify-between gap-3">
          {/* Search Input */}
          <div className="relative flex-1 min-w-[240px]">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
              placeholder="Filter by Case ID, IP (e.g. 203.0.113.42), title, asset..."
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

          {/* Quick Filters */}
          <div className="flex flex-wrap items-center gap-2 text-xs font-mono">
            {/* Status Filter */}
            <div className="flex items-center rounded-lg bg-slate-900 border border-slate-700 p-0.5">
              {(['ACTIVE', 'ALL', 'OPEN', 'INVESTIGATING', 'CLOSED'] as const).map(st => (
                <button
                  key={st}
                  onClick={() => setStatusFilter(st)}
                  className={`px-2 py-1 rounded transition-colors ${
                    statusFilter === st
                      ? 'bg-slate-800 text-cyan-300 font-bold'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {st === 'ACTIVE' ? 'Active' : st}
                </button>
              ))}
            </div>

            {/* Severity Filter */}
            <select
              value={severityFilter}
              onChange={e => setSeverityFilter(e.target.value as any)}
              aria-label="Filter by Severity"
              className="px-2.5 py-1.5 rounded-lg bg-slate-900 border border-slate-700 text-xs text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
            >
              <option value="ALL">All Severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
              <option value="INFORMATIONAL">Informational</option>
            </select>

            {/* Source Filter */}
            <select
              value={sourceFilter}
              onChange={e => setSourceFilter(e.target.value)}
              aria-label="Filter by Source"
              className="px-2.5 py-1.5 rounded-lg bg-slate-900 border border-slate-700 text-xs text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
            >
              <option value="ALL">All Sources</option>
              {allSources.map(srcId => (
                <option key={srcId} value={srcId}>
                  {srcId}
                </option>
              ))}
            </select>

            {/* Sort Filter */}
            <div className="flex items-center gap-1 pl-1">
              <ArrowUpDown className="w-3.5 h-3.5 text-slate-400" />
              <select
                value={sortBy}
                onChange={e => setSortBy(e.target.value as any)}
                aria-label="Sort by attribute"
                className="px-2 py-1.5 rounded-lg bg-slate-900 border border-slate-700 text-xs text-slate-200 focus:outline-none font-mono"
              >
                <option value="severity">Severity Rank</option>
                <option value="lastActivity">Last Activity</option>
                <option value="events">Event Volume</option>
              </select>
            </div>
          </div>
        </div>
      </div>

      {/* Incidents Table / List */}
      <div className="rounded-xl bg-[#0F1420] border border-slate-800 overflow-hidden shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse font-sans text-xs">
            <thead>
              <tr className="border-b border-slate-800 bg-[#0A0D15] text-[11px] font-mono uppercase tracking-wider text-slate-400">
                <th className="py-3 px-3.5 font-bold">Case Identity</th>
                <th className="py-3 px-3 font-bold">Severity</th>
                <th className="py-3 px-3 font-bold">Lifecycle State</th>
                <th className="py-3 px-3 font-bold">Origin / Source</th>
                <th className="py-3 px-3 font-bold">Attacker IP</th>
                <th className="py-3 px-3 font-bold">Target Asset</th>
                <th className="py-3 px-3 font-bold text-center">Telemetry Evidence</th>
                <th className="py-3 px-3 font-bold">Last Activity</th>
                <th className="py-3 px-3.5 font-bold text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {sortedCases.length === 0 ? (
                <tr>
                  <td colSpan={9} className="py-12 text-center text-slate-500 font-sans">
                    <p className="text-sm">No security incidents match the selected filters.</p>
                    <button
                      onClick={() => {
                        setSearchQuery('');
                        setSeverityFilter('ALL');
                        setStatusFilter('ALL');
                        setSourceFilter('ALL');
                      }}
                      className="mt-2 text-xs text-cyan-400 hover:underline"
                    >
                      Clear all filters
                    </button>
                  </td>
                </tr>
              ) : (
                sortedCases.map(c => {
                  const isCompact = tableDensity === 'compact';
                  return (
                    <tr
                      key={c.humanId}
                      onClick={() => navigate('case-detail', c.humanId)}
                      className="hover:bg-slate-800/50 cursor-pointer transition-colors group"
                    >
                      {/* Identity & Title */}
                      <td className={`px-3.5 ${isCompact ? 'py-2' : 'py-3.5'} font-sans`}>
                        <div className="flex items-center gap-2">
                          <HumanIdTag humanId={c.humanId} internalUuid={c.internalUuid} />
                          {c.isCorrelated && (
                            <span
                              className="text-[10px] font-mono px-1 py-0.2 rounded bg-purple-950 text-purple-300 border border-purple-800"
                              title="Correlated Attack Cluster"
                            >
                              CORRELATED
                            </span>
                          )}
                        </div>
                        <div className={`font-semibold text-slate-200 group-hover:text-cyan-300 mt-1 line-clamp-1 ${isCompact ? 'text-xs' : 'text-xs'}`}>
                          {c.title}
                        </div>
                      </td>

                      {/* Severity */}
                      <td className="py-3 px-3 whitespace-nowrap">
                        <SeverityBadge severity={c.severity} size="sm" />
                      </td>

                      {/* State */}
                      <td className="py-3 px-3 whitespace-nowrap">
                        <StatusBadge
                          status={c.status}
                          resolutionReason={c.closureReason}
                          size="sm"
                        />
                      </td>

                      {/* Source (backend does not attribute cases to sources) */}
                      <td className="py-3 px-3 whitespace-nowrap">
                        {c.sourceName ? (
                          <>
                            <div className="font-semibold text-slate-300 text-xs font-sans">{c.sourceName}</div>
                            <span className="text-[10px] text-slate-500 font-mono">{c.sourceId}</span>
                          </>
                        ) : (
                          <span className="text-slate-500 text-xs" title="The backend does not attribute cases to source instances (documented gap)">—</span>
                        )}
                      </td>

                      {/* Attacker IP (derived from real correlation key parts) */}
                      <td className="py-3 px-3 whitespace-nowrap">
                        {c.attackerIp ? (
                          <>
                            <span className="text-rose-300 font-bold text-xs">{c.attackerIp}</span>
                            <div className="text-[10px] text-slate-400 truncate max-w-[120px]">
                              {c.attackerCountry}
                            </div>
                          </>
                        ) : (
                          <span className="text-slate-500 text-xs" title="No correlation key evidence available for this case">not attributed</span>
                        )}
                      </td>

                      {/* Target */}
                      <td className="py-3 px-3 whitespace-nowrap">
                        <div className="text-cyan-300 text-xs truncate max-w-[140px]" title={c.targetAsset}>
                          {c.targetAsset}
                        </div>
                        {c.targetUser && (
                          <div className="text-[10px] text-slate-400 font-mono truncate max-w-[140px]">
                            {c.targetUser}
                          </div>
                        )}
                      </td>

                      {/* Evidence Summary Badges */}
                      <td className="py-3 px-3 text-center whitespace-nowrap">
                        <div className="inline-flex items-center gap-1.5 text-[11px] font-mono">
                          <span className="px-1.5 py-0.5 rounded bg-slate-900 border border-slate-800 text-slate-300" title="Security Events">
                            {c.eventCount}e
                          </span>
                          <span className="px-1.5 py-0.5 rounded bg-amber-950/60 border border-amber-800/60 text-amber-300" title="Detection Rules">
                            {c.detectionCount}d
                          </span>
                          {c.correlationCount > 0 && (
                            <span className="px-1.5 py-0.5 rounded bg-purple-950/60 border border-purple-800/60 text-purple-300" title="Correlations">
                              {c.correlationCount}c
                            </span>
                          )}
                        </div>
                      </td>

                      {/* Last Activity */}
                      <td className="py-3 px-3 whitespace-nowrap text-slate-400 text-[11px]">
                        {formatIstTime(c.lastSeen)} IST
                        <div className="text-[10px] text-slate-500">
                          {formatIstDate(c.lastSeen)}
                        </div>
                      </td>

                      {/* Actions */}
                      <td className="py-3 px-3.5 text-right whitespace-nowrap font-sans">
                        <div className="flex items-center justify-end gap-1.5">
                          {c.status === 'OPEN' && (
                            <button
                              onClick={(e) => handleQuickAcknowledge(e, c.humanId)}
                              className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-cyan-300 text-[11px] font-mono border border-slate-700 transition-colors"
                              title="Acknowledge Case"
                            >
                              Ack
                            </button>
                          )}
                          {c.status !== 'CLOSED' && (
                            <button
                              onClick={(e) => handleQuickClose(e, c.humanId)}
                              className="px-2 py-1 rounded bg-slate-800 hover:bg-emerald-950/80 text-emerald-400 text-[11px] font-mono border border-slate-700 hover:border-emerald-500 transition-colors"
                              title="Close Case"
                            >
                              Close
                            </button>
                          )}
                          <button
                            onClick={() => navigate('case-detail', c.humanId)}
                            className="p-1 rounded text-slate-400 group-hover:text-cyan-400 transition-colors"
                            title="Open Investigation Workspace"
                          >
                            <ArrowRight className="w-4 h-4" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
