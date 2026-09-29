import React, { useState } from 'react';
import {
  Sparkles,
  ArrowRight,
  Clock,
  Layers,
  FileText,
  Search,
  X
} from 'lucide-react';
import { useSoc } from '../../context/SocContext';
import { SeverityBadge } from '../common/SeverityBadge';
import { HumanIdTag } from '../common/HumanIdTag';

export const CorrelationsPage: React.FC = () => {
  const {
    correlations,
    navigate,
    setCentralizedAnalysisModalOpen,
    setSelectedCaseId,
    setReportModalOpen
  } = useSoc();

  const [searchQuery, setSearchQuery] = useState('');

  const filteredCorrelations = correlations.filter(c => {
    const q = searchQuery.toLowerCase().trim();
    return (
      !q ||
      c.humanId.toLowerCase().includes(q) ||
      c.title.toLowerCase().includes(q) ||
      c.pattern.toLowerCase().includes(q) ||
      c.attacker.toLowerCase().includes(q) ||
      c.target.toLowerCase().includes(q)
    );
  });

  return (
    <div className="space-y-4 pb-12 animate-in fade-in duration-200">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-2 border-b border-slate-800">
        <div>
          <div className="flex flex-wrap items-center gap-2">
            <h1 className="text-lg font-semibold tracking-tight text-slate-100">
              Correlations
            </h1>
            <span className="text-[11px] font-mono px-2 py-0.5 rounded-full bg-slate-800 text-slate-200 border border-slate-700">
              {filteredCorrelations.length} shown
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Related detections grouped together. Open the parent case to investigate or resolve.
          </p>
        </div>
      </div>

      {/* Search Bar */}
      <div className="p-3.5 rounded-xl bg-[#0F1420] border border-slate-800">
        <div className="relative">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={searchQuery}
            onChange={e => setSearchQuery(e.target.value)}
            placeholder="Search correlations by ID, attack pattern, attacker host, or target asset..."
            className="w-full pl-9 pr-8 py-2 rounded-lg bg-slate-900 border border-slate-700 text-xs text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-purple-500 font-mono"
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
      </div>

      {/* Correlation Clusters List */}
      <div className="space-y-4">
        {filteredCorrelations.map(corr => (
          <div
            key={corr.humanId}
            className="p-5 rounded-xl bg-[#0F1420] border border-slate-800 hover:border-purple-500/50 transition-all shadow-xl space-y-4"
          >
            {/* Top Bar */}
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-800">
              <div className="flex items-center gap-2.5">
                <HumanIdTag humanId={corr.humanId} internalUuid={corr.internalUuid} size="lg" />
                <SeverityBadge severity={corr.severity} size="md" />
                <h3 className="text-base font-bold text-slate-100 font-mono">
                  {corr.title}
                </h3>
              </div>

              <div className="flex items-center gap-2">
                {corr.confidenceScore != null ? (
                  <span className="text-xs font-mono font-bold px-2.5 py-1 rounded bg-purple-950 text-purple-300 border border-purple-800 shadow-[0_0_10px_rgba(168,85,247,0.2)]">
                    {corr.confidenceScore}% Confidence Score
                  </span>
                ) : corr.confidenceBand ? (
                  <span
                    className="text-xs font-mono font-bold px-2.5 py-1 rounded bg-purple-950 text-purple-300 border border-purple-800 uppercase"
                    title="Confidence band composed by the backend severity engine and persisted with this correlation"
                  >
                    Confidence: {corr.confidenceBand}
                  </span>
                ) : (
                  <span
                    className="text-xs font-mono px-2.5 py-1 rounded bg-slate-900 text-slate-500 border border-slate-800"
                    title="No confidence band was composed for this correlation (legacy record created before the capability patch)"
                  >
                    Confidence: —
                  </span>
                )}
                {corr.centralizedAnalysisRan && (
                  <span className="text-[11px] font-mono px-2 py-1 rounded bg-cyan-950 text-cyan-300 border border-cyan-800 flex items-center gap-1">
                    <Sparkles className="w-3 h-3 text-cyan-400" />
                    Centralized Verified
                  </span>
                )}
              </div>
            </div>

            {/* Pattern Description */}
            <div className="p-3 rounded-lg bg-[#0A0D15] border border-slate-800/80 space-y-1.5">
              <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-purple-400">
                Correlated Behavioral Pattern:
              </span>
              <p className="text-xs text-slate-200 font-semibold font-mono">
                {corr.pattern}
              </p>
              <p className="text-xs text-slate-400 leading-relaxed font-sans">
                {corr.description}
              </p>
            </div>

            {/* Context Grid */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono">
              <div className="p-2.5 rounded bg-slate-900 border border-slate-800">
                <span className="text-[10px] text-slate-500 uppercase block">Attacker Origin</span>
                <span className="text-rose-300 font-bold truncate block">{corr.attacker}</span>
              </div>
              <div className="p-2.5 rounded bg-slate-900 border border-slate-800">
                <span className="text-[10px] text-slate-500 uppercase block">Target Objective</span>
                <span className="text-cyan-300 font-bold truncate block">{corr.target}</span>
              </div>
              <div className="p-2.5 rounded bg-slate-900 border border-slate-800">
                <span className="text-[10px] text-slate-500 uppercase block">Sliding Window</span>
                <span className="text-slate-200 font-bold flex items-center gap-1">
                  <Clock className="w-3 h-3 text-slate-400" /> {corr.timeWindow}
                </span>
              </div>
              <div className="p-2.5 rounded bg-slate-900 border border-slate-800">
                <span className="text-[10px] text-slate-500 uppercase block">Evidence Volume</span>
                <span className="text-amber-300 font-bold">
                  {corr.eventCount} Events • {corr.detectionCount} Detections
                </span>
              </div>
            </div>

            {/* Tree Relationship Visualizer */}
            <div className="p-3.5 rounded-lg bg-[#070A10] border border-slate-800 space-y-2 font-mono text-xs">
              <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
                <Layers className="w-3.5 h-3.5 text-cyan-400" />
                <span>Correlation Cluster Topology & Hierarchy</span>
              </span>

              <div className="pl-2 space-y-1 text-slate-300">
                <div className="flex items-center gap-2">
                  <span className="text-purple-400 font-bold">{corr.humanId}</span>
                  <span className="text-slate-500">── ({corr.title})</span>
                </div>
                {corr.detectionIds.map(detId => (
                  <div key={detId} className="pl-4 flex items-center gap-2 text-slate-400">
                    <span className="text-slate-600">├──</span>
                    <HumanIdTag humanId={detId} size="sm" />
                    <span className="text-[11px] text-slate-300">Detection Match Trigger</span>
                  </div>
                ))}
                <div className="pl-4 flex items-center gap-2 text-slate-400">
                  <span className="text-slate-600">└──</span>
                  <span className="text-slate-400 text-[11px]">Parent Investigation:</span>
                  <HumanIdTag humanId={corr.caseId} size="sm" />
                </div>
              </div>
            </div>

            {/* Action Bar */}
            <div className="flex flex-wrap items-center justify-between gap-3 pt-2">
              <div className="flex items-center gap-2">
                <button
                  onClick={() => {
                    setSelectedCaseId(corr.caseId);
                    setCentralizedAnalysisModalOpen(true);
                  }}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyan-950 hover:bg-cyan-900 border border-cyan-500/40 text-cyan-300 font-mono text-xs font-bold transition-colors shadow-[0_0_10px_rgba(6,182,212,0.15)]"
                >
                  <Sparkles className="w-3.5 h-3.5" />
                  <span>Execute Centralized Analysis</span>
                </button>

                <button
                  onClick={() => {
                    setSelectedCaseId(corr.caseId);
                    setReportModalOpen(true);
                  }}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-300 font-mono text-xs transition-colors"
                >
                  <FileText className="w-3.5 h-3.5 text-indigo-400" />
                  <span>Generate Report</span>
                </button>
              </div>

              <button
                onClick={() => navigate('case-detail', corr.caseId)}
                className="flex items-center gap-1.5 px-4 py-2 rounded-lg bg-purple-600 hover:bg-purple-500 text-white font-mono text-xs font-bold transition-colors shadow-[0_0_12px_rgba(168,85,247,0.3)]"
              >
                <span>Investigate Case {corr.caseId}</span>
                <ArrowRight className="w-4 h-4" />
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
