import React, { useState } from 'react';
import {
  X,
  Network,
  Sparkles,
  ArrowRight,
  CheckCircle,
  AlertTriangle,
  FileText
} from 'lucide-react';
import { useSoc } from '../../context/SocContext';

/**
 * Centralized analysis — REAL backend operation (`case.centralized`).
 * The backend resolves the case's persisted evidence itself; this modal
 * reports only what the backend actually returned (new correlation ids
 * or the documented failure reason). No simulated completion.
 */
export const CentralizedAnalysisModal: React.FC = () => {
  const {
    isCentralizedAnalysisModalOpen,
    setCentralizedAnalysisModalOpen,
    selectedCaseId,
    cases,
    runCentralizedAnalysis,
    setReportModalOpen,
    refreshAll
  } = useSoc();

  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<{
    ok: boolean;
    failed: boolean;
    failureReason: string | null;
    newCorrelationCount: number;
    error?: string;
  } | null>(null);

  if (!isCentralizedAnalysisModalOpen) return null;

  const currentCase = cases.find(c => c.humanId === selectedCaseId);

  const handleStartAnalysis = async () => {
    setRunning(true);
    setResult(null);
    const r = await runCentralizedAnalysis(selectedCaseId || '');
    setResult(r);
    setRunning(false);
  };

  const handleOpenCentralizedReport = () => {
    setCentralizedAnalysisModalOpen(false);
    setReportModalOpen(true);
  };

  const handleClose = () => {
    setCentralizedAnalysisModalOpen(false);
    setResult(null);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-in fade-in duration-200">
      <div className="relative w-full max-w-2xl rounded-xl bg-[#0F1420] border border-cyan-500/40 shadow-2xl overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between p-4 border-b border-slate-800 bg-[#0A0D15]">
          <div className="flex items-center gap-2.5">
            <div className="p-1.5 rounded bg-cyan-950 text-cyan-400 border border-cyan-500/40">
              <Sparkles className="w-4 h-4" />
            </div>
            <div>
              <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-cyan-400">
                MULTI-SOURCE CORRELATION ENGINE
              </span>
              <h3 className="text-sm font-bold text-slate-100 font-mono">
                CENTRALIZED GRAPH ANALYSIS: {selectedCaseId || '—'}
              </h3>
            </div>
          </div>
          <button
            onClick={handleClose}
            className="p-1 rounded text-slate-400 hover:text-white transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6 text-xs space-y-4">
          {!result && !running && (
            <div className="space-y-4">
              <div className="p-3.5 rounded-lg bg-cyan-950/20 border border-cyan-500/30 space-y-2">
                <h4 className="text-xs font-bold text-cyan-300 font-mono">
                  Real Backend Analysis
                </h4>
                <p className="text-slate-300 text-xs leading-relaxed">
                  The backend will run the centralized correlation engine over this case's
                  PERSISTED evidence (events + detections). The UI sends only the request;
                  it never fabricates evidence or results.
                </p>
              </div>

              <div className="grid grid-cols-3 gap-2.5 font-mono text-center">
                <div className="p-2.5 rounded bg-slate-900 border border-slate-800">
                  <span className="text-slate-500 block text-[10px]">EVIDENCE ITEMS</span>
                  <span className="text-sm font-bold text-cyan-300">{currentCase?.eventCount ?? 0} Events</span>
                </div>
                <div className="p-2.5 rounded bg-slate-900 border border-slate-800">
                  <span className="text-slate-500 block text-[10px]">DETECTIONS</span>
                  <span className="text-sm font-bold text-cyan-300">{currentCase?.detectionCount ?? 0}</span>
                </div>
                <div className="p-2.5 rounded bg-slate-900 border border-slate-800">
                  <span className="text-slate-500 block text-[10px]">PRIOR CORRELATIONS</span>
                  <span className="text-sm font-bold text-cyan-300">{currentCase?.correlationCount ?? 0}</span>
                </div>
              </div>

              {currentCase && currentCase.eventCount === 0 && currentCase.detectionCount === 0 && (
                <div className="p-3 rounded-lg bg-amber-950/30 border border-amber-500/40 text-amber-300 flex items-start gap-2">
                  <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
                  <span>
                    This case has no persisted evidence. The backend truthfully refuses to
                    analyse zero evidence — the request will be rejected.
                  </span>
                </div>
              )}

              <div className="flex justify-end pt-2 border-t border-slate-800">
                <button
                  type="button"
                  onClick={handleStartAnalysis}
                  className="flex items-center gap-2 px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-mono font-bold text-xs transition-colors shadow-[0_0_12px_rgba(6,182,212,0.3)]"
                >
                  <Sparkles className="w-3.5 h-3.5" />
                  <span>RUN CENTRALIZED ANALYSIS</span>
                </button>
              </div>
            </div>
          )}

          {running && (
            <div className="flex items-center gap-4 p-4">
              <div className="relative w-10 h-10">
                <div className="w-10 h-10 rounded-full border-2 border-cyan-500/30 border-t-cyan-400 animate-spin" />
                <Network className="w-5 h-5 text-cyan-400 absolute inset-0 m-auto" />
              </div>
              <div className="space-y-1">
                <h4 className="text-sm font-bold text-slate-100 font-mono">
                  Running backend centralized correlation…
                </h4>
                <p className="text-xs text-cyan-300 font-mono animate-pulse">
                  POST /api/proxy → case.centralized (rate-limited to 5/min per subject)
                </p>
              </div>
            </div>
          )}

          {result && (
            <div className="space-y-4 animate-in fade-in duration-300">
              {result.ok && !result.failed && (
                <div className="flex items-center gap-3 p-3 rounded-lg bg-emerald-950/30 border border-emerald-500/40 text-emerald-300">
                  <CheckCircle className="w-5 h-5 text-emerald-400 shrink-0" />
                  <div>
                    <span className="font-mono font-bold text-xs">
                      CENTRALIZED ANALYSIS COMPLETE (backend-verified)
                    </span>
                    <p className="text-[11px] text-emerald-400/90 mt-0.5">
                      {result.newCorrelationCount} new correlation(s) were persisted by the
                      backend and bound to {selectedCaseId}.
                    </p>
                  </div>
                </div>
              )}

              {result.ok && result.failed && (
                <div className="flex items-center gap-3 p-3 rounded-lg bg-amber-950/30 border border-amber-500/40 text-amber-300">
                  <AlertTriangle className="w-5 h-5 text-amber-400 shrink-0" />
                  <div>
                    <span className="font-mono font-bold text-xs">
                      ANALYSIS RETURNED FAILED (backend truth state)
                    </span>
                    <p className="text-[11px] text-amber-400/90 mt-0.5">
                      Reason: {result.failureReason || 'unspecified by backend'}
                    </p>
                  </div>
                </div>
              )}

              {!result.ok && (
                <div className="flex items-center gap-3 p-3 rounded-lg bg-rose-950/30 border border-rose-500/40 text-rose-300">
                  <AlertTriangle className="w-5 h-5 text-rose-400 shrink-0" />
                  <div>
                    <span className="font-mono font-bold text-xs">
                      ANALYSIS REQUEST FAILED
                    </span>
                    <p className="text-[11px] text-rose-400/90 mt-0.5">
                      {result.error || 'Unknown error'}
                    </p>
                  </div>
                </div>
              )}

              {/* Action Buttons */}
              <div className="flex items-center justify-between pt-3 border-t border-slate-800">
                <div className="flex gap-2">
                  <button
                    onClick={() => { refreshAll(); handleClose(); }}
                    className="px-3.5 py-1.5 rounded-lg text-slate-400 hover:text-white font-mono transition-colors text-xs"
                  >
                    Close Window
                  </button>
                  {!result.ok && (
                    <button
                      onClick={handleStartAnalysis}
                      className="px-3.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-cyan-300 font-mono transition-colors text-xs border border-slate-700"
                    >
                      Retry
                    </button>
                  )}
                </div>
                {result.ok && !result.failed && (result.newCorrelationCount ?? 0) > 0 && (
                  <button
                    onClick={handleOpenCentralizedReport}
                    className="flex items-center gap-2 px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-mono font-bold text-xs transition-colors shadow-[0_0_15px_rgba(16,185,129,0.4)]"
                  >
                    <FileText className="w-3.5 h-3.5" />
                    <span>GENERATE CENTRALIZED REPORT</span>
                    <ArrowRight className="w-3.5 h-3.5" />
                  </button>
                )}
                {result.ok && !result.failed && (result.newCorrelationCount ?? 0) === 0 && (
                  /* AUD-03 fix: when the centralized run produced no new
                     cross-capability correlations (the truthful outcome for
                     a single-capability case), offering a "centralized
                     report" button would silently open the NORMAL report
                     flow. State the truth instead of a mislabeled action. */
                  <span className="text-[10px] font-mono text-slate-500 max-w-[16rem] text-right leading-relaxed">
                    No new centralized correlations were bound to this case, so
                    there is no centralized report to generate. The normal case
                    report remains available.
                  </span>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
