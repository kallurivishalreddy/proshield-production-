import React, { useState } from 'react';
import {
  X,
  FileText,
  Download,
  Check,
  Sparkles
} from 'lucide-react';
import { useSoc } from '../../context/SocContext';
import { formatIstTimestamp } from '../../utils/format';

/**
 * Report generation — REAL backend operations
 * (`report.generate_normal` / `report.generate_centralized` / `report.export`).
 * The preview renders ONLY the sections the backend actually built from the
 * case's persisted evidence. Export downloads the backend-generated JSON
 * artifact — never a client-fabricated document.
 */
export const ReportGeneratorModal: React.FC = () => {
  const {
    isReportModalOpen,
    setReportModalOpen,
    selectedCaseId,
    cases,
    reports,
    generateReport,
    exportReportJson
  } = useSoc();

  const currentCase = cases.find(c => c.humanId === selectedCaseId);
  const isCentralized = !!currentCase?.centralizedAnalysisDone;

  const [reportTitle, setReportTitle] = useState(
    isCentralized
      ? `Centralized Multi-Source Intelligence Report: ${selectedCaseId}`
      : `SOC Incident Evidence Report: ${selectedCaseId}`
  );
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (!isReportModalOpen) return null;

  const handleGenerate = async () => {
    setBusy(true);
    setError(null);
    const r = await generateReport({
      title: reportTitle,
      caseId: selectedCaseId || '',
      isCentralized,
      type: isCentralized ? 'CENTRALIZED_ANALYSIS' : 'CASE_SUMMARY'
    });
    if (!r.ok) setError(r.error || 'Report generation failed.');
    setBusy(false);
  };

  const handleDownload = () => {
    // exportReportJson looks up the latest report for this case in context
    const latest = reportsForCase();
    if (latest) exportReportJson(latest.id);
  };

  // the latest backend report for the selected case (from context state)
  const reportsForCase = () => {
    const technicalId = currentCase?.internalUuid;
    return reports
      .filter(r => r.caseId === technicalId)
      .sort((a, b) => b.generatedAt.localeCompare(a.generatedAt))[0];
  };
  const latest = reportsForCase();

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-in fade-in duration-200">
      <div className="relative w-full max-w-2xl rounded-xl bg-[#0F1420] border border-indigo-500/40 shadow-2xl overflow-hidden max-h-[90vh] flex flex-col">
        {/* Header */}
        <div className="flex items-center justify-between p-4 border-b border-slate-800 bg-[#0A0D15] shrink-0">
          <div className="flex items-center gap-2.5">
            <div className="p-1.5 rounded bg-indigo-950 text-indigo-400 border border-indigo-500/40">
              <FileText className="w-4 h-4" />
            </div>
            <div>
              <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-indigo-400">
                {isCentralized ? 'CENTRALIZED MULTI-SOURCE REPORT' : 'SOURCE-SPECIFIC REPORT'}
              </span>
              <h3 className="text-sm font-bold text-slate-100 font-mono">
                BACKEND REPORT GENERATOR: {selectedCaseId || '—'}
              </h3>
            </div>
          </div>
          <button
            onClick={() => setReportModalOpen(false)}
            className="p-1 rounded text-slate-400 hover:text-white transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Body */}
        <div className="p-5 space-y-4 text-xs overflow-y-auto flex-1">
          <div>
            <label className="block text-[11px] font-semibold text-slate-300 mb-1 font-mono uppercase tracking-wider">
              Report Title
            </label>
            <input
              value={reportTitle}
              onChange={e => setReportTitle(e.target.value)}
              className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-slate-100 focus:outline-none focus:border-cyan-500 font-mono"
            />
          </div>

          {isCentralized && (
            <div className="p-2.5 rounded-lg bg-cyan-950/30 border border-cyan-500/40 text-cyan-300 flex items-start gap-2">
              <Sparkles className="w-3.5 h-3.5 shrink-0 mt-0.5" />
              <span>
                This case has completed centralized analysis — the CENTRALIZED backend report
                path (report.generate_centralized) will be used.
              </span>
            </div>
          )}

          {error && (
            <div className="p-2.5 rounded-lg bg-rose-950/40 border border-rose-500/40 text-rose-300 font-mono" role="alert">
              {error}
            </div>
          )}

          {!latest ? (
            <div className="flex justify-end pt-2">
              <button
                type="button"
                onClick={handleGenerate}
                disabled={busy}
                className="flex items-center gap-2 px-4 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 disabled:bg-slate-800 disabled:text-slate-600 text-white font-mono font-bold text-xs transition-colors shadow-[0_0_15px_rgba(99,102,241,0.4)]"
              >
                <FileText className="w-3.5 h-3.5" />
                <span>{busy ? 'Generating on backend…' : 'Generate Report on Backend'}</span>
              </button>
            </div>
          ) : (
            <div className="space-y-3">
              <div className="flex items-center justify-between p-2.5 rounded-lg bg-emerald-950/40 border border-emerald-500/40 text-emerald-300 text-xs">
                <div className="flex items-center gap-2">
                  <Check className="w-4 h-4" />
                  <span className="font-mono">
                    Backend report persisted: {latest.humanId} ({formatIstTimestamp(latest.generatedAt)})
                  </span>
                </div>
                <button
                  onClick={handleGenerate}
                  disabled={busy}
                  className="text-[11px] underline hover:text-emerald-200 disabled:opacity-40"
                >
                  {busy ? 'Regenerating…' : 'Regenerate'}
                </button>
              </div>

              {/* REAL backend sections */}
              <div className="p-4 rounded-lg bg-[#070A10] border border-slate-800 font-mono text-[11px] text-slate-200 leading-relaxed max-h-72 overflow-y-auto whitespace-pre-wrap select-text">
                {latest.raw?.sections?.length ? (
                  latest.raw.sections.map((s: any, i: number) => (
                    <div key={i} className="mb-3">
                      <div className="text-cyan-300 font-bold">## {s.title}</div>
                      {s.items?.map((it: any, j: number) => (
                        <div key={j} className="text-slate-300">
                          {it.title ? `- ${it.title}` : '-'}{it.text ? `: ${it.text}` : ''}
                          {it.reference_id ? ` [${it.reference_id}]` : ''}
                        </div>
                      ))}
                    </div>
                  ))
                ) : (
                  <span className="text-slate-500">Report contains no sections.</span>
                )}
                {latest.raw?.evidence_references?.length > 0 && (
                  <div className="mt-3 text-slate-500">
                    Evidence references: {latest.raw.evidence_references.join(', ')}
                  </div>
                )}
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="flex items-center justify-between p-4 border-t border-slate-800 bg-[#0A0D15] shrink-0">
          <span className="text-[11px] font-mono text-slate-500">
            Exports are backend-generated JSON (report.export). PDF/CSV are not supported by the backend.
          </span>
          <div className="flex items-center gap-2">
            {latest && (
              <button
                type="button"
                onClick={handleDownload}
                className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white font-mono font-bold text-xs transition-colors shadow-[0_0_12px_rgba(99,102,241,0.3)]"
              >
                <Download className="w-3.5 h-3.5" />
                <span>Download .JSON</span>
              </button>
            )}
            <button
              type="button"
              onClick={() => setReportModalOpen(false)}
              className="px-3.5 py-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 font-mono text-xs transition-colors"
            >
              Close
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
