import React, { useMemo, useState } from 'react';
import { Database, Download, Plus, Search } from 'lucide-react';
import { useSoc } from '../../context/SocContext';

/**
 * 5.7 + 5.8 frontend shell: dataset list/detail/export preview.
 *
 * Datasets are distinct from the evidence archive. The backend dataset API
 * does not exist yet, so this page shows a truthful local preview derived
 * from connected evidence counts. Export buttons download a locally built
 * JSON preview and are labeled accordingly; no backend dataset creation,
 * versioning, Parquet export, or model training is implied.
 */
export const DatasetsPage: React.FC = () => {
  const { cases, detections, correlations } = useSoc();
  const [q, setQ] = useState('');

  const preview = useMemo(() => ([
    {
      id: 'DATASET-PREVIEW-01',
      name: 'Reviewed true-positive preview',
      version: 'v0-preview',
      status: 'Preview',
      evidence: cases.filter((c) => c.status === 'CLOSED').length,
      detections: detections.length,
      correlations: correlations.length,
      updated: new Date().toISOString(),
    },
  ]), [cases, detections, correlations]);

  const rows = preview.filter((d) => {
    const needle = q.toLowerCase().trim();
    if (!needle) return true;
    return [d.id, d.name, d.version].join(' ').toLowerCase().includes(needle);
  });

  const downloadPreview = (id: string) => {
    const payload = {
      dataset: id,
      generated_at: new Date().toISOString(),
      provenance: 'Local UI preview derived from currently loaded ProShield objects. Not a backend dataset version.',
      counts: { cases: cases.length, detections: detections.length, correlations: correlations.length },
      formats: ['JSON preview only', 'CSV/Parquet are future backend exports'],
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${id.toLowerCase()}-preview.json`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-5 pb-12">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-2 border-b border-slate-800">
        <div>
          <div className="flex flex-wrap items-center gap-2">
            <h1 className="text-lg font-semibold tracking-tight text-slate-100">AI Datasets</h1>
            <span className="text-[11px] font-mono px-2 py-0.5 rounded-full bg-slate-800 text-slate-200 border border-slate-700">{rows.length} preview</span>
            <span className="text-[11px] font-mono px-2 py-0.5 rounded-full bg-slate-800 text-slate-400 border border-slate-700">Not Connected</span>
          </div>
          <p className="text-xs text-slate-400 mt-1 max-w-3xl">
            Build quality-controlled datasets from reviewed evidence. This shell previews dataset shape and export workflow.
            It does not train models and does not create backend dataset versions.
          </p>
        </div>
        <button
          type="button"
          disabled
          title="Backend dependency: dataset.create/build API is not available yet"
          className="flex items-center gap-2 px-4 py-2 rounded-lg bg-slate-800 text-slate-500 font-mono font-semibold text-xs cursor-not-allowed border border-slate-700"
        >
          <Plus className="w-4 h-4" />
          <span>Build dataset (Future)</span>
        </button>
      </div>

      <div className="p-3.5 rounded-xl bg-[#0F1420] border border-slate-800">
        <div className="relative">
          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Search dataset previews..."
            aria-label="Search datasets"
            className="w-full pl-9 pr-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-xs text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-slate-500"
          />
        </div>
      </div>

      <div className="space-y-3">
        {rows.map((d) => (
          <section key={d.id} aria-label={`Dataset ${d.name}`} className="p-4 rounded-xl bg-[#0F1420] border border-slate-800 space-y-3">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex items-center gap-2">
                <Database className="w-4 h-4 text-slate-300" />
                <h2 className="text-sm font-semibold text-slate-100">{d.name}</h2>
                <span className="text-[11px] font-mono text-slate-400">{d.id} · {d.version}</span>
              </div>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded border bg-slate-900 border-slate-700 text-slate-300">{d.status} · Demo Data</span>
            </div>
            <dl className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-[11px] font-mono">
              {[
                ['Reviewed cases', String(d.evidence)],
                ['Detections', String(d.detections)],
                ['Correlations', String(d.correlations)],
                ['Export', 'JSON preview'],
              ].map(([k, v]) => (
                <div key={k} className="p-2 rounded bg-slate-900 border border-slate-800">
                  <dt className="text-slate-500">{k}</dt>
                  <dd className="text-slate-100 font-semibold">{v}</dd>
                </div>
              ))}
            </dl>
            <div className="flex flex-wrap gap-2">
              <button
                type="button"
                onClick={() => downloadPreview(d.id)}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs font-mono"
              >
                <Download className="w-3.5 h-3.5" />
                <span>Download JSON preview</span>
              </button>
              {['CSV (Future)', 'Parquet (Future)', 'PDF report (Future)'].map((label) => (
                <button
                  key={label}
                  type="button"
                  disabled
                  title="Future backend export format"
                  className="px-3 py-1.5 rounded-lg bg-slate-900 text-slate-500 border border-slate-800 text-xs font-mono cursor-not-allowed"
                >
                  {label}
                </button>
              ))}
            </div>
          </section>
        ))}
      </div>
    </div>
  );
};
