import React, { useMemo, useState } from 'react';
import { Archive, Download, Filter, Search, ShieldCheck, Clock } from 'lucide-react';
import { useSoc } from '../../context/SocContext';

type LifecycleFilter = 'ALL' | 'LIVE' | 'INVESTIGATION' | 'CANDIDATE' | 'ARCHIVED';

/**
 * 5.5 + 5.6 frontend shell: temporary lifecycle and evidence archive preview.
 *
 * The backend does not yet expose evidence lifecycle/TTL APIs. This page
 * derives a truthful, read-only lifecycle view from real connected cases,
 * detections, and correlations without inventing persistence or promotion
 * actions. Promotion/finalization controls are disabled Future actions.
 */
export const EvidencePage: React.FC = () => {
  const { cases, detections, correlations } = useSoc();
  const [q, setQ] = useState('');
  const [filter, setFilter] = useState<LifecycleFilter>('ALL');

  const rows = useMemo(() => {
    const items = cases.map((c) => {
      const dets = detections.filter((d) => d.caseId === c.humanId).length;
      const corrs = correlations.filter((x) => x.caseId === c.humanId).length;
      const lifecycle: Exclude<LifecycleFilter, 'ALL'> = c.status === 'CLOSED' ? 'ARCHIVED' : dets + corrs > 0 ? 'INVESTIGATION' : 'CANDIDATE';
      return { id: c.humanId, title: c.title, status: c.status, severity: c.severity, dets, corrs, lifecycle, updated: c.lastSeen };
    });
    const needle = q.toLowerCase().trim();
    return items.filter((r) => {
      if (filter !== 'ALL' && r.lifecycle !== filter) return false;
      if (!needle) return true;
      return [r.id, r.title, r.status].join(' ').toLowerCase().includes(needle);
    });
  }, [cases, detections, correlations, q, filter]);

  return (
    <div className="space-y-5 pb-12">
      <div className="pb-2 border-b border-slate-800">
        <div className="flex flex-wrap items-center gap-2">
          <h1 className="text-lg font-semibold tracking-tight text-slate-100">Evidence Archive</h1>
          <span className="text-[11px] font-mono px-2 py-0.5 rounded-full bg-slate-800 text-slate-200 border border-slate-700">{rows.length} items</span>
          <span className="text-[11px] font-mono px-2 py-0.5 rounded-full bg-slate-800 text-slate-400 border border-slate-700">Preview · Demo Data</span>
        </div>
        <p className="text-xs text-slate-400 mt-1 max-w-3xl">
          Candidate security data is temporary. Only analyst-reviewed, promoted evidence belongs in the durable archive.
          This preview derives lifecycle state from live cases; retention and promotion APIs are not connected yet.
        </p>
      </div>

      <div className="p-3.5 rounded-xl bg-[#0F1420] border border-slate-800 flex flex-col lg:flex-row gap-3">
        <div className="relative flex-1">
          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Search evidence by case, title, or state..."
            aria-label="Search evidence"
            className="w-full pl-9 pr-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-xs text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-slate-500"
          />
        </div>
        <label className="flex items-center gap-2 text-[11px] font-mono text-slate-400">
          <Filter className="w-3.5 h-3.5" />
          <select
            value={filter}
            onChange={(e) => setFilter(e.target.value as LifecycleFilter)}
            aria-label="Filter by lifecycle"
            className="px-2.5 py-2 rounded-lg bg-slate-900 border border-slate-700 text-xs text-slate-200 focus:outline-none"
          >
            {(['ALL', 'LIVE', 'INVESTIGATION', 'CANDIDATE', 'ARCHIVED'] as LifecycleFilter[]).map((v) => (
              <option key={v} value={v}>{v === 'ALL' ? 'All lifecycle states' : v}</option>
            ))}
          </select>
        </label>
      </div>

      <div className="rounded-xl bg-[#0F1420] border border-slate-800 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="text-left text-[10px] uppercase tracking-wider text-slate-500 border-b border-slate-800">
                <th className="py-2.5 px-3 font-medium">Evidence</th>
                <th className="py-2.5 px-3 font-medium">Lifecycle</th>
                <th className="py-2.5 px-3 font-medium">Linked objects</th>
                <th className="py-2.5 px-3 font-medium">Retention</th>
                <th className="py-2.5 px-3 font-medium text-right">Action</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.id} className="border-b border-slate-800/60 last:border-0 hover:bg-slate-900/40">
                  <td className="py-3 px-3">
                    <div className="font-mono font-semibold text-slate-100">{r.id}</div>
                    <div className="text-slate-400 truncate max-w-[320px]">{r.title}</div>
                  </td>
                  <td className="py-3 px-3">
                    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded border bg-slate-900 border-slate-700 text-slate-300 text-[11px] font-mono">
                      {r.lifecycle === 'ARCHIVED' ? <Archive className="w-3 h-3" /> : r.lifecycle === 'INVESTIGATION' ? <ShieldCheck className="w-3 h-3" /> : <Clock className="w-3 h-3" />}
                      {r.lifecycle}
                    </span>
                  </td>
                  <td className="py-3 px-3 font-mono text-slate-300">{r.dets}d · {r.corrs}c</td>
                  <td className="py-3 px-3 font-mono text-slate-500">TTL preview only</td>
                  <td className="py-3 px-3 text-right">
                    <button
                      type="button"
                      disabled
                      title="Backend dependency: evidence promotion API is not available yet"
                      className="px-2.5 py-1 rounded bg-slate-900 text-slate-500 border border-slate-800 text-[11px] font-mono cursor-not-allowed"
                    >
                      <Download className="w-3 h-3 inline mr-1" /> Promote (Future)
                    </button>
                  </td>
                </tr>
              ))}
              {rows.length === 0 && (
                <tr>
                  <td colSpan={5} className="py-8 px-3 text-center text-slate-500">
                    No evidence matches this view. Candidate data appears after real detections and cases exist.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
