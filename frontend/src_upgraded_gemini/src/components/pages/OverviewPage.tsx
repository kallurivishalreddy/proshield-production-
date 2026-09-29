import React from 'react';
import {
  AlertTriangle,
  Radio,
  Network,
  Cpu,
  ArrowRight,
  ShieldAlert,
  Activity,
  Sparkles,
  TrendingUp,
  Flame
} from 'lucide-react';
import { useSoc } from '../../context/SocContext';
import { SeverityBadge } from '../common/SeverityBadge';
import { StatusBadge } from '../common/StatusBadge';
import { HumanIdTag } from '../common/HumanIdTag';
import { MetricCard } from '../common/MetricCard';
import { formatIstHourMinute } from '../../utils/format';

export const OverviewPage: React.FC = () => {
  const {
    cases,
    detections,
    correlations,
    sources,
    rules,
    healthSubsystems,
    overviewSeries,
    navigate,
    setCentralizedAnalysisModalOpen,
    setSelectedCaseId
  } = useSoc();

  const openCases = cases.filter(c => c.status !== 'CLOSED');
  const criticalCases = openCases.filter(c => c.severity === 'CRITICAL');
  const highCases = openCases.filter(c => c.severity === 'HIGH');
  const mostUrgentCase = criticalCases[0] || openCases[0] || cases[0];
  const activeSourcesCount = sources.filter(s => s.status === 'ENABLED').length;
  const activeRulesCount = rules.filter(r => r.lifecycleStatus === 'ACTIVE').length;
  const hasHealthWarning = healthSubsystems.some(h => h.status !== 'HEALTHY');

  // Threat trend: the backend's SERVER-SIDE hourly aggregate
  // (overview.timeseries — capability patch gap 15). Each bucket is an
  // explicit, real count of persisted detections; empty periods are
  // real zeros. The client-side timestamp bucketing below is only the
  // fallback when the aggregate op is unavailable.
  const hourlyTrend = (() => {
    if (overviewSeries.length > 0) {
      return overviewSeries.map(b => ({
        hour: b.bucket,
        label: formatIstHourMinute(b.bucket),
        count: b.detections,
      }));
    }
    const buckets: { hour: string; label: string; count: number }[] = [];
    const now = new Date();
    for (let i = 7; i >= 0; i--) {
      const iso = new Date(now.getTime() - i * 3600_000).toISOString();
      buckets.push({ hour: iso, label: formatIstHourMinute(iso), count: 0 });
    }
    const parse = (s: string) => Date.parse(s);
    for (const d of detections) {
      const t = parse(d.timestamp);
      if (Number.isNaN(t)) continue;
      const hoursAgo = Math.floor((now.getTime() - t) / 3600_000);
      if (hoursAgo >= 0 && hoursAgo < 8) buckets[7 - hoursAgo].count += 1;
    }
    return buckets;
  })();
  const maxCount = Math.max(1, ...hourlyTrend.map(t => t.count));
  const peakBucket = hourlyTrend.reduce((a, b) => (b.count > a.count ? b : a), hourlyTrend[0]);

  return (
    <div className="space-y-6 pb-12 animate-in fade-in duration-200">
      {/* 1. HERO / CRITICAL ATTENTION TRIAGE BANNER */}
      {mostUrgentCase && (
        <div className="relative overflow-hidden rounded-xl border border-slate-700 bg-[#101623] p-5">
          <div className="absolute top-0 right-0 w-96 h-96 bg-slate-800/20 rounded-full blur-3xl pointer-events-none" />

          <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-4 relative z-10">
            <div className="space-y-2 max-w-3xl">
              <div className="flex flex-wrap items-center gap-2">
                <span className="flex items-center gap-1.5 px-2 py-0.5 rounded bg-slate-800 text-slate-200 border border-slate-700 font-mono text-[11px] font-semibold">
                  <Flame className="w-3.5 h-3.5 text-slate-300" />
                  Needs attention
                </span>
                <HumanIdTag humanId={mostUrgentCase.humanId} internalUuid={mostUrgentCase.internalUuid} />
                <SeverityBadge severity={mostUrgentCase.severity} size="sm" />
                <StatusBadge status={mostUrgentCase.status} size="sm" />
              </div>

              <h2 className="text-lg font-bold text-slate-100 tracking-tight">
                {mostUrgentCase.title}
              </h2>

              <p className="text-xs text-slate-300 leading-relaxed line-clamp-2">
                {mostUrgentCase.description}
              </p>

              <div className="flex flex-wrap items-center gap-4 text-xs font-mono text-slate-400 pt-1">
                <span>
                  Attacker:{' '}
                  <strong className="text-slate-200">{mostUrgentCase.attackerIp || 'not attributed by backend'}</strong>
                  {mostUrgentCase.attackerCountry ? ` (${mostUrgentCase.attackerCountry})` : ''}
                </span>
                <span>•</span>
                <span>Target: <strong className="text-cyan-300">{mostUrgentCase.targetAsset}</strong></span>
                <span>•</span>
                <span>Evidence: <strong className="text-amber-300">{mostUrgentCase.eventCount} events</strong> across {mostUrgentCase.detectionCount} detections</span>
              </div>
            </div>

            <div className="flex flex-row lg:flex-col items-center lg:items-end gap-2.5 shrink-0 w-full lg:w-auto">
              <button
                onClick={() => navigate('case-detail', mostUrgentCase.humanId)}
                className="flex-1 lg:flex-initial flex items-center justify-center gap-2 px-5 py-2.5 rounded-lg bg-slate-100 hover:bg-white text-slate-900 font-mono font-semibold text-xs transition-colors"
              >
                <span>Investigate</span>
                <ArrowRight className="w-4 h-4" />
              </button>

              {mostUrgentCase.isCorrelated && (
                <button
                  onClick={() => {
                    setSelectedCaseId(mostUrgentCase.humanId);
                    setCentralizedAnalysisModalOpen(true);
                  }}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-200 border border-slate-700 text-xs font-mono transition-colors"
                >
                  <Sparkles className="w-3.5 h-3.5 text-slate-300" />
                  <span>Centralized analysis</span>
                </button>
              )}
            </div>
          </div>
        </div>
      )}

      {/* 2. PRIMARY OPERATIONAL METRICS */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <MetricCard
          title="Active Incidents"
          value={openCases.length}
          subtitle={`${criticalCases.length} Critical, ${highCases.length} High severity in queue`}
          icon={<AlertTriangle className="w-5 h-5" />}
          highlight={criticalCases.length > 0 ? 'red' : 'amber'}
          onClick={() => navigate('incidents')}
        />
        <MetricCard
          title="Detection Alerts"
          value={detections.length}
          subtitle={`Matching ${activeRulesCount} active backend rules`}
          icon={<Radio className="w-5 h-5" />}
          highlight="amber"
          onClick={() => navigate('detections')}
        />
        <MetricCard
          title="Correlations"
          value={correlations.length}
          subtitle="Multi-stage attack clusters synthesized"
          icon={<Network className="w-5 h-5" />}
          highlight="purple"
          onClick={() => navigate('correlations')}
        />
        <MetricCard
          title="Telemetry Sources"
          value={`${activeSourcesCount}/${sources.length}`}
          subtitle={`${activeRulesCount} rules evaluating live streams`}
          icon={<Cpu className="w-5 h-5" />}
          highlight="emerald"
          onClick={() => navigate('sources')}
        />
      </div>

      {/* 3. CORE ANALYST INTELLIGENCE GRID: THREAT TRENDS + QUEUE */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left 2 Cols: Threat Activity Trend & Queue */}
        <div className="lg:col-span-2 space-y-6">
          {/* Hourly Ingestion & Detection Velocity Chart */}
          <div className="p-4 rounded-xl bg-[#0F1420] border border-slate-800 space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <TrendingUp className="w-4 h-4 text-slate-300" />
                <h3 className="text-xs font-semibold text-slate-200 tracking-wide">
                  Detection activity (last 8 hours)
                </h3>
              </div>
              <span className="text-[11px] font-mono text-slate-400">
                Peak: <strong>{peakBucket.count} signals/hr</strong> at {peakBucket.label}
              </span>
            </div>

            {/* Spark Bar Chart */}
            <div className="h-28 flex items-end justify-between gap-3 pt-4 px-2">
              {hourlyTrend.map((item, idx) => {
                const heightPercent = (item.count / maxCount) * 100;
                const isPeak = item.count === maxCount;
                return (
                  <div key={idx} className="flex-1 flex flex-col items-center gap-1.5 group">
                    <span className="text-[10px] font-mono text-slate-400 opacity-0 group-hover:opacity-100 transition-opacity">
                      {item.count}
                    </span>
                    <div
                      className={`w-full rounded-t transition-all ${
                        isPeak
                          ? 'bg-slate-200'
                          : 'bg-slate-600 group-hover:bg-slate-400'
                      }`}
                      style={{ height: `${Math.max(heightPercent, 8)}%` }}
                    />
                    <span className="text-[10px] font-mono text-slate-500 group-hover:text-slate-300">
                      {item.label}
                    </span>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Active Priority Incident Queue */}
          <div className="p-4 rounded-xl bg-[#0F1420] border border-slate-800 space-y-3">
            <div className="flex items-center justify-between pb-2 border-b border-slate-800">
              <div className="flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-amber-400" />
                <h3 className="text-xs font-bold font-mono text-slate-200 uppercase tracking-wider">
                  Active Incident Queue
                </h3>
              </div>
              <button
                onClick={() => navigate('incidents')}
                className="text-xs font-mono text-cyan-400 hover:text-cyan-300 flex items-center gap-1"
              >
                <span>View all ({cases.length})</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </button>
            </div>

            <div className="space-y-2">
              {openCases.slice(0, 4).map(c => (
                <div
                  key={c.humanId}
                  onClick={() => navigate('case-detail', c.humanId)}
                  className="flex items-center justify-between p-3 rounded-lg bg-slate-900/70 hover:bg-slate-800 border border-slate-800 hover:border-cyan-500/40 cursor-pointer group transition-all"
                >
                  <div className="flex items-center gap-3 min-w-0">
                    <SeverityBadge severity={c.severity} size="sm" />
                    <div className="min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="font-mono font-bold text-xs text-cyan-300">
                          {c.humanId}
                        </span>
                        <span className="text-xs font-semibold text-slate-200 group-hover:text-cyan-200 truncate">
                          {c.title}
                        </span>
                      </div>
                      <div className="flex items-center gap-2 text-[11px] text-slate-400 mt-0.5">
                        <span className="truncate">{c.sourceName}</span>
                        <span>•</span>
                        <span className="font-mono text-slate-300">{c.attackerIp}</span>
                      </div>
                    </div>
                  </div>

                  <div className="flex items-center gap-3 shrink-0">
                    <span className="text-[11px] font-mono text-slate-500 hidden sm:inline">
                      {c.eventCount} evts
                    </span>
                    <StatusBadge status={c.status} size="sm" />
                    <ArrowRight className="w-4 h-4 text-slate-600 group-hover:text-cyan-400 transition-colors" />
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Right Col: System Health & Subsystem Status */}
        <div className="space-y-6">
          {/* Subsystem Health Snapshot */}
          <div className="p-4 rounded-xl bg-[#0F1420] border border-slate-800 space-y-3">
            <div className="flex items-center justify-between pb-2 border-b border-slate-800">
              <div className="flex items-center gap-2">
                <Activity className="w-4 h-4 text-emerald-400" />
                <h3 className="text-xs font-bold font-mono text-slate-200 uppercase tracking-wider">
                  Platform Operations
                </h3>
              </div>
              <button
                onClick={() => navigate('health')}
                className="text-xs font-mono text-cyan-400 hover:underline"
              >
                Detailed Diagnostics
              </button>
            </div>

            <div className="space-y-2">
              {healthSubsystems.slice(0, 6).map(sub => (
                <div
                  key={sub.id}
                  onClick={() => navigate('health')}
                  className="flex items-center justify-between p-2 rounded-lg bg-slate-900/60 hover:bg-slate-800 cursor-pointer border border-slate-800/60 transition-colors text-xs font-mono"
                >
                  <div className="flex items-center gap-2 truncate">
                    <span
                      className={`w-2 h-2 rounded-full ${
                        sub.status === 'HEALTHY'
                          ? 'bg-emerald-400'
                          : sub.status === 'WARNING'
                          ? 'bg-amber-400 animate-pulse'
                          : 'bg-rose-500 animate-pulse'
                      }`}
                    />
                    <span className="text-slate-300 truncate">{sub.name}</span>
                  </div>
                  <span className="text-slate-500 text-[11px] shrink-0 ml-2">
                    {sub.latencyMs}ms
                  </span>
                </div>
              ))}
            </div>

            {hasHealthWarning && (
              <div className="p-2.5 rounded-lg bg-amber-950/30 border border-amber-500/40 text-[11px] text-amber-300 flex items-start gap-2">
                <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
                <div>
                  <span className="font-bold font-mono">
                    {healthSubsystems.filter(h => h.status !== 'HEALTHY').length} subsystem(s) reporting warnings:
                  </span>{' '}
                  See Health / System for real diagnostic state.
                </div>
              </div>
            )}
          </div>

          {/* Quick SOC Actions */}
          <div className="p-4 rounded-xl bg-gradient-to-b from-[#111827] to-[#0D131F] border border-slate-800 space-y-3">
            <h3 className="text-xs font-bold font-mono text-slate-300 uppercase tracking-wider">
              Fast Operational Pivots
            </h3>
            <div className="grid grid-cols-2 gap-2 text-xs font-mono">
              <button
                onClick={() => navigate('timeline')}
                className="p-2.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 hover:border-cyan-500/40 text-left transition-colors"
              >
                <span className="text-cyan-400 block font-bold">Forensic Timeline</span>
                <span className="text-[10px] text-slate-500">Live multi-source stream</span>
              </button>
              <button
                onClick={() => navigate('correlations')}
                className="p-2.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 hover:border-purple-500/40 text-left transition-colors"
              >
                <span className="text-purple-400 block font-bold">Correlation Clusters</span>
                <span className="text-[10px] text-slate-500">{correlations.length} clusters on backend</span>
              </button>
              <button
                onClick={() => navigate('sources')}
                className="p-2.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 hover:border-emerald-500/40 text-left transition-colors"
              >
                <span className="text-emerald-400 block font-bold">+ New Source</span>
                <span className="text-[10px] text-slate-500">6-step wizard workflow</span>
              </button>
              <button
                onClick={() => navigate('rules')}
                className="p-2.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 hover:border-sky-500/40 text-left transition-colors"
              >
                <span className="text-sky-400 block font-bold">+ Create Rule</span>
                <span className="text-[10px] text-slate-500">{rules.length} rules on backend</span>
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
