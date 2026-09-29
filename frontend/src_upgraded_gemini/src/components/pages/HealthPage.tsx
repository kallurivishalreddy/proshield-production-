import React from 'react';
import {
  RotateCcw,
  Terminal,
  Bug
} from 'lucide-react';
import { useSoc } from '../../context/SocContext';
import { formatIstTimestamp } from '../../utils/format';

export const HealthPage: React.FC = () => {
  const {
    healthSubsystems,
    resolveHealthSubsystem,
    openPayloadDrawer,
    setErrorSandboxOpen
  } = useSoc();

  const warningCount = healthSubsystems.filter(h => h.status === 'WARNING').length;
  const criticalCount = healthSubsystems.filter(h => h.status === 'CRITICAL').length;

  return (
    <div className="space-y-6 pb-12 animate-in fade-in duration-200">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-2 border-b border-slate-800">
        <div>
          <div className="flex flex-wrap items-center gap-2">
            <h1 className="text-lg font-semibold tracking-tight text-slate-100">
              Health
            </h1>
            <span
              className="text-[11px] font-mono px-2 py-0.5 rounded-full border bg-slate-800 text-slate-200 border-slate-700"
            >
              {warningCount + criticalCount === 0
                ? `${healthSubsystems.length} checks passing`
                : `${warningCount + criticalCount} of ${healthSubsystems.length} need attention`}
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Live backend checks. Open a row for diagnostics and recommended actions.
          </p>
        </div>

        <button
          onClick={() => setErrorSandboxOpen(true)}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 text-xs font-mono transition-colors"
        >
          <Bug className="w-3.5 h-3.5" />
          <span>Error states</span>
        </button>
      </div>

      {/* Subsystem Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {healthSubsystems.map(sub => {
          const isWarning = sub.status === 'WARNING';
          const isCritical = sub.status === 'CRITICAL';

          return (
            <div
              key={sub.id}
              className="p-4 rounded-xl bg-[#0F1420] border border-slate-700 flex flex-col justify-between space-y-4"
            >
              <div className="space-y-3">
                {/* Subsystem Name & Badge */}
                <div className="flex items-start justify-between gap-2">
                  <div className="space-y-0.5">
                    <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400">
                      {sub.category}
                    </span>
                    <h3 className="text-xs font-bold text-slate-100 font-mono leading-snug">
                      {sub.name}
                    </h3>
                  </div>

                  <span
                    className="text-[10px] font-mono font-semibold px-2 py-0.5 rounded border uppercase tracking-wider bg-slate-800 border-slate-700 text-slate-200"
                  >
                    {sub.status}
                  </span>
                </div>

                {/* Subsystem Telemetry Metrics */}
                <div className="grid grid-cols-3 gap-2 p-2 rounded-lg bg-[#0A0D15] border border-slate-800/80 text-center font-mono text-xs">
                  <div>
                    <span className="text-[10px] text-slate-500 uppercase block">Latency</span>
                    <span className="font-semibold text-slate-200">
                      {sub.latencyMs}ms
                    </span>
                  </div>
                  <div>
                    <span className="text-[10px] text-slate-500 uppercase block">Throughput</span>
                    <span className="text-slate-200 font-bold truncate block">{sub.throughput}</span>
                  </div>
                  <div>
                    <span className="text-[10px] text-slate-500 uppercase block">Uptime</span>
                    <span className="text-slate-200 font-semibold">{sub.uptime}</span>
                  </div>
                </div>

                {/* Diagnostics Block: Answers the 4 required questions */}
                {(isWarning || isCritical) && sub.whatIsWrong && (
                  <div className="p-3 rounded-lg bg-slate-900 border border-slate-700 space-y-2 text-xs">
                    <div>
                      <span className="text-[10px] font-semibold text-slate-300 uppercase tracking-wider block">
                        What is wrong?
                      </span>
                      <p className="text-slate-200 text-xs">{sub.whatIsWrong}</p>
                    </div>

                    <div>
                      <span className="text-[10px] font-semibold text-slate-300 uppercase tracking-wider block">
                        How serious is it?
                      </span>
                      <p className="text-slate-300 text-xs">{sub.severityExplanation}</p>
                    </div>

                    {sub.affectedComponents && (
                      <div>
                        <span className="text-[10px] font-semibold text-slate-300 uppercase tracking-wider block">
                          What is affected?
                        </span>
                        <div className="flex flex-wrap gap-1 mt-0.5">
                          {sub.affectedComponents.map(comp => (
                            <span key={comp} className="px-1.5 py-0.2 rounded bg-slate-800 text-slate-200 text-[10px]">
                              {comp}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}

                    <div>
                      <span className="text-[10px] font-semibold text-slate-300 uppercase tracking-wider block">
                        What should I do?
                      </span>
                      <p className="text-slate-300 text-xs">{sub.remediationAction}</p>
                    </div>
                  </div>
                )}
              </div>

              {/* Action Buttons */}
              <div className="pt-2 border-t border-slate-800/80 flex items-center justify-between text-xs font-mono">
                <span className="text-[10px] text-slate-500">
                  Tested: {formatIstTimestamp(sub.lastTested)}
                </span>

                <div className="flex items-center gap-1.5">
                  {(isWarning || isCritical) && (
                    <button
                      onClick={() => resolveHealthSubsystem(sub.id)}
                      title="Re-probe real backend health"
                      className="flex items-center gap-1 px-2.5 py-1 rounded bg-slate-100 hover:bg-white text-slate-900 font-semibold transition-colors"
                    >
                      <RotateCcw className="w-3 h-3" />
                      <span>Re-probe</span>
                    </button>
                  )}

                  <button
                    onClick={() =>
                      openPayloadDrawer({
                        title: `Subsystem Diagnostics: ${sub.name}`,
                        subtitle: `Category: ${sub.category} • Status: ${sub.status}`,
                        payload: {
                          subsystem_id: sub.id,
                          name: sub.name,
                          status: sub.status,
                          latency_ms: sub.latencyMs,
                          throughput: sub.throughput,
                          uptime: sub.uptime,
                          last_tested: sub.lastTested,
                          diagnostics: sub.whatIsWrong || 'All checks passed within SLA.'
                        }
                      })
                    }
                    className="p-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition-colors"
                    title="Open diagnostics"
                  >
                    <Terminal className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
