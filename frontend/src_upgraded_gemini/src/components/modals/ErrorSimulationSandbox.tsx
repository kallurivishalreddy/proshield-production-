import React from 'react';
import {
  X,
  Bug,
  AlertTriangle,
  ArrowRight
} from 'lucide-react';
import { useSoc } from '../../context/SocContext';

export const ErrorSimulationSandbox: React.FC = () => {
  const {
    isErrorSandboxOpen,
    setErrorSandboxOpen,
    activeErrorScenario,
    triggerErrorScenario
  } = useSoc();

  if (!isErrorSandboxOpen) return null;

  const errorScenarios = [
    { code: 409, title: '409 State Conflict (Source Enabled)', desc: 'Attempting to edit an enabled source before disabling it.' },
    { code: 403, title: '403 Forbidden (RBAC Limit)', desc: 'Tier-1 analyst attempting to modify production rules without approval.' },
    { code: 429, title: '429 Rate Limit (Telemetry Lag)', desc: 'Ingestion pipeline backpressure exceeding partition buffers.' },
    { code: 400, title: '400 Bad Request (Schema Error)', desc: 'Invalid JSON/Regex filter payload in detection rule definition.' },
    { code: 401, title: '401 Unauthorized (Session Expired)', desc: 'Analyst JWT SSO session invalidated by IdP.' },
    { code: 404, title: '404 Not Found (Purged Artifact)', desc: 'Querying an ephemeral telemetry event pruned by retention.' },
    { code: 500, title: '500 Server Error (Worker Fault)', desc: 'Correlation graph worker timeout with auto-restart supervisor.' }
  ];

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-in fade-in duration-200">
      <div className="relative w-full max-w-2xl rounded-xl bg-[#0F1420] border border-rose-500/40 shadow-2xl overflow-hidden flex flex-col">
        {/* Header */}
        <div className="flex items-center justify-between p-4 border-b border-slate-800 bg-[#0A0D15]">
          <div className="flex items-center gap-2.5">
            <div className="p-1.5 rounded bg-rose-950 text-rose-400 border border-rose-500/40">
              <Bug className="w-4 h-4" />
            </div>
            <div>
              <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-rose-400">
                SOC TRUTHFUL ERROR UX SANDBOX
              </span>
              <h3 className="text-sm font-bold text-slate-100 font-mono">
                FAILURE STATES & RECOVERY WORKFLOWS
              </h3>
            </div>
          </div>
          <button
            onClick={() => setErrorSandboxOpen(false)}
            className="p-1 rounded text-slate-400 hover:text-white transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Body */}
        <div className="p-5 text-xs space-y-4">
          <p className="text-slate-300 text-xs">
            In high-stakes security operations, silent failures or misleading "Success" indicators cause critical data loss. ProShield enforces <strong>Truthful Error Handling</strong> with explicit causal diagnostics and immediate recovery actions.
          </p>

          {/* Quick Trigger Buttons */}
          <div>
            <span className="text-[11px] font-mono font-bold uppercase tracking-wider text-slate-400 block mb-2">
              Select an Error Scenario to Simulate:
            </span>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
              {errorScenarios.map(sc => (
                <button
                  key={sc.code}
                  onClick={() => triggerErrorScenario(sc.code)}
                  className={`p-2.5 rounded-lg text-left border transition-all ${
                    activeErrorScenario?.code === sc.code
                      ? 'bg-rose-950/50 border-rose-500 text-rose-200 ring-1 ring-rose-500/50'
                      : 'bg-slate-900/60 border-slate-800 text-slate-300 hover:border-slate-700'
                  }`}
                >
                  <div className="flex items-center justify-between font-mono font-bold text-xs text-rose-300">
                    <span>{sc.title}</span>
                    <span className="text-[10px] px-1 rounded bg-slate-800 text-slate-400">
                      HTTP {sc.code}
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-400 mt-1 line-clamp-1">{sc.desc}</p>
                </button>
              ))}
            </div>
          </div>

          {/* Active Error Display Card */}
          {activeErrorScenario && (
            <div className="p-4 rounded-lg bg-rose-950/30 border border-rose-500/50 space-y-3 animate-in slide-in-from-bottom duration-200">
              <div className="flex items-start gap-3">
                <AlertTriangle className="w-5 h-5 text-rose-400 shrink-0 mt-0.5" />
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="font-mono font-bold text-rose-300 text-xs">
                      [HTTP {activeErrorScenario.code}]
                    </span>
                    <h4 className="font-bold text-slate-100 text-xs">
                      {activeErrorScenario.title}
                    </h4>
                  </div>
                  <p className="text-slate-200 text-xs leading-relaxed">
                    {activeErrorScenario.message}
                  </p>
                </div>
              </div>

              {/* Actionable Suggestion */}
              <div className="p-2.5 rounded bg-[#0A0D15] border border-slate-800 space-y-1">
                <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-cyan-400 block">
                  Recommended Recovery Action:
                </span>
                <p className="text-[11px] text-slate-300 font-mono">
                  {activeErrorScenario.suggestion}
                </p>
              </div>

              {/* Action Button */}
              {activeErrorScenario.actionLabel && (
                <div className="flex justify-end pt-1">
                  <button
                    onClick={() => {
                      if (activeErrorScenario.actionTarget) {
                        activeErrorScenario.actionTarget();
                      }
                      setErrorSandboxOpen(false);
                    }}
                    className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-rose-600 hover:bg-rose-500 text-white font-mono font-bold text-xs transition-colors shadow-[0_0_12px_rgba(244,63,94,0.3)]"
                  >
                    <span>{activeErrorScenario.actionLabel}</span>
                    <ArrowRight className="w-3.5 h-3.5" />
                  </button>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="p-3 border-t border-slate-800 bg-[#0A0D15] flex items-center justify-between text-[11px] font-mono text-slate-500">
          <span>Fail-Safe SOC Protocol Active</span>
          <button
            onClick={() => setErrorSandboxOpen(false)}
            className="text-slate-400 hover:text-white"
          >
            Close Sandbox
          </button>
        </div>
      </div>
    </div>
  );
};
