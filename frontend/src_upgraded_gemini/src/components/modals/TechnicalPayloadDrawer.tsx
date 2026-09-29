import React, { useState } from 'react';
import { X, Copy, Check, Terminal, FileCode, Layers } from 'lucide-react';
import { useSoc } from '../../context/SocContext';
import { CopyableText } from '../common/CopyableText';

export const TechnicalPayloadDrawer: React.FC = () => {
  const {
    isPayloadDrawerOpen,
    closePayloadDrawer,
    payloadDrawerData,
    addToast
  } = useSoc();

  const [activeTab, setActiveTab] = useState<'formatted' | 'json' | 'raw'>('formatted');
  const [copiedRaw, setCopiedRaw] = useState(false);

  if (!isPayloadDrawerOpen || !payloadDrawerData) return null;

  const jsonString = JSON.stringify(payloadDrawerData.payload, null, 2);

  const handleCopyRaw = () => {
    navigator.clipboard.writeText(jsonString);
    setCopiedRaw(true);
    addToast('info', 'Payload Copied', 'Raw JSON payload copied to clipboard.');
    setTimeout(() => setCopiedRaw(false), 2000);
  };

  return (
    <div className="fixed inset-0 z-50 overflow-hidden bg-black/60 backdrop-blur-xs animate-in fade-in duration-200">
      <div className="absolute inset-0" onClick={closePayloadDrawer} />

      <div className="absolute inset-y-0 right-0 max-w-xl w-full bg-[#0E131E] border-l border-slate-700 shadow-2xl flex flex-col z-10 animate-in slide-in-from-right duration-300">
        {/* Drawer Header */}
        <div className="p-4 border-b border-slate-800 bg-[#0A0D15]">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <div className="p-1.5 rounded bg-cyan-950 text-cyan-400 border border-cyan-500/30">
                <Terminal className="w-4 h-4" />
              </div>
              <div>
                <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-cyan-400">
                  Forensic Technical Inspector
                </span>
                <h3 className="text-sm font-bold text-slate-100 truncate">
                  {payloadDrawerData.title}
                </h3>
              </div>
            </div>
            <button
              onClick={closePayloadDrawer}
              className="p-1 rounded-md text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
            >
              <X className="w-5 h-5" />
            </button>
          </div>

          {/* Human ID & Technical UUID Bar */}
          <div className="mt-3 flex flex-wrap items-center gap-2 text-xs">
            {payloadDrawerData.humanId && (
              <span className="font-mono font-bold text-cyan-300 px-2 py-0.5 rounded bg-cyan-950/60 border border-cyan-800">
                {payloadDrawerData.humanId}
              </span>
            )}
            {payloadDrawerData.internalUuid && (
              <div className="flex items-center gap-1">
                <span className="text-slate-400 font-mono text-[11px]">UUID:</span>
                <CopyableText text={payloadDrawerData.internalUuid} truncate={true} truncateLength={28} />
              </div>
            )}
          </div>

          <p className="text-xs text-slate-400 mt-2">
            {payloadDrawerData.subtitle}
          </p>

          {/* View Mode Tabs */}
          <div className="flex items-center gap-2 mt-4 pt-2 border-t border-slate-800/80">
            <button
              onClick={() => setActiveTab('formatted')}
              className={`flex items-center gap-1.5 px-3 py-1 rounded text-xs font-mono font-semibold transition-colors ${
                activeTab === 'formatted'
                  ? 'bg-slate-800 text-cyan-300 border border-slate-700 shadow-xs'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Layers className="w-3.5 h-3.5" />
              <span>Key-Value Map</span>
            </button>
            <button
              onClick={() => setActiveTab('json')}
              className={`flex items-center gap-1.5 px-3 py-1 rounded text-xs font-mono font-semibold transition-colors ${
                activeTab === 'json'
                  ? 'bg-slate-800 text-cyan-300 border border-slate-700 shadow-xs'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <FileCode className="w-3.5 h-3.5" />
              <span>Structured JSON</span>
            </button>
          </div>
        </div>

        {/* Body Content */}
        <div className="flex-1 overflow-y-auto p-4 bg-[#0A0D15]/80 font-mono text-xs">
          {activeTab === 'formatted' ? (
            <div className="space-y-2">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="border-b border-slate-800 text-slate-400 text-[11px] uppercase tracking-wider">
                    <th className="py-2 px-2 font-semibold w-1/3">Field</th>
                    <th className="py-2 px-2 font-semibold">Normalized Value</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {Object.entries(payloadDrawerData.payload).map(([key, val]) => (
                    <tr key={key} className="hover:bg-slate-800/40 transition-colors">
                      <td className="py-2 px-2 text-cyan-400 font-semibold align-top break-all">
                        {key}
                      </td>
                      <td className="py-2 px-2 text-slate-200 break-all">
                        {typeof val === 'object' && val !== null ? (
                          <pre className="text-[11px] bg-slate-900 p-1.5 rounded border border-slate-800 text-amber-200 overflow-x-auto">
                            {JSON.stringify(val, null, 2)}
                          </pre>
                        ) : (
                          <span>{String(val)}</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="relative">
              <pre className="p-3.5 rounded-lg bg-[#070A10] border border-slate-800 text-cyan-200 text-[11px] leading-relaxed overflow-x-auto selection:bg-cyan-600/40">
                {jsonString}
              </pre>
            </div>
          )}
        </div>

        {/* Drawer Footer */}
        <div className="p-3 border-t border-slate-800 bg-[#0A0D15] flex items-center justify-between">
          <span className="text-[11px] font-mono text-slate-500">
            Immutable Ingest Record
          </span>
          <button
            onClick={handleCopyRaw}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-mono font-medium border border-slate-700 transition-colors"
          >
            {copiedRaw ? (
              <>
                <Check className="w-3.5 h-3.5 text-emerald-400" />
                <span className="text-emerald-400">Copied</span>
              </>
            ) : (
              <>
                <Copy className="w-3.5 h-3.5" />
                <span>Copy Raw JSON</span>
              </>
            )}
          </button>
        </div>
      </div>
    </div>
  );
};
