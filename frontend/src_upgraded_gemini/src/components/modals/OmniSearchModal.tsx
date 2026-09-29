import React, { useState, useEffect, useRef } from 'react';
import {
  Search,
  X,
  AlertCircle,
  Radio,
  Network,
  ArrowRight
} from 'lucide-react';
import { useSoc } from '../../context/SocContext';
import { SeverityBadge } from '../common/SeverityBadge';

export const OmniSearchModal: React.FC = () => {
  const {
    isOmniSearchOpen,
    setOmniSearchOpen,
    navigate,
    cases,
    detections,
    correlations,
    sources,
    rules
  } = useSoc();

  const [query, setQuery] = useState('');
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (isOmniSearchOpen) {
      setTimeout(() => inputRef.current?.focus(), 50);
    } else {
      setQuery('');
    }
  }, [isOmniSearchOpen]);

  if (!isOmniSearchOpen) return null;

  const q = query.toLowerCase().trim();

  const filteredCases = cases.filter(
    c =>
      c.humanId.toLowerCase().includes(q) ||
      c.title.toLowerCase().includes(q) ||
      c.attackerIp.toLowerCase().includes(q) ||
      c.targetAsset.toLowerCase().includes(q) ||
      c.description.toLowerCase().includes(q)
  );

  const filteredDetections = detections.filter(
    d =>
      d.humanId.toLowerCase().includes(q) ||
      d.title.toLowerCase().includes(q) ||
      d.ruleName.toLowerCase().includes(q) ||
      (d.attackerIp && d.attackerIp.toLowerCase().includes(q))
  );

  const filteredCorrelations = correlations.filter(
    corr =>
      corr.humanId.toLowerCase().includes(q) ||
      corr.title.toLowerCase().includes(q) ||
      corr.attacker.toLowerCase().includes(q)
  );

  const filteredSources = sources.filter(
    s =>
      s.humanId.toLowerCase().includes(q) ||
      s.name.toLowerCase().includes(q) ||
      s.endpoint.toLowerCase().includes(q)
  );

  const filteredRules = rules.filter(
    r =>
      r.humanId.toLowerCase().includes(q) ||
      r.name.toLowerCase().includes(q) ||
      r.description.toLowerCase().includes(q)
  );

  const totalResults =
    filteredCases.length +
    filteredDetections.length +
    filteredCorrelations.length +
    filteredSources.length +
    filteredRules.length;

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center pt-20 px-4 bg-black/70 backdrop-blur-sm animate-in fade-in duration-200">
      <div className="relative w-full max-w-2xl rounded-xl bg-[#0F141F] border border-slate-700 shadow-2xl overflow-hidden">
        {/* Search Input Bar */}
        <div className="flex items-center gap-3 px-4 py-3 border-b border-slate-800 bg-[#0A0D15]">
          <Search className="w-5 h-5 text-cyan-400 shrink-0" />
          <input
            ref={inputRef}
            type="text"
            value={query}
            onChange={e => setQuery(e.target.value)}
            placeholder="Type a case ID, detection, IP, hostname, or rule..."
            className="w-full bg-transparent text-sm text-slate-100 placeholder:text-slate-500 focus:outline-none"
            onKeyDown={e => {
              if (e.key === 'Escape') setOmniSearchOpen(false);
            }}
          />
          {query && (
            <button
              onClick={() => setQuery('')}
              className="p-1 rounded text-slate-400 hover:text-white"
            >
              <X className="w-4 h-4" />
            </button>
          )}
          <kbd className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700">
            ESC
          </kbd>
        </div>

        {/* Results Body */}
        <div className="max-h-[60vh] overflow-y-auto p-4 space-y-4">
          {totalResults === 0 && (
            <div className="text-center py-12 text-slate-500">
              <p className="text-sm">No security artifacts matched "{query}"</p>
              <p className="text-xs mt-1">Try searching by IP (e.g. 203.0.113.42), human ID (e.g. CASE-01), or keyword (NGINX).</p>
            </div>
          )}

          {/* Incidents Section */}
          {filteredCases.length > 0 && (
            <div>
              <div className="flex items-center justify-between text-[11px] font-mono uppercase tracking-wider text-slate-400 mb-2 px-1">
                <span>Incidents / Cases ({filteredCases.length})</span>
              </div>
              <div className="space-y-1.5">
                {filteredCases.slice(0, 4).map(c => (
                  <div
                    key={c.humanId}
                    onClick={() => {
                      setOmniSearchOpen(false);
                      navigate('case-detail', c.humanId);
                    }}
                    className="flex items-center justify-between p-2.5 rounded-lg bg-slate-900/80 hover:bg-slate-800 border border-slate-800/80 hover:border-cyan-500/40 cursor-pointer group transition-all"
                  >
                    <div className="flex items-center gap-3">
                      <div className="p-1.5 rounded bg-slate-800 text-cyan-400 group-hover:bg-cyan-950">
                        <AlertCircle className="w-4 h-4" />
                      </div>
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="font-mono font-bold text-xs text-cyan-300">
                            {c.humanId}
                          </span>
                          <span className="text-xs font-semibold text-slate-200 group-hover:text-cyan-200">
                            {c.title}
                          </span>
                        </div>
                        <p className="text-[11px] text-slate-400 mt-0.5">
                          IP: {c.attackerIp} • Target: {c.targetAsset}
                        </p>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <SeverityBadge severity={c.severity} size="sm" />
                      <ArrowRight className="w-3.5 h-3.5 text-slate-500 group-hover:text-cyan-400 transition-colors" />
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Detections Section */}
          {filteredDetections.length > 0 && (
            <div>
              <div className="flex items-center justify-between text-[11px] font-mono uppercase tracking-wider text-slate-400 mb-2 px-1">
                <span>Detections ({filteredDetections.length})</span>
              </div>
              <div className="space-y-1.5">
                {filteredDetections.slice(0, 3).map(d => (
                  <div
                    key={d.humanId}
                    onClick={() => {
                      setOmniSearchOpen(false);
                      navigate('detections', d.humanId);
                    }}
                    className="flex items-center justify-between p-2 rounded-lg bg-slate-900/60 hover:bg-slate-800 border border-slate-800/80 hover:border-amber-500/40 cursor-pointer group transition-all"
                  >
                    <div className="flex items-center gap-2.5">
                      <Radio className="w-3.5 h-3.5 text-amber-400" />
                      <div>
                        <span className="font-mono font-bold text-xs text-amber-300 mr-2">
                          {d.humanId}
                        </span>
                        <span className="text-xs text-slate-300 group-hover:text-amber-200">
                          {d.title}
                        </span>
                      </div>
                    </div>
                    <SeverityBadge severity={d.severity} size="sm" />
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Correlations Section */}
          {filteredCorrelations.length > 0 && (
            <div>
              <div className="flex items-center justify-between text-[11px] font-mono uppercase tracking-wider text-slate-400 mb-2 px-1">
                <span>Correlations ({filteredCorrelations.length})</span>
              </div>
              <div className="space-y-1.5">
                {filteredCorrelations.slice(0, 2).map(corr => (
                  <div
                    key={corr.humanId}
                    onClick={() => {
                      setOmniSearchOpen(false);
                      navigate('correlations', corr.humanId);
                    }}
                    className="flex items-center justify-between p-2 rounded-lg bg-slate-900/60 hover:bg-slate-800 border border-slate-800/80 hover:border-purple-500/40 cursor-pointer group transition-all"
                  >
                    <div className="flex items-center gap-2.5">
                      <Network className="w-3.5 h-3.5 text-purple-400" />
                      <div>
                        <span className="font-mono font-bold text-xs text-purple-300 mr-2">
                          {corr.humanId}
                        </span>
                        <span className="text-xs text-slate-300 group-hover:text-purple-200">
                          {corr.title}
                        </span>
                      </div>
                    </div>
                    <span className="text-[10px] font-mono text-purple-400 px-1.5 py-0.5 rounded bg-purple-950/60 border border-purple-800">
                      {corr.confidenceScore}% Conf
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Sources & Rules */}
          {(filteredSources.length > 0 || filteredRules.length > 0) && (
            <div className="grid grid-cols-2 gap-3 pt-1">
              {filteredSources.length > 0 && (
                <div>
                  <div className="text-[11px] font-mono uppercase text-slate-400 mb-1.5">Sources</div>
                  {filteredSources.slice(0, 2).map(s => (
                    <div
                      key={s.humanId}
                      onClick={() => {
                        setOmniSearchOpen(false);
                        navigate('sources', s.humanId);
                      }}
                      className="p-2 rounded bg-slate-900/60 hover:bg-slate-800 border border-slate-800 cursor-pointer text-xs mb-1"
                    >
                      <span className="font-mono text-emerald-300 font-bold mr-1">{s.humanId}</span>
                      <span className="text-slate-300 truncate">{s.name}</span>
                    </div>
                  ))}
                </div>
              )}

              {filteredRules.length > 0 && (
                <div>
                  <div className="text-[11px] font-mono uppercase text-slate-400 mb-1.5">Rules</div>
                  {filteredRules.slice(0, 2).map(r => (
                    <div
                      key={r.humanId}
                      onClick={() => {
                        setOmniSearchOpen(false);
                        navigate('rules', r.humanId);
                      }}
                      className="p-2 rounded bg-slate-900/60 hover:bg-slate-800 border border-slate-800 cursor-pointer text-xs mb-1"
                    >
                      <span className="font-mono text-sky-300 font-bold mr-1">{r.humanId}</span>
                      <span className="text-slate-300 truncate">{r.name}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>

        {/* Footer shortcuts */}
        <div className="flex items-center justify-between px-4 py-2 border-t border-slate-800 bg-[#0A0D15] text-[11px] font-mono text-slate-500">
          <span>Navigate with ↑ ↓ • Select ↵</span>
          <span>ProShield OmniSearch v2.4</span>
        </div>
      </div>
    </div>
  );
};
