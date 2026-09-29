import React, { useState } from 'react';
import { Compass, Send } from 'lucide-react';
import { useSoc } from '../../context/SocContext';

/**
 * 5.9 Future ProShield Guide shell.
 *
 * The Guide is a future helper, not an autonomous operator. This panel
 * explains the current workflow context and offers only static next-step
 * suggestions. It performs no backend actions and makes no security
 * decisions.
 */
export const GuidePage: React.FC = () => {
  const { currentPage, selectedCaseId, cases } = useSoc();
  const [input, setInput] = useState('');
  const [messages, setMessages] = useState<{ role: 'guide' | 'analyst'; text: string }[]>([
    { role: 'guide', text: 'I am a future helper preview. I can explain the current page, but I cannot change cases, sources, rules, evidence, or datasets.' },
  ]);

  const send = (e: React.FormEvent) => {
    e.preventDefault();
    const text = input.trim();
    if (!text) return;
    setMessages((prev) => [
      ...prev,
      { role: 'analyst', text },
      {
        role: 'guide',
        text: 'Preview response: I do not have backend Guide intelligence yet. For this workflow, review the linked evidence and keep the analyst as the final authority.',
      },
    ]);
    setInput('');
  };

  return (
    <div className="space-y-5 pb-12">
      <div className="pb-2 border-b border-slate-800">
        <div className="flex flex-wrap items-center gap-2">
          <h1 className="text-lg font-semibold tracking-tight text-slate-100">ProShield Guide</h1>
          <span className="text-[11px] font-mono px-2 py-0.5 rounded-full bg-amber-950 text-amber-300 border border-amber-800">Coming Soon</span>
          <span className="text-[11px] font-mono px-2 py-0.5 rounded-full bg-slate-800 text-slate-400 border border-slate-700">Helper preview only</span>
        </div>
        <p className="text-xs text-slate-400 mt-1 max-w-3xl">
          Current context: <span className="font-mono text-slate-300">{currentPage}</span>
          {selectedCaseId ? <span className="font-mono text-slate-300"> · {selectedCaseId}</span> : null}
          {` · ${cases.length} cases loaded`}. The Guide never overrides analyst authority.
        </p>
      </div>

      <section aria-label="Guide conversation preview" className="rounded-xl bg-[#0F1420] border border-slate-800 overflow-hidden">
        <div className="p-3 border-b border-slate-800 flex items-center gap-2 text-xs font-mono text-slate-300">
          <Compass className="w-4 h-4 text-slate-400" /> Contextual help preview
        </div>
        <div className="p-4 space-y-3 max-h-[420px] overflow-y-auto">
          {messages.map((m, i) => (
            <div key={i} className={`max-w-[80%] p-2.5 rounded-lg text-xs ${m.role === 'guide' ? 'bg-slate-900 border border-slate-800 text-slate-200' : 'bg-slate-800 text-slate-100 ml-auto'}`}>
              {m.text}
            </div>
          ))}
        </div>
        <form onSubmit={send} className="p-3 border-t border-slate-800 flex gap-2">
          <input
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="Ask for workflow help (preview only, no backend call)..."
            aria-label="Ask the Guide"
            className="flex-1 px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-xs text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-slate-500"
          />
          <button type="submit" className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs font-mono">
            <Send className="w-3.5 h-3.5" /> Send
          </button>
        </form>
      </section>
    </div>
  );
};
