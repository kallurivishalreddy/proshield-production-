import React, { useState } from 'react';
import { X, CheckCircle } from 'lucide-react';
import { useSoc } from '../../context/SocContext';
import { ResolutionReason } from '../../types/soc';

export const CloseCaseModal: React.FC = () => {
  const {
    isCloseCaseModalOpen,
    setCloseCaseModalOpen,
    selectedCaseId,
    cases,
    updateCaseStatus
  } = useSoc();

  const [reason, setReason] = useState<ResolutionReason>('TRUE_POSITIVE');
  const [notes, setNotes] = useState('');
  const [confirmed, setConfirmed] = useState(false);

  if (!isCloseCaseModalOpen) return null;

  const currentCase = cases.find(c => c.humanId === selectedCaseId);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!notes.trim()) return;

    updateCaseStatus(selectedCaseId, 'CLOSED', reason, notes);
    setCloseCaseModalOpen(false);
    setNotes('');
    setConfirmed(false);
  };

  const reasonsList: { value: ResolutionReason; label: string; desc: string }[] = [
    {
      value: 'TRUE_POSITIVE',
      label: 'True Positive (Malicious Activity Contained)',
      desc: 'Confirmed adversary action; mitigation / containment completed.'
    },
    {
      value: 'BENIGN_TRUE_POSITIVE',
      label: 'Benign True Positive (Authorized Admin / Tool)',
      desc: 'Legitimate authorized tool, pentest, or DevOps administrative action.'
    },
    {
      value: 'FALSE_POSITIVE',
      label: 'False Positive (Benign Traffic / Tuning Needed)',
      desc: 'Normal benign business traffic triggered detection threshold.'
    },
    {
      value: 'DUPLICATE',
      label: 'Duplicate Incident Record',
      desc: 'Evidence already tracked under an existing master case.'
    },
    {
      value: 'TEST_DRILL',
      label: 'SOC Simulation / Red Team Drill',
      desc: 'Scheduled cyber drill or automated attack simulation test.'
    }
  ];

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-sm animate-in fade-in duration-200">
      <div className="relative w-full max-w-lg rounded-xl bg-[#0F1420] border border-slate-700 shadow-2xl overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between p-4 border-b border-slate-800 bg-[#0A0D15]">
          <div className="flex items-center gap-2">
            <div className="p-1.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-500/30">
              <CheckCircle className="w-4 h-4" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-slate-100 font-mono">
                RESOLVE & CLOSE CASE {selectedCaseId}
              </h3>
              <p className="text-xs text-slate-400 truncate max-w-xs">
                {currentCase?.title}
              </p>
            </div>
          </div>
          <button
            onClick={() => setCloseCaseModalOpen(false)}
            className="p-1 rounded text-slate-400 hover:text-white"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Form */}
        <form onSubmit={handleSubmit} className="p-5 space-y-4 text-xs">
          {/* Reason Selection */}
          <div>
            <label className="block text-xs font-semibold text-slate-300 mb-2 font-mono uppercase tracking-wider">
              Resolution Classification *
            </label>
            <div className="space-y-2">
              {reasonsList.map(r => (
                <label
                  key={r.value}
                  className={`flex items-start gap-3 p-2.5 rounded-lg border cursor-pointer transition-all ${
                    reason === r.value
                      ? 'bg-cyan-950/40 border-cyan-500/60 text-cyan-200'
                      : 'bg-slate-900/60 border-slate-800 text-slate-300 hover:border-slate-700'
                  }`}
                >
                  <input
                    type="radio"
                    name="resolutionReason"
                    value={r.value}
                    checked={reason === r.value}
                    onChange={() => setReason(r.value)}
                    className="mt-0.5 text-cyan-500 focus:ring-cyan-400"
                  />
                  <div>
                    <div className="font-semibold text-slate-100">{r.label}</div>
                    <div className="text-[11px] text-slate-400">{r.desc}</div>
                  </div>
                </label>
              ))}
            </div>
          </div>

          {/* Justification Notes */}
          <div>
            <label className="block text-xs font-semibold text-slate-300 mb-1 font-mono uppercase tracking-wider">
              Closure Summary & Remediation Notes *
            </label>
            <textarea
              rows={3}
              required
              value={notes}
              onChange={e => setNotes(e.target.value)}
              placeholder="Explain how the threat was remediated, firewall rules applied, credential rotations done, or why it was deemed benign..."
              className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-cyan-500 font-sans text-xs"
            />
          </div>

          {/* Safeguard Confirmation */}
          <div className="p-3 rounded-lg bg-slate-900/90 border border-slate-800 flex items-start gap-2.5">
            <input
              type="checkbox"
              id="confirmCheck"
              checked={confirmed}
              onChange={e => setConfirmed(e.target.checked)}
              className="mt-0.5 rounded text-cyan-500 focus:ring-cyan-400"
            />
            <label htmlFor="confirmCheck" className="text-[11px] text-slate-400 cursor-pointer">
              I certify that all forensic evidence has been preserved and necessary containment actions have been logged into the incident audit trail.
            </label>
          </div>

          {/* Footer Actions */}
          <div className="flex items-center justify-end gap-2.5 pt-3 border-t border-slate-800">
            <button
              type="button"
              onClick={() => setCloseCaseModalOpen(false)}
              className="px-3.5 py-1.5 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800 font-mono transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={!confirmed || !notes.trim()}
              className="flex items-center gap-1.5 px-4 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 disabled:bg-slate-800 disabled:text-slate-600 text-white font-mono font-bold transition-colors shadow-[0_0_12px_rgba(16,185,129,0.3)]"
            >
              <CheckCircle className="w-3.5 h-3.5" />
              <span>Confirm Case Closure</span>
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
