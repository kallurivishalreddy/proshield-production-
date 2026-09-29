import React from 'react';
import { BookOpen, FlaskConical, Save, Upload } from 'lucide-react';

/**
 * 5.3 Future Learning Application shell.
 *
 * Explicitly future/HOLD functionality. No learning backend exists, no lab
 * execution occurs here, and no production security data is used for
 * training. This is a static workflow preview only.
 */
export const LearningPage: React.FC = () => (
  <div className="space-y-5 pb-12">
    <div className="pb-2 border-b border-slate-800">
      <div className="flex flex-wrap items-center gap-2">
        <h1 className="text-lg font-semibold tracking-tight text-slate-100">Learning Lab</h1>
        <span className="text-[11px] font-mono px-2 py-0.5 rounded-full bg-amber-950 text-amber-300 border border-amber-800">Coming Soon</span>
        <span className="text-[11px] font-mono px-2 py-0.5 rounded-full bg-slate-800 text-slate-400 border border-slate-700">Not Connected</span>
      </div>
      <p className="text-xs text-slate-400 mt-1 max-w-3xl">
        Future Blue Team learning workspace. It will use ProShield as a scoped security backend when implemented.
        Nothing on this page runs labs, saves learner progress to a backend, or affects production cases.
      </p>
    </div>

    <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
      {[
        { title: 'Current exercise', body: 'Example: investigate a staged brute-force login pattern in an isolated lab tenant.' },
        { title: 'Lab status', body: 'Preview states: Not started, In progress, Completed, Needs review.' },
        { title: 'Evidence observed', body: 'Learner-visible detections and timeline excerpts only; production evidence stays separate.' },
      ].map((c) => (
        <section key={c.title} className="p-4 rounded-xl bg-[#0F1420] border border-slate-800">
          <h2 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
            <FlaskConical className="w-4 h-4 text-slate-400" /> {c.title}
          </h2>
          <p className="text-xs text-slate-400 mt-1">{c.body}</p>
        </section>
      ))}
    </div>

    <div className="flex flex-wrap gap-2">
      {[
        { label: 'Save progress (Future)', icon: Save },
        { label: 'Import progress (Future)', icon: Upload },
        { label: 'Open Guide (Future)', icon: BookOpen },
      ].map(({ label, icon: Icon }) => (
        <button
          key={label}
          type="button"
          disabled
          title="Future learning backend capability"
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 text-slate-500 border border-slate-800 text-xs font-mono cursor-not-allowed"
        >
          <Icon className="w-3.5 h-3.5" /> {label}
        </button>
      ))}
    </div>
  </div>
);
