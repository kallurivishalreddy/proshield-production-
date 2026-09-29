import React, { useState } from 'react';
import { Shield, Lock } from 'lucide-react';
import { useSoc } from '../context/SocContext';

/**
 * Real login gate backed by the backend `auth.issue` operation.
 * No demo bypass: only genuine backend-issued session tokens open the app.
 */
export const LoginGate: React.FC = () => {
  const { login, bootError, bootState } = useSoc();
  const [subject, setSubject] = useState('');
  const [credential, setCredential] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!subject.trim() || !credential) return;
    setBusy(true);
    setError(null);
    const r = await login(subject.trim(), credential);
    if (!r.ok) setError(r.error || 'Sign-in failed.');
    setBusy(false);
  };

  return (
    <div className="flex items-center justify-center min-h-screen w-full bg-[#0B0F17] px-4">
      <div className="w-full max-w-md">
        <div className="rounded-xl bg-[#0F1420] border border-slate-800 shadow-2xl overflow-hidden">
          <div className="flex items-center gap-2.5 p-5 border-b border-slate-800 bg-[#0A0D15]">
            <div className="p-2 rounded-lg bg-gradient-to-br from-cyan-500 to-blue-600 text-slate-950">
              <Shield className="w-5 h-5" />
            </div>
            <div>
              <div className="text-base font-bold text-slate-100 font-mono tracking-tight">PROSHIELD</div>
              <div className="text-[11px] text-slate-500 font-mono">Security Intelligence Engine — Analyst Console</div>
            </div>
          </div>

          <form onSubmit={handleSubmit} className="p-5 space-y-4 text-xs">
            {bootError && (
              <div className="p-2.5 rounded-lg bg-rose-950/40 border border-rose-500/40 text-rose-300 font-mono">
                Backend error: {bootError}
              </div>
            )}
            <div>
              <label htmlFor="subject" className="block text-[11px] font-semibold text-slate-300 mb-1 font-mono uppercase tracking-wider">
                Subject ID
              </label>
              <input
                id="subject"
                name="subject"
                autoComplete="username"
                placeholder="analyst / admin / collector"
                value={subject}
                onChange={e => setSubject(e.target.value)}
                required
                className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-slate-100 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500 font-mono"
              />
            </div>
            <div>
              <label htmlFor="credential" className="block text-[11px] font-semibold text-slate-300 mb-1 font-mono uppercase tracking-wider">
                Credential
              </label>
              <input
                id="credential"
                name="credential"
                type="password"
                autoComplete="current-password"
                value={credential}
                onChange={e => setCredential(e.target.value)}
                required
                className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-slate-100 focus:outline-none focus:border-cyan-500 font-mono"
              />
            </div>
            {error && (
              <div className="p-2.5 rounded-lg bg-rose-950/40 border border-rose-500/40 text-rose-300 font-mono" role="alert">
                {error}
              </div>
            )}
            <button
              type="submit"
              disabled={busy || bootState === 'loading'}
              className="w-full flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:bg-slate-800 disabled:text-slate-600 text-white font-mono font-bold transition-colors shadow-[0_0_12px_rgba(6,182,212,0.25)]"
            >
              <Lock className="w-3.5 h-3.5" />
              <span>{busy ? 'Authenticating…' : 'Sign in'}</span>
            </button>
            <p className="text-[10px] text-slate-500 font-mono leading-relaxed">
              Authentication uses the real <code className="text-slate-400">auth.issue</code> operation on
              the SecureProxy wire boundary. Sessions are verified on every request.
            </p>
          </form>
        </div>
      </div>
    </div>
  );
};
