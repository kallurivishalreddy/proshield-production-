import { SocProvider, useSoc } from './context/SocContext';
import { Shell } from './components/layout/Shell';
import { LoginGate } from './components/LoginGate';

function Gate() {
  const { bootState } = useSoc();
  if (bootState === 'anon' || bootState === 'error') {
    return <LoginGate />;
  }
  if (bootState === 'loading') {
    return (
      <div className="flex items-center justify-center min-h-screen w-full bg-[#0B0F17]">
        <div className="text-center space-y-3">
          <div className="w-8 h-8 mx-auto rounded-full border-2 border-cyan-500 border-t-transparent animate-spin" />
          <p className="text-xs font-mono text-slate-400">
            {bootState === 'loading' ? 'Restoring session and loading real backend data…' : ''}
          </p>
        </div>
      </div>
    );
  }
  return <Shell />;
}

export function App() {
  return (
    <SocProvider>
      <Gate />
    </SocProvider>
  );
}

export default App;
