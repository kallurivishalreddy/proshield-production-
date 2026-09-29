import React from 'react';
import { useSoc } from '../../context/SocContext';
import { AlertTriangle, CheckCircle, Info, XCircle, X } from 'lucide-react';

export const ToastContainer: React.FC = () => {
  const { toasts, removeToast } = useSoc();

  if (toasts.length === 0) return null;

  const getIcon = (type: string) => {
    switch (type) {
      case 'success':
        return <CheckCircle className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />;
      case 'warning':
        return <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />;
      case 'error':
        return <XCircle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />;
      case 'info':
      default:
        return <Info className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />;
    }
  };

  const getBorder = (type: string) => {
    switch (type) {
      case 'success': return 'border-emerald-500/40 bg-[#0B1516]/95';
      case 'warning': return 'border-amber-500/40 bg-[#16120B]/95';
      case 'error': return 'border-rose-500/40 bg-[#170B0E]/95';
      case 'info':
      default: return 'border-cyan-500/40 bg-[#0B121A]/95';
    }
  };

  return (
    <div className="fixed bottom-5 right-5 z-50 flex flex-col gap-2.5 max-w-sm w-full pointer-events-none">
      {toasts.map(toast => (
        <div
          key={toast.id}
          className={`pointer-events-auto flex items-start justify-between gap-3 p-3.5 rounded-lg border shadow-2xl backdrop-blur-md transition-all duration-300 transform translate-y-0 ${getBorder(
            toast.type
          )}`}
        >
          <div className="flex items-start gap-2.5">
            {getIcon(toast.type)}
            <div>
              <h4 className="text-xs font-bold text-slate-100 tracking-wide">
                {toast.title}
              </h4>
              <p className="text-xs text-slate-300 mt-0.5 leading-relaxed">
                {toast.message}
              </p>
            </div>
          </div>
          <button
            onClick={() => removeToast(toast.id)}
            className="text-slate-400 hover:text-white transition-colors p-0.5 rounded hover:bg-slate-800"
          >
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      ))}
    </div>
  );
};
