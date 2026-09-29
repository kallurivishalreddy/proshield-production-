import React from 'react';
import { CaseStatus, ResolutionReason } from '../../types/soc';

interface StatusBadgeProps {
  status: CaseStatus | 'ENABLED' | 'DISABLED' | 'ERROR' | 'RETIRED' | 'ACTIVE' | 'TESTING';
  resolutionReason?: ResolutionReason;
  size?: 'sm' | 'md' | 'lg';
  className?: string;
}

export const StatusBadge: React.FC<StatusBadgeProps> = ({
  status,
  resolutionReason,
  size = 'md',
  className = ''
}) => {
  const getStyles = () => {
    switch (status) {
      case 'OPEN':
        return {
          bg: 'bg-indigo-500/15 border-indigo-500/40 text-indigo-300',
          label: 'OPEN',
          dot: 'bg-indigo-400'
        };
      case 'ACKNOWLEDGED':
        return {
          bg: 'bg-blue-500/15 border-blue-500/40 text-blue-300',
          label: 'ACKNOWLEDGED',
          dot: 'bg-blue-400'
        };
      case 'INVESTIGATING':
        return {
          bg: 'bg-cyan-500/15 border-cyan-500/40 text-cyan-300 shadow-[0_0_12px_rgba(6,182,212,0.15)]',
          label: 'INVESTIGATING',
          dot: 'bg-cyan-400 animate-pulse'
        };
      case 'CLOSED':
        return {
          bg: 'bg-emerald-500/15 border-emerald-500/40 text-emerald-300',
          label: 'CLOSED',
          dot: 'bg-emerald-400'
        };
      case 'ENABLED':
      case 'ACTIVE':
        return {
          bg: 'bg-emerald-500/15 border-emerald-500/40 text-emerald-300',
          label: status,
          dot: 'bg-emerald-400'
        };
      case 'DISABLED':
        return {
          bg: 'bg-slate-700/30 border-slate-600/40 text-slate-400',
          label: 'DISABLED',
          dot: 'bg-slate-500'
        };
      case 'TESTING':
        return {
          bg: 'bg-purple-500/15 border-purple-500/40 text-purple-300',
          label: 'TESTING',
          dot: 'bg-purple-400'
        };
      case 'RETIRED':
        return {
          bg: 'bg-zinc-800/60 border-zinc-700 text-zinc-500',
          label: 'RETIRED',
          dot: 'bg-zinc-600'
        };
      case 'ERROR':
        return {
          bg: 'bg-rose-500/20 border-rose-500/50 text-rose-300',
          label: 'ERROR',
          dot: 'bg-rose-500 animate-pulse'
        };
      default:
        return {
          bg: 'bg-slate-700/30 border-slate-600/40 text-slate-300',
          label: status,
          dot: 'bg-slate-400'
        };
    }
  };

  const sizeStyles = {
    sm: 'text-[10px] px-1.5 py-0.5 tracking-wider font-semibold font-mono',
    md: 'text-xs px-2 py-0.5 tracking-wider font-semibold font-mono',
    lg: 'text-sm px-2.5 py-1 tracking-wider font-bold font-mono'
  };

  const style = getStyles();

  const formatReason = (reason: ResolutionReason) => {
    switch (reason) {
      case 'TRUE_POSITIVE': return 'True Positive';
      case 'BENIGN_TRUE_POSITIVE': return 'Benign TP';
      case 'FALSE_POSITIVE': return 'False Positive';
      case 'DUPLICATE': return 'Duplicate';
      case 'TEST_DRILL': return 'Test Drill';
      default: return reason;
    }
  };

  return (
    <div className="inline-flex items-center gap-1.5">
      <span
        className={`inline-flex items-center gap-1.5 rounded border ${style.bg} ${sizeStyles[size]} ${className}`}
      >
        <span className={`w-1.5 h-1.5 rounded-full ${style.dot}`} />
        <span>{style.label}</span>
      </span>
      {status === 'CLOSED' && resolutionReason && (
        <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 border border-slate-700 text-slate-300 font-mono">
          {formatReason(resolutionReason)}
        </span>
      )}
    </div>
  );
};
