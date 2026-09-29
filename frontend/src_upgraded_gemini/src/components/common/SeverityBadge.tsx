import React from 'react';
import { Severity } from '../../types/soc';

interface SeverityBadgeProps {
  severity: Severity | null;
  size?: 'sm' | 'md' | 'lg';
  showDot?: boolean;
  className?: string;
}

export const SeverityBadge: React.FC<SeverityBadgeProps> = ({
  severity,
  size = 'md',
  showDot = true,
  className = ''
}) => {
  const getStyles = () => {
    switch (severity) {
      case 'CRITICAL':
        return {
          bg: 'bg-rose-950/60 border-slate-700 text-rose-200',
          dot: 'bg-rose-400'
        };
      case 'HIGH':
        return {
          bg: 'bg-amber-950/50 border-slate-700 text-amber-200',
          dot: 'bg-amber-400'
        };
      case 'MEDIUM':
        return {
          bg: 'bg-slate-800 border-slate-700 text-amber-100',
          dot: 'bg-amber-200'
        };
      case 'LOW':
        return {
          bg: 'bg-slate-800 border-slate-700 text-slate-200',
          dot: 'bg-slate-300'
        };
      case 'INFORMATIONAL':
      default:
        return {
          bg: 'bg-slate-700/30 border-slate-600/40 text-slate-300',
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

  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded border ${style.bg} ${sizeStyles[size]} ${className}`}
    >
      {showDot && <span className={`w-1.5 h-1.5 rounded-full ${style.dot}`} />}
      <span>{severity ?? 'UNRATED'}</span>
    </span>
  );
};
