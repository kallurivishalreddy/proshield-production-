import React, { ReactNode } from 'react';

interface MetricCardProps {
  title: string;
  value: string | number;
  subtitle?: string;
  icon?: ReactNode;
  trend?: {
    value: string;
    isUp: boolean;
    isGood?: boolean;
  };
  highlight?: 'red' | 'amber' | 'cyan' | 'emerald' | 'purple' | 'slate';
  onClick?: () => void;
  active?: boolean;
  badgeText?: string;
}

export const MetricCard: React.FC<MetricCardProps> = ({
  title,
  value,
  subtitle,
  icon,
  trend,
  highlight = 'slate',
  onClick,
  active = false,
  badgeText
}) => {
  const getHighlightBorder = () => {
    if (active) return 'border-cyan-500 shadow-[0_0_15px_rgba(6,182,212,0.2)] ring-1 ring-cyan-500';
    switch (highlight) {
      case 'red': return 'hover:border-rose-500/50 hover:shadow-[0_0_15px_rgba(244,63,94,0.15)]';
      case 'amber': return 'hover:border-amber-500/50 hover:shadow-[0_0_15px_rgba(245,158,11,0.15)]';
      case 'cyan': return 'hover:border-cyan-500/50 hover:shadow-[0_0_15px_rgba(6,182,212,0.15)]';
      case 'emerald': return 'hover:border-emerald-500/50 hover:shadow-[0_0_15px_rgba(16,185,129,0.15)]';
      case 'purple': return 'hover:border-purple-500/50 hover:shadow-[0_0_15px_rgba(168,85,247,0.15)]';
      default: return 'hover:border-slate-600';
    }
  };

  const getAccentColor = () => {
    switch (highlight) {
      case 'red': return 'text-rose-400';
      case 'amber': return 'text-amber-400';
      case 'cyan': return 'text-cyan-400';
      case 'emerald': return 'text-emerald-400';
      case 'purple': return 'text-purple-400';
      default: return 'text-slate-400';
    }
  };

  return (
    <div
      onClick={onClick}
      className={`relative bg-[#111827]/80 backdrop-blur border border-slate-800 rounded-lg p-4 transition-all duration-200 ${
        onClick ? 'cursor-pointer' : ''
      } ${getHighlightBorder()}`}
    >
      <div className="flex items-center justify-between gap-2 mb-2">
        <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">
          {title}
        </span>
        {badgeText && (
          <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800 border border-slate-700 text-slate-300">
            {badgeText}
          </span>
        )}
        {icon && (
          <div className={`p-1.5 rounded-md bg-slate-800/80 ${getAccentColor()}`}>
            {icon}
          </div>
        )}
      </div>

      <div className="flex items-baseline justify-between mt-1">
        <div className="text-2xl font-bold font-mono text-slate-100 tracking-tight">
          {value}
        </div>
        {trend && (
          <div
            className={`text-xs font-medium font-mono flex items-center gap-0.5 ${
              trend.isGood !== undefined
                ? trend.isGood ? 'text-emerald-400' : 'text-rose-400'
                : trend.isUp ? 'text-rose-400' : 'text-emerald-400'
            }`}
          >
            <span>{trend.isUp ? '↑' : '↓'}</span>
            <span>{trend.value}</span>
          </div>
        )}
      </div>

      {subtitle && (
        <p className="mt-1.5 text-xs text-slate-400 line-clamp-1">
          {subtitle}
        </p>
      )}
    </div>
  );
};
