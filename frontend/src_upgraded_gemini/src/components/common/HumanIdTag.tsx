import React, { useState } from 'react';
import { Copy, Check, ExternalLink } from 'lucide-react';
import { useSoc, PageId } from '../../context/SocContext';

interface HumanIdTagProps {
  humanId: string;
  internalUuid?: string;
  type?: 'case' | 'detection' | 'correlation' | 'source' | 'rule' | 'report' | 'generic';
  showCopy?: boolean;
  clickable?: boolean;
  size?: 'sm' | 'md' | 'lg';
  className?: string;
}

export const HumanIdTag: React.FC<HumanIdTagProps> = ({
  humanId,
  internalUuid,
  showCopy = true,
  clickable = true,
  size = 'md',
  className = ''
}) => {
  const { navigate, addToast } = useSoc();
  const [copied, setCopied] = useState(false);

  const handleCopy = (e: React.MouseEvent) => {
    e.stopPropagation();
    const textToCopy = internalUuid || humanId;
    navigator.clipboard.writeText(textToCopy);
    setCopied(true);
    addToast('info', 'ID Copied', `Copied ${internalUuid ? 'technical UUID' : 'identifier'}: ${textToCopy}`);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleClick = (e: React.MouseEvent) => {
    if (!clickable) return;
    e.stopPropagation();

    if (humanId.startsWith('CASE-')) {
      navigate('case-detail' as PageId, humanId);
    } else if (humanId.startsWith('DET-')) {
      navigate('detections' as PageId, humanId);
    } else if (humanId.startsWith('CORR-')) {
      navigate('correlations' as PageId, humanId);
    } else if (humanId.startsWith('SRC-')) {
      navigate('sources' as PageId, humanId);
    } else if (humanId.startsWith('RULE-')) {
      navigate('rules' as PageId, humanId);
    }
  };

  const getTypeColor = () => {
    if (humanId.startsWith('CASE-')) return 'text-cyan-300 border-cyan-500/30 bg-cyan-950/40 hover:border-cyan-400/60';
    if (humanId.startsWith('DET-')) return 'text-amber-300 border-amber-500/30 bg-amber-950/40 hover:border-amber-400/60';
    if (humanId.startsWith('CORR-')) return 'text-purple-300 border-purple-500/30 bg-purple-950/40 hover:border-purple-400/60';
    if (humanId.startsWith('SRC-')) return 'text-emerald-300 border-emerald-500/30 bg-emerald-950/40 hover:border-emerald-400/60';
    if (humanId.startsWith('RULE-')) return 'text-sky-300 border-sky-500/30 bg-sky-950/40 hover:border-sky-400/60';
    if (humanId.startsWith('REPORT-')) return 'text-indigo-300 border-indigo-500/30 bg-indigo-950/40 hover:border-indigo-400/60';
    return 'text-slate-300 border-slate-700 bg-slate-800 hover:border-slate-600';
  };

  const sizeClasses = {
    sm: 'text-[11px] px-1.5 py-0.5 gap-1',
    md: 'text-xs px-2 py-0.5 gap-1.5',
    lg: 'text-sm px-2.5 py-1 gap-2'
  };

  return (
    <div
      onClick={handleClick}
      className={`group relative inline-flex items-center font-mono font-bold rounded border transition-colors ${getTypeColor()} ${sizeClasses[size]} ${
        clickable ? 'cursor-pointer hover:shadow-[0_0_10px_rgba(6,182,212,0.15)]' : ''
      } ${className}`}
      title={internalUuid ? `Technical UUID: ${internalUuid} (Click to open, hover for copy)` : humanId}
    >
      <span>{humanId}</span>

      {showCopy && (
        <button
          onClick={handleCopy}
          aria-label="Copy identifier"
          className="p-0.5 rounded text-slate-400 hover:text-white hover:bg-slate-700/50 transition-colors opacity-70 group-hover:opacity-100"
        >
          {copied ? (
            <Check className="w-3 h-3 text-emerald-400" />
          ) : (
            <Copy className="w-3 h-3" />
          )}
        </button>
      )}

      {clickable && (
        <ExternalLink className="w-2.5 h-2.5 opacity-0 group-hover:opacity-60 transition-opacity" />
      )}
    </div>
  );
};
