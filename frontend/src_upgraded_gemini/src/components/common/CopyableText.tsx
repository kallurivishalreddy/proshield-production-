import React, { useState } from 'react';
import { Copy, Check } from 'lucide-react';
import { useSoc } from '../../context/SocContext';

interface CopyableTextProps {
  text: string;
  label?: string;
  truncate?: boolean;
  truncateLength?: number;
  isSecret?: boolean;
  className?: string;
}

export const CopyableText: React.FC<CopyableTextProps> = ({
  text,
  label,
  truncate = false,
  truncateLength = 24,
  isSecret = false,
  className = ''
}) => {
  const { addToast } = useSoc();
  const [copied, setCopied] = useState(false);

  const handleCopy = (e: React.MouseEvent) => {
    e.stopPropagation();
    navigator.clipboard.writeText(text);
    setCopied(true);
    addToast('info', 'Copied', `Copied ${label || 'value'} to clipboard.`);
    setTimeout(() => setCopied(false), 2000);
  };

  const displayText = isSecret
    ? '••••••••••••••••••••' + text.substring(text.length - 4)
    : truncate && text.length > truncateLength
    ? text.substring(0, truncateLength) + '...'
    : text;

  return (
    <span
      onClick={handleCopy}
      className={`inline-flex items-center gap-1.5 px-1.5 py-0.5 rounded bg-slate-800/80 hover:bg-slate-700 border border-slate-700/60 font-mono text-xs text-slate-200 cursor-pointer transition-colors group ${className}`}
      title={`Click to copy: ${text}`}
    >
      <span className="truncate">{displayText}</span>
      <span className="text-slate-400 group-hover:text-cyan-300 transition-colors">
        {copied ? (
          <Check className="w-3 h-3 text-emerald-400" />
        ) : (
          <Copy className="w-3 h-3" />
        )}
      </span>
    </span>
  );
};
