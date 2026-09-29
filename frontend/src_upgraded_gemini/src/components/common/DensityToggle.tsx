import React from 'react';
import { AlignJustify, List } from 'lucide-react';
import { useSoc } from '../../context/SocContext';

export const DensityToggle: React.FC = () => {
  const { tableDensity, setTableDensity } = useSoc();

  return (
    <div className="inline-flex items-center p-0.5 rounded-md bg-slate-900 border border-slate-800 text-xs">
      <button
        onClick={() => setTableDensity('comfortable')}
        className={`flex items-center gap-1.5 px-2 py-1 rounded transition-colors ${
          tableDensity === 'comfortable'
            ? 'bg-slate-800 text-cyan-300 font-medium shadow-sm'
            : 'text-slate-400 hover:text-slate-200'
        }`}
        title="Comfortable Density (Generous padding & metadata)"
      >
        <List className="w-3.5 h-3.5" />
        <span>Comfortable</span>
      </button>
      <button
        onClick={() => setTableDensity('compact')}
        className={`flex items-center gap-1.5 px-2 py-1 rounded transition-colors ${
          tableDensity === 'compact'
            ? 'bg-slate-800 text-cyan-300 font-medium shadow-sm'
            : 'text-slate-400 hover:text-slate-200'
        }`}
        title="Compact Density (High-density tabular scanning)"
      >
        <AlignJustify className="w-3.5 h-3.5" />
        <span>Compact</span>
      </button>
    </div>
  );
};
