import React, { useState } from 'react';
import {
  Maximize2,
  Minimize2,
  Box,
  Layers,
  Shield,
  Radio,
  Server,
  User,
  ExternalLink,
  Info
} from 'lucide-react';
import { useSoc } from '../../context/SocContext';
import { Case } from '../../types/soc';
import { formatIstTimestamp } from '../../utils/format';

interface AttackGraphProps {
  currentCase: Case;
}

interface GraphNode {
  id: string;
  label: string;
  sublabel: string;
  type: 'attacker' | 'ingress' | 'detection' | 'correlation' | 'target';
  x2d: number;
  y2d: number;
  x3d: number;
  y3d: number;
  status: 'critical' | 'high' | 'warning' | 'info';
  details: Record<string, string>;
}

export const AttackGraphTopology: React.FC<AttackGraphProps> = ({ currentCase }) => {
  const { openPayloadDrawer, detections, correlations } = useSoc();
  const [viewMode, setViewMode] = useState<'2D' | '3D'>('2D');
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>('node-attacker');
  const [isExpanded, setIsExpanded] = useState(false);

  // ALL node attributes below come from REAL backend data loaded in
  // context (case evidence, detection list, correlation list). Where the
  // backend does not supply a value the inspector says so explicitly —
  // no invented ASN / reputation / confidence values.
  const caseDetections = detections.filter(d => d.caseId === currentCase.humanId);
  const ruleCounts = new Map<string, number>();
  for (const d of caseDetections) {
    ruleCounts.set(d.ruleId, (ruleCounts.get(d.ruleId) || 0) + 1);
  }
  const ruleSummary = Array.from(ruleCounts.entries())
    .sort((a, b) => b[1] - a[1])
    .map(([rid, n]) => `${rid} ×${n}`)
    .join(', ') || '—';
  const caseCorrelations = correlations.filter(c => c.caseId === currentCase.humanId);
  const primaryCorr = caseCorrelations[0];

  const nodes: GraphNode[] = [
    {
      id: 'node-attacker',
      label: currentCase.attackerIp || 'Attacker not attributed',
      sublabel: currentCase.attackerCountry || 'derived from correlation key',
      type: 'attacker',
      x2d: 80,
      y2d: 150,
      x3d: 90,
      y3d: 220,
      status: 'critical',
      details: {
        'IP Address': currentCase.attackerIp || 'not attributed by backend',
        'Origin': 'correlation key evidence (backend)',
        'Geo / ASN / Reputation': 'not available from backend'
      }
    },
    {
      id: 'node-ingress',
      label: currentCase.sourceName || 'Ingest source',
      sublabel: currentCase.sourceId || 'attribution not available',
      type: 'ingress',
      x2d: 260,
      y2d: 150,
      x3d: 250,
      y3d: 170,
      status: 'high',
      details: {
        'Source Attribution': currentCase.sourceId
          ? `${currentCase.sourceId} (${currentCase.sourceName})`
          : 'not available from backend (documented gap)',
        'Underlying Events': `${currentCase.eventCount} persisted event(s)`
      }
    },
    {
      id: 'node-detection',
      label: `${currentCase.detectionCount} Detections Triggered`,
      sublabel: ruleSummary,
      type: 'detection',
      x2d: 460,
      y2d: 80,
      x3d: 420,
      y3d: 110,
      status: 'high',
      details: {
        'Rules Matched (real)': ruleSummary,
        'First Match': formatIstTimestamp(caseDetections.length
          ? caseDetections.map(d => d.timestamp).sort()[0]
          : currentCase.firstSeen),
        'Last Match': formatIstTimestamp(caseDetections.length
          ? caseDetections.map(d => d.timestamp).sort().slice(-1)[0]
          : currentCase.lastSeen),
        'Severity': 'not composed per-detection by backend'
      }
    },
    {
      id: 'node-correlation',
      label: primaryCorr
        ? `${primaryCorr.humanId} Cluster Synthesized`
        : 'No correlation bound',
      sublabel: primaryCorr ? primaryCorr.pattern : '—',
      type: 'correlation',
      x2d: 460,
      y2d: 220,
      x3d: 440,
      y3d: 250,
      status: 'critical',
      details: primaryCorr
        ? {
            'Correlation ID': `${primaryCorr.humanId} (${primaryCorr.internalUuid})`,
            'Pattern (backend)': primaryCorr.pattern,
            'Key (real)': `${primaryCorr.attacker} → ${primaryCorr.target}`,
            'Linked Detections': primaryCorr.detectionIds.join(', ') || '—',
            'Confidence Score': 'not exposed by backend'
          }
        : {
            'Correlation ID': 'none bound to this case',
            'Pattern (backend)': '—'
          }
    },
    {
      id: 'node-target',
      label: currentCase.targetAsset || 'Target not attributed',
      sublabel: currentCase.targetUser || 'from correlation key',
      type: 'target',
      x2d: 660,
      y2d: 150,
      x3d: 620,
      y3d: 180,
      status: 'critical',
      details: {
        'Target Asset': currentCase.targetAsset || 'not attributed by backend',
        'Target Accounts': currentCase.targetUser || 'not available from backend',
        'Compromise Status': 'not available from backend'
      }
    }
  ];

  const edges = [
    { from: 'node-attacker', to: 'node-ingress', label: 'Ingress stream' },
    { from: 'node-ingress', to: 'node-detection', label: 'Rule evaluation' },
    { from: 'node-ingress', to: 'node-correlation', label: 'Window clustering' },
    { from: 'node-detection', to: 'node-target', label: 'Evidence reference' },
    { from: 'node-correlation', to: 'node-target', label: 'Key convergence' }
  ];

  const selectedNode = nodes.find(n => n.id === selectedNodeId) || nodes[0];

  const getNodeColor = (status: string) => {
    switch (status) {
      case 'critical': return { bg: '#2A0E17', stroke: '#EF4444', text: '#FCA5A5' };
      case 'high': return { bg: '#2A180E', stroke: '#F97316', text: '#FDBA74' };
      case 'warning': return { bg: '#28240D', stroke: '#EAB308', text: '#FDE047' };
      default: return { bg: '#0A202A', stroke: '#06B6D4', text: '#67E8F9' };
    }
  };

  return (
    <div className={`relative bg-[#090D14] border border-slate-800 rounded-xl overflow-hidden flex flex-col ${
      isExpanded ? 'fixed inset-4 z-50 shadow-2xl' : 'h-[440px]'
    }`}>
      {/* Topology Header Controls */}
      <div className="flex items-center justify-between p-3 border-b border-slate-800/80 bg-[#06090F]/90">
        <div className="flex items-center gap-2">
          <div className="p-1 rounded bg-cyan-950 text-cyan-400 border border-cyan-500/30">
            <Layers className="w-3.5 h-3.5" />
          </div>
          <span className="text-xs font-bold font-mono text-slate-200">
            INCIDENT ATTACK TOPOLOGY & EVIDENCE GRAPH
          </span>
          <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-slate-800 text-slate-400">
            5 Nodes • 5 Vectors
          </span>
        </div>

        <div className="flex items-center gap-2">
          {/* 2D vs 3D Isometric View Mode Toggle */}
          <div className="flex items-center rounded bg-slate-900 border border-slate-800 p-0.5 text-xs font-mono">
            <button
              onClick={() => setViewMode('2D')}
              className={`flex items-center gap-1 px-2 py-0.5 rounded transition-colors ${
                viewMode === '2D' ? 'bg-slate-800 text-cyan-300 font-bold' : 'text-slate-400 hover:text-slate-200'
              }`}
              title="2D Planar Forensic Schematic"
            >
              <Layers className="w-3 h-3" />
              <span>2D Schematic</span>
            </button>
            <button
              onClick={() => setViewMode('3D')}
              className={`flex items-center gap-1 px-2 py-0.5 rounded transition-colors ${
                viewMode === '3D' ? 'bg-slate-800 text-cyan-300 font-bold' : 'text-slate-400 hover:text-slate-200'
              }`}
              title="3D Isometric Topology Projection"
            >
              <Box className="w-3 h-3 text-cyan-400" />
              <span>3D Isometric</span>
            </button>
          </div>

          <button
            onClick={() => setIsExpanded(!isExpanded)}
            className="p-1.5 rounded text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
            title={isExpanded ? 'Collapse view' : 'Expand full screen'}
          >
            {isExpanded ? <Minimize2 className="w-4 h-4" /> : <Maximize2 className="w-4 h-4" />}
          </button>
        </div>
      </div>

      {/* Main Canvas Area */}
      <div className="flex-1 relative flex overflow-hidden">
        {/* SVG Interactive Canvas */}
        <div className="flex-1 relative bg-[radial-gradient(#1e293b_1px,transparent_1px)] [background-size:24px_24px] bg-[#070A10]">
          <svg className="w-full h-full min-h-[340px]" viewBox="0 0 760 300">
            <defs>
              <linearGradient id="edgeGrad" x1="0%" y1="0%" x2="100%" y2="0%">
                <stop offset="0%" stopColor="#EF4444" stopOpacity="0.8" />
                <stop offset="50%" stopColor="#06B6D4" stopOpacity="0.8" />
                <stop offset="100%" stopColor="#EAB308" stopOpacity="0.8" />
              </linearGradient>
              <filter id="glow" x="-20%" y="-20%" width="140%" height="140%">
                <feGaussianBlur stdDeviation="3" result="blur" />
                <feComposite in="SourceGraphic" in2="blur" operator="over" />
              </filter>
            </defs>

            {/* Render Edges */}
            {edges.map((edge, idx) => {
              const sourceNode = nodes.find(n => n.id === edge.from)!;
              const targetNode = nodes.find(n => n.id === edge.to)!;
              const sx = viewMode === '2D' ? sourceNode.x2d : sourceNode.x3d;
              const sy = viewMode === '2D' ? sourceNode.y2d : sourceNode.y3d;
              const tx = viewMode === '2D' ? targetNode.x2d : targetNode.x3d;
              const ty = viewMode === '2D' ? targetNode.y2d : targetNode.y3d;

              // Curved bezier
              const mx = (sx + tx) / 2;
              const my = (sy + ty) / 2 - (viewMode === '3D' ? 15 : 0);

              return (
                <g key={idx}>
                  <path
                    d={`M ${sx} ${sy} Q ${mx} ${my} ${tx} ${ty}`}
                    fill="none"
                    stroke="#1E293B"
                    strokeWidth="3"
                  />
                  <path
                    d={`M ${sx} ${sy} Q ${mx} ${my} ${tx} ${ty}`}
                    fill="none"
                    stroke="url(#edgeGrad)"
                    strokeWidth="1.5"
                    strokeDasharray="4,4"
                    className="animate-pulse"
                  />
                  {/* Moving packet dot */}
                  <circle r="3" fill="#06B6D4">
                    <animateMotion
                      path={`M ${sx} ${sy} Q ${mx} ${my} ${tx} ${ty}`}
                      dur="3s"
                      repeatCount="indefinite"
                    />
                  </circle>
                </g>
              );
            })}

            {/* Render Nodes */}
            {nodes.map(node => {
              const x = viewMode === '2D' ? node.x2d : node.x3d;
              const y = viewMode === '2D' ? node.y2d : node.y3d;
              const isSelected = selectedNodeId === node.id;
              const style = getNodeColor(node.status);

              return (
                <g
                  key={node.id}
                  transform={`translate(${x}, ${y})`}
                  className="cursor-pointer transition-transform hover:scale-105"
                  onClick={() => setSelectedNodeId(node.id)}
                >
                  {/* 3D isometric base layer */}
                  {viewMode === '3D' && (
                    <polygon
                      points="-35,10 0,25 35,10 0,-5"
                      fill="#0B132B"
                      stroke="#1E293B"
                      strokeWidth="1"
                    />
                  )}

                  {/* Node Background Glow */}
                  {isSelected && (
                    <circle
                      r="26"
                      fill={style.stroke}
                      opacity="0.25"
                      filter="url(#glow)"
                    />
                  )}

                  <circle
                    r="20"
                    fill={style.bg}
                    stroke={isSelected ? '#06B6D4' : style.stroke}
                    strokeWidth={isSelected ? '2.5' : '1.5'}
                  />

                  {/* Icon Representation */}
                  <g transform="translate(-8, -8)">
                    {node.type === 'attacker' && <Radio className="w-4 h-4 text-rose-400" />}
                    {node.type === 'ingress' && <Server className="w-4 h-4 text-amber-400" />}
                    {node.type === 'detection' && <Shield className="w-4 h-4 text-amber-400" />}
                    {node.type === 'correlation' && <Layers className="w-4 h-4 text-purple-400" />}
                    {node.type === 'target' && <User className="w-4 h-4 text-cyan-400" />}
                  </g>

                  {/* Node Label Text */}
                  <text
                    y="32"
                    textAnchor="middle"
                    className="font-mono font-bold text-[11px] fill-slate-200"
                  >
                    {node.label}
                  </text>
                  <text
                    y="44"
                    textAnchor="middle"
                    className="font-mono text-[9px] fill-slate-400"
                  >
                    {node.sublabel}
                  </text>
                </g>
              );
            })}
          </svg>

          {/* Quick Guidance Overlay */}
          <div className="absolute bottom-2 left-2 flex items-center gap-1.5 px-2 py-1 rounded bg-[#0A0D15]/80 border border-slate-800 text-[10px] font-mono text-slate-400">
            <Info className="w-3 h-3 text-cyan-400" />
            <span>Click any node to inspect evidence attributes</span>
          </div>
        </div>

        {/* Selected Node Forensic Inspector Panel */}
        <div className="w-72 border-l border-slate-800 bg-[#0B0F19] p-3.5 flex flex-col justify-between text-xs font-mono">
          <div>
            <div className="flex items-center justify-between pb-2 border-b border-slate-800">
              <span className="text-[10px] font-bold text-cyan-400 uppercase tracking-wider">
                Node Inspector
              </span>
              <span className="text-[10px] px-1.5 py-0.2 rounded bg-slate-800 text-slate-300">
                {selectedNode.type.toUpperCase()}
              </span>
            </div>

            <div className="mt-2.5">
              <h4 className="text-xs font-bold text-slate-100 break-all">
                {selectedNode.label}
              </h4>
              <p className="text-[10px] text-slate-400 mt-0.5">
                {selectedNode.sublabel}
              </p>
            </div>

            {/* Properties Table */}
            <div className="mt-3 space-y-2 max-h-48 overflow-y-auto">
              {Object.entries(selectedNode.details).map(([k, v]) => (
                <div key={k} className="p-1.5 rounded bg-slate-900/90 border border-slate-800/80">
                  <div className="text-[10px] text-slate-500 uppercase">{k}</div>
                  <div className="text-[11px] text-slate-200 break-all font-semibold">{v}</div>
                </div>
              ))}
            </div>
          </div>

          <button
            onClick={() =>
              openPayloadDrawer({
                title: `Node Forensic Telemetry: ${selectedNode.label}`,
                subtitle: `Associated with ${currentCase.humanId}`,
                humanId: currentCase.humanId,
                internalUuid: currentCase.internalUuid,
                payload: selectedNode.details
              })
            }
            className="w-full mt-3 flex items-center justify-center gap-1.5 py-1.5 px-2 rounded bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-slate-700 text-xs font-semibold transition-colors"
          >
            <ExternalLink className="w-3.5 h-3.5" />
            <span>Open Raw Telemetry</span>
          </button>
        </div>
      </div>
    </div>
  );
};
