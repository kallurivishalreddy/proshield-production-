import React, { useEffect, useState } from 'react';
import {
  ArrowLeft,
  Clock,
  Radio,
  Network,
  Layers,
  FileText,
  Sparkles,
  CheckCircle,
  MessageSquare,
  Shield,
  Send,
  Terminal,
  Activity
} from 'lucide-react';
import { useSoc } from '../../context/SocContext';
import { SeverityBadge } from '../common/SeverityBadge';
import { StatusBadge } from '../common/StatusBadge';
import { HumanIdTag } from '../common/HumanIdTag';
import { CopyableText } from '../common/CopyableText';
import { AttackGraphTopology } from '../investigation/AttackGraphTopology';
import { formatIstTime, formatIstTimestamp } from '../../utils/format';

export const CaseDetailPage: React.FC = () => {
  const {
    selectedCaseId,
    cases,
    detections,
    correlations,
    timelineEvents,
    navigate,
    updateCaseStatus,
    addCaseNote,
    setCloseCaseModalOpen,
    setCentralizedAnalysisModalOpen,
    setReportModalOpen,
    openPayloadDrawer,
    loadCaseTimeline
  } = useSoc();

  const [activeTab, setActiveTab] = useState<'topology' | 'timeline' | 'detections' | 'correlations' | 'notes' | 'report'>('topology');
  const [newNoteText, setNewNoteText] = useState('');

  const currentCase = cases.find(c => c.humanId === selectedCaseId) || cases[0];

  // AUD-02 fix: fetch the real backend timeline (timeline.build_for_incident)
  // when a case workspace opens. Previously timelineEvents were only loaded
  // from the global Timeline page, so the per-case Timeline tab always
  // showed 0 items even though the backend had the full evidence timeline.
  useEffect(() => {
    if (currentCase?.humanId) {
      loadCaseTimeline(currentCase.humanId);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [currentCase?.humanId]);

  const linkedDetections = detections.filter(d => d.caseId === currentCase.humanId);
  const linkedCorrelations = correlations.filter(corr => corr.caseId === currentCase.humanId);
  const linkedTimeline = timelineEvents.filter(t => t.humanId === currentCase.humanId || t.caseId === currentCase.humanId);

  const handleAddNote = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newNoteText.trim()) return;
    addCaseNote(currentCase.humanId, newNoteText);
    setNewNoteText('');
  };

  // Lifecycle states
  const lifecycleStates: { id: 'OPEN' | 'ACKNOWLEDGED' | 'INVESTIGATING' | 'CLOSED'; label: string }[] = [
    { id: 'OPEN', label: '1. Open' },
    { id: 'ACKNOWLEDGED', label: '2. Acknowledged' },
    { id: 'INVESTIGATING', label: '3. Investigating' },
    { id: 'CLOSED', label: '4. Closed' }
  ];

  return (
    <div className="space-y-5 pb-12 animate-in fade-in duration-200">
      {/* Back to Queue Navigation */}
      <div className="flex items-center justify-between">
        <button
          onClick={() => navigate('incidents')}
          className="flex items-center gap-1.5 text-xs font-mono text-slate-400 hover:text-cyan-300 transition-colors"
        >
          <ArrowLeft className="w-4 h-4" />
          <span>Back to Incident Queue</span>
        </button>

        {/* Global Case Actions */}
        <div className="flex items-center gap-2">
          {currentCase.status !== 'CLOSED' && (
            <button
              onClick={() => {
                setCentralizedAnalysisModalOpen(true);
              }}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyan-950/80 hover:bg-cyan-900 border border-cyan-500/40 text-cyan-300 text-xs font-mono font-bold transition-all shadow-[0_0_12px_rgba(6,182,212,0.2)]"
            >
              <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
              <span>Centralized Analysis</span>
            </button>
          )}

          <button
            onClick={() => setReportModalOpen(true)}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-indigo-950/80 hover:bg-indigo-900 border border-indigo-500/40 text-indigo-300 text-xs font-mono font-bold transition-colors"
          >
            <FileText className="w-3.5 h-3.5" />
            <span>Generate Report</span>
          </button>

          {currentCase.status !== 'CLOSED' ? (
            <button
              onClick={() => setCloseCaseModalOpen(true)}
              className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-mono font-bold transition-colors shadow-[0_0_12px_rgba(16,185,129,0.3)]"
            >
              <CheckCircle className="w-3.5 h-3.5" />
              <span>Close Case</span>
            </button>
          ) : (
            <button
              onClick={() => updateCaseStatus(currentCase.humanId, 'INVESTIGATING')}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-mono border border-slate-700 transition-colors"
            >
              <Activity className="w-3.5 h-3.5" />
              <span>Reopen Case</span>
            </button>
          )}
        </div>
      </div>

      {/* Case Header Banner */}
      <div className="p-5 rounded-xl bg-[#0F1420] border border-slate-800 shadow-xl space-y-4">
        <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-4">
          <div className="space-y-2">
            <div className="flex flex-wrap items-center gap-2.5">
              <HumanIdTag humanId={currentCase.humanId} internalUuid={currentCase.internalUuid} size="lg" />
              <SeverityBadge severity={currentCase.severity} size="md" />
              <StatusBadge status={currentCase.status} resolutionReason={currentCase.closureReason} size="md" />
              {currentCase.isCorrelated && (
                <span className="text-xs font-mono font-bold px-2 py-0.5 rounded bg-purple-950 text-purple-300 border border-purple-800">
                  CORRELATED
                </span>
              )}
            </div>

            <h1 className="text-xl font-bold text-slate-100 tracking-tight">
              {currentCase.title}
            </h1>

            <p className="text-xs text-slate-300 leading-relaxed max-w-4xl">
              {currentCase.description}
            </p>
          </div>

          {/* Assigned Analyst Card */}
          {currentCase.assignedAnalyst && (
            <div className="flex items-center gap-3 p-3 rounded-lg bg-slate-900 border border-slate-800 shrink-0">
              <div className="w-9 h-9 rounded-full bg-cyan-950 border border-cyan-500/40 flex items-center justify-center text-cyan-300 font-mono font-bold text-xs">
                {currentCase.assignedAnalyst.avatar}
              </div>
              <div>
                <div className="text-xs font-bold text-slate-200">
                  {currentCase.assignedAnalyst.name}
                </div>
                <div className="text-[10px] font-mono text-slate-400">
                  {currentCase.assignedAnalyst.role}
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Forensic Metadata Strip */}
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3 pt-3 border-t border-slate-800/80 font-mono text-xs">
          <div>
            <span className="text-[10px] text-slate-500 uppercase block">Source Ingress</span>
            <span className="text-slate-200 font-semibold">{currentCase.sourceName}</span>
          </div>
          <div>
            <span className="text-[10px] text-slate-500 uppercase block">Attacker IP</span>
            <CopyableText text={currentCase.attackerIp} label="Attacker IP" />
          </div>
          <div>
            <span className="text-[10px] text-slate-500 uppercase block">Target Asset</span>
            <span className="text-cyan-300 font-semibold truncate block" title={currentCase.targetAsset}>
              {currentCase.targetAsset}
            </span>
          </div>
          <div>
            <span className="text-[10px] text-slate-500 uppercase block">First Seen</span>
            <span className="text-slate-300">{formatIstTime(currentCase.firstSeen)} IST</span>
          </div>
          <div>
            <span className="text-[10px] text-slate-500 uppercase block">Last Seen</span>
            <span className="text-slate-300">{formatIstTime(currentCase.lastSeen)} IST</span>
          </div>
          <div>
            <span className="text-[10px] text-slate-500 uppercase block">Evidence Summary</span>
            <span className="text-amber-300 font-bold">
              {currentCase.eventCount}e • {currentCase.detectionCount}d • {currentCase.correlationCount}c
            </span>
          </div>
        </div>

        {/* Interactive Case Lifecycle Stepper */}
        <div className="p-3 rounded-lg bg-[#0A0D15] border border-slate-800/80">
          <div className="flex items-center justify-between mb-2">
            <span className="text-[11px] font-mono font-bold text-slate-400 uppercase tracking-wider">
              Investigation Lifecycle Pipeline
            </span>
            <span className="text-[10px] font-mono text-slate-500">
              Click step to transition lifecycle
            </span>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
            {lifecycleStates.map(st => {
              const isCurrent = currentCase.status === st.id;
              return (
                <button
                  key={st.id}
                  onClick={() => {
                    if (st.id === 'CLOSED') {
                      setCloseCaseModalOpen(true);
                    } else {
                      updateCaseStatus(currentCase.humanId, st.id);
                    }
                  }}
                  className={`p-2 rounded-md font-mono text-xs font-bold text-left transition-all border ${
                    isCurrent
                      ? 'bg-cyan-950/80 border-cyan-500 text-cyan-200 shadow-[0_0_10px_rgba(6,182,212,0.2)]'
                      : 'bg-slate-900/60 border-slate-800 text-slate-400 hover:border-slate-700 hover:text-slate-200'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span>{st.label}</span>
                    {isCurrent && <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" />}
                  </div>
                </button>
              );
            })}
          </div>
        </div>
      </div>

      {/* Main Investigation Sub-Tabs */}
      <div className="space-y-4">
        <div className="flex items-center gap-2 border-b border-slate-800 pb-2 text-xs font-mono">
          <button
            onClick={() => setActiveTab('topology')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg font-semibold transition-colors ${
              activeTab === 'topology'
                ? 'bg-cyan-950/80 text-cyan-300 border border-cyan-500/50'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Layers className="w-3.5 h-3.5" />
            <span>Attack Topology Graph</span>
          </button>
          <button
            onClick={() => setActiveTab('timeline')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg font-semibold transition-colors ${
              activeTab === 'timeline'
                ? 'bg-cyan-950/80 text-cyan-300 border border-cyan-500/50'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Clock className="w-3.5 h-3.5" />
            <span>Timeline ({linkedTimeline.length})</span>
          </button>
          <button
            onClick={() => setActiveTab('detections')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg font-semibold transition-colors ${
              activeTab === 'detections'
                ? 'bg-cyan-950/80 text-cyan-300 border border-cyan-500/50'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Radio className="w-3.5 h-3.5 text-amber-400" />
            <span>Detections ({linkedDetections.length})</span>
          </button>
          <button
            onClick={() => setActiveTab('correlations')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg font-semibold transition-colors ${
              activeTab === 'correlations'
                ? 'bg-cyan-950/80 text-cyan-300 border border-cyan-500/50'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Network className="w-3.5 h-3.5 text-purple-400" />
            <span>Correlations ({linkedCorrelations.length})</span>
          </button>
          <button
            onClick={() => setActiveTab('notes')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg font-semibold transition-colors ${
              activeTab === 'notes'
                ? 'bg-cyan-950/80 text-cyan-300 border border-cyan-500/50'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <MessageSquare className="w-3.5 h-3.5" />
            <span>Analyst Notes ({currentCase.notes.length})</span>
          </button>
          <button
            onClick={() => setActiveTab('report')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg font-semibold transition-colors ${
              activeTab === 'report'
                ? 'bg-cyan-950/80 text-cyan-300 border border-cyan-500/50'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <FileText className="w-3.5 h-3.5 text-indigo-400" />
            <span>Case Intelligence Report</span>
          </button>
        </div>

        {/* TAB 1: ATTACK TOPOLOGY GRAPH */}
        {activeTab === 'topology' && (
          <div className="space-y-4">
            <AttackGraphTopology currentCase={currentCase} />
          </div>
        )}

        {/* TAB 2: TIMELINE */}
        {activeTab === 'timeline' && (
          <div className="p-4 rounded-xl bg-[#0F1420] border border-slate-800 space-y-3">
            <h3 className="text-xs font-bold font-mono text-slate-300 uppercase tracking-wider">
              Chronological Evidence Chain ({linkedTimeline.length} entries)
            </h3>
            <div className="space-y-2">
              {linkedTimeline.map(evt => (
                <div
                  key={evt.id}
                  className="p-3 rounded-lg bg-slate-900/80 border border-slate-800 hover:border-slate-700 transition-colors flex items-start justify-between gap-3 text-xs"
                >
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-cyan-300 text-[11px] font-bold">
                        {formatIstTimestamp(evt.timestamp)}
                      </span>
                      <span className="font-mono text-[10px] px-1.5 py-0.2 rounded bg-slate-800 text-slate-300">
                        {evt.type}
                      </span>
                      <SeverityBadge severity={evt.severity} size="sm" />
                    </div>
                    <div className="font-semibold text-slate-100">{evt.title}</div>
                    <p className="text-slate-400 text-xs">{evt.shortExplanation}</p>
                  </div>
                  <button
                    onClick={() =>
                      openPayloadDrawer({
                        title: evt.title,
                        subtitle: `${evt.sourceName} • ${formatIstTimestamp(evt.timestamp)}`,
                        humanId: evt.humanId,
                        payload: evt.rawPayload || { event_id: evt.id, source: evt.sourceName, actor: evt.actor }
                      })
                    }
                    className="p-1.5 rounded bg-slate-800 hover:bg-slate-700 text-cyan-300 shrink-0 font-mono text-[10px]"
                    title="View Raw Forensic Payload"
                  >
                    <Terminal className="w-3.5 h-3.5" />
                  </button>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* TAB 3: DETECTIONS */}
        {activeTab === 'detections' && (
          <div className="p-4 rounded-xl bg-[#0F1420] border border-slate-800 space-y-3">
            <h3 className="text-xs font-bold font-mono text-slate-300 uppercase tracking-wider">
              Linked Detections ({linkedDetections.length})
            </h3>
            <div className="space-y-2">
              {linkedDetections.map(det => (
                <div
                  key={det.humanId}
                  className="p-3.5 rounded-lg bg-slate-900 border border-slate-800 hover:border-amber-500/40 transition-all space-y-2 text-xs"
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <HumanIdTag humanId={det.humanId} internalUuid={det.internalUuid} />
                      <SeverityBadge severity={det.severity} size="sm" />
                      <span className="font-semibold text-slate-100">{det.title}</span>
                    </div>
                    <span className="font-mono text-[11px] text-slate-400">
                      {formatIstTimestamp(det.timestamp)}
                    </span>
                  </div>

                  <p className="text-slate-300 text-xs">{det.evidenceSummary}</p>

                  <div className="flex flex-wrap items-center justify-between gap-2 pt-2 border-t border-slate-800/60 font-mono text-[11px]">
                    <div className="flex items-center gap-2 text-slate-400">
                      <span>Rule: <strong className="text-slate-200">{det.ruleName}</strong></span>
                      <span>•</span>
                      <span>Source: <strong className="text-cyan-300">{det.sourceName}</strong></span>
                    </div>
                    <button
                      onClick={() =>
                        openPayloadDrawer({
                          title: det.title,
                          subtitle: `${det.humanId} • ${det.ruleName}`,
                          humanId: det.humanId,
                          internalUuid: det.internalUuid,
                          payload: det.rawPayload
                        })
                      }
                      className="flex items-center gap-1 text-cyan-400 hover:text-cyan-300"
                    >
                      <Terminal className="w-3.5 h-3.5" />
                      <span>Inspect JSON Payload</span>
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* TAB 4: CORRELATIONS */}
        {activeTab === 'correlations' && (
          <div className="p-4 rounded-xl bg-[#0F1420] border border-slate-800 space-y-3">
            <h3 className="text-xs font-bold font-mono text-slate-300 uppercase tracking-wider">
              Linked Attack Correlations ({linkedCorrelations.length})
            </h3>
            <div className="space-y-3">
              {linkedCorrelations.map(corr => (
                <div
                  key={corr.humanId}
                  className="p-4 rounded-lg bg-slate-900 border border-slate-800 space-y-3 text-xs"
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <HumanIdTag humanId={corr.humanId} internalUuid={corr.internalUuid} />
                      <SeverityBadge severity={corr.severity} size="sm" />
                      <span className="font-semibold text-slate-100">{corr.title}</span>
                    </div>
                    {corr.confidenceScore != null ? (
                      <span className="font-mono text-purple-300 text-xs px-2 py-0.5 rounded bg-purple-950 border border-purple-800">
                        {corr.confidenceScore}% Confidence
                      </span>
                    ) : (
                      <span
                        className="font-mono text-slate-500 text-xs px-2 py-0.5 rounded bg-slate-900 border border-slate-800"
                        title="The backend does not expose a correlation confidence score (documented gap)"
                      >
                        Confidence: —
                      </span>
                    )}
                  </div>

                  <p className="text-slate-300 leading-relaxed">{corr.description}</p>

                  <div className="p-3 rounded bg-[#0A0D15] border border-slate-800 space-y-1.5 font-mono text-[11px]">
                    <div className="text-slate-400">
                      Pattern: <span className="text-slate-200">{corr.pattern}</span>
                    </div>
                    <div className="text-slate-400">
                      Cross-source relations:
                      {corr.crossSourceRelationships.map((rel, idx) => (
                        <div key={idx} className="text-cyan-300 pl-2">
                          → {rel.source} ↔ {rel.target} ({rel.relation})
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* TAB 5: ANALYST NOTES & MITRE ATT&CK */}
        {activeTab === 'notes' && (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            {/* Notes List & Input */}
            <div className="lg:col-span-2 p-4 rounded-xl bg-[#0F1420] border border-slate-800 space-y-4">
              <h3 className="text-xs font-bold font-mono text-slate-300 uppercase tracking-wider">
                Investigation Notes ({currentCase.notes.length})
              </h3>

              {/* Note input form */}
              <form onSubmit={handleAddNote} className="flex gap-2">
                <input
                  type="text"
                  value={newNoteText}
                  onChange={e => setNewNoteText(e.target.value)}
                  placeholder="Record an investigation observation, firewall change, or pivot..."
                  className="flex-1 px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-xs text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-cyan-500"
                />
                <button
                  type="submit"
                  className="flex items-center gap-1.5 px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-mono text-xs font-bold transition-colors"
                >
                  <Send className="w-3.5 h-3.5" />
                  <span>Post Note</span>
                </button>
              </form>

              {/* Notes Stream */}
              <div className="space-y-2.5">
                {currentCase.notes.length === 0 ? (
                  <p className="text-xs text-slate-500 py-4 text-center font-mono">
                    No notes recorded for this case yet. Add your investigation findings above.
                  </p>
                ) : (
                  currentCase.notes.map(note => (
                    <div key={note.id} className="p-3 rounded-lg bg-slate-900 border border-slate-800 space-y-1 text-xs">
                      <div className="flex items-center justify-between text-[11px] font-mono">
                        <span className="font-bold text-cyan-300">{note.author}</span>
                        <span className="text-slate-500">{formatIstTimestamp(note.timestamp)}</span>
                      </div>
                      <p className="text-slate-200 leading-relaxed">{note.text}</p>
                    </div>
                  ))
                )}
              </div>
            </div>

            {/* MITRE ATT&CK Matrix */}
            <div className="p-4 rounded-xl bg-[#0F1420] border border-slate-800 space-y-3">
              <h3 className="text-xs font-bold font-mono text-slate-300 uppercase tracking-wider flex items-center gap-1.5">
                <Shield className="w-4 h-4 text-cyan-400" />
                <span>MITRE ATT&CK Framework</span>
              </h3>
              <div className="space-y-2 font-mono text-xs">
                {currentCase.mitreTactics.map((tactic, idx) => (
                  <div
                    key={idx}
                    className="p-2.5 rounded-lg bg-slate-900 border border-slate-800 text-slate-200"
                  >
                    <span className="text-cyan-400 font-bold block">{tactic.split(' ')[0]}</span>
                    <span>{tactic.split(' ').slice(1).join(' ')}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* TAB 6: REPORT */}
        {activeTab === 'report' && (
          <div className="p-5 rounded-xl bg-[#0F1420] border border-slate-800 space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div>
                <h3 className="text-sm font-bold text-slate-100 font-mono">
                  CASE INTELLIGENCE REPORT STATUS
                </h3>
                <p className="text-xs text-slate-400">
                  Compile executive briefs, forensic artifact extracts, and mitigation recommendations.
                </p>
              </div>
              <button
                onClick={() => setReportModalOpen(true)}
                className="flex items-center gap-2 px-4 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white font-mono font-bold text-xs transition-colors shadow-[0_0_12px_rgba(99,102,241,0.3)]"
              >
                <FileText className="w-4 h-4" />
                <span>Open Report Generator</span>
              </button>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono">
              <div className="p-3.5 rounded-lg bg-slate-900 border border-slate-800 space-y-2">
                <span className="text-slate-400 font-bold uppercase text-[11px]">Normal Case Evidence Summary</span>
                <p className="text-slate-300 font-sans text-xs leading-relaxed">
                  Summarizes the {currentCase.eventCount} events, attacker origin ({currentCase.attackerIp}), and containment status for operational handover.
                </p>
              </div>

              <div className="p-3.5 rounded-lg bg-slate-900 border border-slate-800 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-cyan-400 font-bold uppercase text-[11px] flex items-center gap-1">
                    <Sparkles className="w-3.5 h-3.5" /> Centralized Multi-Source Report
                  </span>
                  <span className="text-[10px] px-1.5 py-0.2 rounded bg-cyan-950 text-cyan-300 border border-cyan-800">
                    {currentCase.centralizedAnalysisDone ? 'Synthesized' : 'Pending Run'}
                  </span>
                </div>
                <p className="text-slate-300 font-sans text-xs leading-relaxed">
                  Synthesizes cross-source telemetry graphs between {currentCase.sourceName} and corporate identity SSO feeds.
                </p>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
