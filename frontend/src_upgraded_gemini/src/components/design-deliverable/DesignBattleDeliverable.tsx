import React, { useState } from 'react';
import {
  Sparkles,
  Layers,
  Shield,
  CheckCircle,
  AlertTriangle,
  Smartphone,
  Monitor,
  Zap
} from 'lucide-react';
import { useSoc } from '../../context/SocContext';

export const DesignBattleDeliverable: React.FC = () => {
  const { navigate } = useSoc();
  const [activeSection, setActiveSection] = useState<'vision' | 'principles' | 'design-system' | 'shell' | 'nine-pages' | 'workflows' | 'errors' | 'responsive' | 'superiority'>('vision');

  return (
    <div className="space-y-6 pb-16 animate-in fade-in duration-200">
      {/* Blueprint Hero */}
      <div className="p-6 rounded-2xl bg-gradient-to-r from-cyan-950/60 via-[#0E1524] to-[#0A0D15] border border-cyan-500/40 shadow-2xl relative overflow-hidden">
        <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-4 relative z-10">
          <div className="space-y-2 max-w-3xl">
            <div className="flex items-center gap-2">
              <span className="px-2.5 py-0.5 rounded-full bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 font-mono text-[11px] font-bold">
                DESIGN BATTLE SPECIFICATION DELIVERABLE
              </span>
              <span className="text-xs font-mono text-slate-400">Sections A — P Complete</span>
            </div>
            <h1 className="text-2xl font-bold font-mono tracking-tight text-slate-100">
              PROSHIELD NEXT-GEN SOC PLATFORM DESIGN SYSTEM
            </h1>
            <p className="text-xs text-slate-300 leading-relaxed font-sans">
              A bespoke, high-signal, human-first security operations architecture engineered specifically to minimize analyst cognitive fatigue during continuous 8-hour investigation shifts.
            </p>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => navigate('overview')}
              className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-mono text-xs font-bold transition-colors shadow-[0_0_15px_rgba(6,182,212,0.4)]"
            >
              Explore Live 9-Page Platform
            </button>
          </div>
        </div>
      </div>

      {/* Navigation Pills for Sections A-P */}
      <div className="flex flex-wrap items-center gap-2 p-2 rounded-xl bg-[#0F1420] border border-slate-800 text-xs font-mono">
        {[
          { id: 'vision', label: 'A. Vision & Archetype' },
          { id: 'principles', label: 'B. Core Principles' },
          { id: 'design-system', label: 'C. Design System & Tokens' },
          { id: 'shell', label: 'D. Global Shell Arch' },
          { id: 'nine-pages', label: 'E-F. 9-Page Architecture' },
          { id: 'workflows', label: 'G-K. Workflows (Sources/Rules/Cases)' },
          { id: 'errors', label: 'L. Truthful Error UX' },
          { id: 'responsive', label: 'M-O. Responsive & 3D Decisions' },
          { id: 'superiority', label: 'P. Why ProShield Wins' }
        ].map(tab => (
          <button
            key={tab.id}
            onClick={() => setActiveSection(tab.id as any)}
            className={`px-3 py-1.5 rounded-lg transition-all ${
              activeSection === tab.id
                ? 'bg-cyan-950 text-cyan-300 border border-cyan-500/50 font-bold shadow-sm'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* SECTION CONTENT BLOCKS */}

      {/* SECTION A: VISION */}
      {activeSection === 'vision' && (
        <div className="p-6 rounded-xl bg-[#0F1420] border border-slate-800 space-y-6 text-xs">
          <div className="flex items-center gap-2.5 pb-3 border-b border-slate-800">
            <Sparkles className="w-5 h-5 text-cyan-400" />
            <h2 className="text-base font-bold font-mono text-slate-100">
              SECTION A — PRODUCT DESIGN VISION
            </h2>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="p-4 rounded-lg bg-slate-900 border border-slate-800 space-y-2">
              <span className="text-[11px] font-mono font-bold text-cyan-400 uppercase">1. Simple for New Analysts</span>
              <p className="text-slate-300 leading-relaxed font-sans">
                Zero onboarding friction. Clean human-readable identifiers (<code className="text-cyan-300">CASE-01</code>, <code className="text-amber-300">DET-01</code>) replace unreadable 36-character UUIDs. Every view answers: <em>What happened? How serious is it? What should I do next?</em>
              </p>
            </div>
            <div className="p-4 rounded-lg bg-slate-900 border border-slate-800 space-y-2">
              <span className="text-[11px] font-mono font-bold text-cyan-400 uppercase">2. Powerful for Senior SOC</span>
              <p className="text-slate-300 leading-relaxed font-sans">
                High-density scanning modes, keyboard omni-search (<code className="text-cyan-300">Cmd+K</code>), multi-source correlation synthesizers, Sigma/CEL logic authoring, and raw JSON forensic payloads always 1 click away via slide-over drawers.
              </p>
            </div>
            <div className="p-4 rounded-lg bg-slate-900 border border-slate-800 space-y-2">
              <span className="text-[11px] font-mono font-bold text-cyan-400 uppercase">3. Distinctive Visual Identity</span>
              <p className="text-slate-300 leading-relaxed font-sans">
                Deep obsidian slate backgrounds (<code className="text-cyan-300">#0B0F17</code>) with high-contrast tactical cyan accents and semantic severity palettes. No generic SaaS gradients, no distracting neon clutter.
              </p>
            </div>
          </div>
        </div>
      )}

      {/* SECTION B: PRINCIPLES */}
      {activeSection === 'principles' && (
        <div className="p-6 rounded-xl bg-[#0F1420] border border-slate-800 space-y-6 text-xs">
          <div className="flex items-center gap-2.5 pb-3 border-b border-slate-800">
            <Shield className="w-5 h-5 text-cyan-400" />
            <h2 className="text-base font-bold font-mono text-slate-100">
              SECTION B — SOC DESIGN PRINCIPLES
            </h2>
          </div>

          <div className="space-y-3">
            {[
              {
                title: '1. Human-First Object Identity System',
                desc: 'Never make raw database UUIDs the primary visual identifier. Use clean human labels: CASE-01, DET-01, CORR-01, SRC-01, RULE-01. Expose technical UUIDs through tooltips and one-click copy.'
              },
              {
                title: '2. Progressive Forensic Disclosure',
                desc: 'Primary views prioritize context, attacker IP, target asset, and severity. Raw JSON logs, PCAP headers, and low-level stacks remain secondary in non-disruptive slide-out drawers.'
              },
              {
                title: '3. Purposeful 2D & 3D Interaction',
                desc: '2D schematic layouts handle fast day-to-day triage. Isometric 3D attack topology is reserved for visualizing complex multi-stage lateral pivots.'
              },
              {
                title: '4. Truthful Error Handling & Unambiguous State',
                desc: 'Never show misleading success badges when an API fails. Every error message clearly answers: What failed? Why did it fail? What exact action will fix it?'
              }
            ].map((principle, idx) => (
              <div key={idx} className="p-3.5 rounded-lg bg-slate-900/90 border border-slate-800 space-y-1">
                <h4 className="font-mono font-bold text-slate-100 text-xs text-cyan-300">
                  {principle.title}
                </h4>
                <p className="text-slate-300 font-sans leading-relaxed">
                  {principle.desc}
                </p>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* SECTION C: DESIGN SYSTEM & TOKENS */}
      {activeSection === 'design-system' && (
        <div className="p-6 rounded-xl bg-[#0F1420] border border-slate-800 space-y-6 text-xs font-mono">
          <div className="flex items-center gap-2.5 pb-3 border-b border-slate-800">
            <Layers className="w-5 h-5 text-cyan-400" />
            <h2 className="text-base font-bold text-slate-100">
              SECTION C — COMPLETE DESIGN SYSTEM TOKENS
            </h2>
          </div>

          {/* Color Palette Tokens */}
          <div className="space-y-3">
            <h3 className="text-xs font-bold text-slate-300 uppercase tracking-wider">
              1. Semantic Severity System (WCAG AAA Contrast on Dark Obsidian)
            </h3>
            <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 text-center">
              <div className="p-3 rounded-lg bg-rose-950/40 border border-rose-500/60 text-rose-300">
                <span className="font-bold block">CRITICAL</span>
                <span className="text-[10px] text-slate-400">#EF4444 / Rose-500</span>
              </div>
              <div className="p-3 rounded-lg bg-amber-950/40 border border-amber-500/60 text-amber-300">
                <span className="font-bold block">HIGH</span>
                <span className="text-[10px] text-slate-400">#F97316 / Amber-500</span>
              </div>
              <div className="p-3 rounded-lg bg-yellow-950/40 border border-yellow-500/60 text-yellow-300">
                <span className="font-bold block">MEDIUM</span>
                <span className="text-[10px] text-slate-400">#EAB308 / Yellow-500</span>
              </div>
              <div className="p-3 rounded-lg bg-sky-950/40 border border-sky-500/60 text-sky-300">
                <span className="font-bold block">LOW</span>
                <span className="text-[10px] text-slate-400">#0EA5E9 / Sky-500</span>
              </div>
              <div className="p-3 rounded-lg bg-slate-900 border border-slate-700 text-slate-300">
                <span className="font-bold block">INFORMATIONAL</span>
                <span className="text-[10px] text-slate-400">#64748B / Slate-500</span>
              </div>
            </div>
          </div>

          {/* 20 Component Matrix */}
          <div className="space-y-3 pt-4 border-t border-slate-800">
            <h3 className="text-xs font-bold text-slate-300 uppercase tracking-wider">
              2. Standardized 20-Component System Inventory
            </h3>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-[11px] text-slate-300">
              <div className="p-2 rounded bg-slate-900 border border-slate-800">1. Typography Hierarchy</div>
              <div className="p-2 rounded bg-slate-900 border border-slate-800">2. Dark Obsidian Palette</div>
              <div className="p-2 rounded bg-slate-900 border border-slate-800">3. Severity Badges</div>
              <div className="p-2 rounded bg-slate-900 border border-slate-800">4. Status Badges</div>
              <div className="p-2 rounded bg-slate-900 border border-slate-800">5. 8pt Spacing Grid</div>
              <div className="p-2 rounded bg-slate-900 border border-slate-800">6. Metric Cards & Sparklines</div>
              <div className="p-2 rounded bg-slate-900 border border-slate-800">7. Action Buttons</div>
              <div className="p-2 rounded bg-slate-900 border border-slate-800">8. Form Inputs & DSL Editors</div>
              <div className="p-2 rounded bg-slate-900 border border-slate-800">9. Tables & Density Toggles</div>
              <div className="p-2 rounded bg-slate-900 border border-slate-800">10. Human ID Tags</div>
              <div className="p-2 rounded bg-slate-900 border border-slate-800">11. Investigation Tabs</div>
              <div className="p-2 rounded bg-slate-900 border border-slate-800">12. Modals (Wizard & Action)</div>
              <div className="p-2 rounded bg-slate-900 border border-slate-800">13. Slide-Out Drawers</div>
              <div className="p-2 rounded bg-slate-900 border border-slate-800">14. Tooltips & Copy Triggers</div>
              <div className="p-2 rounded bg-slate-900 border border-slate-800">15. Empty States</div>
              <div className="p-2 rounded bg-slate-900 border border-slate-800">16. Truthful Error Cards</div>
              <div className="p-2 rounded bg-slate-900 border border-slate-800">17. Loading Skeletons</div>
              <div className="p-2 rounded bg-slate-900 border border-slate-800">18. Grouped Sidebar Shell</div>
              <div className="p-2 rounded bg-slate-900 border border-slate-800">19. Global OmniSearch (⌘K)</div>
              <div className="p-2 rounded bg-slate-900 border border-slate-800">20. Notification Toasts</div>
            </div>
          </div>
        </div>
      )}

      {/* SECTION D: SHELL */}
      {activeSection === 'shell' && (
        <div className="p-6 rounded-xl bg-[#0F1420] border border-slate-800 space-y-6 text-xs">
          <div className="flex items-center gap-2.5 pb-3 border-b border-slate-800">
            <Monitor className="w-5 h-5 text-cyan-400" />
            <h2 className="text-base font-bold font-mono text-slate-100">
              SECTION D — GLOBAL APPLICATION SHELL ARCHITECTURE
            </h2>
          </div>

          <div className="space-y-4 font-sans text-slate-300">
            <p>
              The ProShield shell is built around three core cognitive anchor questions:
            </p>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-3 font-mono">
              <div className="p-3.5 rounded-lg bg-slate-900 border border-slate-800 space-y-1">
                <span className="text-cyan-400 font-bold block">WHERE AM I?</span>
                <span className="text-slate-300 text-xs font-sans">
                  Active location is perpetually visible in breadcrumbs and high-contrast sidebar indicators.
                </span>
              </div>
              <div className="p-3.5 rounded-lg bg-slate-900 border border-slate-800 space-y-1">
                <span className="text-amber-400 font-bold block">WHAT NEEDS ATTENTION?</span>
                <span className="text-slate-300 text-xs font-sans">
                  Top bar health pulse, unread notification counter, and priority hero banners highlight critical queue anomalies immediately.
                </span>
              </div>
              <div className="p-3.5 rounded-lg bg-slate-900 border border-slate-800 space-y-1">
                <span className="text-emerald-400 font-bold block">WHAT CAN I DO NEXT?</span>
                <span className="text-slate-300 text-xs font-sans">
                  Contextual next steps (Acknowledge, Investigate, Close, Centralized Analysis) are prominently placed in the top right.
                </span>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* SECTION E & F: 9-PAGE ARCHITECTURE */}
      {activeSection === 'nine-pages' && (
        <div className="p-6 rounded-xl bg-[#0F1420] border border-slate-800 space-y-6 text-xs">
          <div className="flex items-center gap-2.5 pb-3 border-b border-slate-800">
            <Layers className="w-5 h-5 text-cyan-400" />
            <h2 className="text-base font-bold font-mono text-slate-100">
              SECTION E & F — 9-PAGE ANALYST EXPERIENCE MATRIX
            </h2>
          </div>

          <div className="space-y-3 font-mono">
            {[
              { num: '01', title: 'OVERVIEW', desc: 'High-signal triage dashboard with hero attention banner, threat velocity hourly chart, and subsystem status.' },
              { num: '02', title: 'INCIDENTS / CASES', desc: 'Prioritized investigation queue with human IDs, multi-facet filtering (Severity/State/Source), and density toggling.' },
              { num: '03', title: 'CASE DETAIL', desc: 'Real workspace with 6 sub-investigation tabs, interactive 2D/3D attack graph, lifecycle pipeline, and centralized analysis.' },
              { num: '04', title: 'DETECTIONS', desc: 'Alert queue showing rule matches, matched fields, evidence summary, and direct pivots to rules and cases.' },
              { num: '05', title: 'CORRELATIONS', desc: 'Multi-detection clustering intelligence with tree hierarchies, confidence scoring, and cross-source mapping.' },
              { num: '06', title: 'TIMELINE', desc: 'Multi-stream chronological forensic timeline with progressive disclosure drawers for raw payload JSON.' },
              { num: '07', title: 'SOURCES', desc: 'Reusable Connector Capability → Source Instance → Ingest Pipeline architecture with 6-step creation wizard and token rotation.' },
              { num: '08', title: 'RULES', desc: 'Analyst-friendly security controls with Sigma/CEL DSL editors, affected detections tracker, and lifecycle toggles.' },
              { num: '09', title: 'HEALTH / SYSTEM', desc: 'Operational monitor covering all 9 subsystems with causal diagnostics answering What is wrong? and What should I do?' }
            ].map(page => (
              <div key={page.num} className="p-3 rounded-lg bg-slate-900 border border-slate-800 flex items-start gap-3">
                <span className="text-cyan-400 font-bold text-sm">{page.num}</span>
                <div>
                  <h4 className="font-bold text-slate-200">{page.title}</h4>
                  <p className="text-slate-400 font-sans text-xs mt-0.5">{page.desc}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* SECTION G-K: WORKFLOWS */}
      {activeSection === 'workflows' && (
        <div className="p-6 rounded-xl bg-[#0F1420] border border-slate-800 space-y-6 text-xs font-sans">
          <div className="flex items-center gap-2.5 pb-3 border-b border-slate-800">
            <Zap className="w-5 h-5 text-cyan-400" />
            <h2 className="text-base font-bold font-mono text-slate-100">
              SECTION G — K: CORE OPERATIONAL WORKFLOWS
            </h2>
          </div>

          <div className="space-y-4">
            <div className="p-4 rounded-lg bg-slate-900 border border-slate-800 space-y-2">
              <span className="text-xs font-mono font-bold text-emerald-400 uppercase">
                Section G: Source Creation Workflow Architecture
              </span>
              <p className="text-slate-300 leading-relaxed">
                Clicking <strong>+ ADD SOURCE</strong> leads directly into the dedicated 6-step creation flow: <em>Identity & Metadata → Reusable Connector Capability Selection → Ingress Endpoint Mapping → Bearer Token Generation → Real-time Handshake Validation → Enable & Ready</em>. Multiple source instances can share one driver without confusing sub-connector proliferation.
              </p>
            </div>

            <div className="p-4 rounded-lg bg-slate-900 border border-slate-800 space-y-2">
              <span className="text-xs font-mono font-bold text-sky-400 uppercase">
                Section H: Rule Creation Workflow
              </span>
              <p className="text-slate-300 leading-relaxed">
                Rules are created for existing connector capabilities. The analyst chooses the target connector, defines a human-facing name and plain-language purpose description, selects source instance scopes, and writes or validates detection DSL (Sigma / YARA-L / CEL).
              </p>
            </div>

            <div className="p-4 rounded-lg bg-slate-900 border border-slate-800 space-y-2">
              <span className="text-xs font-mono font-bold text-cyan-400 uppercase">
                Section I-K: Centralized Multi-Source Analysis & Reporting
              </span>
              <p className="text-slate-300 leading-relaxed">
                When an analyst clicks <strong>Centralized Analysis</strong>, ProShield runs the multi-source sliding-window graph synthesizer. Upon completion, the UI presents distinct new findings and transitions to <strong>GENERATE CENTRALIZED REPORT</strong>, making it crystal clear that this is a synthesized cross-source intelligence product.
              </p>
            </div>
          </div>
        </div>
      )}

      {/* SECTION L: TRUTHFUL ERROR UX */}
      {activeSection === 'errors' && (
        <div className="p-6 rounded-xl bg-[#0F1420] border border-slate-800 space-y-6 text-xs font-mono">
          <div className="flex items-center gap-2.5 pb-3 border-b border-slate-800">
            <AlertTriangle className="w-5 h-5 text-rose-400" />
            <h2 className="text-base font-bold text-slate-100">
              SECTION L — TRUTHFUL ERROR UX & FAILURE RECOVERY
            </h2>
          </div>

          <p className="font-sans text-slate-300 leading-relaxed">
            In security operations, silent failures or generic "Something went wrong" banners are unacceptable. ProShield designs explicit failure semantics for all standard HTTP status codes:
          </p>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
            <div className="p-3 rounded-lg bg-slate-900 border border-slate-800 space-y-1">
              <span className="text-rose-400 font-bold">HTTP 409 State Conflict:</span>
              <p className="text-slate-300 font-sans">"Could not update source. This source is currently ENABLED. Disable source before changing configuration."</p>
            </div>
            <div className="p-3 rounded-lg bg-slate-900 border border-slate-800 space-y-1">
              <span className="text-rose-400 font-bold">HTTP 403 Forbidden:</span>
              <p className="text-slate-300 font-sans">"Insufficient RBAC privileges. Tier-1 analyst cannot disable production ingress sources."</p>
            </div>
            <div className="p-3 rounded-lg bg-slate-900 border border-slate-800 space-y-1">
              <span className="text-rose-400 font-bold">HTTP 429 Rate Limit:</span>
              <p className="text-slate-300 font-sans">"Buffer lag detected. Ingestion backpressure actively queued in Kafka partitions without telemetry loss."</p>
            </div>
            <div className="p-3 rounded-lg bg-slate-900 border border-slate-800 space-y-1">
              <span className="text-rose-400 font-bold">HTTP 500 Worker Fault:</span>
              <p className="text-slate-300 font-sans">"Correlation supervisor restarting worker automatically. No state lost."</p>
            </div>
          </div>
        </div>
      )}

      {/* SECTION M-O: RESPONSIVE & 3D */}
      {activeSection === 'responsive' && (
        <div className="p-6 rounded-xl bg-[#0F1420] border border-slate-800 space-y-6 text-xs">
          <div className="flex items-center gap-2.5 pb-3 border-b border-slate-800">
            <Smartphone className="w-5 h-5 text-cyan-400" />
            <h2 className="text-base font-bold font-mono text-slate-100">
              SECTION M — O: RESPONSIVE BREAKPOINTS & PURPOSEFUL 3D
            </h2>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="p-4 rounded-lg bg-slate-900 border border-slate-800 space-y-2">
              <span className="text-xs font-mono font-bold text-cyan-400 uppercase">
                Desktop-First SOC Breakpoint Strategy
              </span>
              <ul className="space-y-1 text-slate-300 font-mono text-xs">
                <li>• <strong>1440px+</strong>: Full 3-column analytical grid with expanded metadata.</li>
                <li>• <strong>1280px</strong>: Collapsible side panels; preserved tabular density.</li>
                <li>• <strong>1024px</strong>: Stacked metric cards; collapsed left sidebar.</li>
                <li>• <strong>768px</strong>: Horizontal scroll tables; off-canvas search modal.</li>
                <li>• <strong>390px (Mobile Emergency)</strong>: Read-only incident triage with swipe actions.</li>
              </ul>
            </div>

            <div className="p-4 rounded-lg bg-slate-900 border border-slate-800 space-y-2">
              <span className="text-xs font-mono font-bold text-purple-400 uppercase">
                Purposeful 3D / 2D Decision Matrix
              </span>
              <p className="text-slate-300 leading-relaxed font-sans">
                3D is never mandatory for primary triage workflows. 2D schematic is the default for speed, while isometric 3D projection can be toggled to explore deep lateral movement graphs with multi-host topology relationships.
              </p>
            </div>
          </div>
        </div>
      )}

      {/* SECTION P: SUPERIORITY DEFENSE */}
      {activeSection === 'superiority' && (
        <div className="p-6 rounded-xl bg-[#0F1420] border border-cyan-500/40 space-y-6 text-xs">
          <div className="flex items-center gap-2.5 pb-3 border-b border-slate-800">
            <CheckCircle className="w-5 h-5 text-emerald-400" />
            <h2 className="text-base font-bold font-mono text-slate-100">
              SECTION P — WHY PROSHIELD IS SUPERIOR FOR 8-HOUR SOC SHIFTS
            </h2>
          </div>

          <div className="space-y-4 font-sans text-slate-200">
            <div className="p-4 rounded-lg bg-emerald-950/20 border border-emerald-500/30 space-y-2">
              <h4 className="text-xs font-bold text-emerald-300 font-mono">
                The SOC Cognitive-Fatigue Test (8-Hour Shift Feasibility)
              </h4>
              <p className="text-xs leading-relaxed text-slate-300">
                Most SIEM/SOC platforms fail because they treat the interface as a database query tool. Analysts spend hours copying raw UUIDs, squinting at unpadded tables, and navigating bloated connector stores.
              </p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="p-4 rounded-lg bg-slate-900 border border-slate-800 space-y-2">
                <span className="font-mono font-bold text-cyan-400 text-xs">Why ProShield Wins in 5 Seconds:</span>
                <ul className="space-y-1.5 text-slate-300 text-xs font-sans">
                  <li className="flex items-start gap-2">
                    <span className="text-emerald-400 font-bold">✓</span>
                    <span><strong>Human-First IDs:</strong> CASE-01 vs case-04861cab-8f92-4911-b4fa-6c1e95b058fe.</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <span className="text-emerald-400 font-bold">✓</span>
                    <span><strong>Clear Lifecycle Pipeline:</strong> Open → Acknowledged → Investigating → Closed with mandatory rationale.</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <span className="text-emerald-400 font-bold">✓</span>
                    <span><strong>Explicit Connector Separation:</strong> Reusable Connector Capability vs. Live Source Instances.</span>
                  </li>
                </ul>
              </div>

              <div className="p-4 rounded-lg bg-slate-900 border border-slate-800 space-y-2">
                <span className="font-mono font-bold text-cyan-400 text-xs">Production Operational Reliability:</span>
                <ul className="space-y-1.5 text-slate-300 text-xs font-sans">
                  <li className="flex items-start gap-2">
                    <span className="text-emerald-400 font-bold">✓</span>
                    <span><strong>Centralized Analysis Distinct Action:</strong> Synthesizes real multi-source correlations.</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <span className="text-emerald-400 font-bold">✓</span>
                    <span><strong>Truthful Error Handling:</strong> Specific failure codes with causal diagnostics.</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <span className="text-emerald-400 font-bold">✓</span>
                    <span><strong>Progressive Forensic Disclosure:</strong> Drawers for JSON logs without page disruption.</span>
                  </li>
                </ul>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
