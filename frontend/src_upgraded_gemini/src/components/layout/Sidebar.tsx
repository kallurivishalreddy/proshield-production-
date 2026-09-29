import React, { useState } from 'react';
import {
  Shield,
  LayoutDashboard,
  AlertCircle,
  Radio,
  Network,
  Clock,
  Cpu,
  Sliders,
  Layers,
  Archive,
  Database,
  GraduationCap,
  Compass,
  Activity,
  BookOpen,
  ChevronLeft,
  ChevronRight,
  Plus,
  Sparkles
} from 'lucide-react';
import { useSoc, PageId } from '../../context/SocContext';

export const Sidebar: React.FC = () => {
  const {
    currentPage,
    navigate,
    cases,
    detections,
    setAddSourceModalOpen,
    setAddRuleModalOpen,
    healthSubsystems
  } = useSoc();

  const [collapsed, setCollapsed] = useState(false);

  const openCasesCount = cases.filter(c => c.status !== 'CLOSED').length;
  const criticalCasesCount = cases.filter(c => c.severity === 'CRITICAL' && c.status !== 'CLOSED').length;
  const hasHealthWarning = healthSubsystems.some(h => h.status !== 'HEALTHY');

  const navItems: {
    group: 'OPERATIONS' | 'CONFIGURATION' | 'KNOWLEDGE' | 'FUTURE' | 'SYSTEM';
    items: {
      id: PageId;
      label: string;
      icon: React.ReactNode;
      badge?: string | number;
      badgeColor?: string;
      shortcut?: string;
      quickAction?: {
        label: string;
        onClick: (e: React.MouseEvent) => void;
      };
    }[];
  }[] = [
    {
      group: 'OPERATIONS',
      items: [
        {
          id: 'overview',
          label: 'Overview',
          icon: <LayoutDashboard className="w-4 h-4" />,
          shortcut: '1'
        },
        {
          id: 'incidents',
          label: 'Incidents / Cases',
          icon: <AlertCircle className="w-4 h-4" />,
          badge: openCasesCount,
          badgeColor: criticalCasesCount > 0 ? 'bg-rose-500 text-white' : 'bg-cyan-600 text-cyan-100',
          shortcut: '2'
        },
        {
          id: 'detections',
          label: 'Detections',
          icon: <Radio className="w-4 h-4" />,
          shortcut: '3'
        },
        {
          id: 'correlations',
          label: 'Correlations',
          icon: <Network className="w-4 h-4" />,
          shortcut: '4'
        },
        {
          id: 'timeline',
          label: 'Timeline',
          icon: <Clock className="w-4 h-4" />,
          shortcut: '5'
        }
      ]
    },
    {
      group: 'CONFIGURATION',
      items: [
        {
          id: 'sources',
          label: 'Sources',
          icon: <Cpu className="w-4 h-4" />,
          shortcut: '6',
          quickAction: {
            label: '+ Source',
            onClick: (e) => {
              e.stopPropagation();
              setAddSourceModalOpen(true);
            }
          }
        },
        {
          id: 'rules',
          label: 'Rules',
          icon: <Sliders className="w-4 h-4" />,
          shortcut: '7',
          quickAction: {
            label: '+ Rule',
            onClick: (e) => {
              e.stopPropagation();
              setAddRuleModalOpen(true);
            }
          }
        },
        {
          id: 'capabilities',
          label: 'Capabilities',
          icon: <Layers className="w-4 h-4" />,
          shortcut: '8'
        }
      ]
    },
    {
      group: 'KNOWLEDGE',
      items: [
        {
          id: 'evidence',
          label: 'Evidence Archive',
          icon: <Archive className="w-4 h-4" />,
          badge: 'Preview',
          badgeColor: 'bg-slate-800 text-slate-300 border border-slate-700'
        },
        {
          id: 'datasets',
          label: 'AI Datasets',
          icon: <Database className="w-4 h-4" />,
          badge: 'Preview',
          badgeColor: 'bg-slate-800 text-slate-300 border border-slate-700'
        }
      ]
    },
    {
      group: 'FUTURE',
      items: [
        {
          id: 'learning',
          label: 'Learning Lab',
          icon: <GraduationCap className="w-4 h-4" />,
          badge: 'Coming Soon',
          badgeColor: 'bg-slate-800 text-slate-400 border border-slate-700'
        },
        {
          id: 'guide',
          label: 'ProShield Guide',
          icon: <Compass className="w-4 h-4" />,
          badge: 'Coming Soon',
          badgeColor: 'bg-slate-800 text-slate-400 border border-slate-700'
        }
      ]
    },
    {
      group: 'SYSTEM',
      items: [
        {
          id: 'health',
          label: 'Health / System',
          icon: <Activity className="w-4 h-4" />,
          badge: hasHealthWarning ? '1 Alert' : 'OK',
          badgeColor: hasHealthWarning ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40' : 'bg-emerald-500/20 text-emerald-300',
          shortcut: '9'
        },
        {
          id: 'design-spec',
          label: 'Design Battle Blueprint',
          icon: <BookOpen className="w-4 h-4 text-cyan-400" />,
          badge: 'A-P Spec',
          badgeColor: 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
        }
      ]
    }
  ];

  return (
    <aside
      className={`relative flex flex-col justify-between border-r border-slate-800/80 bg-[#0C1019] transition-all duration-300 z-30 shrink-0 ${
        collapsed ? 'w-18' : 'w-64'
      }`}
    >
      {/* Platform Branding */}
      <div>
        <div className="flex items-center justify-between px-4 py-4 border-b border-slate-800/80 bg-[#090D14]/50">
          {!collapsed ? (
            <div
              onClick={() => navigate('overview')}
              className="flex items-center gap-2.5 cursor-pointer group"
            >
              <div className="relative flex items-center justify-center w-8 h-8 rounded-lg bg-cyan-950 border border-cyan-500/40 group-hover:border-cyan-400 transition-colors shadow-[0_0_12px_rgba(6,182,212,0.25)]">
                <Shield className="w-4 h-4 text-cyan-400" />
                <span className="absolute -top-0.5 -right-0.5 w-2 h-2 rounded-full bg-cyan-400 animate-pulse" />
              </div>
              <div>
                <div className="flex items-center gap-1.5">
                  <span className="font-mono font-bold tracking-wider text-slate-100 text-sm">
                    PROSHIELD
                  </span>
                  <span className="text-[10px] font-mono font-semibold px-1 py-0.2 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
                    SOC
                  </span>
                </div>
                <p className="text-[10px] font-mono text-slate-500">Security Ops Platform</p>
              </div>
            </div>
          ) : (
            <div
              onClick={() => navigate('overview')}
              className="mx-auto flex items-center justify-center w-8 h-8 rounded-lg bg-cyan-950 border border-cyan-500/40 cursor-pointer"
            >
              <Shield className="w-4 h-4 text-cyan-400" />
            </div>
          )}

          <button
            onClick={() => setCollapsed(!collapsed)}
            className="p-1 rounded text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
            title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          >
            {collapsed ? <ChevronRight className="w-4 h-4" /> : <ChevronLeft className="w-4 h-4" />}
          </button>
        </div>

        {/* Navigation Groups */}
        <div className="py-3 px-2 space-y-4">
          {navItems.map(group => (
            <div key={group.group} className="space-y-1">
              {!collapsed && (
                <div className="px-3 py-1 text-[10px] font-mono font-bold tracking-wider text-slate-500 uppercase">
                  {group.group}
                </div>
              )}

              {group.items.map(item => {
                const isActive = currentPage === item.id || (item.id === 'incidents' && currentPage === 'case-detail');
                return (
                  <div
                    key={item.id}
                    onClick={() => navigate(item.id)}
                    className={`group relative flex items-center justify-between px-3 py-2 rounded-lg text-xs font-medium cursor-pointer transition-all ${
                      isActive
                        ? 'bg-slate-800/90 text-cyan-300 font-semibold shadow-inner'
                        : 'text-slate-400 hover:text-slate-100 hover:bg-slate-800/40'
                    }`}
                    title={collapsed ? item.label : undefined}
                  >
                    {isActive && (
                      <span className="absolute left-0 top-1.5 bottom-1.5 w-1 rounded-r bg-cyan-400 shadow-[0_0_8px_rgba(6,182,212,0.8)]" />
                    )}

                    <div className="flex items-center gap-2.5 min-w-0">
                      <span className={`${isActive ? 'text-cyan-400' : 'text-slate-400 group-hover:text-slate-200'}`}>
                        {item.icon}
                      </span>
                      {!collapsed && (
                        <span className="truncate">{item.label}</span>
                      )}
                    </div>

                    {!collapsed && (
                      <div className="flex items-center gap-1.5">
                        {item.quickAction && (
                          <button
                            onClick={item.quickAction.onClick}
                            className="opacity-0 group-hover:opacity-100 transition-opacity text-[10px] px-1.5 py-0.5 rounded bg-cyan-950/80 text-cyan-300 border border-cyan-600/40 hover:bg-cyan-900"
                            title={item.quickAction.label}
                          >
                            <Plus className="w-3 h-3 inline" />
                          </button>
                        )}
                        {item.badge !== undefined && (
                          <span
                            className={`text-[10px] font-mono font-bold px-1.5 py-0.2 rounded ${
                              item.badgeColor || 'bg-slate-800 text-slate-300'
                            }`}
                          >
                            {item.badge}
                          </span>
                        )}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          ))}
        </div>
      </div>

      {/* Footer / Live Stream Indicator */}
      <div className="p-3 border-t border-slate-800/80 bg-[#090D14]/50">
        {!collapsed ? (
          <div className="space-y-2">
            <div className="flex items-center justify-between text-[11px] font-mono">
              <span className="flex items-center gap-1.5 text-emerald-400">
                <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
                BACKEND LINKED
              </span>
              <span className="text-slate-500">{detections.length} DET</span>
            </div>
            <button
              onClick={() => navigate('design-spec')}
              className="w-full flex items-center justify-center gap-1.5 py-1.5 px-2 rounded-md bg-gradient-to-r from-cyan-950/60 to-blue-950/60 border border-cyan-500/30 text-cyan-300 text-xs font-semibold hover:border-cyan-400 transition-all shadow-[0_0_10px_rgba(6,182,212,0.15)]"
            >
              <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
              <span>Design Blueprint (A-P)</span>
            </button>
          </div>
        ) : (
          <div className="flex justify-center" title={`Backend linked: ${detections.length} detections loaded`}>
            <span className="w-2.5 h-2.5 rounded-full bg-emerald-400 animate-pulse" />
          </div>
        )}
      </div>
    </aside>
  );
};
