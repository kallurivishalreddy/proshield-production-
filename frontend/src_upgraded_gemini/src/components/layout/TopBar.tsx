import React, { useState } from 'react';
import {
  Search,
  Bell,
  Activity,
  Bug,
  BookOpen,
  ChevronRight,
  RefreshCw
} from 'lucide-react';
import { useSoc } from '../../context/SocContext';
import { SeverityBadge } from '../common/SeverityBadge';
import { formatIstTimestamp } from '../../utils/format';

export const TopBar: React.FC = () => {
  const {
    currentPage,
    navigate,
    selectedCaseId,
    setOmniSearchOpen,
    globalTimeRange,
    setGlobalTimeRange,
    notifications,
    markAllNotificationsRead,
    healthSubsystems,
    setErrorSandboxOpen,
    user,
    logout,
    refreshAll,
    addToast
  } = useSoc();

  const [isNotifOpen, setNotifOpen] = useState(false);
  const [isReloading, setReloading] = useState(false);

  // Batch 1/2 T04-FE-01: the analyst surfaces read the backend once at boot and
  // after the app's own mutations, so a state change made elsewhere (ingress
  // ingestion, the pipeline, another operator) was invisible until a full page
  // load or a re-login. This control re-reads every view from the authoritative
  // backend on demand. It never fabricates or patches local state.
  const handleReload = async () => {
    if (isReloading) return;
    setReloading(true);
    try {
      await refreshAll();
      addToast(
        'info',
        'Reloaded from backend',
        'Every view was re-read from the authoritative backend state.'
      );
    } catch (e) {
      addToast(
        'error',
        'Reload failed',
        e instanceof Error ? e.message : 'The backend did not answer.'
      );
    } finally {
      setReloading(false);
    }
  };

  const unreadNotifs = notifications.filter(n => !n.read);
  const warningSubsystems = healthSubsystems.filter(h => h.status !== 'HEALTHY');

  const getBreadcrumbs = () => {
    switch (currentPage) {
      case 'overview':
        return [{ label: 'OPERATIONS' }, { label: 'SOC Overview' }];
      case 'incidents':
        return [{ label: 'OPERATIONS' }, { label: 'Incident Queue' }];
      case 'case-detail':
        return [
          { label: 'OPERATIONS', link: 'incidents' },
          { label: 'Incidents', link: 'incidents' },
          { label: selectedCaseId }
        ];
      case 'detections':
        return [{ label: 'OPERATIONS' }, { label: 'Detections Surface' }];
      case 'correlations':
        return [{ label: 'OPERATIONS' }, { label: 'Correlation Intelligence' }];
      case 'timeline':
        return [{ label: 'OPERATIONS' }, { label: 'Forensic Timeline' }];
      case 'sources':
        return [{ label: 'CONFIGURATION' }, { label: 'Telemetry Sources' }];
      case 'rules':
        return [{ label: 'CONFIGURATION' }, { label: 'Detection Rules' }];
      case 'capabilities':
        return [{ label: 'CONFIGURATION' }, { label: 'Capabilities' }];
      case 'evidence':
        return [{ label: 'OPERATIONS' }, { label: 'Evidence Archive' }];
      case 'datasets':
        return [{ label: 'OPERATIONS' }, { label: 'AI Datasets' }];
      case 'learning':
        return [{ label: 'FUTURE' }, { label: 'Learning Lab (Preview)' }];
      case 'guide':
        return [{ label: 'FUTURE' }, { label: 'ProShield Guide (Preview)' }];
      case 'health':
        return [{ label: 'SYSTEM' }, { label: 'Platform & Subsystem Health' }];
      case 'design-spec':
        return [{ label: 'SPECIFICATION' }, { label: 'Design Battle Blueprint (A-P)' }];
      default:
        return [{ label: 'PROSHIELD' }];
    }
  };

  const breadcrumbs = getBreadcrumbs();

  return (
    <header className="sticky top-0 z-20 flex items-center justify-between h-14 px-4 bg-[#090D14]/90 backdrop-blur-md border-b border-slate-800/80">
      {/* Left: Breadcrumbs */}
      <div className="flex items-center gap-2 text-xs font-mono">
        {breadcrumbs.map((crumb, idx) => (
          <React.Fragment key={idx}>
            {idx > 0 && <ChevronRight className="w-3.5 h-3.5 text-slate-600" />}
            {crumb.link ? (
              <button
                onClick={() => navigate(crumb.link as any)}
                className="text-slate-400 hover:text-cyan-300 transition-colors"
              >
                {crumb.label}
              </button>
            ) : (
              <span className={idx === breadcrumbs.length - 1 ? 'text-slate-200 font-bold' : 'text-slate-500'}>
                {crumb.label}
              </span>
            )}
          </React.Fragment>
        ))}
      </div>

      {/* Center: Global OmniSearch Trigger */}
      <div className="flex-1 max-w-md mx-4 hidden md:block">
        <button
          onClick={() => setOmniSearchOpen(true)}
          className="w-full flex items-center justify-between px-3 py-1.5 rounded-lg bg-slate-900/90 border border-slate-800 text-xs text-slate-400 hover:border-cyan-500/50 hover:text-slate-200 transition-colors shadow-inner"
        >
          <div className="flex items-center gap-2">
            <Search className="w-3.5 h-3.5 text-slate-400" />
            <span>Search cases, detections, rules, IPs, hosts...</span>
          </div>
          <kbd className="hidden sm:inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded bg-slate-800 text-[10px] font-mono text-slate-400 border border-slate-700">
            ⌘K
          </kbd>
        </button>
      </div>

      {/* Right Controls */}
      <div className="flex items-center gap-3">
        {/* Batch 1/2 T04-FE-01: re-read every view from the authoritative
            backend without a page load or a re-login. */}
        <button
          onClick={() => void handleReload()}
          disabled={isReloading}
          className="flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-slate-900 border border-slate-800 hover:border-cyan-500/50 hover:text-cyan-200 transition-colors text-xs font-mono text-slate-300 disabled:opacity-60"
          title="Re-read every view from the authoritative backend state"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${isReloading ? 'animate-spin text-cyan-300' : ''}`} />
          <span className="hidden sm:inline">{isReloading ? 'Reloading…' : 'Reload'}</span>
        </button>

        {/* System Health Pill */}
        <button
          onClick={() => navigate('health')}
          className="hidden lg:flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-slate-900 border border-slate-800 hover:border-slate-700 transition-colors text-xs font-mono"
          title="Click to view full System & Subsystem Health page"
        >
          <Activity className="w-3.5 h-3.5 text-emerald-400" />
          {/* Real liveness probe latency from the health subsystem row (no fabricated uptime). */}
          <span className="text-slate-300 font-semibold">
            {healthSubsystems.find(h => h.id === 'sub-api')
              ? `${healthSubsystems.find(h => h.id === 'sub-api')!.latencyMs}ms`
              : '—'}
          </span>
          {warningSubsystems.length > 0 ? (
            <span className="text-[10px] px-1 rounded bg-amber-500/20 text-amber-400 border border-amber-500/30">
              {warningSubsystems.length} Warn
            </span>
          ) : (
            <span className="text-[10px] px-1 rounded bg-emerald-500/20 text-emerald-400">
              All Healthy
            </span>
          )}
        </button>

        {/* Global Time Range */}
        <div className="flex items-center rounded-md bg-slate-900 border border-slate-800 p-0.5 text-xs font-mono">
          {(['15m', '1h', '24h', '7d'] as const).map(range => (
            <button
              key={range}
              onClick={() => setGlobalTimeRange(range)}
              className={`px-2 py-0.5 rounded transition-colors ${
                globalTimeRange === range
                  ? 'bg-slate-800 text-cyan-300 font-bold'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              {range}
            </button>
          ))}
        </div>

        {/* Error Sandbox Button */}
        <button
          onClick={() => setErrorSandboxOpen(true)}
          className="flex items-center gap-1 px-2 py-1 rounded-md bg-rose-950/40 border border-rose-500/30 text-rose-300 hover:bg-rose-900/50 transition-colors text-xs font-mono"
          title="Interactive Error Handling & Truthful UX Simulator"
        >
          <Bug className="w-3.5 h-3.5" />
          <span className="hidden sm:inline">Error Sandbox</span>
        </button>

        {/* Design Battle Blueprint Button */}
        <button
          onClick={() => navigate('design-spec')}
          className="flex items-center gap-1 px-2 py-1 rounded-md bg-cyan-950/40 border border-cyan-500/30 text-cyan-300 hover:bg-cyan-900/50 transition-colors text-xs font-mono"
          title="Open Complete Design Battle Specification (Sections A-P)"
        >
          <BookOpen className="w-3.5 h-3.5" />
          <span className="hidden md:inline">Spec A-P</span>
        </button>

        {/* Notifications Popover */}
        <div className="relative">
          <button
            onClick={() => setNotifOpen(!isNotifOpen)}
            className="relative p-1.5 rounded-md text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors"
            title="Notifications"
          >
            <Bell className="w-4 h-4" />
            {unreadNotifs.length > 0 && (
              <span className="absolute top-1 right-1 w-2 h-2 rounded-full bg-rose-500 animate-pulse" />
            )}
          </button>

          {isNotifOpen && (
            <div className="absolute right-0 mt-2 w-80 rounded-lg bg-[#0C111C] border border-slate-800 shadow-2xl p-3 z-50">
              <div className="flex items-center justify-between pb-2 border-b border-slate-800 text-xs">
                <span className="font-bold text-slate-200 font-mono">
                  NOTIFICATIONS ({unreadNotifs.length})
                </span>
                {unreadNotifs.length > 0 && (
                  <button
                    onClick={markAllNotificationsRead}
                    className="text-[10px] text-cyan-400 hover:underline"
                  >
                    Mark all read
                  </button>
                )}
              </div>

              <div className="py-2 space-y-2 max-h-72 overflow-y-auto">
                {notifications.map(notif => (
                  <div
                    key={notif.id}
                    onClick={() => {
                      setNotifOpen(false);
                      navigate(notif.linkPage as any, notif.targetId);
                    }}
                    className={`p-2 rounded cursor-pointer transition-colors text-xs ${
                      notif.read ? 'bg-slate-900/40 opacity-70 hover:opacity-100' : 'bg-slate-800/80 border border-slate-700'
                    }`}
                  >
                    <div className="flex items-center justify-between mb-1">
                      <SeverityBadge severity={notif.severity} size="sm" />
                      <span className="text-[10px] font-mono text-slate-500">
                        {formatIstTimestamp(notif.timestamp)}
                      </span>
                    </div>
                    <p className="font-semibold text-slate-200 text-xs">
                      {notif.title}
                    </p>
                    <p className="text-[11px] text-slate-400 mt-0.5">
                      {notif.description}
                    </p>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Analyst Profile (real authenticated session) */}
        <div className="flex items-center gap-2 pl-2 border-l border-slate-800">
          <div className="w-7 h-7 rounded-full bg-cyan-950 border border-cyan-500/40 flex items-center justify-center text-cyan-300 font-mono text-xs font-bold">
            {(user?.subject_id || '?').slice(0, 2).toUpperCase()}
          </div>
          <div className="hidden xl:block text-left">
            <div className="text-xs font-semibold text-slate-200 leading-tight">{user?.subject_id || 'unknown'}</div>
            <div className="text-[10px] font-mono text-slate-500 leading-tight">{user?.role || ''}</div>
          </div>
          <button
            onClick={logout}
            title="End session"
            className="ml-1 px-2 py-1 rounded text-[10px] font-mono text-slate-400 hover:text-rose-300 hover:bg-slate-800 border border-slate-800 transition-colors"
          >
            Sign out
          </button>
        </div>
      </div>
    </header>
  );
};
