import React from 'react';
import { useSoc } from '../../context/SocContext';
import { Sidebar } from './Sidebar';
import { TopBar } from './TopBar';
import { ToastContainer } from '../common/ToastContainer';

// Pages
import { OverviewPage } from '../pages/OverviewPage';
import { IncidentsPage } from '../pages/IncidentsPage';
import { CaseDetailPage } from '../pages/CaseDetailPage';
import { DetectionsPage } from '../pages/DetectionsPage';
import { CorrelationsPage } from '../pages/CorrelationsPage';
import { TimelinePage } from '../pages/TimelinePage';
import { SourcesPage } from '../pages/SourcesPage';
import { RulesPage } from '../pages/RulesPage';
import { CapabilitiesPage } from '../pages/CapabilitiesPage';
import { EvidencePage } from '../pages/EvidencePage';
import { DatasetsPage } from '../pages/DatasetsPage';
import { LearningPage } from '../pages/LearningPage';
import { GuidePage } from '../pages/GuidePage';
import { HealthPage } from '../pages/HealthPage';
import { DesignBattleDeliverable } from '../design-deliverable/DesignBattleDeliverable';

// Global Modals & Drawers
import { OmniSearchModal } from '../modals/OmniSearchModal';
import { AddSourceModal } from '../modals/AddSourceModal';
import { AddRuleModal } from '../modals/AddRuleModal';
import { CloseCaseModal } from '../modals/CloseCaseModal';
import { CentralizedAnalysisModal } from '../investigation/CentralizedAnalysisModal';
import { ReportGeneratorModal } from '../investigation/ReportGeneratorModal';
import { ErrorSimulationSandbox } from '../modals/ErrorSimulationSandbox';
import { TechnicalPayloadDrawer } from '../modals/TechnicalPayloadDrawer';

export const Shell: React.FC = () => {
  const { currentPage } = useSoc();

  const renderCurrentPage = () => {
    switch (currentPage) {
      case 'overview':
        return <OverviewPage />;
      case 'incidents':
        return <IncidentsPage />;
      case 'case-detail':
        return <CaseDetailPage />;
      case 'detections':
        return <DetectionsPage />;
      case 'correlations':
        return <CorrelationsPage />;
      case 'timeline':
        return <TimelinePage />;
      case 'sources':
        return <SourcesPage />;
      case 'rules':
        return <RulesPage />;
      case 'capabilities':
        return <CapabilitiesPage />;
      case 'evidence':
        return <EvidencePage />;
      case 'datasets':
        return <DatasetsPage />;
      case 'learning':
        return <LearningPage />;
      case 'guide':
        return <GuidePage />;
      case 'health':
        return <HealthPage />;
      case 'design-spec':
        return <DesignBattleDeliverable />;
      default:
        return <OverviewPage />;
    }
  };

  return (
    <div className="flex h-screen w-screen overflow-hidden bg-[#0B0F17] text-slate-100 selection:bg-cyan-500/30 selection:text-cyan-200">
      {/* Left Application Sidebar */}
      <Sidebar />

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0 h-full overflow-hidden">
        <TopBar />

        {/* Scrollable Page Body */}
        <main className="flex-1 overflow-y-auto px-4 md:px-6 py-5 bg-[#0B0F17]">
          <div className="max-w-7xl mx-auto">
            {renderCurrentPage()}
          </div>
        </main>
      </div>

      {/* Global Modals & Overlay Drawers */}
      <OmniSearchModal />
      <AddSourceModal />
      <AddRuleModal />
      <CloseCaseModal />
      <CentralizedAnalysisModal />
      <ReportGeneratorModal />
      <ErrorSimulationSandbox />
      <TechnicalPayloadDrawer />
      <ToastContainer />
    </div>
  );
};
