"use client"

import { AppStateProvider, useAppState } from "@/components/app/app-state"
import { Sidebar } from "@/components/app/sidebar"
import { Topbar } from "@/components/app/topbar"
import { LandingView } from "@/components/views/landing-view"
import { RiskAssessmentView } from "@/components/views/risk-assessment-view"
import { OverviewView } from "@/components/views/overview-view"
import { ExplorerView } from "@/components/views/explorer-view"
import { AnalystView } from "@/components/views/analyst-view"
import { InvestmentsView } from "@/components/views/investments-view"
import { GapsView } from "@/components/views/gaps-view"
import { ActivityView } from "@/components/views/activity-view"
import { ReportUploadView } from "@/components/views/report-upload-view"
import { ReportAnalysisView } from "@/components/views/report-analysis-view"
import { AgentSimulationView } from "@/components/views/agent-simulation-view"
import { SettingsView } from "@/components/views/settings-view"

function DashboardContent() {
  const { view } = useAppState()

  // Minimal entry layout: render without sidebar or topbar
  if (
    view === "landing" ||
    view === "risk-assessment" ||
    view === "report-upload" ||
    view === "report-analysis" ||
    view === "agent-simulation"
  ) {
    return (
      <main className="min-h-svh w-full bg-background text-foreground">
        {view === "landing" && <LandingView />}
        {view === "risk-assessment" && <RiskAssessmentView />}
        {view === "report-upload" && <ReportUploadView />}
        {view === "report-analysis" && <ReportAnalysisView />}
        {view === "agent-simulation" && <AgentSimulationView />}
      </main>
    )
  }

  // Dashboard layout: render with full sidebar and topbar
  return (
    <div className="flex min-h-svh bg-background text-foreground">
      <Sidebar />
      <div className="flex min-w-0 flex-1 flex-col">
        <Topbar />
        <main className="flex-1 p-4 lg:p-6">
          {view === "overview" && <OverviewView />}
          {view === "explorer" && <ExplorerView />}
          {view === "analyst" && <AnalystView />}
          {view === "investments" && <InvestmentsView />}
          {view === "gaps" && <GapsView />}
          {view === "activity" && <ActivityView />}
          {view === "settings" && <SettingsView />}
        </main>
      </div>
    </div>
  )
}

export default function Home() {
  return (
    <AppStateProvider>
      <DashboardContent />
    </AppStateProvider>
  )
}
