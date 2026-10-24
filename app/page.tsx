"use client"

import { AppStateProvider, useAppState } from "@/components/app/app-state"
import { Sidebar } from "@/components/app/sidebar"
import { Topbar } from "@/components/app/topbar"
import { OverviewView } from "@/components/views/overview-view"
import { ExplorerView } from "@/components/views/explorer-view"
import { AnalystView } from "@/components/views/analyst-view"
import { InvestmentsView } from "@/components/views/investments-view"
import { GapsView } from "@/components/views/gaps-view"
import { ActivityView } from "@/components/views/activity-view"
import { SettingsView } from "@/components/views/settings-view"

function DashboardContent() {
  const { view } = useAppState()

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
//https://v0.app/chat/iFBZ1tSbucK