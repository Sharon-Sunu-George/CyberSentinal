"use client"

import { useDeferredValue, useMemo, useState } from "react"
import { ArrowLeft, ArrowRight, FileSearch, RotateCcw, Search } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet"
import { useAppState } from "@/components/app/app-state"
import { AssetRiskTable } from "@/components/app/asset-risk-table"
import { AssetDetail } from "@/components/app/asset-detail"
import { ActivityList } from "@/components/app/activity-list"
import { LevelBadge } from "@/components/app/badges"
import { Panel } from "@/components/app/panel"
import { SummaryCards } from "./overview/summary-cards"
import { RiskDistribution } from "./overview/risk-distribution"
import { RiskTrend } from "./overview/risk-trend"
import { TopRecommendations } from "./overview/top-recommendations"

export function OverviewView() {
  const { assessment, gaps, activity, navigate, activeReport, restoreBaseline, goBack, history } = useAppState()
  const [query, setQuery] = useState("")
  const deferredQuery = useDeferredValue(query)
  const [selected, setSelected] = useState<string | null>(null)

  const filtered = useMemo(() => {
    const q = deferredQuery.trim().toLowerCase()
    if (!q) return assessment.assetRisks
    return assessment.assetRisks.filter(
      (r) =>
        r.asset.name.toLowerCase().includes(q) ||
        r.asset.type.toLowerCase().includes(q) ||
        r.asset.owner.toLowerCase().includes(q),
    )
  }, [assessment.assetRisks, deferredQuery])

  const selectedRisk = assessment.assetRisks.find((r) => r.asset.id === selected)

  return (
    <div className="flex flex-col gap-4">
      {/* Active Ingested Security Scan Notice */}
      {activeReport ? (
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 rounded-lg border border-primary/30 bg-primary/10 p-3.5 text-xs">
          <div className="flex items-center gap-2.5">
            <span className="flex size-7 shrink-0 items-center justify-center rounded-md bg-primary text-primary-foreground font-semibold">
              <FileSearch className="size-4" />
            </span>
            <div>
              <div className="flex flex-wrap items-center gap-2">
                <p className="font-semibold text-foreground">
                  Active Security Scan: <span className="font-mono">{activeReport.filename || activeReport.report_id}</span> ({activeReport.target})
                </p>
                <span className="rounded bg-emerald-500/15 border border-emerald-500/30 px-1.5 py-0.2 font-mono text-[10px] text-emerald-600 dark:text-emerald-400 font-semibold">
                  {activeReport.analysis_status || "COMPLETED"}
                </span>
                {activeReport.detected_format && (
                  <span className="rounded bg-muted border px-1.5 py-0.2 font-mono text-[10px] text-muted-foreground">
                    {activeReport.detected_format}
                  </span>
                )}
              </div>
              <p className="text-[11px] text-muted-foreground mt-0.5">
                Displaying live parsed findings: <strong className="text-destructive">{activeReport.summary.critical} Critical</strong>, <strong className="text-orange-500">{activeReport.summary.high} High</strong>, <strong className="text-warning">{activeReport.summary.medium} Medium</strong>, <strong className="text-blue-500">{activeReport.summary.low} Low</strong> ({activeReport.summary.total_findings} total findings).
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            <Button
              variant="outline"
              size="sm"
              className="h-7 text-xs"
              onClick={() => navigate("report-upload")}
            >
              Upload New Report
            </Button>
            <Button
              variant="ghost"
              size="sm"
              className="h-7 text-xs text-muted-foreground hover:text-foreground"
              onClick={restoreBaseline}
            >
              <RotateCcw className="size-3 mr-1" />
              Restore Demo Estate
            </Button>
          </div>
        </div>
      ) : (
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 rounded-lg border border-border bg-card/60 p-3.5 text-xs">
          <div className="flex items-center gap-2.5">
            <span className="flex size-7 shrink-0 items-center justify-center rounded-md bg-muted text-muted-foreground font-semibold">
              <FileSearch className="size-4" />
            </span>
            <div>
              <p className="font-semibold text-foreground">
                Baseline Demonstration Estate Active
              </p>
              <p className="text-[11px] text-muted-foreground">
                Upload a structured report (CSV, JSON), Word document (DOCX), PDF, or image to ingest live scan findings and compute real FAIR risk metrics.
              </p>
            </div>
          </div>
          <Button
            size="sm"
            className="h-7 text-xs shrink-0"
            onClick={() => navigate("report-upload")}
          >
            Upload New Report
          </Button>
        </div>
      )}

      <SummaryCards />

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
        <RiskTrend className="xl:col-span-2" />
        <RiskDistribution />
      </div>

      <Panel
        title="Prioritised asset risk"
        description="Ranked by the shared risk model. Select an asset for its score breakdown."
        bodyClassName="p-0"
        action={
          <div className="relative w-44 sm:w-60">
            <Search
              className="pointer-events-none absolute top-1/2 left-2.5 size-3.5 -translate-y-1/2 text-muted-foreground"
              aria-hidden="true"
            />
            <Input
              type="search"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search assets…"
              aria-label="Search assets"
              className="h-8 pl-8 text-xs"
            />
          </div>
        }
      >
        <div className="px-2">
          <AssetRiskTable risks={filtered} onSelect={setSelected} selectedId={selected} />
        </div>
      </Panel>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <TopRecommendations />

        <Panel
          title="Security gaps"
          description="Highest-urgency control weaknesses."
          action={
            <Button variant="ghost" size="sm" onClick={() => navigate("gaps")}>
              All gaps
              <ArrowRight aria-hidden="true" />
            </Button>
          }
          bodyClassName="p-0"
        >
          <ul className="divide-y">
            {gaps.slice(0, 5).map((g) => (
              <li key={g.id}>
                <button
                  type="button"
                  onClick={() => navigate("gaps")}
                  className="flex w-full items-center gap-3 px-4 py-2.5 text-left hover:bg-muted/40 focus-visible:outline-2 focus-visible:outline-ring"
                >
                  <span className="min-w-0 flex-1">
                    <span className="block truncate text-sm text-foreground">{g.title}</span>
                    <span className="block text-xs text-muted-foreground">
                      {g.affectedAssets.length} asset{g.affectedAssets.length === 1 ? "" : "s"} · urgency{" "}
                      <span className="font-mono tabular-nums">{g.urgencyScore}</span>
                    </span>
                  </span>
                  <LevelBadge level={g.severity} />
                </button>
              </li>
            ))}
          </ul>
        </Panel>

        <Panel
          title="Recent activity"
          description="Simulated events."
          action={
            <Button variant="ghost" size="sm" onClick={() => navigate("activity")}>
              Log
              <ArrowRight aria-hidden="true" />
            </Button>
          }
          bodyClassName="py-0"
        >
          <ActivityList events={activity.slice(0, 4)} compact />
        </Panel>
      </div>

      <Sheet open={!!selectedRisk} onOpenChange={(o) => !o && setSelected(null)}>
        <SheetContent className="w-full overflow-y-auto sm:max-w-lg">
          {selectedRisk ? (
            <>
              <SheetHeader className="border-b">
                <SheetTitle>{selectedRisk.asset.name}</SheetTitle>
                <SheetDescription>Risk breakdown from the simulated dataset.</SheetDescription>
              </SheetHeader>
              <div className="px-4 pb-6">
                <AssetDetail risk={selectedRisk} />
              </div>
            </>
          ) : null}
        </SheetContent>
      </Sheet>
    </div>
  )
}
