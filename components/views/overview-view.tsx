"use client"

import { useMemo, useState } from "react"
import {
  AlertCircle,
  ArrowRight,
  BrainCircuit,
  CheckCircle2,
  ExternalLink,
  Flame,
  Gauge,
  Server,
  ShieldAlert,
  Siren,
  Sparkles,
  TrendingDown,
  TrendingUp,
  Wallet,
} from "lucide-react"
import { Button } from "@/components/ui/button"
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet"
import { useAppState } from "@/components/app/app-state"
import { AssetDetail } from "@/components/app/asset-detail"
import { ExposureText, LevelBadge, RiskScore, scoreBarColor, scoreColor } from "@/components/app/badges"
import { DEFAULT_BUDGET, investmentOptions } from "@/lib/investments"
import { optimizeBudget } from "@/lib/optimizer"
import { formatINR } from "@/lib/format"
import { cn } from "@/lib/utils"
import { RiskTrend } from "./overview/risk-trend"

export function OverviewView() {
  const { assessment: a, previousAssessment: p, dataset, navigate } = useAppState()
  const [selectedAssetId, setSelectedAssetId] = useState<string | null>(null)

  // 1. Highest Risk Asset (#1 rank)
  const topRisk = a.assetRisks[0]
  const selectedRisk = a.assetRisks.find((r) => r.asset.id === selectedAssetId)

  // 2. Single Most Important Recommended Action (top ROI pick)
  const optResult = useMemo(() => optimizeBudget(dataset, investmentOptions, DEFAULT_BUDGET), [dataset])
  const topAction = useMemo(() => {
    return optResult.insights
      .filter((i) => i.selected)
      .sort((x, y) => (y.marginalReduction ?? 0) - (x.marginalReduction ?? 0))[0]
  }, [optResult])

  // Delta calculation for Overall Score
  const scoreDelta = p ? a.overallScore - p.overallScore : null

  return (
    <div className="mx-auto flex max-w-5xl flex-col gap-5 pb-8">
      {/* ─────────────────────────────────────────────────────────────
          ROW 1: OVERALL RISK (1) + CRITICAL ISSUES (2)
      ───────────────────────────────────────────────────────────── */}
      <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
        {/* 1. OVERALL RISK */}
        <div className="flex flex-col justify-between rounded-xl border border-border/80 bg-card p-5 shadow-sm">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="flex size-7 items-center justify-center rounded-md bg-muted text-muted-foreground">
                <Gauge className="size-4" aria-hidden="true" />
              </span>
              <h2 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                Overall Risk Posture
              </h2>
            </div>
            <LevelBadge level={a.overallCategory} />
          </div>

          <div className="my-4 flex items-baseline gap-3">
            <span
              className={cn(
                "font-mono text-5xl font-bold tracking-tight tabular-nums",
                scoreColor(a.overallScore),
              )}
            >
              {a.overallScore}
            </span>
            <span className="text-lg font-medium text-muted-foreground">/ 100</span>

            {scoreDelta !== null ? (
              <span
                className={cn(
                  "ml-auto inline-flex items-center gap-1 rounded-md px-2 py-1 font-mono text-xs font-semibold",
                  scoreDelta > 0
                    ? "bg-destructive/10 text-destructive"
                    : scoreDelta < 0
                      ? "bg-success/10 text-success"
                      : "bg-muted text-muted-foreground",
                )}
              >
                {scoreDelta > 0 ? (
                  <TrendingUp className="size-3.5" />
                ) : scoreDelta < 0 ? (
                  <TrendingDown className="size-3.5" />
                ) : null}
                <span>
                  {scoreDelta > 0 ? "+" : ""}
                  {scoreDelta} vs baseline
                </span>
              </span>
            ) : (
              <span className="ml-auto font-mono text-xs text-muted-foreground">Baseline run</span>
            )}
          </div>

          <div>
            <div className="h-2 w-full overflow-hidden rounded-full bg-muted" aria-hidden="true">
              <div
                className={cn("h-full rounded-full transition-all duration-500", scoreBarColor(a.overallScore))}
                style={{ width: `${Math.min(100, Math.max(0, a.overallScore))}%` }}
              />
            </div>
            <div className="mt-2 flex items-center justify-between text-xs text-muted-foreground">
              <span>Status: <strong className="text-foreground">{a.overallCategory} Risk</strong></span>
              <span>{a.overallScore >= 80 ? "Critical Threshold Exceeded" : "Monitored Stable"}</span>
            </div>
          </div>
        </div>

        {/* 2. CRITICAL ISSUES */}
        <div className="flex flex-col justify-between rounded-xl border border-border/80 bg-card p-5 shadow-sm">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="flex size-7 items-center justify-center rounded-md bg-destructive/10 text-destructive">
                <AlertCircle className="size-4" aria-hidden="true" />
              </span>
              <h2 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                Critical Issues
              </h2>
            </div>
            <span className="rounded bg-muted px-2 py-0.5 font-mono text-[11px] text-muted-foreground">
              Needs Attention
            </span>
          </div>

          <div className="my-3 grid grid-cols-3 gap-2 rounded-lg bg-muted/30 p-3 text-center">
            <div>
              <span className="block font-mono text-2xl font-bold text-foreground tabular-nums">
                {a.criticalAssetCount}
              </span>
              <span className="mt-0.5 block text-[11px] text-muted-foreground">Critical Hosts</span>
            </div>
            <div className="border-x border-border/50">
              <span className="block font-mono text-2xl font-bold text-destructive tabular-nums">
                {a.openHighSeverityIncidents}
              </span>
              <span className="mt-0.5 block text-[11px] text-muted-foreground">High Incidents</span>
            </div>
            <div>
              <span className="block font-mono text-2xl font-bold text-foreground tabular-nums">
                {a.openVulnerabilityCount}
              </span>
              <span className="mt-0.5 block text-[11px] text-muted-foreground">Open Findings</span>
            </div>
          </div>

          <div className="flex items-center justify-between border-t border-border/50 pt-2.5 text-xs">
            <span className="text-muted-foreground">
              {a.openHighSeverityIncidents > 0
                ? "Active security incidents require containment"
                : "No uncontained high incidents"}
            </span>
            <Button
              variant="ghost"
              size="sm"
              onClick={() => navigate("explorer")}
              className="h-7 gap-1 px-2 text-xs text-foreground hover:text-primary"
            >
              Explorer <ArrowRight className="size-3" />
            </Button>
          </div>
        </div>
      </div>

      {/* ─────────────────────────────────────────────────────────────
          ROW 2: HIGHEST RISK ASSET (3) + RECOMMENDED ACTION (5)
      ───────────────────────────────────────────────────────────── */}
      <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
        {/* 3. HIGHEST RISK ASSET */}
        {topRisk ? (
          <div className="flex flex-col justify-between rounded-xl border border-destructive/30 bg-card p-5 shadow-sm">
            <div>
              <div className="flex items-center justify-between border-b border-border/60 pb-3">
                <div className="flex items-center gap-2">
                  <span className="flex size-6 items-center justify-center rounded bg-destructive/15 font-mono text-xs font-bold text-destructive">
                    #1
                  </span>
                  <h2 className="text-xs font-semibold uppercase tracking-wider text-destructive">
                    Highest Risk Asset
                  </h2>
                </div>
                <LevelBadge level={topRisk.category} />
              </div>

              <div className="mt-3.5">
                <div className="flex items-start justify-between gap-2">
                  <div>
                    <h3 className="text-base font-bold text-foreground">{topRisk.asset.name}</h3>
                    <p className="mt-0.5 text-xs text-muted-foreground">
                      {topRisk.asset.type} · Managed by {topRisk.asset.owner}
                    </p>
                  </div>
                  <RiskScore score={topRisk.score} />
                </div>

                <div className="mt-3 flex flex-wrap items-center gap-2 text-xs">
                  <span className="text-muted-foreground">Exposure:</span>
                  <ExposureText exposure={topRisk.asset.exposure} />
                  <span className="text-muted-foreground">·</span>
                  <span className="font-mono text-foreground font-medium">
                    {topRisk.asset.openVulnerabilityCount} findings
                  </span>
                  <span className="text-muted-foreground">·</span>
                  <span className="text-destructive font-mono font-medium">
                    {topRisk.asset.openHighSeverityIncidents} active incident{topRisk.asset.openHighSeverityIncidents === 1 ? "" : "s"}
                  </span>
                </div>

                {topRisk.nextAction ? (
                  <div className="mt-3 rounded-md bg-muted/40 p-2.5 text-xs text-muted-foreground">
                    <strong className="text-foreground">Immediate action:</strong> {topRisk.nextAction}
                  </div>
                ) : null}
              </div>
            </div>

            <div className="mt-4 flex items-center gap-2 border-t border-border/60 pt-3">
              <Button
                variant="default"
                size="sm"
                onClick={() => navigate("analyst", topRisk.asset.id)}
                className="flex-1 gap-1.5 text-xs font-medium"
              >
                <BrainCircuit className="size-3.5 text-primary-foreground" aria-hidden="true" />
                Investigate in AI Analyst
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={() => setSelectedAssetId(topRisk.asset.id)}
                className="gap-1.5 text-xs"
              >
                <ExternalLink className="size-3.5" aria-hidden="true" />
                View Details
              </Button>
            </div>
          </div>
        ) : null}

        {/* 5. RECOMMENDED ACTION (Single Priority Action) */}
        {topAction ? (
          <div className="flex flex-col justify-between rounded-xl border border-primary/30 bg-card p-5 shadow-sm">
            <div>
              <div className="flex items-center justify-between border-b border-border/60 pb-3">
                <div className="flex items-center gap-2">
                  <span className="flex size-6 items-center justify-center rounded bg-primary/15 text-primary">
                    <Sparkles className="size-3.5" aria-hidden="true" />
                  </span>
                  <h2 className="text-xs font-semibold uppercase tracking-wider text-primary">
                    Top Recommended Action
                  </h2>
                </div>
                <span className="rounded bg-primary/10 px-2 py-0.5 font-mono text-[11px] font-semibold text-primary">
                  Highest ROI
                </span>
              </div>

              <div className="mt-3.5">
                <h3 className="text-base font-bold text-foreground">{topAction.option.name}</h3>
                <p className="mt-1 text-xs text-muted-foreground leading-relaxed">
                  {topAction.option.description}
                </p>

                <div className="mt-3.5 grid grid-cols-3 gap-2 rounded-lg bg-muted/30 p-2.5 text-center text-xs">
                  <div>
                    <span className="block text-[10px] uppercase tracking-wider text-muted-foreground">Impact</span>
                    <span className="font-mono font-bold text-success">
                      −{(((topAction.marginalReduction ?? 0) / optResult.proposed.baselineExposure) * 100).toFixed(1)}%
                    </span>
                  </div>
                  <div className="border-x border-border/50">
                    <span className="block text-[10px] uppercase tracking-wider text-muted-foreground">Cost</span>
                    <span className="font-mono font-semibold text-foreground">
                      {formatINR(topAction.option.cost)}
                    </span>
                  </div>
                  <div>
                    <span className="block text-[10px] uppercase tracking-wider text-muted-foreground">Effort</span>
                    <span className="font-medium text-foreground">{topAction.option.effort}</span>
                  </div>
                </div>
              </div>
            </div>

            <div className="mt-4 flex items-center justify-between border-t border-border/60 pt-3">
              <span className="text-xs text-muted-foreground">
                Overall score will drop:{" "}
                <strong className="font-mono text-success">
                  {optResult.proposed.baselineOverall} → {optResult.proposed.residualOverall}
                </strong>
              </span>
              <Button
                variant="ghost"
                size="sm"
                onClick={() => navigate("investments")}
                className="gap-1 text-xs text-primary hover:text-primary px-2"
              >
                Open Optimizer
                <ArrowRight className="size-3" />
              </Button>
            </div>
          </div>
        ) : null}
      </div>

      {/* ─────────────────────────────────────────────────────────────
          ROW 3: RISK TREND (4)
      ───────────────────────────────────────────────────────────── */}
      <section aria-label="Seven-Day Risk Trend">
        <RiskTrend />
      </section>

      {/* ─────────────────────────────────────────────────────────────
          PROGRESSIVE DISCLOSURE: ASSET DETAIL DRAWER
      ───────────────────────────────────────────────────────────── */}
      <Sheet open={!!selectedRisk} onOpenChange={(open) => !open && setSelectedAssetId(null)}>
        <SheetContent className="w-full overflow-y-auto sm:max-w-lg">
          {selectedRisk ? (
            <>
              <SheetHeader className="border-b pb-4">
                <SheetTitle className="text-base font-bold text-foreground">
                  {selectedRisk.asset.name}
                </SheetTitle>
                <SheetDescription className="text-xs text-muted-foreground">
                  Detailed risk factors, control checks, and vulnerability findings.
                </SheetDescription>
              </SheetHeader>
              <div className="px-4 pb-6 pt-4">
                <AssetDetail risk={selectedRisk} />
              </div>
            </>
          ) : null}
        </SheetContent>
      </Sheet>
    </div>
  )
}
