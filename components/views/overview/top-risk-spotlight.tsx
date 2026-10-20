"use client"

import { useMemo } from "react"
import { AlertTriangle, ArrowRight, BrainCircuit, ExternalLink, Flame, ShieldAlert, Sparkles } from "lucide-react"
import { Button } from "@/components/ui/button"
import { cn } from "@/lib/utils"
import type { AssetRisk, RiskFactor } from "@/lib/types"
import { ExposureText, LevelBadge, RiskScore } from "@/components/app/badges"

const FACTOR_LABEL_MAP: Record<string, string> = {
  threat: "Threat Intelligence & Targeting",
  controls: "Security Control Deficiencies",
  exposure: "Network Attack Surface",
  vulnerability: "Vulnerability Severity & CVSS",
  criticality: "Business Asset Criticality",
  incidents: "Active Incident Activity",
}

interface TopRiskSpotlightProps {
  topRisk?: AssetRisk
  onSelectAsset: (assetId: string) => void
  onInvestigateAI: (assetId: string) => void
}

export function TopRiskSpotlight({
  topRisk,
  onSelectAsset,
  onInvestigateAI,
}: TopRiskSpotlightProps) {
  if (!topRisk) return null

  const { asset, score, category, factors, rank, openVulns } = topRisk

  // Sort factors by contribution points descending and take top 4
  const topDrivers = useMemo(() => {
    return factors
      .slice()
      .sort((a, b) => b.contribution - a.contribution)
      .slice(0, 4)
  }, [factors])

  const maxContribution = Math.max(...factors.map((f) => f.weight * 100), 1)

  return (
    <section aria-label="Top Risk Spotlight and Key Drivers" className="grid grid-cols-1 gap-4 lg:grid-cols-12">
      {/* LEFT: TOP RISK (7 cols on lg) */}
      <div className="flex flex-col justify-between rounded-lg border border-border/80 bg-card p-5 shadow-sm lg:col-span-7">
        <div>
          {/* Header Badge & Rank */}
          <div className="flex items-center justify-between gap-2 border-b border-border/60 pb-3">
            <div className="flex items-center gap-2">
              <span className="flex size-6 items-center justify-center rounded bg-destructive/15 text-destructive font-mono text-xs font-bold">
                #{rank}
              </span>
              <span className="text-xs font-semibold uppercase tracking-wider text-destructive">
                Highest Risk Exposure
              </span>
            </div>
            <div className="flex items-center gap-2">
              <LevelBadge level={category} />
            </div>
          </div>

          {/* Asset Title & Score */}
          <div className="mt-4 flex flex-wrap items-start justify-between gap-4">
            <div className="min-w-0 flex-1">
              <h3 className="text-lg font-bold tracking-tight text-foreground sm:text-xl truncate">
                {asset.name}
              </h3>
              <p className="mt-0.5 text-xs text-muted-foreground">
                {asset.type} · Managed by <span className="text-foreground">{asset.owner}</span>
              </p>
            </div>
            <div className="flex flex-col items-end">
              <span className="text-[10px] font-medium uppercase tracking-wider text-muted-foreground">
                Risk Score
              </span>
              <RiskScore score={score} className="scale-105 origin-right" />
            </div>
          </div>

          {/* Quick Stats Grid */}
          <div className="mt-4 grid grid-cols-2 gap-3 rounded-md border border-border/60 bg-muted/20 p-3 sm:grid-cols-4">
            <div>
              <span className="block text-[11px] text-muted-foreground">Criticality</span>
              <div className="mt-1">
                <LevelBadge level={asset.criticality} />
              </div>
            </div>
            <div>
              <span className="block text-[11px] text-muted-foreground">Exposure</span>
              <div className="mt-1 font-medium">
                <ExposureText exposure={asset.exposure} />
              </div>
            </div>
            <div>
              <span className="block text-[11px] text-muted-foreground">Open Findings</span>
              <span className="mt-1 block font-mono text-sm font-semibold tabular-nums text-foreground">
                {asset.openVulnerabilityCount}
              </span>
            </div>
            <div>
              <span className="block text-[11px] text-muted-foreground">High Incidents</span>
              <span
                className={cn(
                  "mt-1 block font-mono text-sm font-semibold tabular-nums",
                  asset.openHighSeverityIncidents > 0 ? "text-destructive" : "text-foreground",
                )}
              >
                {asset.openHighSeverityIncidents}
              </span>
            </div>
          </div>

          {/* Top Recommendation snippet for this asset */}
          {topRisk.nextAction ? (
            <div className="mt-3.5 flex items-start gap-2 rounded-md bg-muted/30 px-3 py-2 text-xs text-muted-foreground">
              <Flame className="size-4 shrink-0 text-high mt-0.5" aria-hidden="true" />
              <p className="line-clamp-2">
                <strong className="text-foreground">Next Action:</strong> {topRisk.nextAction}
              </p>
            </div>
          ) : null}
        </div>

        {/* Action Buttons */}
        <div className="mt-5 flex flex-wrap items-center gap-2.5 border-t border-border/60 pt-4">
          <Button
            variant="default"
            size="sm"
            onClick={() => onInvestigateAI(asset.id)}
            className="flex-1 sm:flex-initial gap-1.5 font-medium"
          >
            <BrainCircuit className="size-3.5 text-primary-foreground" aria-hidden="true" />
            Investigate with AI Analyst
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={() => onSelectAsset(asset.id)}
            className="flex-1 sm:flex-initial gap-1.5"
          >
            <ExternalLink className="size-3.5" aria-hidden="true" />
            View Details
          </Button>
        </div>
      </div>

      {/* RIGHT: WHY THIS RISK (5 cols on lg) */}
      <div className="flex flex-col justify-between rounded-lg border border-border/80 bg-card p-5 shadow-sm lg:col-span-5">
        <div>
          <div className="flex items-center justify-between border-b border-border/60 pb-3">
            <div className="flex items-center gap-2">
              <span className="flex size-6 items-center justify-center rounded bg-primary/15 text-primary">
                <Sparkles className="size-3.5" aria-hidden="true" />
              </span>
              <h2 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                Why This Risk?
              </h2>
            </div>
            <span className="font-mono text-[11px] text-muted-foreground">
              Top Score Drivers
            </span>
          </div>

          {/* Drivers List */}
          <ul className="mt-3 flex flex-col divide-y divide-border/40">
            {topDrivers.map((driver: RiskFactor) => {
              const friendlyLabel = FACTOR_LABEL_MAP[driver.key] || driver.label
              const maxPts = Math.round(driver.weight * 100)
              const pctOfMax = Math.min(100, Math.round((driver.contribution / maxPts) * 100))

              return (
                <li key={driver.key} className="py-2.5 first:pt-1 last:pb-1">
                  <div className="flex items-center justify-between gap-2 text-xs">
                    <span className="font-medium text-foreground">{friendlyLabel}</span>
                    <span className="font-mono text-[11px] tabular-nums text-muted-foreground">
                      <span className="font-semibold text-foreground">+{driver.contribution}</span> / {maxPts} pts
                    </span>
                  </div>

                  {/* Progress bar */}
                  <div className="mt-1.5 h-1.5 w-full overflow-hidden rounded-full bg-muted" aria-hidden="true">
                    <div
                      className={cn(
                        "h-full rounded-full transition-all duration-500",
                        pctOfMax >= 75
                          ? "bg-destructive"
                          : pctOfMax >= 50
                            ? "bg-high"
                            : pctOfMax >= 25
                              ? "bg-warning"
                              : "bg-success",
                      )}
                      style={{ width: `${Math.max(8, pctOfMax)}%` }}
                    />
                  </div>

                  <p className="mt-1 text-[11px] leading-relaxed text-muted-foreground text-pretty">
                    {driver.detail}
                  </p>
                </li>
              )
            })}
          </ul>
        </div>

        <div className="mt-4 border-t border-border/60 pt-3 text-[11px] text-muted-foreground">
          Calculated by multi-factor risk model across asset telemetry, threat intel, and control postures.
        </div>
      </div>
    </section>
  )
}
