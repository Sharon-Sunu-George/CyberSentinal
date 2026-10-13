"use client"

import { Bug, Gauge, Server, Siren, TrendingDown, TrendingUp, type LucideIcon } from "lucide-react"
import { cn } from "@/lib/utils"
import { useAppState } from "@/components/app/app-state"
import { LevelBadge, scoreBarColor, scoreColor } from "@/components/app/badges"

function Delta({ value, invert = false }: { value: number; invert?: boolean }) {
  if (value === 0) {
    return <span className="text-muted-foreground font-mono text-xs">0 vs baseline</span>
  }
  const worse = invert ? value < 0 : value > 0
  const Icon = worse ? TrendingUp : TrendingDown
  return (
    <span className={cn("inline-flex items-center gap-1 font-mono text-xs font-medium", worse ? "text-destructive" : "text-success")}>
      <Icon className="size-3.5" aria-hidden="true" />
      <span>
        {value > 0 ? "+" : ""}
        {value} vs last run
      </span>
    </span>
  )
}

export function SummaryCards() {
  const { assessment: a, previousAssessment: p } = useAppState()

  return (
    <section aria-label="Security Posture Overview" className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
      {/* Dominant KPI: Overall Risk Score */}
      <div className="relative flex flex-col justify-between overflow-hidden rounded-lg border border-border/80 bg-card p-4 sm:col-span-2 lg:col-span-1 shadow-sm">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <span className="flex size-7 items-center justify-center rounded-md bg-muted text-muted-foreground">
              <Gauge className="size-4" aria-hidden="true" />
            </span>
            <span className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
              Overall Risk Score
            </span>
          </div>
          <LevelBadge level={a.overallCategory} />
        </div>

        <div className="my-3 flex items-baseline gap-2">
          <span className={cn("font-mono text-4xl font-bold tracking-tight tabular-nums", scoreColor(a.overallScore))}>
            {a.overallScore}
          </span>
          <span className="text-sm font-medium text-muted-foreground">/100</span>
        </div>

        <div className="flex flex-col gap-2">
          <div className="h-2 w-full overflow-hidden rounded-full bg-muted" aria-hidden="true">
            <div
              className={cn("h-full rounded-full transition-all duration-500", scoreBarColor(a.overallScore))}
              style={{ width: `${Math.min(100, Math.max(0, a.overallScore))}%` }}
            />
          </div>
          <div className="flex items-center justify-between text-xs text-muted-foreground">
            {p ? (
              <Delta value={a.overallScore - p.overallScore} />
            ) : (
              <span className="text-muted-foreground font-mono text-xs">Baseline assessment</span>
            )}
            <span className="text-[11px] text-muted-foreground">
              {a.overallScore >= 80 ? "Critical Action Needed" : a.overallScore >= 60 ? "Elevated Risk" : "Stable"}
            </span>
          </div>
        </div>
      </div>

      {/* Critical Assets Card */}
      <div className="flex flex-col justify-between rounded-lg border border-border/80 bg-card p-4 shadow-sm">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <span className="flex size-7 items-center justify-center rounded-md bg-muted text-muted-foreground">
              <Server className="size-4" aria-hidden="true" />
            </span>
            <span className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
              Critical Assets
            </span>
          </div>
          <span className="rounded bg-muted px-1.5 py-0.5 font-mono text-[10px] text-muted-foreground">
            Tier 1
          </span>
        </div>

        <div className="my-3">
          <span className="font-mono text-3xl font-bold tracking-tight tabular-nums text-foreground">
            {a.criticalAssetCount}
          </span>
          <span className="ml-2 text-xs text-muted-foreground">monitored hosts</span>
        </div>

        <div className="border-t border-border/50 pt-2 text-xs text-muted-foreground">
          <span>Business criticality: </span>
          <span className="font-medium text-foreground">Critical</span>
        </div>
      </div>

      {/* Open Vulnerabilities Card */}
      <div className="flex flex-col justify-between rounded-lg border border-border/80 bg-card p-4 shadow-sm">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <span className="flex size-7 items-center justify-center rounded-md bg-muted text-muted-foreground">
              <Bug className="size-4" aria-hidden="true" />
            </span>
            <span className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
              Open Vulnerabilities
            </span>
          </div>
        </div>

        <div className="my-3">
          <span className="font-mono text-3xl font-bold tracking-tight tabular-nums text-foreground">
            {a.openVulnerabilityCount}
          </span>
          <span className="ml-2 text-xs text-muted-foreground">active findings</span>
        </div>

        <div className="border-t border-border/50 pt-2 text-xs">
          {p ? (
            <Delta value={a.openVulnerabilityCount - p.openVulnerabilityCount} />
          ) : (
            <span className="text-muted-foreground">Across all asset inventory</span>
          )}
        </div>
      </div>

      {/* Open High-Severity Incidents Card */}
      <div className="flex flex-col justify-between rounded-lg border border-border/80 bg-card p-4 shadow-sm">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <span className="flex size-7 items-center justify-center rounded-md bg-destructive/10 text-destructive">
              <Siren className="size-4" aria-hidden="true" />
            </span>
            <span className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
              High Incidents
            </span>
          </div>
          {a.openHighSeverityIncidents > 0 ? (
            <span className="inline-flex size-2 rounded-full bg-destructive animate-pulse" aria-hidden="true" />
          ) : null}
        </div>

        <div className="my-3">
          <span
            className={cn(
              "font-mono text-3xl font-bold tracking-tight tabular-nums",
              a.openHighSeverityIncidents > 0 ? "text-destructive" : "text-foreground",
            )}
          >
            {a.openHighSeverityIncidents}
          </span>
          <span className="ml-2 text-xs text-muted-foreground">uncontained</span>
        </div>

        <div className="border-t border-border/50 pt-2 text-xs">
          {p ? (
            <Delta value={a.openHighSeverityIncidents - p.openHighSeverityIncidents} />
          ) : (
            <span className="text-muted-foreground">Awaiting active containment</span>
          )}
        </div>
      </div>
    </section>
  )
}
