import { Bug, DollarSign, Gauge, Percent, Server, ShieldCheck, Siren, TrendingDown, type LucideIcon } from "lucide-react"
import { cn } from "@/lib/utils"
import { useAppState } from "@/components/app/app-state"
import { LevelBadge, scoreBarColor, scoreColor } from "@/components/app/badges"
import { formatCurrency } from "@/lib/format"

function Delta({ value, invert = false }: { value: number; invert?: boolean }) {
  if (value === 0) return <span className="text-muted-foreground">no change</span>
  const worse = invert ? value < 0 : value > 0
  return (
    <span className={worse ? "text-destructive" : "text-success"}>
      {value > 0 ? "+" : ""}
      {value} since last run
    </span>
  )
}

function DeltaCurrency({ current, previous }: { current: number; previous?: number }) {
  if (previous === undefined) return <span className="text-muted-foreground">Baseline quantified</span>
  const diff = current - previous
  if (diff === 0) return <span className="text-muted-foreground">no change since last run</span>
  return (
    <span className={diff > 0 ? "text-destructive" : "text-success"}>
      {diff > 0 ? "+" : ""}
      {formatCurrency(diff)} since last run
    </span>
  )
}

function Card({
  label,
  icon: Icon,
  children,
  footer,
}: {
  label: string
  icon: LucideIcon
  children: React.ReactNode
  footer: React.ReactNode
}) {
  return (
    <div className="flex flex-col gap-3 rounded-lg border bg-card p-4">
      <div className="flex items-center justify-between">
        <span className="text-xs font-medium text-muted-foreground">{label}</span>
        <Icon className="size-4 text-muted-foreground" aria-hidden="true" />
      </div>
      <div className="flex items-baseline gap-2">{children}</div>
      <div className="text-xs">{footer}</div>
    </div>
  )
}

export function SummaryCards() {
  const { assessment: a, previousAssessment: p } = useAppState()
  const b = a.backendResult
  const pb = p?.backendResult

  return (
    <div className="flex flex-col gap-4">
      {/* FAIR Quantitative Financial Risk Metrics */}
      {b && (
        <div className="flex flex-col gap-3 rounded-lg border border-primary/20 bg-primary/5 p-4">
          <div className="flex flex-wrap items-center justify-between gap-2 border-b border-primary/10 pb-3">
            <div className="flex items-center gap-2">
              <span className="flex size-2 rounded-full bg-emerald-500 animate-pulse" />
              <span className="text-xs font-semibold text-foreground">
                FAIR Financial Risk Quantification
              </span>
              <span className="text-xs text-muted-foreground">
                · {b.asset_name}
              </span>
            </div>
            <span className="text-[11px] font-mono text-muted-foreground truncate max-w-md">
              {b.scenario_name}
            </span>
          </div>

          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4">
            <Card
              label="Annual Loss Expectancy (ALE)"
              icon={DollarSign}
              footer={
                <div className="flex flex-col gap-1">
                  <DeltaCurrency
                    current={b.metrics.annual_loss_expectancy}
                    previous={pb?.metrics.annual_loss_expectancy}
                  />
                  <span className="text-[11px] text-muted-foreground">
                    SLE: {formatCurrency(b.metrics.single_loss_expectancy)} · LEF: {b.metrics.loss_event_frequency}/yr
                  </span>
                </div>
              }
            >
              <span className="font-mono text-3xl font-bold tabular-nums text-destructive">
                {formatCurrency(b.metrics.annual_loss_expectancy)}
              </span>
              <span className="text-xs text-muted-foreground">/yr</span>
            </Card>

            <Card
              label="Mitigated Loss Expectancy"
              icon={ShieldCheck}
              footer={
                <span className="text-[11px] text-muted-foreground">
                  With proposed controls deployed
                </span>
              }
            >
              <span className="font-mono text-3xl font-bold tabular-nums text-foreground">
                {b.metrics.mitigated_annual_loss_expectancy != null
                  ? formatCurrency(b.metrics.mitigated_annual_loss_expectancy)
                  : "—"}
              </span>
              <span className="text-xs text-muted-foreground">/yr</span>
            </Card>

            <Card
              label="Annual Risk Reduction"
              icon={TrendingDown}
              footer={
                <span className="text-[11px] text-muted-foreground">
                  Expected annual financial savings
                </span>
              }
            >
              <span className="font-mono text-3xl font-bold tabular-nums text-emerald-600 dark:text-emerald-400">
                {b.metrics.annual_risk_reduction != null
                  ? `-${formatCurrency(b.metrics.annual_risk_reduction)}`
                  : "—"}
              </span>
              <span className="text-xs text-muted-foreground">/yr</span>
            </Card>

            <Card
              label="Security Control ROI"
              icon={Percent}
              footer={
                <span className="text-[11px] text-muted-foreground">
                  Net return on proposed investment
                </span>
              }
            >
              <span className="font-mono text-3xl font-bold tabular-nums text-primary">
                {b.metrics.security_roi_percentage != null
                  ? `+${b.metrics.security_roi_percentage.toFixed(0)}%`
                  : "—"}
              </span>
            </Card>
          </div>

          <div className="rounded border border-primary/10 bg-background/50 px-3 py-2 text-xs text-muted-foreground">
            <span className="font-semibold text-foreground">Recommendation: </span>
            {b.recommendation}
          </div>
        </div>
      )}

      {/* Monitored Estate Inventory Posture */}
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <Card
          label="Overall risk score"
          icon={Gauge}
          footer={
            <div className="flex flex-col gap-2">
              <div className="h-1.5 overflow-hidden rounded-full bg-muted" aria-hidden="true">
                <div className={cn("h-full rounded-full", scoreBarColor(a.overallScore))} style={{ width: `${a.overallScore}%` }} />
              </div>
              {p ? <Delta value={a.overallScore - p.overallScore} /> : <span className="text-muted-foreground">Baseline assessment</span>}
            </div>
          }
        >
          <span className={cn("font-mono text-3xl font-semibold tabular-nums", scoreColor(a.overallScore))}>{a.overallScore}</span>
          <span className="text-sm text-muted-foreground">/100</span>
          <LevelBadge level={a.overallCategory} className="ml-auto" />
        </Card>
        <Card
          label="Critical assets"
          icon={Server}
          footer={<span className="text-muted-foreground">Business criticality: Critical</span>}
        >
          <span className="font-mono text-3xl font-semibold tabular-nums text-foreground">{a.criticalAssetCount}</span>
        </Card>
        <Card
          label="Open vulnerabilities"
          icon={Bug}
          footer={p ? <Delta value={a.openVulnerabilityCount - p.openVulnerabilityCount} /> : <span className="text-muted-foreground">Across all monitored assets</span>}
        >
          <span className="font-mono text-3xl font-semibold tabular-nums text-foreground">{a.openVulnerabilityCount}</span>
        </Card>
        <Card
          label="Open high-severity incidents"
          icon={Siren}
          footer={p ? <Delta value={a.openHighSeverityIncidents - p.openHighSeverityIncidents} /> : <span className="text-muted-foreground">Awaiting containment</span>}
        >
          <span className="font-mono text-3xl font-semibold tabular-nums text-destructive">{a.openHighSeverityIncidents}</span>
        </Card>
      </div>
    </div>
  )
}
