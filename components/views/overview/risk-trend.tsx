"use client"

import { useMemo } from "react"
import { CheckCircle2, Info } from "lucide-react"
import { Area, AreaChart, CartesianGrid, ReferenceLine, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts"
import { TrendingDown, TrendingUp } from "lucide-react"
import { useAppState } from "@/components/app/app-state"
import { DemoTag, LevelBadge, scoreColor } from "@/components/app/badges"
import { Panel } from "@/components/app/panel"

function formatISTDay(date: Date): string {
  return new Intl.DateTimeFormat("en-US", {
    timeZone: "Asia/Kolkata",
    month: "short",
    day: "numeric",
  }).format(date)
}

export function RiskTrend({ className }: { className?: string }) {
  const { assessment, activeReport } = useAppState()

  const data = useMemo(() => {
    // Anchor to actual assessment timestamp or now, formatted dynamically in Asia/Kolkata (IST)
    const anchorDate = assessment.evaluatedAt ? new Date(assessment.evaluatedAt) : new Date()

    // 6-day baseline trajectory preceding the current assessment date
    const baselineScores = [69, 71, 70, 73, 74, 76]
    const points = []

    for (let i = 6; i >= 1; i--) {
      const pastDate = new Date(anchorDate.getTime() - i * 24 * 60 * 60 * 1000)
      points.push({
        day: formatISTDay(pastDate),
        score: baselineScores[6 - i],
        isSimulated: true,
      })
    }

    // Current point derived from the real assessment / active report
    points.push({
      day: formatISTDay(anchorDate),
      score: assessment.overallScore,
      isSimulated: false,
    })

    return points
  }, [assessment.evaluatedAt, assessment.overallScore])

  const first = data[0]?.score ?? assessment.overallScore
  const change = Number((assessment.overallScore - first).toFixed(1))
  const isUp = change > 0
  const currentDayLabel = data[data.length - 1]?.day || "Today"

  return (
    <Panel
      className={className}
      title={activeReport ? "Risk Posture Progression" : "Seven-Day Risk Trend"}
      description={
        activeReport
          ? `Authoritative risk score ${assessment.overallScore}/100 derived from ${activeReport.filename || activeReport.report_id}.`
          : `Official risk score is ${assessment.overallScore}/100 (${isUp ? "+" : ""}${change} pts over 7 days). Reference line marks Critical threshold (80).`
      }
      action={
        <div className="flex flex-wrap items-center gap-2">
          {activeReport && (
            <span className="flex items-center gap-1.5 font-mono text-[10px] text-emerald-600 dark:text-emerald-400 font-semibold rounded bg-emerald-500/10 border border-emerald-500/30 px-2 py-0.5">
              <CheckCircle2 className="size-3 text-emerald-500" />
              Report Assessment ({currentDayLabel})
            </span>
          )}
          <DemoTag label="Simulated Baseline (Past 6 Days)" />
        </div>
      }
    >
      {/* Visual Header Metrics Banner */}
      <div className="mb-4 grid grid-cols-3 gap-2 rounded-md border border-border/50 bg-muted/20 p-2.5 text-xs">
        <div>
          <span className="block text-[10px] uppercase tracking-wider text-muted-foreground">Current Risk</span>
          <span className="mt-0.5 font-mono text-sm font-bold text-foreground">
            {assessment.overallScore}/100
          </span>
        </div>
        <div>
          <span className="block text-[10px] uppercase tracking-wider text-muted-foreground">7-Day Trajectory</span>
          <span className="mt-0.5 inline-flex items-center gap-1 font-mono text-xs font-semibold text-foreground">
            {change === 0 ? (
              "No net change"
            ) : (
              <>
                {isUp ? (
                  <TrendingUp className="size-3 text-destructive" />
                ) : (
                  <TrendingDown className="size-3 text-success" />
                )}
                <span className={isUp ? "text-destructive" : "text-success"}>
                  {isUp ? "+" : ""}{change} pts
                </span>
              </>
            )}
          </span>
        </div>
        <div>
          <span className="block text-[10px] uppercase tracking-wider text-muted-foreground">Critical Line</span>
          <span className="mt-0.5 font-mono text-xs font-semibold text-destructive">
            ≥ 80 Score
          </span>
        </div>
      </div>

      <div className="h-60 w-full" role="img" aria-label={`Risk trend: ${data.map((d) => `${d.day} ${d.score}`).join(", ")}`}>
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={data} margin={{ left: -16, right: 12, top: 10, bottom: 0 }}>
            <defs>
              <linearGradient id="trendFill" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="var(--high)" stopOpacity={0.3} />
                <stop offset="100%" stopColor="var(--high)" stopOpacity={0.0} />
              </linearGradient>
            </defs>
            <CartesianGrid stroke="var(--border)" strokeDasharray="3 3" vertical={false} />
            <XAxis
              dataKey="day"
              tickLine={false}
              axisLine={false}
              tick={{ fill: "var(--muted-foreground)", fontSize: 11 }}
            />
            <YAxis
              domain={[50, 100]}
              tickLine={false}
              axisLine={false}
              tick={{ fill: "var(--muted-foreground)", fontSize: 11 }}
            />
            <ReferenceLine
              y={80}
              stroke="var(--destructive)"
              strokeDasharray="4 4"
              strokeOpacity={0.8}
              label={{
                value: "Critical (80)",
                fill: "var(--destructive)",
                fontSize: 10,
                position: "insideTopRight",
              }}
            />
            <Tooltip
content={({ active, payload }) => {
                if (!active || !payload || !payload.length) return null
                const item = payload[0].payload as { day: string; score: number; isSimulated: boolean }
                return (
                  <div className="rounded-md border bg-popover p-2.5 text-xs shadow-md">
                    <p className="font-semibold text-foreground">{item.day} (IST)</p>
                    <p className="text-muted-foreground mt-0.5">
                      Risk Score: <strong className="font-mono text-foreground">{item.score}/100</strong>
                    </p>
                    <p className="text-[10px] mt-1 font-mono">
                      {item.isSimulated ? (
                        <span className="text-amber-500 font-medium">● Simulated Historical Baseline</span>
                      ) : (
                        <span className="text-emerald-500 font-medium">
                          ● {activeReport ? "Actual Report Assessment" : "Current Assessment"}
                        </span>
                      )}
                    </p>
                  </div>
                )
              }}
            />
            <Area
              type="monotone"
              dataKey="score"
              stroke="var(--high)"
              strokeWidth={2.5}
              fill="url(#trendFill)"
dot={{ r: 3.5, fill: "var(--high)", strokeWidth: 0 }}
              activeDot={{ r: 5 }}
              isAnimationActive={true}
              animationDuration={600}
              animationEasing="ease-out"
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>

      <div className="mt-2 flex items-center gap-1.5 text-[11px] text-muted-foreground border-t pt-2">
        <Info className="size-3.5 text-primary shrink-0" />
        <span>
          {activeReport
            ? `Points 1–6 represent simulated baseline telemetry. Current assessment (${currentDayLabel}, IST) is calculated from ${activeReport.filename || activeReport.report_id}.`
            : "Points 1–6 represent simulated baseline telemetry. Current score reflects evaluated active assets."}
        </span>
      </div>
    </Panel>
  )
}
