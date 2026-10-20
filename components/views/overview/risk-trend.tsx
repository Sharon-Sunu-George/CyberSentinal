"use client"

import { useMemo } from "react"
import { CheckCircle2, Info } from "lucide-react"
import { Area, AreaChart, CartesianGrid, ReferenceLine, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts"
import { useAppState } from "@/components/app/app-state"
import { DemoTag } from "@/components/app/badges"
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
  const currentDayLabel = data[data.length - 1]?.day || "Today"

  return (
    <Panel
      className={className}
      title={activeReport ? "Risk Posture Progression" : "Seven-day risk trend"}
      description={
        activeReport
          ? `Authoritative risk score ${assessment.overallScore}/100 derived from ${activeReport.filename || activeReport.report_id}.`
          : `Overall risk score ${change >= 0 ? "up" : "down"} ${Math.abs(change)} points across demonstration baseline estate.`
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
      <div className="h-56" role="img" aria-label={`Risk trend: ${data.map((d) => `${d.day} ${d.score}`).join(", ")}`}>
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={data} margin={{ left: -16, right: 8, top: 8, bottom: 0 }}>
            <defs>
              <linearGradient id="trendFill" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="var(--high)" stopOpacity={0.25} />
                <stop offset="100%" stopColor="var(--high)" stopOpacity={0} />
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
              strokeOpacity={0.6}
              label={{ value: "Critical", fill: "var(--destructive)", fontSize: 10, position: "insideTopRight" }}
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
              strokeWidth={2}
              fill="url(#trendFill)"
              dot={{ r: 3, fill: "var(--high)", strokeWidth: 0 }}
              activeDot={{ r: 4 }}
              isAnimationActive={false}
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
