"use client"

import { useEffect, useMemo, useRef, useState } from "react"
import { Area, AreaChart, CartesianGrid, ReferenceLine, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts"
import { TrendingDown, TrendingUp } from "lucide-react"
import { useAppState } from "@/components/app/app-state"
import { DemoTag, LevelBadge, scoreColor } from "@/components/app/badges"
import { Panel } from "@/components/app/panel"

export function RiskTrend({ className }: { className?: string }) {
  const { assessment, trendHistory } = useAppState()

  // State to hold the live subtle animated offset (mean-reverting around 0)
  const [liveOffset, setLiveOffset] = useState<number>(0)
  const offsetRef = useRef<number>(0)

  // Live simulation update loop: 2-second interval, subtle noise, mean-reverting
  useEffect(() => {
    let isDocVisible = !document.hidden
    const handleVisibility = () => {
      isDocVisible = !document.hidden
    }
    document.addEventListener("visibilitychange", handleVisibility)

    const interval = setInterval(() => {
      if (!isDocVisible) return

      // Ornstein-Uhlenbeck / Mean-Reverting Random Walk:
      // dX = -theta * X + noise
      // theta = 0.35 (pulls offset back toward 0)
      const current = offsetRef.current
      const meanReversionPull = -0.35 * current

      // Generate realistic noise
      const r = Math.random()
      let rawStep: number
      if (r < 0.85) {
        rawStep = Math.random() * 0.5 - 0.25
      } else {
        rawStep = Math.random() * 1.2 - 0.6
      }

      // Calculate next bounded offset (bounded strictly within [-1.5, +1.5] around official score)
      let next = current + meanReversionPull + rawStep
      next = Math.max(-1.5, Math.min(1.5, next))
      next = Number(next.toFixed(1))

      offsetRef.current = next
      setLiveOffset(next)
    }, 2000)

    return () => {
      clearInterval(interval)
      document.removeEventListener("visibilitychange", handleVisibility)
    }
  }, [])

  // Calculate live displayed score for "Today"
  const currentLiveScore = useMemo(() => {
    const raw = assessment.overallScore + liveOffset
    return Math.max(0, Math.min(100, Number(raw.toFixed(1))))
  }, [assessment.overallScore, liveOffset])

  const data = useMemo(() => {
    if (!trendHistory || trendHistory.length === 0) {
      return [{ day: "Today", score: currentLiveScore, officialScore: assessment.overallScore }]
    }

    const basePoints = trendHistory.map((pt) => ({
      day: pt.day,
      score: pt.day === "Today" ? currentLiveScore : pt.score,
      officialScore: pt.day === "Today" ? assessment.overallScore : pt.score,
    }))

    const last = basePoints[basePoints.length - 1]
    if (last.day === "Today") {
      return basePoints
    }
    return [...basePoints, { day: "Today", score: currentLiveScore, officialScore: assessment.overallScore }]
  }, [trendHistory, currentLiveScore, assessment.overallScore])

  const first = data[0]?.officialScore ?? assessment.overallScore
  const change = Number((assessment.overallScore - first).toFixed(1))
  const isUp = change > 0

  return (
    <Panel
      className={className}
      title="Seven-Day Risk Trend"
      description={`Official risk score is ${assessment.overallScore}/100 (${isUp ? "+" : ""}${change} pts over 7 days). Reference line marks Critical threshold (80).`}
      action={
        <div className="flex items-center gap-2">
          <span className="flex items-center gap-1.5 font-mono text-[10px] text-muted-foreground">
            <span className="size-1.5 rounded-full bg-emerald-500 animate-ping" />
            <span className="text-emerald-500 font-semibold">Live 2s</span>
          </span>
          <DemoTag />
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
              contentStyle={{
                background: "var(--popover)",
                border: "1px solid var(--border)",
                borderRadius: 6,
                fontSize: 12,
              }}
              labelStyle={{ color: "var(--foreground)", fontWeight: 600 }}
              itemStyle={{ color: "var(--muted-foreground)" }}
              formatter={(v, _name, item) => {
                const payload = item?.payload
                if (payload?.day === "Today") {
                  return [
                    `${v}/100 (Official: ${payload.officialScore})`,
                    "Live Telemetry",
                  ]
                }
                return [`${v}/100`, "Assessed Risk"]
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
    </Panel>
  )
}
