"use client"

import { useMemo } from "react"
import { Bar, BarChart, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts"
import { useAppState } from "@/components/app/app-state"
import { Panel } from "@/components/app/panel"
import type { RiskCategory } from "@/lib/types"

const CATEGORIES: { key: RiskCategory; color: string }[] = [
  { key: "Critical", color: "var(--destructive)" },
  { key: "High", color: "var(--high)" },
  { key: "Medium", color: "var(--warning)" },
  { key: "Low", color: "var(--success)" },
]

export function RiskDistribution() {
  const { assessment, activeReport } = useAppState()

  // Calculate counts from active scanner report or current asset inventory
  const data = useMemo(() => {
    if (activeReport) {
      return [
        { category: "Critical" as RiskCategory, color: "var(--destructive)", count: activeReport.summary.critical },
        { category: "High" as RiskCategory, color: "var(--high)", count: activeReport.summary.high },
        { category: "Medium" as RiskCategory, color: "var(--warning)", count: activeReport.summary.medium },
        { category: "Low" as RiskCategory, color: "var(--success)", count: activeReport.summary.low },
      ]
    }
    return CATEGORIES.map((c) => ({
      category: c.key,
      color: c.color,
      count: assessment.assetRisks.filter((r) => r.category === c.key).length,
    }))
  }, [assessment.assetRisks, activeReport])

  const totalCount = activeReport ? activeReport.summary.total_findings : assessment.assetRisks.length
  const labelType = activeReport ? "findings" : "assets"

  return (
    <Panel
      title={activeReport ? "Report Severity Breakdown" : "Asset Risk Distribution"}
      description={
        activeReport
          ? `${totalCount} itemized findings from ${activeReport.report_id}`
          : `${totalCount} monitored assets grouped by risk level`
      }
    >
      <div
        className="h-44"
        role="img"
        aria-label={`Asset risk distribution: ${data.map((d) => `${d.category}: ${d.count}`).join(", ")} (${totalCount} total ${labelType})`}
      >
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={data} layout="vertical" margin={{ left: 0, right: 16, top: 4, bottom: 4 }}>
            <XAxis type="number" allowDecimals={false} hide domain={[0, "auto"]} />
            <YAxis
              type="category"
              dataKey="category"
              width={60}
              tickLine={false}
              axisLine={false}
              tick={{ fill: "var(--muted-foreground)", fontSize: 12 }}
            />
            <Tooltip
              cursor={{ fill: "var(--muted)", opacity: 0.4 }}
              contentStyle={{
                background: "var(--popover)",
                border: "1px solid var(--border)",
                borderRadius: 6,
                fontSize: 12,
              }}
              labelStyle={{ color: "var(--foreground)" }}
              itemStyle={{ color: "var(--muted-foreground)" }}
              formatter={(v) => [`${v} asset${Number(v) === 1 ? "" : "s"}`, "Count"]}
            />
            <Bar dataKey="count" radius={[0, 3, 3, 0]} barSize={18}>
              {data.map((d) => (
                <Cell key={d.category} fill={d.color} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>
      <ul className="mt-2 grid grid-cols-4 gap-2 border-t pt-3">
        {data.map((d) => (
          <li key={d.category} className="flex flex-col">
            <span className="font-mono text-lg font-semibold tabular-nums text-foreground">{d.count}</span>
            <span className="flex items-center gap-1.5 text-[11px] text-muted-foreground">
              <span className="size-2 rounded-sm" style={{ background: d.color }} aria-hidden="true" />
              {d.category}
            </span>
          </li>
        ))}
      </ul>
    </Panel>
  )
}

