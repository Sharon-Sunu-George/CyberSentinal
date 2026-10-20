"use client"

import { useMemo } from "react"
import { ArrowRight } from "lucide-react"
import { Button } from "@/components/ui/button"
import { useAppState } from "@/components/app/app-state"
import { Panel } from "@/components/app/panel"
import { DEFAULT_BUDGET, investmentOptions } from "@/lib/investments"
import { optimizeBudget } from "@/lib/optimizer"
import { formatCurrency } from "@/lib/format"

export function TopRecommendations() {
  const { dataset, navigate, currency } = useAppState()
  const result = useMemo(() => optimizeBudget(dataset, investmentOptions, DEFAULT_BUDGET), [dataset])
  const picks = result.insights
    .filter((i) => i.selected)
    .toSorted((a, b) => (b.marginalReduction ?? 0) - (a.marginalReduction ?? 0))

  return (
    <Panel
      title="Top recommendations"
      description={`Optimal plan within the default ${formatCurrency(DEFAULT_BUDGET, currency)} budget.`}
      action={
        <Button variant="ghost" size="sm" onClick={() => navigate("investments")}>
          Optimizer
          <ArrowRight aria-hidden="true" />
        </Button>
      }
      bodyClassName="p-0"
    >
      <ol className="divide-y">
        {picks.map((p, i) => (
          <li key={p.option.id} className="flex items-start gap-3 px-4 py-2.5">
            <span className="mt-0.5 flex size-5 shrink-0 items-center justify-center rounded bg-primary/15 font-mono text-[11px] font-semibold text-primary">
              {i + 1}
            </span>
            <div className="min-w-0 flex-1">
              <p className="text-sm text-foreground">{p.option.name}</p>
              <p className="text-xs text-muted-foreground">
                {formatCurrency(p.option.cost, currency)} · {p.option.effort} effort · {p.coverage} assets
              </p>
            </div>
            <span className="font-mono text-xs tabular-nums text-success">
              −{(((p.marginalReduction ?? 0) / result.proposed.baselineExposure) * 100).toFixed(1)}%
            </span>
          </li>
        ))}
      </ol>
      <div className="border-t px-4 py-2.5 text-xs text-muted-foreground">
        Combined reduction{" "}
        <span className="font-mono text-success">−{result.proposed.reductionPct.toFixed(1)}%</span> of exposure · overall risk{" "}
        <span className="font-mono text-foreground">
          {result.proposed.baselineOverall} → {result.proposed.residualOverall}
        </span>
      </div>
    </Panel>
  )
}
