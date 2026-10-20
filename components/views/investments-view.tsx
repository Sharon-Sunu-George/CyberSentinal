"use client"

import { useMemo, useState } from "react"
import { CheckCircle2, TrendingDown, Wallet } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { useAppState } from "@/components/app/app-state"
import { investmentOptions, DEFAULT_BUDGET } from "@/lib/investments"
import { optimizeBudget } from "@/lib/optimizer"
import { formatCurrency } from "@/lib/format"

export function InvestmentsView() {
  const { dataset, currency } = useAppState()
  const [budgetInput, setBudgetInput] = useState<number>(DEFAULT_BUDGET)

  const result = useMemo(() => {
    return optimizeBudget(dataset, investmentOptions, budgetInput)
  }, [dataset, budgetInput])

  return (
    <div className="flex flex-col gap-6">
      <Card className="border-primary/20 bg-primary/5">
        <CardHeader>
          <div className="flex items-center gap-2 text-primary">
            <Wallet className="size-5" />
            <CardTitle>Security Investment Optimizer</CardTitle>
          </div>
          <CardDescription>
            Simulate capital allocation to maximize financial risk reduction within budget boundaries.
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col sm:flex-row items-center gap-4">
          <div className="flex-1 w-full">
            <label className="text-xs font-medium text-muted-foreground block mb-1.5">
              Available Security Budget (USD Base · Displayed in {currency})
            </label>
            <Input
              type="number"
              value={budgetInput}
              onChange={(e) => setBudgetInput(Number(e.target.value))}
              step={50000}
              min={0}
              className="font-mono"
            />
          </div>
          <div className="flex gap-2 pt-5 sm:pt-0">
            <Button variant="outline" size="sm" onClick={() => setBudgetInput(500000)}>
              {formatCurrency(500000, currency)}
            </Button>
            <Button variant="outline" size="sm" onClick={() => setBudgetInput(1000000)}>
              {formatCurrency(1000000, currency)}
            </Button>
            <Button variant="outline" size="sm" onClick={() => setBudgetInput(1500000)}>
              {formatCurrency(1500000, currency)}
            </Button>
          </div>
        </CardContent>
      </Card>

      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <Card>
          <CardHeader className="pb-2">
            <CardDescription>Proposed Total Spend</CardDescription>
            <CardTitle className="text-2xl font-bold font-mono">
              {formatCurrency(result.proposed.totalCost, currency)}
            </CardTitle>
          </CardHeader>
          <CardContent className="text-xs text-muted-foreground">
            {((result.proposed.totalCost / (budgetInput || 1)) * 100).toFixed(1)}% of budget allocated
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardDescription>Total Financial Risk Reduction</CardDescription>
            <CardTitle className="text-2xl font-bold font-mono text-emerald-600 dark:text-emerald-400 flex items-center gap-2">
              <TrendingDown className="size-5" />
              {result.proposed.reductionPct.toFixed(1)}%
            </CardTitle>
          </CardHeader>
          <CardContent className="text-xs text-muted-foreground">
            Overall risk score reduced {result.proposed.baselineOverall} → {result.proposed.residualOverall}
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardDescription>Combinations Evaluated</CardDescription>
            <CardTitle className="text-2xl font-bold font-mono">
              {result.feasibleCombinations} / {result.combinationsEvaluated}
            </CardTitle>
          </CardHeader>
          <CardContent className="text-xs text-muted-foreground">
            Exhaustive 2ⁿ optimization options
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base font-semibold">Evaluated Investment Projects</CardTitle>
          <CardDescription>Select investments included in the optimal allocation portfolio.</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            {result.insights.map(({ option, selected, standalonePct, efficiencyPerLakh }) => (
              <div
                key={option.id}
                className={`rounded-lg border p-4 transition-colors ${
                  selected ? "border-emerald-500/50 bg-emerald-500/5" : "bg-card"
                }`}
              >
                <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-2 mb-2">
                  <div className="flex items-center gap-2">
                    {selected ? (
                      <CheckCircle2 className="size-5 text-emerald-500 shrink-0" />
                    ) : (
                      <div className="size-5 rounded-full border border-muted-foreground/30 shrink-0" />
                    )}
                    <h4 className="font-semibold text-foreground text-sm">{option.name}</h4>
                  </div>
                  <div className="flex items-center gap-3 text-xs font-mono">
                    <span className="text-muted-foreground">Cost: {formatCurrency(option.cost, currency)}</span>
                    <span className="bg-muted px-2 py-0.5 rounded text-foreground font-semibold">
                      Effort: {option.effort}
                    </span>
                  </div>
                </div>
                <p className="text-xs text-muted-foreground mb-3">{option.description}</p>
                <div className="flex flex-wrap gap-4 text-xs font-mono pt-2 border-t text-muted-foreground">
                  <span>Standalone Impact: <strong className="text-foreground">-{standalonePct.toFixed(1)}% risk</strong></span>
                  <span>Efficiency: <strong className="text-foreground">{efficiencyPerLakh.toFixed(1)} pts / {formatCurrency(100000, currency)}</strong></span>
                </div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
