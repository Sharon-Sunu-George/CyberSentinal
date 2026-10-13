"use client"

import { useMemo, useState } from "react"
import {
  ArrowRight,
  CheckCircle2,
  ChevronRight,
  Cpu,
  DollarSign,
  Layers,
  Sparkles,
  TrendingDown,
  Wallet,
  Zap,
} from "lucide-react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { useAppState } from "@/components/app/app-state"
import { investmentOptions, DEFAULT_BUDGET } from "@/lib/investments"
import { optimizeBudget } from "@/lib/optimizer"
import { formatCurrency } from "@/lib/format"
import { cn } from "@/lib/utils"
import { InvestmentDetailSheet } from "./investments/investment-detail-sheet"

export function InvestmentsView() {
  const { dataset, navigate } = useAppState()
  const [budgetInput, setBudgetInput] = useState<number>(DEFAULT_BUDGET)
  const [selectedOptionId, setSelectedOptionId] = useState<string | null>(null)

  const result = useMemo(() => {
    return optimizeBudget(dataset, investmentOptions, budgetInput)
  }, [dataset, budgetInput])

  // Split and rank selected vs unselected options
  const sortedInsights = useMemo(() => {
    const selected = result.insights
      .filter((i) => i.selected)
      .sort((a, b) => (b.marginalReduction ?? 0) - (a.marginalReduction ?? 0))

    const unselected = result.insights
      .filter((i) => !i.selected)
      .sort((a, b) => b.efficiencyPerLakh - a.efficiencyPerLakh)

    return { selected, unselected, all: [...selected, ...unselected] }
  }, [result.insights])

  const selectedCount = sortedInsights.selected.length

  // Find currently inspected insight for the detail sheet
  const activeInsight = useMemo(() => {
    if (!selectedOptionId) return null
    return result.insights.find((i) => i.option.id === selectedOptionId) ?? null
  }, [result.insights, selectedOptionId])

  return (
    <div className="mx-auto flex max-w-5xl flex-col gap-6 pb-12">
      {/* ─────────────────────────────────────────────────────────────
          1. BUDGET INPUT & PRESET CONTROLS
      ───────────────────────────────────────────────────────────── */}
      <div className="flex flex-col gap-4 rounded-xl border border-primary/30 bg-primary/5 p-5 shadow-sm sm:flex-row sm:items-center sm:justify-between">
        <div className="flex items-center gap-3">
          <span className="flex size-10 items-center justify-center rounded-lg bg-primary/15 text-primary ring-1 ring-primary/30">
            <Wallet className="size-5" aria-hidden="true" />
          </span>
          <div>
            <h1 className="text-sm font-bold tracking-tight text-foreground">
              Security Investment Optimizer
            </h1>
            <p className="text-xs text-muted-foreground">
              Simulate capital allocation to maximize financial risk reduction within budget limits.
            </p>
          </div>
        </div>

        <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-2">
          <div className="relative w-full sm:w-48">
            <DollarSign className="pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              type="number"
              value={budgetInput}
              onChange={(e) => setBudgetInput(Math.max(0, Number(e.target.value)))}
              step={50000}
              min={0}
              className="h-9 pl-8 font-mono text-xs font-semibold"
              placeholder="Budget amount"
            />
          </div>

          <div className="flex gap-1.5">
            <Button
              variant={budgetInput === 500000 ? "default" : "outline"}
              size="sm"
              onClick={() => setBudgetInput(500000)}
              className="h-9 text-xs px-2.5 font-mono"
            >
              $500k
            </Button>
            <Button
              variant={budgetInput === 1000000 ? "default" : "outline"}
              size="sm"
              onClick={() => setBudgetInput(1000000)}
              className="h-9 text-xs px-2.5 font-mono"
            >
              $1M
            </Button>
            <Button
              variant={budgetInput === 1500000 ? "default" : "outline"}
              size="sm"
              onClick={() => setBudgetInput(1500000)}
              className="h-9 text-xs px-2.5 font-mono"
            >
              $1.5M
            </Button>
          </div>
        </div>
      </div>

      {/* ─────────────────────────────────────────────────────────────
          2. THREE SUMMARY KPI CARDS
      ───────────────────────────────────────────────────────────── */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        {/* Proposed Spend */}
        <div className="flex flex-col justify-between rounded-xl border border-border/80 bg-card p-4.5 shadow-sm">
          <div>
            <span className="text-[10px] font-bold uppercase tracking-wider text-muted-foreground">
              Proposed Total Spend
            </span>
            <div className="my-1.5 flex items-baseline gap-2">
              <span className="font-mono text-3xl font-bold tracking-tight text-foreground tabular-nums">
                {formatCurrency(result.proposed.totalCost)}
              </span>
            </div>
          </div>
          <div className="border-t border-border/50 pt-2 text-xs text-muted-foreground">
            <strong className="text-foreground">
              {((result.proposed.totalCost / (budgetInput || 1)) * 100).toFixed(1)}%
            </strong>{" "}
            of {formatCurrency(budgetInput)} allocated
          </div>
        </div>

        {/* Risk Reduction */}
        <div className="flex flex-col justify-between rounded-xl border border-emerald-500/30 bg-emerald-500/5 p-4.5 shadow-sm">
          <div>
            <span className="text-[10px] font-bold uppercase tracking-wider text-emerald-600 dark:text-emerald-400">
              Total Risk Reduction
            </span>
            <div className="my-1.5 flex items-baseline gap-2">
              <span className="font-mono text-3xl font-extrabold tracking-tight text-emerald-600 dark:text-emerald-400 tabular-nums">
                −{result.proposed.reductionPct.toFixed(1)}%
              </span>
            </div>
          </div>
          <div className="border-t border-emerald-500/20 pt-2 text-xs text-muted-foreground">
            Overall risk score:{" "}
            <span className="font-mono text-foreground font-semibold">
              {result.proposed.baselineOverall} →{" "}
              <span className="text-emerald-600 dark:text-emerald-400">{result.proposed.residualOverall}</span>
            </span>
          </div>
        </div>

        {/* Optimization Depth */}
        <div className="flex flex-col justify-between rounded-xl border border-border/80 bg-card p-4.5 shadow-sm">
          <div>
            <span className="text-[10px] font-bold uppercase tracking-wider text-muted-foreground">
              Combinations Evaluated
            </span>
            <div className="my-1.5 flex items-baseline gap-2">
              <span className="font-mono text-3xl font-bold tracking-tight text-foreground tabular-nums">
                {result.feasibleCombinations}{" "}
                <span className="text-sm font-normal text-muted-foreground">/ {result.combinationsEvaluated}</span>
              </span>
            </div>
          </div>
          <div className="border-t border-border/50 pt-2 text-xs text-muted-foreground">
            Exhaustive mathematical portfolio optimization
          </div>
        </div>
      </div>

      {/* ─────────────────────────────────────────────────────────────
          3. DECISION-FOCUSED INVESTMENT PORTFOLIO
      ───────────────────────────────────────────────────────────── */}
      <section aria-label="Optimized Investment Priority List" className="flex flex-col gap-4">
        <div className="flex items-center justify-between border-b border-border/80 pb-3">
          <div>
            <h2 className="text-sm font-bold text-foreground">
              Prioritized Investment Allocation
            </h2>
            <p className="mt-0.5 text-xs text-muted-foreground">
              Click any investment control below to inspect what specific security problems it solves.
            </p>
          </div>
          <span className="rounded bg-primary/10 px-2 py-0.5 font-mono text-xs font-semibold text-primary">
            {selectedCount} Active in Plan
          </span>
        </div>

        <div className="flex flex-col gap-3">
          {sortedInsights.all.map(({ option, selected, standalonePct, efficiencyPerLakh, marginalReduction, coverage }, idx) => {
            const isSelected = selected
            const priorityNumber = isSelected ? idx + 1 : null
            const isTopPick = isSelected && priorityNumber === 1

            return (
              <div
                key={option.id}
                onClick={() => setSelectedOptionId(option.id)}
                className={cn(
                  "group flex flex-col justify-between rounded-xl border p-4 shadow-sm transition-all cursor-pointer hover:border-primary/60 sm:flex-row sm:items-center sm:gap-4",
                  isTopPick
                    ? "border-primary/60 bg-primary/5 ring-1 ring-primary/20"
                    : isSelected
                      ? "border-emerald-500/40 bg-emerald-500/5 hover:bg-emerald-500/10"
                      : "border-border/60 bg-card/60 opacity-70 hover:opacity-100 hover:bg-muted/30",
                )}
              >
                <div className="flex items-start gap-3.5 min-w-0 flex-1">
                  {/* Priority Badge Indicator */}
                  <span
                    className={cn(
                      "mt-0.5 flex size-7 shrink-0 items-center justify-center rounded-lg font-mono text-xs font-bold",
                      isTopPick
                        ? "bg-primary text-primary-foreground shadow-sm"
                        : isSelected
                          ? "bg-emerald-500/20 text-emerald-600 dark:text-emerald-400"
                          : "bg-muted text-muted-foreground",
                    )}
                  >
                    {priorityNumber ? `#${priorityNumber}` : "—"}
                  </span>

                  <div className="space-y-1 min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <h3 className="text-sm font-bold text-foreground group-hover:text-primary transition-colors truncate">
                        {option.name}
                      </h3>

                      {isTopPick ? (
                        <span className="inline-flex items-center gap-1 rounded bg-primary/20 px-2 py-0.5 font-mono text-[10px] font-bold text-primary uppercase tracking-wider">
                          <Sparkles className="size-3" /> Best Investment
                        </span>
                      ) : isSelected ? (
                        <span className="inline-flex items-center gap-1 rounded bg-emerald-500/15 px-2 py-0.5 font-mono text-[10px] font-bold text-emerald-600 dark:text-emerald-400">
                          <CheckCircle2 className="size-3" /> Included in Plan
                        </span>
                      ) : (
                        <span className="rounded bg-muted px-2 py-0.5 font-mono text-[10px] text-muted-foreground">
                          Exceeds Current Budget
                        </span>
                      )}
                    </div>

                    <p className="text-xs text-muted-foreground leading-relaxed">
                      {option.description}
                    </p>

                    <div className="flex flex-wrap items-center gap-3 pt-1 text-[11px] text-muted-foreground">
                      <span>
                        Coverage: <strong className="text-foreground">{coverage} monitored hosts</strong>
                      </span>
                      <span>·</span>
                      <span>
                        Standalone: <strong className="text-foreground">−{standalonePct.toFixed(1)}% risk</strong>
                      </span>
                      <span>·</span>
                      <span>
                        Efficiency: <strong className="text-foreground">{efficiencyPerLakh.toFixed(1)} pts / $100k</strong>
                      </span>
                      <span>·</span>
                      <span className="text-primary font-medium group-hover:underline">
                        Click to view problem & ROI details →
                      </span>
                    </div>
                  </div>
                </div>

                {/* Right Metrics Box */}
                <div className="mt-3 flex items-center justify-between border-t border-border/40 pt-3 sm:mt-0 sm:border-t-0 sm:pt-0 sm:flex-col sm:items-end sm:gap-1.5 sm:shrink-0">
                  <div className="font-mono text-base font-bold text-foreground">
                    {formatCurrency(option.cost)}
                  </div>
                  <div className="flex items-center gap-1.5">
                    <span className="rounded bg-muted px-2 py-0.5 text-[10px] font-semibold text-muted-foreground">
                      {option.effort} Effort
                    </span>
                    {isSelected && (
                      <span className="font-mono text-xs font-bold text-emerald-600 dark:text-emerald-400">
                        {marginalReduction ? `−${((marginalReduction / (result.proposed.baselineExposure || 1)) * 100).toFixed(1)}%` : ""}
                      </span>
                    )}
                    <ChevronRight className="size-4 text-muted-foreground group-hover:text-primary transition-transform group-hover:translate-x-0.5" />
                  </div>
                </div>
              </div>
            )
          })}
        </div>
      </section>

      {/* ─────────────────────────────────────────────────────────────
          4. CONCISE FINAL RECOMMENDATION BANNER
      ───────────────────────────────────────────────────────────── */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 rounded-xl border border-primary/40 bg-gradient-to-r from-primary/10 via-card to-card p-5 shadow-sm">
        <div>
          <div className="flex items-center gap-2 text-xs font-bold text-primary uppercase tracking-wider">
            <Zap className="size-4" />
            Executive Decision Summary
          </div>
          <p className="mt-1 text-sm font-semibold text-foreground">
            Recommended allocation:{" "}
            <span className="text-primary font-mono font-bold">
              {formatCurrency(result.proposed.totalCost)}
            </span>{" "}
            across {selectedCount} control{selectedCount === 1 ? "" : "s"} → estimated risk reduction:{" "}
            <span className="text-emerald-600 dark:text-emerald-400 font-mono font-bold">
              −{result.proposed.reductionPct.toFixed(1)}%
            </span>{" "}
            (Residual Score: <span className="font-mono font-bold">{result.proposed.residualOverall}/100</span>).
          </p>
        </div>

        <div className="shrink-0 font-mono text-xs text-muted-foreground">
          Budget headroom: <span className="font-semibold text-foreground">{formatCurrency(Math.max(0, budgetInput - result.proposed.totalCost))}</span>
        </div>
      </div>

      {/* ─────────────────────────────────────────────────────────────
          5. COMPACT DETAIL SIDE PANEL (DRAWER)
      ───────────────────────────────────────────────────────────── */}
      <InvestmentDetailSheet
        option={activeInsight?.option ?? null}
        standalonePct={activeInsight?.standalonePct}
        marginalReduction={activeInsight?.marginalReduction}
        efficiencyPerLakh={activeInsight?.efficiencyPerLakh}
        coverageCount={activeInsight?.coverage}
        baselineExposure={result.proposed.baselineExposure}
        dataset={dataset}
        isOpen={!!selectedOptionId}
        onClose={() => setSelectedOptionId(null)}
        onNavigateToExplorer={() => navigate("explorer")}
      />
    </div>
  )
}
