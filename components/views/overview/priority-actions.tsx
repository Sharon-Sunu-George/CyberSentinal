"use client"

import { useMemo } from "react"
import { ArrowRight, ShieldAlert, Sparkles, TrendingDown, Wallet } from "lucide-react"
import { Button } from "@/components/ui/button"
import { useAppState } from "@/components/app/app-state"
import { LevelBadge } from "@/components/app/badges"
import { DEFAULT_BUDGET, investmentOptions } from "@/lib/investments"
import { optimizeBudget } from "@/lib/optimizer"
import { formatINR } from "@/lib/format"
import { cn } from "@/lib/utils"

export function PriorityActionsAndGaps() {
  const { dataset, gaps, navigate } = useAppState()

  // 1. Calculate Top 3 recommendations from optimizer
  const optResult = useMemo(() => optimizeBudget(dataset, investmentOptions, DEFAULT_BUDGET), [dataset])
  const topPicks = useMemo(() => {
    return optResult.insights
      .filter((i) => i.selected)
      .sort((a, b) => (b.marginalReduction ?? 0) - (a.marginalReduction ?? 0))
      .slice(0, 3)
  }, [optResult])

  // 2. Take top 3 urgent security gaps
  const topGaps = useMemo(() => gaps.slice(0, 3), [gaps])

  return (
    <section aria-label="Priority Actions and Security Gaps" className="grid grid-cols-1 gap-4 lg:grid-cols-2">
      {/* LEFT: PRIORITY ACTIONS */}
      <div className="flex flex-col justify-between rounded-lg border border-border/80 bg-card p-5 shadow-sm">
        <div>
          <div className="flex items-center justify-between border-b border-border/60 pb-3">
            <div className="flex items-center gap-2">
              <span className="flex size-6 items-center justify-center rounded bg-primary/15 text-primary">
                <Wallet className="size-3.5" aria-hidden="true" />
              </span>
              <div>
                <h2 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                  Priority Actions
                </h2>
              </div>
            </div>
            <Button
              variant="ghost"
              size="sm"
              onClick={() => navigate("investments")}
              className="h-7 text-xs text-primary hover:text-primary gap-1 px-2"
            >
              Open Investment Optimizer
              <ArrowRight className="size-3" aria-hidden="true" />
            </Button>
          </div>

          <p className="mt-2.5 text-xs text-muted-foreground">
            Optimal allocation plan for default budget ({formatINR(DEFAULT_BUDGET)}) delivering{" "}
            <span className="font-semibold text-success font-mono">
              −{optResult.proposed.reductionPct.toFixed(1)}%
            </span>{" "}
            risk exposure reduction.
          </p>

          <ol className="mt-3 flex flex-col divide-y divide-border/40">
            {topPicks.map((p, idx) => {
              const reductionPct = (
                ((p.marginalReduction ?? 0) / optResult.proposed.baselineExposure) *
                100
              ).toFixed(1)

              return (
                <li key={p.option.id} className="flex items-start gap-3 py-3 first:pt-1 last:pb-1">
                  <span className="mt-0.5 flex size-5 shrink-0 items-center justify-center rounded bg-primary/15 font-mono text-[11px] font-bold text-primary">
                    {idx + 1}
                  </span>
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center justify-between gap-2">
                      <p className="text-sm font-semibold text-foreground truncate">
                        {p.option.name}
                      </p>
                      <span className="font-mono text-xs font-semibold tabular-nums text-success shrink-0">
                        −{reductionPct}%
                      </span>
                    </div>
                    <div className="mt-1 flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
                      <span className="font-medium text-foreground">{formatINR(p.option.cost)}</span>
                      <span>·</span>
                      <span>{p.option.effort} effort</span>
                      <span>·</span>
                      <span>{p.coverage} assets covered</span>
                    </div>
                  </div>
                </li>
              )
            })}
          </ol>
        </div>

        <div className="mt-4 flex items-center justify-between border-t border-border/60 pt-3 text-xs text-muted-foreground">
          <span>Overall Score Impact:</span>
          <span className="font-mono font-medium text-foreground">
            {optResult.proposed.baselineOverall} →{" "}
            <span className="text-success font-semibold">{optResult.proposed.residualOverall}</span>
          </span>
        </div>
      </div>

      {/* RIGHT: SECURITY GAPS */}
      <div className="flex flex-col justify-between rounded-lg border border-border/80 bg-card p-5 shadow-sm">
        <div>
          <div className="flex items-center justify-between border-b border-border/60 pb-3">
            <div className="flex items-center gap-2">
              <span className="flex size-6 items-center justify-center rounded bg-warning/15 text-warning">
                <ShieldAlert className="size-3.5" aria-hidden="true" />
              </span>
              <div>
                <h2 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                  Security Gaps
                </h2>
              </div>
            </div>
            <Button
              variant="ghost"
              size="sm"
              onClick={() => navigate("gaps")}
              className="h-7 text-xs text-foreground hover:text-foreground gap-1 px-2"
            >
              View All Gaps ({gaps.length})
              <ArrowRight className="size-3" aria-hidden="true" />
            </Button>
          </div>

          <p className="mt-2.5 text-xs text-muted-foreground">
            Highest-urgency control weaknesses ranked by cross-asset blast radius and attacker reachability.
          </p>

          <ul className="mt-3 flex flex-col divide-y divide-border/40">
            {topGaps.map((g) => (
              <li key={g.id} className="py-3 first:pt-1 last:pb-1">
                <button
                  type="button"
                  onClick={() => navigate("gaps")}
                  className="flex w-full items-start justify-between gap-3 text-left group focus-visible:outline-2 focus-visible:outline-ring rounded"
                >
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2">
                      <p className="text-sm font-semibold text-foreground group-hover:text-primary transition-colors truncate">
                        {g.title}
                      </p>
                    </div>
                    <p className="mt-1 text-xs text-muted-foreground line-clamp-1">
                      {g.consequence}
                    </p>
                    <div className="mt-1.5 flex items-center gap-2 text-[11px] text-muted-foreground">
                      <span>
                        {g.affectedAssets.length} affected asset{g.affectedAssets.length === 1 ? "" : "s"}
                      </span>
                      <span>·</span>
                      <span>
                        Urgency Score: <strong className="font-mono text-foreground">{g.urgencyScore}</strong>
                      </span>
                    </div>
                  </div>
                  <LevelBadge level={g.severity} className="shrink-0 mt-0.5" />
                </button>
              </li>
            ))}
          </ul>
        </div>

        <div className="mt-4 border-t border-border/60 pt-3 text-xs text-muted-foreground flex items-center justify-between">
          <span>Total control weaknesses:</span>
          <span className="font-mono font-medium text-foreground">{gaps.length} identified</span>
        </div>
      </div>
    </section>
  )
}
