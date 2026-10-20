"use client"

import { useState } from "react"
import {
  AlertTriangle,
  ArrowRight,
  ChevronDown,
  ChevronUp,
  Server,
  ShieldAlert,
  ShieldCheck,
  Wrench,
} from "lucide-react"
import { Button } from "@/components/ui/button"
import { Card } from "@/components/ui/card"
import { useAppState } from "@/components/app/app-state"
import { ControlStatusText, ExposureText, LevelBadge } from "@/components/app/badges"
import { CONTROL_LABELS } from "@/lib/risk"
import { cn } from "@/lib/utils"

export function GapsView() {
  const { gaps, navigate } = useAppState()
  // Track only single expanded gap ID at a time
  const [expandedId, setExpandedId] = useState<string | null>(null)

  const toggleExpand = (id: string) => {
    setExpandedId((current) => (current === id ? null : id))
  }

  return (
    <div className="mx-auto flex max-w-4xl flex-col gap-5 pb-12">
      {/* ─────────────────────────────────────────────────────────────
          PAGE TITLE
      ───────────────────────────────────────────────────────────── */}
      <div className="flex flex-col gap-1 border-b border-border/80 pb-4 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex items-center gap-2.5">
          <span className="flex size-8 items-center justify-center rounded-lg bg-warning/15 text-warning ring-1 ring-warning/30">
            <ShieldAlert className="size-4.5" aria-hidden="true" />
          </span>
          <div>
            <h1 className="text-base font-bold tracking-tight text-foreground">
              Security Gaps & Control Deficiencies
            </h1>
            <p className="text-xs text-muted-foreground">
              Prioritized control weaknesses ranked by urgency and reachability.
            </p>
          </div>
        </div>

        <span className="self-start rounded bg-muted px-2.5 py-1 font-mono text-xs font-semibold text-muted-foreground sm:self-auto">
          {gaps.length} Total Gaps
        </span>
      </div>

      {/* ─────────────────────────────────────────────────────────────
          EMPTY STATE OR COMPACT CARDS LIST
      ───────────────────────────────────────────────────────────── */}
      {gaps.length === 0 ? (
        <Card className="p-8 text-center border-dashed">
          <ShieldCheck className="mx-auto size-8 text-emerald-500 mb-2" />
          <p className="text-sm font-semibold text-foreground">No Active Security Control Gaps</p>
          <p className="text-xs text-muted-foreground mt-1 max-w-md mx-auto">
            All assets evaluated in the current assessment meet baseline control criteria (MFA, EDR, Patching, Segmentation, and Backup).
          </p>
        </Card>
      ) : (
        <div className="flex flex-col gap-3">
          {gaps.map((gap) => {
            const isExpanded = expandedId === gap.id
            const controlLabel = CONTROL_LABELS[gap.control] || gap.control

            return (
              <div
                key={gap.id}
                className={cn(
                  "overflow-hidden rounded-xl border bg-card shadow-sm transition-all",
                  isExpanded
                    ? "border-warning/60 bg-card ring-1 ring-warning/20"
                    : "border-border/80 hover:border-border/100 hover:bg-card/90",
                )}
              >
                {/* ───────────────────────────────────────────────────────
                    COLLAPSED CARD (Problem → Severity → Impact → Action)
                ─────────────────────────────────────────────────────── */}
                <div className="flex flex-col justify-between p-4">
                  {/* Row 1: [Severity] Gap Name ... Urgency Score */}
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex items-center gap-2 min-w-0">
                      <LevelBadge level={gap.severity} />
                      <h2 className="text-sm font-bold text-foreground truncate">
                        {gap.title}
                      </h2>
                    </div>

                    <div className="font-mono text-xs text-muted-foreground shrink-0">
                      Urgency: <strong className="text-foreground">{gap.urgencyScore}</strong>
                    </div>
                  </div>

                  {/* Row 2: Short 1-line explanation */}
                  <p className="mt-2 text-xs text-foreground/90 line-clamp-1 text-pretty">
                    {gap.consequence}
                  </p>

                  {/* Row 3: Affected assets count ... View details action */}
                  <div className="mt-2.5 flex items-center justify-between border-t border-border/40 pt-2.5 text-xs">
                    <div className="text-muted-foreground">
                      Affected assets:{" "}
                      <strong className="font-mono font-semibold text-foreground">
                        {gap.affectedAssets.length}
                      </strong>
                    </div>

                    <button
                      type="button"
                      onClick={() => toggleExpand(gap.id)}
                      className="inline-flex items-center gap-1 font-semibold text-primary hover:underline focus-visible:outline-2 focus-visible:outline-ring rounded"
                    >
                      <span>{isExpanded ? "Hide details" : "View details"}</span>
                      {isExpanded ? (
                        <ChevronUp className="size-3.5" aria-hidden="true" />
                      ) : (
                        <ArrowRight className="size-3.5" aria-hidden="true" />
                      )}
                    </button>
                  </div>

                  {/* Row 4: Recommended action snippet */}
                  <div className="mt-2 text-xs text-muted-foreground truncate">
                    <span className="font-medium text-foreground">Recommended action: </span>
                    <span>{gap.remediation}</span>
                  </div>
                </div>

                {/* ───────────────────────────────────────────────────────
                    EXPANDED VIEW (Shown only when active)
                ─────────────────────────────────────────────────────── */}
                {isExpanded && (
                  <div className="border-t border-border/60 bg-muted/20 p-4 sm:p-5 animate-in fade-in-50 duration-150 flex flex-col gap-4 text-xs">
                    {/* Full Remediation & Why it matters */}
                    <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                      <div className="rounded-lg border border-warning/30 bg-warning/5 p-3">
                        <div className="flex items-center gap-1.5 font-bold text-warning mb-1">
                          <AlertTriangle className="size-3.5" />
                          Why Those Assets Are Affected
                        </div>
                        <p className="text-foreground/90 leading-relaxed text-pretty">
                          {controlLabel} is deficient across these {gap.affectedAssets.length} hosts, allowing potential attacker reachability and lateral blast radius.
                        </p>
                      </div>

                      <div className="rounded-lg border border-primary/30 bg-primary/5 p-3">
                        <div className="flex items-center gap-1.5 font-bold text-primary mb-1">
                          <Wrench className="size-3.5" />
                          Full Remediation Plan
                        </div>
                        <p className="text-foreground/90 leading-relaxed text-pretty">
                          {gap.remediation}
                        </p>
                      </div>
                    </div>

                    {/* Full Affected Assets List */}
                    <div className="flex flex-col gap-2">
                      <div className="flex items-center justify-between font-bold text-foreground">
                        <div className="flex items-center gap-1.5">
                          <Server className="size-3.5 text-muted-foreground" />
                          <span>Affected Asset Breakdown ({gap.affectedAssets.length} hosts)</span>
                        </div>
                        <button
                          type="button"
                          onClick={() => navigate("explorer")}
                          className="text-[11px] font-semibold text-primary hover:underline"
                        >
                          Inspect in Explorer →
                        </button>
                      </div>

                      <div className="divide-y divide-border/40 rounded-lg border border-border/60 bg-card overflow-hidden">
                        {gap.affectedAssets.map((asset) => {
                          const status = asset.controls[gap.control]

                          return (
                            <div
                              key={asset.id}
                              className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 p-2.5 hover:bg-muted/30 transition-colors"
                            >
                              <div className="min-w-0 flex-1">
                                <div className="flex items-center gap-2">
                                  <span className="font-semibold text-foreground text-xs">{asset.name}</span>
                                  <LevelBadge level={asset.criticality} />
                                </div>
                                <p className="mt-0.5 text-[11px] text-muted-foreground">
                                  {asset.type} · Managed by {asset.owner} · <ExposureText exposure={asset.exposure} />
                                </p>
                              </div>

                              <div className="flex items-center gap-2 shrink-0 text-right">
                                <span className="text-[10px] text-muted-foreground">Status:</span>
                                <ControlStatusText status={status} />
                              </div>
                            </div>
                          )
                        })}
                      </div>
                    </div>
                  </div>
                )}
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}
