import { ArrowRight, Bug, CheckCircle2, Gauge, ShieldOff, Siren, TrendingUp, type LucideIcon } from "lucide-react"
import { useState } from "react"
import { cn } from "@/lib/utils"
import { formatDateTime } from "@/lib/format"
import type { ActivityEvent, ActivityKind } from "@/lib/types"
import { LevelBadge, scoreColor } from "./badges"
import { EmptyState } from "./panel"

const KIND_ICON: Record<ActivityKind, LucideIcon> = {
  vulnerability: Bug,
  "risk-change": TrendingUp,
  control: ShieldOff,
  remediation: CheckCircle2,
  assessment: Gauge,
  incident: Siren,
}

const KIND_COLOR: Record<ActivityKind, string> = {
  vulnerability: "text-destructive",
  "risk-change": "text-high",
  control: "text-warning",
  remediation: "text-success",
  assessment: "text-muted-foreground",
  incident: "text-destructive",
}

export function ActivityList({ events, compact = false }: { events: ActivityEvent[]; compact?: boolean }) {
  const [expandedId, setExpandedId] = useState<string | null>(null);

  // Summary calculations (compact version respects the same events)
  const total = events.length;
  const highCritical = events.filter((e) => e.severity === "Critical" || e.severity === "High").length;
  const resolved = events.filter((e) => e.kind === "remediation").length;
  const riskChanges = events.filter((e) => e.kind === "risk-change").length;

  if (events.length === 0) {
    return <EmptyState title="No activity yet" description="Simulated events will appear here." />
  }

  return (
    <div className="space-y-6">
      {/* Compact summary row */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 bg-muted/30 p-4 rounded-md">
        <div className="text-sm">
          <span className="font-medium">Total Events:</span> {total}
        </div>
        <div className="text-sm">
          <span className="font-medium text-destructive">Critical/High:</span> {highCritical}
        </div>
        <div className="text-sm">
          <span className="font-medium text-success">Resolved:</span> {resolved}
        </div>
        <div className="text-sm">
          <span className="font-medium text-warning">Risk Changes:</span> {riskChanges}
        </div>
      </div>

      {/* Vertical timeline */}
      <ol className="relative border-l border-muted">
        {events.map((e) => {
          const Icon = KIND_ICON[e.kind];
          const isExpanded = expandedId === e.id;
          return (
            <li key={e.id} className="mb-6 ml-4">
              <div className="flex items-start">
                {/* Timeline dot */}
                <span
                  className={cn(
                    "absolute -left-3 flex size-6 items-center justify-center rounded-full border-2 border-background bg-muted",
                    KIND_COLOR[e.kind]
                  )}
                >
                  <Icon className="size-3.5" aria-hidden="true" />
                </span>
                <div className="flex-1 space-y-1">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <p className="text-sm font-medium text-foreground">{e.title}</p>
                      {e.severity !== "Info" ? <LevelBadge level={e.severity} /> : null}
                    </div>
                    <p className="text-xs text-muted-foreground">{formatDateTime(e.at)}</p>
                  </div>
                  {/* Primary line: description (short) and risk delta */}
                  <p className={cn("text-xs text-muted-foreground", compact && "line-clamp-1")}>
                    {e.description}
                  </p>
                  {/* Score changes displayed inline */}
                  {!compact && (e.scoreChange?.length || e.overallChange) && (
                    <div className="flex flex-wrap gap-2 mt-1">
                      {e.scoreChange?.map((c) => (
                        <ScoreDelta key={c.assetName} label={c.assetName} before={c.before} after={c.after} />
                      ))}
                      {e.overallChange && (
                        <ScoreDelta label="Overall risk" before={e.overallChange.before} after={e.overallChange.after} />
                      )}
                    </div>
                  )}
                  {/* Details toggle */}
                  <button
                    type="button"
                    className="mt-1 text-xs text-primary underline"
                    onClick={() => setExpandedId(isExpanded ? null : e.id)}
                  >
                    {isExpanded ? "Hide details" : "View details"}
                  </button>
                  {isExpanded && (
                    <div className="mt-2 border-t pt-2 text-xs text-muted-foreground">
                      {/* Full description and any additional info can be placed here */}
                      <p>{e.description}</p>
                      {/* Re‑render score changes for consistency when expanded */}
                      {(e.scoreChange?.length || e.overallChange) && (
                        <div className="flex flex-wrap gap-2 mt-2">
                          {e.scoreChange?.map((c) => (
                            <ScoreDelta key={c.assetName} label={c.assetName} before={c.before} after={c.after} />
                          ))}
                          {e.overallChange && (
                            <ScoreDelta label="Overall risk" before={e.overallChange.before} after={e.overallChange.after} />
                          )}
                        </div>
                      )}
                    </div>
                  )}
                </div>
              </div>
            </li>
          );
        })}
      </ol>
    </div>
  );
}

export function ScoreDelta({ label, before, after }: { label: string; before: number; after: number }) {
  const diff = after - before
  return (
    <span className="inline-flex items-center gap-1.5 rounded border bg-background px-2 py-1 text-xs">
      <span className="text-muted-foreground">{label}</span>
      <span className={cn("font-mono tabular-nums", scoreColor(before))}>{before}</span>
      <ArrowRight className="size-3 text-muted-foreground" aria-label="to" />
      <span className={cn("font-mono font-semibold tabular-nums", scoreColor(after))}>{after}</span>
      <span
        className={cn(
          "font-mono tabular-nums",
          diff > 0 ? "text-destructive" : diff < 0 ? "text-success" : "text-muted-foreground",
        )}
      >
        ({diff > 0 ? "+" : ""}
        {diff})
      </span>
    </span>
  )
}
