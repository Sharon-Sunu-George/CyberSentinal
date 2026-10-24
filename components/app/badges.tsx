import { cn } from "@/lib/utils"
import type { ControlStatus, Criticality, Exposure, RiskCategory, Severity } from "@/lib/types"

type Level = Severity | RiskCategory | Criticality | "None" | "Info"

const LEVEL_STYLES: Record<Level, string> = {
  Critical: "bg-destructive/15 text-destructive ring-destructive/30",
  High: "bg-high/15 text-high ring-high/30",
  Medium: "bg-warning/15 text-warning ring-warning/30",
  Low: "bg-success/10 text-success ring-success/25",
  None: "bg-muted text-muted-foreground ring-border",
  Info: "bg-muted text-muted-foreground ring-border",
}

export function LevelBadge({ level, className }: { level: Level; className?: string }) {
  return (
    <span
      className={cn(
        "inline-flex h-5 shrink-0 items-center rounded px-1.5 text-[11px] font-medium ring-1 ring-inset whitespace-nowrap",
        LEVEL_STYLES[level],
        className,
      )}
    >
      {level}
    </span>
  )
}

const CONTROL_STYLES: Record<ControlStatus, string> = {
  Active: "text-success",
  Partial: "text-warning",
  Missing: "text-destructive",
  Unavailable: "text-destructive",
}

export function ControlStatusText({ status }: { status: ControlStatus }) {
  return (
    <span className={cn("inline-flex items-center gap-1.5 text-xs font-medium", CONTROL_STYLES[status])}>
      <span aria-hidden="true" className="size-1.5 rounded-full bg-current" />
      {status}
    </span>
  )
}

export function ExposureText({ exposure }: { exposure: Exposure }) {
  return (
    <span className={cn("text-xs", exposure === "Internet-facing" ? "text-high" : "text-muted-foreground")}>
      {exposure}
    </span>
  )
}

export function scoreColor(score: number) {
  if (score >= 80) return "text-destructive"
  if (score >= 60) return "text-high"
  if (score >= 40) return "text-warning"
  return "text-success"
}

export function scoreBarColor(score: number) {
  if (score >= 80) return "bg-destructive"
  if (score >= 60) return "bg-high"
  if (score >= 40) return "bg-warning"
  return "bg-success"
}

export function RiskScore({ score, className }: { score: number; className?: string }) {
  return (
    <span className={cn("inline-flex items-center gap-2", className)}>
      <span className={cn("w-7 text-right font-mono text-sm font-semibold tabular-nums", scoreColor(score))}>{score}</span>
      <span className="h-1.5 w-12 overflow-hidden rounded-full bg-muted" aria-hidden="true">
        <span className={cn("block h-full rounded-full", scoreBarColor(score))} style={{ width: `${score}%` }} />
      </span>
    </span>
  )
}

export function DemoTag({ className, label = "Demo" }: { className?: string; label?: string }) {
  return (
    <span
      className={cn(
        "inline-flex h-4 items-center rounded-sm border border-dashed border-warning/50 px-1 text-[10px] font-medium uppercase tracking-wide text-warning",
        className,
      )}
    >
      {label}
    </span>
  )
}
