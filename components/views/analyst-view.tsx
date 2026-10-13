"use client"

import { useMemo, useState } from "react"
import {
  AlertTriangle,
  ArrowRight,
  BrainCircuit,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  Database,
  ExternalLink,
  Flame,
  HelpCircle,
  Lightbulb,
  Server,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Wrench,
  Zap,
} from "lucide-react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { useAppState } from "@/components/app/app-state"
import { investigate, SAMPLE_QUESTION } from "@/lib/analyst"
import { ExposureText, LevelBadge, RiskScore, scoreBarColor, scoreColor } from "@/components/app/badges"
import { cn } from "@/lib/utils"
import type { RiskFactor } from "@/lib/types"

const DRIVER_LABEL_MAP: Record<string, string> = {
  threat: "Threat Intelligence & Targeting",
  controls: "Security Control Deficiencies",
  exposure: "Network Attack Surface",
  vulnerability: "Vulnerability Severity & CVSS",
  criticality: "Business Asset Criticality",
  incidents: "Active Incident Activity",
}

const FIELD_LABEL_MAP: Record<string, string> = {
  businessCriticality: "Business Criticality",
  exposure: "Network Exposure",
  openHighSeverityIncidents: "High-Severity Incidents",
  threatEvidence: "Threat Intel Score",
  openVulnerabilityCount: "Open Vulnerabilities",
  "controls.mfa": "MFA Status",
  "controls.edr": "EDR Status",
  "controls.patching": "Patch Management Status",
  "controls.segmentation": "Network Segmentation Status",
  "controls.backup": "Backup Protection Status",
}

export function AnalystView() {
  const { assessment, gaps, analystAssetId, navigate } = useAppState()
  const [selectedAssetId, setSelectedAssetId] = useState<string>(
    analystAssetId || (assessment.assetRisks[0]?.asset.id ?? ""),
  )
  const [question] = useState(SAMPLE_QUESTION)
  const [showEvidence, setShowEvidence] = useState(false)

  const selectedAssetRisk = useMemo(
    () => assessment.assetRisks.find((r) => r.asset.id === selectedAssetId),
    [assessment.assetRisks, selectedAssetId],
  )

  const investigation = useMemo(
    () => (selectedAssetId ? investigate(selectedAssetId, question, assessment, gaps) : null),
    [selectedAssetId, question, assessment, gaps],
  )

  // Top 3 factors
  const topDrivers = useMemo(() => {
    if (!investigation) return []
    return investigation.factors
      .slice()
      .sort((a, b) => b.contribution - a.contribution)
      .slice(0, 3)
  }, [investigation])

  return (
    <div className="mx-auto flex max-w-5xl flex-col gap-6 pb-12">
      {/* ─────────────────────────────────────────────────────────────
          TOP: ASSET SELECTOR BAR
      ───────────────────────────────────────────────────────────── */}
      <div className="flex flex-col gap-3 rounded-xl border border-primary/30 bg-primary/5 p-4 shadow-sm sm:flex-row sm:items-center sm:justify-between">
        <div className="flex items-center gap-2.5">
          <span className="flex size-9 items-center justify-center rounded-lg bg-primary/15 text-primary ring-1 ring-primary/30">
            <BrainCircuit className="size-5" aria-hidden="true" />
          </span>
          <div>
            <h1 className="text-sm font-bold tracking-tight text-foreground">AI Risk Analyst</h1>
            <p className="text-xs text-muted-foreground">
              Evidence-backed automated investigation & prescriptive remediation.
            </p>
          </div>
        </div>

        <div className="w-full sm:w-80">
          <Select
            value={selectedAssetId}
            onValueChange={(val) => {
              if (val) setSelectedAssetId(val)
            }}
          >
            <SelectTrigger className="h-9 w-full bg-card text-xs font-medium">
              <SelectValue placeholder="Select asset to analyze..." />
            </SelectTrigger>
            <SelectContent>
              {assessment.assetRisks.map((r) => (
                <SelectItem key={r.asset.id} value={r.asset.id} className="text-xs">
                  <span className="font-mono font-bold">#{r.rank}</span> {r.asset.name} (
                  <span className={scoreColor(r.score)}>{r.score}/100</span>)
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      </div>

      {investigation && selectedAssetRisk && (
        <div className="flex flex-col gap-6">
          {/* ─────────────────────────────────────────────────────────────
              1. WHAT IS THE RISK? (EXECUTIVE INVESTIGATION SUMMARY)
          ───────────────────────────────────────────────────────────── */}
          <section
            aria-label="What is the Risk"
            className="flex flex-col justify-between rounded-xl border border-border/80 bg-card p-6 shadow-sm"
          >
            <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border/60 pb-4">
              <div className="flex items-center gap-2">
                <span className="flex size-6 items-center justify-center rounded bg-destructive/15 font-mono text-xs font-bold text-destructive">
                  #{investigation.rank}
                </span>
                <span className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                  Question 1: What is the risk?
                </span>
              </div>
              <div className="flex items-center gap-2">
                <LevelBadge level={investigation.category} />
              </div>
            </div>

            <div className="mt-4 flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
              <div className="min-w-0 flex-1">
                <div className="flex items-baseline gap-2">
                  <h2 className="text-xl font-bold tracking-tight text-foreground sm:text-2xl">
                    {selectedAssetRisk.asset.name}
                  </h2>
                </div>
                <p className="mt-1 text-xs text-muted-foreground">
                  {selectedAssetRisk.asset.type} · Managed by{" "}
                  <span className="text-foreground font-medium">{selectedAssetRisk.asset.owner}</span>
                </p>

                {/* AI Executive Summary Callout */}
                <div className="mt-4 rounded-lg border border-primary/20 bg-muted/30 p-3.5">
                  <div className="flex items-center gap-1.5 text-xs font-semibold text-primary">
                    <Sparkles className="size-3.5" aria-hidden="true" />
                    AI Analyst Assessment
                  </div>
                  <p className="mt-1.5 text-xs leading-relaxed text-foreground text-pretty">
                    {investigation.summary}
                  </p>
                </div>
              </div>

              {/* Prominent Score Card */}
              <div className="flex flex-col items-center justify-center rounded-lg border border-border/60 bg-muted/20 p-4 text-center lg:min-w-44">
                <span className="text-[10px] font-bold uppercase tracking-wider text-muted-foreground">
                  Asset Risk Score
                </span>
                <div className="my-1 flex items-baseline justify-center gap-1">
                  <span
                    className={cn(
                      "font-mono text-4xl font-extrabold tabular-nums",
                      scoreColor(investigation.score),
                    )}
                  >
                    {investigation.score}
                  </span>
                  <span className="text-xs text-muted-foreground">/100</span>
                </div>
                <div className="h-1.5 w-28 overflow-hidden rounded-full bg-muted">
                  <div
                    className={cn("h-full rounded-full", scoreBarColor(investigation.score))}
                    style={{ width: `${investigation.score}%` }}
                  />
                </div>
                <span className="mt-2 text-[11px] font-medium text-muted-foreground">
                  {investigation.priorityStatement}
                </span>
              </div>
            </div>
          </section>

          {/* ─────────────────────────────────────────────────────────────
              2. WHY IS IT RISKY? (TOP 3 KEY RISK DRIVERS)
          ───────────────────────────────────────────────────────────── */}
          <section aria-label="Why is it Risky">
            <div className="mb-3 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <span className="flex size-6 items-center justify-center rounded bg-warning/15 text-warning">
                  <Flame className="size-3.5" aria-hidden="true" />
                </span>
                <h3 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                  Question 2: Why is it risky? (Top 3 Risk Drivers)
                </h3>
              </div>
              <span className="text-[11px] text-muted-foreground">
                Score contribution breakdown
              </span>
            </div>

            <div className="grid grid-cols-1 gap-3.5 sm:grid-cols-3">
              {topDrivers.map((driver: RiskFactor, idx: number) => {
                const label = DRIVER_LABEL_MAP[driver.key] || driver.label
                const maxPts = Math.round(driver.weight * 100)
                const pct = Math.min(100, Math.round((driver.contribution / maxPts) * 100))

                return (
                  <div
                    key={driver.key}
                    className="flex flex-col justify-between rounded-xl border border-border/80 bg-card p-4 shadow-sm"
                  >
                    <div>
                      <div className="flex items-center justify-between gap-1">
                        <span className="text-xs font-bold text-foreground truncate">{label}</span>
                        <span className="font-mono text-xs font-bold text-foreground shrink-0">
                          +{driver.contribution} pts
                        </span>
                      </div>

                      <div className="my-2.5 h-1.5 w-full overflow-hidden rounded-full bg-muted">
                        <div
                          className={cn(
                            "h-full rounded-full transition-all duration-500",
                            pct >= 75
                              ? "bg-destructive"
                              : pct >= 50
                                ? "bg-high"
                                : pct >= 25
                                  ? "bg-warning"
                                  : "bg-success",
                          )}
                          style={{ width: `${Math.max(10, pct)}%` }}
                        />
                      </div>

                      <p className="text-[11px] leading-relaxed text-muted-foreground text-pretty">
                        {driver.detail}
                      </p>
                    </div>

                    <div className="mt-3 border-t border-border/50 pt-2 text-[10px] text-muted-foreground">
                      Weight: <span className="font-mono text-foreground font-medium">{maxPts} pts max</span>
                    </div>
                  </div>
                )
              })}
            </div>
          </section>

          {/* ─────────────────────────────────────────────────────────────
              3. WHAT SHOULD I DO? (PRIORITIZED REMEDIATION ACTIONS)
          ───────────────────────────────────────────────────────────── */}
          <section aria-label="What should I do">
            <div className="mb-3 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <span className="flex size-6 items-center justify-center rounded bg-primary/15 text-primary">
                  <Wrench className="size-3.5" aria-hidden="true" />
                </span>
                <h3 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                  Question 3: What should I do? (Action Plan)
                </h3>
              </div>
              <span className="text-[11px] text-muted-foreground">
                Ranked by risk reduction
              </span>
            </div>

            <div className="flex flex-col gap-3">
              {investigation.actions.slice(0, 3).map((act, idx) => {
                const isImmediatePriority = idx === 0

                return (
                  <div
                    key={act.id}
                    className={cn(
                      "flex flex-col gap-3 rounded-xl border p-4.5 shadow-sm transition-all sm:flex-row sm:items-start sm:justify-between",
                      isImmediatePriority
                        ? "border-primary/50 bg-primary/5 ring-1 ring-primary/20"
                        : "border-border/80 bg-card",
                    )}
                  >
                    <div className="flex items-start gap-3 min-w-0 flex-1">
                      <span
                        className={cn(
                          "mt-0.5 flex size-6 shrink-0 items-center justify-center rounded font-mono text-xs font-bold",
                          isImmediatePriority
                            ? "bg-primary text-primary-foreground"
                            : "bg-muted text-muted-foreground",
                        )}
                      >
                        {idx + 1}
                      </span>

                      <div className="space-y-1 min-w-0 flex-1">
                        <div className="flex flex-wrap items-center gap-2">
                          <h4 className="text-sm font-bold text-foreground">{act.title}</h4>
                          {isImmediatePriority ? (
                            <span className="inline-flex items-center gap-1 rounded bg-primary/20 px-2 py-0.5 font-mono text-[10px] font-bold text-primary uppercase tracking-wider">
                              <Zap className="size-3" /> Immediate Priority
                            </span>
                          ) : null}
                        </div>

                        <p className="text-xs text-muted-foreground">{act.rationale}</p>

                        <div className="mt-2 flex items-center gap-1.5 text-xs text-success font-medium">
                          <CheckCircle2 className="size-3.5 shrink-0" aria-hidden="true" />
                          <span>
                            <strong>Expected Outcome:</strong> {act.expectedEffect}
                          </span>
                        </div>
                      </div>
                    </div>
                  </div>
                )
              })}
            </div>
          </section>

          {/* ─────────────────────────────────────────────────────────────
              4. COLLECTED AUDIT EVIDENCE (EXPANDABLE SECONDARY SECTION)
          ───────────────────────────────────────────────────────────── */}
          <section aria-label="Technical Evidence and Control Gaps">
            <div className="rounded-xl border border-border/80 bg-card p-4 shadow-sm">
              <button
                type="button"
                onClick={() => setShowEvidence((prev) => !prev)}
                className="flex w-full items-center justify-between text-left focus-visible:outline-2 focus-visible:outline-ring rounded"
              >
                <div className="flex items-center gap-2">
                  <Database className="size-4 text-muted-foreground" aria-hidden="true" />
                  <span className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                    Audit Signals & Technical Evidence ({investigation.evidence.length} signals)
                  </span>
                </div>
                <div className="flex items-center gap-1 text-xs text-primary font-medium">
                  <span>{showEvidence ? "Hide Technical Evidence" : "View Technical Evidence"}</span>
                  {showEvidence ? <ChevronUp className="size-4" /> : <ChevronDown className="size-4" />}
                </div>
              </button>

              {showEvidence && (
                <div className="mt-4 border-t border-border/60 pt-4 flex flex-col gap-4 animate-in fade-in-50 duration-200">
                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-xs">
                      <thead>
                        <tr className="border-b border-border/50 text-muted-foreground">
                          <th className="pb-2 font-semibold">Audit Field</th>
                          <th className="pb-2 font-semibold">Data Source</th>
                          <th className="pb-2 font-semibold text-right">Collected Value</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-border/30 font-mono text-[11px]">
                        {investigation.evidence.map((ev, i) => {
                          const friendlyField = FIELD_LABEL_MAP[ev.field] || ev.field

                          return (
                            <tr key={i} className="hover:bg-muted/30">
                              <td className="py-2 text-foreground font-sans font-medium">
                                {friendlyField}
                                {friendlyField !== ev.field ? (
                                  <span className="ml-1 text-[10px] text-muted-foreground font-mono opacity-60">
                                    ({ev.field})
                                  </span>
                                ) : null}
                              </td>
                              <td className="py-2 text-muted-foreground font-sans">{ev.source}</td>
                              <td className="py-2 text-right">
                                <span className="rounded bg-muted px-2 py-0.5 text-foreground font-semibold">
                                  {ev.value}
                                </span>
                              </td>
                            </tr>
                          )
                        })}
                      </tbody>
                    </table>
                  </div>

                  {investigation.gaps.length > 0 && (
                    <div className="rounded-lg border border-warning/30 bg-warning/5 p-3 mt-2">
                      <div className="flex items-center gap-1.5 text-xs font-semibold text-warning mb-2">
                        <ShieldAlert className="size-3.5" />
                        Associated Control Gaps on this Host
                      </div>
                      <div className="space-y-2">
                        {investigation.gaps.map((g, idx) => (
                          <div key={idx} className="text-xs flex items-start justify-between gap-2">
                            <div>
                              <p className="font-medium text-foreground">{g.title}</p>
                              <p className="text-[11px] text-muted-foreground">{g.detail}</p>
                            </div>
                            <LevelBadge level={g.severity} />
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          </section>
        </div>
      )}
    </div>
  )
}
