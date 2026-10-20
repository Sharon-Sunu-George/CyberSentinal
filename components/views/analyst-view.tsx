"use client"

import { useState } from "react"
import { BrainCircuit, ShieldAlert } from "lucide-react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { useAppState } from "@/components/app/app-state"
import { investigate, SAMPLE_QUESTION } from "@/lib/analyst"
import { LevelBadge } from "@/components/app/badges"

export function AnalystView() {
  const { assessment, gaps, analystAssetId, activeReport } = useAppState()
  const [selectedAssetId, setSelectedAssetId] = useState<string>(
    analystAssetId || (assessment.assetRisks[0]?.asset.id ?? "")
  )
  const [question] = useState(SAMPLE_QUESTION)

  const currentAssetId =
    selectedAssetId && assessment.assetRisks.some((r) => r.asset.id === selectedAssetId)
      ? selectedAssetId
      : analystAssetId && assessment.assetRisks.some((r) => r.asset.id === analystAssetId)
      ? analystAssetId
      : (assessment.assetRisks[0]?.asset.id ?? "")

  const investigation = investigate(currentAssetId, question, assessment, gaps)

  return (
    <div className="flex flex-col gap-6">
      <Card className="border-primary/20 bg-primary/5">
        <CardHeader>
          <div className="flex items-center gap-2 text-primary">
            <BrainCircuit className="size-5" />
            <CardTitle>AI Risk Analyst (Deterministic Simulation)</CardTitle>
          </div>
          <CardDescription>
            Rule-based evidence investigation engine for prioritised security assets. Explanations are derived from deterministic multi-factor scoring and verified document findings.
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-3">
          <div className="flex-1 w-full">
            <label className="text-xs font-medium text-muted-foreground block mb-1.5">
              Select Asset to Investigate
            </label>
            <Select value={currentAssetId} onValueChange={(val) => val && setSelectedAssetId(val)}>
              <SelectTrigger className="w-full">
                <SelectValue placeholder="Select asset..." />
              </SelectTrigger>
              <SelectContent>
                {assessment.assetRisks.map((r) => (
                  <SelectItem key={r.asset.id} value={r.asset.id}>
                    #{r.rank} {r.asset.name} ({r.score}/100 - {r.category})
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          {activeReport && (
            <div className="flex items-center gap-2 rounded bg-card/80 border px-2.5 py-1 text-xs text-muted-foreground">
              <span className="font-semibold text-foreground">Active Scan Source:</span>
              <span className="font-mono text-primary font-medium">{activeReport.filename || activeReport.report_id}</span>
              <span>· Target: {activeReport.target} ({activeReport.summary.total_findings} findings evaluated)</span>
            </div>
          )}
        </CardContent>
      </Card>

      {investigation && (
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
          <div className="lg:col-span-2 flex flex-col gap-6">
            <Card>
              <CardHeader>
                <CardTitle className="text-base font-semibold flex items-center justify-between">
                  <span>Executive Investigation Summary</span>
                  <LevelBadge level={investigation.category} />
                </CardTitle>
                <CardDescription className="text-sm font-medium text-foreground">
                  {investigation.priorityStatement}
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <p className="text-sm text-muted-foreground leading-relaxed">
                  {investigation.summary}
                </p>
                
                <div className="pt-2">
                  <h4 className="text-xs font-semibold text-foreground uppercase tracking-wider mb-2">
                    Key Risk Drivers
                  </h4>
                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                    {investigation.factors.slice(0, 3).map((f) => (
                      <div key={f.key} className="rounded-md border p-3 bg-muted/30">
                        <span className="text-xs text-muted-foreground block">{f.label}</span>
                        <span className="text-lg font-bold font-mono text-foreground">{f.contribution} pts</span>
                        <span className="text-[11px] text-muted-foreground block truncate">{f.detail}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="text-base font-semibold">Recommended Remediation Actions</CardTitle>
                <CardDescription>Prioritised actions to lower this asset&apos;s risk exposure.</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  {investigation.actions.map((act, idx) => (
                    <div key={act.id} className="flex gap-3 rounded-md border p-3 text-sm">
                      <span className="flex size-6 shrink-0 items-center justify-center rounded-full bg-primary/10 text-xs font-semibold text-primary font-mono">
                        {idx + 1}
                      </span>
                      <div className="space-y-1">
                        <p className="font-medium text-foreground">{act.title}</p>
                        <p className="text-xs text-muted-foreground">{act.rationale}</p>
                        <p className="text-xs text-emerald-600 dark:text-emerald-400 font-medium">
                          Expected outcome: {act.expectedEffect}
                        </p>
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </div>

          <div className="flex flex-col gap-6">
            <Card>
              <CardHeader>
                <CardTitle className="text-base font-semibold">Collected Audit Evidence</CardTitle>
                <CardDescription>Signals collected from inventory and monitoring.</CardDescription>
              </CardHeader>
              <CardContent className="space-y-2">
                {investigation.evidence.map((ev, i) => (
                  <div key={i} className="flex justify-between items-start border-b py-2 text-xs last:border-0">
                    <div>
                      <span className="font-mono font-medium text-foreground block">{ev.field}</span>
                      <span className="text-[11px] text-muted-foreground">{ev.source}</span>
                    </div>
                    <span className="font-mono text-muted-foreground bg-muted px-2 py-0.5 rounded">{ev.value}</span>
                  </div>
                ))}
              </CardContent>
            </Card>

            {investigation.gaps.length > 0 && (
              <Card className="border-warning/30 bg-warning/5">
                <CardHeader>
                  <CardTitle className="text-base font-semibold text-warning flex items-center gap-2">
                    <ShieldAlert className="size-4" /> Control Gaps
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-2">
                  {investigation.gaps.map((g, idx) => (
                    <div key={idx} className="text-xs space-y-1">
                      <div className="flex justify-between items-center">
                        <span className="font-medium text-foreground">{g.title}</span>
                        <LevelBadge level={g.severity} />
                      </div>
                      <p className="text-muted-foreground">{g.detail}</p>
                    </div>
                  ))}
                </CardContent>
              </Card>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
