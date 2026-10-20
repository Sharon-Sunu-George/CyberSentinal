"use client"

import { useState, useEffect } from "react"
import {
  AlertTriangle,
  ArrowLeft,
  CheckCircle2,
  Code2,
  DollarSign,
  FileText,
  Globe,
  Layers,
  Loader2,
  RotateCcw,
  Shield,
  ShieldCheck,
  Sliders,
  Terminal,
  Wrench,
  XCircle,
} from "lucide-react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { useAppState } from "@/components/app/app-state"
import {
  apiClient,
  type AttackerScanResponse,
  type DefenderAnalysisResponse,
  type RemediationRecommendation,
} from "@/lib/api-client"

export function RemediationCenterView({ scanId: propScanId }: { scanId?: string }) {
  const { selectedScanId, navigate } = useAppState()
  const activeScanId = propScanId || selectedScanId

  const [scanResult, setScanResult] = useState<AttackerScanResponse | null>(null)
  const [defenderPlan, setDefenderPlan] = useState<DefenderAnalysisResponse | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [isCalculating, setIsCalculating] = useState(false)
  const [error, setError] = useState<string | null>(null)

  // Budget settings
  const [availableBudget, setAvailableBudget] = useState<number>(5000)
  const [hourlyRate, setHourlyRate] = useState<number>(125)
  const [currency, setCurrency] = useState<string>("USD")

  // Priority tabs
  const [activeTab, setActiveTab] = useState<"fix_immediately" | "fix_next" | "defer_or_mitigate" | "all">("fix_immediately")

  // Status updating & verification states
  const [statusUpdating, setStatusUpdating] = useState<Record<string, boolean>>({})
  const [isVerifying, setIsVerifying] = useState<Record<string, boolean>>({})
  const [verificationFeedback, setVerificationFeedback] = useState<Record<string, {
    success: boolean
    message: string
    new_status: string
    is_inconclusive?: boolean
  }>>({})

  // Remediation history audit log
  const [historyEvents, setHistoryEvents] = useState<any[]>([])

  const loadData = async () => {
    setIsLoading(true)
    setError(null)
    try {
      let targetId = activeScanId

      // If no scanId, get latest recent scan
      if (!targetId) {
        const recent = await apiClient.getRecentScans(1)
        if (recent && recent.length > 0) {
          targetId = recent[0].scan_id
        }
      }

      if (!targetId) {
        setIsLoading(false)
        return
      }

      // Fetch scan record
      const scan = await apiClient.getScanRecord(targetId)
      setScanResult(scan)

      // Fetch existing plan or calculate new one
      let plan = await apiClient.getDefenderPlan(targetId).catch(() => null)
      if (!plan && scan.findings.length > 0) {
        plan = await apiClient.analyzeDefenderBudget({
          scan_id: scan.scan_id,
          target_url: scan.target_url,
          findings: scan.findings,
          available_budget: availableBudget,
          hourly_rate: hourlyRate,
          currency: currency,
        }).catch(() => null)
      }

      if (plan) {
        setDefenderPlan(plan)
        setAvailableBudget(plan.available_budget)
        setHourlyRate(plan.hourly_rate)
        if (plan.currency) setCurrency(plan.currency)
      }

      // Load audit history
      const historyResp = await apiClient.getRemediationHistory(targetId).catch(() => null)
      if (historyResp && historyResp.history) {
        setHistoryEvents(historyResp.history)
      }
    } catch (err: any) {
      setError(err.message || "Failed to load remediation data.")
    } finally {
      setIsLoading(false)
    }
  }

  useEffect(() => {
    loadData()
  }, [activeScanId])

  const handleRecalculateBudget = async () => {
    if (!scanResult) return
    setIsCalculating(true)
    setError(null)
    try {
      const plan = await apiClient.analyzeDefenderBudget({
        scan_id: scanResult.scan_id,
        target_url: scanResult.target_url,
        findings: scanResult.findings,
        available_budget: availableBudget,
        hourly_rate: hourlyRate,
        currency: currency,
      })
      setDefenderPlan(plan)
    } catch (err: any) {
      setError(err.message || "Failed to recalculate budget.")
    } finally {
      setIsCalculating(false)
    }
  }

  const handleUpdateStatus = async (findingId: string, newStatus: string) => {
    if (!scanResult) return
    setStatusUpdating((prev) => ({ ...prev, [findingId]: true }))
    try {
      await apiClient.updateRemediationStatus(scanResult.scan_id, findingId, newStatus)

      // Update locally in plan
      if (defenderPlan) {
        const updateList = (list: RemediationRecommendation[]) =>
          list.map((item) =>
            item.finding_id === findingId ? { ...item, status: newStatus as any, remediation_status: newStatus } : item
          )

        setDefenderPlan({
          ...defenderPlan,
          fix_immediately: updateList(defenderPlan.fix_immediately),
          fix_next: updateList(defenderPlan.fix_next),
          defer_or_mitigate: updateList(defenderPlan.defer_or_mitigate),
          unbudgeted_high_risk_findings: updateList(defenderPlan.unbudgeted_high_risk_findings),
        })
      }

      // Refresh audit history
      const historyResp = await apiClient.getRemediationHistory(scanResult.scan_id).catch(() => null)
      if (historyResp && historyResp.history) {
        setHistoryEvents(historyResp.history)
      }
    } catch (err: any) {
      setError(`Failed to update status: ${err.message}`)
    } finally {
      setStatusUpdating((prev) => ({ ...prev, [findingId]: false }))
    }
  }

  const handleVerify = async (findingId: string) => {
    if (!scanResult) return
    setIsVerifying((prev) => ({ ...prev, [findingId]: true }))
    setError(null)
    try {
      const res = await apiClient.verifyRemediation(scanResult.scan_id, findingId, scanResult.target_url)

      setVerificationFeedback((prev) => ({
        ...prev,
        [findingId]: {
          success: res.verification_passed,
          message: res.evidence_summary || res.message,
          new_status: res.new_status,
          is_inconclusive: res.is_inconclusive,
        },
      }))

      // Update locally in plan
      if (defenderPlan) {
        const updateList = (list: RemediationRecommendation[]) =>
          list.map((item) =>
            item.finding_id === findingId
              ? {
                  ...item,
                  status: res.new_status as any,
                  remediation_status: res.new_status,
                }
              : item
          )

        setDefenderPlan({
          ...defenderPlan,
          fix_immediately: updateList(defenderPlan.fix_immediately),
          fix_next: updateList(defenderPlan.fix_next),
          defer_or_mitigate: updateList(defenderPlan.defer_or_mitigate),
          unbudgeted_high_risk_findings: updateList(defenderPlan.unbudgeted_high_risk_findings),
        })
      }

      // Refresh audit history
      const historyResp = await apiClient.getRemediationHistory(scanResult.scan_id).catch(() => null)
      if (historyResp && historyResp.history) {
        setHistoryEvents(historyResp.history)
      }
    } catch (err: any) {
      setError(`Verification probe failed: ${err.message}`)
    } finally {
      setIsVerifying((prev) => ({ ...prev, [findingId]: false }))
    }
  }

  if (isLoading) {
    return (
      <div className="mx-auto flex max-w-5xl min-h-[400px] flex-col items-center justify-center gap-3 p-8 text-center">
        <Loader2 className="size-6 animate-spin text-primary" />
        <p className="text-xs text-muted-foreground font-mono">Loading remediation workspace…</p>
      </div>
    )
  }

  if (!scanResult) {
    return (
      <div className="mx-auto flex max-w-4xl flex-col gap-4 p-8 text-center">
        <div className="rounded-xl border border-dashed p-10 space-y-3">
          <Wrench className="size-8 mx-auto text-muted-foreground" />
          <h2 className="text-base font-bold text-foreground">No Scan Selected for Remediation</h2>
          <p className="text-xs text-muted-foreground max-w-md mx-auto">
            Run an assessment scan first to discover security gaps and compute budget-aware remediation plans.
          </p>
          <Button onClick={() => navigate("agent-simulation")} className="gap-2 text-xs font-semibold">
            Open Attack Surface Scanner
          </Button>
        </div>
      </div>
    )
  }

  const getSeverityBadgeClass = (sev: string) => {
    switch (sev.toLowerCase()) {
      case "critical":
        return "bg-rose-500/15 text-rose-400 border-rose-500/30"
      case "high":
        return "bg-destructive/15 text-destructive border-destructive/30"
      case "medium":
        return "bg-amber-500/15 text-amber-400 border-amber-500/30"
      case "low":
        return "bg-blue-500/15 text-blue-400 border-blue-500/30"
      default:
        return "bg-muted text-muted-foreground border-border"
    }
  }

  let displayedRecs: RemediationRecommendation[] = []
  if (defenderPlan) {
    if (activeTab === "fix_immediately") displayedRecs = defenderPlan.fix_immediately
    else if (activeTab === "fix_next") displayedRecs = defenderPlan.fix_next
    else if (activeTab === "defer_or_mitigate") displayedRecs = defenderPlan.defer_or_mitigate
    else displayedRecs = [...defenderPlan.fix_immediately, ...defenderPlan.fix_next, ...defenderPlan.defer_or_mitigate]
  }

  return (
    <div className="mx-auto flex max-w-5xl flex-col gap-6 pb-12">
      {/* ─────────────────────────────────────────────────────────────
          PAGE HEADER
      ───────────────────────────────────────────────────────────── */}
      <div className="flex flex-col gap-2 border-b border-border/80 pb-4 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex items-center gap-3">
          <span className="flex size-9 items-center justify-center rounded-lg bg-primary/15 text-primary ring-1 ring-primary/30">
            <Wrench className="size-5" />
          </span>
          <div>
            <h1 className="text-lg font-bold tracking-tight text-foreground">
              Remediation Planner & Verification Workspace
            </h1>
            <p className="text-xs text-muted-foreground">
              Deterministic, budget-constrained technical fix playbooks and empirical verification probes.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={() => navigate("agent-simulation")}
            className="h-8 gap-1.5 text-xs"
          >
            <ArrowLeft className="size-3" /> Scanner
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={() => navigate("assessment-report", undefined, scanResult.scan_id)}
            className="h-8 gap-1.5 text-xs"
          >
            <FileText className="size-3" /> View Findings Report
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={() => navigate("overview")}
            className="h-8 gap-1.5 text-xs"
          >
            Overview
          </Button>
        </div>
      </div>

      {error && (
        <div className="rounded-lg border border-destructive/30 bg-destructive/10 p-3 text-xs text-destructive flex items-center gap-2">
          <AlertTriangle className="size-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* ─────────────────────────────────────────────────────────────
          BUDGET & LABOR RATE ALLOCATION CARD
      ───────────────────────────────────────────────────────────── */}
      <Card className="border-border bg-card shadow-sm">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-base text-foreground flex items-center gap-2">
              <DollarSign className="size-4 text-primary" />
              Remediation Budget & Labor Rate Constraints
            </CardTitle>
            <span className="text-[11px] font-mono text-muted-foreground">
              Target: <span className="text-foreground">{scanResult.normalized_url}</span>
            </span>
          </div>
          <CardDescription className="text-xs text-muted-foreground">
            The Remediation Planner applies deterministic knapsack prioritization to sequence technical fixes under explicit labor and budget bounds.
          </CardDescription>
        </CardHeader>

        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 sm:grid-cols-4 gap-3">
            <div className="space-y-1">
              <label className="text-xs font-medium text-foreground">Available Budget</label>
              <input
                type="number"
                min="100"
                step="250"
                value={availableBudget}
                onChange={(e) => setAvailableBudget(Number(e.target.value))}
                disabled={isCalculating}
                className="flex h-9 w-full rounded border border-input bg-background px-3 font-mono text-xs font-bold"
              />
            </div>

            <div className="space-y-1">
              <label className="text-xs font-medium text-foreground">Hourly Rate</label>
              <input
                type="number"
                min="50"
                step="25"
                value={hourlyRate}
                onChange={(e) => setHourlyRate(Number(e.target.value))}
                disabled={isCalculating}
                className="flex h-9 w-full rounded border border-input bg-background px-3 font-mono text-xs"
              />
            </div>

            <div className="space-y-1">
              <label className="text-xs font-medium text-foreground">Currency</label>
              <select
                value={currency}
                onChange={(e) => setCurrency(e.target.value)}
                disabled={isCalculating}
                className="flex h-9 w-full rounded border border-input bg-background px-2.5 font-mono text-xs"
              >
                <option value="USD">USD ($)</option>
                <option value="EUR">EUR (€)</option>
                <option value="GBP">GBP (£)</option>
                <option value="CAD">CAD ($)</option>
                <option value="AUD">AUD ($)</option>
              </select>
            </div>

            <div className="flex items-end">
              <Button
                onClick={handleRecalculateBudget}
                disabled={isCalculating}
                className="w-full h-9 text-xs font-semibold gap-1.5"
              >
                {isCalculating ? (
                  <>
                    <Loader2 className="size-3.5 animate-spin" /> Recalculating…
                  </>
                ) : (
                  <>
                    <Sliders className="size-3.5" /> Optimize Budget
                  </>
                )}
              </Button>
            </div>
          </div>

          {/* Budget Allocation Summary Cards */}
          {defenderPlan && (
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-2 text-xs">
              <div className="rounded-lg border bg-muted/20 p-2.5 text-center">
                <span className="text-[10px] text-muted-foreground block uppercase">Proposed Spending</span>
                <span className="font-mono text-base font-bold text-foreground">
                  ${defenderPlan.proposed_spending.toLocaleString()}
                </span>
              </div>
              <div className="rounded-lg border bg-muted/20 p-2.5 text-center">
                <span className="text-[10px] text-muted-foreground block uppercase">Remaining Budget</span>
                <span className="font-mono text-base font-bold text-emerald-400">
                  ${defenderPlan.remaining_budget.toLocaleString()}
                </span>
              </div>
              <div className="rounded-lg border bg-muted/20 p-2.5 text-center">
                <span className="text-[10px] text-muted-foreground block uppercase">Risk Reduction</span>
                <span className="font-mono text-base font-bold text-emerald-400">
                  -{defenderPlan.total_risk_reduction_percent}%
                </span>
              </div>
              <div className="rounded-lg border bg-muted/20 p-2.5 text-center">
                <span className="text-[10px] text-muted-foreground block uppercase">Cost Efficiency</span>
                <span className="font-mono text-base font-bold text-primary">
                  {defenderPlan.risk_reduction_per_dollar} pts / $1k
                </span>
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {/* ─────────────────────────────────────────────────────────────
          PRIORITIZED REMEDIATION PLAYBOOKS
      ───────────────────────────────────────────────────────────── */}
      {defenderPlan && (
        <Card className="border-border bg-card shadow-sm">
          <CardHeader className="pb-3">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div>
                <CardTitle className="text-base text-foreground flex items-center gap-2">
                  <Layers className="size-4 text-primary" />
                  Prioritized Remediation Actions
                </CardTitle>
                <CardDescription className="text-xs text-muted-foreground">
                  Actionable technical steps with ready-to-use configuration examples.
                </CardDescription>
              </div>

              {/* Priority Tiers */}
              <div className="inline-flex rounded-lg border bg-muted/30 p-1 text-xs">
                <button
                  type="button"
                  onClick={() => setActiveTab("fix_immediately")}
                  className={`rounded px-2.5 py-1 font-mono text-[11px] font-medium transition-all ${
                    activeTab === "fix_immediately"
                      ? "bg-rose-500/20 text-rose-300 font-bold border border-rose-500/40"
                      : "text-muted-foreground hover:text-foreground"
                  }`}
                >
                  Fix Immediately ({defenderPlan.fix_immediately.length})
                </button>
                <button
                  type="button"
                  onClick={() => setActiveTab("fix_next")}
                  className={`rounded px-2.5 py-1 font-mono text-[11px] font-medium transition-all ${
                    activeTab === "fix_next"
                      ? "bg-primary/20 text-primary font-bold border border-primary/40"
                      : "text-muted-foreground hover:text-foreground"
                  }`}
                >
                  Fix Next ({defenderPlan.fix_next.length})
                </button>
                <button
                  type="button"
                  onClick={() => setActiveTab("defer_or_mitigate")}
                  className={`rounded px-2.5 py-1 font-mono text-[11px] font-medium transition-all ${
                    activeTab === "defer_or_mitigate"
                      ? "bg-amber-500/20 text-amber-300 font-bold border border-amber-500/40"
                      : "text-muted-foreground hover:text-foreground"
                  }`}
                >
                  Defer ({defenderPlan.defer_or_mitigate.length})
                </button>
              </div>
            </div>
          </CardHeader>

          <CardContent className="space-y-4">
            {displayedRecs.length === 0 ? (
              <div className="rounded-lg border border-dashed p-8 text-center text-xs text-muted-foreground">
                No findings categorized in this priority tier under current budget constraints.
              </div>
            ) : (
              <div className="space-y-4">
                {displayedRecs.map((item) => (
                  <div
                    key={item.finding_id}
                    className="rounded-lg border bg-muted/10 p-4 space-y-3.5 text-xs transition-colors hover:bg-muted/15"
                  >
                    {/* Header */}
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b pb-2.5">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className={`rounded-full border px-2 py-0.5 font-mono text-[10px] font-bold ${getSeverityBadgeClass(item.severity)}`}>
                          {item.severity}
                        </span>
                        <h4 className="font-bold text-foreground text-sm">{item.finding_title}</h4>
                        {item.cwe_id && (
                          <span className="rounded bg-muted px-1.5 py-0.5 font-mono text-[10px] text-muted-foreground">
                            {item.cwe_id}
                          </span>
                        )}
                      </div>

                      <div className="flex items-center gap-3 font-mono text-[11px]">
                        <span className="text-muted-foreground">Effort: <strong>{item.estimated_effort_hours}h</strong></span>
                        <span className="text-foreground font-bold">Cost: ${item.total_cost.toLocaleString()}</span>
                        <span className="text-emerald-400 font-bold">-{item.projected_risk_reduction} pts</span>
                      </div>
                    </div>

                    {/* Explanations */}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3 leading-relaxed">
                      <div className="space-y-1">
                        <p className="font-semibold text-foreground flex items-center gap-1.5">
                          <AlertTriangle className="size-3.5 text-amber-400" /> Why It Matters
                        </p>
                        <p className="text-muted-foreground">{item.why_it_matters || item.root_cause}</p>
                      </div>

                      <div className="space-y-1">
                        <p className="font-semibold text-foreground flex items-center gap-1.5">
                          <CheckCircle2 className="size-3.5 text-emerald-400" /> Concrete Fix
                        </p>
                        <p className="text-muted-foreground">{item.recommended_fix || item.actionable_fix}</p>
                      </div>
                    </div>

                    {/* Code Snippets */}
                    {item.code_snippets && Object.keys(item.code_snippets).length > 0 && (
                      <div className="space-y-1.5">
                        <p className="text-[10px] font-mono font-semibold uppercase tracking-wider text-muted-foreground">
                          Server Hardening Configuration Snippets:
                        </p>
                        <div className="grid grid-cols-1 gap-2">
                          {Object.entries(item.code_snippets).map(([srv, code]) => (
                            <div key={srv} className="rounded-md border bg-black/60 p-2.5 font-mono text-[11px]">
                              <span className="text-[10px] text-primary font-bold">// {srv}</span>
                              <pre className="text-emerald-400 whitespace-pre-wrap overflow-x-auto mt-1">
                                {code}
                              </pre>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Action & Verification Box */}
                    <div className="rounded-md border bg-background/80 p-3 space-y-2 font-mono">
                      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                        <div className="flex items-center gap-2 text-[11px] text-muted-foreground truncate">
                          <Terminal className="size-3 text-primary shrink-0" />
                          <span className="font-semibold text-foreground">Verification Procedure:</span>
                          <span className="text-emerald-400 truncate">{item.verification_procedure}</span>
                        </div>

                        <div className="flex items-center gap-2 shrink-0">
                          <Button
                            type="button"
                            size="sm"
                            variant="outline"
                            onClick={() => handleVerify(item.finding_id)}
                            disabled={isVerifying[item.finding_id]}
                            className="h-7 text-xs font-mono border-emerald-500/40 text-emerald-400 hover:bg-emerald-500/10"
                          >
                            {isVerifying[item.finding_id] ? (
                              <>
                                <Loader2 className="mr-1 size-3 animate-spin" /> Verifying…
                              </>
                            ) : (
                              <>
                                <ShieldCheck className="mr-1 size-3.5" /> Verify Fix on Wire
                              </>
                            )}
                          </Button>

                          <div className="flex items-center gap-1.5">
                            <label className="text-[10px] text-muted-foreground">Status:</label>
                            <select
                              value={item.status}
                              onChange={(e) => handleUpdateStatus(item.finding_id, e.target.value)}
                              disabled={statusUpdating[item.finding_id] || isVerifying[item.finding_id]}
                              className="h-7 rounded border bg-background px-2 text-xs font-mono font-semibold"
                            >
                              <option value="Not Started">Not Started</option>
                              <option value="In Progress">In Progress</option>
                              <option value="Fixed Pending Verification">Fixed Pending Verification</option>
                              <option value="Verified Fixed">Verified Fixed</option>
                              <option value="Reopened">Reopened</option>
                            </select>
                            {statusUpdating[item.finding_id] && (
                              <Loader2 className="size-3 animate-spin text-primary" />
                            )}
                          </div>
                        </div>
                      </div>

                      {/* Verification Outcome Banner */}
                      {verificationFeedback[item.finding_id] && (
                        <div
                          className={`rounded p-2 text-xs font-sans space-y-0.5 ${
                            verificationFeedback[item.finding_id].success
                              ? "bg-emerald-500/10 border border-emerald-500/30 text-emerald-300"
                              : verificationFeedback[item.finding_id].is_inconclusive
                              ? "bg-amber-500/10 border border-amber-500/30 text-amber-300"
                              : "bg-destructive/10 border border-destructive/30 text-destructive"
                          }`}
                        >
                          <span className="font-bold font-mono">
                            Outcome: {verificationFeedback[item.finding_id].new_status}
                          </span>
                          <p className="text-[11px] leading-relaxed">
                            {verificationFeedback[item.finding_id].message}
                          </p>
                        </div>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {/* ─────────────────────────────────────────────────────────────
          REMEDIATION AUDIT TRAIL TABLE
      ───────────────────────────────────────────────────────────── */}
      {historyEvents.length > 0 && (
        <Card className="border-border bg-card shadow-sm">
          <CardHeader className="pb-3">
            <CardTitle className="text-base text-foreground">Remediation Audit Trail</CardTitle>
            <CardDescription className="text-xs text-muted-foreground">
              Immutable history of status transitions, notes, and wire verification timestamps.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-border/60 text-[11px] font-mono text-muted-foreground">
                    <th className="pb-2 font-medium">Finding ID</th>
                    <th className="pb-2 font-medium">Previous State</th>
                    <th className="pb-2 font-medium">New State</th>
                    <th className="pb-2 font-medium">Notes / Probe Evidence</th>
                    <th className="pb-2 text-right font-medium">Timestamp</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border/40 font-mono text-[11px]">
                  {historyEvents.slice(0, 10).map((h, i) => (
                    <tr key={i} className="hover:bg-muted/10 transition-colors">
                      <td className="py-2.5 font-bold text-foreground">{h.finding_id}</td>
                      <td className="py-2.5 text-muted-foreground">{h.old_status}</td>
                      <td className="py-2.5">
                        <span className="rounded bg-primary/10 text-primary border border-primary/20 px-1.5 py-0.5 font-semibold">
                          {h.new_status}
                        </span>
                      </td>
                      <td className="py-2.5 text-muted-foreground font-sans text-xs max-w-sm truncate">
                        {h.notes || h.evidence?.evidence_desc || "Status updated"}
                      </td>
                      <td className="py-2.5 text-right text-muted-foreground font-sans text-[11px]">
                        {new Date(h.changed_at).toLocaleString()}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  )
}
