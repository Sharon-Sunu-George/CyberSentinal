"use client"

import { useEffect, useState } from "react"
import {
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  Clock,
  ExternalLink,
  FileText,
  Globe,
  Layers,
  Loader2,
  PlusCircle,
  RefreshCw,
  RotateCcw,
  Shield,
  ShieldAlert,
  ShieldCheck,
  TrendingDown,
  Wrench,
} from "lucide-react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { useAppState } from "@/components/app/app-state"
import {
  apiClient,
  type AttackerScanResponse,
  type DefenderAnalysisResponse,
} from "@/lib/api-client"

export function DashboardView() {
  const { navigate } = useAppState()
  const [recentScans, setRecentScans] = useState<any[]>([])
  const [latestScan, setLatestScan] = useState<AttackerScanResponse | null>(null)
  const [latestPlan, setLatestPlan] = useState<DefenderAnalysisResponse | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const loadDashboardData = async () => {
    setIsLoading(true)
    setError(null)
    try {
      // 1. Fetch recent scans from persisted backend database
      const scans = await apiClient.getRecentScans(10)
      setRecentScans(scans || [])

      if (scans && scans.length > 0) {
        const latestId = scans[0].scan_id
        // 2. Fetch full scan details for the latest scan
        const scanRecord = await apiClient.getScanRecord(latestId).catch(() => null)
        setLatestScan(scanRecord)

        // 3. Fetch latest remediation plan for this scan if available
        const planRecord = await apiClient.getDefenderPlan(latestId).catch(() => null)
        setLatestPlan(planRecord)
      } else {
        setLatestScan(null)
        setLatestPlan(null)
      }
    } catch (err: any) {
      setError(err.message || "Failed to load dashboard data from backend.")
    } finally {
      setIsLoading(false)
    }
  }

  useEffect(() => {
    loadDashboardData()
  }, [])

  // Derive findings breakdown from actual latest scan findings
  const findings = latestScan?.findings || []
  const totalFindings = findings.length
  const criticalCount = findings.filter((f) => f.severity.toLowerCase() === "critical").length
  const highCount = findings.filter((f) => f.severity.toLowerCase() === "high").length
  const mediumCount = findings.filter((f) => f.severity.toLowerCase() === "medium").length
  const lowCount = findings.filter((f) => f.severity.toLowerCase() === "low").length
  const infoCount = findings.filter((f) => f.severity.toLowerCase() === "info").length

  // Remediation status breakdown derived from persisted records
  const verifiedFixedCount = findings.filter(
    (f) => f.remediation_status === "Verified"
  ).length
  const fixedCount = findings.filter(
    (f) => f.remediation_status === "Fixed"
  ).length
  const inProgressCount = findings.filter((f) => f.remediation_status === "In Progress").length
  const unresolvedCount = findings.filter(
    (f) => f.remediation_status !== "Verified"
  ).length

  return (
    <div className="mx-auto flex max-w-6xl flex-col gap-6 pb-12">
      {/* ─────────────────────────────────────────────────────────────
          PAGE HEADER
      ───────────────────────────────────────────────────────────── */}
      <div className="flex flex-col gap-2 border-b border-border/80 pb-4 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex items-center gap-3">
          <span className="flex size-9 items-center justify-center rounded-lg bg-primary/15 text-primary ring-1 ring-primary/30">
            <Shield className="size-5" />
          </span>
          <div>
            <h1 className="text-lg font-bold tracking-tight text-foreground">
              Security Assessment Dashboard
            </h1>
            <p className="text-xs text-muted-foreground">
              Real-time attack surface posture, empirical findings, and remediation budget tracking.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={loadDashboardData}
            disabled={isLoading}
            className="h-8 gap-1.5 text-xs font-medium"
          >
            <RefreshCw className={`size-3.5 ${isLoading ? "animate-spin" : ""}`} />
            Refresh
          </Button>

          <Button
            size="sm"
            onClick={() => navigate("new-assessment")}
            className="h-8 gap-1.5 bg-primary text-primary-foreground text-xs font-semibold hover:bg-primary/90"
          >
            <PlusCircle className="size-3.5" />
            New Assessment
          </Button>
        </div>
      </div>

      {/* ─────────────────────────────────────────────────────────────
          ERROR NOTICE
      ───────────────────────────────────────────────────────────── */}
      {error && (
        <div className="rounded-lg border border-destructive/40 bg-destructive/10 p-3.5 text-xs text-destructive flex items-center justify-between">
          <div className="flex items-center gap-2">
            <AlertTriangle className="size-4 shrink-0" />
            <span>{error}</span>
          </div>
          <Button variant="ghost" size="sm" onClick={loadDashboardData} className="h-7 text-xs text-destructive hover:bg-destructive/20">
            Retry
          </Button>
        </div>
      )}

      {/* ─────────────────────────────────────────────────────────────
          LOADING STATE
      ───────────────────────────────────────────────────────────── */}
      {isLoading && (
        <div className="flex min-h-[300px] flex-col items-center justify-center gap-3 rounded-xl border border-dashed p-8 text-center">
          <Loader2 className="size-6 animate-spin text-primary" />
          <p className="text-xs text-muted-foreground font-mono">Loading persisted assessment records…</p>
        </div>
      )}

      {/* ─────────────────────────────────────────────────────────────
          EMPTY STATE
      ───────────────────────────────────────────────────────────── */}
      {!isLoading && recentScans.length === 0 && (
        <div className="flex min-h-[360px] flex-col items-center justify-center gap-4 rounded-xl border border-dashed border-border/80 bg-card/40 p-8 text-center">
          <div className="flex size-12 items-center justify-center rounded-full bg-muted/60 text-muted-foreground">
            <Globe className="size-6" />
          </div>
          <div className="max-w-md space-y-1.5">
            <h3 className="text-base font-bold text-foreground">No Assessments Recorded Yet</h3>
            <p className="text-xs text-muted-foreground leading-relaxed">
              Launch an automated perimeter scan using the Attack Surface Scanner. Empirical findings, evidence-backed vulnerability classifications, and prioritized remediation playbooks will appear here.
            </p>
          </div>
          <Button
            onClick={() => navigate("new-assessment")}
            className="gap-2 text-xs font-semibold"
          >
            <PlusCircle className="size-4" /> Start First Assessment
          </Button>
        </div>
      )}

      {/* ─────────────────────────────────────────────────────────────
          LIVE DASHBOARD CONTENT
      ───────────────────────────────────────────────────────────── */}
      {!isLoading && recentScans.length > 0 && (
        <>
          {/* ROW 1: PRIMARY METRIC CARDS */}
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
            {/* CARD 1: LATEST TARGET */}
            <Card className="border-border bg-card">
              <CardHeader className="pb-2">
                <CardDescription className="text-[11px] font-medium text-muted-foreground uppercase tracking-wider">
                  Latest Target
                </CardDescription>
                <CardTitle className="truncate font-mono text-base font-bold text-foreground">
                  {latestScan?.target_url || recentScans[0]?.target_url || "N/A"}
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-1.5">
                <div className="flex items-center justify-between text-xs">
                  <span className="text-muted-foreground">Scan Status:</span>
                  <span
                    className={`rounded px-1.5 py-0.5 font-mono text-[10px] font-semibold uppercase ${
                      (latestScan?.status || recentScans[0]?.status) === "completed"
                        ? "bg-emerald-500/15 text-emerald-400 border border-emerald-500/30"
                        : "bg-muted text-foreground"
                    }`}
                  >
                    {latestScan?.status || recentScans[0]?.status}
                  </span>
                </div>
                <div className="text-[11px] font-mono text-muted-foreground">
                  {new Date(latestScan?.scanned_at || recentScans[0]?.scanned_at).toLocaleString()}
                </div>
              </CardContent>
            </Card>

            {/* CARD 2: TOTAL UNIQUE FINDINGS */}
            <Card className="border-border bg-card">
              <CardHeader className="pb-2">
                <CardDescription className="text-[11px] font-medium text-muted-foreground uppercase tracking-wider">
                  Total Unique Findings
                </CardDescription>
                <div className="flex items-baseline gap-2">
                  <span className="font-mono text-2xl font-bold text-foreground tabular-nums">
                    {totalFindings}
                  </span>
                  <span className="text-xs text-muted-foreground">in perimeter</span>
                </div>
              </CardHeader>
              <CardContent>
                <div className="flex flex-wrap gap-1.5 text-[10px] font-mono font-bold">
                  {criticalCount > 0 && (
                    <span className="rounded bg-rose-500/15 text-rose-400 border border-rose-500/30 px-1.5 py-0.5">
                      {criticalCount} Critical
                    </span>
                  )}
                  {highCount > 0 && (
                    <span className="rounded bg-destructive/15 text-destructive border border-destructive/30 px-1.5 py-0.5">
                      {highCount} High
                    </span>
                  )}
                  {mediumCount > 0 && (
                    <span className="rounded bg-amber-500/15 text-amber-400 border border-amber-500/30 px-1.5 py-0.5">
                      {mediumCount} Med
                    </span>
                  )}
                  {lowCount > 0 && (
                    <span className="rounded bg-blue-500/15 text-blue-400 border border-blue-500/30 px-1.5 py-0.5">
                      {lowCount} Low
                    </span>
                  )}
                  {infoCount > 0 && (
                    <span className="rounded bg-muted px-1.5 py-0.5 text-muted-foreground">
                      {infoCount} Info
                    </span>
                  )}
                </div>
              </CardContent>
            </Card>

            {/* CARD 3: REMEDIATION PROGRESS */}
            <Card className="border-border bg-card">
              <CardHeader className="pb-2">
                <CardDescription className="text-[11px] font-medium text-muted-foreground uppercase tracking-wider">
                  Verified Fixes
                </CardDescription>
                <div className="flex items-baseline gap-2">
                  <span className="font-mono text-2xl font-bold text-emerald-400 tabular-nums">
                    {verifiedFixedCount}
                  </span>
                  <span className="text-xs text-muted-foreground font-mono">
                    / {totalFindings} resolved
                  </span>
                </div>
              </CardHeader>
              <CardContent className="space-y-1 text-xs">
                <div className="flex items-center justify-between">
                  <span className="text-muted-foreground">Unresolved:</span>
                  <span className="font-mono font-semibold text-rose-400">{unresolvedCount}</span>
                </div>
                {fixedCount > 0 && (
                  <div className="flex items-center justify-between text-amber-300">
                    <span>Fixed (Awaiting Retest):</span>
                    <span className="font-mono font-semibold">{fixedCount}</span>
                  </div>
                )}
              </CardContent>
            </Card>

            {/* CARD 4: BUDGET ALLOCATION (FROM REAL REMEDIATION PLAN) */}
            <Card className="border-border bg-card">
              <CardHeader className="pb-2">
                <CardDescription className="text-[11px] font-medium text-muted-foreground uppercase tracking-wider">
                  Remediation Budget
                </CardDescription>
                <div className="flex items-baseline gap-2">
                  {latestPlan ? (
                    <>
                      <span className="font-mono text-xl font-bold text-foreground tabular-nums">
                        ${latestPlan.proposed_spending.toLocaleString()}
                      </span>
                      <span className="text-xs text-muted-foreground font-mono">
                        / ${latestPlan.available_budget.toLocaleString()}
                      </span>
                    </>
                  ) : (
                    <span className="text-xs text-muted-foreground">Plan Not Formulated</span>
                  )}
                </div>
              </CardHeader>
              <CardContent className="text-xs">
                {latestPlan ? (
                  <div className="space-y-1">
                    <div className="flex items-center justify-between">
                      <span className="text-muted-foreground">Remaining:</span>
                      <span className="font-mono font-semibold text-emerald-400">
                        ${latestPlan.remaining_budget.toLocaleString()}
                      </span>
                    </div>
                    <div className="flex items-center justify-between text-[11px] text-muted-foreground">
                      <span>Rate: ${latestPlan.hourly_rate}/hr</span>
                      <span className="text-emerald-400 font-mono">
                        -{latestPlan.total_risk_reduction_percent}% risk
                      </span>
                    </div>
                  </div>
                ) : (
                  <p className="text-[11px] text-muted-foreground">
                    Open Remediation Center to calculate plan.
                  </p>
                )}
              </CardContent>
            </Card>
          </div>

          {/* ROW 2: ACTIVE SCAN DETAILS & QUICK ACTIONS */}
          {latestScan && (
            <Card className="border-border/80 bg-card shadow-sm">
              <CardHeader className="pb-3">
                <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
                  <div className="flex items-center gap-2.5">
                    <span className="flex size-7 items-center justify-center rounded bg-primary/10 text-primary">
                      <FileText className="size-4" />
                    </span>
                    <div>
                      <CardTitle className="text-base text-foreground">
                        Latest Assessment Summary: {latestScan.normalized_url}
                      </CardTitle>
                      <CardDescription className="text-xs text-muted-foreground">
                        Scan ID: <span className="font-mono text-foreground">{latestScan.scan_id}</span> · Target IP: {latestScan.target_ip || "External Gateway"}
                      </CardDescription>
                    </div>
                  </div>

                  <div className="flex items-center gap-2">
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => navigate("assessment-report", undefined, latestScan.scan_id)}
                      className="h-8 gap-1 text-xs"
                    >
                      View Report <ArrowRight className="size-3" />
                    </Button>
                    <Button
                      size="sm"
                      onClick={() => navigate("remediation-center", undefined, latestScan.scan_id)}
                      className="h-8 gap-1.5 bg-primary text-primary-foreground text-xs font-semibold"
                    >
                      <Wrench className="size-3" />
                      Remediation Center
                    </Button>
                  </div>
                </div>
              </CardHeader>

              <CardContent className="space-y-4">
                {/* Findings Breakdown Bar */}
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
                  <div className="rounded-lg border bg-muted/20 p-2.5 text-center">
                    <span className="text-[10px] text-muted-foreground block uppercase">Critical / High</span>
                    <span className="font-mono text-base font-bold text-destructive">
                      {criticalCount + highCount}
                    </span>
                  </div>
                  <div className="rounded-lg border bg-muted/20 p-2.5 text-center">
                    <span className="text-[10px] text-muted-foreground block uppercase">Medium / Low</span>
                    <span className="font-mono text-base font-bold text-foreground">
                      {mediumCount + lowCount}
                    </span>
                  </div>
                  <div className="rounded-lg border bg-muted/20 p-2.5 text-center">
                    <span className="text-[10px] text-muted-foreground block uppercase">Pages Crawled</span>
                    <span className="font-mono text-base font-bold text-foreground">
                      {latestScan.summary?.pages_visited || latestScan.discovered_pages?.length || 1}
                    </span>
                  </div>
                  <div className="rounded-lg border bg-muted/20 p-2.5 text-center">
                    <span className="text-[10px] text-muted-foreground block uppercase">Verified Resolved</span>
                    <span className="font-mono text-base font-bold text-emerald-400">
                      {verifiedFixedCount}
                    </span>
                  </div>
                </div>

                {/* Top 3 Unresolved Findings */}
                {findings.length > 0 && (
                  <div className="space-y-2 pt-1">
                    <div className="flex items-center justify-between text-xs">
                      <span className="font-semibold text-foreground">Priority Findings to Address:</span>
                      <button
                        type="button"
                        onClick={() => navigate("assessment-report", undefined, latestScan.scan_id)}
                        className="text-[11px] text-primary hover:underline font-mono"
                      >
                        View all {findings.length} findings →
                      </button>
                    </div>

                    <div className="space-y-2">
                      {findings.slice(0, 3).map((f) => (
                        <div
                          key={f.id}
                          className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 rounded-lg border bg-muted/10 p-3 text-xs"
                        >
                          <div className="flex items-center gap-2.5">
                            <span
                              className={`rounded px-1.5 py-0.5 font-mono text-[10px] font-bold ${
                                f.severity.toLowerCase() === "critical"
                                  ? "bg-rose-500/15 text-rose-400 border border-rose-500/30"
                                  : f.severity.toLowerCase() === "high"
                                  ? "bg-destructive/15 text-destructive border border-destructive/30"
                                  : "bg-amber-500/15 text-amber-400 border border-amber-500/30"
                              }`}
                            >
                              {f.severity}
                            </span>
                            <span className="font-medium text-foreground">{f.title}</span>
                          </div>

                          <div className="flex items-center gap-2">
                            <span className="font-mono text-[10px] text-muted-foreground">
                              {f.remediation_status}
                            </span>
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => navigate("remediation-center", undefined, latestScan.scan_id)}
                              className="h-6 px-2 text-[11px] text-primary hover:underline"
                            >
                              Plan Fix
                            </Button>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>
          )}

          {/* ROW 3: RECENT ASSESSMENTS TABLE */}
          <Card className="border-border/80 bg-card shadow-sm">
            <CardHeader className="pb-3">
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle className="text-base text-foreground">Recent Assessments</CardTitle>
                  <CardDescription className="text-xs text-muted-foreground">
                    Persisted scan history from local assessment database.
                  </CardDescription>
                </div>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => navigate("assessment-history")}
                  className="h-7 text-xs"
                >
                  View All History
                </Button>
              </div>
            </CardHeader>
            <CardContent>
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead>
                    <tr className="border-b border-border/60 text-[11px] font-mono text-muted-foreground">
                      <th className="pb-2 font-medium">Target URL</th>
                      <th className="pb-2 font-medium">Scan ID</th>
                      <th className="pb-2 font-medium">Scanned At</th>
                      <th className="pb-2 font-medium">Status</th>
                      <th className="pb-2 font-medium">Findings</th>
                      <th className="pb-2 text-right font-medium">Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border/40 font-mono text-[11px]">
                    {recentScans.slice(0, 5).map((scan) => (
                      <tr key={scan.scan_id} className="hover:bg-muted/15 transition-colors">
                        <td className="py-2.5 font-medium text-foreground truncate max-w-xs font-sans">
                          {scan.target_url}
                        </td>
                        <td className="py-2.5 text-muted-foreground">{scan.scan_id.slice(0, 16)}…</td>
                        <td className="py-2.5 text-muted-foreground font-sans text-xs">
                          {new Date(scan.scanned_at || scan.created_at).toLocaleString()}
                        </td>
                        <td className="py-2.5">
                          <span
                            className={`rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase ${
                              scan.status === "completed"
                                ? "bg-emerald-500/15 text-emerald-400"
                                : scan.status === "cancelled"
                                ? "bg-amber-500/15 text-amber-400"
                                : "bg-destructive/15 text-destructive"
                            }`}
                          >
                            {scan.status}
                          </span>
                        </td>
                        <td className="py-2.5 text-foreground font-bold">
                          {scan.summary?.total_findings ?? "—"}
                        </td>
                        <td className="py-2.5 text-right font-sans">
                          <button
                            type="button"
                            onClick={() => navigate("assessment-report", undefined, scan.scan_id)}
                            className="text-xs font-medium text-primary hover:underline"
                          >
                            Report →
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </CardContent>
          </Card>
        </>
      )}
    </div>
  )
}
