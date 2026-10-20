"use client"

import { useState, useEffect } from "react"
import {
  AlertTriangle,
  ArrowRight,
  FileText,
  History,
  Loader2,
  PlusCircle,
  RefreshCw,
  Wrench,
} from "lucide-react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { useAppState } from "@/components/app/app-state"
import { apiClient } from "@/lib/api-client"

export function AssessmentHistoryView() {
  const { navigate } = useAppState()
  const [scans, setScans] = useState<any[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const loadScans = async () => {
    setIsLoading(true)
    setError(null)
    try {
      const data = await apiClient.getRecentScans(30)
      setScans(data || [])
    } catch (err: any) {
      setError(err.message || "Failed to load scan history.")
    } finally {
      setIsLoading(false)
    }
  }

  useEffect(() => {
    loadScans()
  }, [])

  return (
    <div className="mx-auto flex max-w-5xl flex-col gap-6 pb-12">
      {/* ─────────────────────────────────────────────────────────────
          PAGE HEADER
      ───────────────────────────────────────────────────────────── */}
      <div className="flex flex-col gap-2 border-b border-border/80 pb-4 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex items-center gap-3">
          <span className="flex size-9 items-center justify-center rounded-lg bg-primary/15 text-primary ring-1 ring-primary/30">
            <History className="size-5" />
          </span>
          <div>
            <h1 className="text-lg font-bold tracking-tight text-foreground">
              Assessment History
            </h1>
            <p className="text-xs text-muted-foreground">
              Persisted audit records of executed attack surface evaluations.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={loadScans}
            disabled={isLoading}
            className="h-8 gap-1.5 text-xs font-medium"
          >
            <RefreshCw className={`size-3.5 ${isLoading ? "animate-spin" : ""}`} />
            Refresh
          </Button>

          <Button
            size="sm"
            onClick={() => navigate("new-assessment")}
            className="h-8 gap-1.5 bg-primary text-primary-foreground text-xs font-semibold"
          >
            <PlusCircle className="size-3.5" />
            New Assessment
          </Button>
        </div>
      </div>

      {error && (
        <div className="rounded-lg border border-destructive/30 bg-destructive/10 p-3 text-xs text-destructive flex items-center gap-2">
          <AlertTriangle className="size-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {isLoading && (
        <div className="flex min-h-[300px] flex-col items-center justify-center gap-3 rounded-xl border border-dashed p-8 text-center">
          <Loader2 className="size-6 animate-spin text-primary" />
          <p className="text-xs text-muted-foreground font-mono">Loading assessment history…</p>
        </div>
      )}

      {!isLoading && scans.length === 0 && (
        <div className="flex min-h-[300px] flex-col items-center justify-center gap-4 rounded-xl border border-dashed p-8 text-center">
          <History className="size-8 text-muted-foreground" />
          <div className="max-w-md space-y-1">
            <h3 className="text-base font-bold text-foreground">No Past Assessments Found</h3>
            <p className="text-xs text-muted-foreground">
              Every completed or cancelled scan is persisted in the local SQLite database.
            </p>
          </div>
          <Button size="sm" onClick={() => navigate("new-assessment")}>
            Run Assessment Now
          </Button>
        </div>
      )}

      {!isLoading && scans.length > 0 && (
        <Card className="border-border bg-card shadow-sm">
          <CardHeader className="pb-3">
            <CardTitle className="text-base text-foreground">All Persisted Assessments ({scans.length})</CardTitle>
            <CardDescription className="text-xs text-muted-foreground">
              Select any assessment to inspect detailed wire findings or calculate remediation budgets.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-border/60 text-[11px] font-mono text-muted-foreground">
                    <th className="pb-2 font-medium">Target URL</th>
                    <th className="pb-2 font-medium">Scan ID</th>
                    <th className="pb-2 font-medium">Scanned Date</th>
                    <th className="pb-2 font-medium">Execution Status</th>
                    <th className="pb-2 font-medium">Total Findings</th>
                    <th className="pb-2 text-right font-medium">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border/40 font-mono text-[11px]">
                  {scans.map((s) => (
                    <tr key={s.scan_id} className="hover:bg-muted/10 transition-colors">
                      <td className="py-2.5 font-sans font-medium text-foreground truncate max-w-xs">
                        {s.target_url}
                      </td>
                      <td className="py-2.5 text-muted-foreground">{s.scan_id.slice(0, 16)}…</td>
                      <td className="py-2.5 font-sans text-muted-foreground text-xs">
                        {new Date(s.scanned_at || s.created_at).toLocaleString()}
                      </td>
                      <td className="py-2.5">
                        <span
                          className={`rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase ${
                            s.status === "completed"
                              ? "bg-emerald-500/15 text-emerald-400"
                              : s.status === "cancelled"
                              ? "bg-amber-500/15 text-amber-400"
                              : "bg-destructive/15 text-destructive"
                          }`}
                        >
                          {s.status}
                        </span>
                      </td>
                      <td className="py-2.5 font-bold text-foreground">
                        {s.summary?.total_findings ?? "—"}
                      </td>
                      <td className="py-2.5 text-right font-sans space-x-2">
                        <button
                          type="button"
                          onClick={() => navigate("assessment-report", undefined, s.scan_id)}
                          className="text-xs font-medium text-primary hover:underline"
                        >
                          Report
                        </button>
                        <span className="text-muted-foreground">·</span>
                        <button
                          type="button"
                          onClick={() => navigate("remediation-center", undefined, s.scan_id)}
                          className="text-xs font-medium text-foreground hover:underline"
                        >
                          Plan
                        </button>
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
