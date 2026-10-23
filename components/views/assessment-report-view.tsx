"use client"

import { useState, useEffect } from "react"
import {
  AlertTriangle,
  ArrowLeft,
  ArrowRight,
  CheckCircle2,
  Clock,
  Code2,
  ExternalLink,
  FileText,
  Globe,
  Info,
  Layers,
  Loader2,
  Lock,
  RefreshCw,
  RotateCcw,
  Shield,
  ShieldAlert,
  ShieldCheck,
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
  type VulnerabilityFinding,
  type DiscoveredPage,
} from "@/lib/api-client"

export function AssessmentReportView({ scanId: propScanId }: { scanId?: string }) {
  const { selectedScanId, navigate, recordCompletedScan } = useAppState()
  const activeScanId = propScanId || selectedScanId

  const [scanResult, setScanResult] = useState<AttackerScanResponse | null>(null)
  const [pagesList, setPagesList] = useState<DiscoveredPage[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [severityFilter, setSeverityFilter] = useState<string>("all")
  const [activeTab, setActiveTab] = useState<"findings" | "pages">("findings")
  const [expandedEvidence, setExpandedEvidence] = useState<Record<string, boolean>>({})

  const loadScanData = async () => {
    setIsLoading(true)
    setError(null)
    try {
      let targetId = activeScanId

      // If no activeScanId specified, query the latest scan from recent history
      if (!targetId) {
        const recent = await apiClient.getRecentScans(1)
        if (recent && recent.length > 0) {
          targetId = recent[0].scan_id
        }
      }

      if (!targetId) {
        setScanResult(null)
        setIsLoading(false)
        return
      }

      const record = await apiClient.getScanRecord(targetId)
      setScanResult(record)
      const plan = await apiClient.getDefenderPlan(targetId).catch(() => null)
      recordCompletedScan(record, plan)

      if (record.discovered_pages && record.discovered_pages.length > 0) {
        setPagesList(record.discovered_pages)
      } else {
        const pages = await apiClient.getScanPages(targetId).catch(() => [])
        setPagesList(pages)
      }
    } catch (err: any) {
      setError(err.message || "Failed to load assessment report for this scan.")
    } finally {
      setIsLoading(false)
    }
  }

  useEffect(() => {
    loadScanData()
  }, [activeScanId])

  const toggleEvidence = (id: string) => {
    setExpandedEvidence((prev) => ({ ...prev, [id]: !prev[id] }))
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

  const filteredFindings = scanResult
    ? scanResult.findings.filter((f) => {
        if (severityFilter === "all") return true
        return f.severity.toLowerCase() === severityFilter.toLowerCase()
      })
    : []

  if (isLoading) {
    return (
      <div className="mx-auto flex max-w-5xl min-h-[400px] flex-col items-center justify-center gap-3 p-8 text-center">
        <Loader2 className="size-6 animate-spin text-primary" />
        <p className="text-xs text-muted-foreground font-mono">Loading scan-specific assessment report…</p>
      </div>
    )
  }

  if (error || !scanResult) {
    return (
      <div className="mx-auto flex max-w-4xl flex-col gap-5 p-4 text-center">
        <div className="rounded-xl border border-dashed border-border p-10 space-y-4">
          <AlertTriangle className="size-8 mx-auto text-amber-400" />
          <h2 className="text-base font-bold text-foreground">Assessment Report Unavailable</h2>
          <p className="text-xs text-muted-foreground max-w-md mx-auto leading-relaxed">
            {error || "No scan record found. You can start a new assessment or view recent scans."}
          </p>
          <div className="flex justify-center gap-3">
            <Button size="sm" onClick={() => navigate("agent-simulation")}>
              Attack Surface Scanner
            </Button>
          </div>
        </div>
      </div>
    )
  }

  const s = scanResult.summary || {
    total_findings: scanResult.findings.length,
    critical_count: scanResult.findings.filter((f) => f.severity === "Critical").length,
    high_count: scanResult.findings.filter((f) => f.severity === "High").length,
    medium_count: scanResult.findings.filter((f) => f.severity === "Medium").length,
    low_count: scanResult.findings.filter((f) => f.severity === "Low").length,
  }

  // Group findings by severity
  const severityGroups = ["Critical", "High", "Medium", "Low", "Info"] as const
  const findingsBySeverity = severityGroups.map((sev) => ({
    severity: sev,
    findings: scanResult.findings.filter((f) => f.severity.toLowerCase() === sev.toLowerCase()),
  }))

  const totalFindings = scanResult.findings.length
  const criticalHighCount = s.critical_count + s.high_count
  const isTargetUnreachable = scanResult.target_unreachable || scanResult.findings?.some((f) => f.id === "VULN-SCAN-CONNECTION-FAILED")

  return (
    <div className="mx-auto flex max-w-5xl flex-col gap-6 pb-16">
      {/* ─────────────────────────────────────────────────────────────
          1. HEADER & TOP ACTIONS (Preserved existing top actions)
      ───────────────────────────────────────────────────────────── */}
      <div className="flex flex-col gap-3 border-b border-border/80 pb-4 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex items-center gap-3 min-w-0">
          <span className="flex size-9 shrink-0 items-center justify-center rounded-lg bg-primary/15 text-primary ring-1 ring-primary/30">
            <FileText className="size-5" />
          </span>
          <div className="min-w-0">
            <h1 className="text-lg font-bold tracking-tight text-foreground truncate">
              Assessment Report
            </h1>
            <p className="text-xs text-muted-foreground truncate font-mono">
              {scanResult.normalized_url || scanResult.target_url}
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2 shrink-0">
          <Button
            variant="outline"
            size="sm"
            onClick={() => navigate("agent-simulation")}
            className="h-8 gap-1.5 text-xs"
          >
            <ArrowLeft className="size-3" /> Back to Scanner
          </Button>

          <Button
            size="sm"
            onClick={() => navigate("remediation-center", undefined, scanResult.scan_id)}
            className="h-8 gap-1.5 bg-primary text-primary-foreground text-xs font-semibold hover:bg-primary/90"
          >
            <Wrench className="size-3.5" />
            Remediation Planner
          </Button>
        </div>
      </div>

      {/* ─────────────────────────────────────────────────────────────
          2. TARGET & STATUS
      ───────────────────────────────────────────────────────────── */}
      <Card className="border-border bg-card shadow-sm">
        <CardContent className="p-4 sm:p-5">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 text-xs font-mono">
            <div className="space-y-1">
              <span className="text-[10px] uppercase text-muted-foreground tracking-wider font-sans font-medium block">
                Target Destination
              </span>
              <p className="text-foreground font-semibold truncate text-xs" title={scanResult.target_url}>
                {scanResult.target_url}
              </p>
              {scanResult.target_ip && (
                <p className="text-[11px] text-muted-foreground truncate">
                  IP: {scanResult.target_ip}
                </p>
              )}
            </div>

            <div className="space-y-1">
              <span className="text-[10px] uppercase text-muted-foreground tracking-wider font-sans font-medium block">
                Scan ID
              </span>
              <p className="text-foreground truncate text-xs font-bold" title={scanResult.scan_id}>
                {scanResult.scan_id}
              </p>
              <p className="text-[11px] text-muted-foreground">
                {new Date(scanResult.scanned_at).toLocaleDateString()} {new Date(scanResult.scanned_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
              </p>
            </div>

            <div className="space-y-1">
              <span className="text-[10px] uppercase text-muted-foreground tracking-wider font-sans font-medium block">
                Backend Status
              </span>
              <div>
                <span className={`inline-flex items-center gap-1.5 rounded px-2 py-0.5 text-[11px] font-semibold uppercase ${
                  isTargetUnreachable
                    ? "bg-amber-500/15 text-amber-400 border border-amber-500/30"
                    : scanResult.status === "completed"
                    ? "bg-emerald-500/15 text-emerald-400 border border-emerald-500/30"
                    : scanResult.status === "failed"
                    ? "bg-rose-500/15 text-rose-400 border border-rose-500/30"
                    : "bg-primary/15 text-primary border border-primary/30"
                }`}>
                  {scanResult.status === "completed" && <CheckCircle2 className="size-3" />}
                  {isTargetUnreachable ? "Host Unreachable" : scanResult.status}
                </span>
              </div>
              <p className="text-[11px] text-muted-foreground truncate font-sans">
                {scanResult.scanner_info?.engine || "Headless Playwright"}
              </p>
            </div>

            <div className="space-y-1">
              <span className="text-[10px] uppercase text-muted-foreground tracking-wider font-sans font-medium block">
                Coverage Scope
              </span>
              <p className="text-foreground text-xs">
                {pagesList.length || 1} {pagesList.length === 1 ? "page" : "pages"} crawled
              </p>
              <p className="text-[11px] text-muted-foreground truncate font-sans" title={scanResult.scope_limitations}>
                {scanResult.scope_limitations || "Non-destructive passive audit"}
              </p>
            </div>
          </div>

          {/* Unreachable alert notice (rendered only when target truly offline) */}
          {isTargetUnreachable && (
            <div className="mt-4 rounded border border-amber-500/30 bg-amber-500/10 p-3 text-xs text-amber-300 flex items-start gap-2.5">
              <AlertTriangle className="size-4 shrink-0 text-amber-400 mt-0.5" />
              <div className="space-y-0.5">
                <span className="font-semibold text-amber-200">Target host offline or unreachable</span>
                <p className="text-[11px] text-amber-300/80 leading-relaxed font-sans">
                  The target server did not respond on HTTP/HTTPS ports during the assessment. Verify the host address or retry with a reachable target.
                </p>
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {/* ─────────────────────────────────────────────────────────────
          3. RISK SUMMARY
      ───────────────────────────────────────────────────────────── */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
        <div className="rounded-lg border bg-card p-3.5 space-y-1">
          <span className="text-[10px] uppercase text-muted-foreground font-semibold block">Total Findings</span>
          <span className="font-mono text-xl font-bold text-foreground">{totalFindings}</span>
          <p className="text-[10px] text-muted-foreground">Observable security items</p>
        </div>

        <div className="rounded-lg border bg-card p-3.5 space-y-1">
          <span className="text-[10px] uppercase text-muted-foreground font-semibold block">Critical & High</span>
          <span className={`font-mono text-xl font-bold ${criticalHighCount > 0 ? "text-destructive" : "text-emerald-400"}`}>
            {criticalHighCount}
          </span>
          <p className="text-[10px] text-muted-foreground">{s.critical_count} critical, {s.high_count} high</p>
        </div>

        <div className="rounded-lg border bg-card p-3.5 space-y-1">
          <span className="text-[10px] uppercase text-muted-foreground font-semibold block">Medium & Low</span>
          <span className="font-mono text-xl font-bold text-foreground">{s.medium_count + s.low_count}</span>
          <p className="text-[10px] text-muted-foreground">{s.medium_count} medium, {s.low_count} low</p>
        </div>

        <div className="rounded-lg border bg-card p-3.5 space-y-1">
          <span className="text-[10px] uppercase text-muted-foreground font-semibold block">Trust Standing</span>
          <span className={`font-mono text-base font-bold truncate block ${
            scanResult.trust_assessment?.trust_state === "Known Malicious / Phishing"
              ? "text-rose-400"
              : scanResult.trust_assessment?.trust_state === "Suspicious" || scanResult.trust_assessment?.trust_state === "Likely Impersonation"
              ? "text-amber-400"
              : "text-emerald-400"
          }`}>
            {scanResult.trust_assessment?.trust_state || "Evaluated"}
          </span>
          <p className="text-[10px] text-muted-foreground truncate">{scanResult.trust_assessment?.trust_score_label || "No threats listed"}</p>
        </div>
      </div>

      {/* ─────────────────────────────────────────────────────────────
          4. SEVERITY-GROUPED FINDINGS & EXPANDABLE EVIDENCE & RECOMMENDED FIXES
      ───────────────────────────────────────────────────────────── */}
      <Card className="border-border bg-card shadow-sm">
        <CardHeader className="pb-3 border-b border-border/60">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div>
              <CardTitle className="text-base text-foreground flex items-center gap-2">
                <ShieldAlert className="size-4 text-primary" />
                Security Findings
              </CardTitle>
              <CardDescription className="text-xs text-muted-foreground">
                Grouped by severity level. Expand each finding for wire evidence and remediation instructions.
              </CardDescription>
            </div>

            {/* Severity Filter Pills */}
            <div className="flex flex-wrap items-center gap-1.5 text-xs">
              <button
                type="button"
                onClick={() => setSeverityFilter("all")}
                className={`rounded px-2.5 py-1 font-mono text-[11px] transition-colors ${
                  severityFilter === "all"
                    ? "bg-primary text-primary-foreground font-semibold"
                    : "bg-muted text-muted-foreground hover:bg-muted/80"
                }`}
              >
                All ({totalFindings})
              </button>
              {severityGroups.map((sev) => {
                const count = scanResult.findings.filter((f) => f.severity.toLowerCase() === sev.toLowerCase()).length
                if (count === 0 && severityFilter !== sev) return null
                return (
                  <button
                    key={sev}
                    type="button"
                    onClick={() => setSeverityFilter(sev)}
                    className={`rounded px-2.5 py-1 font-mono text-[11px] transition-colors ${
                      severityFilter === sev
                        ? "bg-foreground text-background font-bold"
                        : "bg-muted/50 text-muted-foreground hover:bg-muted"
                    }`}
                  >
                    {sev} ({count})
                  </button>
                )
              })}
            </div>
          </div>
        </CardHeader>

        <CardContent className="space-y-6 pt-4">
          {filteredFindings.length === 0 ? (
            <div className="rounded-lg border border-dashed p-8 text-center text-xs text-muted-foreground">
              {totalFindings === 0
                ? "No security vulnerabilities observed for this target perimeter."
                : "No findings match the selected severity filter."}
            </div>
          ) : (
            findingsBySeverity
              .filter((group) => {
                if (severityFilter === "all") return group.findings.length > 0
                return group.severity.toLowerCase() === severityFilter.toLowerCase() && group.findings.length > 0
              })
              .map((group) => (
                <div key={group.severity} className="space-y-3">
                  <div className="flex items-center gap-2 border-b border-border/50 pb-1.5">
                    <span className={`rounded px-2 py-0.5 font-mono text-[10px] font-bold ${getSeverityBadgeClass(group.severity)}`}>
                      {group.severity} Priority
                    </span>
                    <span className="text-xs text-muted-foreground">
                      {group.findings.length} {group.findings.length === 1 ? "finding" : "findings"}
                    </span>
                  </div>

                  <div className="space-y-3">
                    {group.findings.map((finding) => {
                      const isExpanded = !!expandedEvidence[finding.id]
                      return (
                        <div
                          key={finding.id}
                          className="rounded-lg border bg-muted/10 p-4 space-y-3 text-xs transition-colors hover:bg-muted/20"
                        >
                          {/* Finding Title & Badges */}
                          <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-2">
                            <div className="space-y-1">
                              <div className="flex flex-wrap items-center gap-2">
                                <h3 className="font-semibold text-foreground text-sm">{finding.title}</h3>
                                {finding.cwe_id && (
                                  <span className="rounded bg-muted px-1.5 py-0.5 font-mono text-[10px] text-muted-foreground border">
                                    {finding.cwe_id}
                                  </span>
                                )}
                                {finding.cve_id && (
                                  <span className="rounded bg-destructive/15 text-destructive font-mono text-[10px] font-bold px-1.5 py-0.5 border border-destructive/30">
                                    {finding.cve_id}
                                  </span>
                                )}
                              </div>
                              <p className="text-[11px] font-mono text-muted-foreground">
                                {finding.affected_url_or_component}
                              </p>
                            </div>

                            <span className="rounded bg-background px-2 py-0.5 font-mono text-[10px] text-muted-foreground border shrink-0">
                              {finding.category}
                            </span>
                          </div>

                          {/* Impact & Recommended Fixes */}
                          <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-1 text-xs">
                            <div className="rounded bg-background/60 border p-3 space-y-1">
                              <span className="text-[10px] uppercase font-semibold text-muted-foreground tracking-wider block">
                                Potential Impact
                              </span>
                              <p className="text-foreground/90 leading-relaxed text-[11px]">
                                {finding.potential_impact}
                              </p>
                            </div>

                            <div className="rounded bg-primary/5 border border-primary/20 p-3 space-y-1">
                              <span className="text-[10px] uppercase font-semibold text-primary tracking-wider block">
                                Recommended Fix
                              </span>
                              <p className="text-foreground/90 leading-relaxed text-[11px]">
                                {finding.remediation}
                              </p>
                            </div>
                          </div>

                          {/* Evidence Toggle & References */}
                          <div className="flex items-center justify-between pt-1 text-[11px]">
                            <button
                              type="button"
                              onClick={() => toggleEvidence(finding.id)}
                              className="text-primary hover:underline font-mono flex items-center gap-1.5 font-medium"
                            >
                              <Terminal className="size-3" />
                              {isExpanded ? "Hide Wire Evidence" : "View Wire Evidence & Details"}
                            </button>

                            {finding.references && finding.references.length > 0 && (
                              <a
                                href={finding.references[0]}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="text-muted-foreground hover:text-foreground flex items-center gap-1 font-mono text-[10px]"
                              >
                                Guidance <ExternalLink className="size-3" />
                              </a>
                            )}
                          </div>

                          {/* Expandable Wire Evidence */}
                          {isExpanded && (
                            <div className="rounded-md bg-background border p-3 font-mono text-[11px] space-y-2.5 overflow-x-auto animate-in fade-in">
                              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 pb-2 border-b border-border/40 text-[10px]">
                                <div>
                                  <span className="text-muted-foreground">Check Type: </span>
                                  <span className="text-foreground">{finding.evidence.check_type}</span>
                                </div>
                                <div>
                                  <span className="text-muted-foreground">HTTP Status: </span>
                                  <span className="text-foreground">{finding.evidence.status_code ?? "N/A"}</span>
                                </div>
                                <div className="sm:col-span-2">
                                  <span className="text-muted-foreground">Target URL: </span>
                                  <span className="text-foreground break-all">{finding.evidence.requested_url || finding.affected_url_or_component}</span>
                                </div>
                              </div>

                              {(finding.evidence.observed_value || finding.evidence.expected_condition) && (
                                <div className="rounded bg-muted/20 p-2 border border-border/40 space-y-1 text-[10px]">
                                  {finding.evidence.observed_value && (
                                    <div>
                                      <span className="text-amber-400 font-semibold">Observed: </span>
                                      <span className="text-foreground/90 break-all">{finding.evidence.observed_value}</span>
                                    </div>
                                  )}
                                  {finding.evidence.expected_condition && (
                                    <div>
                                      <span className="text-emerald-400 font-semibold">Expected: </span>
                                      <span className="text-foreground/90 break-all">{finding.evidence.expected_condition}</span>
                                    </div>
                                  )}
                                </div>
                              )}

                              {finding.affected_urls && finding.affected_urls.length > 1 && (
                                <div className="space-y-1 text-[10px]">
                                  <span className="text-muted-foreground">Affected URLs ({finding.affected_urls.length}):</span>
                                  <div className="bg-muted/20 rounded p-1.5 border border-border/30 max-h-24 overflow-y-auto space-y-0.5">
                                    {finding.affected_urls.map((u, i) => (
                                      <div key={i} className="text-foreground/80 truncate">
                                        • {u}
                                      </div>
                                    ))}
                                  </div>
                                </div>
                              )}

                              {finding.evidence.raw_snippet && (
                                <div>
                                  <span className="text-muted-foreground block text-[10px] mb-1">Raw Response Snippet:</span>
                                  <pre className="text-emerald-400 bg-black/70 rounded p-2 border border-emerald-500/20 text-[10px] whitespace-pre-wrap break-all">
                                    {finding.evidence.raw_snippet}
                                  </pre>
                                </div>
                              )}
                            </div>
                          )}
                        </div>
                      )
                    })}
                  </div>
                </div>
              ))
          )}
        </CardContent>
      </Card>

      {/* ─────────────────────────────────────────────────────────────
          5. WEBSITE TRUST ASSESSMENT
      ───────────────────────────────────────────────────────────── */}
      {scanResult.trust_assessment && (
        <Card className="border-border bg-card shadow-sm">
          <CardHeader className="pb-3 border-b border-border/60">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
              <div>
                <CardTitle className="text-base text-foreground flex items-center gap-2">
                  <ShieldCheck className="size-4 text-primary" />
                  Website Trust & Fraud Assessment
                </CardTitle>
                <CardDescription className="text-xs text-muted-foreground">
                  Domain legitimacy, threat list matching, and impersonation signal verification.
                </CardDescription>
              </div>

              <span className={`inline-flex items-center gap-1.5 rounded px-2.5 py-0.5 text-xs font-semibold uppercase ${
                scanResult.trust_assessment.trust_state === "Known Malicious / Phishing"
                  ? "bg-rose-500/15 text-rose-400 border border-rose-500/30"
                  : scanResult.trust_assessment.trust_state === "Suspicious" || scanResult.trust_assessment.trust_state === "Likely Impersonation"
                  ? "bg-amber-500/15 text-amber-400 border border-amber-500/30"
                  : "bg-emerald-500/15 text-emerald-400 border border-emerald-500/30"
              }`}>
                {scanResult.trust_assessment.trust_state}
              </span>
            </div>
          </CardHeader>

          <CardContent className="space-y-4 pt-4 text-xs">
            <div className="rounded-lg border bg-muted/10 p-3 space-y-1.5">
              <div className="flex flex-wrap items-center justify-between gap-1 text-[11px] font-mono text-muted-foreground">
                <span>Canonical: <strong className="text-foreground">{scanResult.trust_assessment.canonical_url}</strong></span>
                <span>Confidence: <strong className="text-primary uppercase">{scanResult.trust_assessment.confidence}</strong></span>
              </div>
              <p className="text-foreground text-xs leading-relaxed">
                {scanResult.trust_assessment.trust_score_label}
              </p>
            </div>

            {/* Threat Intelligence Providers Grid */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              {/* Google Safe Browsing */}
              {(() => {
                const match = scanResult.trust_assessment?.threat_intel_matches.find(
                  (m) => m.provider.toLowerCase().includes("safe browsing")
                )
                const status = match ? match.status : (scanResult.trust_assessment?.reputation_providers_configured ? "no_match" : "unconfigured")
                return (
                  <div className="rounded border bg-background/50 p-3 space-y-1">
                    <div className="flex items-center justify-between">
                      <span className="font-semibold text-foreground">Google Safe Browsing</span>
                      <span className={`rounded px-1.5 py-0.5 text-[10px] font-mono uppercase font-semibold ${
                        status === "no_match"
                          ? "bg-emerald-500/15 text-emerald-400"
                          : status === "match_detected"
                          ? "bg-rose-500/15 text-rose-400"
                          : "bg-muted text-muted-foreground"
                      }`}>
                        {status === "no_match" ? "clean" : status === "match_detected" ? "threat match" : status}
                      </span>
                    </div>
                    <p className="text-[11px] text-muted-foreground">
                      {status === "no_match"
                        ? "No malicious entry found in threat lists."
                        : match?.details || "Lookup complete."}
                    </p>
                  </div>
                )
              })()}

              {/* PhishTank */}
              {(() => {
                const match = scanResult.trust_assessment?.threat_intel_matches.find(
                  (m) => m.provider.toLowerCase().includes("phishtank")
                )
                const status = match ? match.status : (scanResult.trust_assessment?.reputation_providers_configured ? "no_match" : "unconfigured")
                return (
                  <div className="rounded border bg-background/50 p-3 space-y-1">
                    <div className="flex items-center justify-between">
                      <span className="font-semibold text-foreground">PhishTank Directory</span>
                      <span className={`rounded px-1.5 py-0.5 text-[10px] font-mono uppercase font-semibold ${
                        status === "no_match"
                          ? "bg-emerald-500/15 text-emerald-400"
                          : status === "match_detected"
                          ? "bg-rose-500/15 text-rose-400"
                          : "bg-muted text-muted-foreground"
                      }`}>
                        {status === "no_match" ? "clean" : status === "match_detected" ? "threat match" : status}
                      </span>
                    </div>
                    <p className="text-[11px] text-muted-foreground">
                      {status === "no_match"
                        ? "Not listed in phishing repository."
                        : match?.details || "Lookup complete."}
                    </p>
                  </div>
                )
              })()}
            </div>

            {/* Impersonation Signals (if any) */}
            {scanResult.trust_assessment.impersonation_signals && scanResult.trust_assessment.impersonation_signals.length > 0 && (
              <div className="space-y-2 pt-1">
                <span className="text-[11px] font-semibold text-muted-foreground uppercase tracking-wider block">
                  Impersonation Signals ({scanResult.trust_assessment.impersonation_signals.length})
                </span>
                <div className="space-y-1.5">
                  {scanResult.trust_assessment.impersonation_signals.map((sig, idx) => (
                    <div key={idx} className="rounded border bg-muted/15 p-2.5 text-xs flex items-start gap-2">
                      <AlertTriangle className="size-3.5 text-amber-400 shrink-0 mt-0.5" />
                      <div className="space-y-0.5">
                        <span className="font-semibold text-foreground">{sig.signal_type.replace(/_/g, " ")}: </span>
                        <span className="text-muted-foreground">{sig.description}</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {/* ─────────────────────────────────────────────────────────────
          6. CRAWL COVERAGE
      ───────────────────────────────────────────────────────────── */}
      <Card className="border-border bg-card shadow-sm">
        <CardHeader className="pb-3 border-b border-border/60">
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="text-base text-foreground flex items-center gap-2">
                <Globe className="size-4 text-primary" />
                Crawl Coverage & Discovered Pages
              </CardTitle>
              <CardDescription className="text-xs text-muted-foreground">
                Inventory of pages analyzed by the headless Playwright crawler.
              </CardDescription>
            </div>
            <span className="rounded bg-muted px-2 py-0.5 font-mono text-xs text-muted-foreground">
              {pagesList.length} {pagesList.length === 1 ? "page" : "pages"}
            </span>
          </div>
        </CardHeader>

        <CardContent className="pt-4">
          {pagesList.length === 0 ? (
            <div className="rounded border border-dashed p-6 text-center text-xs text-muted-foreground font-mono">
              Target origin landing page evaluated.
            </div>
          ) : (
            <div className="space-y-1.5 max-h-64 overflow-y-auto pr-1">
              {pagesList.map((pg, idx) => (
                <div
                  key={idx}
                  className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 rounded border bg-muted/10 p-2 text-xs font-mono"
                >
                  <div className="flex items-center gap-2 truncate min-w-0">
                    <span className={`rounded px-1.5 py-0.2 text-[10px] font-bold shrink-0 ${
                      pg.status_code && pg.status_code < 400
                        ? "bg-emerald-500/15 text-emerald-400"
                        : "bg-destructive/15 text-destructive"
                    }`}>
                      {pg.status_code ? `HTTP ${pg.status_code}` : "200"}
                    </span>
                    <span className="text-foreground truncate" title={pg.url}>
                      {pg.url}
                    </span>
                  </div>
                  <span className="text-muted-foreground text-[10px] shrink-0">
                    depth {pg.depth}
                  </span>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* ─────────────────────────────────────────────────────────────
          7. BOTTOM NAVIGATION: RETURN TO EXECUTIVE OVERVIEW ONLY
      ───────────────────────────────────────────────────────────── */}
      <div className="flex justify-end pt-4">
        <Button
          onClick={() => {
            if (scanResult) {
              recordCompletedScan(scanResult)
            }
            navigate("overview", undefined, scanResult?.scan_id)
          }}
          className="h-9 gap-2 px-5 text-xs font-semibold bg-primary text-primary-foreground hover:bg-primary/90"
        >
          Executive Overview
          <ArrowRight className="size-3.5" />
        </Button>
      </div>
    </div>
  )
}

