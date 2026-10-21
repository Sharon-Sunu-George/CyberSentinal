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
  const { selectedScanId, navigate } = useAppState()
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
            <Button variant="outline" size="sm" onClick={() => navigate("overview")}>
              Executive Overview
            </Button>
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

  return (
    <div className="mx-auto flex max-w-5xl flex-col gap-6 pb-12">
      {/* ─────────────────────────────────────────────────────────────
          PAGE HEADER
      ───────────────────────────────────────────────────────────── */}
      <div className="flex flex-col gap-2 border-b border-border/80 pb-4 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex items-center gap-3">
          <span className="flex size-9 items-center justify-center rounded-lg bg-primary/15 text-primary ring-1 ring-primary/30">
            <FileText className="size-5" />
          </span>
          <div>
            <h1 className="text-lg font-bold tracking-tight text-foreground truncate max-w-xl">
              Assessment Report: {scanResult.normalized_url}
            </h1>
            <p className="text-xs font-mono text-muted-foreground">
              Scan ID: <span className="text-foreground">{scanResult.scan_id}</span> · Scanned {new Date(scanResult.scanned_at).toLocaleString()}
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
            <ArrowLeft className="size-3" /> Back to Scanner
          </Button>

          <Button
            variant="outline"
            size="sm"
            onClick={() => navigate("overview")}
            className="h-8 gap-1.5 text-xs"
          >
            Overview
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
          SECTION A: WEBSITE TRUST & FRAUD ASSESSMENT
      ───────────────────────────────────────────────────────────── */}
      <Card className="border-border bg-card shadow-sm overflow-hidden">
        <CardHeader className="pb-3 border-b border-border/60 bg-muted/20">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div>
              <div className="flex items-center gap-2">
                <ShieldAlert className="size-4 text-primary" />
                <CardTitle className="text-base text-foreground">
                  Section A: Website Trust & Fraud Assessment
                </CardTitle>
              </div>
              <CardDescription className="text-xs text-muted-foreground mt-0.5">
                Independent threat intelligence, brand impersonation, and legitimacy evaluation.
              </CardDescription>
            </div>

            {/* Trust State Badge */}
            {scanResult.trust_assessment ? (
              <div className="flex items-center gap-2">
                <span
                  className={`inline-flex items-center gap-1.5 rounded-full border px-3 py-1 text-xs font-semibold uppercase tracking-wider ${
                    scanResult.trust_assessment.trust_state === "Known Malicious / Phishing"
                      ? "bg-rose-500/20 text-rose-400 border-rose-500/50"
                      : scanResult.trust_assessment.trust_state === "Likely Impersonation"
                      ? "bg-orange-500/20 text-orange-400 border-orange-500/50"
                      : scanResult.trust_assessment.trust_state === "Suspicious"
                      ? "bg-amber-500/20 text-amber-400 border-amber-500/50"
                      : scanResult.trust_assessment.trust_state === "No Known Threat Detected"
                      ? "bg-emerald-500/20 text-emerald-400 border-emerald-500/50"
                      : "bg-blue-500/20 text-blue-400 border-blue-500/50"
                  }`}
                >
                  {scanResult.trust_assessment.trust_state === "Known Malicious / Phishing" && <XCircle className="size-3.5" />}
                  {scanResult.trust_assessment.trust_state === "Likely Impersonation" && <AlertTriangle className="size-3.5" />}
                  {scanResult.trust_assessment.trust_state === "Suspicious" && <AlertTriangle className="size-3.5" />}
                  {scanResult.trust_assessment.trust_state === "No Known Threat Detected" && <CheckCircle2 className="size-3.5" />}
                  {scanResult.trust_assessment.trust_state === "Inconclusive" && <Info className="size-3.5" />}
                  {scanResult.trust_assessment.trust_state}
                </span>
              </div>
            ) : (
              <span className="rounded-full bg-muted px-2.5 py-0.5 text-xs text-muted-foreground font-mono">
                Trust Assessment Not Performed
              </span>
            )}
          </div>
        </CardHeader>

        <CardContent className="space-y-4 pt-4">
          {scanResult.trust_assessment ? (
            <>
              {/* Trust Summary & Canonical Target */}
              <div className="rounded-lg border bg-muted/15 p-3.5 text-xs space-y-2">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1 text-[11px] text-muted-foreground">
                  <div>
                    Canonical Target: <span className="font-mono text-foreground font-bold">{scanResult.trust_assessment.canonical_url}</span>
                  </div>
                  <div>
                    Confidence: <span className="font-mono text-primary uppercase font-bold">{scanResult.trust_assessment.confidence}</span> · Assessed: {new Date(scanResult.trust_assessment.assessed_at).toLocaleTimeString()}
                  </div>
                </div>
                <p className="text-foreground text-xs leading-relaxed font-medium">
                  {scanResult.trust_assessment.trust_score_label}
                </p>
                {scanResult.trust_assessment.assessment_notes && scanResult.trust_assessment.assessment_notes.length > 0 && (
                  <ul className="list-disc list-inside space-y-1 text-[11px] text-muted-foreground pt-1">
                    {scanResult.trust_assessment.assessment_notes.map((note, nIdx) => (
                      <li key={nIdx}>{note}</li>
                    ))}
                  </ul>
                )}
              </div>

              {/* Providers Status & Warnings */}
              <div className="space-y-2">
                <div className="flex items-center justify-between text-xs font-semibold text-muted-foreground uppercase tracking-wider">
                  <span>Threat Intelligence Providers</span>
                  <span className="text-[10px] lowercase text-muted-foreground">server-side API lookups</span>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
                  {/* Google Safe Browsing */}
                  {(() => {
                    const match = scanResult.trust_assessment?.threat_intel_matches.find(
                      (m) => m.provider.toLowerCase().includes("safe browsing")
                    )
                    const status = match ? match.status : (scanResult.trust_assessment?.reputation_providers_configured ? "no_match" : "unconfigured")
                    return (
                      <div className="rounded-lg border bg-card p-3 space-y-1.5">
                        <div className="flex items-center justify-between">
                          <span className="font-semibold text-foreground flex items-center gap-1.5">
                            <Globe className="size-3.5 text-primary" /> Google Safe Browsing
                          </span>
                          <span
                            className={`rounded px-1.5 py-0.5 text-[10px] font-mono uppercase font-bold ${
                              status === "no_match"
                                ? "bg-emerald-500/15 text-emerald-400"
                                : status === "match_detected"
                                ? "bg-rose-500/15 text-rose-400"
                                : status === "unconfigured"
                                ? "bg-amber-500/15 text-amber-400"
                                : "bg-muted text-muted-foreground"
                            }`}
                          >
                            {status === "no_match" ? "clean" : status === "match_detected" ? "match" : status}
                          </span>
                        </div>
                        <p className="text-[11px] text-muted-foreground">
                          {status === "unconfigured"
                            ? "API key not set in GOOGLE_SAFE_BROWSING_API_KEY. Provider lookup skipped."
                            : status === "no_match"
                            ? "No malicious entry found in Google Safe Browsing v4 threat lists."
                            : status === "match_detected"
                            ? (match?.details || "Threat list entry match detected!")
                            : (match?.details || "Service was unreachable or timed out.")}
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
                      <div className="rounded-lg border bg-card p-3 space-y-1.5">
                        <div className="flex items-center justify-between">
                          <span className="font-semibold text-foreground flex items-center gap-1.5">
                            <Shield className="size-3.5 text-primary" /> PhishTank Verification
                          </span>
                          <span
                            className={`rounded px-1.5 py-0.5 text-[10px] font-mono uppercase font-bold ${
                              status === "no_match"
                                ? "bg-emerald-500/15 text-emerald-400"
                                : status === "match_detected"
                                ? "bg-rose-500/15 text-rose-400"
                                : status === "unconfigured"
                                ? "bg-amber-500/15 text-amber-400"
                                : "bg-muted text-muted-foreground"
                            }`}
                          >
                            {status === "no_match" ? "clean" : status === "match_detected" ? "match" : status}
                          </span>
                        </div>
                        <p className="text-[11px] text-muted-foreground">
                          {status === "unconfigured"
                            ? "API key not set in PHISHTANK_API_KEY. Provider lookup skipped."
                            : status === "no_match"
                            ? "URL is not listed in PhishTank verified phishing database."
                            : status === "match_detected"
                            ? (match?.details || "Verified phishing URL found in PhishTank database!")
                            : (match?.details || "Service unavailable or lookup timed out.")}
                        </p>
                      </div>
                    )
                  })()}
                </div>

                {/* Unconfigured Provider Warning Banner */}
                {!scanResult.trust_assessment.reputation_providers_configured && (
                  <div className="rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 text-xs text-amber-300 flex items-start gap-2">
                    <Info className="size-4 shrink-0 text-amber-400 mt-0.5" />
                    <div>
                      <span className="font-bold">Live Threat Reputation Checking is Limited:</span>
                      <p className="text-[11px] text-amber-300/90 mt-0.5">
                        External threat-intelligence API keys (GOOGLE_SAFE_BROWSING_API_KEY / PHISHTANK_API_KEY) are not configured on this server. Impersonation, typosquatting, and heuristic lookalike domain analysis were performed locally.
                      </p>
                    </div>
                  </div>
                )}
              </div>

              {/* Impersonation & Lookalike Indicators */}
              {scanResult.trust_assessment.impersonation_signals && scanResult.trust_assessment.impersonation_signals.length > 0 && (
                <div className="space-y-2">
                  <span className="text-xs font-semibold text-muted-foreground uppercase tracking-wider block">
                    Detected Impersonation & Fraud Signals ({scanResult.trust_assessment.impersonation_signals.length})
                  </span>
                  <div className="space-y-2">
                    {scanResult.trust_assessment.impersonation_signals.map((sig, idx) => (
                      <div
                        key={idx}
                        className={`rounded-lg border p-3 text-xs space-y-1 ${
                          sig.severity === "High"
                            ? "border-rose-500/40 bg-rose-500/5"
                            : sig.severity === "Medium"
                            ? "border-amber-500/40 bg-amber-500/5"
                            : "border-border bg-muted/10"
                        }`}
                      >
                        <div className="flex items-center justify-between">
                          <span className="font-bold text-foreground flex items-center gap-1.5">
                            <AlertTriangle className={`size-3.5 ${sig.severity === "High" ? "text-rose-400" : "text-amber-400"}`} />
                            {sig.signal_type.replace(/_/g, " ").toUpperCase()}
                          </span>
                          <span className="text-[10px] font-mono uppercase text-muted-foreground font-semibold">
                            Severity: {sig.severity}
                          </span>
                        </div>
                        <p className="text-xs text-foreground/90">{sig.description}</p>
                        <div className="rounded bg-black/40 p-2 font-mono text-[11px] text-muted-foreground">
                          Evidence: <span className="text-foreground">{JSON.stringify(sig.evidence)}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Limitations & Disclaimer */}
              <div className="rounded border border-border/60 bg-muted/10 p-2.5 text-[11px] text-muted-foreground flex items-start gap-2">
                <Info className="size-3.5 shrink-0 text-muted-foreground mt-0.5" />
                <span>
                  <strong>Assessment Scope & Limitations:</strong> A clean lookup against blacklist providers does not guarantee safety. CyberSentinal distinguishes website trust from technical vulnerabilities (e.g. missing HTTP headers).
                </span>
              </div>
            </>
          ) : (
            <p className="text-xs text-muted-foreground">No trust assessment data available for this scan.</p>
          )}
        </CardContent>
      </Card>

      {/* ─────────────────────────────────────────────────────────────
          SECTION B: TECHNICAL SECURITY ASSESSMENT
      ───────────────────────────────────────────────────────────── */}
      <Card className="border-border bg-card shadow-sm">
        <CardHeader className="pb-3">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div>
              <CardTitle className="text-base text-foreground flex items-center gap-2">
                <Shield className="size-4 text-primary" />
                Section B: Technical Security Assessment
              </CardTitle>
              <CardDescription className="text-xs text-muted-foreground">
                Target IP: {scanResult.target_ip || "Public Gateway"} · Scope: {scanResult.scope_limitations || "Non-destructive perimeter inspection"}
              </CardDescription>
            </div>

            {/* Severity Filter Buttons */}
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
                All ({s.total_findings})
              </button>
              {s.critical_count > 0 && (
                <button
                  type="button"
                  onClick={() => setSeverityFilter("Critical")}
                  className={`rounded px-2.5 py-1 font-mono text-[11px] ${
                    severityFilter === "Critical"
                      ? "bg-rose-500 text-white font-bold"
                      : "bg-rose-500/15 text-rose-400 hover:bg-rose-500/25"
                  }`}
                >
                  Critical ({s.critical_count})
                </button>
              )}
              <button
                type="button"
                onClick={() => setSeverityFilter("High")}
                className={`rounded px-2.5 py-1 font-mono text-[11px] ${
                  severityFilter === "High"
                    ? "bg-destructive text-destructive-foreground font-bold"
                    : "bg-destructive/15 text-destructive hover:bg-destructive/25"
                }`}
              >
                High ({s.high_count})
              </button>
              <button
                type="button"
                onClick={() => setSeverityFilter("Medium")}
                className={`rounded px-2.5 py-1 font-mono text-[11px] ${
                  severityFilter === "Medium"
                    ? "bg-amber-500 text-black font-bold"
                    : "bg-amber-500/15 text-amber-400 hover:bg-amber-500/25"
                }`}
              >
                Medium ({s.medium_count})
              </button>
              <button
                type="button"
                onClick={() => setSeverityFilter("Low")}
                className={`rounded px-2.5 py-1 font-mono text-[11px] ${
                  severityFilter === "Low"
                    ? "bg-blue-500 text-white font-bold"
                    : "bg-blue-500/15 text-blue-400 hover:bg-blue-500/25"
                }`}
              >
                Low ({s.low_count})
              </button>
            </div>
          </div>
        </CardHeader>

        <CardContent className="space-y-4">
          {/* Target Unreachable Notice */}
          {(scanResult.target_unreachable || scanResult.findings?.some((f) => f.id === "VULN-SCAN-CONNECTION-FAILED")) && (
            <div className="rounded-lg border border-amber-500/40 bg-amber-500/10 p-3.5 text-xs text-amber-200 space-y-1.5">
              <p className="font-semibold text-amber-300 flex items-center gap-1.5">
                <AlertTriangle className="size-4 text-amber-400" /> Target Host Unreachable / Offline
              </p>
              <p className="leading-relaxed text-amber-300/90 text-[11px]">
                The target host <span className="font-mono text-foreground font-bold">{scanResult.target_url}</span> did not respond on HTTP or HTTPS ports (connection timed out or host is offline). No live web server responses could be inspected.
              </p>
              <div className="pt-1 flex flex-wrap gap-2 items-center">
                <span className="text-[11px] text-muted-foreground">Try a live testing target:</span>
                <Button
                  variant="outline"
                  size="sm"
                  className="h-6 text-[11px] px-2 text-foreground"
                  onClick={() => navigate("agent-simulation")}
                >
                  <RefreshCw className="size-3 mr-1" />
                  Try Live Target in Scanner
                </Button>
              </div>
            </div>
          )}

          {/* Inconclusive Scan Notice */}
          {scanResult.is_inconclusive && !(scanResult.target_unreachable || scanResult.findings?.some((f) => f.id === "VULN-SCAN-CONNECTION-FAILED")) && (
            <div className="rounded-lg border border-blue-500/40 bg-blue-500/10 p-3.5 text-xs text-blue-200 space-y-1.5">
              <p className="font-semibold text-blue-300 flex items-center gap-1.5">
                <AlertTriangle className="size-4 text-blue-400" /> Assessment Inconclusive (Gateway / Proxy Error)
              </p>
              <p className="leading-relaxed text-blue-300/90 text-[11px]">
                Target scan encountered an upstream proxy or connection error. Missing security headers are not asserted as confirmed vulnerabilities for this run.
              </p>
            </div>
          )}

          {/* Honest Zero Findings Disclaimer */}
          {scanResult.zero_findings_disclaimer && (
            <div className="rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 text-xs text-amber-300 space-y-1">
              <p className="font-semibold text-amber-400 flex items-center gap-1.5">
                <Info className="size-4" /> Honest Assessment Notice
              </p>
              <p className="leading-relaxed text-[11px]">{scanResult.zero_findings_disclaimer}</p>
            </div>
          )}

          {/* Metric Bar */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
            <div className="rounded-lg border bg-muted/20 p-2.5 text-center">
              <span className="text-[10px] text-muted-foreground block uppercase">Total Findings</span>
              <span className="font-mono text-base font-bold text-foreground">{s.total_findings}</span>
            </div>
            <div className="rounded-lg border bg-muted/20 p-2.5 text-center">
              <span className="text-[10px] text-muted-foreground block uppercase">High / Critical</span>
              <span className="font-mono text-base font-bold text-destructive">{s.critical_count + s.high_count}</span>
            </div>
            <div className="rounded-lg border bg-muted/20 p-2.5 text-center">
              <span className="text-[10px] text-muted-foreground block uppercase">Pages Crawled</span>
              <span className="font-mono text-base font-bold text-foreground">{pagesList.length || 1}</span>
            </div>
            <div className="rounded-lg border bg-muted/20 p-2.5 text-center">
              <span className="text-[10px] text-muted-foreground block uppercase">Remediation Status</span>
              <span className={`font-mono text-base font-bold ${
                (scanResult.target_unreachable || scanResult.findings?.some((f) => f.id === "VULN-SCAN-CONNECTION-FAILED"))
                  ? "text-amber-400"
                  : "text-primary"
              }`}>
                {(scanResult.target_unreachable || scanResult.findings?.some((f) => f.id === "VULN-SCAN-CONNECTION-FAILED"))
                  ? "Target Unreachable"
                  : "Ready to Plan"}
              </span>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* ─────────────────────────────────────────────────────────────
          FINDINGS LIST & DISCOVERED PAGES TABS
      ───────────────────────────────────────────────────────────── */}
      <div className="space-y-4">
        <div className="flex items-center gap-2 border-b pb-2">
          <button
            type="button"
            onClick={() => setActiveTab("findings")}
            className={`flex items-center gap-2 rounded-md px-3.5 py-1.5 text-xs font-semibold transition-all ${
              activeTab === "findings"
                ? "bg-primary text-primary-foreground shadow"
                : "bg-muted/40 text-muted-foreground hover:text-foreground"
            }`}
          >
            <FileText className="size-3.5" />
            Security Findings ({filteredFindings.length})
          </button>

          <button
            type="button"
            onClick={() => setActiveTab("pages")}
            className={`flex items-center gap-2 rounded-md px-3.5 py-1.5 text-xs font-semibold transition-all ${
              activeTab === "pages"
                ? "bg-destructive text-destructive-foreground shadow"
                : "bg-muted/40 text-muted-foreground hover:text-foreground"
            }`}
          >
            <Globe className="size-3.5" />
            Discovered Pages ({pagesList.length})
          </button>
        </div>

        {activeTab === "findings" && (
          <div className="space-y-3">
            {filteredFindings.length === 0 ? (
              <div className="rounded-lg border border-dashed p-8 text-center text-xs text-muted-foreground">
                No findings match the selected severity filter.
              </div>
            ) : (
              filteredFindings.map((finding) => {
                const isExpanded = !!expandedEvidence[finding.id]
                return (
                  <div
                    key={finding.id}
                    className="rounded-lg border bg-card p-4 space-y-3 text-xs transition-colors hover:bg-muted/10"
                  >
                    {/* Finding Header */}
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b pb-2.5">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className={`rounded-full border px-2 py-0.5 font-mono text-[10px] font-bold ${getSeverityBadgeClass(finding.severity)}`}>
                          {finding.severity}
                        </span>
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

                      <div className="flex items-center gap-2 font-mono text-[10px]">
                        <span className="rounded border px-2 py-0.5 text-muted-foreground">
                          {finding.category}
                        </span>
                        <span className="rounded bg-primary/10 text-primary border border-primary/20 px-2 py-0.5 font-semibold">
                          {finding.remediation_status}
                        </span>
                      </div>
                    </div>

                    {/* Impact & Action Summary */}
                    <div className="space-y-1.5 text-muted-foreground leading-relaxed">
                      <p>
                        <strong className="text-foreground">Impact:</strong> {finding.potential_impact}
                      </p>
                      <p>
                        <strong className="text-foreground">Recommended Fix:</strong> {finding.remediation}
                      </p>
                    </div>

                    {/* Evidence Toggle & References */}
                    <div className="flex items-center justify-between pt-1 text-[11px]">
                      <button
                        type="button"
                        onClick={() => toggleEvidence(finding.id)}
                        className="text-primary hover:underline font-mono flex items-center gap-1 font-medium"
                      >
                        <Terminal className="size-3" />
                        {isExpanded ? "Collapse Wire Evidence" : "Inspect Wire Evidence & Details"}
                      </button>

                      {finding.references && finding.references.length > 0 && (
                        <a
                          href={finding.references[0]}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-muted-foreground hover:text-foreground flex items-center gap-1 font-mono text-[10px]"
                        >
                          OWASP Reference <ExternalLink className="size-3" />
                        </a>
                      )}
                    </div>

                    {/* Expanded Evidence Box with secret redaction */}
                    {isExpanded && (
                      <div className="rounded-md bg-muted/20 border p-3 font-mono text-[11px] space-y-2.5 overflow-x-auto animate-in fade-in">
                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 pb-2 border-b border-border/40 text-[10px]">
                          <div>
                            <span className="text-muted-foreground">Check Type: </span>
                            <span className="text-foreground">{finding.evidence.check_type}</span>
                          </div>
                          <div>
                            <span className="text-muted-foreground">HTTP Status: </span>
                            <span className="text-foreground">{finding.evidence.status_code ?? "N/A"}</span>
                          </div>
                          <div>
                            <span className="text-muted-foreground">Target URL: </span>
                            <span className="text-foreground break-all">{finding.evidence.requested_url || finding.affected_url_or_component}</span>
                          </div>
                          <div>
                            <span className="text-muted-foreground">Evidence Confidence: </span>
                            <span className="text-foreground font-semibold">{finding.confidence}</span>
                          </div>
                          {finding.occurrence_count && finding.occurrence_count > 1 && (
                            <div>
                              <span className="text-muted-foreground">Occurrences: </span>
                              <span className="text-primary font-bold">{finding.occurrence_count} instances</span>
                            </div>
                          )}
                        </div>

                        {(finding.evidence.observed_value || finding.evidence.expected_condition) && (
                          <div className="rounded bg-background/80 p-2 border border-border/40 space-y-1 text-[10px]">
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
                          <div>
                            <p className="text-muted-foreground mb-1 text-[10px]">// Affected URLs ({finding.affected_urls.length}):</p>
                            <div className="bg-background/80 rounded p-1.5 border border-border/30 space-y-0.5 text-[10px] max-h-24 overflow-y-auto">
                              {finding.affected_urls.map((u, i) => (
                                <div key={i} className="text-primary truncate font-mono">
                                  • {u}
                                </div>
                              ))}
                            </div>
                          </div>
                        )}

                        {finding.evidence.raw_snippet && (
                          <div>
                            <p className="text-muted-foreground mb-0.5 text-[10px]">// Raw Wire Snippet:</p>
                            <p className="text-emerald-400 bg-black/60 rounded p-2 border border-emerald-500/20 break-all text-[10px]">
                              {finding.evidence.raw_snippet}
                            </p>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                )
              })
            )}
          </div>
        )}

        {activeTab === "pages" && (
          <Card className="border-border bg-card">
            <CardHeader className="pb-3">
              <CardTitle className="text-base text-foreground">Discovered Pages Inventory</CardTitle>
              <CardDescription className="text-xs text-muted-foreground">
                All URLs crawled within the permitted target scope during this assessment.
              </CardDescription>
            </CardHeader>
            <CardContent>
              {pagesList.length === 0 ? (
                <div className="rounded-lg border border-dashed p-8 text-center text-xs text-muted-foreground">
                  No additional internal pages discovered. Target landing was evaluated.
                </div>
              ) : (
                <div className="space-y-2">
                  {pagesList.map((pg, idx) => (
                    <div key={idx} className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 rounded border bg-muted/15 p-2.5 text-xs font-mono">
                      <div className="flex items-center gap-2 truncate max-w-xl">
                        <span className={`rounded px-1.5 py-0.5 text-[10px] font-bold ${pg.status_code && pg.status_code < 400 ? "bg-emerald-500/15 text-emerald-400" : "bg-destructive/15 text-destructive"}`}>
                          {pg.status_code ? `HTTP ${pg.status_code}` : "Rendered"}
                        </span>
                        <span className="text-foreground truncate">{pg.url}</span>
                      </div>
                      <span className="text-muted-foreground text-[10px]">Depth: {pg.depth}</span>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        )}
      </div>
    </div>
  )
}
