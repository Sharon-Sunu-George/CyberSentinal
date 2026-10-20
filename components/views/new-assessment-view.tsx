"use client"

import { useState, useEffect, useRef } from "react"
import {
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  Clock,
  ExternalLink,
  Globe,
  Info,
  Loader2,
  Lock,
  PlusCircle,
  RotateCcw,
  Shield,
  ShieldAlert,
  Terminal,
  XCircle,
  Zap,
} from "lucide-react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { useAppState } from "@/components/app/app-state"
import { apiClient } from "@/lib/api-client"

export function NewAssessmentView() {
  const { navigate } = useAppState()

  const [targetUrl, setTargetUrl] = useState("https://example.com")
  const [isAuthorized, setIsAuthorized] = useState(false)
  const [maxPages, setMaxPages] = useState<number>(10)
  const [maxDepth, setMaxDepth] = useState<number>(2)

  const [isScanning, setIsScanning] = useState(false)
  const [scanStatus, setScanStatus] = useState<"idle" | "queued" | "running" | "completed" | "failed" | "cancelled">("idle")
  const [scanProgress, setScanProgress] = useState(0)
  const [scanStageText, setScanStageText] = useState("")
  const [scanError, setScanError] = useState<string | null>(null)
  const [activeScanId, setActiveScanId] = useState<string | null>(null)

  const [crawlerMetrics, setCrawlerMetrics] = useState<{
    pages_discovered: number
    pages_visited: number
    requests_completed: number
    current_url?: string | null
    current_depth: number
    elapsed_seconds: number
  }>({
    pages_discovered: 0,
    pages_visited: 0,
    requests_completed: 0,
    current_url: null,
    current_depth: 0,
    elapsed_seconds: 0,
  })

  const [scannerStatus, setScannerStatus] = useState<any>(null)

  useEffect(() => {
    apiClient
      .getScannerStatus()
      .then((data) => setScannerStatus(data))
      .catch(() => {})
  }, [])

  const pollTimerRef = useRef<NodeJS.Timeout | null>(null)

  const stopPolling = () => {
    if (pollTimerRef.current) {
      clearInterval(pollTimerRef.current)
      pollTimerRef.current = null
    }
  }

  // Cleanup polling timer on unmount
  useEffect(() => {
    return () => stopPolling()
  }, [])

  const handleStartScan = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!isAuthorized) {
      setScanError("Explicit target authorization is required before initiating assessment.")
      return
    }

    setScanError(null)
    setScanStatus("queued")
    setIsScanning(true)
    setScanProgress(5)
    setScanStageText("Initiating Attack Surface Scanner crawl job…")
    setCrawlerMetrics({
      pages_discovered: 1,
      pages_visited: 0,
      requests_completed: 0,
      current_url: targetUrl.trim(),
      current_depth: 0,
      elapsed_seconds: 0,
    })

    try {
      const queueResp = await apiClient.startCrawl({
        target_url: targetUrl.trim(),
        is_authorized: true,
        max_pages: maxPages,
        max_depth: maxDepth,
        timeout_seconds: 90,
      })

      const scanId = queueResp.scan_id
      setActiveScanId(scanId)
      setScanStatus("running")
      setScanStageText("Headless Chromium browser rendering web perimeter…")

      // Poll live progress every 800ms
      stopPolling()
      pollTimerRef.current = setInterval(async () => {
        try {
          const prog = await apiClient.getScanProgress(scanId)
          setScanProgress(prog.progress_percentage || 10)
          setScanStageText(prog.message || "Crawling and analyzing perimeter…")
          setCrawlerMetrics({
            pages_discovered: prog.pages_discovered,
            pages_visited: prog.pages_visited,
            requests_completed: prog.requests_completed,
            current_url: prog.current_url,
            current_depth: prog.current_depth,
            elapsed_seconds: prog.elapsed_seconds,
          })

          if (prog.status === "completed") {
            stopPolling()
            setScanProgress(100)
            setScanStatus("completed")
            setIsScanning(false)
            setScanStageText("Assessment completed. Navigating to report…")

            // Auto-navigate to dedicated Assessment Report page with scanId
            setTimeout(() => {
              navigate("assessment-report", undefined, scanId)
            }, 600)
          } else if (prog.status === "failed") {
            stopPolling()
            setIsScanning(false)
            setScanStatus("failed")
            setScanError(prog.error || prog.message || "Assessment scan failed.")
          } else if (prog.status === "cancelled") {
            stopPolling()
            setIsScanning(false)
            setScanStatus("cancelled")
            setScanStageText("Scan was cancelled by user.")
          }
        } catch {
          // Ignore transient poll network errors
        }
      }, 850)
    } catch (err: any) {
      stopPolling()
      setScanStatus("failed")
      setIsScanning(false)
      setScanError(err.message || "Failed to start scan job. Check URL format and target availability.")
    }
  }

  const handleCancelScan = async () => {
    if (!activeScanId) return
    try {
      await apiClient.cancelScan(activeScanId)
      stopPolling()
      setScanStatus("cancelled")
      setIsScanning(false)
      setScanStageText("Scan cancelled.")
    } catch (err: any) {
      setScanError(`Cancel failed: ${err.message}`)
    }
  }

  return (
    <div className="mx-auto flex max-w-4xl flex-col gap-6 pb-12">
      {/* ─────────────────────────────────────────────────────────────
          PAGE HEADER
      ───────────────────────────────────────────────────────────── */}
      <div className="flex flex-col gap-1 border-b border-border/80 pb-4 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex items-center gap-3">
          <span className="flex size-9 items-center justify-center rounded-lg bg-destructive/15 text-destructive ring-1 ring-destructive/30">
            <Globe className="size-5" />
          </span>
          <div>
            <h1 className="text-lg font-bold tracking-tight text-foreground">
              New Assessment — Attack Surface Scanner
            </h1>
            <p className="text-xs text-muted-foreground">
              Non-destructive, evidence-backed security inspection of web perimeter and HTTP responses.
            </p>
          </div>
        </div>

        <Button
          variant="outline"
          size="sm"
          onClick={() => navigate("dashboard")}
          className="self-start text-xs sm:self-auto"
        >
          Back to Dashboard
        </Button>
      </div>

      {/* ─────────────────────────────────────────────────────────────
          FOCUSED SCAN CONFIGURATION FORM
      ───────────────────────────────────────────────────────────── */}
      <Card className="border-border/80 bg-card shadow-sm">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-base text-foreground flex items-center gap-2">
              <Zap className="size-4 text-destructive" />
              Target Specification
            </CardTitle>
            <span className="inline-flex items-center gap-1.5 rounded-full bg-primary/10 px-2.5 py-0.5 text-[11px] font-semibold text-primary font-mono">
              <Lock className="size-3" /> Safe Passive Crawl
            </span>
          </div>
          <CardDescription className="text-xs text-muted-foreground">
            The Attack Surface Scanner evaluates TLS configuration, HTTP security headers, CORS policies, session cookie flags, robots.txt, RFC 9116 security.txt, and passive CVE correlations.
          </CardDescription>
        </CardHeader>

        <CardContent className="space-y-5">
          <form onSubmit={handleStartScan} className="space-y-4">
            {/* Target URL Input */}
            <div className="space-y-1.5">
              <label className="text-xs font-medium text-foreground flex items-center justify-between">
                <span className="flex items-center gap-1.5">
                  <Globe className="size-3.5 text-destructive" /> Target Website URL
                </span>
                <span className="text-[11px] text-muted-foreground font-mono">HTTPS or HTTP</span>
              </label>
              <input
                type="text"
                value={targetUrl}
                onChange={(e) => setTargetUrl(e.target.value)}
                placeholder="https://example.com"
                disabled={isScanning}
                className="flex h-10 w-full rounded-md border border-input bg-background px-3 py-1 text-xs text-foreground outline-none focus-visible:border-ring focus-visible:ring-2 focus-visible:ring-ring font-mono"
                required
              />
            </div>

            {/* Scope & Crawler Settings */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 rounded-lg border bg-muted/10 p-3.5">
              <div className="space-y-1">
                <label className="text-xs font-medium text-foreground flex items-center justify-between">
                  <span>Max Crawl Pages</span>
                  <span className="font-mono text-primary font-bold">{maxPages}</span>
                </label>
                <input
                  type="number"
                  min={1}
                  max={50}
                  value={maxPages}
                  onChange={(e) => setMaxPages(Math.max(1, Math.min(50, parseInt(e.target.value) || 1)))}
                  disabled={isScanning}
                  className="flex h-8 w-full rounded border border-input bg-background px-2.5 text-xs font-mono"
                />
                <p className="text-[10px] text-muted-foreground">Upper bound on unique pages visited (1–50).</p>
              </div>

              <div className="space-y-1">
                <label className="text-xs font-medium text-foreground flex items-center justify-between">
                  <span>Crawl Link Depth</span>
                  <span className="font-mono text-primary font-bold">{maxDepth}</span>
                </label>
                <input
                  type="number"
                  min={1}
                  max={4}
                  value={maxDepth}
                  onChange={(e) => setMaxDepth(Math.max(1, Math.min(4, parseInt(e.target.value) || 1)))}
                  disabled={isScanning}
                  className="flex h-8 w-full rounded border border-input bg-background px-2.5 text-xs font-mono"
                />
                <p className="text-[10px] text-muted-foreground">Maximum hyperlink distance from origin (1–4).</p>
              </div>
            </div>

            {/* Explicit Authorization Checkbox */}
            <div className="rounded-lg border border-amber-500/30 bg-amber-500/5 p-3.5 space-y-2">
              <label className="flex items-start gap-2.5 cursor-pointer">
                <input
                  type="checkbox"
                  checked={isAuthorized}
                  onChange={(e) => setIsAuthorized(e.target.checked)}
                  disabled={isScanning}
                  className="mt-0.5 size-4 rounded border-amber-500 text-amber-500 focus:ring-amber-400"
                />
                <div className="space-y-0.5 text-xs">
                  <span className="font-semibold text-amber-300">
                    Explicit Assessment Authorization Confirmation
                  </span>
                  <p className="text-[11px] text-muted-foreground leading-relaxed">
                    I confirm that I own or possess written authorization to perform a non-destructive security assessment on this target destination. Unauthorized scanning is prohibited.
                  </p>
                </div>
              </label>
            </div>

            {/* Live Progress Bar and Feedback */}
            {scanStatus !== "idle" && (
              <div className="space-y-3 rounded-lg border p-4 bg-muted/20 animate-in fade-in">
                <div className="flex items-center justify-between text-xs font-mono">
                  <span className="text-foreground font-semibold flex items-center gap-2 truncate max-w-[80%]">
                    {isScanning ? (
                      <Loader2 className="size-3.5 animate-spin text-destructive shrink-0" />
                    ) : scanStatus === "completed" ? (
                      <CheckCircle2 className="size-3.5 text-emerald-400 shrink-0" />
                    ) : scanStatus === "cancelled" ? (
                      <Clock className="size-3.5 text-amber-400 shrink-0" />
                    ) : (
                      <XCircle className="size-3.5 text-destructive shrink-0" />
                    )}
                    <span className="truncate">{scanStageText}</span>
                  </span>
                  <span className="font-bold text-destructive">{scanProgress}%</span>
                </div>

                <div className="h-2 w-full overflow-hidden rounded-full bg-muted">
                  <div
                    className="h-full bg-destructive transition-all duration-300"
                    style={{ width: `${scanProgress}%` }}
                  />
                </div>

                {/* Telemetry metrics */}
                <div className="grid grid-cols-4 gap-2 pt-1 text-[10px] font-mono">
                  <div className="rounded bg-background/80 border p-2 text-center">
                    <span className="text-muted-foreground block text-[9px] uppercase">Discovered</span>
                    <span className="font-bold text-foreground text-xs">{crawlerMetrics.pages_discovered}</span>
                  </div>
                  <div className="rounded bg-background/80 border p-2 text-center">
                    <span className="text-muted-foreground block text-[9px] uppercase">Visited</span>
                    <span className="font-bold text-destructive text-xs">{crawlerMetrics.pages_visited}</span>
                  </div>
                  <div className="rounded bg-background/80 border p-2 text-center">
                    <span className="text-muted-foreground block text-[9px] uppercase">Requests</span>
                    <span className="font-bold text-foreground text-xs">{crawlerMetrics.requests_completed}</span>
                  </div>
                  <div className="rounded bg-background/80 border p-2 text-center">
                    <span className="text-muted-foreground block text-[9px] uppercase">Elapsed</span>
                    <span className="font-bold text-foreground text-xs">{crawlerMetrics.elapsed_seconds}s</span>
                  </div>
                </div>

                {crawlerMetrics.current_url && (
                  <p className="text-[10px] font-mono text-muted-foreground truncate pt-0.5">
                    <span className="text-foreground/80 font-semibold">Current:</span> {crawlerMetrics.current_url}
                  </p>
                )}
              </div>
            )}

            {/* Error Banner */}
            {scanError && (
              <div className="rounded-lg border border-destructive/30 bg-destructive/10 p-3 text-xs text-destructive flex items-start gap-2.5">
                <AlertTriangle className="size-4 shrink-0 mt-0.5" />
                <div className="space-y-1">
                  <p className="font-semibold">Assessment Request Failed</p>
                  <p className="text-[11px] leading-relaxed">{scanError}</p>
                </div>
              </div>
            )}

            {/* Action Buttons */}
            <div className="flex gap-3 pt-2">
              {isScanning ? (
                <Button
                  type="button"
                  variant="destructive"
                  onClick={handleCancelScan}
                  className="w-full text-xs font-semibold"
                >
                  <XCircle className="mr-1.5 size-4" /> Cancel Scan
                </Button>
              ) : (
                <Button
                  type="submit"
                  disabled={!isAuthorized || !targetUrl.trim()}
                  className="w-full bg-destructive text-destructive-foreground hover:bg-destructive/90 text-xs font-bold h-10"
                >
                  <Zap className="mr-1.5 size-4" />
                  Start Attack Surface Scan
                </Button>
              )}
            </div>
          </form>
        </CardContent>
      </Card>

      {/* ─────────────────────────────────────────────────────────────
          SECURITY BOUNDARIES & ENGINE CAPABILITIES
      ───────────────────────────────────────────────────────────── */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs text-muted-foreground">
        <div className="rounded-lg border bg-card/60 p-4 space-y-1.5">
          <p className="font-semibold text-foreground flex items-center gap-1.5">
            <Lock className="size-3.5 text-primary" /> Guarded SSRF Restrictions
          </p>
          <p className="leading-relaxed text-[11px]">
            Target addresses in private ranges (RFC 1918), loopback (127.0.0.1), link-local, and cloud metadata (169.254.169.254) are rejected by default unless explicit local development mode is configured on the host.
          </p>
        </div>

        <div className="rounded-lg border bg-card/60 p-4 space-y-1.5">
          <p className="font-semibold text-foreground flex items-center gap-1.5">
            <Terminal className="size-3.5 text-primary" /> Supported Detection Modules
          </p>
          <p className="leading-relaxed text-[11px]">
            TLS & cipher suite checks, missing Content-Security-Policy, HSTS, X-Frame-Options, secure cookie attributes, exposed source maps, robots.txt disallow policies, and RFC 9116 security.txt validation.
          </p>
        </div>
      </div>
    </div>
  )
}
