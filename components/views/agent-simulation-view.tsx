"use client"

import { useState, useEffect, useRef } from "react"
import {
  AlertTriangle,
  ArrowLeft,
  ArrowRight,
  Bot,
  CheckCircle2,
  CheckSquare,
  Clock,
  Code2,
  DollarSign,
  ExternalLink,
  FileText,
  Flame,
  Globe,
  Info,
  Layers,
  Loader2,
  Lock,
  RefreshCw,
  RotateCcw,
  Server,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Sliders,
  Sparkles,
  Terminal,
  TrendingDown,
  Workflow,
  XCircle,
  Zap,
} from "lucide-react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { useAppState } from "@/components/app/app-state"
import {
  apiClient,
  type AttackerScanResponse,
  type VulnerabilityFinding,
  type DefenderAnalysisResponse,
  type RemediationRecommendation,
} from "@/lib/api-client"

interface AttackStage {
  stage_number: number
  name: string
  description: string
  technique: string
  success_likelihood: number
  evidence: string
}

interface AttackSimulationResult {
  asset_id: string
  asset_name: string
  attack_scenario: string
  threat_intensity: string
  baseline_risk_score: number
  simulated_risk_score: number
  is_compromise_modeled: boolean
  stages: AttackStage[]
  affected_assets: string[]
  potential_business_impact: string
  exploit_factors: string[]
  suggested_defenses: string[]
}

interface AppliedDefenseImpact {
  control_id: string
  control_name: string
  mitigation_reason: string
  points_reduced: number
}

interface DefenseSimulationResult {
  asset_id: string
  asset_name: string
  pre_defense_risk_score: number
  residual_risk_score: number
  absolute_risk_reduction: number
  percentage_risk_reduction: number
  applied_controls: AppliedDefenseImpact[]
  remaining_weaknesses: string[]
  recommended_next_action: string
}

export function AgentSimulationView() {
  const { navigate, dataset } = useAppState()

  // Main Mode: Real Website Scanner (Live) vs Simulated Scenario Demo
  const [activeMode, setActiveMode] = useState<"live_assessment" | "simulation_demo">("live_assessment")

  // ==========================================
  // REAL ATTACKER AGENT (WEBSITE SCANNER) STATE
  // ==========================================
  const [targetUrl, setTargetUrl] = useState("https://example.com")
  const [isAuthorized, setIsAuthorized] = useState(false)
  const [isScanning, setIsScanning] = useState(false)
  const [scanProgress, setScanProgress] = useState(0)
  const [scanStageText, setScanStageText] = useState("")
  const [scanStatus, setScanStatus] = useState<"idle" | "queued" | "running" | "completed" | "failed" | "cancelled">("idle")
  const [scanResult, setScanResult] = useState<AttackerScanResponse | null>(null)
  const [scanError, setScanError] = useState<string | null>(null)
  const [activeScanId, setActiveScanId] = useState<string | null>(null)
  const [severityFilter, setSeverityFilter] = useState<string>("all")
  const [expandedEvidence, setExpandedEvidence] = useState<Record<string, boolean>>({})
  const [scannerStatusInfo, setScannerStatusInfo] = useState<any>(null)

  // ==========================================
  // REAL DEFENDER AGENT (REMEDIATION) STATE
  // ==========================================
  const [availableBudget, setAvailableBudget] = useState<number>(5000)
  const [hourlyRate, setHourlyRate] = useState<number>(125)
  const [isAnalyzingDefender, setIsAnalyzingDefender] = useState(false)
  const [defenderPlan, setDefenderPlan] = useState<DefenderAnalysisResponse | null>(null)
  const [defenderError, setDefenderError] = useState<string | null>(null)
  const [activePriorityTab, setActivePriorityTab] = useState<"fix_immediately" | "fix_next" | "defer_or_mitigate" | "all">("fix_immediately")
  const [statusUpdating, setStatusUpdating] = useState<Record<string, boolean>>({})

  // ==========================================
  // SIMULATED DEMO SANDBOX STATE (PRESERVED)
  // ==========================================
  const [selectedAssetId, setSelectedAssetId] = useState(dataset.assets[0]?.id || "a-pay-prod")
  const [attackScenario, setAttackScenario] = useState("vulnerability_exploitation")
  const [threatIntensity, setThreatIntensity] = useState("medium")
  const [isSimulatingAttack, setIsSimulatingAttack] = useState(false)
  const [attackResult, setAttackResult] = useState<AttackSimulationResult | null>(null)
  const [attackError, setAttackError] = useState<string | null>(null)
  const [selectedControls, setSelectedControls] = useState<string[]>([])
  const [isSimulatingDefense, setIsSimulatingDefense] = useState(false)
  const [defenseResult, setDefenseResult] = useState<DefenseSimulationResult | null>(null)
  const [defenseError, setDefenseError] = useState<string | null>(null)

  // Load scanner status on mount
  useEffect(() => {
    apiClient
      .getScannerStatus()
      .then((data) => setScannerStatusInfo(data))
      .catch(() => {})
  }, [])

  // Progress bar ticker ref
  const progressTimerRef = useRef<NodeJS.Timeout | null>(null)

  const startProgressAnimation = () => {
    setScanProgress(5)
    setScanStageText("Validating URL & Enforcing SSRF Target Guard…")
    let p = 5

    progressTimerRef.current = setInterval(() => {
      p += Math.floor(Math.random() * 12) + 6
      if (p >= 95) {
        p = 95
        if (progressTimerRef.current) clearInterval(progressTimerRef.current)
      }
      setScanProgress(p)

      if (p < 25) {
        setScanStageText("Probing TLS Transport Security & Cipher Suites…")
      } else if (p < 45) {
        setScanStageText("Inspecting HTTP Response Headers & CSP Directives…")
      } else if (p < 65) {
        setScanStageText("Analyzing Session Cookie Attributes & CORS Policies…")
      } else if (p < 85) {
        setScanStageText("Checking robots.txt & RFC 9116 security.txt…")
      } else {
        setScanStageText("Correlating CVE Knowledge & Generating Defender Handover…")
      }
    }, 450)
  }

  const stopProgressAnimation = () => {
    if (progressTimerRef.current) {
      clearInterval(progressTimerRef.current)
      progressTimerRef.current = null
    }
  }

  const [maxPages, setMaxPages] = useState<number>(10)
  const [maxDepth, setMaxDepth] = useState<number>(2)
  const [resultsTab, setResultsTab] = useState<"findings" | "pages">("findings")
  const [discoveredPagesList, setDiscoveredPagesList] = useState<any[]>([])
  const [liveCrawlerMetrics, setLiveCrawlerMetrics] = useState<{
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

  // Polling ref for async scan progress
  const pollTimerRef = useRef<NodeJS.Timeout | null>(null)

  const stopPolling = () => {
    if (pollTimerRef.current) {
      clearInterval(pollTimerRef.current)
      pollTimerRef.current = null
    }
  }

  // ==========================================
  // ATTACKER SCAN HANDLERS (ASYNC CRAWLER)
  // ==========================================
  const handleStartRealScan = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!isAuthorized) {
      setScanError("Explicit target authorization is required before initiating assessment.")
      return
    }

    setScanError(null)
    setDefenderError(null)
    setScanStatus("queued")
    setIsScanning(true)
    setScanProgress(5)
    setScanStageText("Initiating asynchronous browser crawler…")
    setDiscoveredPagesList([])
    setLiveCrawlerMetrics({
      pages_discovered: 1,
      pages_visited: 0,
      requests_completed: 0,
      current_url: targetUrl.trim(),
      current_depth: 0,
      elapsed_seconds: 0,
    })

    try {
      // Step 1: Promptly trigger asynchronous crawl job
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

      // Step 2: Poll live progress every 800ms
      stopPolling()
      pollTimerRef.current = setInterval(async () => {
        try {
          const prog = await apiClient.getScanProgress(scanId)
          setScanProgress(prog.progress_percentage || 10)
          setScanStageText(prog.message || "Crawling and analyzing perimeter…")
          setLiveCrawlerMetrics({
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
            setScanStageText("Crawl & Security Assessment Completed.")

            // Fetch final persisted scan record and pages
            const fullRecord = await apiClient.getScanRecord(scanId)
            setScanResult(fullRecord)
            if (fullRecord.discovered_pages) {
              setDiscoveredPagesList(fullRecord.discovered_pages)
            } else {
              const pages = await apiClient.getScanPages(scanId).catch(() => [])
              setDiscoveredPagesList(pages)
            }

            // Handover actual findings to Defender Agent
            runDefenderAnalysis(fullRecord.scan_id, fullRecord.target_url, fullRecord.findings, availableBudget, hourlyRate)
          } else if (prog.status === "failed") {
            stopPolling()
            setIsScanning(false)
            setScanStatus("failed")
            setScanError(prog.error || prog.message || "Crawl failed.")
          } else if (prog.status === "cancelled") {
            stopPolling()
            setIsScanning(false)
            setScanStatus("cancelled")
            setScanStageText("Scan was cancelled.")
          }
        } catch (err: any) {
          // Non-fatal poll blip
        }
      }, 850)
    } catch (err: any) {
      stopPolling()
      setScanStatus("failed")
      setIsScanning(false)
      setScanError(err.message || "Failed to start crawler job. Check URL and authorization.")
    }
  }

  const handleCancelScan = async () => {
    if (!activeScanId && !isScanning) return
    stopPolling()
    setIsScanning(false)
    setScanStatus("cancelled")
    setScanStageText("Crawl Cancelled by User.")

    if (activeScanId) {
      try {
        await apiClient.cancelScan(activeScanId)
      } catch {}
    }
  }

  const handleRescan = async () => {
    if (!scanResult) return
    setScanError(null)
    setIsScanning(true)
    setScanStatus("queued")
    setScanProgress(5)
    setScanStageText("Re-queueing authorized security crawl…")

    try {
      const queueResp = await apiClient.startCrawl({
        target_url: scanResult.target_url,
        is_authorized: true,
        max_pages: maxPages,
        max_depth: maxDepth,
        timeout_seconds: 90,
      })

      const scanId = queueResp.scan_id
      setActiveScanId(scanId)
      setScanStatus("running")

      stopPolling()
      pollTimerRef.current = setInterval(async () => {
        try {
          const prog = await apiClient.getScanProgress(scanId)
          setScanProgress(prog.progress_percentage || 10)
          setScanStageText(prog.message || "Crawling…")
          setLiveCrawlerMetrics({
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
            const fullRecord = await apiClient.getScanRecord(scanId)
            setScanResult(fullRecord)
            if (fullRecord.discovered_pages) {
              setDiscoveredPagesList(fullRecord.discovered_pages)
            }
            runDefenderAnalysis(fullRecord.scan_id, fullRecord.target_url, fullRecord.findings, availableBudget, hourlyRate)
          } else if (prog.status === "failed" || prog.status === "cancelled") {
            stopPolling()
            setIsScanning(false)
            setScanStatus(prog.status)
            if (prog.error) setScanError(prog.error)
          }
        } catch {}
      }, 850)
    } catch (err: any) {
      stopPolling()
      setIsScanning(false)
      setScanStatus("failed")
      setScanError(err.message || "Rescan failed.")
    }
  }

  // ==========================================
  // DEFENDER AGENT HANDLERS
  // ==========================================
  const runDefenderAnalysis = async (
    scanId: string | undefined,
    url: string,
    findings: VulnerabilityFinding[],
    budget: number,
    rate: number
  ) => {
    setIsAnalyzingDefender(true)
    setDefenderError(null)

    try {
      const plan = await apiClient.analyzeDefenderBudget({
        scan_id: scanId,
        target_url: url,
        findings: findings,
        available_budget: budget,
        hourly_rate: rate,
      })
      setDefenderPlan(plan)
    } catch (err: any) {
      setDefenderError(err.message || "Failed to calculate defender remediation plan.")
    } finally {
      setIsAnalyzingDefender(false)
    }
  }

  const handleRecalculateBudget = () => {
    if (!scanResult) return
    runDefenderAnalysis(
      scanResult.scan_id,
      scanResult.target_url,
      scanResult.findings,
      availableBudget,
      hourlyRate
    )
  }

  const handleUpdateRemediationStatus = async (findingId: string, newStatus: string) => {
    if (!scanResult) return
    setStatusUpdating((prev) => ({ ...prev, [findingId]: true }))

    try {
      await apiClient.updateRemediationStatus(scanResult.scan_id, findingId, newStatus)

      // Update in local Defender Plan
      if (defenderPlan) {
        const updateList = (list: RemediationRecommendation[]) =>
          list.map((item) =>
            item.finding_id === findingId ? { ...item, status: newStatus as any } : item
          )

        setDefenderPlan({
          ...defenderPlan,
          fix_immediately: updateList(defenderPlan.fix_immediately),
          fix_next: updateList(defenderPlan.fix_next),
          defer_or_mitigate: updateList(defenderPlan.defer_or_mitigate),
          unbudgeted_high_risk_findings: updateList(defenderPlan.unbudgeted_high_risk_findings),
        })
      }

      // Update in local Scan findings
      setScanResult({
        ...scanResult,
        findings: scanResult.findings.map((f) =>
          f.id === findingId ? { ...f, remediation_status: newStatus as any } : f
        ),
      })
    } catch (err: any) {
      setDefenderError(`Failed to update status: ${err.message}`)
    } finally {
      setStatusUpdating((prev) => ({ ...prev, [findingId]: false }))
    }
  }

  const toggleEvidence = (id: string) => {
    setExpandedEvidence((prev) => ({ ...prev, [id]: !prev[id] }))
  }

  const filteredFindings = scanResult
    ? scanResult.findings.filter((f) => {
        if (severityFilter === "all") return true
        return f.severity.toLowerCase() === severityFilter.toLowerCase()
      })
    : []

  // ==========================================
  // SIMULATION DEMO FALLBACKS (PRESERVED)
  // ==========================================
  const runFallbackAttack = (assetId: string, scenario: string, intensity: string): AttackSimulationResult => {
    const asset = dataset.assets.find((a) => a.id === assetId) || dataset.assets[0]
    const intensityFactor = intensity === "low" ? 0.8 : intensity === "high" ? 1.25 : 1.0
    const baseScore = asset ? (asset.criticality === "Critical" ? 85.0 : 65.0) : 70.0
    const simScore = Math.min(100.0, Number((baseScore + 12.0 * intensityFactor).toFixed(1)))

    const stages: AttackStage[] = [
      {
        stage_number: 1,
        name: "Initial Access & Reconnaissance",
        description: `Attacker identifies exposed services and configurations on ${asset?.name || "Target"}.`,
        technique: "T1190 - Exploit Public-Facing Application",
        success_likelihood: Math.min(0.95, Number((0.75 * intensityFactor).toFixed(2))),
        evidence: `Asset exposure is '${asset?.exposure || "Internet-facing"}'; patch compliance is '${asset?.controls.patching || "Missing"}'.`,
      },
      {
        stage_number: 2,
        name: "Payload Execution & Privilege Escalation",
        description: `Delivers exploit payload exploiting vulnerable endpoint on ${asset?.name || "Target"}.`,
        technique: "T1059 - Command and Scripting Interpreter",
        success_likelihood: Math.min(0.90, Number((0.70 * intensityFactor).toFixed(2))),
        evidence: `EDR status is '${asset?.controls.edr || "Partial"}'; lateral inspection unblocked.`,
      },
      {
        stage_number: 3,
        name: "Lateral Pivot & Data Infiltration",
        description: "Adversary establishes persistence and maps adjacent internal subnets.",
        technique: "T1021 - Remote Services & Lateral Movement",
        success_likelihood: Math.min(0.85, Number((0.60 * intensityFactor).toFixed(2))),
        evidence: `Network segmentation is '${asset?.controls.segmentation || "Missing"}'.`,
      },
    ]

    return {
      asset_id: assetId,
      asset_name: asset?.name || "Monitored Asset",
      attack_scenario: scenario,
      threat_intensity: intensity,
      baseline_risk_score: baseScore,
      simulated_risk_score: simScore,
      is_compromise_modeled: true,
      stages,
      affected_assets: [asset?.name || "Primary Asset", "Customer Database", "Identity Gateway"],
      potential_business_impact: `Simulated compromise of ${asset?.name || "Asset"} risks service outage and exposure of sensitive operational data.`,
      exploit_factors: ["Unpatched remote vulnerability", "Missing network segmentation barriers"],
      suggested_defenses: ["patching", "mfa", "segmentation", "edr"],
    }
  }

  const runFallbackDefense = (
    assetId: string,
    simScore: number,
    controls: string[]
  ): DefenseSimulationResult => {
    const CONTROL_VALUES: Record<string, { name: string; points: number; reason: string }> = {
      patching: {
        name: "Security Patch Deployment",
        points: 14.0,
        reason: "Eliminates known public exploit vectors and addresses unpatched vulnerabilities.",
      },
      mfa: {
        name: "Multi-Factor Authentication (MFA)",
        points: 12.0,
        reason: "Blocks credential stuffing, brute force attempts, and unauthorized session establishment.",
      },
      segmentation: {
        name: "Micro-Segmentation & East-West Filtering",
        points: 10.0,
        reason: "Restricts lateral pivot attempts to connected internal databases and services.",
      },
      edr: {
        name: "Endpoint Detection & Response (EDR)",
        points: 8.0,
        reason: "Enhances anomaly detection, memory inspection, and automated containment response.",
      },
    }

    const applied: AppliedDefenseImpact[] = []
    let totalReduction = 0

    for (const c of controls) {
      if (CONTROL_VALUES[c]) {
        applied.push({
          control_id: c,
          control_name: CONTROL_VALUES[c].name,
          mitigation_reason: CONTROL_VALUES[c].reason,
          points_reduced: CONTROL_VALUES[c].points,
        })
        totalReduction += CONTROL_VALUES[c].points
      }
    }

    const residual = Math.max(15.0, Number((simScore - totalReduction).toFixed(1)))
    const absReduction = Number((simScore - residual).toFixed(1))
    const pctReduction = Number(((absReduction / simScore) * 100).toFixed(1))

    return {
      asset_id: assetId,
      asset_name: dataset.assets.find((a) => a.id === assetId)?.name || "Target Asset",
      pre_defense_risk_score: simScore,
      residual_risk_score: residual,
      absolute_risk_reduction: absReduction,
      percentage_risk_reduction: pctReduction,
      applied_controls: applied,
      remaining_weaknesses:
        controls.length < 4
          ? ["Some unselected defense-in-depth controls leave residual exposure."]
          : ["Defense-in-depth controls fully applied across tested parameters."],
      recommended_next_action:
        residual <= 40
          ? "Maintain telemetry monitoring and schedule regular automated patch compliance."
          : "Apply additional defensive safeguards to lower residual exposure below medium tier.",
    }
  }

  const handleRunSimulatedAttack = async (e: React.FormEvent) => {
    e.preventDefault()
    setAttackError(null)
    setDefenseResult(null)
    setSelectedControls([])
    setIsSimulatingAttack(true)

    const payload = {
      asset_id: selectedAssetId,
      attack_scenario: attackScenario,
      threat_intensity: threatIntensity,
    }

    try {
      const data = await apiClient.simulateAttack(payload)
      setAttackResult(data)
      setSelectedControls(data.suggested_defenses)
    } catch {
      const fallback = runFallbackAttack(selectedAssetId, attackScenario, threatIntensity)
      setAttackResult(fallback)
      setSelectedControls(fallback.suggested_defenses)
    } finally {
      setIsSimulatingAttack(false)
    }
  }

  const handleRunSimulatedDefense = async () => {
    if (!attackResult) return
    if (selectedControls.length === 0) {
      setDefenseError("Please select at least one defensive control.")
      return
    }

    setDefenseError(null)
    setIsSimulatingDefense(true)

    const payload = {
      asset_id: attackResult.asset_id,
      baseline_risk_score: attackResult.baseline_risk_score,
      simulated_risk_score: attackResult.simulated_risk_score,
      selected_controls: selectedControls,
      attack_scenario: attackResult.attack_scenario,
    }

    try {
      const data = await apiClient.simulateDefense(payload)
      setDefenseResult(data)
    } catch {
      const fallback = runFallbackDefense(
        attackResult.asset_id,
        attackResult.simulated_risk_score,
        selectedControls
      )
      setDefenseResult(fallback)
    } finally {
      setIsSimulatingDefense(false)
    }
  }

  const toggleControl = (controlKey: string) => {
    setSelectedControls((prev) =>
      prev.includes(controlKey) ? prev.filter((c) => c !== controlKey) : [...prev, controlKey]
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
        return "bg-slate-500/15 text-slate-400 border-slate-500/30"
    }
  }

  const getStatusBadgeClass = (st: string) => {
    switch (st) {
      case "Fixed":
      case "Verified":
        return "bg-emerald-500/15 text-emerald-400 border-emerald-500/30"
      case "In Progress":
        return "bg-amber-500/15 text-amber-400 border-amber-500/30"
      case "Planned":
        return "bg-blue-500/15 text-blue-400 border-blue-500/30"
      case "Accepted Risk":
        return "bg-purple-500/15 text-purple-400 border-purple-500/30"
      default:
        return "bg-muted/50 text-muted-foreground border-border"
    }
  }

  return (
    <div className="flex min-h-svh w-full flex-col items-center justify-start p-4 md:p-8">
      <div className="w-full max-w-6xl space-y-6">
        {/* Top Navigation Bar */}
        <div className="flex items-center justify-between border-b pb-4">
          <Button
            type="button"
            variant="ghost"
            size="sm"
            onClick={() => navigate("landing")}
            className="flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground"
          >
            <ArrowLeft className="size-4" />
            Back to Home
          </Button>

          <div className="flex items-center gap-2">
            <ShieldCheck className="size-4 text-primary" />
            <span className="text-xs font-semibold text-foreground">CyberSentinel AI</span>
            <span className="text-xs text-muted-foreground">· Attacker & Defender Autonomous Security Platform</span>
          </div>

          <Button
            type="button"
            variant="outline"
            size="sm"
            onClick={() => {
              setScanResult(null)
              setDefenderPlan(null)
              setScanError(null)
              setDefenderError(null)
              setScanStatus("idle")
            }}
            className="text-xs flex items-center gap-1.5"
            title="Reset Session"
          >
            <RotateCcw className="size-3.5" />
            New Assessment
          </Button>
        </div>

        {/* Mode Selector Tabs */}
        <div className="flex items-center justify-between flex-wrap gap-3">
          <div className="inline-flex rounded-lg border bg-card p-1 text-xs">
            <button
              type="button"
              onClick={() => setActiveMode("live_assessment")}
              className={`flex items-center gap-2 rounded-md px-3.5 py-1.5 font-medium transition-all ${
                activeMode === "live_assessment"
                  ? "bg-primary text-primary-foreground shadow-sm"
                  : "text-muted-foreground hover:text-foreground"
              }`}
            >
              <Zap className="size-3.5" />
              Live Website Scanner & Remediation Engine
            </button>
            <button
              type="button"
              onClick={() => setActiveMode("simulation_demo")}
              className={`flex items-center gap-2 rounded-md px-3.5 py-1.5 font-medium transition-all ${
                activeMode === "simulation_demo"
                  ? "bg-warning text-warning-foreground shadow-sm"
                  : "text-muted-foreground hover:text-foreground"
              }`}
            >
              <Bot className="size-3.5" />
              Simulated Scenario Sandbox (Demo)
            </button>
          </div>

          {/* Scanner provenance badge */}
          {scannerStatusInfo && (
            <div className="flex items-center gap-2 text-[11px] text-muted-foreground font-mono flex-wrap">
              <span className="inline-block size-2 rounded-full bg-emerald-500 animate-pulse" />
              <span>{scannerStatusInfo.engine}</span>
              {scannerStatusInfo.owasp_zap?.is_available ? (
                <span className="text-emerald-400 font-semibold">[ZAP Active]</span>
              ) : (
                <span className="text-muted-foreground/70">[Built-in Passive Mode]</span>
              )}
              {scannerStatusInfo.local_dev_scan?.is_enabled && (
                <span className="text-amber-400 bg-amber-400/10 border border-amber-400/30 px-2 py-0.5 rounded text-[10px] font-semibold" title={`Configured target: ${scannerStatusInfo.local_dev_scan.target}`}>
                  [Local Dev Target: {scannerStatusInfo.local_dev_scan.target}]
                </span>
              )}
            </div>
          )}
        </div>

        {/* ======================================================== */}
        {/* MODE 1: REAL EVIDENCE-BASED SCANNER & DEFENDER ENGINE    */}
        {/* ======================================================== */}
        {activeMode === "live_assessment" && (
          <div className="space-y-6 animate-in fade-in duration-300">
            {/* Top Overview Banner */}
            <Card className="border-primary/30 bg-primary/5">
              <CardHeader className="pb-3">
                <div className="flex items-center justify-between flex-wrap gap-2">
                  <div className="flex items-center gap-2.5 text-primary">
                    <Globe className="size-5" />
                    <CardTitle className="text-base">Evidence-Based Website Assessment & Budget Optimization</CardTitle>
                  </div>
                  <span className="inline-flex items-center gap-1.5 rounded-full bg-primary/15 px-3 py-1 text-xs font-semibold text-primary font-mono">
                    <Lock className="size-3.5" /> Non-Destructive Safe Scan
                  </span>
                </div>
                <CardDescription className="text-xs text-foreground/80 mt-1 leading-relaxed">
                  The <strong>Attacker Agent</strong> executes real passive socket/TLS and header inspections against your explicitly authorized web perimeter.
                  The <strong>Defender Agent</strong> consumes concrete findings, calculates technical implementation costs, and prioritizes remediation to maximize risk reduction within your budget.
                </CardDescription>
              </CardHeader>
            </Card>

            {/* Side-by-side Dual Agent Panels */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* PANEL 1: ATTACKER AGENT */}
              <Card className="border-destructive/30 bg-card flex flex-col justify-between">
                <CardHeader className="pb-3">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2 text-destructive font-semibold text-base">
                      <Sparkles className="size-5" />
                      <span>Attacker Agent — Real Website Scanner</span>
                    </div>
                    {scanStatus === "running" && (
                      <span className="text-[11px] font-mono font-semibold text-destructive flex items-center gap-1">
                        <Loader2 className="size-3 animate-spin" /> Scanning…
                      </span>
                    )}
                  </div>
                  <CardDescription className="text-xs">
                    Passive web security scanner probing transport security, HTTP headers, CORS, cookie attributes, exposed metadata, and known CVEs.
                  </CardDescription>
                </CardHeader>

                <CardContent className="space-y-4">
                  <form onSubmit={handleStartRealScan} className="space-y-3.5">
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
                        className="flex h-9 w-full rounded-md border border-input bg-background px-3 py-1 text-xs text-foreground outline-none focus-visible:border-ring focus-visible:ring-2 focus-visible:ring-ring font-mono"
                        required
                      />
                    </div>

                    {/* Crawler Configuration: Max Pages & Max Depth */}
                    <div className="grid grid-cols-2 gap-3">
                      <div className="space-y-1">
                        <label className="text-[11px] font-medium text-muted-foreground flex items-center justify-between">
                          <span>Max Crawl Pages</span>
                          <span className="font-mono text-foreground font-semibold">{maxPages}</span>
                        </label>
                        <input
                          type="number"
                          min={1}
                          max={50}
                          value={maxPages}
                          onChange={(e) => setMaxPages(Math.max(1, Math.min(50, parseInt(e.target.value) || 1)))}
                          disabled={isScanning}
                          className="flex h-8 w-full rounded-md border border-input bg-background px-2.5 py-1 text-xs text-foreground font-mono"
                        />
                      </div>
                      <div className="space-y-1">
                        <label className="text-[11px] font-medium text-muted-foreground flex items-center justify-between">
                          <span>Max Crawl Depth</span>
                          <span className="font-mono text-foreground font-semibold">{maxDepth}</span>
                        </label>
                        <input
                          type="number"
                          min={1}
                          max={5}
                          value={maxDepth}
                          onChange={(e) => setMaxDepth(Math.max(1, Math.min(5, parseInt(e.target.value) || 1)))}
                          disabled={isScanning}
                          className="flex h-8 w-full rounded-md border border-input bg-background px-2.5 py-1 text-xs text-foreground font-mono"
                        />
                      </div>
                    </div>

                    {/* Scope & Limitations Info Callout */}
                    <div className="rounded-lg border bg-muted/20 p-2.5 text-[11px] text-muted-foreground space-y-1">
                      <p className="font-semibold text-foreground flex items-center gap-1">
                        <Info className="size-3 text-primary" /> Scope & Assessment Boundaries
                      </p>
                      <p className="leading-relaxed">
                        Bounded to safe non-destructive external auditing (TLS configuration, HTTP response headers, cookie security, RFC 9116 security.txt, and component version correlation). Does NOT execute intrusive exploit payloads, brute force, or fuzzing.
                      </p>
                    </div>

                    {/* Authorization Confirmation Checkbox */}
                    <label className="flex items-start gap-2.5 rounded-lg border border-destructive/20 bg-destructive/5 p-2.5 cursor-pointer transition-colors hover:bg-destructive/10">
                      <input
                        type="checkbox"
                        checked={isAuthorized}
                        onChange={(e) => setIsAuthorized(e.target.checked)}
                        disabled={isScanning}
                        className="mt-0.5 rounded border-destructive text-destructive focus:ring-destructive size-4"
                      />
                      <div className="min-w-0 flex-1 text-xs">
                        <p className="font-semibold text-foreground">Explicit Authorization Confirmation</p>
                        <p className="text-[11px] text-muted-foreground leading-relaxed">
                          I verify that I own or possess explicit written authorization to perform a non-destructive security assessment on this target.
                        </p>
                      </div>
                    </label>

                    {/* Progress Bar & Live Telemetry Indicator */}
                    {(isScanning || scanStatus === "completed" || scanStatus === "running" || scanStatus === "queued") && (
                      <div className="space-y-2 rounded-lg border p-3 bg-muted/10 animate-in fade-in">
                        <div className="flex items-center justify-between text-xs font-mono">
                          <span className="text-foreground font-semibold flex items-center gap-1.5 truncate max-w-[80%]">
                            {isScanning ? (
                              <Loader2 className="size-3 animate-spin text-destructive shrink-0" />
                            ) : scanStatus === "completed" ? (
                              <CheckCircle2 className="size-3 text-emerald-400 shrink-0" />
                            ) : (
                              <Clock className="size-3 text-muted-foreground shrink-0" />
                            )}
                            <span className="truncate">{scanStageText}</span>
                          </span>
                          <span className="text-destructive font-bold">{scanProgress}%</span>
                        </div>
                        <div className="h-1.5 w-full overflow-hidden rounded-full bg-muted">
                          <div
                            className="h-full bg-destructive transition-all duration-300"
                            style={{ width: `${scanProgress}%` }}
                          />
                        </div>

                        {/* Live Crawler Telemetry Cards */}
                        <div className="grid grid-cols-4 gap-1.5 pt-1 text-[10px] font-mono">
                          <div className="rounded bg-background/60 border p-1.5 text-center">
                            <span className="text-muted-foreground block text-[9px]">Discovered</span>
                            <span className="font-bold text-foreground text-xs">{liveCrawlerMetrics.pages_discovered}</span>
                          </div>
                          <div className="rounded bg-background/60 border p-1.5 text-center">
                            <span className="text-muted-foreground block text-[9px]">Visited</span>
                            <span className="font-bold text-destructive text-xs">{liveCrawlerMetrics.pages_visited}</span>
                          </div>
                          <div className="rounded bg-background/60 border p-1.5 text-center">
                            <span className="text-muted-foreground block text-[9px]">Requests</span>
                            <span className="font-bold text-foreground text-xs">{liveCrawlerMetrics.requests_completed}</span>
                          </div>
                          <div className="rounded bg-background/60 border p-1.5 text-center">
                            <span className="text-muted-foreground block text-[9px]">Elapsed</span>
                            <span className="font-bold text-foreground text-xs">{liveCrawlerMetrics.elapsed_seconds}s</span>
                          </div>
                        </div>

                        {liveCrawlerMetrics.current_url && (
                          <div className="text-[10px] font-mono text-muted-foreground truncate pt-0.5">
                            <span className="text-foreground/70 font-semibold">Current URL:</span> {liveCrawlerMetrics.current_url}
                          </div>
                        )}
                      </div>
                    )}

                    {/* Error Notice */}
                    {scanError && (
                      <div className="rounded-md bg-destructive/10 border border-destructive/20 p-2.5 text-xs text-destructive flex items-start gap-2">
                        <XCircle className="size-4 shrink-0 mt-0.5" />
                        <div className="space-y-1">
                          <p className="font-semibold">Assessment Error</p>
                          <p className="text-[11px] leading-relaxed">{scanError}</p>
                        </div>
                      </div>
                    )}

                    {/* Action Buttons */}
                    <div className="flex gap-2 pt-1">
                      {isScanning ? (
                        <Button
                          type="button"
                          variant="destructive"
                          onClick={handleCancelScan}
                          className="w-full text-xs font-medium"
                        >
                          <XCircle className="mr-1.5 size-3.5" /> Cancel Scan
                        </Button>
                      ) : (
                        <Button
                          type="submit"
                          disabled={!isAuthorized || !targetUrl.trim()}
                          className="w-full bg-destructive text-destructive-foreground hover:bg-destructive/90 text-xs font-medium"
                        >
                          <Zap className="mr-1.5 size-3.5" />
                          Start Real Security Scan
                        </Button>
                      )}

                      {scanResult && !isScanning && (
                        <Button
                          type="button"
                          variant="outline"
                          onClick={handleRescan}
                          className="text-xs"
                          title="Run Authorized Rescan to verify fixes"
                        >
                          <RefreshCw className="size-3.5 mr-1" />
                          Rescan
                        </Button>
                      )}
                    </div>
                  </form>
                </CardContent>
              </Card>

              {/* PANEL 2: DEFENDER AGENT */}
              <Card className="border-primary/30 bg-card flex flex-col justify-between">
                <CardHeader className="pb-3">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2 text-primary font-semibold text-base">
                      <Workflow className="size-5" />
                      <span>Defender Agent — Remediation Engine</span>
                    </div>
                    {isAnalyzingDefender && (
                      <span className="text-[11px] font-mono font-semibold text-primary flex items-center gap-1">
                        <Loader2 className="size-3 animate-spin" /> Optimizing…
                      </span>
                    )}
                  </div>
                  <CardDescription className="text-xs">
                    Synthesizes empirical findings into actionable playbooks and allocates financial resources to maximize risk reduction.
                  </CardDescription>
                </CardHeader>

                <CardContent className="space-y-4">
                  {/* Budget Configuration Form */}
                  <div className="grid grid-cols-2 gap-3">
                    <div className="space-y-1.5">
                      <label className="text-xs font-medium text-foreground flex items-center gap-1">
                        <DollarSign className="size-3.5 text-primary" /> Remediation Budget (USD)
                      </label>
                      <input
                        type="number"
                        min="100"
                        step="250"
                        value={availableBudget}
                        onChange={(e) => setAvailableBudget(Number(e.target.value))}
                        disabled={isAnalyzingDefender}
                        className="flex h-9 w-full rounded-md border border-input bg-background px-3 py-1 text-xs text-foreground outline-none focus-visible:border-ring focus-visible:ring-2 focus-visible:ring-ring font-mono font-bold"
                      />
                    </div>

                    <div className="space-y-1.5">
                      <label className="text-xs font-medium text-foreground flex items-center gap-1">
                        <Clock className="size-3.5 text-primary" /> Engineering Rate ($/hr)
                      </label>
                      <input
                        type="number"
                        min="50"
                        step="25"
                        value={hourlyRate}
                        onChange={(e) => setHourlyRate(Number(e.target.value))}
                        disabled={isAnalyzingDefender}
                        className="flex h-9 w-full rounded-md border border-input bg-background px-3 py-1 text-xs text-foreground outline-none focus-visible:border-ring focus-visible:ring-2 focus-visible:ring-ring font-mono"
                      />
                    </div>
                  </div>

                  {/* Recalculate button */}
                  {scanResult && (
                    <Button
                      type="button"
                      size="sm"
                      onClick={handleRecalculateBudget}
                      disabled={isAnalyzingDefender}
                      className="w-full text-xs font-medium"
                    >
                      {isAnalyzingDefender ? (
                        <>
                          <Loader2 className="mr-1.5 size-3.5 animate-spin" /> Recalculating Priorities…
                        </>
                      ) : (
                        <>
                          <Sliders className="mr-1.5 size-3.5" /> Re-Prioritize with Updated Budget
                        </>
                      )}
                    </Button>
                  )}

                  {/* Empty state when no scan has completed */}
                  {!scanResult && (
                    <div className="rounded-lg border border-dashed p-6 text-center text-xs text-muted-foreground space-y-2">
                      <Workflow className="size-8 mx-auto text-muted-foreground/50" />
                      <p className="font-semibold text-foreground">Waiting for Attacker Scan Findings</p>
                      <p className="text-[11px] max-w-xs mx-auto">
                        Initiate a scan against your authorized website on the left. The Defender Agent will immediately ingest the empirical findings and formulate an actionable plan.
                      </p>
                    </div>
                  )}

                  {/* Summary Metric Cards when plan is active */}
                  {defenderPlan && (
                    <div className="space-y-3 pt-1 animate-in fade-in">
                      <div className="grid grid-cols-2 gap-2 text-xs">
                        <div className="rounded-lg border bg-muted/20 p-2.5 space-y-0.5">
                          <span className="text-[10px] text-muted-foreground block">Proposed Spending</span>
                          <span className="font-mono text-sm font-bold text-foreground">
                            ${defenderPlan.proposed_spending.toLocaleString()} / ${defenderPlan.available_budget.toLocaleString()}
                          </span>
                        </div>

                        <div
                          className={`rounded-lg border p-2.5 space-y-0.5 ${
                            defenderPlan.budget_shortfall > 0
                              ? "border-rose-500/40 bg-rose-500/10 text-rose-400"
                              : "border-emerald-500/30 bg-emerald-500/5 text-emerald-400"
                          }`}
                        >
                          <span className="text-[10px] block">
                            {defenderPlan.budget_shortfall > 0 ? "Budget Shortfall" : "Remaining Budget"}
                          </span>
                          <span className="font-mono text-sm font-bold">
                            {defenderPlan.budget_shortfall > 0
                              ? `-$${defenderPlan.budget_shortfall.toLocaleString()}`
                              : `+$${defenderPlan.remaining_budget.toLocaleString()}`}
                          </span>
                        </div>
                      </div>

                      {/* Risk Drop Card */}
                      <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/5 p-3 flex items-center justify-between">
                        <div>
                          <span className="text-[10px] text-muted-foreground uppercase tracking-wider block font-semibold">
                            Projected Risk Reduction
                          </span>
                          <span className="text-lg font-bold font-mono text-emerald-400">
                            {defenderPlan.baseline_risk_score} &rarr; {defenderPlan.projected_residual_risk}{" "}
                            <span className="text-xs font-normal">(-{defenderPlan.total_risk_reduction_percent}%)</span>
                          </span>
                        </div>
                        <div className="text-right">
                          <span className="text-[10px] text-muted-foreground block">Cost Efficiency</span>
                          <span className="text-xs font-mono font-bold text-foreground">
                            {defenderPlan.risk_reduction_per_dollar} pts / $1k
                          </span>
                        </div>
                      </div>

                      {/* Unbudgeted High-Risk Alert Callout */}
                      {defenderPlan.unbudgeted_high_risk_findings.length > 0 && (
                        <div className="rounded-lg border border-rose-500/40 bg-rose-500/10 p-3 text-xs text-rose-300 space-y-1.5 animate-in fade-in">
                          <div className="flex items-center gap-1.5 font-bold text-rose-400">
                            <AlertTriangle className="size-4 shrink-0" />
                            <span>Unbudgeted High-Risk Exposures Detected!</span>
                          </div>
                          <p className="text-[11px] leading-relaxed">
                            {defenderPlan.unbudgeted_high_risk_findings.length} critical/high issue(s) cannot be fully resolved within your ${defenderPlan.available_budget.toLocaleString()} budget. An additional <strong>${defenderPlan.budget_shortfall.toLocaleString()}</strong> is required to fund complete perimeter hardening.
                          </p>
                        </div>
                      )}
                    </div>
                  )}
                </CardContent>
              </Card>
            </div>

            {/* ======================================================== */}
            {/* FINDINGS & PRIORITIZED REMEDIATION TABS SECTION          */}
            {/* ======================================================== */}
            {scanResult && (
              <div className="space-y-6 pt-2 animate-in fade-in slide-in-from-bottom-2 duration-300">
                {/* Result Section Navigation Tabs */}
                <div className="flex items-center justify-between border-b pb-3 flex-wrap gap-2">
                  <div className="flex items-center gap-2">
                    <button
                      type="button"
                      onClick={() => setResultsTab("findings")}
                      className={`flex items-center gap-2 rounded-md px-3.5 py-1.5 text-xs font-semibold transition-all ${
                        resultsTab === "findings"
                          ? "bg-primary text-primary-foreground shadow"
                          : "bg-muted/40 text-muted-foreground hover:text-foreground"
                      }`}
                    >
                      <FileText className="size-3.5" />
                      Perimeter Findings ({scanResult.findings.length})
                    </button>
                    <button
                      type="button"
                      onClick={() => setResultsTab("pages")}
                      className={`flex items-center gap-2 rounded-md px-3.5 py-1.5 text-xs font-semibold transition-all ${
                        resultsTab === "pages"
                          ? "bg-destructive text-destructive-foreground shadow"
                          : "bg-muted/40 text-muted-foreground hover:text-foreground"
                      }`}
                    >
                      <Globe className="size-3.5" />
                      Discovered Pages & Form Inventory ({discoveredPagesList.length || scanResult.discovered_pages?.length || 0})
                    </button>
                  </div>
                  <span className="text-xs font-mono text-muted-foreground">
                    Scan ID: <span className="text-foreground">{scanResult.scan_id.slice(0, 8)}…</span>
                  </span>
                </div>

                {resultsTab === "findings" && (
                  <div className="space-y-6">
                {/* Findings Breakdown Bar */}
                <Card className="border-border bg-card">
                  <CardHeader className="pb-3">
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                      <div>
                        <CardTitle className="text-base text-foreground flex items-center gap-2">
                          <FileText className="size-4 text-primary" />
                          Target Perimeter Findings: {scanResult.normalized_url}
                        </CardTitle>
                        <CardDescription className="text-xs text-muted-foreground pt-0.5">
                          Scanned at {new Date(scanResult.scanned_at).toLocaleString()} · Resolved IP: {scanResult.target_ip || "Public Gateway"}
                        </CardDescription>
                      </div>

                      {/* Severity Counters & Filter */}
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
                          All ({scanResult.summary.total_findings})
                        </button>
                        {scanResult.summary.critical_count > 0 && (
                          <button
                            type="button"
                            onClick={() => setSeverityFilter("Critical")}
                            className={`rounded px-2.5 py-1 font-mono text-[11px] ${
                              severityFilter === "Critical"
                                ? "bg-rose-500 text-white font-bold"
                                : "bg-rose-500/15 text-rose-400 hover:bg-rose-500/25"
                            }`}
                          >
                            Critical ({scanResult.summary.critical_count})
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
                          High ({scanResult.summary.high_count})
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
                          Medium ({scanResult.summary.medium_count})
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
                          Low ({scanResult.summary.low_count})
                        </button>
                      </div>
                    </div>
                  </CardHeader>

                  <CardContent className="space-y-4">
                    {/* Zero Findings Honesty Disclaimer */}
                    {scanResult.zero_findings_disclaimer && (
                      <div className="rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 text-xs text-amber-300 space-y-1">
                        <p className="font-semibold text-amber-400 flex items-center gap-1.5">
                          <Info className="size-4" /> Honest Assessment Notice
                        </p>
                        <p className="leading-relaxed">{scanResult.zero_findings_disclaimer}</p>
                      </div>
                    )}

                    {/* Findings List */}
                    <div className="space-y-3">
                      {filteredFindings.map((finding) => {
                        const isExpanded = !!expandedEvidence[finding.id]
                        return (
                          <div
                            key={finding.id}
                            className="rounded-lg border bg-muted/15 p-3.5 space-y-2.5 text-xs transition-colors hover:bg-muted/25"
                          >
                            {/* Header row */}
                            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                              <div className="flex flex-wrap items-center gap-2">
                                <span className={`rounded-full border px-2 py-0.5 font-mono text-[10px] font-bold ${getSeverityBadgeClass(finding.severity)}`}>
                                  {finding.severity}
                                </span>
                                <span className="font-semibold text-foreground text-sm">{finding.title}</span>
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

                              <div className="flex items-center gap-2">
                                <span className="text-[10px] text-muted-foreground font-mono">
                                  {finding.validation_status}
                                </span>
                                <span className={`rounded-full border px-2 py-0.5 text-[10px] font-semibold font-mono ${getStatusBadgeClass(finding.remediation_status)}`}>
                                  {finding.remediation_status}
                                </span>
                              </div>
                            </div>

                            {/* Impact & Remediation summary */}
                            <div className="space-y-1 text-muted-foreground">
                              <p className="leading-relaxed">
                                <strong className="text-foreground">Impact:</strong> {finding.potential_impact}
                              </p>
                              <p className="leading-relaxed">
                                <strong className="text-foreground">Action:</strong> {finding.remediation}
                              </p>
                            </div>

                            {/* Expandable Evidence Snippet */}
                            <div className="pt-1 flex items-center justify-between text-[11px]">
                              <button
                                type="button"
                                onClick={() => toggleEvidence(finding.id)}
                                className="text-primary hover:underline font-mono flex items-center gap-1"
                              >
                                <Terminal className="size-3" />
                                {isExpanded ? "Hide Wire Evidence" : "View Observed Scanner Evidence"}
                              </button>

                              {finding.references && finding.references.length > 0 && (
                                <a
                                  href={finding.references[0]}
                                  target="_blank"
                                  rel="noopener noreferrer"
                                  className="text-muted-foreground hover:text-foreground flex items-center gap-1"
                                >
                                  OWASP Guidance <ExternalLink className="size-3" />
                                </a>
                              )}
                            </div>

                            {isExpanded && (
                              <div className="rounded-md bg-background/80 border p-2.5 font-mono text-[11px] space-y-1 text-foreground/90 overflow-x-auto">
                                <p className="text-muted-foreground">// Check Type: {finding.evidence.check_type}</p>
                                {finding.evidence.raw_snippet && (
                                  <p className="text-emerald-400">{finding.evidence.raw_snippet}</p>
                                )}
                                {finding.evidence.status_code && (
                                  <p className="text-muted-foreground">HTTP Status: {finding.evidence.status_code}</p>
                                )}
                              </div>
                            )}
                          </div>
                        )
                      })}
                    </div>
                  </CardContent>
                </Card>

                {/* ======================================================== */}
                {/* DEFENDER PRIORITIZATION TIERS & ACTIONABLE PLAYBOOKS     */}
                {/* ======================================================== */}
                {defenderPlan && (
                  <Card className="border-primary/40 bg-card shadow-xl animate-in fade-in slide-in-from-bottom-2 duration-300">
                    <CardHeader className="pb-3">
                      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                        <div>
                          <CardTitle className="text-base text-foreground flex items-center gap-2">
                            <Layers className="size-5 text-primary" />
                            Defender Budget-Aware Prioritization & Remediation Playbooks
                          </CardTitle>
                          <CardDescription className="text-xs text-muted-foreground pt-0.5">
                            Optimized for maximum risk reduction within ${defenderPlan.available_budget.toLocaleString()} budget (Labor Rate: ${defenderPlan.hourly_rate}/hr).
                          </CardDescription>
                        </div>

                        {/* Priority Group Filter Tabs */}
                        <div className="inline-flex rounded-lg border bg-muted/30 p-1 text-xs">
                          <button
                            type="button"
                            onClick={() => setActivePriorityTab("fix_immediately")}
                            className={`rounded-md px-3 py-1 font-medium transition-all ${
                              activePriorityTab === "fix_immediately"
                                ? "bg-rose-500/20 text-rose-300 font-bold border border-rose-500/40"
                                : "text-muted-foreground hover:text-foreground"
                            }`}
                          >
                            Fix Immediately ({defenderPlan.fix_immediately.length})
                          </button>
                          <button
                            type="button"
                            onClick={() => setActivePriorityTab("fix_next")}
                            className={`rounded-md px-3 py-1 font-medium transition-all ${
                              activePriorityTab === "fix_next"
                                ? "bg-primary/20 text-primary font-bold border border-primary/40"
                                : "text-muted-foreground hover:text-foreground"
                            }`}
                          >
                            Fix Next ({defenderPlan.fix_next.length})
                          </button>
                          <button
                            type="button"
                            onClick={() => setActivePriorityTab("defer_or_mitigate")}
                            className={`rounded-md px-3 py-1 font-medium transition-all ${
                              activePriorityTab === "defer_or_mitigate"
                                ? "bg-amber-500/20 text-amber-300 font-bold border border-amber-500/40"
                                : "text-muted-foreground hover:text-foreground"
                            }`}
                          >
                            Defer / Mitigate ({defenderPlan.defer_or_mitigate.length})
                          </button>
                        </div>
                      </div>
                    </CardHeader>

                    <CardContent className="space-y-4">
                      {/* Recommendations in selected tab */}
                      {(() => {
                        let recs: RemediationRecommendation[] = []
                        if (activePriorityTab === "fix_immediately") recs = defenderPlan.fix_immediately
                        else if (activePriorityTab === "fix_next") recs = defenderPlan.fix_next
                        else if (activePriorityTab === "defer_or_mitigate") recs = defenderPlan.defer_or_mitigate
                        else recs = [...defenderPlan.fix_immediately, ...defenderPlan.fix_next, ...defenderPlan.defer_or_mitigate]

                        if (recs.length === 0) {
                          return (
                            <div className="rounded-lg border border-dashed p-6 text-center text-xs text-muted-foreground">
                              No findings categorized under this tier for the current budget.
                            </div>
                          )
                        }

                        return (
                          <div className="space-y-4">
                            {recs.map((item) => (
                              <div
                                key={item.finding_id}
                                className={`rounded-xl border p-4 space-y-3.5 transition-all ${
                                  item.priority_group === "fix_immediately"
                                    ? "border-rose-500/30 bg-rose-500/5"
                                    : item.priority_group === "defer_or_mitigate"
                                    ? "border-amber-500/30 bg-amber-500/5"
                                    : "border-primary/30 bg-primary/5"
                                }`}
                              >
                                {/* Title & Metrics Row */}
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

                                  <div className="flex items-center gap-3 text-xs font-mono">
                                    <span className="text-muted-foreground">
                                      Effort: <strong>{item.estimated_effort_hours}h</strong>
                                    </span>
                                    <span className="text-foreground font-bold">
                                      Cost: ${item.total_cost.toLocaleString()}
                                    </span>
                                    <span className="text-emerald-400 font-bold">
                                      -{item.projected_risk_reduction} pts
                                    </span>
                                  </div>
                                </div>

                                {/* Root Cause & Actionable Fix */}
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
                                  <div className="space-y-1">
                                    <p className="font-semibold text-foreground flex items-center gap-1.5">
                                      <AlertTriangle className="size-3.5 text-amber-400" /> Root Cause
                                    </p>
                                    <p className="text-muted-foreground leading-relaxed">{item.root_cause}</p>
                                  </div>

                                  <div className="space-y-1">
                                    <p className="font-semibold text-foreground flex items-center gap-1.5">
                                      <CheckCircle2 className="size-3.5 text-emerald-400" /> Actionable Fix
                                    </p>
                                    <p className="text-muted-foreground leading-relaxed">{item.actionable_fix}</p>
                                  </div>
                                </div>

                                {/* Step-by-Step Implementation */}
                                <div className="space-y-1.5 rounded-lg border bg-background/60 p-3 text-xs">
                                  <p className="font-semibold text-foreground flex items-center gap-1.5">
                                    <Code2 className="size-3.5 text-primary" /> Step-by-Step Implementation Guide
                                  </p>
                                  <ul className="space-y-1 text-muted-foreground text-[11px] list-disc list-inside">
                                    {item.implementation_steps.map((step, idx) => (
                                      <li key={idx} className="leading-relaxed">
                                        {step}
                                      </li>
                                    ))}
                                  </ul>
                                </div>

                                {/* Ready-to-use Server Code Snippets */}
                                {item.code_snippets && Object.keys(item.code_snippets).length > 0 && (
                                  <div className="space-y-1.5">
                                    <p className="text-[11px] font-semibold text-muted-foreground uppercase tracking-wider font-mono">
                                      Server Hardening Configuration Snippets
                                    </p>
                                    <div className="grid grid-cols-1 gap-2">
                                      {Object.entries(item.code_snippets).map(([srv, snippet]) => (
                                        <div key={srv} className="rounded-md border bg-black/60 p-2 text-xs font-mono">
                                          <div className="text-[10px] text-primary/80 font-bold mb-1">// {srv}</div>
                                          <pre className="text-[11px] text-emerald-400/90 whitespace-pre-wrap overflow-x-auto">
                                            {snippet}
                                          </pre>
                                        </div>
                                      ))}
                                    </div>
                                  </div>
                                )}

                                {/* Deferral Explanation & Temporary Mitigation */}
                                {item.priority_group === "defer_or_mitigate" && (
                                  <div className="rounded-md border border-amber-500/30 bg-amber-500/10 p-2.5 text-xs text-amber-300 space-y-1">
                                    <p className="font-semibold">Budget Deferral Rationale: {item.deferral_reason}</p>
                                    {item.temporary_mitigation && (
                                      <p className="text-[11px]">
                                        <strong>Interim Compensating Control:</strong> {item.temporary_mitigation}
                                      </p>
                                    )}
                                  </div>
                                )}

                                {/* Verification Command */}
                                <div className="rounded-md border bg-muted/30 p-2.5 text-xs flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                                  <div className="flex items-center gap-2 text-muted-foreground">
                                    <Terminal className="size-3.5 text-primary shrink-0" />
                                    <span className="font-semibold text-foreground text-[11px]">Recommended Verification:</span>
                                    <code className="rounded bg-black/40 px-2 py-0.5 text-[10px] text-emerald-400 font-mono">
                                      {item.verification_procedure}
                                    </code>
                                  </div>

                                  {/* Interactive Remediation Status Selector */}
                                  <div className="flex items-center gap-2">
                                    <label className="text-[11px] text-muted-foreground font-mono">Status:</label>
                                    <select
                                      value={item.status}
                                      onChange={(e) => handleUpdateRemediationStatus(item.finding_id, e.target.value)}
                                      disabled={statusUpdating[item.finding_id]}
                                      className="h-7 rounded border border-input bg-background px-2 text-xs text-foreground outline-none font-mono"
                                    >
                                      <option value="Open">Open</option>
                                      <option value="Planned">Planned</option>
                                      <option value="In Progress">In Progress</option>
                                      <option value="Fixed">Fixed</option>
                                      <option value="Accepted Risk">Accepted Risk</option>
                                      <option value="Verified">Verified</option>
                                    </select>
                                    {statusUpdating[item.finding_id] && (
                                      <Loader2 className="size-3 animate-spin text-primary" />
                                    )}
                                  </div>
                                </div>
                              </div>
                            ))}
                          </div>
                        )
                      })()}
                    </CardContent>
                  </Card>
                )}
                  </div>
                )}

                {/* DISCOVERED PAGES & FORM INVENTORY TAB */}
                {resultsTab === "pages" && (
                  <Card className="border-border bg-card animate-in fade-in">
                    <CardHeader className="pb-3">
                      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                        <div>
                          <CardTitle className="text-base text-foreground flex items-center gap-2">
                            <Globe className="size-4 text-destructive" />
                            Discovered Pages & Browser Navigation Inventory
                          </CardTitle>
                          <CardDescription className="text-xs text-muted-foreground pt-0.5">
                            Playwright rendered internal pages, form action endpoints, query parameters, and browser subresource traffic.
                          </CardDescription>
                        </div>
                        <div className="flex items-center gap-2 text-xs font-mono">
                          <span className="rounded bg-muted px-2.5 py-1 text-foreground font-semibold">
                            Total Discovered: {discoveredPagesList.length || scanResult.discovered_pages?.length || 0}
                          </span>
                        </div>
                      </div>
                    </CardHeader>
                    <CardContent className="space-y-3">
                      {(discoveredPagesList.length === 0 && (!scanResult.discovered_pages || scanResult.discovered_pages.length === 0)) ? (
                        <div className="rounded-lg border border-dashed p-8 text-center text-xs text-muted-foreground space-y-1">
                          <p className="font-semibold text-foreground">No additional internal pages discovered</p>
                          <p>The single-page landing was evaluated. Internal links within scope will appear here after multi-page crawling.</p>
                        </div>
                      ) : (
                        <div className="space-y-3">
                          {(discoveredPagesList.length > 0 ? discoveredPagesList : scanResult.discovered_pages || []).map((pg, idx) => (
                            <div
                              key={idx}
                              className="rounded-lg border bg-muted/15 p-3.5 space-y-2 text-xs transition-colors hover:bg-muted/25"
                            >
                              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                                <div className="flex flex-wrap items-center gap-2">
                                  <span
                                    className={`rounded px-1.5 py-0.5 font-mono text-[10px] font-bold ${
                                      pg.status_code && pg.status_code < 400
                                        ? "bg-emerald-500/15 text-emerald-400 border border-emerald-500/30"
                                        : "bg-rose-500/15 text-rose-400 border border-rose-500/30"
                                    }`}
                                  >
                                    {pg.status_code ? `HTTP ${pg.status_code}` : "Rendered"}
                                  </span>
                                  <span className="font-semibold text-foreground font-mono text-xs break-all">
                                    {pg.url}
                                  </span>
                                </div>
                                <div className="flex items-center gap-2 text-[11px] font-mono text-muted-foreground">
                                  <span>Depth: {pg.depth}</span>
                                  {pg.content_type && (
                                    <span className="rounded bg-muted px-1.5 py-0.5 text-[10px]">
                                      {pg.content_type.split(";")[0]}
                                    </span>
                                  )}
                                </div>
                              </div>

                              {pg.title && (
                                <p className="text-[11px] text-foreground/80 font-medium">
                                  Page Title: <span className="italic font-normal">{pg.title}</span>
                                </p>
                              )}

                              {/* Query parameters */}
                              {pg.query_params && pg.query_params.length > 0 && (
                                <div className="flex flex-wrap items-center gap-1.5 text-[11px]">
                                  <span className="text-muted-foreground font-mono">Query Parameters:</span>
                                  {pg.query_params.map((param: string, pIdx: number) => (
                                    <span
                                      key={pIdx}
                                      className="rounded bg-muted px-1.5 py-0.5 font-mono text-[10px] text-foreground"
                                    >
                                      {param}
                                    </span>
                                  ))}
                                </div>
                              )}

                              {/* Discovered Forms */}
                              {pg.forms && pg.forms.length > 0 && (
                                <div className="rounded border bg-background/50 p-2.5 space-y-1.5">
                                  <p className="text-[11px] font-semibold text-destructive flex items-center gap-1">
                                    <Code2 className="size-3" /> Discovered Forms ({pg.forms.length}) — Observed passively without submission
                                  </p>
                                  <div className="space-y-1">
                                    {pg.forms.map((f: any, fIdx: number) => (
                                      <div
                                        key={fIdx}
                                        className="text-[10px] font-mono flex flex-wrap items-center gap-2 text-muted-foreground"
                                      >
                                        <span className="font-bold text-foreground bg-muted px-1.5 py-0.5 rounded">
                                          {f.method || "GET"}
                                        </span>
                                        <span className="text-primary truncate max-w-sm">
                                          Action: {f.action_url || "(self)"}
                                        </span>
                                        {f.input_names && f.input_names.length > 0 && (
                                          <span className="text-muted-foreground">
                                            Inputs: [{f.input_names.join(", ")}]
                                          </span>
                                        )}
                                      </div>
                                    ))}
                                  </div>
                                </div>
                              )}
                            </div>
                          ))}
                        </div>
                      )}
                    </CardContent>
                  </Card>
                )}
              </div>
            )}
          </div>
        )}

        {/* ======================================================== */}
        {/* MODE 2: SIMULATED SCENARIO DEMO SANDBOX (PRESERVED)      */}
        {/* ======================================================== */}
        {activeMode === "simulation_demo" && (
          <div className="space-y-6 animate-in fade-in duration-300">
            {/* Simulation Disclaimer Banner */}
            <div className="rounded-lg border border-warning/40 bg-warning/10 p-3.5 text-xs text-warning-foreground flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Info className="size-4 text-warning" />
                <span>
                  <strong>Simulated Demonstration Sandbox:</strong> Modeled adversary attack chains and hypothetical controls for offline demo scenarios. This does not perform real network probes.
                </span>
              </div>
              <Button size="sm" variant="outline" onClick={() => setActiveMode("live_assessment")} className="text-xs">
                Switch to Live Scanner
              </Button>
            </div>

            {/* Sandbox Grid: Attacker & Defender Form */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* Card 1: Attacker Agent Sandbox */}
              <Card className="border-destructive/30 bg-card flex flex-col justify-between">
                <CardHeader className="pb-4">
                  <div className="flex items-center gap-2 text-destructive font-semibold text-base">
                    <Sparkles className="size-5" />
                    <span>Attacker Agent Sandbox (Demo)</span>
                  </div>
                  <CardDescription className="text-xs">
                    Configure adversary tactics, exploit vector, and threat actor intensity.
                  </CardDescription>
                </CardHeader>

                <CardContent className="space-y-4">
                  <form onSubmit={handleRunSimulatedAttack} className="space-y-4">
                    <div className="space-y-1.5">
                      <label className="text-xs font-medium text-foreground flex items-center gap-1.5">
                        <Server className="size-3.5 text-destructive" /> Target Asset
                      </label>
                      <select
                        value={selectedAssetId}
                        onChange={(e) => setSelectedAssetId(e.target.value)}
                        disabled={isSimulatingAttack}
                        className="flex h-9 w-full rounded-md border border-input bg-background px-3 py-1 text-xs text-foreground outline-none focus-visible:border-ring focus-visible:ring-2 focus-visible:ring-ring"
                      >
                        {dataset.assets.map((asset) => (
                          <option key={asset.id} value={asset.id}>
                            {asset.name} ({asset.criticality} · {asset.exposure})
                          </option>
                        ))}
                      </select>
                    </div>

                    <div className="space-y-1.5">
                      <label className="text-xs font-medium text-foreground flex items-center gap-1.5">
                        <Flame className="size-3.5 text-destructive" /> Attack Scenario
                      </label>
                      <select
                        value={attackScenario}
                        onChange={(e) => setAttackScenario(e.target.value)}
                        disabled={isSimulatingAttack}
                        className="flex h-9 w-full rounded-md border border-input bg-background px-3 py-1 text-xs text-foreground outline-none focus-visible:border-ring focus-visible:ring-2 focus-visible:ring-ring"
                      >
                        <option value="vulnerability_exploitation">
                          Known Vulnerability Exploitation (Remote Code Execution)
                        </option>
                        <option value="unauthorized_access">
                          Unauthorized Access (Credential Spraying & Session Hijack)
                        </option>
                        <option value="privilege_escalation">
                          Local Privilege Escalation (Token Manipulation / Misconfiguration)
                        </option>
                      </select>
                    </div>

                    <div className="space-y-1.5">
                      <label className="text-xs font-medium text-foreground">Threat Actor Intensity</label>
                      <div className="grid grid-cols-3 gap-2 text-xs">
                        {(["low", "medium", "high"] as const).map((lvl) => (
                          <button
                            key={lvl}
                            type="button"
                            onClick={() => setThreatIntensity(lvl)}
                            disabled={isSimulatingAttack}
                            className={`rounded-md border py-2 capitalize font-medium transition-colors ${
                              threatIntensity === lvl
                                ? "border-destructive bg-destructive/15 text-destructive font-semibold"
                                : "bg-muted/30 text-muted-foreground hover:bg-muted/60"
                            }`}
                          >
                            {lvl}
                          </button>
                        ))}
                      </div>
                    </div>

                    {attackError && (
                      <div className="rounded-md bg-destructive/10 border border-destructive/20 p-2.5 text-xs text-destructive">
                        {attackError}
                      </div>
                    )}

                    <Button
                      type="submit"
                      disabled={isSimulatingAttack}
                      className="w-full bg-destructive text-destructive-foreground hover:bg-destructive/90 text-xs font-medium"
                    >
                      {isSimulatingAttack ? (
                        <>
                          <Loader2 className="mr-2 size-3.5 animate-spin" />
                          Running Attack Simulation…
                        </>
                      ) : (
                        <>
                          <Zap className="mr-1.5 size-3.5" />
                          Run Attack Simulation
                        </>
                      )}
                    </Button>
                  </form>
                </CardContent>
              </Card>

              {/* Card 2: Defender Agent Sandbox */}
              <Card className="border-primary/30 bg-card flex flex-col justify-between">
                <CardHeader className="pb-4">
                  <div className="flex items-center gap-2 text-primary font-semibold text-base">
                    <Workflow className="size-5" />
                    <span>Defender Agent Sandbox (Demo)</span>
                  </div>
                  <CardDescription className="text-xs">
                    Select responsive safeguards to mitigate simulated attack vectors.
                  </CardDescription>
                </CardHeader>

                <CardContent className="space-y-4">
                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <label className="text-xs font-medium text-foreground">Available Defensive Controls</label>
                      {attackResult && (
                        <button
                          type="button"
                          onClick={() => setSelectedControls(["patching", "mfa", "segmentation", "edr"])}
                          className="text-[11px] text-primary hover:underline font-mono"
                        >
                          Auto-Select All
                        </button>
                      )}
                    </div>

                    <div className="space-y-2 text-xs">
                      {[
                        { id: "patching", label: "Security Patch Deployment", desc: "Patch CVE findings on target host" },
                        { id: "mfa", label: "Multi-Factor Authentication", desc: "Enforce MFA across admin & API paths" },
                        { id: "segmentation", label: "Network Micro-Segmentation", desc: "Isolate east-west database pivots" },
                        { id: "edr", label: "EDR Detection & Containment", desc: "Automate memory & process behavior alerts" },
                      ].map((ctrl) => {
                        const isChecked = selectedControls.includes(ctrl.id)
                        return (
                          <label
                            key={ctrl.id}
                            className={`flex items-start gap-2.5 rounded-lg border p-2.5 cursor-pointer transition-colors ${
                              isChecked ? "border-primary/50 bg-primary/5" : "bg-muted/10 hover:bg-muted/30"
                            }`}
                          >
                            <input
                              type="checkbox"
                              checked={isChecked}
                              onChange={() => toggleControl(ctrl.id)}
                              className="mt-0.5 rounded border-input text-primary focus:ring-primary size-4"
                            />
                            <div className="min-w-0 flex-1">
                              <p className="font-semibold text-foreground text-xs">{ctrl.label}</p>
                              <p className="text-[11px] text-muted-foreground">{ctrl.desc}</p>
                            </div>
                          </label>
                        )
                      })}
                    </div>
                  </div>

                  {defenseError && (
                    <div className="rounded-md bg-destructive/10 border border-destructive/20 p-2.5 text-xs text-destructive">
                      {defenseError}
                    </div>
                  )}

                  <Button
                    type="button"
                    onClick={handleRunSimulatedDefense}
                    disabled={!attackResult || isSimulatingDefense}
                    className="w-full text-xs font-medium"
                  >
                    {isSimulatingDefense ? (
                      <>
                        <Loader2 className="mr-2 size-3.5 animate-spin" />
                        Calculating Defensive Mitigation…
                      </>
                    ) : (
                      <>
                        <ShieldCheck className="mr-1.5 size-3.5" />
                        Run Defense Simulation
                      </>
                    )}
                  </Button>
                </CardContent>
              </Card>
            </div>

            {/* Simulated Attacker Outcome Breakdown */}
            {attackResult && (
              <div className="space-y-6 animate-in fade-in slide-in-from-bottom-2 duration-300">
                <Card className="border-destructive/30 bg-card">
                  <CardHeader className="pb-3">
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <ShieldAlert className="size-5 text-destructive" />
                        <CardTitle className="text-base text-foreground">
                          Simulated Attacker Outcome: {attackResult.asset_name}
                        </CardTitle>
                      </div>
                      <span className="text-xs font-mono bg-destructive/10 text-destructive px-2.5 py-1 rounded-full font-semibold">
                        Simulated Risk Escalation: {attackResult.baseline_risk_score} &rarr; {attackResult.simulated_risk_score}/100
                      </span>
                    </div>
                    <CardDescription className="text-xs text-muted-foreground pt-1">
                      {attackResult.potential_business_impact}
                    </CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <h4 className="text-xs font-semibold text-foreground uppercase tracking-wider">
                      Modeled Attack Progression Stages
                    </h4>
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                      {attackResult.stages.map((stg) => (
                        <div key={stg.stage_number} className="rounded-lg border bg-muted/20 p-3 space-y-1.5 text-xs">
                          <div className="flex items-center justify-between font-mono">
                            <span className="text-destructive font-bold">Stage 0{stg.stage_number}</span>
                            <span className="text-[10px] text-muted-foreground">Likelihood: {(stg.success_likelihood * 100).toFixed(0)}%</span>
                          </div>
                          <p className="font-semibold text-foreground">{stg.name}</p>
                          <p className="text-[11px] text-muted-foreground leading-relaxed">{stg.description}</p>
                          <div className="border-t pt-1.5 text-[10px] text-muted-foreground">
                            <span className="text-foreground font-mono">{stg.technique}</span>
                          </div>
                        </div>
                      ))}
                    </div>
                  </CardContent>
                </Card>

                {/* Simulated Defense Results */}
                {defenseResult && (
                  <Card className="border-emerald-500/40 bg-card shadow-lg animate-in fade-in slide-in-from-bottom-2 duration-300">
                    <CardHeader className="pb-3">
                      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                        <div className="flex items-center gap-2 text-emerald-600 dark:text-emerald-400">
                          <ShieldCheck className="size-5" />
                          <CardTitle className="text-base font-bold text-foreground">
                            Defender Countermeasure Evaluation & Residual Risk
                          </CardTitle>
                        </div>
                        <span className="text-xs font-mono bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 px-2.5 py-1 rounded-full font-bold flex items-center gap-1">
                          <TrendingDown className="size-3.5" /> -{defenseResult.percentage_risk_reduction}% Risk Reduction
                        </span>
                      </div>
                    </CardHeader>
                    <CardContent className="space-y-4">
                      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                        <div className="rounded-lg border p-3 bg-muted/20">
                          <span className="text-[10px] text-muted-foreground block">Simulated Peak Exposure</span>
                          <span className="text-xl font-bold font-mono text-destructive">
                            {defenseResult.pre_defense_risk_score} <span className="text-xs text-muted-foreground font-normal">/100</span>
                          </span>
                        </div>

                        <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/5 p-3">
                          <span className="text-[10px] text-muted-foreground block">Residual Risk Score</span>
                          <span className="text-xl font-bold font-mono text-emerald-600 dark:text-emerald-400">
                            {defenseResult.residual_risk_score} <span className="text-xs text-muted-foreground font-normal">/100</span>
                          </span>
                        </div>

                        <div className="rounded-lg border p-3 bg-muted/20">
                          <span className="text-[10px] text-muted-foreground block">Absolute Point Drop</span>
                          <span className="text-xl font-bold font-mono text-foreground">
                            -{defenseResult.absolute_risk_reduction} pts
                          </span>
                        </div>
                      </div>

                      {/* Applied Safeguards */}
                      <div className="space-y-2 pt-2 border-t">
                        <h4 className="text-xs font-semibold text-foreground uppercase tracking-wider">
                          Applied Safeguard Impact
                        </h4>
                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs">
                          {defenseResult.applied_controls.map((ctrl) => (
                            <div key={ctrl.control_id} className="rounded-md border p-2.5 bg-muted/20 space-y-1">
                              <div className="flex items-center justify-between">
                                <span className="font-semibold text-foreground flex items-center gap-1.5">
                                  <CheckCircle2 className="size-3.5 text-emerald-500" />
                                  {ctrl.control_name}
                                </span>
                                <span className="font-mono text-emerald-600 dark:text-emerald-400 font-bold">
                                  -{ctrl.points_reduced} pts
                                </span>
                              </div>
                              <p className="text-[11px] text-muted-foreground">{ctrl.mitigation_reason}</p>
                            </div>
                          ))}
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                )}
              </div>
            )}
          </div>
        )}

        {/* Footer Navigation Bar */}
        <div className="flex flex-wrap items-center justify-between gap-4 rounded-lg border bg-card p-4">
          <div className="space-y-0.5">
            <p className="text-sm font-medium text-foreground">Need broader organizational quantification?</p>
            <p className="text-xs text-muted-foreground">Run a complete risk assessment questionnaire or inspect asset findings.</p>
          </div>
          <div className="flex gap-2">
            <Button variant="outline" size="sm" onClick={() => navigate("landing")}>
              Home
            </Button>
            <Button size="sm" onClick={() => navigate("risk-assessment")}>
              Cyber Risk Analysis
            </Button>
          </div>
        </div>
      </div>
    </div>
  )
}
