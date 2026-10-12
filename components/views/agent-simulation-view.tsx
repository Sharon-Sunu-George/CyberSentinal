"use client"

import { useState } from "react"
import {
  ArrowLeft,
  ArrowRight,
  Bot,
  CheckCircle2,
  Flame,
  Info,
  Loader2,
  RotateCcw,
  Server,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  TrendingDown,
  Workflow,
  Zap,
} from "lucide-react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { useAppState } from "@/components/app/app-state"
import { apiClient } from "@/lib/api-client"

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

  // Form State
  const [selectedAssetId, setSelectedAssetId] = useState(dataset.assets[0]?.id || "a-pay-prod")
  const [attackScenario, setAttackScenario] = useState("vulnerability_exploitation")
  const [threatIntensity, setThreatIntensity] = useState("medium")

  // Attacker Agent State
  const [isSimulatingAttack, setIsSimulatingAttack] = useState(false)
  const [attackResult, setAttackResult] = useState<AttackSimulationResult | null>(null)
  const [attackError, setAttackError] = useState<string | null>(null)

  // Defender Agent State
  const [selectedControls, setSelectedControls] = useState<string[]>([])
  const [isSimulatingDefense, setIsSimulatingDefense] = useState(false)
  const [defenseResult, setDefenseResult] = useState<DefenseSimulationResult | null>(null)
  const [defenseError, setDefenseError] = useState<string | null>(null)

  // Helper to calculate fallback if FastAPI backend is offline during demo
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

  // Handle Attacker Simulation
  const handleRunAttack = async (e: React.FormEvent) => {
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

  // Handle Defender Simulation
  const handleRunDefense = async () => {
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

  const handleReset = () => {
    setAttackResult(null)
    setDefenseResult(null)
    setSelectedControls([])
    setAttackError(null)
    setDefenseError(null)
  }

  return (
    <div className="flex min-h-svh w-full flex-col items-center justify-start p-4 md:p-8">
      <div className="w-full max-w-5xl space-y-6">
        {/* Top bar with Back button */}
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
            <span className="text-xs font-semibold text-foreground">CyberSentinel AI</span>
            <span className="text-xs text-muted-foreground">· AI Agent Simulation Engine</span>
          </div>

          <Button
            type="button"
            variant="outline"
            size="sm"
            onClick={handleReset}
            className="text-xs flex items-center gap-1.5"
            title="Reset Simulation"
          >
            <RotateCcw className="size-3.5" />
            New Simulation
          </Button>
        </div>

        {/* Intro Card */}
        <Card className="border-primary/30 bg-primary/5">
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2.5 text-primary">
                <Bot className="size-6" />
                <CardTitle className="text-lg">AI Attacker & Defender Agent Simulation</CardTitle>
              </div>
              <span className="inline-flex items-center gap-1.5 rounded-full bg-primary/15 px-3 py-1 text-xs font-semibold text-primary font-mono">
                <Zap className="size-3.5" /> Live Rule-Based Sandbox
              </span>
            </div>
            <CardDescription className="text-xs text-foreground/80 mt-1 leading-relaxed">
              Model deterministic adversary attack paths against your monitored digital perimeter, evaluate simulated compromise stages, and test automated defender safeguards to quantify residual risk.
            </CardDescription>
          </CardHeader>
        </Card>

        {/* Sandbox Grid: Attacker & Defender Form */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Card 1: Attacker Agent Sandbox */}
          <Card className="border-destructive/30 bg-card flex flex-col justify-between">
            <CardHeader className="pb-4">
              <div className="flex items-center gap-2 text-destructive font-semibold text-base">
                <Sparkles className="size-5" />
                <span>Attacker Agent Sandbox</span>
              </div>
              <CardDescription className="text-xs">
                Configure adversary tactics, exploit vector, and threat actor intensity.
              </CardDescription>
            </CardHeader>

            <CardContent className="space-y-4">
              <form onSubmit={handleRunAttack} className="space-y-4">
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
                <span>Defender Agent Sandbox</span>
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
                onClick={handleRunDefense}
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

        {/* Section: Attacker Results Breakdown */}
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

                <div className="flex flex-wrap items-center gap-2 pt-2 border-t text-xs">
                  <span className="text-muted-foreground">Affected Adjacent Perimeter Assets:</span>
                  {attackResult.affected_assets.map((ast, idx) => (
                    <span key={idx} className="rounded bg-muted px-2 py-0.5 font-mono text-[11px] text-foreground">
                      {ast}
                    </span>
                  ))}
                </div>
              </CardContent>
            </Card>

            {/* Section: Defense Results Comparison */}
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
                  {/* Before / After Risk Score Visual Bar */}
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

                  {/* Applied Safeguard Breakdown */}
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

                  {/* Remaining Weaknesses & Next Recommendation */}
                  <div className="rounded-lg border bg-muted/30 p-3 space-y-2 text-xs">
                    <div className="flex items-start gap-2">
                      <Info className="size-4 text-primary shrink-0 mt-0.5" />
                      <div className="space-y-1">
                        <p className="font-semibold text-foreground">Recommended Next Action</p>
                        <p className="text-muted-foreground leading-relaxed">{defenseResult.recommended_next_action}</p>
                      </div>
                    </div>
                  </div>

                  <div className="pt-2 flex flex-wrap gap-3">
                    <Button size="sm" onClick={() => navigate("overview")}>
                      View in Executive Dashboard
                      <ArrowRight className="size-3.5 ml-1.5" />
                    </Button>
                    <Button variant="outline" size="sm" onClick={() => navigate("investments")}>
                      Open Investment Optimizer
                    </Button>
                  </div>
                </CardContent>
              </Card>
            )}
          </div>
        )}

        {/* Footer Navigation bar */}
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
