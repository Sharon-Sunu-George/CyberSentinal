"use client"

import { useEffect, useState } from "react"
import {
  AlertTriangle,
  Bot,
  CheckCircle2,
  Clock,
  DollarSign,
  Info,
  Loader2,
  Play,
  RefreshCw,
  Settings,
  Shield,
  Zap,
} from "lucide-react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { useAppState } from "@/components/app/app-state"
import { CURRENCY_CONFIGS, RATES_LAST_UPDATED } from "@/lib/format"
import type { CurrencyCode } from "@/lib/types"
import { apiClient } from "@/lib/api-client"

interface AIStatus {
  provider_name: string
  is_configured: boolean
  status: string
  model_type: string
  mode: string
  details: string
}

export function SettingsView() {
  const {
    reset,
    simulateThreat,
    scenariosRemaining,
    isAssessing,
    autoRefreshEnabled,
    nextAssessmentSeconds,
    toggleAutoRefresh,
    runAssessment,
    dataset,
    currency,
    setCurrency,
  } = useAppState()

  const [confirmResetOpen, setConfirmResetOpen] = useState(false)
  const [isResetting, setIsResetting] = useState(false)
  const [resetSuccess, setResetSuccess] = useState(false)
  const [isTriggeringScenario, setIsTriggeringScenario] = useState(false)
  const [scenarioSuccessMessage, setScenarioSuccessMessage] = useState<string | null>(null)

  const [aiStatus, setAiStatus] = useState<AIStatus>({
    provider_name: "CyberSentinel Expert AI Engine",
    is_configured: false,
    status: "Active (Deterministic Rule-Based Sandbox)",
    model_type: "FAIR Risk & MITRE ATT&CK Model",
    mode: "Rule-based fallback sandbox",
    details:
      "Operating in transparent, deterministic expert sandbox mode. All risk formulas follow FAIR and MITRE ATT&CK standards.",
  })

  // Fetch AI status from backend
  useEffect(() => {
    apiClient
      .getAiStatus()
      .then((data: AIStatus) => setAiStatus(data))
      .catch(() => {
        // Keeps local fallback status
      })
  }, [])

  // Handle Threat Simulation
  const handleRunThreatSimulation = async () => {
    if (isAssessing || isTriggeringScenario || scenariosRemaining <= 0) return
    setIsTriggeringScenario(true)
    setScenarioSuccessMessage(null)

    try {
      // Notify backend endpoint
      await apiClient.runScenario().catch(() => {})

      // Trigger state change
      simulateThreat()
      setScenarioSuccessMessage("Threat scenario injected successfully. Risk assessment recalculated.")
      setTimeout(() => setScenarioSuccessMessage(null), 4000)
    } finally {
      setIsTriggeringScenario(false)
    }
  };

  // Handle Confirmed Reset
  const handleConfirmReset = async () => {
    setIsResetting(true)
    try {
      await apiClient.resetDataset().catch(() => {})

      reset()
      setResetSuccess(true)
      setConfirmResetOpen(false)
      setTimeout(() => setResetSuccess(false), 3000)
    } finally {
      setIsResetting(false)
    }
  }

  return (
    <div className="flex flex-col gap-6">
      <Card className="border-border">
        <CardHeader>
          <div className="flex items-center gap-2 text-foreground">
            <Settings className="size-5 text-primary" />
            <CardTitle>System & Simulation Settings</CardTitle>
          </div>
          <CardDescription>
            Configure background risk assessment routines, threat scenario simulations, and AI engine status.
          </CardDescription>
        </CardHeader>

        <CardContent className="space-y-6">
          {/* Section 1: AI Provider Status */}
          <div className="rounded-lg border bg-card p-4 space-y-3">
            <div className="flex items-center justify-between">
              <h4 className="font-semibold text-sm flex items-center gap-2 text-foreground">
                <Bot className="size-4 text-primary" /> AI Engine & Provider Status
              </h4>
              <span className="inline-flex items-center gap-1.5 rounded-full bg-primary/10 px-2.5 py-0.5 text-xs font-medium text-primary font-mono">
                <Shield className="size-3" /> {aiStatus.mode}
              </span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
              <div className="rounded-md border p-2.5 bg-muted/20">
                <span className="text-muted-foreground block text-[11px]">Active Engine</span>
                <span className="font-semibold text-foreground">{aiStatus.provider_name}</span>
              </div>
              <div className="rounded-md border p-2.5 bg-muted/20">
                <span className="text-muted-foreground block text-[11px]">Evaluation Model</span>
                <span className="font-semibold text-foreground">{aiStatus.model_type}</span>
              </div>
            </div>

            <div className="flex items-start gap-2 rounded-md bg-muted/30 p-2.5 text-xs text-muted-foreground">
              <Info className="size-4 text-primary shrink-0 mt-0.5" />
              <p className="leading-relaxed">
                {aiStatus.details} No external API keys are exposed.
              </p>
            </div>
          </div>

          {/* Section: Display Currency Preference */}
          <div className="rounded-lg border bg-card p-4 space-y-3">
            <div className="flex items-center justify-between">
              <h4 className="font-semibold text-sm flex items-center gap-2 text-foreground">
                <DollarSign className="size-4 text-primary" /> Display Currency Preference
              </h4>
              <span className="font-mono text-xs text-muted-foreground">
                Active: <strong className="text-primary font-bold">{currency} ({CURRENCY_CONFIGS[currency]?.symbol})</strong>
              </span>
            </div>
            <p className="text-xs text-muted-foreground leading-relaxed">
              Select your organization&apos;s reporting currency. Financial loss exposure (SLE, ALE), risk reduction, and investment budget recommendations convert dynamically for display while preserving the native FAIR model calculation base.
            </p>

            <div className="grid grid-cols-1 sm:grid-cols-4 gap-2.5 pt-1">
              {(Object.keys(CURRENCY_CONFIGS) as CurrencyCode[]).map((code) => {
                const cfg = CURRENCY_CONFIGS[code]
                const isSelected = currency === code
                return (
                  <button
                    key={code}
                    type="button"
                    onClick={() => setCurrency(code)}
                    className={`flex flex-col items-start justify-between rounded-lg border p-3 text-left transition-all ${
                      isSelected
                        ? "border-primary bg-primary/10 shadow-sm ring-1 ring-primary/40"
                        : "border-border/80 bg-muted/20 hover:border-border hover:bg-muted/40"
                    }`}
                  >
                    <div className="flex w-full items-center justify-between">
                      <span className="font-mono text-base font-bold text-foreground">
                        {cfg.symbol} {cfg.code}
                      </span>
                      {isSelected && <CheckCircle2 className="size-4 text-primary" />}
                    </div>
                    <span className="text-xs font-medium text-foreground mt-1">{cfg.name}</span>
                    <span className="text-[10px] text-muted-foreground mt-0.5 font-mono">
                      {cfg.rateFromUSD === 1.0 ? "Base (1.00)" : `1 USD = ${cfg.symbol}${cfg.rateFromUSD.toFixed(2)}`}
                    </span>
                  </button>
                )
              })}
            </div>

            <div className="flex items-start gap-2 rounded-md bg-muted/30 p-2.5 text-xs text-muted-foreground mt-2">
              <Info className="size-4 text-primary shrink-0 mt-0.5" />
              <p className="leading-relaxed">
                Benchmark source: <strong className="text-foreground">{RATES_LAST_UPDATED}</strong>. Changing the display currency affects monetary presentation only; percentage reductions, risk scores, and underlying calculations remain constant.
              </p>
            </div>
          </div>

          {/* Section 2: Telemetry Simulation Feed & Background Signals */}
          <div className="rounded-lg border bg-card p-4 space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
              <div>
                <h4 className="font-semibold text-sm flex items-center gap-2 text-foreground">
                  <Clock className="size-4 text-primary" /> Simulated Telemetry Feed & Background Signals
                </h4>
                <p className="text-xs text-muted-foreground mt-0.5">
                  Controls periodic baseline telemetry simulations and threat signals on the demo estate. Does not trigger live security scans.
                </p>
              </div>

              <div className="flex items-center gap-2">
                <span className="text-xs font-mono text-muted-foreground">
                  {autoRefreshEnabled ? "Simulation Feed: Active" : "Simulation Feed: Paused"}
                </span>
                <Button
                  variant={autoRefreshEnabled ? "outline" : "default"}
                  size="sm"
                  onClick={toggleAutoRefresh}
                  className="text-xs"
                >
                  {autoRefreshEnabled ? "Pause Simulation Feed" : "Resume Simulation Feed"}
                </Button>
              </div>
            </div>

            <div className="flex items-center justify-between border-t pt-3">
              <span className="text-xs text-muted-foreground">
                Trigger an immediate recalculation using the authoritative risk model.
              </span>
              <Button
                variant="outline"
                size="sm"
                onClick={runAssessment}
                disabled={isAssessing}
                className="text-xs flex items-center gap-1.5"
              >
                {isAssessing ? <Loader2 className="size-3.5 animate-spin" /> : <Play className="size-3.5" />}
                Run Assessment Now
              </Button>
            </div>
          </div>

          {/* Section 3: Threat Scenario Simulation */}
          <div className="rounded-lg border bg-card p-4 space-y-3">
            <div className="flex items-center justify-between">
              <h4 className="font-semibold text-sm flex items-center gap-2 text-foreground">
                <Zap className="size-4 text-warning" /> Simulated Threat Incident Injection
              </h4>
              <span className="text-xs font-mono text-muted-foreground">
                {scenariosRemaining} scenario(s) remaining in cycle
              </span>
            </div>

            <p className="text-xs text-muted-foreground leading-relaxed">
              Inject the next configured adversarial scenario into the current demo estate ({dataset.assets.length} monitored assets). This tests real-time alert dispatching and risk escalation without mutating production systems.
            </p>

            {scenarioSuccessMessage && (
              <div className="flex items-center gap-2 rounded-md bg-success/10 border border-success/30 p-2.5 text-xs text-success">
                <CheckCircle2 className="size-4" />
                {scenarioSuccessMessage}
              </div>
            )}

            <Button
              onClick={handleRunThreatSimulation}
              disabled={isAssessing || isTriggeringScenario || scenariosRemaining <= 0}
              size="sm"
              className="text-xs flex items-center gap-1.5"
            >
              {isTriggeringScenario ? (
                <>
                  <Loader2 className="size-3.5 animate-spin" />
                  Injecting Scenario…
                </>
              ) : (
                <>
                  <Zap className="size-3.5" />
                  Run Threat Simulation
                </>
              )}
            </Button>
          </div>

          {/* Section 4: Reset Demo Dataset */}
          <div className="rounded-lg border border-destructive/30 bg-destructive/5 p-4 space-y-3">
            <div className="flex items-center justify-between">
              <h4 className="font-semibold text-sm flex items-center gap-2 text-destructive">
                <RefreshCw className="size-4" /> Reset Demo Dataset
              </h4>
              {resetSuccess && (
                <span className="flex items-center gap-1 text-xs text-success font-medium">
                  <CheckCircle2 className="size-3.5" /> Reset Complete
                </span>
              )}
            </div>

            <p className="text-xs text-muted-foreground leading-relaxed">
              Restore all 12 assets, vulnerabilities, control statuses, and simulation logs to baseline initial state.
            </p>

            {confirmResetOpen ? (
              <div className="rounded-md border border-destructive/40 bg-background p-3 space-y-2">
                <div className="flex items-center gap-2 text-xs font-semibold text-destructive">
                  <AlertTriangle className="size-4" />
                  Confirm Dataset Reset?
                </div>
                <p className="text-[11px] text-muted-foreground">
                  This action will clear custom threat simulation history and revert all assets to baseline.
                </p>
                <div className="flex gap-2 pt-1">
                  <Button
                    variant="destructive"
                    size="sm"
                    onClick={handleConfirmReset}
                    disabled={isResetting}
                    className="text-xs"
                  >
                    {isResetting ? <Loader2 className="size-3 animate-spin mr-1" /> : null}
                    Yes, Reset Dataset
                  </Button>
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => setConfirmResetOpen(false)}
                    disabled={isResetting}
                    className="text-xs"
                  >
                    Cancel
                  </Button>
                </div>
              </div>
            ) : (
              <Button
                variant="outline"
                size="sm"
                onClick={() => setConfirmResetOpen(true)}
                className="text-destructive border-destructive/30 hover:bg-destructive/10 text-xs"
              >
                Reset Demo Dataset
              </Button>
            )}
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
