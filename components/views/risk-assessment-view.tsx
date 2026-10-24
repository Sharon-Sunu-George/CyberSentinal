"use client"

import { useState } from "react"
import {
  ArrowLeft,
  ArrowRight,
  BrainCircuit,
  Building2,
  CheckCircle2,
  CircleHelp,
  Database,
  ExternalLink,
  Flame,
  Globe,
  HelpCircle,
  Info,
  Loader2,
  Lock,
  RotateCcw,
  Server,
  Settings,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Zap,
} from "lucide-react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Textarea } from "@/components/ui/textarea"
import { Badge } from "@/components/ui/badge"
import { useAppState } from "@/components/app/app-state"
import { apiClient } from "@/lib/api-client"
import { formatCurrency, formatINR } from "@/lib/format"

// Types
export interface SecurityControlConfig {
  id: "mfa" | "edr" | "patching" | "segmentation" | "backup"
  name: string
  label: string
  description: string
  riskImpactNote: string
}

export const SECURITY_CONTROLS_META: SecurityControlConfig[] = [
  {
    id: "mfa",
    name: "Multi-Factor Authentication (MFA)",
    label: "Enforced MFA",
    description: "Requires hardware keys, authenticator apps, or push tokens across privileged and user accounts.",
    riskImpactNote: "Absence allows single credential compromise to yield direct unauthorized access.",
  },
  {
    id: "edr",
    name: "Endpoint Detection & Response (EDR)",
    label: "Active EDR / XDR",
    description: "Continuous behavioral telemetry, memory exploit detection, and automated host isolation.",
    riskImpactNote: "Absence increases adversary dwell time and lateral movement likelihood.",
  },
  {
    id: "patching",
    name: "Automated Vulnerability Patching",
    label: "Automated Patching",
    description: "SLA-driven patch cycles (<14 days for critical CVEs) across OS, libraries, and containers.",
    riskImpactNote: "Absence leaves known publicly exploitable vulnerabilities unmitigated.",
  },
  {
    id: "segmentation",
    name: "Micro-Segmentation & Zero-Trust Network",
    label: "Network Segmentation",
    description: "Strict ACLs, firewall boundaries, and isolation between public dmz, apps, and sensitive data stores.",
    riskImpactNote: "Absence allows an edge breach to immediately reach internal database assets.",
  },
  {
    id: "backup",
    name: "Isolated & Immutable Backups",
    label: "Immutable Backups",
    description: "Air-gapped, WORM-protected backups with verified offline recovery procedures.",
    riskImpactNote: "Absence exposes the organization to catastrophic unrecoverable ransomware extortion.",
  },
]

export interface WizardAssessmentData {
  // Step 1: Organisation profile
  org_name: string
  industry_type: string
  org_description: string
  main_business_asset: string

  // Step 2: Critical asset profile
  asset_name: string
  asset_type: string
  business_criticality: "Low" | "Medium" | "High" | "Critical"
  asset_value: number
  internet_exposure: "Internet-facing" | "Internally accessible" | "Isolated / Air-gapped"
  // Adaptive Step 2 questions
  public_fqdn_or_endpoint: string
  has_api_or_third_party_gateway: boolean
  data_sensitivity: "Public" | "Internal" | "Confidential / PII" | "Restricted Financial"

  // Step 3: Security posture
  has_known_vulnerabilities: boolean
  known_vulnerabilities_details: string
  scanner_finding_severity: "None" | "Low" | "Medium" | "High" | "Critical"
  security_controls: {
    mfa: boolean
    edr: boolean
    patching: boolean
    segmentation: boolean
    backup: boolean
  }
  recent_incident_history: "None in past 24m" | "Minor probe / thwarted" | "Active incident or breach within 12m"

  // Step 4: Threat & Financial Impact (FAIR parameters)
  threat_event_frequency: number
  tef_is_estimated: boolean
  vulnerability_probability: number
  vuln_is_estimated: boolean
  direct_loss: number
  direct_loss_is_estimated: boolean
  indirect_loss: number
  indirect_loss_is_estimated: boolean
  proposed_security_cost: number
  mitigated_vulnerability_probability: number
}

const DEFAULT_WIZARD_DATA: WizardAssessmentData = {
  org_name: "FinSecure Technologies",
  industry_type: "Financial Services / FinTech",
  org_description: "Cloud-native payments processing platform serving 1.2M cardholders.",
  main_business_asset: "Customer Core Banking & PII Database",

  asset_name: "Customer Core Banking & PII Database",
  asset_type: "Database / Data Store",
  business_criticality: "Critical",
  asset_value: 5000000,
  internet_exposure: "Internet-facing",
  public_fqdn_or_endpoint: "api.finsecure.internal.domain/v2",
  has_api_or_third_party_gateway: true,
  data_sensitivity: "Restricted Financial",

  has_known_vulnerabilities: true,
  known_vulnerabilities_details: "Legacy auth endpoint, unpatched OpenSSL TLS library",
  scanner_finding_severity: "High",
  security_controls: {
    mfa: true,
    edr: false,
    patching: false,
    segmentation: true,
    backup: true,
  },
  recent_incident_history: "Minor probe / thwarted",

  threat_event_frequency: 2.0,
  tef_is_estimated: false,
  vulnerability_probability: 0.35,
  vuln_is_estimated: false,
  direct_loss: 150000,
  direct_loss_is_estimated: false,
  indirect_loss: 300000,
  indirect_loss_is_estimated: false,
  proposed_security_cost: 50000,
  mitigated_vulnerability_probability: 0.1,
}

// Preset options for streamlined selection
const INDUSTRY_PRESETS = [
  "Financial Services / FinTech",
  "Healthcare & Life Sciences",
  "E-Commerce & Retail",
  "Critical Infrastructure & Energy",
  "SaaS & Cloud Software",
  "Government & Public Sector",
  "Manufacturing & Industrial",
  "Professional Services",
]

const ASSET_TYPE_PRESETS = [
  "Database / Data Store",
  "Web Application / Portal",
  "Cloud Infrastructure / Kubernetes",
  "API Gateway / Microservice",
  "Identity & Access Provider (IdP)",
  "Payment Switch / Transaction Gateway",
  "Internal Network / Active Directory",
  "CI/CD Pipeline / Source Code",
]

export function RiskAssessmentView() {
  const { navigate, recordRiskAssessment, currency } = useAppState()

  // Wizard state: 1 to 4 are form steps, 5 is Review, 6 is Calculation/Analysis transition
  const [currentStep, setCurrentStep] = useState<number>(1)
  const [data, setData] = useState<WizardAssessmentData>(DEFAULT_WIZARD_DATA)

  // Step-level validation errors
  const [errors, setErrors] = useState<Record<string, string>>({})

  // Analysis / execution state
  const [calculating, setCalculating] = useState(false)
  const [calcStatusMessage, setCalcStatusMessage] = useState("")
  const [calcProgressPercent, setCalcProgressPercent] = useState(0)
  const [calculationError, setCalculationError] = useState<string | null>(null)

  // Contextual help drawer toggle
  const [showHelp, setShowHelp] = useState(false)

  // Updaters
  const updateData = <K extends keyof WizardAssessmentData>(key: K, value: WizardAssessmentData[K]) => {
    setData((prev) => ({ ...prev, [key]: value }))
    if (errors[key]) {
      setErrors((prev) => {
        const next = { ...prev }
        delete next[key]
        return next
      })
    }
  }

  const toggleControl = (controlId: keyof WizardAssessmentData["security_controls"]) => {
    setData((prev) => ({
      ...prev,
      security_controls: {
        ...prev.security_controls,
        [controlId]: !prev.security_controls[controlId],
      },
    }))
  }

  // Baseline Estimator Helpers
  const applyBaselineTEF = () => {
    // Standard empirical baseline based on exposure and industry
    let est = 1.0
    if (data.internet_exposure === "Internet-facing") {
      est = data.industry_type.includes("Financial") || data.industry_type.includes("SaaS") ? 2.5 : 1.8
    } else if (data.internet_exposure === "Internally accessible") {
      est = 0.8
    } else {
      est = 0.2
    }
    setData((prev) => ({
      ...prev,
      threat_event_frequency: est,
      tef_is_estimated: true,
    }))
  }

  const applyBaselineVulnProb = () => {
    // Calculate empirical vulnerability probability based on configured controls & scanner status
    let base = 0.50
    const ctrlCount = Object.values(data.security_controls).filter(Boolean).length
    base -= ctrlCount * 0.08 // each control reduces vulnerability probability

    if (data.has_known_vulnerabilities) {
      if (data.scanner_finding_severity === "Critical") base += 0.25
      else if (data.scanner_finding_severity === "High") base += 0.15
      else if (data.scanner_finding_severity === "Medium") base += 0.08
    }

    if (data.internet_exposure === "Internet-facing") base += 0.10
    if (data.internet_exposure === "Isolated / Air-gapped") base -= 0.20

    // Clamp between 0.05 and 0.95
    const clamped = Math.max(0.05, Math.min(0.95, Math.round(base * 100) / 100))

    setData((prev) => ({
      ...prev,
      vulnerability_probability: clamped,
      vuln_is_estimated: true,
      mitigated_vulnerability_probability: Math.max(0.02, Math.round((clamped * 0.3) * 100) / 100),
    }))
  }

  const applyBaselineLossEstimates = () => {
    // Conservative baseline loss: direct response ~ 3% of asset value, indirect ~ 6%
    const direct = Math.round(data.asset_value * 0.03)
    const indirect = Math.round(data.asset_value * 0.06)
    const proposedSec = Math.round(data.asset_value * 0.01)

    setData((prev) => ({
      ...prev,
      direct_loss: direct,
      direct_loss_is_estimated: true,
      indirect_loss: indirect,
      indirect_loss_is_estimated: true,
      proposed_security_cost: proposedSec > 0 ? proposedSec : 25000,
    }))
  }

  // Step Validation Logic
  const validateStep = (step: number): boolean => {
    const newErrors: Record<string, string> = {}

    if (step === 1) {
      if (!data.org_name.trim()) newErrors.org_name = "Organization name is required."
      if (!data.industry_type.trim()) newErrors.industry_type = "Industry type is required."
      if (!data.main_business_asset.trim()) newErrors.main_business_asset = "Main business asset/system is required."
    } else if (step === 2) {
      if (!data.asset_name.trim()) newErrors.asset_name = "Asset name is required."
      if (!data.asset_type.trim()) newErrors.asset_type = "Asset type is required."
      if (data.asset_value <= 0 || isNaN(data.asset_value)) {
        newErrors.asset_value = "Asset value must be a positive number greater than 0."
      }
      if (data.internet_exposure === "Internet-facing" && !data.public_fqdn_or_endpoint.trim()) {
        newErrors.public_fqdn_or_endpoint = "Please specify the public URL, API gateway, or domain endpoint."
      }
    } else if (step === 3) {
      if (data.has_known_vulnerabilities && !data.known_vulnerabilities_details.trim()) {
        newErrors.known_vulnerabilities_details = "Please summarize the scanner findings or reported issues."
      }
    } else if (step === 4) {
      if (data.threat_event_frequency < 0 || isNaN(data.threat_event_frequency)) {
        newErrors.threat_event_frequency = "Threat event frequency must be 0 or greater."
      }
      if (data.vulnerability_probability < 0 || data.vulnerability_probability > 1 || isNaN(data.vulnerability_probability)) {
        newErrors.vulnerability_probability = "Vulnerability probability must be between 0.0 and 1.0."
      }
      if (data.direct_loss < 0 || isNaN(data.direct_loss)) {
        newErrors.direct_loss = "Direct loss must be 0 or greater."
      }
      if (data.indirect_loss < 0 || isNaN(data.indirect_loss)) {
        newErrors.indirect_loss = "Indirect loss must be 0 or greater."
      }
      if (data.proposed_security_cost < 0 || isNaN(data.proposed_security_cost)) {
        newErrors.proposed_security_cost = "Proposed security investment must be 0 or greater."
      }
      if (
        data.mitigated_vulnerability_probability < 0 ||
        data.mitigated_vulnerability_probability > 1 ||
        isNaN(data.mitigated_vulnerability_probability)
      ) {
        newErrors.mitigated_vulnerability_probability = "Mitigated probability must be between 0.0 and 1.0."
      }
    }

    setErrors(newErrors)
    return Object.keys(newErrors).length === 0
  }

  const handleNext = () => {
    if (validateStep(currentStep)) {
      setCurrentStep((prev) => Math.min(prev + 1, 5))
    }
  }

  const handleBack = () => {
    setErrors({})
    setCurrentStep((prev) => Math.max(prev - 1, 1))
  }

  const handleReset = () => {
    setData(DEFAULT_WIZARD_DATA)
    setErrors({})
    setCurrentStep(1)
    setCalculationError(null)
  }

  // Submission & Real FastAPI Calculation
  const handleConfirmAndCalculate = async () => {
    // Final sanity check
    for (let s = 1; s <= 4; s++) {
      if (!validateStep(s)) {
        setCurrentStep(s)
        return
      }
    }

    // Move to step 6 (Analysis Transition)
    setCurrentStep(6)
    setCalculating(true)
    setCalculationError(null)
    setCalcProgressPercent(15)
    setCalcStatusMessage("Validating assessment parameters and FAIR model inputs…")

    // Construct backend payload compatible with FastAPI POST /api/v1/risk/assess
    const payload = {
      scenario_name: `${data.org_name} - ${data.asset_name} Risk Evaluation`,
      asset_name: data.asset_name,
      asset_value: Number(data.asset_value),
      threat_event_frequency: Number(data.threat_event_frequency),
      vulnerability_probability: Number(data.vulnerability_probability),
      direct_loss: Number(data.direct_loss),
      indirect_loss: Number(data.indirect_loss),
      proposed_security_cost: Number(data.proposed_security_cost),
      mitigated_vulnerability_probability: Number(data.mitigated_vulnerability_probability),
    }

    try {
      // Simulate real-time progress indicator stages
      await new Promise((res) => setTimeout(res, 350))
      setCalcProgressPercent(45)
      setCalcStatusMessage("Connecting to FastAPI quantitative risk engine (port 8000)…")

      await new Promise((res) => setTimeout(res, 300))
      setCalcProgressPercent(75)
      setCalcStatusMessage("Calculating Single Loss Expectancy (SLE), LEF, and Annual Loss Expectancy (ALE)…")

      const backendResponse = await apiClient.assessRisk(payload)

      setCalcProgressPercent(100)
      setCalcStatusMessage("Quantification complete! Calibrating dashboard and recording activity…")
      await new Promise((res) => setTimeout(res, 400))

      // Record in app state
      recordRiskAssessment(backendResponse)

      // Navigate to overview dashboard
      navigate("overview")
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Failed to connect to risk assessment engine"
      setCalculationError(
        `Quantitative calculation failed: ${msg}. Please verify that the FastAPI backend server is running on http://127.0.0.1:8000.`
      )
      setCalculating(false)
    }
  }

  // Progress percentage for wizard steps 1-5
  const wizardProgressPercent = Math.min(100, Math.round(((currentStep - 1) / 4) * 100))

  return (
    <div className="flex min-h-svh w-full flex-col items-center justify-start p-4 md:p-8 bg-background">
      <div className="w-full max-w-4xl space-y-6">
        {/* Top Header Bar */}
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
            <span className="flex size-2 rounded-full bg-emerald-500 animate-pulse" />
            <span className="text-xs font-semibold text-foreground">CyberQuant Guided Assessment</span>
            <span className="text-xs text-muted-foreground hidden sm:inline">· Adaptive Risk Wizard</span>
          </div>

          <div className="flex items-center gap-1">
            <Button
              type="button"
              variant="ghost"
              size="sm"
              onClick={() => setShowHelp(!showHelp)}
              className="text-xs text-muted-foreground hover:text-foreground"
              title="Toggle Security Glossary & Help"
            >
              <HelpCircle className="size-4" />
            </Button>
            <Button
              type="button"
              variant="ghost"
              size="sm"
              onClick={() => navigate("settings")}
              className="text-xs text-muted-foreground hover:text-foreground"
              title="Settings"
            >
              <Settings className="size-4" />
            </Button>
          </div>
        </div>

        {/* Wizard Header & Progress Indicator (Steps 1 to 5) */}
        {currentStep <= 5 && (
          <div className="space-y-3">
            <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
              <div>
                <div className="flex items-center gap-2 text-primary font-semibold text-lg">
                  <BrainCircuit className="size-5" />
                  <span>
                    {currentStep === 1 && "Step 1: Organisation Profile"}
                    {currentStep === 2 && "Step 2: Critical Asset Profile & Exposure"}
                    {currentStep === 3 && "Step 3: Security Posture & Control Hygiene"}
                    {currentStep === 4 && "Step 4: Threat Frequency & Financial Loss Assumptions"}
                    {currentStep === 5 && "Assessment Review & Model Verification"}
                  </span>
                </div>
                <p className="text-xs text-muted-foreground mt-0.5">
                  {currentStep === 1 && "Define the operating enterprise context, industry sector, and core business scope."}
                  {currentStep === 2 && "Specify the primary asset at risk, business criticality, exposure, and boundaries."}
                  {currentStep === 3 && "Report active security controls, vulnerability status, and defensive capabilities."}
                  {currentStep === 4 && "Calibrate annual threat frequency, exploit probability, and financial impact parameters."}
                  {currentStep === 5 && "Review your synthesized assessment parameters before calculating quantitative risk."}
                </p>
              </div>

              <div className="flex items-center gap-2 shrink-0">
                <Badge variant="outline" className="font-mono text-xs border-primary/30 text-primary">
                  {currentStep <= 4 ? `Step ${currentStep} of 4` : "Final Review"}
                </Badge>
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  onClick={handleReset}
                  className="h-7 text-xs text-muted-foreground hover:text-foreground"
                >
                  <RotateCcw className="size-3 mr-1" />
                  Reset
                </Button>
              </div>
            </div>

            {/* Custom Visual Progress Bar */}
            <div className="space-y-1">
              <div className="h-1.5 w-full bg-secondary/60 rounded-full overflow-hidden">
                <div
                  className="h-full bg-primary transition-all duration-300 ease-out"
                  style={{ width: `${wizardProgressPercent}%` }}
                />
              </div>
              <div className="flex justify-between text-[11px] text-muted-foreground px-0.5">
                <span className={currentStep >= 1 ? "text-primary font-medium" : ""}>1. Organisation</span>
                <span className={currentStep >= 2 ? "text-primary font-medium" : ""}>2. Asset</span>
                <span className={currentStep >= 3 ? "text-primary font-medium" : ""}>3. Controls</span>
                <span className={currentStep >= 4 ? "text-primary font-medium" : ""}>4. Financials</span>
                <span className={currentStep === 5 ? "text-primary font-medium" : ""}>5. Review</span>
              </div>
            </div>
          </div>
        )}

        {/* Collapsible Contextual Help Area */}
        {showHelp && (
          <div className="rounded-lg border border-primary/20 bg-primary/5 p-4 text-xs space-y-2.5 transition-all">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-1.5 font-semibold text-primary">
                <Info className="size-4" />
                <span>Security & FAIR Methodology Reference</span>
              </div>
              <Button
                variant="ghost"
                size="sm"
                onClick={() => setShowHelp(false)}
                className="h-5 px-1.5 text-[10px] text-muted-foreground"
              >
                Close
              </Button>
            </div>
            <p className="text-muted-foreground leading-relaxed">
              CyberQuant implements the <strong>FAIR (Factor Analysis of Information Risk)</strong> quantitative framework.
              Risk is evaluated as expected annual loss: <code>ALE = LEF × SLE</code>, where <em>LEF</em> (Loss Event Frequency) is the annual breach rate (<code>Threat Event Frequency × Vulnerability Probability</code>), and <em>SLE</em> (Single Loss Expectancy) is the combined direct and indirect cost per incident.
            </p>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-2 pt-1">
              <div className="rounded bg-background/60 p-2 border border-border/50">
                <div className="font-semibold text-foreground">Threat Event Frequency (TEF)</div>
                <div className="text-[11px] text-muted-foreground">Estimated count of malicious attempts per year targeting the asset.</div>
              </div>
              <div className="rounded bg-background/60 p-2 border border-border/50">
                <div className="font-semibold text-foreground">Vulnerability Probability</div>
                <div className="text-[11px] text-muted-foreground">Likelihood (0% to 100%) that an attack attempt succeeds given current controls.</div>
              </div>
              <div className="rounded bg-background/60 p-2 border border-border/50">
                <div className="font-semibold text-foreground">Single Loss Expectancy (SLE)</div>
                <div className="text-[11px] text-muted-foreground">Total direct cleanup + indirect fines/reputational damage per incident.</div>
              </div>
            </div>
          </div>
        )}

        {/* ============================================================== */}
        {/* STEP 1: ORGANISATION PROFILE                                   */}
        {/* ============================================================== */}
        {currentStep === 1 && (
          <Card className="border-border shadow-sm">
            <CardHeader className="pb-3 border-b">
              <div className="flex items-center gap-2">
                <div className="p-1.5 rounded-md bg-primary/10 text-primary">
                  <Building2 className="size-4" />
                </div>
                <div>
                  <CardTitle className="text-sm font-semibold">Organisation Profile</CardTitle>
                  <CardDescription className="text-xs">
                    Establish the target business context and core industry environment.
                  </CardDescription>
                </div>
              </div>
            </CardHeader>
            <CardContent className="space-y-5 pt-4">
              {/* Org Name */}
              <div className="space-y-1.5">
                <div className="flex items-center justify-between">
                  <label className="text-xs font-medium text-foreground">
                    Organisation Name <span className="text-destructive">*</span>
                  </label>
                  {errors.org_name && <span className="text-[11px] text-destructive">{errors.org_name}</span>}
                </div>
                <Input
                  value={data.org_name}
                  onChange={(e) => updateData("org_name", e.target.value)}
                  placeholder="e.g., FinSecure Technologies"
                  className={errors.org_name ? "border-destructive focus-visible:ring-destructive" : ""}
                />
              </div>

              {/* Industry Selection with Chips */}
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <label className="text-xs font-medium text-foreground">
                    Industry Sector <span className="text-destructive">*</span>
                  </label>
                  {errors.industry_type && <span className="text-[11px] text-destructive">{errors.industry_type}</span>}
                </div>
                <div className="flex flex-wrap gap-1.5">
                  {INDUSTRY_PRESETS.map((ind) => (
                    <button
                      key={ind}
                      type="button"
                      onClick={() => updateData("industry_type", ind)}
                      className={`text-xs px-2.5 py-1 rounded-full border transition-colors ${
                        data.industry_type === ind
                          ? "bg-primary text-primary-foreground border-primary font-medium"
                          : "bg-secondary/40 text-muted-foreground border-border hover:bg-secondary hover:text-foreground"
                      }`}
                    >
                      {ind}
                    </button>
                  ))}
                </div>
                <Input
                  value={data.industry_type}
                  onChange={(e) => updateData("industry_type", e.target.value)}
                  placeholder="Or enter a custom industry sector…"
                  className="text-xs mt-1"
                />
              </div>

              {/* Business Description */}
              <div className="space-y-1.5">
                <label className="text-xs font-medium text-foreground">
                  Brief Business Description <span className="text-muted-foreground font-normal">(Optional context)</span>
                </label>
                <Textarea
                  rows={2}
                  value={data.org_description}
                  onChange={(e) => updateData("org_description", e.target.value)}
                  placeholder="Briefly describe what your organization does and who you serve..."
                  className="text-xs resize-none"
                />
              </div>

              {/* Main Business Asset */}
              <div className="space-y-1.5">
                <div className="flex items-center justify-between">
                  <label className="text-xs font-medium text-foreground">
                    Main Business System / Scope to Assess <span className="text-destructive">*</span>
                  </label>
                  {errors.main_business_asset && (
                    <span className="text-[11px] text-destructive">{errors.main_business_asset}</span>
                  )}
                </div>
                <Input
                  value={data.main_business_asset}
                  onChange={(e) => {
                    updateData("main_business_asset", e.target.value)
                    // Autofill asset_name if user hasn't edited it yet
                    if (data.asset_name === data.main_business_asset || data.asset_name === DEFAULT_WIZARD_DATA.asset_name) {
                      updateData("asset_name", e.target.value)
                    }
                  }}
                  placeholder="e.g., Customer Core Banking & PII Database"
                  className={errors.main_business_asset ? "border-destructive focus-visible:ring-destructive" : ""}
                />
                <p className="text-[11px] text-muted-foreground">
                  In Step 2, we will focus specifically on this asset&apos;s boundaries, criticality, and financial valuation.
                </p>
              </div>
            </CardContent>
          </Card>
        )}

        {/* ============================================================== */}
        {/* STEP 2: CRITICAL ASSET PROFILE & EXPOSURE                     */}
        {/* ============================================================== */}
        {currentStep === 2 && (
          <Card className="border-border shadow-sm">
            <CardHeader className="pb-3 border-b">
              <div className="flex items-center gap-2">
                <div className="p-1.5 rounded-md bg-primary/10 text-primary">
                  <Database className="size-4" />
                </div>
                <div>
                  <CardTitle className="text-sm font-semibold">Critical Asset Profile & Boundaries</CardTitle>
                  <CardDescription className="text-xs">
                    Define the technical asset, operational criticality, exposure surface, and estimated value.
                  </CardDescription>
                </div>
              </div>
            </CardHeader>
            <CardContent className="space-y-5 pt-4">
              {/* Asset Name */}
              <div className="space-y-1.5">
                <div className="flex items-center justify-between">
                  <label className="text-xs font-medium text-foreground">
                    Primary Asset Name <span className="text-destructive">*</span>
                  </label>
                  {errors.asset_name && <span className="text-[11px] text-destructive">{errors.asset_name}</span>}
                </div>
                <Input
                  value={data.asset_name}
                  onChange={(e) => updateData("asset_name", e.target.value)}
                  placeholder="e.g., Customer Core Banking & PII Database"
                  className={errors.asset_name ? "border-destructive" : ""}
                />
              </div>

              {/* Asset Type Selector */}
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <label className="text-xs font-medium text-foreground">
                    Asset Type <span className="text-destructive">*</span>
                  </label>
                  {errors.asset_type && <span className="text-[11px] text-destructive">{errors.asset_type}</span>}
                </div>
                <div className="flex flex-wrap gap-1.5">
                  {ASSET_TYPE_PRESETS.map((t) => (
                    <button
                      key={t}
                      type="button"
                      onClick={() => updateData("asset_type", t)}
                      className={`text-xs px-2.5 py-1 rounded-full border transition-colors ${
                        data.asset_type === t
                          ? "bg-primary text-primary-foreground border-primary font-medium"
                          : "bg-secondary/40 text-muted-foreground border-border hover:bg-secondary hover:text-foreground"
                      }`}
                    >
                      {t}
                    </button>
                  ))}
                </div>
              </div>

              {/* Criticality & Asset Valuation */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="space-y-1.5">
                  <label className="text-xs font-medium text-foreground">Business Criticality</label>
                  <div className="grid grid-cols-4 gap-1.5">
                    {(["Low", "Medium", "High", "Critical"] as const).map((crit) => (
                      <button
                        key={crit}
                        type="button"
                        onClick={() => updateData("business_criticality", crit)}
                        className={`text-xs py-1.5 rounded border transition-colors text-center ${
                          data.business_criticality === crit
                            ? crit === "Critical"
                              ? "bg-destructive/15 text-destructive border-destructive/50 font-semibold"
                              : "bg-primary text-primary-foreground border-primary font-semibold"
                            : "bg-secondary/30 text-muted-foreground border-border hover:bg-secondary"
                        }`}
                      >
                        {crit}
                      </button>
                    ))}
                  </div>
                  <span className="text-[10px] text-muted-foreground">
                    Reflects enterprise downtime tolerance and revenue dependency.
                  </span>
                </div>

                <div className="space-y-1.5">
                  <div className="flex items-center justify-between">
                    <label className="text-xs font-medium text-foreground">
                      Estimated Asset Value ($ USD) <span className="text-destructive">*</span>
                    </label>
                    {errors.asset_value && <span className="text-[11px] text-destructive">{errors.asset_value}</span>}
                  </div>
                  <Input
                    type="number"
                    min={1}
                    value={data.asset_value || ""}
                    onChange={(e) => updateData("asset_value", Number(e.target.value))}
                    className="font-mono text-xs"
                  />
                  <div className="flex items-center justify-between text-[10px] text-muted-foreground">
                    <span>
                      {currency !== "USD"
                        ? `Equivalent: ${formatCurrency(data.asset_value, currency)}`
                        : `Equivalent: ${formatINR(data.asset_value * 83.5)} (@ ₹83.5/$)`}
                    </span>
                    <button
                      type="button"
                      onClick={applyBaselineLossEstimates}
                      className="text-primary hover:underline"
                    >
                      Calibrate loss baselines from value
                    </button>
                  </div>
                </div>
              </div>

              {/* Exposure Surface */}
              <div className="space-y-2 pt-1">
                <label className="text-xs font-medium text-foreground">Network & Internet Exposure Surface</label>
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
                  {(
                    [
                      {
                        val: "Internet-facing",
                        label: "Internet-Facing",
                        desc: "Reachable directly or via public domain/API.",
                        badge: "Higher threat vector",
                      },
                      {
                        val: "Internally accessible",
                        label: "Internally Accessible",
                        desc: "Accessible within VPN / corporate intranet.",
                        badge: "Internal lateral scope",
                      },
                      {
                        val: "Isolated / Air-gapped",
                        label: "Isolated / Air-Gapped",
                        desc: "Physical or strict zero-trust boundary.",
                        badge: "Lowest exposure",
                      },
                    ] as const
                  ).map((exp) => (
                    <button
                      key={exp.val}
                      type="button"
                      onClick={() => updateData("internet_exposure", exp.val)}
                      className={`flex flex-col text-left p-3 rounded-lg border transition-all ${
                        data.internet_exposure === exp.val
                          ? "border-primary bg-primary/10 shadow-sm"
                          : "border-border bg-card/50 hover:bg-muted/40"
                      }`}
                    >
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-semibold text-foreground">{exp.label}</span>
                        {data.internet_exposure === exp.val && <CheckCircle2 className="size-3.5 text-primary" />}
                      </div>
                      <span className="text-[11px] text-muted-foreground mt-1">{exp.desc}</span>
                      <span className="text-[10px] text-primary/80 mt-2 font-mono">{exp.badge}</span>
                    </button>
                  ))}
                </div>
              </div>

              {/* ADAPTIVE FOLLOW-UP: If asset is internet-facing */}
              {data.internet_exposure === "Internet-facing" && (
                <div className="rounded-lg border border-primary/20 bg-primary/5 p-3.5 space-y-3 animate-in fade-in duration-200">
                  <div className="flex items-center gap-2 text-xs font-semibold text-foreground">
                    <Globe className="size-4 text-primary" />
                    <span>Adaptive Follow-up: Public Exposure Scope</span>
                  </div>
                  <div className="space-y-1.5">
                    <div className="flex items-center justify-between">
                      <label className="text-[11px] font-medium text-foreground">
                        Public Domain, API FQDN, or Service Endpoint
                      </label>
                      {errors.public_fqdn_or_endpoint && (
                        <span className="text-[10px] text-destructive">{errors.public_fqdn_or_endpoint}</span>
                      )}
                    </div>
                    <Input
                      value={data.public_fqdn_or_endpoint}
                      onChange={(e) => updateData("public_fqdn_or_endpoint", e.target.value)}
                      placeholder="e.g. api.finsecure.com or portal.myorg.io"
                      className="text-xs font-mono"
                    />
                    <span className="text-[10px] text-muted-foreground">
                      Publicly exposed assets typically experience automated scanner bots and credential stuffing.
                    </span>
                  </div>

                  <div className="flex items-center gap-2 pt-1">
                    <input
                      type="checkbox"
                      id="api-gateway-check"
                      checked={data.has_api_or_third_party_gateway}
                      onChange={(e) => updateData("has_api_or_third_party_gateway", e.target.checked)}
                      className="size-3.5 rounded border-border text-primary focus:ring-primary accent-emerald-500"
                    />
                    <label htmlFor="api-gateway-check" className="text-xs text-foreground cursor-pointer">
                      Includes third-party APIs, webhooks, or external integration endpoints
                    </label>
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        )}

        {/* ============================================================== */}
        {/* STEP 3: SECURITY POSTURE & CONTROL HYGIENE                     */}
        {/* ============================================================== */}
        {currentStep === 3 && (
          <Card className="border-border shadow-sm">
            <CardHeader className="pb-3 border-b">
              <div className="flex items-center gap-2">
                <div className="p-1.5 rounded-md bg-primary/10 text-primary">
                  <Shield className="size-4" />
                </div>
                <div>
                  <CardTitle className="text-sm font-semibold">Security Posture & Controls</CardTitle>
                  <CardDescription className="text-xs">
                    Record implemented defensive controls, known vulnerabilities, and scanner findings.
                  </CardDescription>
                </div>
              </div>
            </CardHeader>
            <CardContent className="space-y-5 pt-4">
              {/* Security Controls Grid */}
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <label className="text-xs font-medium text-foreground">
                    Implemented Defensive Controls
                  </label>
                  <span className="text-[11px] text-muted-foreground">
                    {Object.values(data.security_controls).filter(Boolean).length} of 5 Active
                  </span>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5">
                  {SECURITY_CONTROLS_META.map((ctrl) => {
                    const isEnabled = data.security_controls[ctrl.id]
                    return (
                      <div
                        key={ctrl.id}
                        onClick={() => toggleControl(ctrl.id)}
                        className={`cursor-pointer rounded-lg border p-3 transition-all flex flex-col justify-between ${
                          isEnabled
                            ? "border-emerald-500/40 bg-emerald-500/10"
                            : "border-border bg-card/60 hover:border-muted-foreground/40"
                        }`}
                      >
                        <div>
                          <div className="flex items-center justify-between">
                            <span className="text-xs font-semibold text-foreground flex items-center gap-1.5">
                              {isEnabled ? (
                                <ShieldCheck className="size-4 text-emerald-400" />
                              ) : (
                                <ShieldAlert className="size-4 text-muted-foreground" />
                              )}
                              {ctrl.label}
                            </span>
                            <Badge
                              variant="outline"
                              className={`text-[10px] ${
                                isEnabled
                                  ? "bg-emerald-500/20 text-emerald-300 border-emerald-500/40"
                                  : "text-muted-foreground"
                              }`}
                            >
                              {isEnabled ? "Enforced" : "Missing / Partial"}
                            </Badge>
                          </div>
                          <p className="text-[11px] text-muted-foreground mt-1">{ctrl.description}</p>
                        </div>

                        {!isEnabled && (
                          <div className="mt-2 text-[10px] text-amber-400/90 bg-amber-500/10 rounded px-2 py-1">
                            <strong>Risk note:</strong> {ctrl.riskImpactNote}
                          </div>
                        )}
                      </div>
                    )
                  })}
                </div>
              </div>

              {/* Vulnerabilities & Scanner Findings */}
              <div className="border-t pt-4 space-y-3">
                <div className="flex items-center justify-between">
                  <div>
                    <label className="text-xs font-medium text-foreground">
                      Known Vulnerabilities or Scanner Findings?
                    </label>
                    <p className="text-[11px] text-muted-foreground">
                      Indicate if penetration tests or scanners identified unpatched CVEs, configuration flaws, or weak endpoints.
                    </p>
                  </div>
                  <div className="flex items-center gap-2">
                    <button
                      type="button"
                      onClick={() => updateData("has_known_vulnerabilities", false)}
                      className={`text-xs px-3 py-1 rounded border transition-colors ${
                        !data.has_known_vulnerabilities
                          ? "bg-primary text-primary-foreground font-semibold"
                          : "bg-secondary/40 text-muted-foreground"
                      }`}
                    >
                      No Findings
                    </button>
                    <button
                      type="button"
                      onClick={() => updateData("has_known_vulnerabilities", true)}
                      className={`text-xs px-3 py-1 rounded border transition-colors ${
                        data.has_known_vulnerabilities
                          ? "bg-destructive text-destructive-foreground font-semibold"
                          : "bg-secondary/40 text-muted-foreground"
                      }`}
                    >
                      Yes, Reported
                    </button>
                  </div>
                </div>

                {/* ADAPTIVE FOLLOW-UP: If vulnerabilities reported */}
                {data.has_known_vulnerabilities && (
                  <div className="rounded-lg border border-destructive/30 bg-destructive/5 p-3.5 space-y-3 animate-in fade-in duration-200">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-semibold text-destructive flex items-center gap-1.5">
                        <Flame className="size-3.5" />
                        Adaptive Follow-up: Vulnerability Details & Severity
                      </span>
                      <div className="flex items-center gap-1">
                        {(["Low", "Medium", "High", "Critical"] as const).map((sev) => (
                          <button
                            key={sev}
                            type="button"
                            onClick={() => updateData("scanner_finding_severity", sev)}
                            className={`text-[10px] px-2 py-0.5 rounded border transition-colors ${
                              data.scanner_finding_severity === sev
                                ? "bg-destructive text-destructive-foreground font-semibold"
                                : "text-muted-foreground border-border bg-card/60"
                            }`}
                          >
                            {sev}
                          </button>
                        ))}
                      </div>
                    </div>

                    <div className="space-y-1">
                      <div className="flex items-center justify-between">
                        <label className="text-[11px] font-medium text-foreground">
                          Observed Issues / Scanner Findings Description <span className="text-destructive">*</span>
                        </label>
                        {errors.known_vulnerabilities_details && (
                          <span className="text-[10px] text-destructive">{errors.known_vulnerabilities_details}</span>
                        )}
                      </div>
                      <Textarea
                        rows={2}
                        value={data.known_vulnerabilities_details}
                        onChange={(e) => updateData("known_vulnerabilities_details", e.target.value)}
                        placeholder="e.g., Unpatched OpenSSL CVE-2023-3817, legacy auth endpoints, missing security headers..."
                        className="text-xs resize-none"
                      />
                      <span className="text-[10px] text-muted-foreground">
                        Note: User-reported findings are preserved for assessment context and do not fabricate confirmed exploits without scanning.
                      </span>
                    </div>
                  </div>
                )}
              </div>

              {/* Recent Incident History */}
              <div className="space-y-1.5 border-t pt-3">
                <label className="text-xs font-medium text-foreground">
                  Recent Threat or Incident History (Past 24 Months)
                </label>
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
                  {(
                    [
                      "None in past 24m",
                      "Minor probe / thwarted",
                      "Active incident or breach within 12m",
                    ] as const
                  ).map((inc) => (
                    <button
                      key={inc}
                      type="button"
                      onClick={() => updateData("recent_incident_history", inc)}
                      className={`text-xs py-2 px-2.5 rounded border text-left transition-colors ${
                        data.recent_incident_history === inc
                          ? "bg-primary/10 border-primary text-foreground font-medium"
                          : "bg-card/40 border-border text-muted-foreground hover:bg-muted/30"
                      }`}
                    >
                      {inc}
                    </button>
                  ))}
                </div>
              </div>
            </CardContent>
          </Card>
        )}

        {/* ============================================================== */}
        {/* STEP 4: THREAT & FINANCIAL IMPACT (FAIR PARAMETERS)            */}
        {/* ============================================================== */}
        {currentStep === 4 && (
          <Card className="border-border shadow-sm">
            <CardHeader className="pb-3 border-b">
              <div className="flex items-center gap-2">
                <div className="p-1.5 rounded-md bg-primary/10 text-primary">
                  <Zap className="size-4" />
                </div>
                <div>
                  <CardTitle className="text-sm font-semibold">Threat Frequency & Financial Parameters</CardTitle>
                  <CardDescription className="text-xs">
                    Calibrate the mathematical inputs used by the FAIR risk quantification engine.
                  </CardDescription>
                </div>
              </div>
            </CardHeader>
            <CardContent className="space-y-6 pt-4">
              {/* TEF & Vulnerability Probability */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
                {/* Threat Event Frequency */}
                <div className="rounded-lg border p-3.5 space-y-2 bg-card/40">
                  <div className="flex items-start justify-between">
                    <div>
                      <label className="text-xs font-semibold text-foreground flex items-center gap-1.5">
                        Threat Event Frequency (TEF) <span className="text-destructive">*</span>
                      </label>
                      <p className="text-[11px] text-muted-foreground mt-0.5">
                        Estimated number of targeted attack attempts per year.
                      </p>
                    </div>
                    {data.tef_is_estimated && (
                      <Badge variant="outline" className="text-[10px] text-amber-400 border-amber-400/40">
                        Estimated
                      </Badge>
                    )}
                  </div>

                  <div className="flex items-center gap-2">
                    <Input
                      type="number"
                      step={0.1}
                      min={0}
                      value={data.threat_event_frequency}
                      onChange={(e) => {
                        updateData("threat_event_frequency", Number(e.target.value))
                        updateData("tef_is_estimated", false)
                      }}
                      className="font-mono text-xs w-28"
                    />
                    <span className="text-xs text-muted-foreground">attempts / year</span>
                  </div>

                  {errors.threat_event_frequency && (
                    <span className="text-[10px] text-destructive">{errors.threat_event_frequency}</span>
                  )}

                  <div className="pt-1 flex items-center justify-between border-t text-[10px]">
                    <span className="text-muted-foreground">Unsure of threat rate?</span>
                    <button
                      type="button"
                      onClick={applyBaselineTEF}
                      className="text-primary hover:underline font-medium flex items-center gap-1"
                    >
                      <Sparkles className="size-3" />
                      Estimate from industry & exposure
                    </button>
                  </div>
                </div>

                {/* Baseline Vulnerability Probability */}
                <div className="rounded-lg border p-3.5 space-y-2 bg-card/40">
                  <div className="flex items-start justify-between">
                    <div>
                      <label className="text-xs font-semibold text-foreground flex items-center gap-1.5">
                        Vulnerability Probability <span className="text-destructive">*</span>
                      </label>
                      <p className="text-[11px] text-muted-foreground mt-0.5">
                        Likelihood (0.00 to 1.00) that an attempt causes a breach.
                      </p>
                    </div>
                    {data.vuln_is_estimated && (
                      <Badge variant="outline" className="text-[10px] text-amber-400 border-amber-400/40">
                        Estimated
                      </Badge>
                    )}
                  </div>

                  <div className="flex items-center gap-2">
                    <Input
                      type="number"
                      step={0.01}
                      min={0}
                      max={1}
                      value={data.vulnerability_probability}
                      onChange={(e) => {
                        updateData("vulnerability_probability", Number(e.target.value))
                        updateData("vuln_is_estimated", false)
                      }}
                      className="font-mono text-xs w-28"
                    />
                    <span className="text-xs font-mono text-primary">
                      = {(data.vulnerability_probability * 100).toFixed(0)}% breach chance
                    </span>
                  </div>

                  {errors.vulnerability_probability && (
                    <span className="text-[10px] text-destructive">{errors.vulnerability_probability}</span>
                  )}

                  <div className="pt-1 flex items-center justify-between border-t text-[10px]">
                    <span className="text-muted-foreground">Derive from selected controls?</span>
                    <button
                      type="button"
                      onClick={applyBaselineVulnProb}
                      className="text-primary hover:underline font-medium flex items-center gap-1"
                    >
                      <Sparkles className="size-3" />
                      Calculate baseline from Step 3 controls
                    </button>
                  </div>
                </div>
              </div>

              {/* Financial Losses: Direct & Indirect */}
              <div className="rounded-lg border p-4 space-y-3 bg-card/20">
                <div className="flex items-center justify-between">
                  <div className="space-y-0.5">
                    <div className="text-xs font-semibold text-foreground">
                      Financial Impact per Incident (Single Loss Expectancy)
                    </div>
                    <p className="text-[11px] text-muted-foreground">
                      Quantified in USD. Total SLE = Direct Loss + Indirect Loss.
                    </p>
                  </div>
                  <div className="text-right">
                    <div className="text-xs text-muted-foreground">Total SLE per Incident</div>
                    <div className="text-sm font-mono font-bold text-destructive">
                      {formatCurrency(Number(data.direct_loss || 0) + Number(data.indirect_loss || 0), currency)}
                    </div>
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-1">
                  <div className="space-y-1.5">
                    <div className="flex items-center justify-between">
                      <label className="text-xs font-medium text-foreground">
                        Direct Loss ($ USD) <span className="text-destructive">*</span>
                      </label>
                      {data.direct_loss_is_estimated && (
                        <Badge variant="outline" className="text-[10px] text-amber-400">
                          Est.
                        </Badge>
                      )}
                    </div>
                    <Input
                      type="number"
                      min={0}
                      value={data.direct_loss}
                      onChange={(e) => {
                        updateData("direct_loss", Number(e.target.value))
                        updateData("direct_loss_is_estimated", false)
                      }}
                      className="font-mono text-xs"
                    />
                    <span className="text-[10px] text-muted-foreground">
                      Forensic analysis, incident response, immediate system rebuild costs.
                    </span>
                    {errors.direct_loss && <span className="text-[10px] text-destructive">{errors.direct_loss}</span>}
                  </div>

                  <div className="space-y-1.5">
                    <div className="flex items-center justify-between">
                      <label className="text-xs font-medium text-foreground">
                        Indirect Loss ($ USD) <span className="text-destructive">*</span>
                      </label>
                      {data.indirect_loss_is_estimated && (
                        <Badge variant="outline" className="text-[10px] text-amber-400">
                          Est.
                        </Badge>
                      )}
                    </div>
                    <Input
                      type="number"
                      min={0}
                      value={data.indirect_loss}
                      onChange={(e) => {
                        updateData("indirect_loss", Number(e.target.value))
                        updateData("indirect_loss_is_estimated", false)
                      }}
                      className="font-mono text-xs"
                    />
                    <span className="text-[10px] text-muted-foreground">
                      Regulatory fines (GDPR, PCI-DSS), brand damage, customer churn.
                    </span>
                    {errors.indirect_loss && <span className="text-[10px] text-destructive">{errors.indirect_loss}</span>}
                  </div>
                </div>

                <div className="pt-2 flex justify-end">
                  <button
                    type="button"
                    onClick={applyBaselineLossEstimates}
                    className="text-[11px] text-primary hover:underline flex items-center gap-1"
                  >
                    <Sparkles className="size-3" />
                    Estimate direct & indirect loss from asset value ({formatCurrency(data.asset_value, currency)})
                  </button>
                </div>
              </div>

              {/* Proposed Investment & Target Mitigated Risk */}
              <div className="rounded-lg border p-4 space-y-3 bg-card/20">
                <div className="text-xs font-semibold text-foreground">
                  Security Investment & Risk Mitigation Goals (ROI Engine)
                </div>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="space-y-1.5">
                    <label className="text-xs font-medium text-foreground">
                      Proposed Security Budget ($ USD)
                    </label>
                    <Input
                      type="number"
                      min={0}
                      value={data.proposed_security_cost}
                      onChange={(e) => updateData("proposed_security_cost", Number(e.target.value))}
                      className="font-mono text-xs"
                    />
                    <span className="text-[10px] text-muted-foreground">
                      Investment in tools (EDR, MFA, patch automation) to calculate financial ROI.
                    </span>
                  </div>

                  <div className="space-y-1.5">
                    <label className="text-xs font-medium text-foreground">
                      Target Mitigated Vulnerability Probability (0.0 to 1.0)
                    </label>
                    <Input
                      type="number"
                      step={0.01}
                      min={0}
                      max={1}
                      value={data.mitigated_vulnerability_probability}
                      onChange={(e) => updateData("mitigated_vulnerability_probability", Number(e.target.value))}
                      className="font-mono text-xs"
                    />
                    <span className="text-[10px] text-muted-foreground">
                      Target post-remediation breach probability (e.g. 0.10 = 10%).
                    </span>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        )}

        {/* ============================================================== */}
        {/* STEP 5: ASSESSMENT REVIEW SCREEN                               */}
        {/* ============================================================== */}
        {currentStep === 5 && (
          <Card className="border-border shadow-sm">
            <CardHeader className="pb-3 border-b">
              <div className="flex items-center gap-2">
                <div className="p-1.5 rounded-md bg-primary/10 text-primary">
                  <CheckCircle2 className="size-4" />
                </div>
                <div>
                  <CardTitle className="text-sm font-semibold">Assessment Review & Summary</CardTitle>
                  <CardDescription className="text-xs">
                    Verify collected parameters and model assumptions before calculating final risk.
                  </CardDescription>
                </div>
              </div>
            </CardHeader>
            <CardContent className="space-y-5 pt-4">
              {/* Summary Cards */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3.5">
                {/* Org & Asset Summary */}
                <div className="rounded-lg border p-3.5 space-y-2 bg-card/40">
                  <div className="flex items-center justify-between border-b pb-2">
                    <span className="text-xs font-semibold text-foreground flex items-center gap-1.5">
                      <Building2 className="size-3.5 text-primary" />
                      Organisation & Critical Asset
                    </span>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => setCurrentStep(1)}
                      className="h-6 text-[11px] text-primary"
                    >
                      Edit
                    </Button>
                  </div>
                  <div className="space-y-1 text-xs">
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Organisation:</span>
                      <span className="font-medium text-foreground">{data.org_name}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Industry:</span>
                      <span className="text-foreground">{data.industry_type}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Asset Name:</span>
                      <span className="font-medium text-foreground">{data.asset_name}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Asset Type:</span>
                      <span className="text-foreground">{data.asset_type}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Asset Valuation:</span>
                      <span className="font-mono font-semibold text-foreground">
                        {formatCurrency(data.asset_value, currency)}
                      </span>
                    </div>
                  </div>
                </div>

                {/* Criticality & Exposure Summary */}
                <div className="rounded-lg border p-3.5 space-y-2 bg-card/40">
                  <div className="flex items-center justify-between border-b pb-2">
                    <span className="text-xs font-semibold text-foreground flex items-center gap-1.5">
                      <Globe className="size-3.5 text-primary" />
                      Criticality & Exposure Surface
                    </span>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => setCurrentStep(2)}
                      className="h-6 text-[11px] text-primary"
                    >
                      Edit
                    </Button>
                  </div>
                  <div className="space-y-1 text-xs">
                    <div className="flex justify-between items-center">
                      <span className="text-muted-foreground">Criticality:</span>
                      <Badge variant="outline" className="text-[10px]">
                        {data.business_criticality}
                      </Badge>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="text-muted-foreground">Exposure:</span>
                      <span className="font-medium text-foreground">{data.internet_exposure}</span>
                    </div>
                    {data.internet_exposure === "Internet-facing" && (
                      <div className="flex justify-between">
                        <span className="text-muted-foreground">Public Endpoint:</span>
                        <span className="font-mono text-[11px] text-primary truncate max-w-[180px]">
                          {data.public_fqdn_or_endpoint || "Configured"}
                        </span>
                      </div>
                    )}
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Incident History:</span>
                      <span className="text-foreground">{data.recent_incident_history}</span>
                    </div>
                  </div>
                </div>

                {/* Security Controls & Findings Summary */}
                <div className="rounded-lg border p-3.5 space-y-2 bg-card/40">
                  <div className="flex items-center justify-between border-b pb-2">
                    <span className="text-xs font-semibold text-foreground flex items-center gap-1.5">
                      <Shield className="size-3.5 text-primary" />
                      Security Controls & Findings
                    </span>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => setCurrentStep(3)}
                      className="h-6 text-[11px] text-primary"
                    >
                      Edit
                    </Button>
                  </div>
                  <div className="space-y-1.5 text-xs">
                    <div className="flex flex-wrap gap-1">
                      {SECURITY_CONTROLS_META.map((ctrl) => {
                        const active = data.security_controls[ctrl.id]
                        return (
                          <Badge
                            key={ctrl.id}
                            variant={active ? "default" : "outline"}
                            className={`text-[10px] ${
                              active ? "bg-emerald-600/30 text-emerald-400 border-emerald-500/40" : "text-muted-foreground/60"
                            }`}
                          >
                            {ctrl.label}: {active ? "Yes" : "No"}
                          </Badge>
                        )
                      })}
                    </div>
                    <div className="pt-1 text-[11px]">
                      <span className="text-muted-foreground">Reported Vulnerabilities: </span>
                      {data.has_known_vulnerabilities ? (
                        <span className="text-destructive font-medium">
                          Yes ({data.scanner_finding_severity} severity: {data.known_vulnerabilities_details})
                        </span>
                      ) : (
                        <span className="text-emerald-400 font-medium">None reported</span>
                      )}
                    </div>
                  </div>
                </div>

                {/* Financial Assumptions Summary */}
                <div className="rounded-lg border p-3.5 space-y-2 bg-card/40">
                  <div className="flex items-center justify-between border-b pb-2">
                    <span className="text-xs font-semibold text-foreground flex items-center gap-1.5">
                      <Zap className="size-3.5 text-primary" />
                      Threat & Financial Modeling Inputs
                    </span>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => setCurrentStep(4)}
                      className="h-6 text-[11px] text-primary"
                    >
                      Edit
                    </Button>
                  </div>
                  <div className="space-y-1 text-xs">
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Threat Frequency (TEF):</span>
                      <span className="font-mono text-foreground">
                        {data.threat_event_frequency.toFixed(2)}/yr
                        {data.tef_is_estimated && " (Est)"}
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Vulnerability Prob.:</span>
                      <span className="font-mono text-foreground">
                        {(data.vulnerability_probability * 100).toFixed(1)}%
                        {data.vuln_is_estimated && " (Est)"}
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Direct Loss / Breach:</span>
                      <span className="font-mono text-foreground">{formatCurrency(data.direct_loss, currency)}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Indirect Loss / Breach:</span>
                      <span className="font-mono text-foreground">{formatCurrency(data.indirect_loss, currency)}</span>
                    </div>
                    <div className="flex justify-between border-t pt-1">
                      <span className="text-muted-foreground font-medium">Proposed Investment:</span>
                      <span className="font-mono font-semibold text-primary">
                        {formatCurrency(data.proposed_security_cost, currency)}
                      </span>
                    </div>
                  </div>
                </div>
              </div>

              {/* Preliminary Baseline Preview */}
              <div className="rounded-lg border border-primary/20 bg-primary/5 p-3.5 text-xs flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                <div className="space-y-0.5">
                  <div className="font-semibold text-foreground flex items-center gap-1.5">
                    <Sparkles className="size-4 text-primary" />
                    <span>Calculated Scenario Preview</span>
                  </div>
                  <p className="text-[11px] text-muted-foreground">
                    Projected Loss Event Frequency:{" "}
                    <code className="text-primary font-mono">
                      {(data.threat_event_frequency * data.vulnerability_probability).toFixed(2)} events/year
                    </code>
                    {" · "}
                    Projected Single Loss:{" "}
                    <code className="text-destructive font-mono">
                      {formatCurrency(data.direct_loss + data.indirect_loss, currency)}
                    </code>
                  </p>
                </div>

                <div className="shrink-0">
                  <Button
                    type="button"
                    onClick={handleConfirmAndCalculate}
                    className="font-semibold bg-primary hover:bg-primary/90 text-primary-foreground"
                  >
                    Confirm & Calculate Risk
                    <ArrowRight className="ml-1.5 size-4" />
                  </Button>
                </div>
              </div>
            </CardContent>
          </Card>
        )}

        {/* ============================================================== */}
        {/* STEP 6: REAL CALCULATION / ANALYSIS TRANSITION SCREEN          */}
        {/* ============================================================== */}
        {currentStep === 6 && (
          <Card className="border-border shadow-md">
            <CardContent className="py-12 px-6 flex flex-col items-center justify-center text-center space-y-6">
              {calculationError ? (
                /* Calculation Error State */
                <div className="space-y-4 max-w-lg">
                  <div className="p-3 rounded-full bg-destructive/10 text-destructive mx-auto w-fit">
                    <ShieldAlert className="size-8" />
                  </div>
                  <div className="space-y-1">
                    <h3 className="text-base font-semibold text-destructive">Risk Engine Quantification Failed</h3>
                    <p className="text-xs text-muted-foreground leading-relaxed">{calculationError}</p>
                  </div>
                  <div className="flex items-center justify-center gap-3 pt-2">
                    <Button
                      type="button"
                      variant="outline"
                      size="sm"
                      onClick={() => setCurrentStep(5)}
                    >
                      <ArrowLeft className="mr-1.5 size-4" />
                      Back to Review
                    </Button>
                    <Button
                      type="button"
                      size="sm"
                      onClick={handleConfirmAndCalculate}
                    >
                      <RotateCcw className="mr-1.5 size-4" />
                      Retry Calculation
                    </Button>
                  </div>
                </div>
              ) : (
                /* Calculating Active State */
                <div className="space-y-5 max-w-md w-full">
                  <div className="relative mx-auto w-fit">
                    <div className="size-16 rounded-full border-4 border-primary/20 border-t-primary animate-spin" />
                    <div className="absolute inset-0 flex items-center justify-center">
                      <BrainCircuit className="size-6 text-primary animate-pulse" />
                    </div>
                  </div>

                  <div className="space-y-1.5">
                    <h3 className="text-sm font-semibold text-foreground">
                      Quantifying Financial Cyber Risk
                    </h3>
                    <p className="text-xs text-muted-foreground font-mono">
                      {calcStatusMessage}
                    </p>
                  </div>

                  {/* Real progress track */}
                  <div className="space-y-1.5 w-full">
                    <div className="h-2 w-full bg-secondary rounded-full overflow-hidden">
                      <div
                        className="h-full bg-primary transition-all duration-300 ease-out"
                        style={{ width: `${calcProgressPercent}%` }}
                      />
                    </div>
                    <div className="flex justify-between text-[11px] text-muted-foreground font-mono">
                      <span>FAIR Engine (FastAPI 8000)</span>
                      <span>{calcProgressPercent}%</span>
                    </div>
                  </div>

                  <div className="rounded-lg bg-card border p-3 text-left space-y-1 text-[11px] text-muted-foreground">
                    <div className="flex items-center gap-1.5 text-foreground font-medium">
                      <Shield className="size-3.5 text-primary" />
                      <span>Deterministic Calculations in Progress:</span>
                    </div>
                    <p>• Single Loss Expectancy (SLE) = Direct Loss + Indirect Loss</p>
                    <p>• Loss Event Frequency (LEF) = Threat Frequency × Vulnerability Probability</p>
                    <p>• Annual Loss Expectancy (ALE) = LEF × SLE</p>
                    <p>• Net Security ROI = (Risk Reduction - Investment Cost) / Investment Cost</p>
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        )}

        {/* Wizard Navigation Footer (Steps 1 to 4) */}
        {currentStep <= 4 && (
          <div className="flex items-center justify-between border-t pt-4">
            <Button
              type="button"
              variant="outline"
              size="sm"
              disabled={currentStep === 1}
              onClick={handleBack}
              className="text-xs"
            >
              <ArrowLeft className="mr-1.5 size-3.5" />
              Previous Step
            </Button>

            <div className="flex items-center gap-2">
              <Button
                type="button"
                variant="ghost"
                size="sm"
                onClick={() => navigate("landing")}
                className="text-xs text-muted-foreground"
              >
                Cancel
              </Button>

              <Button
                type="button"
                size="sm"
                onClick={handleNext}
                className="text-xs font-semibold"
              >
                Continue
                <ArrowRight className="ml-1.5 size-3.5" />
              </Button>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
