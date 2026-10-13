"use client"

import { useState } from "react"
import {
  ArrowLeft,
  ArrowRight,
  BrainCircuit,
  Building2,
  Loader2,
  RotateCcw,
  Server,
  Settings,
  Shield,
  ShieldAlert,
  Zap,
} from "lucide-react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Textarea } from "@/components/ui/textarea"
import { useAppState } from "@/components/app/app-state"
import { apiClient } from "@/lib/api-client"

export interface QuestionnaireForm {
  org_name: string
  industry_type: string
  asset_name: string
  asset_type: string
  business_criticality: string
  internet_exposure: string
  asset_value: number
  threat_event_frequency: number
  vulnerability_probability: number
  known_vulnerabilities: string
  security_controls: {
    mfa: boolean
    edr: boolean
    patching: boolean
    segmentation: boolean
    backup: boolean
  }
  direct_loss: number
  indirect_loss: number
  proposed_security_cost: number
  mitigated_vulnerability_probability: number
}

const DEFAULT_FORM: QuestionnaireForm = {
  org_name: "FinSecure Technologies",
  industry_type: "Financial Services / FinTech",
  asset_name: "Customer Core Banking & PII Database",
  asset_type: "Database",
  business_criticality: "Critical",
  internet_exposure: "Internet-facing",
  asset_value: 5000000,
  threat_event_frequency: 2.0,
  vulnerability_probability: 0.35,
  known_vulnerabilities: "Legacy authentication endpoint, unpatched OpenSSL library",
  security_controls: {
    mfa: true,
    edr: false,
    patching: false,
    segmentation: true,
    backup: true,
  },
  direct_loss: 150000,
  indirect_loss: 300000,
  proposed_security_cost: 50000,
  mitigated_vulnerability_probability: 0.1,
}

export function RiskAssessmentView() {
  const { navigate, recordRiskAssessment } = useAppState()
  const [form, setForm] = useState<QuestionnaireForm>(DEFAULT_FORM)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const handleControlToggle = (control: keyof QuestionnaireForm["security_controls"]) => {
    setForm((prev) => ({
      ...prev,
      security_controls: {
        ...prev.security_controls,
        [control]: !prev.security_controls[control],
      },
    }))
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError(null)

    // Form field validations
    if (!form.org_name.trim()) {
      setError("Please enter your organization name.")
      return
    }
    if (!form.asset_name.trim()) {
      setError("Please enter the primary asset name.")
      return
    }
    if (form.asset_value <= 0) {
      setError("Asset value must be greater than 0.")
      return
    }

    setLoading(true)

    // Construct backend payload compatible with FastAPI POST /api/v1/risk/assess
    const payload = {
      scenario_name: `${form.org_name} - ${form.asset_name} Risk Evaluation`,
      asset_name: form.asset_name,
      asset_value: Number(form.asset_value),
      threat_event_frequency: Number(form.threat_event_frequency),
      vulnerability_probability: Number(form.vulnerability_probability),
      direct_loss: Number(form.direct_loss),
      indirect_loss: Number(form.indirect_loss),
      proposed_security_cost: Number(form.proposed_security_cost),
      mitigated_vulnerability_probability: Number(form.mitigated_vulnerability_probability),
    }

    try {
      // Send questionnaire to FastAPI risk engine
      const data = await apiClient.assessRisk(payload)
      recordRiskAssessment(data)
      navigate("overview")
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Failed to connect to risk assessment engine"
      setError(`Quantification failed: ${msg}. Please ensure the FastAPI backend is running on http://127.0.0.1:8010.`)
    } finally {
      setLoading(false)
    }
  }

  const handleReset = () => {
    setForm(DEFAULT_FORM)
    setError(null)
  }

  return (
    <div className="flex min-h-svh w-full flex-col items-center justify-start p-4 md:p-8">
      <div className="w-full max-w-4xl space-y-6">
        {/* Top bar with Back button and Settings link */}
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
            <span className="text-xs text-muted-foreground">· Assessment Questionnaire</span>
          </div>

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

        {/* Title Header */}
        <div>
          <div className="flex items-center gap-2 text-primary font-semibold text-lg">
            <BrainCircuit className="size-5" />
            <span>Cyber Risk Analysis Questionnaire</span>
          </div>
          <p className="text-xs text-muted-foreground mt-0.5">
            Provide organization context, asset classification, and security control signals to calibrate the risk quantification engine.
          </p>
        </div>

        {/* Clear Error Feedback Banner */}
        {error && (
          <div className="flex items-start gap-2.5 rounded-lg border border-destructive/30 bg-destructive/10 p-3.5 text-xs text-destructive">
            <ShieldAlert className="size-4 shrink-0 mt-0.5" />
            <div className="flex-1 space-y-0.5">
              <p className="font-semibold">Assessment Request Failed</p>
              <p className="text-destructive/90">{error}</p>
            </div>
          </div>
        )}

        {/* Questionnaire Form */}
        <form onSubmit={handleSubmit} className="space-y-6">
          {/* Section 1: Organization & Industry Context */}
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-semibold flex items-center gap-2">
                <Building2 className="size-4 text-primary" /> 1. Organization & Industry Context
              </CardTitle>
              <CardDescription className="text-xs">
                General profile used to benchmark threat frequency and regulatory baseline impact.
              </CardDescription>
            </CardHeader>
            <CardContent className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div className="space-y-1.5">
                <label className="text-xs font-medium text-foreground">Organization Name *</label>
                <Input
                  type="text"
                  value={form.org_name}
                  onChange={(e) => setForm({ ...form, org_name: e.target.value })}
                  required
                  placeholder="e.g. Acme Financial"
                />
              </div>

              <div className="space-y-1.5">
                <label className="text-xs font-medium text-foreground">Industry Sector</label>
                <select
                  value={form.industry_type}
                  onChange={(e) => setForm({ ...form, industry_type: e.target.value })}
                  className="flex h-9 w-full rounded-md border border-input bg-background px-3 py-1.5 text-xs text-foreground outline-none focus-visible:border-ring focus-visible:ring-2 focus-visible:ring-ring"
                >
                  <option value="Financial Services / FinTech">Financial Services / FinTech</option>
                  <option value="Healthcare & Life Sciences">Healthcare & Life Sciences</option>
                  <option value="E-Commerce & Retail">E-Commerce & Retail</option>
                  <option value="SaaS & Cloud Infrastructure">SaaS & Cloud Infrastructure</option>
                  <option value="Energy & Critical Infrastructure">Energy & Critical Infrastructure</option>
                  <option value="Government & Education">Government & Education</option>
                  <option value="Other / General Enterprise">Other / General Enterprise</option>
                </select>
              </div>
            </CardContent>
          </Card>

          {/* Section 2: Asset Profile & Exposure */}
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-semibold flex items-center gap-2">
                <Server className="size-4 text-primary" /> 2. Asset Profile & Valuation
              </CardTitle>
              <CardDescription className="text-xs">
                Specify the primary digital asset, its criticality, and estimated business value.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div className="space-y-1.5">
                  <label className="text-xs font-medium text-foreground">Asset Name *</label>
                  <Input
                    type="text"
                    value={form.asset_name}
                    onChange={(e) => setForm({ ...form, asset_name: e.target.value })}
                    required
                    placeholder="e.g. Customer Core Banking & PII Database"
                  />
                </div>

                <div className="space-y-1.5">
                  <label className="text-xs font-medium text-foreground">Asset Type</label>
                  <select
                    value={form.asset_type}
                    onChange={(e) => setForm({ ...form, asset_type: e.target.value })}
                    className="flex h-9 w-full rounded-md border border-input bg-background px-3 py-1.5 text-xs text-foreground outline-none focus-visible:border-ring focus-visible:ring-2 focus-visible:ring-ring"
                  >
                    <option value="Database">Database (PostgreSQL / DynamoDB / Oracle)</option>
                    <option value="Application Server">Application Server / API Microservices</option>
                    <option value="Identity Server">Identity Server (Active Directory / Okta)</option>
                    <option value="Web Server">Web Server (Public Facing)</option>
                    <option value="Backup System">Backup & Disaster Recovery Tier</option>
                    <option value="Network Appliance">Network Appliance / VPN Gateway</option>
                  </select>
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                <div className="space-y-1.5">
                  <label className="text-xs font-medium text-foreground">Business Criticality</label>
                  <select
                    value={form.business_criticality}
                    onChange={(e) => setForm({ ...form, business_criticality: e.target.value })}
                    className="flex h-9 w-full rounded-md border border-input bg-background px-3 py-1.5 text-xs text-foreground outline-none focus-visible:border-ring focus-visible:ring-2 focus-visible:ring-ring"
                  >
                    <option value="Critical">Critical (Tier 1 core operations)</option>
                    <option value="High">High (High business impact)</option>
                    <option value="Medium">Medium (Internal business tool)</option>
                    <option value="Low">Low (Development / Non-critical)</option>
                  </select>
                </div>

                <div className="space-y-1.5">
                  <label className="text-xs font-medium text-foreground">Network Exposure</label>
                  <select
                    value={form.internet_exposure}
                    onChange={(e) => setForm({ ...form, internet_exposure: e.target.value })}
                    className="flex h-9 w-full rounded-md border border-input bg-background px-3 py-1.5 text-xs text-foreground outline-none focus-visible:border-ring focus-visible:ring-2 focus-visible:ring-ring"
                  >
                    <option value="Internet-facing">Internet-facing (Public Web)</option>
                    <option value="Partner network">Partner / Third-Party VPC</option>
                    <option value="Internal">Internal (Restricted subnet)</option>
                  </select>
                </div>

                <div className="space-y-1.5">
                  <label className="text-xs font-medium text-foreground">Asset Value ($ USD) *</label>
                  <Input
                    type="number"
                    min={1}
                    value={form.asset_value}
                    onChange={(e) => setForm({ ...form, asset_value: Number(e.target.value) })}
                    required
                    className="font-mono text-xs"
                  />
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Section 3: Threat Signals & Existing Security Controls */}
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-semibold flex items-center gap-2">
                <Shield className="size-4 text-primary" /> 3. Threat Signals & Active Security Controls
              </CardTitle>
              <CardDescription className="text-xs">
                Active security safeguards and observed threat parameters.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <label className="text-xs font-medium text-foreground block">Active Defensive Safeguards</label>
                <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 text-xs">
                  <label className="flex items-center gap-2 rounded-md border p-2.5 cursor-pointer bg-card hover:bg-muted/30 transition-colors">
                    <input
                      type="checkbox"
                      checked={form.security_controls.mfa}
                      onChange={() => handleControlToggle("mfa")}
                      className="rounded border-input text-primary focus:ring-primary size-4"
                    />
                    <span>MFA Enforced</span>
                  </label>

                  <label className="flex items-center gap-2 rounded-md border p-2.5 cursor-pointer bg-card hover:bg-muted/30 transition-colors">
                    <input
                      type="checkbox"
                      checked={form.security_controls.edr}
                      onChange={() => handleControlToggle("edr")}
                      className="rounded border-input text-primary focus:ring-primary size-4"
                    />
                    <span>EDR Deployed</span>
                  </label>

                  <label className="flex items-center gap-2 rounded-md border p-2.5 cursor-pointer bg-card hover:bg-muted/30 transition-colors">
                    <input
                      type="checkbox"
                      checked={form.security_controls.patching}
                      onChange={() => handleControlToggle("patching")}
                      className="rounded border-input text-primary focus:ring-primary size-4"
                    />
                    <span>Automated Patching</span>
                  </label>

                  <label className="flex items-center gap-2 rounded-md border p-2.5 cursor-pointer bg-card hover:bg-muted/30 transition-colors">
                    <input
                      type="checkbox"
                      checked={form.security_controls.segmentation}
                      onChange={() => handleControlToggle("segmentation")}
                      className="rounded border-input text-primary focus:ring-primary size-4"
                    />
                    <span>Micro-segmentation</span>
                  </label>

                  <label className="flex items-center gap-2 rounded-md border p-2.5 cursor-pointer bg-card hover:bg-muted/30 transition-colors">
                    <input
                      type="checkbox"
                      checked={form.security_controls.backup}
                      onChange={() => handleControlToggle("backup")}
                      className="rounded border-input text-primary focus:ring-primary size-4"
                    />
                    <span>Isolated Backups</span>
                  </label>
                </div>
              </div>

              <div className="space-y-1.5">
                <label className="text-xs font-medium text-foreground">Known Vulnerabilities / Scanner Findings</label>
                <Textarea
                  value={form.known_vulnerabilities}
                  onChange={(e) => setForm({ ...form, known_vulnerabilities: e.target.value })}
                  placeholder="e.g. CVE-2024-XXXX finding, unpatched API endpoint, weak TLS cipher"
                  className="text-xs min-h-[60px]"
                />
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 border-t pt-3">
                <div className="space-y-1.5">
                  <label className="text-xs font-medium text-foreground">Threat Frequency (TEF / yr)</label>
                  <Input
                    type="number"
                    step="0.1"
                    min={0}
                    value={form.threat_event_frequency}
                    onChange={(e) => setForm({ ...form, threat_event_frequency: Number(e.target.value) })}
                    className="font-mono text-xs"
                  />
                  <span className="text-[10px] text-muted-foreground">Expected attack attempts per year</span>
                </div>

                <div className="space-y-1.5">
                  <label className="text-xs font-medium text-foreground">Vulnerability Probability (0.0 - 1.0)</label>
                  <Input
                    type="number"
                    step="0.01"
                    min={0}
                    max={1}
                    value={form.vulnerability_probability}
                    onChange={(e) => setForm({ ...form, vulnerability_probability: Number(e.target.value) })}
                    className="font-mono text-xs"
                  />
                  <span className="text-[10px] text-muted-foreground">Probability of an exploit succeeding</span>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Section 4: Loss Impact Parameters */}
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-semibold flex items-center gap-2">
                <Zap className="size-4 text-primary" /> 4. Financial Impact Estimates
              </CardTitle>
              <CardDescription className="text-xs">
                Estimated single loss magnitude components per breach incident.
              </CardDescription>
            </CardHeader>
            <CardContent className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div className="space-y-1.5">
                <label className="text-xs font-medium text-foreground">Direct Loss per Breach ($ USD)</label>
                <Input
                  type="number"
                  min={0}
                  value={form.direct_loss}
                  onChange={(e) => setForm({ ...form, direct_loss: Number(e.target.value) })}
                  className="font-mono text-xs"
                />
                <span className="text-[10px] text-muted-foreground">Forensics, incident response, repair</span>
              </div>

              <div className="space-y-1.5">
                <label className="text-xs font-medium text-foreground">Indirect Loss per Breach ($ USD)</label>
                <Input
                  type="number"
                  min={0}
                  value={form.indirect_loss}
                  onChange={(e) => setForm({ ...form, indirect_loss: Number(e.target.value) })}
                  className="font-mono text-xs"
                />
                <span className="text-[10px] text-muted-foreground">Fines, churn, customer notification</span>
              </div>
            </CardContent>
          </Card>

          {/* Error Banner */}
          {error && (
            <div className="rounded-md bg-destructive/10 border border-destructive/20 p-3 text-xs text-destructive flex items-center gap-2">
              <ShieldAlert className="size-4 shrink-0" />
              <span>{error}</span>
            </div>
          )}

          {/* Action Buttons */}
          <div className="flex flex-col sm:flex-row items-center justify-between gap-3 pt-2">
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={handleReset}
              className="w-full sm:w-auto"
            >
              <RotateCcw className="size-3.5 mr-1.5" />
              Reset Form
            </Button>

            <div className="flex items-center gap-3 w-full sm:w-auto">
              <Button
                type="button"
                variant="ghost"
                size="sm"
                onClick={() => navigate("landing")}
                className="w-full sm:w-auto"
              >
                Cancel
              </Button>

              <Button
                type="submit"
                disabled={loading}
                className="w-full sm:w-auto font-medium"
              >
                {loading ? (
                  <>
                    <Loader2 className="mr-2 size-4 animate-spin" />
                    Submitting & Quantifying…
                  </>
                ) : (
                  <>
                    Submit & Open Dashboard
                    <ArrowRight className="ml-1.5 size-4" />
                  </>
                )}
              </Button>
            </div>
          </div>
        </form>
      </div>
    </div>
  )
}
