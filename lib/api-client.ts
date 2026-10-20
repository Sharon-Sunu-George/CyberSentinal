/**
 * CyberQuant API Client
 * Centralized client connecting the Next.js frontend to the FastAPI backend.
 */

const API_BASE_URL =
  process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000"

export interface BackendRiskAssessmentRequest {
  scenario_name: string
  asset_name: string
  asset_value: number
  threat_event_frequency: number
  vulnerability_probability: number
  direct_loss: number
  indirect_loss: number
  proposed_security_cost?: number
  mitigated_vulnerability_probability?: number | null
}

export interface BackendRiskMetrics {
  loss_event_frequency: number
  single_loss_expectancy: number
  annual_loss_expectancy: number
  mitigated_annual_loss_expectancy?: number | null
  annual_risk_reduction?: number | null
  security_roi_percentage?: number | null
}

export interface BackendRiskAssessmentResponse {
  scenario_name: string
  asset_name: string
  asset_value: number
  metrics: BackendRiskMetrics
  assumptions: string[]
  recommendation: string
}

export interface BackendAIProviderStatus {
  provider_name: string
  is_configured: boolean
  status: string
  model_type: string
  mode: string
  details: string
}

export interface BackendThreatScenarioResponse {
  scenario_id: string
  scenario_title: string
  scenario_kind: string
  severity: string
  description: string
  affected_asset_ids: string[]
  scenarios_remaining: number
}

export interface BackendDatasetResetResponse {
  status: string
  message: string
  total_assets: number
  baseline_restored: boolean
}

export interface BackendAttackSimulationRequest {
  asset_id: string
  attack_scenario: string
  threat_intensity: string
}

export interface BackendAttackStage {
  stage_number: number
  name: string
  description: string
  technique: string
  success_likelihood: number
  evidence: string
}

export interface BackendAttackSimulationResponse {
  asset_id: string
  asset_name: string
  attack_scenario: string
  threat_intensity: string
  baseline_risk_score: number
  simulated_risk_score: number
  is_compromise_modeled: boolean
  stages: BackendAttackStage[]
  affected_assets: string[]
  potential_business_impact: string
  exploit_factors: string[]
  suggested_defenses: string[]
}

export interface BackendDefenseSimulationRequest {
  asset_id: string
  baseline_risk_score: number
  simulated_risk_score: number
  selected_controls: string[]
  attack_scenario?: string
}

export interface BackendAppliedDefenseImpact {
  control_id: string
  control_name: string
  mitigation_reason: string
  points_reduced: number
}

export interface BackendDefenseSimulationResponse {
  asset_id: string
  asset_name: string
  pre_defense_risk_score: number
  residual_risk_score: number
  absolute_risk_reduction: number
  percentage_risk_reduction: number
  applied_controls: BackendAppliedDefenseImpact[]
  remaining_weaknesses: string[]
  recommended_next_action: string
}

export interface BackendReportSummary {
  critical: number
  high: number
  medium: number
  low: number
  total_findings: number
}

export interface BackendReportFinding {
  id: string
  title: string
  severity: "Critical" | "High" | "Medium" | "Low" | "Info"
  cvss_score?: number | null
  cve?: string | null
  asset?: string | null
  evidence?: string | Record<string, unknown> | null
  recommendation?: string | null
  is_inferred?: boolean
  source?: string | null
}

export interface BackendNormalizedRiskScenario {
  scenario_id: string
  scenario_name: string
  asset_name: string
  asset_value?: number | null
  threat_event_frequency?: number | null
  vulnerability_probability?: number | null
  direct_loss?: number | null
  indirect_loss?: number | null
  proposed_security_cost?: number | null
  mitigated_vulnerability_probability?: number | null
  is_inferred?: boolean
  metrics?: BackendRiskMetrics | null
  assumptions?: string[]
  recommendation?: string | null
}

export interface BackendParsedReportResponse {
  report_id: string
  target: string
  filename?: string | null
  detected_format?: string | null
  report_date?: string | null
  environment?: string | null
  report_type?: string | null
  notice?: string | null
  is_synthetic: boolean
  summary: BackendReportSummary
  findings: BackendReportFinding[]
  scenarios?: BackendNormalizedRiskScenario[]
  extracted_text_preview?: string | null
  calculated_metrics?: BackendRiskMetrics | null
  warnings?: string[]
  missing_fields?: string[]
  analysis_status?: string
  ai_status?: string
  ocr_status?: string
}


export const apiClient = {
  baseUrl: API_BASE_URL,

  async checkHealth(): Promise<{ status: string; service: string; version: string }> {
    const res = await fetch(`${API_BASE_URL}/api/v1/risk/health`)
    if (!res.ok) throw new Error(`Health check failed: HTTP ${res.status}`)
    return res.json()
  },

  async assessRisk(payload: BackendRiskAssessmentRequest): Promise<BackendRiskAssessmentResponse> {
    const res = await fetch(`${API_BASE_URL}/api/v1/risk/assess`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    })
    if (!res.ok) {
      let errorDetail = `HTTP ${res.status}`
      try {
        const errorJson = await res.json()
        if (errorJson.detail) errorDetail = typeof errorJson.detail === "string" ? errorJson.detail : JSON.stringify(errorJson.detail)
      } catch {
        const text = await res.text().catch(() => "")
        if (text) errorDetail = text
      }
      throw new Error(`Risk assessment failed: ${errorDetail}`)
    }
    return res.json()
  },

  async uploadReport(file: File): Promise<BackendParsedReportResponse> {
    const formData = new FormData()
    formData.append("file", file)
    const res = await fetch(`${API_BASE_URL}/api/v1/reports/upload`, {
      method: "POST",
      body: formData,
    })
    if (!res.ok) {
      let errorDetail = `HTTP ${res.status}`
      try {
        const errorJson = await res.json()
        if (errorJson.detail) errorDetail = typeof errorJson.detail === "string" ? errorJson.detail : JSON.stringify(errorJson.detail)
      } catch {
        const text = await res.text().catch(() => "")
        if (text) errorDetail = text
      }
      throw new Error(`Report upload failed: ${errorDetail}`)
    }
    return res.json()
  },

  async getAiStatus(): Promise<BackendAIProviderStatus> {
    const res = await fetch(`${API_BASE_URL}/api/v1/settings/ai-status`)
    if (!res.ok) throw new Error(`AI status fetch failed: HTTP ${res.status}`)
    return res.json()
  },

  async runScenario(): Promise<BackendThreatScenarioResponse> {
    const res = await fetch(`${API_BASE_URL}/api/v1/settings/run-scenario`, {
      method: "POST",
    })
    if (!res.ok) throw new Error(`Run scenario failed: HTTP ${res.status}`)
    return res.json()
  },

  async resetDataset(): Promise<BackendDatasetResetResponse> {
    const res = await fetch(`${API_BASE_URL}/api/v1/settings/reset-dataset`, {
      method: "POST",
    })
    if (!res.ok) throw new Error(`Reset dataset failed: HTTP ${res.status}`)
    return res.json()
  },

  async simulateAttack(payload: BackendAttackSimulationRequest): Promise<BackendAttackSimulationResponse> {
    const res = await fetch(`${API_BASE_URL}/api/v1/simulation/attack`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    })
    if (!res.ok) throw new Error(`Attack simulation failed: HTTP ${res.status}`)
    return res.json()
  },

  async simulateDefense(payload: BackendDefenseSimulationRequest): Promise<BackendDefenseSimulationResponse> {
    const res = await fetch(`${API_BASE_URL}/api/v1/simulation/defend`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    })
    if (!res.ok) throw new Error(`Defense simulation failed: HTTP ${res.status}`)
    return res.json()
  },
}

