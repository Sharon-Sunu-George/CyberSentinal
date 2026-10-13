/**
 * CyberQuant API Client
 * Centralized client connecting the Next.js frontend to the FastAPI backend.
 */

const API_BASE_URL =
  process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8010"

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
      const errorText = await res.text().catch(() => "")
      throw new Error(`Risk assessment failed: HTTP ${res.status} ${errorText}`)
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
