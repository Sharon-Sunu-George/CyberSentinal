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

  // Real Website Security Assessment (Attacker Agent)
  async scanWebsite(payload: {
    target_url: string
    is_authorized: boolean
    scanner_mode?: string
    max_pages?: number
    max_depth?: number
    timeout_seconds?: number
  }): Promise<AttackerScanResponse> {
    const res = await fetch(`${API_BASE_URL}/api/v1/attacker/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    })
    if (!res.ok) {
      const errorJson = await res.json().catch(() => null)
      const detail = errorJson?.detail || (await res.text().catch(() => "Unknown error"))
      throw new Error(detail)
    }
    return res.json()
  },

  async startCrawl(payload: {
    target_url: string
    is_authorized: boolean
    scanner_mode?: string
    max_pages?: number
    max_depth?: number
    timeout_seconds?: number
  }): Promise<{ scan_id: string; status: string; target_url: string; message: string }> {
    const res = await fetch(`${API_BASE_URL}/api/v1/attacker/crawl`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    })
    if (!res.ok) {
      const errorJson = await res.json().catch(() => null)
      const detail = errorJson?.detail || (await res.text().catch(() => "Unknown error"))
      throw new Error(detail)
    }
    return res.json()
  },

  async getScanProgress(scanId: string): Promise<ScanProgressUpdate> {
    const res = await fetch(`${API_BASE_URL}/api/v1/attacker/scan/${scanId}/progress`)
    if (!res.ok) throw new Error(`Failed to load progress: HTTP ${res.status}`)
    return res.json()
  },

  async getScanPages(scanId: string): Promise<DiscoveredPage[]> {
    const res = await fetch(`${API_BASE_URL}/api/v1/attacker/scan/${scanId}/pages`)
    if (!res.ok) throw new Error(`Failed to load pages: HTTP ${res.status}`)
    return res.json()
  },

  async getScanRecord(scanId: string): Promise<AttackerScanResponse> {
    const res = await fetch(`${API_BASE_URL}/api/v1/attacker/scan/${scanId}`)
    if (!res.ok) throw new Error(`Failed to load scan record: HTTP ${res.status}`)
    return res.json()
  },

  async cancelScan(scanId: string): Promise<{ scan_id: string; status: string; message: string }> {
    const res = await fetch(`${API_BASE_URL}/api/v1/attacker/scan/${scanId}/cancel`, {
      method: "POST",
    })
    if (!res.ok) throw new Error(`Cancel scan failed: HTTP ${res.status}`)
    return res.json()
  },

  async rescanTarget(scanId: string): Promise<AttackerScanResponse> {
    const res = await fetch(`${API_BASE_URL}/api/v1/attacker/scan/${scanId}/rescan`, {
      method: "POST",
    })
    if (!res.ok) {
      const errorJson = await res.json().catch(() => null)
      const detail = errorJson?.detail || (await res.text().catch(() => "Unknown error"))
      throw new Error(detail)
    }
    return res.json()
  },

  async getScannerStatus(): Promise<{
    engine: string
    active_concurrent_scans: number
    max_concurrent_capacity: number
    owasp_zap: {
      is_available: boolean
      service_name: string
      endpoint: string
      version?: string | null
      instructions: string
    }
    local_dev_scan?: {
      is_enabled: boolean
      target?: string | null
      allowed_host?: string | null
      allowed_port?: number | null
    }
    supported_checks: string[]
  }> {
    const res = await fetch(`${API_BASE_URL}/api/v1/attacker/scanner-status`)
    if (!res.ok) throw new Error(`Failed to fetch scanner status: HTTP ${res.status}`)
    return res.json()
  },

  // Real Remediation Planning & Budgeting (Defender Agent)
  async analyzeDefenderBudget(payload: {
    scan_id?: string
    target_url: string
    findings: any[]
    available_budget: number
    hourly_rate?: number
    business_criticality?: string
  }): Promise<DefenderAnalysisResponse> {
    const res = await fetch(`${API_BASE_URL}/api/v1/defender/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    })
    if (!res.ok) {
      const errorJson = await res.json().catch(() => null)
      const detail = errorJson?.detail || (await res.text().catch(() => "Unknown error"))
      throw new Error(detail)
    }
    return res.json()
  },

  async updateRemediationStatus(
    scanId: string,
    findingId: string,
    status: string,
    notes?: string
  ): Promise<{ scan_id: string; finding_id: string; remediation_status: string; updated: boolean }> {
    const res = await fetch(`${API_BASE_URL}/api/v1/defender/remediation/${scanId}/${findingId}/status`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ status, notes }),
    })
    if (!res.ok) {
      const errorJson = await res.json().catch(() => null)
      const detail = errorJson?.detail || (await res.text().catch(() => "Unknown error"))
      throw new Error(detail)
    }
    return res.json()
  },

  async getDefenderPlan(scanId: string): Promise<DefenderAnalysisResponse> {
    const res = await fetch(`${API_BASE_URL}/api/v1/defender/scans/${scanId}/plan`)
    if (!res.ok) throw new Error(`Failed to load remediation plan: HTTP ${res.status}`)
    return res.json()
  },

  async getDefenderSettings(): Promise<{
    currency: string
    default_hourly_rate: number
    valid_statuses: string[]
    cost_assumptions: string[]
  }> {
    const res = await fetch(`${API_BASE_URL}/api/v1/defender/settings`)
    if (!res.ok) throw new Error(`Failed to fetch defender settings: HTTP ${res.status}`)
    return res.json()
  },
}

export interface FindingEvidence {
  check_type: string
  observed_data: Record<string, any>
  raw_snippet?: string | null
  status_code?: number | null
}

export interface VulnerabilityFinding {
  id: string
  title: string
  category: string
  severity: "Critical" | "High" | "Medium" | "Low" | "Info"
  confidence: "High" | "Medium" | "Low"
  affected_url_or_component: string
  evidence: FindingEvidence
  potential_impact: string
  remediation: string
  cwe_id?: string | null
  cve_id?: string | null
  scanner_name: string
  scanned_at?: string | null
  references: string[]
  is_confirmed: boolean
  validation_status: string
  remediation_status: "Open" | "Planned" | "In Progress" | "Fixed" | "Accepted Risk" | "Verified"
}

export interface InferredAttackScenario {
  scenario_title: string
  adversary_technique: string
  preconditions: string[]
  modeled_chain: string[]
  potential_impact: string
  confidence: string
}

export interface DiscoveredForm {
  action: string
  method: string
  input_names: string[]
}

export interface DiscoveredRequest {
  url: string
  method: string
  resource_type: string
  status?: number | null
}

export interface DiscoveredPage {
  url: string
  path: string
  depth: number
  status_code?: number | null
  content_type?: string | null
  title?: string | null
  query_params: string[]
  forms: DiscoveredForm[]
  requests: DiscoveredRequest[]
  discovery_source: string
  discovered_at?: string | null
}

export interface ScanProgressUpdate {
  scan_id: string
  status: "queued" | "running" | "completed" | "failed" | "cancelled"
  pages_discovered: number
  pages_visited: number
  requests_completed: number
  current_url?: string | null
  current_depth: number
  findings_count: number
  progress_percentage: number
  message: string
  started_at?: string | null
  elapsed_seconds: number
  completed_at?: string | null
  error?: string | null
}

export interface AttackerScanSummary {
  total_findings: number
  critical_count: number
  high_count: number
  medium_count: number
  low_count: number
  info_count: number
  confirmed_count: number
  pages_discovered?: number
  pages_visited?: number
  requests_completed?: number
}

export interface AttackerScanResponse {
  scan_id: string
  target_url: string
  normalized_url: string
  scanned_at: string
  status: string
  target_ip?: string | null
  scanner_info: {
    engine?: string
    mode?: string
    zap_integration?: {
      is_available: boolean
      service_name: string
      endpoint: string
      version?: string | null
      instructions: string
    }
    checks_executed?: string[]
  }
  scope_limitations: string
  zero_findings_disclaimer?: string | null
  summary: AttackerScanSummary
  findings: VulnerabilityFinding[]
  discovered_pages?: DiscoveredPage[]
  inferred_attack_scenarios: InferredAttackScenario[]
  defender_handover: Record<string, any>
}

export interface RemediationRecommendation {
  finding_id: string
  finding_title: string
  severity: "Critical" | "High" | "Medium" | "Low" | "Info"
  category: string
  cwe_id?: string | null
  cve_id?: string | null
  affected_url_or_component: string
  root_cause: string
  actionable_fix: string
  implementation_steps: string[]
  code_snippets: Record<string, string>
  estimated_effort_hours: number
  hourly_rate: number
  labor_cost: number
  service_cost: number
  total_cost: number
  risk_score: number
  projected_risk_reduction: number
  cost_efficiency: number
  priority_group: "fix_immediately" | "fix_next" | "defer_or_mitigate"
  priority_rationale: string
  deferral_reason?: string | null
  temporary_mitigation?: string | null
  dependencies: string[]
  assumptions: string[]
  confidence_range: string
  verification_procedure: string
  status: "Open" | "Planned" | "In Progress" | "Fixed" | "Accepted Risk" | "Verified"
  status_notes?: string | null
}

export interface DefenderAnalysisResponse {
  analysis_id: string
  scan_id?: string | null
  target_url: string
  currency: string
  available_budget: number
  hourly_rate: number
  total_remediation_cost: number
  proposed_spending: number
  remaining_budget: number
  budget_shortfall: number
  baseline_risk_score: number
  projected_residual_risk: number
  total_risk_reduction_points: number
  total_risk_reduction_percent: number
  risk_reduction_per_dollar: number
  fix_immediately: RemediationRecommendation[]
  fix_next: RemediationRecommendation[]
  defer_or_mitigate: RemediationRecommendation[]
  unbudgeted_high_risk_findings: RemediationRecommendation[]
  scoring_model_notes: string[]
  created_at: string
}
