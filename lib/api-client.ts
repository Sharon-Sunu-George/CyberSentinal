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

  async getRecentScans(limit: number = 10): Promise<Array<{
    scan_id: string
    target_url: string
    normalized_url: string
    scanned_at: string
    status: string
    target_ip?: string | null
    summary: AttackerScanSummary
    created_at: string
  }>> {
    const res = await fetch(`${API_BASE_URL}/api/v1/attacker/recent?limit=${limit}`)
    if (!res.ok) throw new Error(`Failed to load recent scans: HTTP ${res.status}`)
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
    currency?: string
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

  async verifyRemediation(
    scanId: string,
    findingId: string,
    targetUrl?: string
  ): Promise<VerifyRemediationResponse> {
    const res = await fetch(`${API_BASE_URL}/api/v1/defender/remediation/${scanId}/${findingId}/verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target_url: targetUrl }),
    })
    if (!res.ok) {
      const errorJson = await res.json().catch(() => null)
      const detail = errorJson?.detail || (await res.text().catch(() => "Unknown error"))
      throw new Error(detail)
    }
    return res.json()
  },

  async getRemediationHistory(
    scanId: string,
    findingId?: string
  ): Promise<{
    scan_id: string
    finding_id?: string
    total_events: number
    history: Array<{
      id: number
      scan_id: string
      finding_id: string
      old_status: string
      new_status: string
      evidence?: any
      notes?: string
      changed_at: string
    }>
  }> {
    const query = findingId ? `?finding_id=${encodeURIComponent(findingId)}` : ""
    const res = await fetch(`${API_BASE_URL}/api/v1/defender/remediation/${scanId}/history${query}`)
    if (!res.ok) throw new Error(`Failed to load remediation history: HTTP ${res.status}`)
    return res.json()
  },

  async getDefenderPlan(scanId: string): Promise<DefenderAnalysisResponse> {
    const res = await fetch(`${API_BASE_URL}/api/v1/defender/scans/${scanId}/plan`)
    if (!res.ok) throw new Error(`Failed to load remediation plan: HTTP ${res.status}`)
    return res.json()
  },

  async getDefenderSettings(): Promise<{
    currencies: string[]
    default_currency: string
    default_hourly_rate: number
    valid_statuses: string[]
    lifecycle_stages: string[]
    cost_assumptions: string[]
  }> {
    const res = await fetch(`${API_BASE_URL}/api/v1/defender/settings`)
    if (!res.ok) throw new Error(`Failed to fetch defender settings: HTTP ${res.status}`)
    return res.json()
  },
}

export interface FindingEvidence {
  check_type: string
  evidence_source?: string
  observed_value?: string | null
  expected_condition?: string | null
  observed_data: Record<string, any>
  raw_snippet?: string | null
  status_code?: number | null
  requested_url?: string | null
  final_url?: string | null
  redirect_chain?: Array<{ from_url: string; to_url: string; status_code: number }>
  observed_headers?: Record<string, string>
  check_result?: string | null
  confidence_reason?: string | null
  is_inferred?: boolean
  response_timestamp?: string | null
}

export interface VulnerabilityFinding {
  id: string
  title: string
  category: string
  severity: "Critical" | "High" | "Medium" | "Low" | "Info"
  severity_reason?: string | null
  confidence: "High" | "Medium" | "Low"
  affected_url_or_component: string
  affected_urls?: string[]
  occurrence_count?: number
  fingerprint?: string | null
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

export interface ThreatIntelligenceMatch {
  provider: string
  status: "match_detected" | "no_match" | "service_unavailable" | "unconfigured" | "lookup_failed"
  threat_type?: string | null
  details?: string | null
  cached: boolean
  lookup_timestamp: string
  reference_url?: string | null
}

export interface ImpersonationSignal {
  signal_type: "homoglyph" | "punycode" | "typosquatting" | "brand_name_in_subdomain" | "suspicious_redirect" | "copied_branding_with_credentials"
  severity: "High" | "Medium" | "Low" | "Info"
  target_brand?: string | null
  official_domain?: string | null
  description: string
  evidence: Record<string, any>
}

export interface WebsiteTrustAssessment {
  trust_state: "Known Malicious / Phishing" | "Likely Impersonation" | "Suspicious" | "No Known Threat Detected" | "Inconclusive"
  trust_score_label: string
  canonical_url: string
  canonical_domain: string
  is_duplicate_scan: boolean
  duplicate_of_scan_id?: string | null
  threat_intel_matches: ThreatIntelligenceMatch[]
  impersonation_signals: ImpersonationSignal[]
  reputation_providers_configured: boolean
  confidence: "High" | "Medium" | "Low"
  assessment_notes: string[]
  assessed_at: string
}

export interface AttackerScanResponse {
  scan_id: string
  target_url: string
  normalized_url: string
  scanned_at: string
  status: string
  target_class?: string
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
  is_inconclusive?: boolean
  allows_retry?: boolean
  summary: AttackerScanSummary
  findings: VulnerabilityFinding[]
  discovered_pages?: DiscoveredPage[]
  inferred_attack_scenarios: InferredAttackScenario[]
  defender_handover: Record<string, any>
  trust_assessment?: WebsiteTrustAssessment | null
}

export interface RemediationRecommendation {
  finding_id: string
  finding_title: string
  severity: "Critical" | "High" | "Medium" | "Low" | "Info"
  confidence?: "High" | "Medium" | "Low"
  category: string
  cwe_id?: string | null
  cve_id?: string | null
  affected_url_or_component: string
  short_explanation?: string
  why_it_matters?: string
  root_cause: string
  actionable_fix: string
  recommended_fix?: string
  implementation_steps: string[]
  code_snippets: Record<string, string>
  file_or_config_location?: string
  implementation_difficulty?: "Easy" | "Moderate" | "Hard"
  estimated_effort_hours: number
  hourly_rate: number
  currency?: string
  labor_cost: number
  service_cost: number
  total_cost: number
  cost_assumption?: string
  risk_score: number
  priority_score?: number
  priority_explanation?: string
  projected_risk_reduction: number
  risk_reduction_expected?: string
  cost_efficiency: number
  priority_group: "fix_immediately" | "fix_next" | "defer_or_mitigate"
  priority_rationale: string
  deferral_reason?: string | null
  temporary_mitigation?: string | null
  dependencies_and_side_effects?: string
  dependencies: string[]
  assumptions: string[]
  confidence_range: string
  validation_steps?: string[]
  verification_procedure: string
  rollback_guidance?: string
  status: "Not Started" | "In Progress" | "Fixed Pending Verification" | "Verified Fixed" | "Reopened" | "Open" | "Planned" | "Fixed" | "Accepted Risk" | "Verified" | "Needs Verification"
  remediation_status?: string
  status_notes?: string | null
  verification_evidence?: Record<string, any> | null
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
  cost_assumptions?: string[]
  created_at: string
}

export interface VerifyRemediationResponse {
  scan_id: string
  finding_id: string
  target_url: string
  previous_status: string
  new_status: string
  is_verified: boolean
  verification_passed: boolean
  is_inconclusive: boolean
  evidence_summary: string
  observed_headers: Record<string, string>
  observed_status?: number | null
  verification_timestamp: string
  message: string
}
