export type Criticality = "Critical" | "High" | "Medium" | "Low"
export type Severity = "Critical" | "High" | "Medium" | "Low"
export type RiskCategory = "Critical" | "High" | "Medium" | "Low"
export type Exposure = "Internet-facing" | "Partner network" | "Internal"
export type ControlStatus = "Active" | "Partial" | "Missing" | "Unavailable"
export type ExploitStatus = "Exploited (simulated intel)" | "Public PoC" | "None known"
export type Effort = "Low" | "Medium" | "High"

export type ControlKey = "mfa" | "edr" | "patching" | "segmentation" | "backup"

export type AssetType =
  | "Application Server"
  | "Database"
  | "Identity Server"
  | "Workstation"
  | "Backup System"
  | "API Gateway"
  | "Network Appliance"
  | "Web Server"
  | "Integration Hub"

export interface Asset {
  id: string
  name: string
  type: AssetType
  owner: string
  criticality: Criticality
  exposure: Exposure
  /** 0–1: strength of simulated threat-intelligence signals targeting this asset */
  threatEvidence: number
  openHighSeverityIncidents: number
  /** Total open findings, including lower-severity items not itemised below */
  openVulnerabilityCount: number
  controls: Record<ControlKey, ControlStatus>
}

export interface Vulnerability {
  id: string
  /** Fictional identifier. Always demo data — never a real CVE. */
  demoId: string
  title: string
  assetId: string
  cvss: number
  exploitStatus: ExploitStatus
  patchAvailable: boolean
  remediated: boolean
  lastAssessed: string
  remediation: string
}

export interface Dataset {
  assets: Asset[]
  vulnerabilities: Vulnerability[]
}

export interface RiskFactor {
  key: "criticality" | "exposure" | "vulnerability" | "threat" | "incidents" | "controls"
  label: string
  weight: number
  /** normalised 0–1 input */
  value: number
  /** points contributed to the 0–100 score */
  contribution: number
  detail: string
}

export interface AssetRisk {
  asset: Asset
  score: number
  category: RiskCategory
  rank: number
  factors: RiskFactor[]
  highestSeverity: Severity | "None"
  maxCvss: number
  openVulns: Vulnerability[]
  nextAction: string
}

export interface Assessment {
  evaluatedAt: string
  overallScore: number
  overallCategory: RiskCategory
  assetRisks: AssetRisk[]
  criticalAssetCount: number
  openVulnerabilityCount: number
  openHighSeverityIncidents: number
  backendResult?: {
    scenario_name: string
    asset_name: string
    asset_value: number
    metrics: {
      loss_event_frequency: number
      single_loss_expectancy: number
      annual_loss_expectancy: number
      mitigated_annual_loss_expectancy?: number | null
      annual_risk_reduction?: number | null
      security_roi_percentage?: number | null
    }
    assumptions: string[]
    recommendation: string
  }
}

export interface SecurityGapDefinition {
  id: string
  control: ControlKey
  title: string
  evidenceTemplate: string
  consequence: string
  remediation: string
}

export interface SecurityGap extends SecurityGapDefinition {
  affectedAssets: Asset[]
  severity: Severity
  urgencyScore: number
  evidence: string[]
}

export interface InvestmentOption {
  id: string
  name: string
  description: string
  cost: number
  effort: Effort
  riskCategories: string[]
  /** Pure transformation describing what the investment changes in the dataset */
  apply: (dataset: Dataset) => Dataset
}

export type ActivityKind = "vulnerability" | "risk-change" | "control" | "remediation" | "assessment" | "incident"

export interface ActivityEvent {
  id: string
  at: string
  kind: ActivityKind
  title: string
  description: string
  severity: Severity | "Info"
  assetId?: string
  scoreChange?: { assetName: string; before: number; after: number }[]
  overallChange?: { before: number; after: number }
}

export type CurrencyCode = "USD" | "INR" | "EUR" | "GBP"

export type ViewId =
  | "landing"
  | "risk-assessment"
  | "overview"
  | "explorer"
  | "analyst"
  | "investments"
  | "gaps"
  | "activity"
  | "settings"
  | "report-upload"
  | "report-analysis"
  | "agent-simulation"
