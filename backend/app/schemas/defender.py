"""
Defender Agent Schemas for CyberSentinal.
Defines evidence-based remediation recommendations, cost modeling,
and budget-constrained prioritization models.
"""

from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class RemediationRecommendation(BaseModel):
    finding_id: str = Field(..., description="Correlated finding ID from Attacker Agent")
    finding_title: str = Field(..., description="Finding title")
    severity: str = Field(..., description="'Critical', 'High', 'Medium', 'Low', or 'Info'")
    confidence: str = Field(default="High", description="Evidence confidence: 'High', 'Medium', or 'Low'")
    category: str = Field(..., description="Vulnerability category")
    cwe_id: Optional[str] = Field(None, description="CWE identifier")
    cve_id: Optional[str] = Field(None, description="CVE identifier")
    affected_url_or_component: str = Field(...)

    # Defender Remediation Details
    short_explanation: str = Field(default="", description="Short explanation of the security issue")
    why_it_matters: str = Field(default="", description="Why this security issue matters to perimeter security")
    root_cause: str = Field(..., description="Technical root cause explanation")
    actionable_fix: str = Field(..., description="Concrete, actionable fix description")
    recommended_fix: str = Field(default="", description="Recommended technical fix for engineers")
    implementation_steps: List[str] = Field(
        ..., description="Step-by-step implementation guide tailored to web servers and frameworks"
    )
    code_snippets: Dict[str, str] = Field(
        default_factory=dict,
        description="Ready-to-use configuration snippets (e.g., Nginx, Apache, Express, Next.js, Cloudflare)"
    )
    file_or_config_location: str = Field(
        default="Web server configuration / HTTP framework response middleware",
        description="Relevant file or configuration location (with generic assumptions clearly labeled)"
    )
    implementation_difficulty: str = Field(
        default="Easy",
        description="'Easy', 'Moderate', or 'Hard'"
    )

    # Cost & Engineering Effort Modeling
    estimated_effort_hours: float = Field(..., description="Estimated engineering labor hours")
    hourly_rate: float = Field(..., description="Labor cost rate per engineering hour in specified currency")
    currency: str = Field(default="USD", description="Currency code (e.g. USD, EUR, GBP, CAD, AUD)")
    labor_cost: float = Field(..., description="Calculated labor cost (hours * hourly_rate)")
    service_cost: float = Field(default=0.0, description="Estimated third-party service or license cost")
    total_cost: float = Field(..., description="Total estimated remediation cost")
    cost_assumption: str = Field(
        default="Internal senior engineering time (implementation, local testing, and peer review)",
        description="Clear statement of cost assumptions"
    )

    # Risk & Prioritization Scoring
    risk_score: float = Field(..., description="Baseline risk score contribution (0-100 scale)")
    priority_score: float = Field(default=0.0, description="Multi-factor priority score (0-100)")
    priority_explanation: str = Field(default="", description="Transparent explanation of priority score calculation")
    projected_risk_reduction: float = Field(..., description="Expected qualitative or quantitative risk reduction")
    risk_reduction_expected: str = Field(default="", description="Qualitative risk reduction description")
    cost_efficiency: float = Field(..., description="Risk reduction points achieved per 1,000 currency units invested")
    priority_group: str = Field(
        ..., description="'fix_immediately', 'fix_next', or 'defer_or_mitigate'"
    )
    priority_rationale: str = Field(..., description="Explicit rationale for priority placement")
    deferral_reason: Optional[str] = Field(None, description="Reason if deferred or mitigated temporarily")
    temporary_mitigation: Optional[str] = Field(None, description="Compensating control if deferred")

    # Workflow, Rollback & Verification
    dependencies_and_side_effects: str = Field(
        default="Verify browser and client compatibility before applying changes.",
        description="Known dependencies and potential side effects"
    )
    dependencies: List[str] = Field(default_factory=list, description="Prerequisite fixes or infrastructure requirements")
    assumptions: List[str] = Field(default_factory=list, description="Documented engineering and costing assumptions")
    confidence_range: str = Field(default="±15%", description="Estimation variance range")
    validation_steps: List[str] = Field(default_factory=list, description="Step-by-step validation procedures")
    verification_procedure: str = Field(..., description="Recommended verification command or test procedure")
    rollback_guidance: str = Field(
        default="Revert configuration changes in version control and reload web server.",
        description="Rollback guidance if configuration changes cause issues"
    )
    status: str = Field(
        default="Not Started",
        description="'Not Started', 'In Progress', 'Fixed Pending Verification', 'Verified Fixed', or 'Reopened'"
    )
    remediation_status: str = Field(
        default="Not Started",
        description="Remediation lifecycle status matching user requirements"
    )
    status_notes: Optional[str] = Field(None, description="User or auditor notes on status change")
    verification_evidence: Optional[Dict[str, Any]] = Field(
        None, description="Empirical evidence recorded during live verification probe"
    )


class DefenderAnalysisRequest(BaseModel):
    scan_id: Optional[str] = Field(None, description="Optional scan ID if loading from stored scan")
    target_url: str = Field(..., description="Target website URL")
    findings: List[Dict[str, Any]] = Field(
        ..., description="Raw or normalized findings from Attacker Agent"
    )
    available_budget: float = Field(
        default=5000.0,
        gt=0,
        description="Available security remediation budget"
    )
    currency: Optional[str] = Field(
        default="USD",
        description="Budget currency (e.g., 'USD', 'EUR', 'GBP', 'CAD', 'AUD')"
    )
    hourly_rate: Optional[float] = Field(
        default=125.0,
        gt=0,
        description="Configurable senior engineer rate in currency/hour"
    )
    business_criticality: Optional[str] = Field(
        default="High",
        description="'Critical', 'High', 'Medium', or 'Low'"
    )


class DefenderAnalysisResponse(BaseModel):
    analysis_id: str
    scan_id: Optional[str] = None
    target_url: str
    currency: str = "USD"
    available_budget: float
    hourly_rate: float
    total_remediation_cost: float
    proposed_spending: float
    remaining_budget: float
    budget_shortfall: float

    # Risk Metrics
    baseline_risk_score: float = Field(..., description="Measured overall risk before remediation (0-100)")
    projected_residual_risk: float = Field(..., description="Projected residual risk after proposed fixes (0-100)")
    total_risk_reduction_points: float
    total_risk_reduction_percent: float
    risk_reduction_per_dollar: float

    # Categorized Priorities
    fix_immediately: List[RemediationRecommendation] = Field(
        default_factory=list,
        description="Urgent risk reduction items (highest risk / critical ROI)"
    )
    fix_next: List[RemediationRecommendation] = Field(
        default_factory=list,
        description="Important fixes that fit within the remaining planned budget"
    )
    defer_or_mitigate: List[RemediationRecommendation] = Field(
        default_factory=list,
        description="Findings deferred or requiring temporary mitigation due to budget constraints"
    )
    unbudgeted_high_risk_findings: List[RemediationRecommendation] = Field(
        default_factory=list,
        description="Explicit alert: Critical/High items that CANNOT be addressed under current budget"
    )

    # Transparency
    scoring_model_notes: List[str] = Field(
        default_factory=list,
        description="Documentation of risk equations, cost multipliers, and optimization heuristics"
    )
    cost_assumptions: List[str] = Field(
        default_factory=list,
        description="Explicit statements regarding labor rates, material costs, and currency"
    )
    created_at: str


class RemediationStatusUpdateRequest(BaseModel):
    status: str = Field(
        ...,
        description="'Not Started', 'In Progress', 'Fixed Pending Verification', 'Verified Fixed', or 'Reopened' (legacy: 'Open', 'Planned', 'Fixed', 'Verified')"
    )
    notes: Optional[str] = Field(None, description="Optional justification or verification evidence")


class VerifyRemediationRequest(BaseModel):
    target_url: Optional[str] = Field(None, description="Optional target URL override; defaults to scan target")


class VerifyRemediationResponse(BaseModel):
    scan_id: str
    finding_id: str
    target_url: str
    previous_status: str
    new_status: str
    is_verified: bool
    verification_passed: bool
    is_inconclusive: bool
    evidence_summary: str
    observed_headers: Dict[str, str] = Field(default_factory=dict)
    observed_status: Optional[int] = None
    verification_timestamp: str
    message: str
