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
    category: str = Field(..., description="Vulnerability category")
    cwe_id: Optional[str] = Field(None, description="CWE identifier")
    cve_id: Optional[str] = Field(None, description="CVE identifier")
    affected_url_or_component: str = Field(...)

    # Defender Remediation Details
    root_cause: str = Field(..., description="Technical root cause explanation")
    actionable_fix: str = Field(..., description="Concrete, actionable fix description")
    implementation_steps: List[str] = Field(
        ..., description="Step-by-step implementation guide tailored to web servers and frameworks"
    )
    code_snippets: Dict[str, str] = Field(
        default_factory=dict,
        description="Ready-to-use configuration snippets (e.g., Nginx, Apache, Express, Next.js, Cloudflare)"
    )

    # Cost & Engineering Effort Modeling
    estimated_effort_hours: float = Field(..., description="Estimated engineering labor hours")
    hourly_rate: float = Field(..., description="Labor cost rate per engineering hour in USD")
    labor_cost: float = Field(..., description="Calculated labor cost (hours * hourly_rate)")
    service_cost: float = Field(default=0.0, description="Estimated third-party service or license cost")
    total_cost: float = Field(..., description="Total estimated remediation cost")

    # Risk & Prioritization Scoring
    risk_score: float = Field(..., description="Baseline risk score contribution (0-100 scale)")
    projected_risk_reduction: float = Field(..., description="Expected risk reduction points if fixed")
    cost_efficiency: float = Field(..., description="Risk reduction points achieved per $1,000 invested")
    priority_group: str = Field(
        ..., description="'fix_immediately', 'fix_next', or 'defer_or_mitigate'"
    )
    priority_rationale: str = Field(..., description="Explicit rationale for priority placement")
    deferral_reason: Optional[str] = Field(None, description="Reason if deferred or mitigated temporarily")
    temporary_mitigation: Optional[str] = Field(None, description="Compensating control if deferred")

    # Workflow & Verification
    dependencies: List[str] = Field(default_factory=list, description="Prerequisite fixes or infrastructure requirements")
    assumptions: List[str] = Field(default_factory=list, description="Documented engineering and costing assumptions")
    confidence_range: str = Field(default="±15%", description="Estimation variance range")
    verification_procedure: str = Field(..., description="Recommended verification command or test procedure")
    status: str = Field(
        default="Open",
        description="'Open', 'Planned', 'In Progress', 'Fixed', 'Accepted Risk', or 'Verified'"
    )
    status_notes: Optional[str] = Field(None, description="User or auditor notes on status change")


class DefenderAnalysisRequest(BaseModel):
    scan_id: Optional[str] = Field(None, description="Optional scan ID if loading from stored scan")
    target_url: str = Field(..., description="Target website URL")
    findings: List[Dict[str, Any]] = Field(
        ..., description="Raw or normalized findings from Attacker Agent"
    )
    available_budget: float = Field(
        default=5000.0,
        gt=0,
        description="Available security remediation budget in USD ($)"
    )
    hourly_rate: Optional[float] = Field(
        default=125.0,
        gt=0,
        description="Configurable senior engineer rate in USD/hour"
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
    created_at: str


class RemediationStatusUpdateRequest(BaseModel):
    status: str = Field(
        ...,
        description="'Open', 'Planned', 'In Progress', 'Fixed', 'Accepted Risk', or 'Verified'"
    )
    notes: Optional[str] = Field(None, description="Optional justification or verification evidence")
