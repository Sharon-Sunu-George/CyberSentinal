from typing import List, Optional, Dict, Any, Union
from pydantic import BaseModel, Field
from app.schemas.risk import RiskMetrics


class ReportSummary(BaseModel):
    critical: int = Field(default=0, ge=0)
    high: int = Field(default=0, ge=0)
    medium: int = Field(default=0, ge=0)
    low: int = Field(default=0, ge=0)
    total_findings: int = Field(default=0, ge=0)


class ReportFinding(BaseModel):
    id: str = Field(..., description="Unique identifier for finding")
    title: str = Field(..., description="Title of the security finding")
    severity: str = Field(..., description="Severity level: Critical, High, Medium, Low, or Info")
    cvss_score: Optional[float] = Field(None, ge=0.0, le=10.0, description="CVSS base score (0.0 to 10.0)")
    cve: Optional[str] = Field(None, description="CVE identifier if applicable")
    asset: Optional[str] = Field(None, description="Affected target asset or component")
    evidence: Optional[Union[str, Dict[str, Any]]] = Field(None, description="Empirical evidence or proof excerpt")
    recommendation: Optional[str] = Field(None, description="Remediation or mitigation guidance")
    is_inferred: bool = Field(default=False, description="True if finding was inferred by AI/rules rather than explicitly stated in source")
    source: Optional[str] = Field(default="explicit_file_content", description="Provenance of finding (e.g. explicit_file_content, ai_inferred)")


class NormalizedRiskScenario(BaseModel):
    scenario_id: str = Field(..., description="Unique identifier for scenario")
    scenario_name: str = Field(..., description="Name or title of cyber risk scenario")
    asset_name: str = Field(..., description="Target or affected asset name")
    asset_value: Optional[float] = Field(None, ge=0, description="Asset valuation in USD if explicitly provided")
    threat_event_frequency: Optional[float] = Field(None, ge=0, description="Threat event frequency (TEF) per year")
    vulnerability_probability: Optional[float] = Field(None, ge=0.0, le=1.0, description="Vulnerability probability (0.0 to 1.0)")
    direct_loss: Optional[float] = Field(None, ge=0, description="Direct financial loss in USD")
    indirect_loss: Optional[float] = Field(None, ge=0, description="Indirect financial loss in USD")
    proposed_security_cost: Optional[float] = Field(None, ge=0, description="Proposed security control cost in USD")
    mitigated_vulnerability_probability: Optional[float] = Field(None, ge=0.0, le=1.0, description="Mitigated vulnerability probability (0.0 to 1.0)")
    is_inferred: bool = Field(default=False, description="True if values were inferred rather than explicitly provided")
    metrics: Optional[RiskMetrics] = Field(None, description="FAIR risk calculation output if all required numerical inputs are present")
    assumptions: List[str] = Field(default_factory=list, description="Assumptions used for calculation")
    recommendation: Optional[str] = Field(None, description="Actionable recommendation based on calculated metrics")


class ParsedReportResponse(BaseModel):
    report_id: str = Field(..., description="Report identifier")
    target: str = Field(..., description="Target host, domain, or system")
    filename: Optional[str] = Field(None, description="Uploaded file name")
    detected_format: Optional[str] = Field(None, description="Detected document/data format (JSON, CSV, TXT, DOCX, PDF, IMAGE)")
    report_date: Optional[str] = Field(None, description="Date report was produced")
    environment: Optional[str] = Field(None, description="Environment tag (e.g., test-only, production)")
    report_type: Optional[str] = Field(None, description="Type of security report")
    notice: Optional[str] = Field(None, description="Legal notice or synthetic data label")
    is_synthetic: bool = Field(default=False, description="Flag indicating if the report is synthetic/fictional test data")
    summary: ReportSummary
    findings: List[ReportFinding]
    scenarios: List[NormalizedRiskScenario] = Field(default_factory=list, description="Normalized risk scenarios extracted from report")
    extracted_text_preview: Optional[str] = Field(None, description="Sanitized preview of extracted untrusted document text")
    calculated_metrics: Optional[RiskMetrics] = Field(None, description="FAIR financial metrics calculated by risk engine if quantitative inputs present")
    warnings: List[str] = Field(default_factory=list, description="Processing warnings or schema notes")
    missing_fields: List[str] = Field(default_factory=list, description="Required fields that were missing and deliberately not fabricated")
    analysis_status: str = Field(default="COMPLETED", description="Analysis status: COMPLETED, PARTIAL, or FAILED")
    ai_status: str = Field(default="NOT_CONFIGURED", description="AI status: USED, NOT_CONFIGURED, UNAVAILABLE, or NOT_NEEDED")
    ocr_status: str = Field(default="NOT_NEEDED", description="OCR status: USED, AVAILABLE, UNAVAILABLE, FAILED, or NOT_NEEDED")
