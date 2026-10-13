from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class FindingEvidence(BaseModel):
    check_type: str = Field(..., description="Type of security check, e.g. 'security_headers', 'cookie_flags', 'tls_configuration', 'info_disclosure'")
    observed_data: Dict[str, Any] = Field(default_factory=dict, description="Concrete empirical data observed from response")
    raw_snippet: Optional[str] = Field(None, description="Relevant excerpt or header snippet")
    status_code: Optional[int] = Field(None, description="HTTP status code associated with probe")


class VulnerabilityFinding(BaseModel):
    id: str = Field(..., description="Unique finding ID, e.g. 'VULN-SEC-HDR-01'")
    title: str = Field(..., description="Concise finding title")
    category: str = Field(..., description="Category, e.g. 'Security Headers', 'Transport Security', 'Session Management', 'Information Disclosure', 'Outdated Software'")
    severity: str = Field(..., description="'Critical', 'High', 'Medium', 'Low', or 'Info'")
    confidence: str = Field(..., description="'High', 'Medium', or 'Low'")
    affected_url_or_component: str = Field(..., description="URL path or component affected")
    evidence: FindingEvidence = Field(..., description="Empirical evidence supporting this finding")
    potential_impact: str = Field(..., description="Explanation of potential security and business impact")
    remediation: str = Field(..., description="Actionable technical recommendation to fix the issue")
    cve_id: Optional[str] = Field(None, description="CVE identifier when applicable and verified by component version evidence")
    is_confirmed: bool = Field(..., description="True if verified by direct observation; False if requiring further manual validation")
    validation_status: str = Field(..., description="'Confirmed Observation', 'Security Weakness', or 'Requires Further Validation'")


class InferredAttackScenario(BaseModel):
    scenario_title: str
    adversary_technique: str = Field(..., description="Mapped MITRE ATT&CK technique, e.g. 'T1190 - Exploit Public-Facing Application'")
    preconditions: List[str]
    modeled_chain: List[str]
    potential_impact: str
    confidence: str = Field(default="Inferred Hypothesis", description="Explicit label distinguishing model inference from scanner facts")


class AttackerScanSummary(BaseModel):
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    confirmed_count: int


class AttackerScanRequest(BaseModel):
    target_url: str = Field(..., description="Target web application URL, e.g. 'https://example.com'")
    is_authorized: bool = Field(
        ...,
        description="Explicit authorization confirmation. Must be True indicating the user has permission to assess the target."
    )


class AttackerScanResponse(BaseModel):
    scan_id: str
    target_url: str
    normalized_url: str
    scanned_at: str
    status: str
    target_ip: Optional[str] = None
    summary: AttackerScanSummary
    findings: List[VulnerabilityFinding]
    inferred_attack_scenarios: List[InferredAttackScenario]
    defender_handover: Dict[str, Any] = Field(
        default_factory=dict,
        description="Structured finding data pre-formatted for consumption by the future Defender Agent"
    )
