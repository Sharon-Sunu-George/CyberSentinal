from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class FindingEvidence(BaseModel):
    check_type: str = Field(..., description="Type of security check, e.g. 'security_headers', 'cookie_flags', 'tls_configuration', 'info_disclosure', 'robots_txt', 'cors'")
    observed_data: Dict[str, Any] = Field(default_factory=dict, description="Concrete empirical data observed from response")
    raw_snippet: Optional[str] = Field(None, description="Relevant excerpt, header snippet, or wire observation")
    status_code: Optional[int] = Field(None, description="HTTP status code associated with probe")
    requested_url: Optional[str] = Field(None, description="Original target URL requested")
    final_url: Optional[str] = Field(None, description="Final resolved URL after redirects")
    observed_headers: Dict[str, str] = Field(default_factory=dict, description="Observed response headers relevant to this check")
    check_result: Optional[str] = Field(None, description="Evaluation outcome summary: e.g. 'Confirmed observation', 'Potential risk', 'Inconclusive', 'Scan error'")
    confidence_reason: Optional[str] = Field(None, description="Detailed reasoning explaining the confidence level and factual grounding")
    is_inferred: bool = Field(default=False, description="True if finding is an inferred risk rather than a direct wire observation")
    response_timestamp: Optional[str] = Field(None, description="ISO-8601 timestamp of the observed HTTP interaction")


class VulnerabilityFinding(BaseModel):
    id: str = Field(..., description="Unique finding ID, e.g. 'VULN-SEC-HDR-01'")
    title: str = Field(..., description="Concise finding title")
    category: str = Field(..., description="Category, e.g. 'Security Headers', 'Transport Security', 'Session Management', 'Information Disclosure', 'Outdated Software', 'Access Control'")
    severity: str = Field(..., description="'Critical', 'High', 'Medium', 'Low', or 'Info'")
    confidence: str = Field(..., description="'High', 'Medium', or 'Low'")
    affected_url_or_component: str = Field(..., description="URL path or component affected")
    evidence: FindingEvidence = Field(..., description="Empirical evidence supporting this finding")
    potential_impact: str = Field(..., description="Explanation of potential security and business impact")
    remediation: str = Field(..., description="Actionable technical recommendation to fix the issue")
    cwe_id: Optional[str] = Field(None, description="Common Weakness Enumeration identifier, e.g. 'CWE-319', 'CWE-693'")
    cve_id: Optional[str] = Field(None, description="CVE identifier when applicable and verified by component version evidence")
    scanner_name: str = Field(default="CyberSentinel Evidence-Based Scanner", description="Originating scanner identifier")
    scanned_at: Optional[str] = Field(None, description="Timestamp when finding was verified")
    references: List[str] = Field(default_factory=list, description="Authoritative reference URLs (OWASP, RFC, NIST)")
    is_confirmed: bool = Field(..., description="True if verified by direct observation; False if requiring further manual validation")
    validation_status: str = Field(..., description="'Confirmed Observation', 'Security Weakness', 'Requires Further Validation', or 'Informational Observation'")
    remediation_status: str = Field(default="Open", description="'Open', 'Planned', 'In Progress', 'Fixed', 'Accepted Risk', 'Verified'")


class InferredAttackScenario(BaseModel):
    scenario_title: str
    adversary_technique: str = Field(..., description="Mapped MITRE ATT&CK technique, e.g. 'T1190 - Exploit Public-Facing Application'")
    preconditions: List[str]
    modeled_chain: List[str]
    potential_impact: str
    confidence: str = Field(default="Inferred Hypothesis", description="Explicit label distinguishing model inference from scanner facts")


class DiscoveredForm(BaseModel):
    action: str = Field(..., description="Target form action URL")
    method: str = Field(default="GET", description="Form HTTP method, e.g. GET or POST")
    input_names: List[str] = Field(default_factory=list, description="Observed input field names")

    @property
    def action_url(self) -> str:
        return self.action


class DiscoveredRequest(BaseModel):
    url: str
    method: str = "GET"
    resource_type: str = "document"
    status: Optional[int] = None


class DiscoveredPage(BaseModel):
    url: str
    path: str
    depth: int = 0
    status_code: Optional[int] = None
    content_type: Optional[str] = None
    title: Optional[str] = None
    query_params: List[str] = Field(default_factory=list)
    forms: List[DiscoveredForm] = Field(default_factory=list)
    requests: List[DiscoveredRequest] = Field(default_factory=list)
    discovery_source: str = "crawler"
    discovered_at: Optional[str] = None


class ScanProgressUpdate(BaseModel):
    scan_id: str
    status: str = Field(..., description="'queued', 'running', 'completed', 'failed', 'cancelled'")
    pages_discovered: int = 0
    pages_visited: int = 0
    requests_completed: int = 0
    current_url: Optional[str] = None
    current_depth: int = 0
    findings_count: int = 0
    progress_percentage: int = 0
    message: str = ""
    started_at: Optional[str] = None
    elapsed_seconds: float = 0.0
    completed_at: Optional[str] = None
    error: Optional[str] = None


class AttackerScanSummary(BaseModel):
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    confirmed_count: int
    pages_discovered: int = 0
    pages_visited: int = 0
    requests_completed: int = 0


class AttackerScanRequest(BaseModel):
    target_url: str = Field(..., description="Target web application URL, e.g. 'https://example.com'")
    is_authorized: bool = Field(
        ...,
        description="Explicit authorization confirmation. Must be True indicating the user has permission to assess the target."
    )
    scanner_mode: Optional[str] = Field(
        default="hybrid",
        description="'built-in' (passive safety checks), 'zap' (OWASP ZAP integration if available), or 'hybrid'"
    )
    max_pages: Optional[int] = Field(
        default=15,
        ge=1,
        le=50,
        description="Configurable ceiling on total crawled pages (default: 15, max: 50)"
    )
    max_depth: Optional[int] = Field(
        default=2,
        ge=0,
        le=5,
        description="Configurable maximum link crawl depth from starting origin (default: 2)"
    )
    timeout_seconds: Optional[int] = Field(
        default=90,
        ge=10,
        le=300,
        description="Configurable total scan timeout in seconds (default: 90s)"
    )



class AttackerScanResponse(BaseModel):
    scan_id: str
    target_url: str
    normalized_url: str
    scanned_at: str
    status: str = Field(default="completed", description="'queued', 'running', 'completed', 'failed', or 'cancelled'")
    target_ip: Optional[str] = None
    scanner_info: Dict[str, Any] = Field(
        default_factory=dict,
        description="Active scanner details, version, and OWASP ZAP availability report"
    )
    scope_limitations: str = Field(
        default="",
        description="Clear message explaining scope and boundaries of the scan"
    )
    zero_findings_disclaimer: Optional[str] = Field(
        default=None,
        description="Honest security disclaimer if zero findings are returned"
    )
    is_inconclusive: bool = Field(default=False, description="True if the scan encountered upstream gateway/proxy failure or connection error")
    allows_retry: bool = Field(default=False, description="True if scan failed or was inconclusive due to temporary network/proxy error and can be retried")
    summary: AttackerScanSummary
    findings: List[VulnerabilityFinding]
    discovered_pages: List[DiscoveredPage] = Field(default_factory=list, description="Pages discovered during full-site crawl")
    inferred_attack_scenarios: List[InferredAttackScenario]
    defender_handover: Dict[str, Any] = Field(
        default_factory=dict,
        description="Structured finding data formatted for consumption by the Defender Agent"
    )

