"""
Pydantic Schemas for Website Trust, Phishing, Scam & Impersonation Assessment.
Separates domain trust, threat intelligence, and brand impersonation evidence
from technical HTTP vulnerability findings.
"""

from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class ThreatIntelligenceMatch(BaseModel):
    provider: str = Field(..., description="Provider name, e.g. 'Google Safe Browsing' or 'PhishTank'")
    status: str = Field(..., description="'match_detected', 'no_match', 'service_unavailable', 'unconfigured', or 'lookup_failed'")
    threat_type: Optional[str] = Field(None, description="Reported threat type, e.g. 'MALWARE', 'SOCIAL_ENGINEERING', 'PHISHING'")
    details: Optional[str] = Field(None, description="Detailed provider response summary")
    cached: bool = Field(default=False, description="Whether result was served from cache")
    lookup_timestamp: str = Field(..., description="ISO-8601 timestamp of provider inquiry")
    reference_url: Optional[str] = Field(None, description="Provider reference URL or verification link if available")


class ImpersonationSignal(BaseModel):
    signal_type: str = Field(
        ...,
        description="Type of impersonation signal: 'homoglyph', 'punycode', 'typosquatting', 'brand_name_in_subdomain', 'suspicious_redirect', 'copied_branding_with_credentials'"
    )
    severity: str = Field(..., description="'High', 'Medium', 'Low', or 'Info'")
    target_brand: Optional[str] = Field(None, description="Legitimate brand or website potentially targeted for impersonation")
    official_domain: Optional[str] = Field(None, description="Expected official domain for the recognized brand")
    description: str = Field(..., description="Explainable description of the detected indicator")
    evidence: Dict[str, Any] = Field(default_factory=dict, description="Concrete evidence supporting the signal")


class WebsiteTrustAssessment(BaseModel):
    trust_state: str = Field(
        ...,
        description="'Known Malicious / Phishing', 'Likely Impersonation', 'Suspicious', 'No Known Threat Detected', or 'Inconclusive'"
    )
    trust_score_label: str = Field(
        ...,
        description="Explaining label: e.g. 'Threat Identified', 'High Risk of Brand Deception', 'Caution: Unconfirmed Signals', 'Clean Intelligence Lookup (Safety Not Guaranteed)', or 'Reputation Providers Unreachable'"
    )
    canonical_url: str = Field(..., description="Normalized canonical URL used for assessment")
    canonical_domain: str = Field(..., description="Normalized domain/host")
    is_duplicate_scan: bool = Field(default=False, description="Whether identical canonical URL was recently assessed")
    duplicate_of_scan_id: Optional[str] = Field(None, description="Reference to earlier scan ID if duplicate")
    threat_intel_matches: List[ThreatIntelligenceMatch] = Field(default_factory=list, description="Results from threat intelligence feeds")
    impersonation_signals: List[ImpersonationSignal] = Field(default_factory=list, description="Signals of brand impersonation or domain deception")
    reputation_providers_configured: bool = Field(default=False, description="Whether at least one live reputation provider API key is active")
    confidence: str = Field(..., description="'High', 'Medium', or 'Low'")
    assessment_notes: List[str] = Field(default_factory=list, description="Reasoning and limitations of the trust evaluation")
    assessed_at: str = Field(..., description="ISO-8601 timestamp of trust evaluation")
