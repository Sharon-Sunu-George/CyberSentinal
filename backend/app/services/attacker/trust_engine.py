"""
Unified Website Trust, Scam, Phishing, and URL Normalization Orchestrator.
Synthesizes:
1. Threat intelligence matches (Google Safe Browsing, PhishTank).
2. Domain lookalike, typosquatting, and brand impersonation signals.
3. Canonical URL comparison and duplicate detection.

STRICT RULE:
Technical security vulnerabilities (missing CSP, missing HSTS, cookie attributes)
must NEVER automatically make a site classified as a scam or phishing site!
A clean threat-intel response does NOT guarantee complete safety.
"""

import datetime
import urllib.parse
from typing import Optional, Dict, Any, List, Tuple

from app.schemas.trust import (
    WebsiteTrustAssessment,
    ThreatIntelligenceMatch,
    ImpersonationSignal,
)
from app.services.attacker.threat_intel import (
    ThreatIntelligenceAggregator,
    GoogleSafeBrowsingProvider,
    PhishTankProvider,
)
from app.services.attacker.impersonation import (
    analyze_impersonation_risks,
    extract_base_domain,
)
from app.services.storage import get_db_connection


def canonicalize_url(raw_url: str) -> Tuple[str, str]:
    """
    Normalizes a URL to its canonical form for duplicate detection:
    - Lowercase scheme and hostname
    - Default port stripped (80 for http, 443 for https)
    - Normalized path (single trailing slash on root, preserved paths)
    - Sorted query parameters (preserving meaningful parameters)
    - Stripped fragment
    Returns (canonical_url, domain).
    """
    clean = raw_url.strip()
    if not clean:
        return "", ""

    if "://" not in clean:
        clean = f"https://{clean}"

    parsed = urllib.parse.urlsplit(clean)
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").lower().strip(".")
    port = parsed.port

    # Port normalization
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443) or port is None:
        netloc = host
    else:
        netloc = f"{host}:{port}"

    # Path normalization
    path = parsed.path or "/"
    # Clean multiple consecutive slashes
    while "//" in path:
        path = path.replace("//", "/")

    # Query string sorting
    query = ""
    if parsed.query:
        query_params = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        query_params.sort(key=lambda x: x[0])
        query = urllib.parse.urlencode(query_params)

    canonical = urllib.parse.urlunsplit((scheme, netloc, path, query, ""))
    return canonical, host


def check_for_duplicate_recent_scan(canonical_url: str, exclude_scan_id: Optional[str] = None) -> Tuple[bool, Optional[str]]:
    """
    Checks SQLite scans table to verify if this exact canonical URL
    was recently assessed, preventing redundant duplicated scans while
    never conflating different domains or paths.
    """
    conn = get_db_connection()
    try:
        if exclude_scan_id:
            row = conn.execute(
                "SELECT scan_id FROM scans WHERE normalized_url = ? AND scan_id != ? ORDER BY created_at DESC LIMIT 1",
                (canonical_url, exclude_scan_id),
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT scan_id FROM scans WHERE normalized_url = ? ORDER BY created_at DESC LIMIT 1",
                (canonical_url,),
            ).fetchone()

        if row:
            return True, row["scan_id"]
        return False, None
    except Exception:
        return False, None
    finally:
        conn.close()


class WebsiteTrustService:
    """
    Assesses website trust, reputation, and brand impersonation independently
    from technical vulnerability scanning.
    """

    def __init__(self, intel_aggregator: Optional[ThreatIntelligenceAggregator] = None):
        self.intel_aggregator = intel_aggregator or ThreatIntelligenceAggregator()

    def evaluate_trust(
        self,
        target_url: str,
        current_scan_id: Optional[str] = None,
        final_url: Optional[str] = None,
        redirect_chain: Optional[List[Dict[str, Any]]] = None,
        page_title: Optional[str] = None,
        forms: Optional[List[Dict[str, Any]]] = None,
    ) -> WebsiteTrustAssessment:
        canonical_url, domain = canonicalize_url(target_url)
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

        # 1. Duplicate check
        is_duplicate, dup_scan_id = check_for_duplicate_recent_scan(canonical_url, exclude_scan_id=current_scan_id)

        # 2. Query configured threat intelligence feeds
        intel_matches = self.intel_aggregator.evaluate_url(canonical_url)
        has_configured_provider = self.intel_aggregator.has_any_configured_provider()

        # 3. Analyze lookalike, typosquatting, and brand impersonation
        impersonation_signals = analyze_impersonation_risks(
            target_url=canonical_url,
            final_url=final_url,
            redirect_chain=redirect_chain,
            page_title=page_title,
            forms=forms,
        )

        # 4. Synthesize final trust state strictly based on empirical evidence
        # Priority order:
        # State 1: Known Malicious / Phishing (positive threat intelligence match)
        # State 2: Likely Impersonation (evidence of lookalike domain + credential harvesting or verified brand mimicry)
        # State 3: Suspicious (multiple risk signals or typosquatting, but unconfirmed)
        # State 4: No Known Threat Detected (providers checked clean)
        # State 5: Inconclusive (providers unavailable or failed, insufficient evidence)

        assessment_notes: List[str] = []
        positive_threat = next((m for m in intel_matches if m.status == "match_detected"), None)
        has_high_impersonation = any(s.severity == "High" for s in impersonation_signals)
        has_cred_harvesting = any(s.signal_type == "copied_branding_with_credentials" for s in impersonation_signals)

        if positive_threat:
            trust_state = "Known Malicious / Phishing"
            trust_label = f"Confirmed Malicious Entity ({positive_threat.provider})"
            confidence = "High"
            assessment_notes.append(
                f"Threat intelligence provider '{positive_threat.provider}' positively identified this URL as {positive_threat.threat_type or 'MALICIOUS'}."
            )
        elif has_cred_harvesting:
            trust_state = "Likely Impersonation"
            trust_label = "High Risk of Brand Deception & Credential Theft"
            confidence = "High"
            assessment_notes.append(
                "Observed evidence indicates brand impersonation combined with credential input elements on an unofficial domain."
            )
        elif has_high_impersonation:
            # Lookalike or typosquatting detected
            brand_target = impersonation_signals[0].target_brand or "a known brand"
            trust_state = "Likely Impersonation"
            trust_label = f"Probable Impersonation of {brand_target}"
            confidence = "Medium"
            assessment_notes.append(
                f"Domain characteristics strongly mimic {brand_target} without evidence of official authorization."
            )
        elif len(impersonation_signals) > 0:
            trust_state = "Suspicious"
            trust_label = "Unconfirmed Deception Signals"
            confidence = "Medium"
            assessment_notes.append(
                "Multiple potential risk signals observed (e.g. unexpected cross-domain redirection), but malicious intent is not confirmed."
            )
        elif not has_configured_provider:
            trust_state = "Inconclusive"
            trust_label = "Live Threat Intelligence Unavailable"
            confidence = "Low"
            assessment_notes.append(
                "No live reputation providers (Google Safe Browsing or PhishTank) are configured with API keys. Domain was verified free of obvious brand lookalikes."
            )
        else:
            # Check if any provider succeeded with no_match
            any_clean = any(m.status == "no_match" for m in intel_matches)
            all_failed = all(m.status in ("service_unavailable", "lookup_failed", "unconfigured") for m in intel_matches)

            if all_failed:
                trust_state = "Inconclusive"
                trust_label = "Threat Feeds Unreachable"
                confidence = "Low"
                assessment_notes.append(
                    "Configured threat intelligence providers could not be reached due to network timeout or provider errors."
                )
            elif any_clean:
                trust_state = "No Known Threat Detected"
                trust_label = "Clean Threat Feed Lookup"
                confidence = "Medium"
                assessment_notes.append(
                    "Configured threat-intelligence feeds returned no positive blacklist match. "
                    "Important: This result does not guarantee that the website is completely authentic or safe from newly deployed threats."
                )
            else:
                trust_state = "Inconclusive"
                trust_label = "Insufficient Evidence"
                confidence = "Low"
                assessment_notes.append("Unable to establish definitive trust state from available signals.")

        # Duplicate note
        if is_duplicate:
            assessment_notes.append(
                f"Notice: This canonical URL matches earlier scan ID '{dup_scan_id}'."
            )

        return WebsiteTrustAssessment(
            trust_state=trust_state,
            trust_score_label=trust_label,
            canonical_url=canonical_url,
            canonical_domain=domain,
            is_duplicate_scan=is_duplicate,
            duplicate_of_scan_id=dup_scan_id,
            threat_intel_matches=intel_matches,
            impersonation_signals=impersonation_signals,
            reputation_providers_configured=has_configured_provider,
            confidence=confidence,
            assessment_notes=assessment_notes,
            assessed_at=now_iso,
        )
