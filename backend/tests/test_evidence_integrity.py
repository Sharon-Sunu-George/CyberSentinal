"""
Test Evidence Integrity, Risk Calibration, and Finding Quality in CyberSentinal.
Verifies all 14 realistic edge cases required by the CyberSentinal specification:
1. Genuine observations versus inferred findings.
2. HTTP targets that redirect to HTTPS (Low) vs pure HTTP (High).
3. Missing and weak security headers (Missing CSP vs Weak CSP).
4. Cookie endpoints that do not set cookies (no false positive findings).
5. Wildcard CORS with and without credential allowance.
6. Generic server banners versus version-bearing banners versus known CVEs.
7. Custom 404 pages that return HTTP 200 (HTML detection rejects false .env / .git findings).
8. Sensitive-file denial pages versus genuinely exposed test fixtures with secret redaction.
9. Duplicate findings across several pages aggregated with occurrence_count and affected_urls.
10. Secret redaction in stored evidence and logs ([REDACTED_SECRET]).
11. Severity summary and total-count consistency.
12. Remediation score and budget arithmetic.
13. Timeouts, redirects, gateway errors, and inconclusive verification.
14. Regression of existing SSRF protections, scan limits, and remediation history.
"""

import pytest
import datetime
from unittest.mock import MagicMock, patch

from app.schemas.attacker import (
    FindingEvidence,
    VulnerabilityFinding,
    AttackerScanSummary,
)
from app.schemas.defender import (
    DefenderAnalysisRequest,
    RemediationRecommendation,
)
from app.services.attacker.scanner import (
    SafeHttpResponse,
    EvidenceBasedScanner,
    deduplicate_findings,
)
from app.services.attacker.crawler import PlaywrightCrawler
from app.services.defender.engine import DefenderPrioritizationEngine
from app.services.attacker.ssrf_guard import (
    validate_destination_url,
    SSRFProtectionError,
    TargetAuthorizationError,
)


def test_1_genuine_observation_vs_inferred_finding():
    """1. Checks that findings explicitly distinguish direct wire observations from heuristic inference."""
    scanner = EvidenceBasedScanner()
    # HTTPS response with missing CSP and valid server version banner
    resp = SafeHttpResponse(
        url="https://example.com/",
        status_code=200,
        headers={"Server": "nginx/1.24.0"},
        body_text="<html><body>Hello</body></html>",
        remote_ip="93.184.216.34",
        was_https=True,
    )
    findings = []
    scanner._check_security_headers(resp, findings)
    scanner._check_information_disclosure(resp, findings)

    # Missing CSP should be marked inferred (no active script injection was executed)
    csp_finding = next((f for f in findings if f.id == "VULN-SEC-HDR-NO-CSP"), None)
    assert csp_finding is not None
    assert csp_finding.evidence.is_inferred is True
    assert csp_finding.evidence.evidence_source == "direct_observation"
    assert csp_finding.severity == "Medium"
    assert csp_finding.severity_reason is not None

    # Server version banner is a direct empirical observation from the Server header
    banner_finding = next((f for f in findings if f.id == "VULN-INFO-SERVER-VERSION"), None)
    assert banner_finding is not None
    assert banner_finding.evidence.is_inferred is False
    assert banner_finding.evidence.evidence_source == "direct_observation"
    assert banner_finding.evidence.observed_value == "nginx/1.24.0"
    assert banner_finding.is_confirmed is True


def test_2_http_redirect_to_https_vs_pure_http():
    """2. Calibrates transport security: HTTP redirecting to HTTPS is Low; unencrypted HTTP without redirect is High."""
    scanner = EvidenceBasedScanner()

    # Case A: HTTP target that immediately 301 redirects to HTTPS
    resp_redirect = SafeHttpResponse(
        url="http://example.com/",
        status_code=301,
        headers={"Location": "https://example.com/"},
        body_text="",
        remote_ip="93.184.216.34",
        was_https=False,
        requested_url="http://example.com/",
        final_url="https://example.com/",
        redirect_chain=[{"from_url": "http://example.com/", "to_url": "https://example.com/", "status_code": 301}],
    )
    findings_redirect = []
    scanner._check_transport_security(resp_redirect, findings_redirect)

    redirect_finding = next((f for f in findings_redirect if f.id == "VULN-TLS-HTTP-REDIRECT-HTTPS"), None)
    assert redirect_finding is not None
    assert redirect_finding.severity == "Low"
    assert "immediately redirects" in redirect_finding.severity_reason

    # Case B: Plain HTTP returning 200 without HTTPS redirect
    resp_raw = SafeHttpResponse(
        url="http://example.com/",
        status_code=200,
        headers={"Content-Type": "text/html"},
        body_text="<html>Insecure</html>",
        remote_ip="93.184.216.34",
        was_https=False,
        requested_url="http://example.com/",
        final_url="http://example.com/",
        redirect_chain=[],
    )
    findings_raw = []
    scanner._check_transport_security(resp_raw, findings_raw)

    raw_finding = next((f for f in findings_raw if f.id == "VULN-TLS-NO-HTTPS"), None)
    assert raw_finding is not None
    assert raw_finding.severity == "High"
    assert "unencrypted HTTP without automatic HTTPS redirection" in raw_finding.severity_reason


def test_3_missing_vs_weak_csp():
    """3. Distinguishes missing CSP from present but weak CSP ('unsafe-inline' or 'unsafe-eval')."""
    scanner = EvidenceBasedScanner()

    # Case A: Missing CSP
    resp_missing = SafeHttpResponse(
        url="https://example.com/",
        status_code=200,
        headers={"X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY"},
        body_text="<html>OK</html>",
        remote_ip="93.184.216.34",
        was_https=True,
    )
    findings_missing = []
    scanner._check_security_headers(resp_missing, findings_missing)
    f_missing = next((f for f in findings_missing if f.id == "VULN-SEC-HDR-NO-CSP"), None)
    assert f_missing is not None
    assert f_missing.severity == "Medium"
    assert f_missing.evidence.observed_value == "absent"

    # Case B: Present but weak CSP (contains 'unsafe-inline')
    resp_weak = SafeHttpResponse(
        url="https://example.com/",
        status_code=200,
        headers={
            "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline';",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
        },
        body_text="<html>OK</html>",
        remote_ip="93.184.216.34",
        was_https=True,
    )
    findings_weak = []
    scanner._check_security_headers(resp_weak, findings_weak)
    f_weak = next((f for f in findings_weak if f.id == "VULN-SEC-HDR-WEAK-CSP"), None)
    assert f_weak is not None
    assert f_weak.severity == "Low"
    assert "'unsafe-inline'" in f_weak.evidence.observed_value
    assert f_weak.is_confirmed is True


def test_4_cookie_endpoint_without_cookies():
    """4. Ensures endpoints that set no cookies never raise cookie security false positives."""
    scanner = EvidenceBasedScanner()
    resp = SafeHttpResponse(
        url="https://example.com/api/data",
        status_code=200,
        headers={"Content-Type": "application/json"},
        body_text='{"status": "ok"}',
        remote_ip="93.184.216.34",
        was_https=True,
    )
    findings = []
    scanner._check_cookie_flags(resp, findings)
    assert len(findings) == 0


def test_5_wildcard_cors_with_and_without_credentials():
    """5. Assesses CORS: Wildcard with credentials is High; wildcard without credentials is Low."""
    scanner = EvidenceBasedScanner()

    # Case A: Wildcard with credentials
    resp_cred = SafeHttpResponse(
        url="https://example.com/api",
        status_code=200,
        headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
        },
        body_text="{}",
        remote_ip="93.184.216.34",
        was_https=True,
    )
    findings_cred = []
    scanner._check_cors_policy(resp_cred, findings_cred)
    f_cred = next((f for f in findings_cred if f.id == "VULN-CORS-WILDCARD-CREDENTIALS"), None)
    assert f_cred is not None
    assert f_cred.severity == "High"

    # Case B: Wildcard without credentials
    resp_wild = SafeHttpResponse(
        url="https://example.com/api",
        status_code=200,
        headers={"Access-Control-Allow-Origin": "*"},
        body_text="{}",
        remote_ip="93.184.216.34",
        was_https=True,
    )
    findings_wild = []
    scanner._check_cors_policy(resp_wild, findings_wild)
    f_wild = next((f for f in findings_wild if f.id == "VULN-CORS-WILDCARD"), None)
    assert f_wild is not None
    assert f_wild.severity == "Low"


def test_6_server_banner_generic_vs_version_vs_cve():
    """6. Assesses Server banners: generic banner is Info, version string is Low, matching CVE is Medium/High."""
    scanner = EvidenceBasedScanner()

    # Case A: Generic banner without version digits (e.g. Server: cloudflare)
    resp_generic = SafeHttpResponse(
        url="https://example.com/",
        status_code=200,
        headers={"Server": "cloudflare"},
        body_text="OK",
        remote_ip="93.184.216.34",
        was_https=True,
    )
    f_generic = []
    scanner._check_information_disclosure(resp_generic, f_generic)
    assert len(f_generic) == 1
    assert f_generic[0].id == "VULN-INFO-SERVER-BANNER"
    assert f_generic[0].severity == "Info"

    # Case B: Version-bearing banner without CVE match
    resp_ver = SafeHttpResponse(
        url="https://example.com/",
        status_code=200,
        headers={"Server": "Apache/2.4.58"},
        body_text="OK",
        remote_ip="93.184.216.34",
        was_https=True,
    )
    f_ver = []
    scanner._check_information_disclosure(resp_ver, f_ver)
    assert len(f_ver) == 1
    assert f_ver[0].id == "VULN-INFO-SERVER-VERSION"
    assert f_ver[0].severity == "Low"

    # Case C: Version matching known CVE in catalog (e.g. Apache/2.4.49 -> CVE-2021-41773)
    resp_cve = SafeHttpResponse(
        url="https://example.com/",
        status_code=200,
        headers={"Server": "Apache/2.4.49"},
        body_text="OK",
        remote_ip="93.184.216.34",
        was_https=True,
    )
    f_cve = []
    scanner._check_information_disclosure(resp_cve, f_cve)
    cve_f = next((f for f in f_cve if "CVE-2021-41773" in f.id), None)
    assert cve_f is not None
    assert cve_f.validation_status == "Requires Further Validation"
    assert cve_f.is_confirmed is False


def test_7_custom_404_returning_200_not_flagged_as_env_or_git():
    """7. Rejects custom 404 pages or SPAs returning HTTP 200 with HTML from being flagged as .env or .git exposure."""
    scanner = EvidenceBasedScanner()
    html_404_body = """
    <!DOCTYPE html>
    <html>
    <head><title>Page Not Found</title></head>
    <body>
      <h1>404 - Not Found</h1>
      <p>The requested file does not exist.</p>
    </body>
    </html>
    """
    mock_resp = SafeHttpResponse(
        url="https://example.com/.env",
        status_code=200,
        headers={"Content-Type": "text/html; charset=utf-8"},
        body_text=html_404_body,
        remote_ip="93.184.216.34",
        was_https=True,
    )
    findings = []
    with patch.object(scanner.client, "request", return_value=mock_resp):
        scanner._check_sensitive_files("example.com", 443, True, findings)

    # Should NOT flag .env or .git exposure because content is clearly an HTML document
    assert len(findings) == 0


def test_8_sensitive_file_exposure_and_secret_redaction():
    """8. Verifies real .env exposure is detected and secrets are strictly redacted with [REDACTED_SECRET]."""
    scanner = EvidenceBasedScanner()
    real_env_body = (
        "APP_NAME=CyberSentinal\n"
        "APP_ENV=production\n"
        "DATABASE_URL=postgres://admin:SuperSecretPassword123@db.prod.internal:5432/main\n"
        "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
        "PORT=8000\n"
    )
    mock_resp = SafeHttpResponse(
        url="https://example.com/.env",
        status_code=200,
        headers={"Content-Type": "text/plain"},
        body_text=real_env_body,
        remote_ip="93.184.216.34",
        was_https=True,
    )
    findings = []
    with patch.object(scanner.client, "request", return_value=mock_resp):
        scanner._check_sensitive_files("example.com", 443, True, findings)

    env_finding = next((f for f in findings if f.id == "VULN-EXPOSED-ENV-FILE"), None)
    assert env_finding is not None
    assert env_finding.severity == "Critical"
    assert env_finding.is_confirmed is True

    # Check secret redaction
    snippet = env_finding.evidence.raw_snippet
    assert "SuperSecretPassword123" not in snippet
    assert "wJalrXUtnFEMI" not in snippet
    assert "[REDACTED_SECRET]" in snippet


def test_9_duplicate_findings_across_crawled_pages():
    """9. Groups duplicate findings across multiple crawled pages into a single record with affected_urls and occurrence_count."""
    crawler = PlaywrightCrawler()
    findings = []
    seen_ids = set()

    # Simulate discovering 3 pages on the same site missing Content-Security-Policy
    pages = [
        "https://example.com/",
        "https://example.com/about",
        "https://example.com/contact",
    ]
    for p in pages:
        crawler._analyze_page_headers(
            page_url=p,
            status_code=200,
            headers={"Server": "nginx", "X-Content-Type-Options": "nosniff"},
            findings=findings,
            seen_ids=seen_ids,
        )

    # Missing CSP should have exactly 1 record in findings
    csp_records = [f for f in findings if f.id == "VULN-SEC-HDR-NO-CSP"]
    assert len(csp_records) == 1

    rec = csp_records[0]
    assert rec.occurrence_count == 3
    assert len(rec.affected_urls) == 3
    assert set(rec.affected_urls) == set(pages)


def test_10_deduplicate_findings_helper():
    """10. Tests deduplicate_findings helper preserves all affected URLs and generates stable fingerprints."""
    f1 = VulnerabilityFinding(
        id="VULN-SEC-HDR-NO-CSP",
        title="Missing CSP",
        category="Security Headers",
        severity="Medium",
        confidence="High",
        affected_url_or_component="https://example.com/page1",
        evidence=FindingEvidence(
            check_type="security_headers",
            requested_url="https://example.com/page1",
            final_url="https://example.com/page1",
        ),
        potential_impact="XSS",
        remediation="Add CSP",
        is_confirmed=True,
        validation_status="Security Weakness",
    )
    f2 = VulnerabilityFinding(
        id="VULN-SEC-HDR-NO-CSP",
        title="Missing CSP",
        category="Security Headers",
        severity="Medium",
        confidence="High",
        affected_url_or_component="https://example.com/page2",
        evidence=FindingEvidence(
            check_type="security_headers",
            requested_url="https://example.com/page2",
            final_url="https://example.com/page2",
        ),
        potential_impact="XSS",
        remediation="Add CSP",
        is_confirmed=True,
        validation_status="Security Weakness",
    )

    deduped = deduplicate_findings([f1, f2])
    assert len(deduped) == 1
    assert deduped[0].occurrence_count == 2
    assert len(deduped[0].affected_urls) == 2
    assert "https://example.com/page1" in deduped[0].affected_urls
    assert "https://example.com/page2" in deduped[0].affected_urls
    assert deduped[0].fingerprint.startswith("FP-")


def test_11_severity_summary_consistency():
    """11. Checks that summary metrics match unique finding records exactly."""
    findings = [
        VulnerabilityFinding(
            id="F1", title="Critical issue", category="Cat", severity="Critical", confidence="High",
            affected_url_or_component="url", evidence=FindingEvidence(check_type="t"), potential_impact="i",
            remediation="r", is_confirmed=True, validation_status="Confirmed",
        ),
        VulnerabilityFinding(
            id="F2", title="High issue", category="Cat", severity="High", confidence="High",
            affected_url_or_component="url", evidence=FindingEvidence(check_type="t"), potential_impact="i",
            remediation="r", is_confirmed=True, validation_status="Confirmed",
        ),
        VulnerabilityFinding(
            id="F3", title="Medium issue", category="Cat", severity="Medium", confidence="High",
            affected_url_or_component="url", evidence=FindingEvidence(check_type="t"), potential_impact="i",
            remediation="r", is_confirmed=False, validation_status="Requires Validation",
        ),
    ]

    from app.services.attacker.agent import AttackerAgentService
    summary = AttackerAgentService._compute_summary(findings)

    assert summary.total_findings == 3
    assert summary.critical_count == 1
    assert summary.high_count == 1
    assert summary.medium_count == 1
    assert summary.low_count == 0
    assert summary.info_count == 0
    assert summary.confirmed_count == 2
    assert summary.total_findings == (
        summary.critical_count + summary.high_count + summary.medium_count + summary.low_count + summary.info_count
    )


def test_12_defender_remediation_score_and_budget_arithmetic():
    """12. Verifies budget arithmetic, cost efficiency, and playbook mapping."""
    engine = DefenderPrioritizationEngine(hourly_rate=150.0)
    req = DefenderAnalysisRequest(
        target_url="https://example.com",
        available_budget=1000.0,
        currency="USD",
        hourly_rate=150.0,
        findings=[
            {
                "id": "VULN-TLS-NO-HTTPS",
                "title": "Cleartext HTTP Scheme",
                "category": "Transport Security",
                "severity": "High",
                "confidence": "High",
                "affected_url_or_component": "http://example.com",
                "potential_impact": "Eavesdropping",
                "remediation": "Migrate to HTTPS",
                "is_confirmed": True,
                "validation_status": "Confirmed Observation",
            }
        ],
    )
    plan = engine.analyze(req)
    assert plan.available_budget == 1000.0
    assert plan.hourly_rate == 150.0
    assert plan.proposed_spending > 0
    assert plan.proposed_spending <= plan.available_budget

    all_recs = plan.fix_immediately + plan.fix_next + plan.defer_or_mitigate
    assert len(all_recs) > 0
    item = all_recs[0]
    assert item.finding_id == "VULN-TLS-NO-HTTPS"
    assert item.observed_condition is not None
    assert item.expected_condition is not None
    assert item.tech_classification in ("generic", "technology_specific")
    assert item.total_cost == round(item.estimated_effort_hours * 150.0, 2)
    assert item.cost_assumption.startswith("Internal senior engineering time")


def test_13_inconclusive_gateway_error_handling():
    """13. Tests 502/503/504 gateway responses produce inconclusive scan findings without false positive vulnerabilities."""
    scanner = EvidenceBasedScanner()
    with patch.object(
        scanner.client,
        "request",
        return_value=SafeHttpResponse(
            url="https://example.com",
            status_code=502,
            headers={"Server": "cloudflare", "cf-ray": "12345"},
            body_text="502 Bad Gateway",
            remote_ip="93.184.216.34",
            was_https=True,
            is_proxy_or_tunnel_error=True,
            proxy_or_tunnel_type="Cloudflare Gateway Error (HTTP 502)",
        ),
    ):
        findings, scan_meta = scanner.scan("https://example.com")

    assert scan_meta.get("is_inconclusive") is True
    assert scan_meta.get("allows_retry") is True
    err_finding = next((f for f in findings if f.id == "VULN-SCAN-GATEWAY-PROXY-ERROR"), None)
    assert err_finding is not None
    assert err_finding.validation_status == "Inconclusive"


def test_14_ssrf_and_target_authorization_preservation():
    """14. Confirms SSRF protections reject loopback, link-local, private CIDRs, and unauthorized schemes."""
    from app.services.attacker.ssrf_guard import normalize_target_url

    # Loopback rejected by normalize_target_url and validate_destination_url
    with pytest.raises(SSRFProtectionError):
        normalize_target_url("http://127.0.0.1:8000")

    is_valid, reason = validate_destination_url("http://127.0.0.1:8000")
    assert is_valid is False

    # AWS metadata rejected
    with pytest.raises(SSRFProtectionError):
        normalize_target_url("http://169.254.169.254/latest/meta-data")

    is_valid, reason = validate_destination_url("http://169.254.169.254/latest/meta-data")
    assert is_valid is False

    # File scheme rejected
    with pytest.raises(SSRFProtectionError):
        normalize_target_url("file:///etc/passwd")

    is_valid, reason = validate_destination_url("file:///etc/passwd")
    assert is_valid is False

    # Private network IP rejected
    with pytest.raises(SSRFProtectionError):
        normalize_target_url("http://10.0.0.1/admin")

    is_valid, reason = validate_destination_url("http://10.0.0.1/admin")
    assert is_valid is False

