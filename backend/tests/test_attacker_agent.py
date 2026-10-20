"""
Unit Tests for CyberQuant Attacker Agent.
Covers:
- URL validation and normalization
- SSRF protections, loopback, private ranges, cloud metadata, IPv6, DNS boundaries
- Adversarial DNS: mixed public/private answers, resolution deadlines
- Redirect scope preservation: loops, scheme downgrades, cross-port escapes
- Clickjacking validation: effective XFO vs CSP frame-ancestors
- CVE correlation: Apache 2.4.49 vs 2.4.50, unaffected versions, validation status
- security.txt classification: Security Best Practice / Informational Observation
- Concurrency limiter and HTTP 429 overload handling
- FastAPI endpoint contracts and error boundaries.
"""

import os
import socket
import unittest
from unittest.mock import MagicMock, patch
from fastapi import HTTPException

from app.schemas.attacker import (
    AttackerScanRequest,
    AttackerScanResponse,
    VulnerabilityFinding,
)
from app.services.attacker.ssrf_guard import (
    normalize_target_url,
    resolve_and_verify_ip,
    is_ip_forbidden,
    SSRFProtectionError,
    TargetAuthorizationError,
)
from app.services.attacker.cve_catalog import match_known_cve
from app.services.attacker.scanner import (
    EvidenceBasedScanner,
    SafeHttpClient,
    SafeHttpResponse,
)
from app.services.attacker.agent import AttackerAgentService
from app.api.v1.endpoints.attacker import scan_target, scan_limiter
import ipaddress


class TestSSRFGuard(unittest.TestCase):
    """Verifies boundary defenses against SSRF and target manipulation."""

    def test_normalize_valid_urls(self):
        url, host, port, path = normalize_target_url("https://example.com/login?ref=1")
        self.assertEqual(url, "https://example.com/login?ref=1")
        self.assertEqual(host, "example.com")
        self.assertEqual(port, 443)
        self.assertEqual(path, "/login?ref=1")

    def test_normalize_default_scheme(self):
        url, host, port, path = normalize_target_url("example.com")
        self.assertEqual(url, "https://example.com/")
        self.assertEqual(host, "example.com")
        self.assertEqual(port, 443)

    def test_disallow_unsupported_schemes(self):
        with self.assertRaises(SSRFProtectionError):
            normalize_target_url("ftp://example.com/resource")

        with self.assertRaises(SSRFProtectionError):
            normalize_target_url("file:///etc/passwd")

        with self.assertRaises(SSRFProtectionError):
            normalize_target_url("gopher://127.0.0.1:70")

    def test_disallow_embedded_credentials(self):
        with self.assertRaises(SSRFProtectionError):
            normalize_target_url("http://admin:secret@example.com/")

    def test_block_loopback_and_metadata_hostnames(self):
        blocked = [
            "localhost",
            "127.0.0.1",
            "metadata",
            "metadata.google.internal",
            "server.local",
            "api.internal",
            "test.lan",
        ]
        for b in blocked:
            with self.subTest(hostname=b):
                with self.assertRaises(SSRFProtectionError):
                    normalize_target_url(f"http://{b}")

    def test_forbidden_ip_ranges(self):
        forbidden_ips = [
            "127.0.0.1",
            "127.0.1.5",
            "10.0.0.1",
            "10.254.254.254",
            "172.16.0.5",
            "172.31.255.255",
            "192.168.1.1",
            "192.168.100.50",
            "169.254.169.254",  # AWS/GCP/Azure instance metadata
            "0.0.0.0",
            "255.255.255.255",
            "100.64.0.1",       # Carrier NAT
            "192.0.2.1",        # TEST-NET-1
            "198.51.100.1",     # TEST-NET-2
            "203.0.113.1",      # TEST-NET-3
            "::1",              # IPv6 loopback
            "fc00::1",          # IPv6 ULA
            "fe80::1",          # IPv6 link-local
            "::ffff:127.0.0.1", # IPv4-mapped IPv6 loopback
            "::ffff:169.254.169.254", # IPv4-mapped metadata
        ]
        for ip_str in forbidden_ips:
            with self.subTest(ip=ip_str):
                ip_obj = ipaddress.ip_address(ip_str)
                self.assertTrue(
                    is_ip_forbidden(ip_obj),
                    f"Expected {ip_str} to be marked forbidden",
                )

    def test_allowed_public_ips(self):
        allowed_ips = [
            "8.8.8.8",
            "1.1.1.1",
            "93.184.216.34",     # example.com
            "2606:4700:4700::1111", # Cloudflare public DNS
        ]
        for ip_str in allowed_ips:
            with self.subTest(ip=ip_str):
                ip_obj = ipaddress.ip_address(ip_str)
                self.assertFalse(
                    is_ip_forbidden(ip_obj),
                    f"Expected {ip_str} to be permitted as public IP",
                )

    def test_mixed_public_private_dns_answers_rejected(self):
        # Adversary DNS returns a public IP and a private loopback IP in the same response
        mock_addrinfo = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443)),
        ]
        with patch("socket.getaddrinfo", return_value=mock_addrinfo):
            with self.assertRaises(SSRFProtectionError) as ctx:
                resolve_and_verify_ip("attacker-mixed-dns.example.com", 443)
            self.assertIn("prohibited address '127.0.0.1'", str(ctx.exception))

    def test_dns_timeout_enforced(self):
        import time

        def slow_lookup(*args, **kwargs):
            time.sleep(0.1)
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]

        with patch("socket.getaddrinfo", side_effect=slow_lookup):
            with self.assertRaises(SSRFProtectionError) as ctx:
                resolve_and_verify_ip("slow-dns.example.com", 443, dns_timeout=0.01)
            self.assertIn("timed out", str(ctx.exception).lower())


class TestRedirectRestrictions(unittest.TestCase):
    """Verifies scope preservation and boundary enforcement across redirects."""

    def test_redirect_loop_exhaustion(self):
        mock_client = SafeHttpClient()
        # Mock request to trigger loop
        def mock_req(url, method="GET", allowed_origin_scheme=None, allowed_origin_host=None, allowed_origin_port=None, redirect_depth=0):
            if redirect_depth > 2:
                raise SSRFProtectionError("Exceeded maximum redirect limit (2).")
            return SafeHttpResponse(
                url=url,
                status_code=302,
                headers={"Location": f"/redirect-{redirect_depth + 1}"},
                body_text="",
                remote_ip="93.184.216.34",
                was_https=True,
            )

        with self.assertRaises(SSRFProtectionError) as ctx:
            mock_client.request("https://example.com/loop", redirect_depth=3)
        self.assertIn("Exceeded maximum redirect limit", str(ctx.exception))

    def test_cross_port_redirect_rejected(self):
        mock_client = SafeHttpClient()
        # Initial target on 443, redirect attempts to jump to port 8080
        with self.assertRaises(SSRFProtectionError) as ctx:
            mock_client.request(
                "https://example.com:8080/admin",
                allowed_origin_scheme="https",
                allowed_origin_host="example.com",
                allowed_origin_port=443,
                redirect_depth=1,
            )
        self.assertIn("escapes authorized target port scope", str(ctx.exception))

    def test_redirect_scheme_downgrade_rejected(self):
        mock_client = SafeHttpClient()
        # Initial target on HTTPS, redirect attempts to downgrade to HTTP
        with self.assertRaises(SSRFProtectionError) as ctx:
            mock_client.request(
                "http://example.com/insecure",
                allowed_origin_scheme="https",
                allowed_origin_host="example.com",
                allowed_origin_port=443,
                redirect_depth=1,
            )
        self.assertIn("Redirect scheme downgrade from HTTPS to HTTP", str(ctx.exception))

    def test_redirect_host_escape_rejected(self):
        mock_client = SafeHttpClient()
        # Initial target on example.com, redirect attempts to escape to other-domain.com
        with self.assertRaises(SSRFProtectionError) as ctx:
            mock_client.request(
                "https://other-domain.com/",
                allowed_origin_scheme="https",
                allowed_origin_host="example.com",
                allowed_origin_port=443,
                redirect_depth=1,
            )
        self.assertIn("escapes authorized target host", str(ctx.exception))


class TestCVECatalog(unittest.TestCase):
    """Verifies curated CVE correlation triggers only on verified version evidence."""

    def test_match_vulnerable_apache_2_4_49(self):
        match = match_known_cve("Apache/2.4.49 (Unix)")
        self.assertIsNotNone(match)
        self.assertEqual(match["cve_id"], "CVE-2021-41773")
        self.assertEqual(match["severity"], "Critical")
        self.assertIn("2.4.49", match["title"])

    def test_match_vulnerable_apache_2_4_50(self):
        match = match_known_cve("Apache/2.4.50 (Unix)")
        self.assertIsNotNone(match)
        self.assertEqual(match["cve_id"], "CVE-2021-42013")
        self.assertEqual(match["severity"], "Critical")
        self.assertIn("2.4.50", match["title"])

    def test_unaffected_apache_versions(self):
        self.assertIsNone(match_known_cve("Apache/2.4.51 (Unix)"))
        self.assertIsNone(match_known_cve("Apache/2.4.48 (Unix)"))
        self.assertIsNone(match_known_cve("Apache/2.4.58 (Ubuntu)"))

    def test_match_vulnerable_nginx(self):
        match = match_known_cve("nginx/1.16.0")
        self.assertIsNotNone(match)
        self.assertEqual(match["cve_id"], "CVE-2019-9511")

    def test_no_false_positive_for_unaffected_versions(self):
        self.assertIsNone(match_known_cve("nginx/1.24.0"))
        self.assertIsNone(match_known_cve("cloudflare"))
        self.assertIsNone(match_known_cve(""))


class TestEvidenceBasedScanner(unittest.TestCase):
    """Verifies evidence extraction, clickjacking, CVE confidence, and security.txt."""

    def test_scanner_marks_banner_cve_as_requiring_validation(self):
        mock_client = MagicMock(spec=SafeHttpClient)
        mock_client.request.return_value = SafeHttpResponse(
            url="https://app.example.com/",
            status_code=200,
            headers={
                "Server": "Apache/2.4.49",
                "Strict-Transport-Security": "max-age=31536000",
                "X-Frame-Options": "DENY",
                "X-Content-Type-Options": "nosniff",
                "Content-Security-Policy": "default-src 'self'",
            },
            body_text="<html><body>App</body></html>",
            remote_ip="93.184.216.34",
            was_https=True,
        )

        scanner = EvidenceBasedScanner(client=mock_client)
        findings, meta = scanner.scan("https://app.example.com/")

        cve_findings = [f for f in findings if f.cve_id == "CVE-2021-41773"]
        self.assertEqual(len(cve_findings), 1)
        cve_f = cve_findings[0]

        # Must NOT be marked as confirmed
        self.assertFalse(cve_f.is_confirmed)
        self.assertEqual(cve_f.confidence, "Medium")
        self.assertEqual(cve_f.validation_status, "Requires Further Validation")
        self.assertIn("Potential", cve_f.title)
        self.assertIn("Server Banner", cve_f.affected_url_or_component)

    def test_security_txt_classified_as_best_practice(self):
        mock_client = MagicMock(spec=SafeHttpClient)
        mock_client.request.return_value = SafeHttpResponse(
            url="https://app.example.com/.well-known/security.txt",
            status_code=404,
            headers={},
            body_text="",
            remote_ip="93.184.216.34",
            was_https=True,
        )

        scanner = EvidenceBasedScanner(client=mock_client)
        findings: list = []
        scanner._check_security_txt("app.example.com", 443, True, findings)

        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.id, "VULN-BEST-PRACTICE-NO-SECURITY-TXT")
        self.assertEqual(f.category, "Security Best Practice")
        self.assertEqual(f.severity, "Info")
        self.assertEqual(f.validation_status, "Informational Observation")

    def test_clickjacking_detection_matrix(self):
        scanner = EvidenceBasedScanner(client=MagicMock(spec=SafeHttpClient))

        # Case 1: No XFO, No CSP -> Flagged
        findings = []
        r1 = SafeHttpResponse("https://t.com", 200, {}, "", "1.1.1.1", True)
        scanner._check_security_headers(r1, findings)
        self.assertTrue(any(f.id == "VULN-SEC-HDR-NO-XFO" for f in findings))

        # Case 2: Generic CSP without frame-ancestors, No XFO -> STILL Flagged
        findings = []
        r2 = SafeHttpResponse("https://t.com", 200, {"Content-Security-Policy": "script-src 'self'"}, "", "1.1.1.1", True)
        scanner._check_security_headers(r2, findings)
        self.assertTrue(any(f.id == "VULN-SEC-HDR-NO-XFO" for f in findings))

        # Case 3: Ineffective XFO (ALLOWALL), No CSP -> Flagged
        findings = []
        r3 = SafeHttpResponse("https://t.com", 200, {"X-Frame-Options": "ALLOWALL"}, "", "1.1.1.1", True)
        scanner._check_security_headers(r3, findings)
        self.assertTrue(any(f.id == "VULN-SEC-HDR-NO-XFO" for f in findings))

        # Case 4: Effective CSP with frame-ancestors 'self' -> NOT Flagged
        findings = []
        r4 = SafeHttpResponse("https://t.com", 200, {"Content-Security-Policy": "frame-ancestors 'self'"}, "", "1.1.1.1", True)
        scanner._check_security_headers(r4, findings)
        self.assertFalse(any(f.id == "VULN-SEC-HDR-NO-XFO" for f in findings))

        # Case 5: Effective X-Frame-Options SAMEORIGIN -> NOT Flagged
        findings = []
        r5 = SafeHttpResponse("https://t.com", 200, {"X-Frame-Options": "SAMEORIGIN"}, "", "1.1.1.1", True)
        scanner._check_security_headers(r5, findings)
        self.assertFalse(any(f.id == "VULN-SEC-HDR-NO-XFO" for f in findings))


    def test_scanner_on_hardened_site(self):
        mock_client = MagicMock(spec=SafeHttpClient)
        mock_client.request.return_value = SafeHttpResponse(
            url="https://secure.example.com/",
            status_code=200,
            headers={
                "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
                "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                "Set-Cookie": "session=xyz; Secure; HttpOnly; SameSite=Strict",
            },
            body_text="<html><body>Secure Page</body></html>",
            remote_ip="93.184.216.34",
            was_https=True,
        )

        scanner = EvidenceBasedScanner(client=mock_client)
        findings, meta = scanner.scan("https://secure.example.com/")

        high_or_crit = [f for f in findings if f.severity in ("Critical", "High", "Medium")]
        self.assertEqual(len(high_or_crit), 0)

    def test_http_200_missing_headers_populates_evidence(self):
        """Tests that a standard HTTP 200 response missing security headers accurately generates evidence-backed findings."""
        mock_client = MagicMock(spec=SafeHttpClient)
        mock_client.request.return_value = SafeHttpResponse(
            url="https://app.example.com/",
            status_code=200,
            headers={
                "Server": "CustomApp/1.0",
                "Content-Type": "text/html; charset=utf-8",
            },
            body_text="<html><body>Hello World</body></html>",
            remote_ip="93.184.216.34",
            was_https=True,
            requested_url="https://app.example.com/",
            final_url="https://app.example.com/",
        )

        scanner = EvidenceBasedScanner(client=mock_client)
        findings, meta = scanner.scan("https://app.example.com/")

        self.assertFalse(meta.get("is_inconclusive", False))
        self.assertFalse(meta.get("allows_retry", False))

        finding_ids = [f.id for f in findings]
        self.assertIn("VULN-TLS-MISSING-HSTS", finding_ids)
        self.assertIn("VULN-SEC-HDR-NO-CSP", finding_ids)
        self.assertIn("VULN-SEC-HDR-NO-NOSNIFF", finding_ids)
        self.assertIn("VULN-SEC-HDR-NO-XFO", finding_ids)
        self.assertIn("VULN-SEC-HDR-NO-REFERRER", finding_ids)
        self.assertIn("VULN-SEC-HDR-NO-PERMISSIONS", finding_ids)

        csp_f = next(f for f in findings if f.id == "VULN-SEC-HDR-NO-CSP")
        self.assertEqual(csp_f.evidence.status_code, 200)
        self.assertEqual(csp_f.evidence.check_result, "Potential risk")
        self.assertTrue(csp_f.evidence.is_inferred)
        self.assertIn("absence of the Content-Security-Policy header", csp_f.evidence.confidence_reason)

    def test_http_502_proxy_response_marked_inconclusive_without_header_findings(self):
        """Tests that HTTP 502 Bad Gateway responses are marked inconclusive and do not report missing headers."""
        mock_client = MagicMock(spec=SafeHttpClient)
        mock_client.request.return_value = SafeHttpResponse(
            url="https://app.example.com/",
            status_code=502,
            headers={
                "Server": "cloudflare",
                "CF-RAY": "8234abcd1234-IAD",
                "Content-Type": "text/html",
            },
            body_text="<html><head><title>502 Bad Gateway</title></head><body>Cloudflare Bad Gateway</body></html>",
            remote_ip="104.21.5.12",
            was_https=True,
            requested_url="https://app.example.com/",
            final_url="https://app.example.com/",
        )

        scanner = EvidenceBasedScanner(client=mock_client)
        findings, meta = scanner.scan("https://app.example.com/")

        self.assertTrue(meta["is_inconclusive"])
        self.assertTrue(meta["allows_retry"])
        self.assertEqual(len(findings), 1)

        gateway_f = findings[0]
        self.assertEqual(gateway_f.id, "VULN-SCAN-GATEWAY-PROXY-ERROR")
        self.assertEqual(gateway_f.validation_status, "Inconclusive")
        self.assertEqual(gateway_f.evidence.check_result, "Inconclusive")
        self.assertIn("Cloudflare Gateway Error (HTTP 502)", gateway_f.title)
        self.assertEqual(gateway_f.evidence.status_code, 502)

        # Missing headers MUST NOT be flagged
        self.assertNotIn("VULN-SEC-HDR-NO-CSP", [f.id for f in findings])
        self.assertNotIn("VULN-TLS-MISSING-HSTS", [f.id for f in findings])

    def test_connection_failure_records_scan_error(self):
        """Tests that socket/connection timeout generates a clear Scan Error finding with retry allowed."""
        mock_client = MagicMock(spec=SafeHttpClient)
        mock_client.request.side_effect = socket.timeout("Timed out connecting to target port 443")

        scanner = EvidenceBasedScanner(client=mock_client)
        findings, meta = scanner.scan("https://unreachable.example.com/")

        self.assertTrue(meta["is_inconclusive"])
        self.assertTrue(meta["allows_retry"])
        self.assertEqual(len(findings), 1)

        err_f = findings[0]
        self.assertEqual(err_f.id, "VULN-SCAN-CONNECTION-FAILED")
        self.assertEqual(err_f.validation_status, "Scan error")
        self.assertEqual(err_f.evidence.check_result, "Scan error")
        self.assertIn("Timed out", err_f.evidence.raw_snippet)

    def test_redirect_records_requested_and_final_urls(self):
        """Tests that SafeHttpClient and SafeHttpResponse accurately preserve the requested and final URLs after redirection."""
        mock_client = MagicMock(spec=SafeHttpClient)
        mock_client.request.return_value = SafeHttpResponse(
            url="https://example.com/welcome",
            status_code=200,
            headers={
                "Strict-Transport-Security": "max-age=31536000",
                "Content-Security-Policy": "default-src 'self'",
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
            },
            body_text="<html><body>Welcome</body></html>",
            remote_ip="93.184.216.34",
            was_https=True,
            requested_url="https://example.com/",
            final_url="https://example.com/welcome",
            redirect_chain=[{"from_url": "https://example.com/", "to_url": "https://example.com/welcome", "status_code": 302}],
        )

        scanner = EvidenceBasedScanner(client=mock_client)
        findings, meta = scanner.scan("https://example.com/")

        self.assertEqual(meta["requested_url"], "https://example.com/")
        self.assertEqual(meta["final_url"], "https://example.com/welcome")

    def test_hsts_evaluated_only_on_https_responses(self):
        """Tests that HSTS is NOT reported as missing for plain HTTP responses (RFC 6797)."""
        scanner = EvidenceBasedScanner(client=MagicMock(spec=SafeHttpClient))
        findings = []

        http_resp = SafeHttpResponse(
            url="http://example.com/",
            status_code=200,
            headers={},
            body_text="",
            remote_ip="93.184.216.34",
            was_https=False,
            requested_url="http://example.com/",
            final_url="http://example.com/",
        )
        scanner._check_transport_security(http_resp, findings)

        # Cleartext HTTP is flagged, but Missing HSTS is NOT flagged on HTTP
        self.assertTrue(any(f.id == "VULN-TLS-NO-HTTPS" for f in findings))
        self.assertFalse(any(f.id == "VULN-TLS-MISSING-HSTS" for f in findings))

        # Over HTTPS without HSTS: Missing HSTS IS flagged
        findings_https = []
        https_resp = SafeHttpResponse(
            url="https://example.com/",
            status_code=200,
            headers={},
            body_text="",
            remote_ip="93.184.216.34",
            was_https=True,
            requested_url="https://example.com/",
            final_url="https://example.com/",
        )
        scanner._check_transport_security(https_resp, findings_https)
        self.assertTrue(any(f.id == "VULN-TLS-MISSING-HSTS" for f in findings_https))

    def test_csp_frame_ancestors_mitigates_clickjacking(self):
        """Tests that CSP frame-ancestors mitigates clickjacking even when X-Frame-Options is missing."""
        scanner = EvidenceBasedScanner(client=MagicMock(spec=SafeHttpClient))
        findings = []

        resp = SafeHttpResponse(
            url="https://example.com/",
            status_code=200,
            headers={"Content-Security-Policy": "frame-ancestors 'self'"},
            body_text="",
            remote_ip="93.184.216.34",
            was_https=True,
        )
        scanner._check_security_headers(resp, findings)

        self.assertFalse(any(f.id == "VULN-SEC-HDR-NO-XFO" for f in findings))

    def test_security_txt_response_variations(self):
        """Tests security.txt handling for 200 (valid & invalid format), 404 (missing), and 403 (inaccessible)."""
        mock_client = MagicMock(spec=SafeHttpClient)
        scanner = EvidenceBasedScanner(client=mock_client)

        # 1. 200 with valid Contact: directive -> Valid RFC 9116, no finding
        mock_client.request.return_value = SafeHttpResponse(
            url="https://example.com/.well-known/security.txt",
            status_code=200,
            headers={"Content-Type": "text/plain"},
            body_text="Contact: mailto:security@example.com\nExpires: 2027-12-31T23:59:59.000Z\n",
            remote_ip="93.184.216.34",
            was_https=True,
        )
        f_valid = []
        scanner._check_security_txt("example.com", 443, True, f_valid)
        self.assertEqual(len(f_valid), 0)

        # 2. 200 with HTML or missing Contact -> Invalid RFC 9116 format
        mock_client.request.return_value = SafeHttpResponse(
            url="https://example.com/.well-known/security.txt",
            status_code=200,
            headers={"Content-Type": "text/html"},
            body_text="<html><body>Welcome to our website</body></html>",
            remote_ip="93.184.216.34",
            was_https=True,
        )
        f_invalid = []
        scanner._check_security_txt("example.com", 443, True, f_invalid)
        self.assertEqual(len(f_invalid), 1)
        self.assertEqual(f_invalid[0].id, "VULN-BEST-PRACTICE-INVALID-SECURITY-TXT")
        self.assertEqual(f_invalid[0].validation_status, "Confirmed Observation")

        # 3. 404 Not Found -> Missing security.txt
        mock_client.request.return_value = SafeHttpResponse(
            url="https://example.com/.well-known/security.txt",
            status_code=404,
            headers={},
            body_text="",
            remote_ip="93.184.216.34",
            was_https=True,
        )
        f_404 = []
        scanner._check_security_txt("example.com", 443, True, f_404)
        self.assertEqual(len(f_404), 1)
        self.assertEqual(f_404[0].id, "VULN-BEST-PRACTICE-NO-SECURITY-TXT")
        self.assertEqual(f_404[0].validation_status, "Informational Observation")

        # 4. 403 Forbidden -> Inaccessible security.txt (Inconclusive)
        mock_client.request.return_value = SafeHttpResponse(
            url="https://example.com/.well-known/security.txt",
            status_code=403,
            headers={},
            body_text="Forbidden",
            remote_ip="93.184.216.34",
            was_https=True,
        )
        f_403 = []
        scanner._check_security_txt("example.com", 443, True, f_403)
        self.assertEqual(len(f_403), 1)
        self.assertEqual(f_403[0].id, "VULN-BEST-PRACTICE-INACCESSIBLE-SECURITY-TXT")
        self.assertEqual(f_403[0].validation_status, "Inconclusive")


class TestAttackerAgentService(unittest.TestCase):
    """Verifies AI Agent orchestration, authorization gates, and threat modeling."""

    def test_unauthorized_scan_rejected(self):
        service = AttackerAgentService()
        req = AttackerScanRequest(target_url="https://example.com", is_authorized=False)
        with self.assertRaises(TargetAuthorizationError):
            service.run_scan(req)

    def test_agent_synthesizes_inferred_scenarios_from_evidence(self):
        mock_client = MagicMock(spec=SafeHttpClient)
        mock_client.request.return_value = SafeHttpResponse(
            url="https://demo.example.com/",
            status_code=200,
            headers={
                "Server": "Apache/2.4.49",
                "Set-Cookie": "auth_token=secret123",
            },
            body_text="<html><body>App</body></html>",
            remote_ip="93.184.216.34",
            was_https=True,
        )

        scanner = EvidenceBasedScanner(client=mock_client)
        service = AttackerAgentService(scanner=scanner)

        req = AttackerScanRequest(target_url="https://demo.example.com", is_authorized=True)
        response = service.run_scan(req)

        self.assertIsInstance(response, AttackerScanResponse)
        self.assertEqual(response.status, "completed")
        self.assertGreater(response.summary.total_findings, 0)

        for scenario in response.inferred_attack_scenarios:
            self.assertIn("Inferred Hypothesis", scenario.confidence)
            self.assertTrue(len(scenario.modeled_chain) >= 2)

        self.assertTrue(response.defender_handover["ready_for_defender_agent"])
        self.assertIn("deploy_csp_and_frame_options", response.defender_handover["required_countermeasures"])


class TestAttackerEndpoint(unittest.TestCase):
    """Tests POST /api/v1/attacker/scan FastAPI endpoint directly."""

    def test_endpoint_blocks_ssrf(self):
        req = AttackerScanRequest(target_url="http://127.0.0.1:8080", is_authorized=True)
        with self.assertRaises(HTTPException) as ctx:
            scan_target(req)
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertIn("SSRF", ctx.exception.detail)

    def test_endpoint_blocks_unauthorized(self):
        req = AttackerScanRequest(target_url="https://example.com", is_authorized=False)
        with self.assertRaises(HTTPException) as ctx:
            scan_target(req)
        self.assertEqual(ctx.exception.status_code, 403)
        self.assertIn("Authorization rejected", ctx.exception.detail)

    def test_endpoint_timeout_returns_504(self):
        req = AttackerScanRequest(target_url="https://example.com", is_authorized=True)
        with patch.object(AttackerAgentService, "run_scan", side_effect=TimeoutError("Connection timeout")):
            with self.assertRaises(HTTPException) as ctx:
                scan_target(req)
            self.assertEqual(ctx.exception.status_code, 504)
            self.assertIn("timed out", ctx.exception.detail)

    def test_endpoint_concurrency_limit_429(self):
        # Fill all available slots in scan_limiter
        acquired_slots = []
        while scan_limiter.try_acquire():
            acquired_slots.append(True)

        try:
            req = AttackerScanRequest(target_url="https://example.com", is_authorized=True)
            # When limiter is saturated, endpoint must immediately reject with 429
            with self.assertRaises(HTTPException) as ctx:
                scan_target(req)
            self.assertEqual(ctx.exception.status_code, 429)
            self.assertIn("Scan concurrency limit reached", ctx.exception.detail)
        finally:
            # Release acquired slots to restore state
            for _ in acquired_slots:
                scan_limiter.release()


class TestLocalDevScanningOptIn(unittest.TestCase):
    """
    Verifies the opt-in local development scanning workflow:
    1. Disabled by default in production.
    2. Only accepts the strictly configured host & port (e.g. localhost:4000).
    3. Rejects other internal/private ports, IPs, and cloud metadata.
    4. Prohibits redirects escaping to other local services or ports.
    5. Confirms that public-target scanning protections remain active.
    """

    def test_default_production_blocks_localhost_and_ports(self):
        # Ensure dev flags are NOT set
        with patch.dict(os.environ, {"ALLOW_LOCAL_DEV_SCAN": "", "CYBERSENTINEL_ENV": "production"}):
            with self.assertRaises(SSRFProtectionError) as ctx:
                normalize_target_url("http://localhost:4000")
            self.assertIn("prohibited loopback/internal destination", str(ctx.exception))

            with self.assertRaises(SSRFProtectionError):
                normalize_target_url("http://127.0.0.1:4000")

    def test_configured_local_target_accepted_in_dev_mode(self):
        env_vars = {
            "ALLOW_LOCAL_DEV_SCAN": "true",
            "CYBERSENTINEL_ENV": "development",
            "LOCAL_DEV_TARGET": "http://localhost:4000",
        }
        with patch.dict(os.environ, env_vars):
            norm_url, host, port, path = normalize_target_url("http://localhost:4000/app")
            self.assertEqual(norm_url, "http://localhost:4000/app")
            self.assertEqual(host, "localhost")
            self.assertEqual(port, 4000)

            # Verification of IP resolution with loopback address
            mock_addrinfo = [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 4000)),
            ]
            with patch("socket.getaddrinfo", return_value=mock_addrinfo):
                ip_str, family = resolve_and_verify_ip("localhost", 4000)
                self.assertEqual(ip_str, "127.0.0.1")
                self.assertEqual(family, socket.AF_INET)

    def test_unrelated_local_ports_rejected_even_in_dev_mode(self):
        # If LOCAL_DEV_TARGET is port 4000, attempt to scan port 8080 or port 22 or port 8010 must be blocked
        env_vars = {
            "ALLOW_LOCAL_DEV_SCAN": "true",
            "CYBERSENTINEL_ENV": "development",
            "LOCAL_DEV_TARGET": "http://localhost:4000",
        }
        with patch.dict(os.environ, env_vars):
            # Port 8010 (our backend)
            with self.assertRaises(SSRFProtectionError):
                normalize_target_url("http://localhost:8010")

            # Port 22 (SSH)
            with self.assertRaises(SSRFProtectionError):
                normalize_target_url("http://localhost:22")

            # Port 8080 (ZAP or internal service)
            with self.assertRaises(SSRFProtectionError):
                normalize_target_url("http://localhost:8080")

    def test_private_networks_and_metadata_blocked_in_dev_mode(self):
        # Even with local dev scan enabled, other private IPs and cloud metadata MUST remain blocked
        env_vars = {
            "ALLOW_LOCAL_DEV_SCAN": "true",
            "CYBERSENTINEL_ENV": "development",
            "LOCAL_DEV_TARGET": "http://localhost:4000",
        }
        with patch.dict(os.environ, env_vars):
            # Cloud metadata
            with self.assertRaises(SSRFProtectionError):
                normalize_target_url("http://169.254.169.254/latest/meta-data/")

            # RFC1918 Private networks
            with self.assertRaises(SSRFProtectionError):
                normalize_target_url("http://192.168.1.1:4000")

            with self.assertRaises(SSRFProtectionError):
                normalize_target_url("http://10.0.0.1:4000")

    def test_redirect_from_local_target_cannot_escape_port_or_host(self):
        # A test application on localhost:4000 attempting to redirect to localhost:8010 or 169.254.169.254
        env_vars = {
            "ALLOW_LOCAL_DEV_SCAN": "true",
            "CYBERSENTINEL_ENV": "development",
            "LOCAL_DEV_TARGET": "http://localhost:4000",
        }
        with patch.dict(os.environ, env_vars):
            mock_client = SafeHttpClient()

            # Attempt redirect to another port (rejected either by SSRF guard or redirect port constraint)
            with self.assertRaises(SSRFProtectionError) as ctx:
                mock_client.request(
                    "http://localhost:8010/internal",
                    allowed_origin_scheme="http",
                    allowed_origin_host="localhost",
                    allowed_origin_port=4000,
                    redirect_depth=1,
                )
            self.assertTrue(
                "escapes authorized target port scope" in str(ctx.exception)
                or "prohibited loopback/internal destination" in str(ctx.exception)
            )

            # Attempt redirect to another host (e.g. cloud metadata)
            with self.assertRaises(SSRFProtectionError) as ctx:
                mock_client.request(
                    "http://169.254.169.254/metadata",
                    allowed_origin_scheme="http",
                    allowed_origin_host="localhost",
                    allowed_origin_port=4000,
                    redirect_depth=1,
                )
            self.assertTrue(
                "escapes authorized target host" in str(ctx.exception)
                or "prohibited private" in str(ctx.exception)
            )

    def test_dns_rebinding_to_private_non_loopback_rejected_in_dev_mode(self):
        # If localhost:4000 resolved to a non-loopback private IP (e.g. 10.0.0.1 or 192.168.1.5), it must be rejected
        env_vars = {
            "ALLOW_LOCAL_DEV_SCAN": "true",
            "CYBERSENTINEL_ENV": "development",
            "LOCAL_DEV_TARGET": "http://localhost:4000",
        }
        with patch.dict(os.environ, env_vars):
            mock_addrinfo = [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.1", 4000)),
            ]
            with patch("socket.getaddrinfo", return_value=mock_addrinfo):
                with self.assertRaises(SSRFProtectionError) as ctx:
                    resolve_and_verify_ip("localhost", 4000)
                self.assertIn("non-loopback prohibited address", str(ctx.exception))


class TestAdversarialSecuritySuite(unittest.TestCase):
    """
    Adversarial security tests verifying:
    1. Unusual IP encodings and scheme manipulation
    2. Socket connection IP pinning (TOCTOU / DNS rebinding defense)
    3. Server-side authorization enforcement
    4. Malformed JSON and unexpected parameters
    5. Redirect chaining attempting to jump to internal destinations
    """

    def test_unusual_schemes_and_malformed_urls(self):
        prohibited_urls = [
            "gopher://127.0.0.1:70/_",
            "dict://127.0.0.1:2628/",
            "ldap://127.0.0.1:389/",
            "file:///etc/shadow",
            "data:text/html,<script>alert(1)</script>",
            "javascript:alert(1)",
            "php://filter/read=convert.base64-encode/resource=index.php",
            "http://",
            "https://",
            "http://:80",
            "http://user:pass@example.com",
            "http://example.com:99999",
            "http://example.com:-1",
        ]
        for bad_url in prohibited_urls:
            with self.subTest(url=bad_url):
                with self.assertRaises(SSRFProtectionError):
                    normalize_target_url(bad_url)

    def test_ip_pinning_guarantees_connection_to_verified_ip(self):
        """
        Verifies that SafeHttpClient binds the raw TCP socket directly
        to the validated destination IP string, ensuring that any subsequent
        DNS changes (rebinding) do not affect the active connection.
        """
        client = SafeHttpClient()
        with patch("app.services.attacker.scanner.resolve_and_verify_ip") as mock_resolve, \
             patch("socket.socket") as mock_socket_ctor:
            mock_resolve.return_value = ("93.184.216.34", socket.AF_INET)
            mock_sock = MagicMock()
            mock_socket_ctor.return_value = mock_sock

            # Fake minimal HTTP response bytes
            mock_sock.recv.side_effect = [
                b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nOK",
                b"",
            ]

            resp = client.request("http://example.com/test")

            # Check that socket.connect was called with the exact verified IP, not the hostname
            mock_sock.connect.assert_called_once_with(("93.184.216.34", 80))
            self.assertEqual(resp.remote_ip, "93.184.216.34")

    def test_redirect_to_cloud_metadata_blocked(self):
        """
        Verifies that a server returning a 302 redirecting to AWS/GCP
        metadata service (169.254.169.254) is intercepted and aborted.
        """
        client = SafeHttpClient()
        with patch("app.services.attacker.scanner.resolve_and_verify_ip") as mock_resolve, \
             patch("socket.socket") as mock_socket_ctor:
            mock_resolve.return_value = ("93.184.216.34", socket.AF_INET)
            mock_sock = MagicMock()
            mock_socket_ctor.return_value = mock_sock

            # Mock 302 redirecting to 169.254.169.254
            mock_sock.recv.side_effect = [
                b"HTTP/1.1 302 Found\r\nLocation: http://169.254.169.254/latest/meta-data/\r\n\r\n",
                b"",
            ]

            with self.assertRaises(SSRFProtectionError) as ctx:
                client.request("http://example.com/")

            self.assertTrue(
                "escapes authorized target host" in str(ctx.exception)
                or "prohibited" in str(ctx.exception)
            )

    def test_authorization_strictly_enforced_server_side(self):
        """Every scan entry point must reject false, missing, or empty authorization."""
        from app.services.attacker.agent import AttackerAgentService

        service = AttackerAgentService()

        # Missing / false authorization
        req_false = AttackerScanRequest(target_url="https://example.com", is_authorized=False)
        with self.assertRaises(TargetAuthorizationError):
            service.run_scan(req_false)

        # In crawl job manager
        from app.services.attacker.job_manager import scan_job_manager
        with self.assertRaises(TargetAuthorizationError):
            scan_job_manager.create_job(req_false)

    def test_validate_destination_url_enforces_port_restrictions(self):
        """Crawler URL routing must reject exotic/non-standard ports for public targets."""
        from app.services.attacker.ssrf_guard import validate_destination_url

        # Ports like 22 (SSH), 25 (SMTP), 3306 (MySQL), 6379 (Redis) must be rejected
        for bad_port in (22, 25, 3306, 6379, 9200):
            with self.subTest(port=bad_port):
                is_safe, reason = validate_destination_url(f"http://example.com:{bad_port}/")
                self.assertFalse(is_safe)
                self.assertIn("Forbidden port", reason)


if __name__ == "__main__":
    unittest.main()
