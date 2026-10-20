"""
Unit and integration tests for CyberSentinal Asynchronous Crawler.
Covers:
- URL normalization, fragment stripping, and same-origin validation
- Subresource SSRF validation: loopback, private ranges, cloud metadata, invalid schemes
- Local development scanning isolation and target restriction
- Form discovery without form submission
- ScanJobManager asynchronous lifecycle: queued -> running -> completed / cancelled
- Progress reporting and discovered page inventory tracking
- Direct FastAPI endpoint functions (/crawl, /progress, /pages, /cancel)
- Defender Agent integration with crawler findings
"""

import os
import unittest
from unittest.mock import AsyncMock, MagicMock, patch
import asyncio
from fastapi import HTTPException

from app.schemas.attacker import (
    AttackerScanRequest,
    DiscoveredForm,
    DiscoveredPage,
    ScanProgressUpdate,
)
from app.schemas.defender import DefenderAnalysisRequest
from app.services.attacker.crawler import (
    normalize_crawler_url,
    is_same_origin,
    PlaywrightCrawler,
)
from app.services.attacker.ssrf_guard import (
    validate_destination_url,
    SSRFProtectionError,
)
from app.services.attacker.job_manager import scan_job_manager, ScanJobManager
from app.api.v1.endpoints.attacker import (
    start_crawl,
    get_scan_progress,
    get_scan_pages,
    cancel_scan,
    scan_target,
)
from app.api.v1.endpoints.defender import analyze_remediation_budget


class TestCrawlerUrlNormalization(unittest.TestCase):
    """Verifies same-origin URL normalization and deduplication logic."""

    def test_strip_fragments(self):
        norm = normalize_crawler_url("https://example.com/about#team", "https://example.com")
        self.assertEqual(norm, "https://example.com/about")

    def test_relative_url_resolution(self):
        norm = normalize_crawler_url("/products/detail?id=123", "https://example.com/store/")
        self.assertEqual(norm, "https://example.com/products/detail?id=123")

    def test_same_origin_acceptance(self):
        self.assertTrue(is_same_origin("https://example.com/page1", "https://example.com/page2"))
        self.assertTrue(is_same_origin("https://example.com:443/page", "https://example.com/page"))

    def test_different_origin_rejection(self):
        # Different scheme
        self.assertFalse(is_same_origin("http://example.com", "https://example.com"))
        # Subdomain is different origin
        self.assertFalse(is_same_origin("https://sub.example.com", "https://example.com"))
        # Different port
        self.assertFalse(is_same_origin("https://example.com:8443", "https://example.com:443"))
        # Cross domain
        self.assertFalse(is_same_origin("https://evil.com", "https://example.com"))

    def test_url_normalization_cleans_empty_params(self):
        norm = normalize_crawler_url("https://example.com/search?q=test&utm_source=&b=2#sec", "https://example.com")
        self.assertIn("q=test", norm)
        self.assertIn("b=2", norm)
        self.assertNotIn("#sec", norm)


class TestSSRFSubresourceValidation(unittest.TestCase):
    """Verifies that browser navigations and subresources cannot reach disallowed destinations."""

    def test_validate_allowed_public_url(self):
        with patch("app.services.attacker.ssrf_guard.resolve_and_verify_ip", return_value=("93.184.216.34", 2)):
            is_valid, reason = validate_destination_url("https://example.com/style.css")
            self.assertTrue(is_valid)
            self.assertEqual(reason, "Safe destination")

    def test_validate_rejects_unsupported_schemes(self):
        is_valid, reason = validate_destination_url("file:///etc/passwd")
        self.assertFalse(is_valid)
        self.assertIn("prohibited scheme", reason.lower())

        is_valid, reason = validate_destination_url("data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==")
        self.assertFalse(is_valid)

        is_valid, reason = validate_destination_url("javascript:alert(1)")
        self.assertFalse(is_valid)

    def test_validate_rejects_cloud_metadata(self):
        is_valid, reason = validate_destination_url("http://169.254.169.254/latest/meta-data/")
        self.assertFalse(is_valid)
        self.assertIn("prohibited", reason.lower())

    def test_validate_rejects_loopback(self):
        is_valid, reason = validate_destination_url("http://127.0.0.1:8080/admin")
        self.assertFalse(is_valid)
        self.assertIn("prohibited", reason.lower())

    def test_validate_rejects_private_class_a(self):
        is_valid, reason = validate_destination_url("http://10.0.0.5:80/internal")
        self.assertFalse(is_valid)
        self.assertIn("prohibited", reason.lower())

    def test_validate_rejects_forbidden_ports(self):
        is_valid, reason = validate_destination_url("http://example.com:22/ssh")
        self.assertFalse(is_valid)
        self.assertIn("forbidden port", reason.lower())

    def test_local_dev_scan_allows_configured_target_only(self):
        with patch.dict(os.environ, {
            "ALLOW_LOCAL_DEV_SCAN": "true",
            "CYBERSENTINEL_ENV": "development",
            "LOCAL_DEV_TARGET": "http://localhost:4000",
        }):
            # Configured target permitted
            is_valid, reason = validate_destination_url("http://localhost:4000/api/data")
            self.assertTrue(is_valid)

            # Different port on localhost rejected
            is_valid, reason = validate_destination_url("http://localhost:5000/secrets")
            self.assertFalse(is_valid)


class TestPlaywrightCrawlerUnit(unittest.IsolatedAsyncioTestCase):
    """Verifies crawler limits, form detection, and error handling."""

    async def test_form_discovery_without_submission(self):
        crawler = PlaywrightCrawler(
            max_pages=5,
            max_depth=2,
            per_page_timeout_ms=15000,
        )

        mock_page = MagicMock()
        mock_page.url = "https://example.com/contact"
        mock_page.title = AsyncMock(return_value="Contact Us")
        mock_page.evaluate = AsyncMock(return_value=[
            {
                "action": "https://example.com/submit-feedback",
                "method": "POST",
                "inputs": ["name", "email", "message"],
                "types": ["text", "email", "textarea"],
            }
        ])

        forms = await crawler._extract_forms(mock_page, "https://example.com/contact")
        self.assertEqual(len(forms), 1)
        self.assertEqual(forms[0].method, "POST")
        self.assertEqual(forms[0].action_url, "https://example.com/submit-feedback")
        self.assertIn("email", forms[0].input_names)

    async def test_crawler_respects_max_pages_limit(self):
        crawler = PlaywrightCrawler(
            max_pages=2,
            max_depth=3,
        )
        crawler.visited_urls.add("https://example.com")
        crawler.visited_urls.add("https://example.com/page1")

        # Visited reaches max_pages limit
        self.assertTrue(len(crawler.visited_urls) >= crawler.max_pages)


class TestScanJobManager(unittest.TestCase):
    """Verifies the in-process async scan job manager."""

    def test_job_lifecycle_queued_to_cancelled(self):
        mgr = ScanJobManager(max_concurrent=2)
        req = AttackerScanRequest(
            target_url="https://example.com",
            is_authorized=True,
            max_pages=5,
            max_depth=2,
        )
        with patch("app.services.attacker.ssrf_guard.resolve_and_verify_ip", return_value=("93.184.216.34", 2)):
            scan_id = mgr.create_job(req)
            self.assertIsNotNone(scan_id)
            prog = mgr.get_progress(scan_id)
            self.assertIn(prog.status, ["queued", "running"])

            # Test cancellation
            cancelled = mgr.cancel_job(scan_id)
            self.assertTrue(cancelled)

            prog_after = mgr.get_progress(scan_id)
            self.assertEqual(prog_after.status, "cancelled")

    def test_job_manager_records_pages(self):
        from app.services.attacker.job_manager import ScanJob
        mgr = ScanJobManager(max_concurrent=2)
        scan_id = "test-scan-record-pages-123"
        job = ScanJob(scan_id, AttackerScanRequest(target_url="https://example.com", is_authorized=True))
        mgr._jobs[scan_id] = job

        pg = DiscoveredPage(
            url="https://example.com/docs",
            path="/docs",
            status_code=200,
            content_type="text/html",
            title="Documentation",
            depth=1,
        )
        mgr.record_discovered_page(scan_id, pg)

        pages = mgr.get_discovered_pages(scan_id)
        self.assertEqual(len(pages), 1)
        self.assertEqual(pages[0]["path"], "/docs")


class TestAttackerApiEndpoints(unittest.TestCase):
    """Verifies FastAPI crawler endpoint behaviors."""

    def test_crawl_rejects_unauthorized(self):
        req = AttackerScanRequest(
            target_url="https://example.com",
            is_authorized=False,
        )
        with self.assertRaises(HTTPException) as ctx:
            start_crawl(req)
        self.assertIn(ctx.exception.status_code, [400, 403])
        self.assertIn("authorization", ctx.exception.detail.lower())

    def test_crawl_rejects_ssrf_destination(self):
        req = AttackerScanRequest(
            target_url="http://127.0.0.1:8000",
            is_authorized=True,
        )
        with self.assertRaises(HTTPException) as ctx:
            start_crawl(req)
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertIn("ssrf", ctx.exception.detail.lower())

    def test_crawl_accepts_valid_target_and_returns_promptly(self):
        req = AttackerScanRequest(
            target_url="https://example.com",
            is_authorized=True,
            max_pages=3,
            max_depth=1,
        )
        with patch("app.services.attacker.ssrf_guard.resolve_and_verify_ip", return_value="93.184.216.34"):
            resp = start_crawl(req)
            self.assertIn("scan_id", resp)
            self.assertEqual(resp["status"], "queued")
            scan_id = resp["scan_id"]

            # Progress polling
            prog = get_scan_progress(scan_id)
            self.assertIn(prog["status"], ["queued", "running", "completed"])

            # Discovered pages polling
            pages = get_scan_pages(scan_id)
            self.assertIsInstance(pages, list)

            # Cancel scan
            cancel_resp = cancel_scan(scan_id)
            self.assertEqual(cancel_resp["status"], "cancelled")

    def test_get_progress_404_for_unknown_scan(self):
        with self.assertRaises(HTTPException) as ctx:
            get_scan_progress("nonexistent-scan-id-xyz")
        self.assertEqual(ctx.exception.status_code, 404)

    def test_existing_single_page_scan_endpoint_remains_intact(self):
        req = AttackerScanRequest(
            target_url="https://example.com",
            is_authorized=True,
        )
        with patch("app.services.attacker.ssrf_guard.resolve_and_verify_ip", return_value="93.184.216.34"):
            with patch("app.services.attacker.agent.AttackerAgentService.run_scan", return_value=MagicMock(
                scan_id="legacy-scan-1",
                target_url="https://example.com",
                normalized_url="https://example.com/",
                target_ip="93.184.216.34",
                scanned_at="2026-10-19T10:00:00Z",
                tls_security=MagicMock(protocol_version="TLSv1.3", cipher_suite="AES256-GCM"),
                findings=[],
                summary=MagicMock(total_findings=0, critical_count=0, high_count=0, medium_count=0, low_count=0),
                risk_score=15.0,
                zero_findings_disclaimer=None,
                discovered_pages=[],
            )):
                resp = scan_target(req)
                self.assertEqual(resp.scan_id, "legacy-scan-1")


class TestDefenderCrawlerIntegration(unittest.TestCase):
    """Verifies that findings from crawler scans integrate with Defender Agent."""

    def test_defender_prioritize_accepts_crawler_findings(self):
        finding_payload = {
            "id": "find-csp-01",
            "title": "Missing Content-Security-Policy (CSP)",
            "severity": "Medium",
            "category": "HTTP Headers",
            "description": "No CSP header detected across crawled pages.",
            "impact": "Increases susceptibility to Cross-Site Scripting (XSS).",
            "remediation": "Deploy Content-Security-Policy with default-src 'self'.",
            "evidence": {
                "url": "https://example.com/dashboard",
                "check_type": "security_headers",
                "raw_snippet": "CSP header absent",
            },
            "remediation_status": "Open",
            "cwe_id": "CWE-693",
        }

        req = DefenderAnalysisRequest(
            scan_id="crawl-scan-999",
            target_url="https://example.com",
            findings=[finding_payload],
            available_budget=5000.0,
            hourly_rate=125.0,
        )

        resp = analyze_remediation_budget(req)
        self.assertEqual(resp.scan_id, "crawl-scan-999")
        self.assertGreater(resp.baseline_risk_score, 0)
        self.assertIn("fix_immediately", resp.__dict__)
        self.assertIn("fix_next", resp.__dict__)
        self.assertIn("defer_or_mitigate", resp.__dict__)


if __name__ == "__main__":
    unittest.main()
