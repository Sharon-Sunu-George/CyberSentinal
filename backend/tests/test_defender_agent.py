"""
Unit and Integration Tests for CyberSentinal Defender Agent.
Covers:
- Remediation playbook resolution & code snippet generation
- Engineering labor and material cost calculation
- FAIR-aligned risk scoring & residual risk modeling
- Constrained knapsack budget prioritization (fix immediately, fix next, defer or mitigate)
- Unbudgeted high-risk alerts & shortfall calculation
- Remediation status lifecycle (Open, Planned, In Progress, Fixed, Accepted Risk, Verified)
- SQLite persistence of scans, findings, and remediation plans
- Defender REST API contracts and error boundaries.
"""

import unittest
import uuid
from unittest.mock import patch, MagicMock
from app.api.v1.endpoints.defender import (
    analyze_remediation_budget,
    update_status,
    get_plan,
    get_defender_settings,
    verify_remediation,
)
from app.services.attacker.scanner import SafeHttpResponse
from app.schemas.defender import (
    DefenderAnalysisRequest,
    DefenderAnalysisResponse,
    RemediationStatusUpdateRequest,
)
from app.services.defender.remediation_catalog import (
    get_playbook_for_finding,
    REMEDIATION_CATALOG,
)
from app.services.defender.engine import DefenderPrioritizationEngine
from app.services.storage import (
    save_scan_record,
    get_scan_record,
    update_finding_remediation_status,
    save_remediation_plan,
    get_latest_remediation_plan,
)


class TestDefenderRemediationCatalog(unittest.TestCase):
    """Verifies playbook mappings and technical completeness."""

    def test_playbook_resolution_for_standard_findings(self):
        playbook_hsts = get_playbook_for_finding({"id": "VULN-TLS-MISSING-HSTS", "category": "Transport Security"})
        self.assertIn("Strict-Transport-Security", playbook_hsts["root_cause"])
        self.assertGreater(playbook_hsts["effort_hours"], 0)
        self.assertIn("curl", playbook_hsts["verification_procedure"])
        self.assertIn("Nginx", playbook_hsts["code_snippets"])

        playbook_csp = get_playbook_for_finding({"id": "VULN-SEC-HDR-NO-CSP", "category": "Security Headers"})
        self.assertIn("Content-Security-Policy", playbook_csp["actionable_fix"])
        self.assertGreaterEqual(playbook_csp["effort_hours"], 4.0)

    def test_playbook_resolution_for_cve(self):
        cve_finding = {
            "id": "VULN-CVE-CVE-2021-41773",
            "cve_id": "CVE-2021-41773",
            "category": "Outdated Software",
            "title": "Apache Path Traversal",
        }
        playbook = get_playbook_for_finding(cve_finding)
        self.assertIn("CVE-2021-41773", playbook["root_cause"])
        self.assertGreaterEqual(playbook["effort_hours"], 8.0)


class TestDefenderPrioritizationEngine(unittest.TestCase):
    """Verifies budget-constrained optimization and risk calculations."""

    def setUp(self):
        self.engine = DefenderPrioritizationEngine(hourly_rate=125.0)
        self.sample_findings = [
            {
                "id": "VULN-TLS-NO-HTTPS",
                "title": "Cleartext HTTP Scheme in Use",
                "category": "Transport Security",
                "severity": "High",
                "confidence": "High",
                "affected_url_or_component": "http://example.com",
                "is_confirmed": True,
            },
            {
                "id": "VULN-SEC-HDR-NO-CSP",
                "title": "Missing Content Security Policy (CSP)",
                "category": "Security Headers",
                "severity": "Medium",
                "confidence": "High",
                "affected_url_or_component": "https://example.com",
                "is_confirmed": True,
            },
            {
                "id": "VULN-SEC-HDR-NO-XFO",
                "title": "Missing Clickjacking Protection",
                "category": "Security Headers",
                "severity": "Medium",
                "confidence": "High",
                "affected_url_or_component": "https://example.com",
                "is_confirmed": True,
            },
            {
                "id": "VULN-INFO-SERVER-VERSION",
                "title": "Web Server Version Disclosed",
                "category": "Information Disclosure",
                "severity": "Low",
                "confidence": "High",
                "affected_url_or_component": "https://example.com",
                "is_confirmed": True,
            },
        ]

    def test_ample_budget_allocates_all_findings(self):
        # 4h + 6h + 2h + 1.5h = 13.5 hours * 125 = $1,687.50
        req = DefenderAnalysisRequest(
            target_url="https://example.com",
            findings=self.sample_findings,
            available_budget=5000.0,
            hourly_rate=125.0,
        )
        res = self.engine.analyze(req)

        self.assertGreater(res.total_remediation_cost, 0)
        self.assertEqual(res.proposed_spending, res.total_remediation_cost)
        self.assertEqual(len(res.defer_or_mitigate), 0)
        self.assertEqual(len(res.unbudgeted_high_risk_findings), 0)
        self.assertEqual(res.budget_shortfall, 0.0)
        self.assertGreater(res.baseline_risk_score, res.projected_residual_risk)
        self.assertGreater(res.total_risk_reduction_percent, 50.0)

    def test_constrained_budget_defers_and_alerts_unbudgeted_high_risk(self):
        # Budget only $300 (insufficient to fix High severity $500 TLS issue)
        req = DefenderAnalysisRequest(
            target_url="https://example.com",
            findings=self.sample_findings,
            available_budget=300.0,
            hourly_rate=125.0,
        )
        res = self.engine.analyze(req)

        # High severity TLS ($500) exceeds $300 budget -> must be deferred
        self.assertGreater(len(res.defer_or_mitigate), 0)
        high_risk_deferred = [r for r in res.defer_or_mitigate if r.severity == "High"]
        self.assertGreater(len(high_risk_deferred), 0)

        # Unbudgeted high-risk list must explicitly contain this item
        self.assertGreater(len(res.unbudgeted_high_risk_findings), 0)
        self.assertGreater(res.budget_shortfall, 0.0)
        self.assertIsNotNone(high_risk_deferred[0].temporary_mitigation)
        self.assertIn("exceeds remaining budget", high_risk_deferred[0].deferral_reason.lower())

    def test_zero_findings_produces_clean_plan(self):
        req = DefenderAnalysisRequest(
            target_url="https://example.com",
            findings=[],
            available_budget=2000.0,
        )
        res = self.engine.analyze(req)
        self.assertEqual(res.total_remediation_cost, 0.0)
        self.assertEqual(len(res.fix_immediately), 0)
        self.assertEqual(len(res.unbudgeted_high_risk_findings), 0)

    def test_inconclusive_findings_treated_as_needs_verification(self):
        """Inconclusive findings must never be treated as confirmed vulnerabilities."""
        inconclusive_finding = {
            "id": "VULN-SCAN-GATEWAY-PROXY-ERROR",
            "title": "Scan Inconclusive: Upstream Cloudflare Gateway Error (HTTP 502)",
            "category": "Transport Security",
            "severity": "Low",
            "confidence": "High",
            "affected_url_or_component": "https://gateway.example.com",
            "validation_status": "Inconclusive",
            "is_confirmed": True,
            "evidence": {"check_result": "Inconclusive", "status_code": 502},
        }
        req = DefenderAnalysisRequest(
            target_url="https://gateway.example.com",
            findings=[inconclusive_finding],
            available_budget=5000.0,
        )
        res = self.engine.analyze(req)
        self.assertEqual(len(res.fix_immediately), 0)
        self.assertEqual(len(res.defer_or_mitigate), 1)
        rec = res.defer_or_mitigate[0]
        self.assertEqual(rec.status, "Needs Verification")
        self.assertIn("verify target reachability", rec.deferral_reason.lower())
        self.assertEqual(rec.priority_score, 5.0)

    def test_duplicate_findings_prevented(self):
        """Duplicate findings passed from attacker agent must be deduplicated."""
        dup_finding = {
            "id": "VULN-SEC-HDR-NO-CSP",
            "title": "Missing Content Security Policy (CSP)",
            "category": "Security Headers",
            "severity": "Medium",
            "confidence": "High",
            "affected_url_or_component": "https://example.com",
        }
        req = DefenderAnalysisRequest(
            target_url="https://example.com",
            findings=[dup_finding, dup_finding, dup_finding],
            available_budget=5000.0,
        )
        res = self.engine.analyze(req)
        all_recs = res.fix_immediately + res.fix_next + res.defer_or_mitigate
        self.assertEqual(len(all_recs), 1)

    def test_currency_and_hourly_rate_configuration(self):
        """Configurable currencies and rates are preserved in remediation recommendations."""
        finding = {
            "id": "VULN-TLS-MISSING-HSTS",
            "title": "Missing HSTS",
            "category": "Transport Security",
            "severity": "Medium",
            "confidence": "High",
            "affected_url_or_component": "https://example.com",
        }
        req = DefenderAnalysisRequest(
            target_url="https://example.com",
            findings=[finding],
            available_budget=2000.0,
            currency="EUR",
            hourly_rate=150.0,
        )
        res = self.engine.analyze(req)
        self.assertEqual(res.currency, "EUR")
        self.assertEqual(res.hourly_rate, 150.0)
        rec = res.fix_immediately[0] if res.fix_immediately else res.fix_next[0]
        self.assertEqual(rec.currency, "EUR")
        self.assertEqual(rec.hourly_rate, 150.0)
        # 2 hours * 150 = 300 EUR
        self.assertEqual(rec.labor_cost, 300.0)
        self.assertEqual(rec.total_cost, 300.0)

    def test_priority_score_and_explanation(self):
        """Multi-factor priority score calculation is explicit and transparent."""
        finding = {
            "id": "VULN-TLS-NO-HTTPS",
            "title": "Cleartext HTTP",
            "category": "Transport Security",
            "severity": "High",
            "confidence": "High",
            "affected_url_or_component": "http://example.com",
            "cwe_id": "CWE-319",
            "is_confirmed": True,
        }
        req = DefenderAnalysisRequest(
            target_url="http://example.com",
            findings=[finding],
            available_budget=5000.0,
        )
        res = self.engine.analyze(req)
        rec = res.fix_immediately[0]
        self.assertGreaterEqual(rec.priority_score, 60.0)
        self.assertIn("Priority score", rec.priority_explanation)
        self.assertIn("High severity", rec.priority_explanation)
        self.assertIn("CWE: CWE-319", rec.priority_explanation)
        self.assertIn("Security risk is calculated independently of remediation cost", rec.priority_explanation)


class TestPersistenceAndAPI(unittest.TestCase):
    """Verifies SQLite persistence, status lifecycle, and Defender REST API integration."""

    def test_storage_and_status_lifecycle(self):
        import uuid
        scan_id = f"test-scan-defender-{uuid.uuid4().hex[:8]}"
        scan_data = {
            "scan_id": scan_id,
            "target_url": "https://test.example.com",
            "normalized_url": "https://test.example.com/",
            "scanned_at": "2026-10-19T12:00:00Z",
            "status": "completed",
            "target_ip": "1.2.3.4",
            "summary": {"total_findings": 1},
            "findings": [
                {
                    "id": "VULN-TLS-MISSING-HSTS",
                    "title": "Missing HSTS",
                    "category": "Transport Security",
                    "severity": "Medium",
                    "confidence": "High",
                    "affected_url_or_component": "https://test.example.com",
                    "potential_impact": "SSL stripping vulnerability",
                    "remediation": "Add Strict-Transport-Security header",
                    "is_confirmed": True,
                    "validation_status": "Security Weakness",
                }
            ],
        }

        save_scan_record(scan_data)
        record = get_scan_record(scan_id)
        self.assertIsNotNone(record)
        self.assertEqual(record["findings"][0]["remediation_status"], "Open")

        # Update status to In Progress
        success = update_finding_remediation_status(
            scan_id=scan_id,
            finding_id="VULN-TLS-MISSING-HSTS",
            status="In Progress",
            notes="Assigned to DevOps sprint",
        )
        self.assertTrue(success)

        updated_record = get_scan_record(scan_id)
        self.assertEqual(updated_record["findings"][0]["remediation_status"], "In Progress")
        self.assertEqual(updated_record["findings"][0]["remediation_notes"], "Assigned to DevOps sprint")

        # Update to Fixed Pending Verification
        update_finding_remediation_status(
            scan_id=scan_id,
            finding_id="VULN-TLS-MISSING-HSTS",
            status="Fixed Pending Verification",
            notes="Web server reload complete",
        )
        pending_record = get_scan_record(scan_id)
        self.assertEqual(pending_record["findings"][0]["remediation_status"], "Fixed Pending Verification")

    def test_verification_endpoint_workflow(self):
        from unittest.mock import patch, MagicMock
        from app.api.v1.endpoints.defender import verify_remediation
        from app.services.attacker.scanner import SafeHttpResponse
        import uuid

        scan_id = f"test-scan-verify-{uuid.uuid4().hex[:8]}"
        scan_data = {
            "scan_id": scan_id,
            "target_url": "https://test.example.com",
            "normalized_url": "https://test.example.com/",
            "scanned_at": "2026-10-19T12:00:00Z",
            "status": "completed",
            "findings": [
                {
                    "id": "VULN-TLS-MISSING-HSTS",
                    "title": "Missing HSTS",
                    "category": "Transport Security",
                    "severity": "Medium",
                    "confidence": "High",
                    "affected_url_or_component": "https://test.example.com",
                    "potential_impact": "SSL stripping",
                    "remediation": "Add Strict-Transport-Security header",
                    "is_confirmed": True,
                    "validation_status": "Security Weakness",
                    "remediation_status": "Fixed Pending Verification",
                }
            ],
        }
        save_scan_record(scan_data)

        # 1. Successful verification probe -> Verified Fixed
        with patch("app.api.v1.endpoints.defender.SafeHttpClient.request") as mock_req:
            mock_req.return_value = SafeHttpResponse(
                url="https://test.example.com",
                status_code=200,
                headers={"Strict-Transport-Security": "max-age=31536000; includeSubDomains"},
                body_text="<html>OK</html>",
                remote_ip="93.184.216.34",
                was_https=True,
            )
            resp = verify_remediation(scan_id=scan_id, finding_id="VULN-TLS-MISSING-HSTS")
            self.assertTrue(resp.is_verified)
            self.assertTrue(resp.verification_passed)
            self.assertEqual(resp.new_status, "Verified Fixed")
            self.assertIn("Strict-Transport-Security header: max-age=31536000", resp.evidence_summary)

        # 2. Failed verification probe -> Reopened
        with patch("app.api.v1.endpoints.defender.SafeHttpClient.request") as mock_req:
            mock_req.return_value = SafeHttpResponse(
                url="https://test.example.com",
                status_code=200,
                headers={"Server": "nginx"},  # missing HSTS
                body_text="<html>OK</html>",
                remote_ip="93.184.216.34",
                was_https=True,
            )
            resp = verify_remediation(scan_id=scan_id, finding_id="VULN-TLS-MISSING-HSTS")
            self.assertTrue(resp.is_verified)
            self.assertFalse(resp.verification_passed)
            self.assertEqual(resp.new_status, "Reopened")
            self.assertIn("ABSENT", resp.evidence_summary)

        # 3. Gateway proxy error -> Inconclusive, preserves uncertainty
        with patch("app.api.v1.endpoints.defender.SafeHttpClient.request") as mock_req:
            mock_req.return_value = SafeHttpResponse(
                url="https://test.example.com",
                status_code=502,
                headers={"Server": "cloudflare", "cf-ray": "12345"},
                body_text="502 Bad Gateway",
                remote_ip="93.184.216.34",
                was_https=True,
            )
            resp = verify_remediation(scan_id=scan_id, finding_id="VULN-TLS-MISSING-HSTS")
            self.assertFalse(resp.is_verified)
            self.assertTrue(resp.is_inconclusive)
            # Status must be preserved without false transition
            self.assertEqual(resp.new_status, "Reopened")  # previous status was Reopened from step 2

    def test_api_defender_endpoints(self):
        req = DefenderAnalysisRequest(
            target_url="https://api-test.example.com",
            findings=[
                {
                    "id": "VULN-SEC-HDR-NO-XFO",
                    "title": "Missing Clickjacking Protection",
                    "category": "Security Headers",
                    "severity": "Medium",
                    "confidence": "High",
                    "affected_url_or_component": "https://api-test.example.com",
                    "is_confirmed": True,
                }
            ],
            available_budget=1000.0,
            hourly_rate=125.0,
        )

        data = analyze_remediation_budget(req)
        self.assertEqual(data.target_url, "https://api-test.example.com")
        self.assertGreater(data.proposed_spending, 0)
        self.assertTrue(len(data.fix_immediately) > 0 or len(data.fix_next) > 0)

        # Test settings endpoint
        settings_data = get_defender_settings()
        self.assertIn("default_hourly_rate", settings_data)
        self.assertIn("currencies", settings_data)
        self.assertIn("lifecycle_stages", settings_data)


class TestEndToEndWorkflow(unittest.TestCase):
    """
    End-to-End integration and reliability tests verifying:
    1. Attacker Agent scanning an authorized target with mock wire evidence
    2. Validated findings persistence and deduplication
    3. Inconclusive scans handling
    4. Defender Agent remediation budget analysis and prioritization
    5. Remediation lifecycle status transition and history logging
    6. Non-destructive verification workflow (pass -> Verified Fixed, persist issue -> Reopened, proxy 502 -> Inconclusive)
    """

    def setUp(self):
        import uuid
        self.scan_id = f"e2e-scan-{uuid.uuid4().hex[:8]}"
        self.target_url = "https://e2e-target.example.com"

    def test_complete_attacker_defender_remediation_lifecycle(self):
        from app.schemas.attacker import AttackerScanRequest
        from app.services.attacker.agent import AttackerAgentService
        from app.services.attacker.scanner import SafeHttpResponse
        from app.api.v1.endpoints.defender import verify_remediation, get_status_history

        # Step 1: Execute authorized scan with mocked HTTP probe missing CSP and HSTS
        with patch("app.services.attacker.scanner.SafeHttpClient.request") as mock_req, \
             patch("app.services.attacker.ssrf_guard.resolve_and_verify_ip") as mock_dns:
            mock_dns.return_value = "93.184.216.34"
            mock_req.return_value = SafeHttpResponse(
                url=self.target_url,
                status_code=200,
                headers={
                    "Server": "Apache/2.4.41 (Ubuntu)",
                    "X-Content-Type-Options": "nosniff",
                },
                body_text="<html><body>Secure Portal</body></html>",
                remote_ip="93.184.216.34",
                was_https=True,
            )

            service = AttackerAgentService()
            scan_req = AttackerScanRequest(
                target_url=self.target_url,
                is_authorized=True,
            )
            scan_resp = service.run_scan(scan_req, scan_id=self.scan_id)

            # Step 2: Validate Attacker findings
            self.assertEqual(scan_resp.scan_id, self.scan_id)
            self.assertEqual(scan_resp.status, "completed")
            self.assertFalse(scan_resp.is_inconclusive)
            self.assertGreater(scan_resp.summary.total_findings, 0)

            # Check that findings include missing HSTS and missing CSP
            finding_ids = [f.id for f in scan_resp.findings]
            self.assertIn("VULN-TLS-MISSING-HSTS", finding_ids)
            self.assertIn("VULN-SEC-HDR-NO-CSP", finding_ids)

        # Step 3: Verify findings persisted to SQLite storage
        stored_record = get_scan_record(self.scan_id)
        self.assertIsNotNone(stored_record)
        self.assertEqual(len(stored_record["findings"]), len(scan_resp.findings))

        # Step 4: Defender Agent consumes findings and generates prioritized plan
        def_req = DefenderAnalysisRequest(
            scan_id=self.scan_id,
            target_url=self.target_url,
            findings=[f.model_dump() for f in scan_resp.findings],
            available_budget=3000.0,
            hourly_rate=150.0,
            currency="USD",
        )
        plan = analyze_remediation_budget(def_req)
        self.assertEqual(plan.scan_id, self.scan_id)
        self.assertGreater(plan.proposed_spending, 0)
        self.assertLessEqual(plan.proposed_spending, 3000.0)

        # Step 5: User updates finding to 'Fixed Pending Verification'
        update_success = update_finding_remediation_status(
            scan_id=self.scan_id,
            finding_id="VULN-TLS-MISSING-HSTS",
            status="Fixed Pending Verification",
            notes="Added Strict-Transport-Security header to reverse proxy config",
        )
        self.assertTrue(update_success)

        # Step 6: Follow-up verification scan probe
        # Scenario 6A: Probe sees HSTS on the wire -> Transitions to 'Verified Fixed'
        with patch("app.api.v1.endpoints.defender.SafeHttpClient.request") as mock_verify_req, \
             patch("app.api.v1.endpoints.defender.normalize_target_url") as mock_norm:
            mock_norm.return_value = (self.target_url, "e2e-target.example.com", 443, "/")
            mock_verify_req.return_value = SafeHttpResponse(
                url=self.target_url,
                status_code=200,
                headers={
                    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
                    "X-Content-Type-Options": "nosniff",
                },
                body_text="<html><body>Secure Portal</body></html>",
                remote_ip="93.184.216.34",
                was_https=True,
            )

            v_resp = verify_remediation(scan_id=self.scan_id, finding_id="VULN-TLS-MISSING-HSTS")
            self.assertTrue(v_resp.is_verified)
            self.assertTrue(v_resp.verification_passed)
            self.assertEqual(v_resp.new_status, "Verified Fixed")

            # Check database persistence
            refreshed_scan = get_scan_record(self.scan_id)
            hsts_f = next(f for f in refreshed_scan["findings"] if f["id"] == "VULN-TLS-MISSING-HSTS")
            self.assertEqual(hsts_f["remediation_status"], "Verified Fixed")
            self.assertIsNotNone(hsts_f["verification_evidence"])

            # Step 7: Inspect audit history log (returned in descending order by id)
            history_data = get_status_history(self.scan_id, finding_id="VULN-TLS-MISSING-HSTS")
            self.assertGreaterEqual(history_data["total_events"], 2)
            events = history_data["history"]
            self.assertEqual(events[0]["new_status"], "Verified Fixed")


class TestDefenderVerificationHardening(unittest.TestCase):
    """
    TASK 5: Targeted test cases for Fix Verification Hardening:
    1. Missing header remains missing -> Reopened / Still Present.
    2. Missing header is added -> Verified Fixed.
    3. Target timeout -> Inconclusive, preserves status.
    4. Server error or unreachable target -> Not Verified Fixed.
    5. Redirect to prohibited destination / SSRF -> Blocked.
    6. Previously fixed issue reappears -> Reopened.
    7. Verification history persisted and prior evidence preserved.
    8. Invalid finding IDs and unauthorized targets rejected.
    9. Cookie security flags: Verified Fixed, Reopened, and Inconclusive when no Set-Cookie.
    10. CORS and security.txt validations.
    """

    def setUp(self):
        self.scan_id = f"test-harden-{uuid.uuid4().hex[:8]}"
        self.target_url = "https://harden-target.example.com"
        save_scan_record({
            "scan_id": self.scan_id,
            "target_url": self.target_url,
            "normalized_url": self.target_url,
            "status": "completed",
            "findings": [
                {
                    "id": "VULN-SEC-HDR-NO-CSP",
                    "title": "Missing CSP",
                    "category": "Security Headers",
                    "severity": "Medium",
                    "confidence": "High",
                    "affected_url_or_component": self.target_url,
                    "potential_impact": "XSS attacks",
                    "remediation": "Add CSP header",
                    "remediation_status": "Fixed Pending Verification",
                    "evidence": {"check_result": "Failed"},
                },
                {
                    "id": "VULN-COOKIE-NO-SECURE",
                    "title": "Cookie Missing Secure Flag",
                    "category": "Session Management",
                    "severity": "Medium",
                    "confidence": "High",
                    "affected_url_or_component": self.target_url,
                    "potential_impact": "Cookie interception",
                    "remediation": "Set Secure flag",
                    "remediation_status": "Fixed Pending Verification",
                    "evidence": {"observed_data": {"cookie": "session_id"}},
                },
                {
                    "id": "VULN-CORS-WILDCARD-CREDENTIALS",
                    "title": "CORS Wildcard with Credentials",
                    "category": "CORS",
                    "severity": "High",
                    "confidence": "High",
                    "affected_url_or_component": self.target_url,
                    "potential_impact": "Cross-origin data theft",
                    "remediation": "Restrict CORS origin",
                    "remediation_status": "Fixed Pending Verification",
                    "evidence": {},
                },
                {
                    "id": "VULN-BEST-PRACTICE-NO-SECURITY-TXT",
                    "title": "Missing security.txt",
                    "category": "Information Disclosure",
                    "severity": "Low",
                    "confidence": "High",
                    "affected_url_or_component": self.target_url,
                    "potential_impact": "Delayed vulnerability reporting",
                    "remediation": "Publish security.txt",
                    "remediation_status": "Fixed Pending Verification",
                    "evidence": {},
                },
                {
                    "id": "VULN-INFO-SERVER-VERSION",
                    "title": "Server Banner Version Disclosure",
                    "category": "Information Disclosure",
                    "severity": "Low",
                    "confidence": "High",
                    "affected_url_or_component": self.target_url,
                    "potential_impact": "Targeted exploit reconnaissance",
                    "remediation": "Suppress Server version",
                    "remediation_status": "Fixed Pending Verification",
                    "evidence": {},
                },
                {
                    "id": "VULN-EXPOSED-ENV-FILE",
                    "title": "Exposed .env Configuration File",
                    "category": "Information Disclosure",
                    "severity": "Critical",
                    "confidence": "High",
                    "affected_url_or_component": f"{self.target_url}/.env",
                    "potential_impact": "Credential compromise",
                    "remediation": "Remove .env from web root",
                    "remediation_status": "Fixed Pending Verification",
                    "evidence": {},
                },
            ],
            "is_inconclusive": False,
        })

    def test_1_missing_header_remains_missing_results_in_reopened(self):
        """1. When a missing header is still absent, status transitions to 'Reopened' (Still Present)."""
        with patch("app.api.v1.endpoints.defender.SafeHttpClient.request") as mock_req, \
             patch("app.api.v1.endpoints.defender.normalize_target_url") as mock_norm:
            mock_norm.return_value = (self.target_url, "harden-target.example.com", 443, "/")
            mock_req.return_value = SafeHttpResponse(
                url=self.target_url,
                status_code=200,
                headers={"Server": "nginx"},  # No CSP header
                body_text="<html><body>Still no CSP</body></html>",
                remote_ip="93.184.216.34",
                was_https=True,
            )
            resp = verify_remediation(self.scan_id, "VULN-SEC-HDR-NO-CSP")
            self.assertTrue(resp.is_verified)
            self.assertFalse(resp.verification_passed)
            self.assertEqual(resp.new_status, "Reopened")

    def test_2_missing_header_added_results_in_verified_fixed(self):
        """2. When missing header is properly added, status transitions to 'Verified Fixed'."""
        with patch("app.api.v1.endpoints.defender.SafeHttpClient.request") as mock_req, \
             patch("app.api.v1.endpoints.defender.normalize_target_url") as mock_norm:
            mock_norm.return_value = (self.target_url, "harden-target.example.com", 443, "/")
            mock_req.return_value = SafeHttpResponse(
                url=self.target_url,
                status_code=200,
                headers={
                    "Content-Security-Policy": "default-src 'self'",
                    "Server": "nginx",
                },
                body_text="<html><body>Protected</body></html>",
                remote_ip="93.184.216.34",
                was_https=True,
            )
            resp = verify_remediation(self.scan_id, "VULN-SEC-HDR-NO-CSP")
            self.assertTrue(resp.is_verified)
            self.assertTrue(resp.verification_passed)
            self.assertEqual(resp.new_status, "Verified Fixed")

    def test_3_target_timeout_results_in_inconclusive(self):
        """3. Network timeout or socket error yields Inconclusive and preserves original status."""
        with patch("app.api.v1.endpoints.defender.SafeHttpClient.request") as mock_req, \
             patch("app.api.v1.endpoints.defender.normalize_target_url") as mock_norm:
            mock_norm.return_value = (self.target_url, "harden-target.example.com", 443, "/")
            mock_req.side_effect = TimeoutError("Connection to target timed out after 5.0 seconds")

            resp = verify_remediation(self.scan_id, "VULN-SEC-HDR-NO-CSP")
            self.assertFalse(resp.is_verified)
            self.assertFalse(resp.verification_passed)
            self.assertTrue(resp.is_inconclusive)
            self.assertEqual(resp.new_status, "Fixed Pending Verification")
            self.assertIn("timed out", resp.evidence_summary)

    def test_4_gateway_server_error_results_in_inconclusive(self):
        """4. Intermediate gateway error (HTTP 502/503/504) is never treated as a successful fix."""
        with patch("app.api.v1.endpoints.defender.SafeHttpClient.request") as mock_req, \
             patch("app.api.v1.endpoints.defender.normalize_target_url") as mock_norm:
            mock_norm.return_value = (self.target_url, "harden-target.example.com", 443, "/")
            mock_req.return_value = SafeHttpResponse(
                url=self.target_url,
                status_code=502,
                headers={"Server": "cloudflare"},
                body_text="<html><body>502 Bad Gateway</body></html>",
                remote_ip="104.16.132.229",
                was_https=True,
                is_proxy_or_tunnel_error=True,
                proxy_or_tunnel_type="Cloudflare Gateway",
            )
            resp = verify_remediation(self.scan_id, "VULN-SEC-HDR-NO-CSP")
            self.assertFalse(resp.is_verified)
            self.assertTrue(resp.is_inconclusive)
            self.assertEqual(resp.new_status, "Fixed Pending Verification")
            self.assertEqual(resp.observed_status, 502)

    def test_5_ssrf_prohibited_destination_blocked(self):
        """5. Probe to prohibited/private IP or SSRF attempt fails safely and is Inconclusive."""
        from app.services.attacker.ssrf_guard import SSRFProtectionError
        with patch("app.api.v1.endpoints.defender.SafeHttpClient.request") as mock_req, \
             patch("app.api.v1.endpoints.defender.normalize_target_url") as mock_norm:
            mock_norm.return_value = ("http://169.254.169.254/latest/meta-data", "169.254.169.254", 80, "/latest/meta-data")
            mock_req.side_effect = SSRFProtectionError("Target IP 169.254.169.254 belongs to prohibited cloud metadata range")

            resp = verify_remediation(self.scan_id, "VULN-SEC-HDR-NO-CSP")
            self.assertFalse(resp.is_verified)
            self.assertTrue(resp.is_inconclusive)
            self.assertEqual(resp.new_status, "Fixed Pending Verification")
            self.assertIn("prohibited", resp.evidence_summary)

    def test_6_cookie_flags_honesty_without_set_cookie(self):
        """6. Cookie flag verification is Inconclusive if server issues no Set-Cookie header."""
        with patch("app.api.v1.endpoints.defender.SafeHttpClient.request") as mock_req, \
             patch("app.api.v1.endpoints.defender.normalize_target_url") as mock_norm:
            mock_norm.return_value = (self.target_url, "harden-target.example.com", 443, "/")
            mock_req.return_value = SafeHttpResponse(
                url=self.target_url,
                status_code=200,
                headers={"Server": "nginx"},  # No Set-Cookie
                body_text="<html><body>Static page</body></html>",
                remote_ip="93.184.216.34",
                was_https=True,
            )
            resp = verify_remediation(self.scan_id, "VULN-COOKIE-NO-SECURE")
            self.assertTrue(resp.is_inconclusive)
            self.assertEqual(resp.new_status, "Fixed Pending Verification")
            self.assertIn("No Set-Cookie header issued", resp.evidence_summary)

    def test_7_cookie_flags_verified_fixed_when_secure_present(self):
        """7. Cookie flag verification succeeds when target cookie includes Secure flag."""
        with patch("app.api.v1.endpoints.defender.SafeHttpClient.request") as mock_req, \
             patch("app.api.v1.endpoints.defender.normalize_target_url") as mock_norm:
            mock_norm.return_value = (self.target_url, "harden-target.example.com", 443, "/")
            mock_req.return_value = SafeHttpResponse(
                url=self.target_url,
                status_code=200,
                headers={"Set-Cookie": "session_id=abc123xyz; Path=/; Secure; HttpOnly; SameSite=Lax"},
                body_text="<html><body>Logged in</body></html>",
                remote_ip="93.184.216.34",
                was_https=True,
            )
            resp = verify_remediation(self.scan_id, "VULN-COOKIE-NO-SECURE")
            self.assertTrue(resp.is_verified)
            self.assertTrue(resp.verification_passed)
            self.assertEqual(resp.new_status, "Verified Fixed")

    def test_8_cors_wildcard_credentials_fixed_vs_reopened(self):
        """8. CORS wildcard with credentials verified fixed when wildcard or credentials removed."""
        with patch("app.api.v1.endpoints.defender.SafeHttpClient.request") as mock_req, \
             patch("app.api.v1.endpoints.defender.normalize_target_url") as mock_norm:
            mock_norm.return_value = (self.target_url, "harden-target.example.com", 443, "/")

            # Subcase A: Still present (Origin: *, Credentials: true)
            mock_req.return_value = SafeHttpResponse(
                url=self.target_url,
                status_code=200,
                headers={
                    "Access-Control-Allow-Origin": "*",
                    "Access-Control-Allow-Credentials": "true",
                },
                body_text="",
                remote_ip="93.184.216.34",
                was_https=True,
            )
            resp_fail = verify_remediation(self.scan_id, "VULN-CORS-WILDCARD-CREDENTIALS")
            self.assertTrue(resp_fail.is_verified)
            self.assertFalse(resp_fail.verification_passed)
            self.assertEqual(resp_fail.new_status, "Reopened")

            # Subcase B: Fixed (Origin restricted to specific origin)
            mock_req.return_value = SafeHttpResponse(
                url=self.target_url,
                status_code=200,
                headers={
                    "Access-Control-Allow-Origin": "https://app.example.com",
                    "Access-Control-Allow-Credentials": "true",
                },
                body_text="",
                remote_ip="93.184.216.34",
                was_https=True,
            )
            resp_pass = verify_remediation(self.scan_id, "VULN-CORS-WILDCARD-CREDENTIALS")
            self.assertTrue(resp_pass.is_verified)
            self.assertTrue(resp_pass.verification_passed)
            self.assertEqual(resp_pass.new_status, "Verified Fixed")

    def test_9_security_txt_honesty(self):
        """9. security.txt verification checks HTTP 200, valid Contact directive, and non-HTML."""
        with patch("app.api.v1.endpoints.defender.SafeHttpClient.request") as mock_req, \
             patch("app.api.v1.endpoints.defender.normalize_target_url") as mock_norm:
            mock_norm.return_value = (self.target_url, "harden-target.example.com", 443, "/")

            # Subcase A: 200 with HTML 404 custom error page -> Not verified fixed
            mock_req.return_value = SafeHttpResponse(
                url=f"{self.target_url}/.well-known/security.txt",
                status_code=200,
                headers={"Content-Type": "text/html"},
                body_text="<html><head><title>Custom 404</title></head><body>Page Not Found</body></html>",
                remote_ip="93.184.216.34",
                was_https=True,
            )
            resp_html = verify_remediation(self.scan_id, "VULN-BEST-PRACTICE-NO-SECURITY-TXT")
            self.assertTrue(resp_html.is_verified)
            self.assertFalse(resp_html.verification_passed)
            self.assertEqual(resp_html.new_status, "Reopened")

            # Subcase B: Proper RFC 9116 security.txt
            mock_req.return_value = SafeHttpResponse(
                url=f"{self.target_url}/.well-known/security.txt",
                status_code=200,
                headers={"Content-Type": "text/plain"},
                body_text="Contact: mailto:security@example.com\nExpires: 2027-12-31T23:59:59.000Z\n",
                remote_ip="93.184.216.34",
                was_https=True,
            )
            resp_valid = verify_remediation(self.scan_id, "VULN-BEST-PRACTICE-NO-SECURITY-TXT")
            self.assertTrue(resp_valid.is_verified)
            self.assertEqual(resp_valid.new_status, "Verified Fixed")

    def test_10_invalid_scan_or_finding_id_rejected(self):
        """10. Non-existent scan or finding IDs raise HTTP 404."""
        from fastapi import HTTPException
        with self.assertRaises(HTTPException) as ctx:
            verify_remediation("non-existent-scan-id", "VULN-SEC-HDR-NO-CSP")
        self.assertEqual(ctx.exception.status_code, 404)

        with self.assertRaises(HTTPException) as ctx:
            verify_remediation(self.scan_id, "NON-EXISTENT-FINDING")
        self.assertEqual(ctx.exception.status_code, 404)

    def test_11_exposed_env_file_verification(self):
        """11. Verify that .env exposure fix passes when 404/403 returned, and fails if 200 plaintext."""
        with patch("app.api.v1.endpoints.defender.SafeHttpClient.request") as mock_req, \
             patch("app.api.v1.endpoints.defender.normalize_target_url") as mock_norm:
            mock_norm.return_value = (f"{self.target_url}/.env", "harden-target.example.com", 443, "/.env")

            # Case A: Still returns HTTP 200 with plaintext .env content -> Reopened / Not Fixed
            mock_req.return_value = SafeHttpResponse(
                url=f"{self.target_url}/.env",
                status_code=200,
                headers={"Content-Type": "text/plain"},
                body_text="DB_PASSWORD=secret123\nPORT=3000\n",
                remote_ip="93.184.216.34",
                was_https=True,
            )
            resp_still_exposed = verify_remediation(self.scan_id, "VULN-EXPOSED-ENV-FILE")
            self.assertTrue(resp_still_exposed.is_verified)
            self.assertFalse(resp_still_exposed.verification_passed)
            self.assertEqual(resp_still_exposed.new_status, "Reopened")

            # Case B: Returns HTTP 404 -> Verified Fixed
            mock_req.return_value = SafeHttpResponse(
                url=f"{self.target_url}/.env",
                status_code=404,
                headers={},
                body_text="Not Found",
                remote_ip="93.184.216.34",
                was_https=True,
            )
            resp_fixed_404 = verify_remediation(self.scan_id, "VULN-EXPOSED-ENV-FILE")
            self.assertTrue(resp_fixed_404.is_verified)
            self.assertTrue(resp_fixed_404.verification_passed)
            self.assertEqual(resp_fixed_404.new_status, "Verified Fixed")

            # Case C: Returns HTTP 403 Forbidden -> Verified Fixed
            mock_req.return_value = SafeHttpResponse(
                url=f"{self.target_url}/.env",
                status_code=403,
                headers={},
                body_text="Access Denied",
                remote_ip="93.184.216.34",
                was_https=True,
            )
            resp_fixed_403 = verify_remediation(self.scan_id, "VULN-EXPOSED-ENV-FILE")
            self.assertTrue(resp_fixed_403.is_verified)
            self.assertTrue(resp_fixed_403.verification_passed)
            self.assertEqual(resp_fixed_403.new_status, "Verified Fixed")


if __name__ == "__main__":
    unittest.main()
