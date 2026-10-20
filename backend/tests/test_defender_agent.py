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
from app.api.v1.endpoints.defender import (
    analyze_remediation_budget,
    update_status,
    get_plan,
    get_defender_settings,
)
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


class TestPersistenceAndAPI(unittest.TestCase):
    """Verifies SQLite persistence and Defender REST API integration."""

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

        # Update to Fixed
        update_finding_remediation_status(
            scan_id=scan_id,
            finding_id="VULN-TLS-MISSING-HSTS",
            status="Fixed",
        )
        fixed_record = get_scan_record(scan_id)
        self.assertEqual(fixed_record["findings"][0]["remediation_status"], "Fixed")

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
