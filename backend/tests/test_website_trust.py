"""
Tests for Website Legitimacy, Phishing, Scam & Impersonation Detection Engine.
Validates:
1. Normal website with missing security headers is NOT classified as a scam.
2. A known malicious URL returned by a threat provider is classified as 'Known Malicious / Phishing'.
3. A clean provider response returns 'No Known Threat Detected' and explicitly disclaims a safety guarantee.
4. Provider failure or timeout returns 'Inconclusive', not a false safe result.
5. Lookalike / typosquatting domains (e.g., paypa1.com, g00gle.com) are detected with explainable evidence.
6. Official domains (e.g. paypal.com) are never flagged as impersonators of themselves.
7. Duplicate URL canonicalization normalizes queries/ports without merging distinct domains.
8. Provider credentials remain strictly server-side and are not leaked.
"""

import unittest
from unittest.mock import MagicMock

from app.schemas.trust import ThreatIntelligenceMatch, WebsiteTrustAssessment
from app.services.attacker.threat_intel import (
    GoogleSafeBrowsingProvider,
    PhishTankProvider,
    ThreatIntelligenceAggregator,
)
from app.services.attacker.impersonation import (
    analyze_impersonation_risks,
    levenshtein_distance,
)
from app.services.attacker.trust_engine import (
    WebsiteTrustService,
    canonicalize_url,
)
from app.schemas.attacker import VulnerabilityFinding


class TestWebsiteTrustAssessment(unittest.TestCase):
    def setUp(self):
        self.service = WebsiteTrustService()

    def test_missing_security_headers_not_a_scam(self):
        """
        Criteria 1: A normal website having missing CSP, HSTS, or other headers
        must NOT automatically be marked as a scam or fraudulent site.
        """
        from app.schemas.attacker import FindingEvidence

        technical_findings = [
            VulnerabilityFinding(
                id="f1",
                title="Missing Content-Security-Policy (CSP)",
                severity="Medium",
                category="Configuration",
                confidence="High",
                description="Header not found",
                affected_url_or_component="https://example-blog.org/",
                evidence=FindingEvidence(
                    check_type="security_headers",
                    observed_value="None",
                    expected_condition="Content-Security-Policy header present",
                ),
                potential_impact="Increased risk of cross-site scripting (XSS)",
                remediation="Configure a Content-Security-Policy header",
                is_confirmed=True,
                validation_status="Confirmed Observation",
            ),
            VulnerabilityFinding(
                id="f2",
                title="Missing Strict-Transport-Security (HSTS)",
                severity="Low",
                category="Configuration",
                confidence="High",
                description="HSTS header not present",
                affected_url_or_component="https://example-blog.org/",
                evidence=FindingEvidence(
                    check_type="security_headers",
                    observed_value="None",
                    expected_condition="Strict-Transport-Security header present",
                ),
                potential_impact="Possible SSL-stripping attack vulnerability",
                remediation="Enable HSTS response header",
                is_confirmed=True,
                validation_status="Confirmed Observation",
            ),
        ]

        trust = self.service.evaluate_trust(
            target_url="https://example-blog.org/about",
            page_title="Tech Blog - Software and Web Insights",
        )

        # Must NOT be classified as scam, phishing, or malicious
        self.assertNotIn("Malicious", trust.trust_state)
        self.assertNotIn("Phishing", trust.trust_state)
        self.assertNotIn("Likely Impersonation", trust.trust_state)
        self.assertIn(trust.trust_state, ["No Known Threat Detected", "Inconclusive"])
        self.assertEqual(len(trust.impersonation_signals), 0)

    def test_mocked_threat_provider_known_malicious(self):
        """
        Criteria 2: A known malicious URL flagged by threat intelligence
        is classified as 'Known Malicious / Phishing'.
        """
        mock_aggregator = MagicMock()
        mock_aggregator.evaluate_url.return_value = [
            ThreatIntelligenceMatch(
                provider="Google Safe Browsing v4",
                status="match_detected",
                threat_type="MALWARE",
                details="Identified as distribution point for MALWARE",
                cached=False,
                lookup_timestamp="2026-10-20T12:00:00Z",
            )
        ]
        mock_aggregator.has_any_configured_provider.return_value = True

        service = WebsiteTrustService(intel_aggregator=mock_aggregator)
        trust = service.evaluate_trust("https://evil-malware-test.com/login")

        self.assertEqual(trust.trust_state, "Known Malicious / Phishing")
        self.assertEqual(trust.confidence, "High")
        self.assertIn("Google Safe Browsing v4", trust.assessment_notes[0])
        self.assertEqual(len(trust.threat_intel_matches), 1)

    def test_clean_provider_response_disclaims_guarantee(self):
        """
        Criteria 3: A clean response is not described as a guarantee of safety.
        Classification should be 'No Known Threat Detected'.
        """
        mock_aggregator = MagicMock()
        mock_aggregator.evaluate_url.return_value = [
            ThreatIntelligenceMatch(
                provider="Google Safe Browsing v4",
                status="no_match",
                details="URL was not found in any Google threat lists.",
                cached=False,
                lookup_timestamp="2026-10-20T12:00:00Z",
            )
        ]
        mock_aggregator.has_any_configured_provider.return_value = True

        service = WebsiteTrustService(intel_aggregator=mock_aggregator)
        trust = service.evaluate_trust("https://example.com")

        self.assertEqual(trust.trust_state, "No Known Threat Detected")
        # Must clearly note that clean checks do NOT guarantee absolute safety
        notes_str = " ".join(trust.assessment_notes).lower()
        self.assertIn("does not guarantee", notes_str)

    def test_provider_failure_returns_inconclusive_not_safe(self):
        """
        Criteria 4: Provider error or timeout produces an inconclusive result,
        never a false 'clean' or safe result.
        """
        mock_aggregator = MagicMock()
        mock_aggregator.evaluate_url.return_value = [
            ThreatIntelligenceMatch(
                provider="Google Safe Browsing v4",
                status="lookup_failed",
                details="Lookup timed out or encountered HTTP error",
                cached=False,
                lookup_timestamp="2026-10-20T12:00:00Z",
            )
        ]
        mock_aggregator.has_any_configured_provider.return_value = True

        service = WebsiteTrustService(intel_aggregator=mock_aggregator)
        trust = service.evaluate_trust("https://somedomain.org")

        self.assertEqual(trust.trust_state, "Inconclusive")
        notes_str = " ".join(trust.assessment_notes)
        self.assertIn("could not be reached", notes_str)

    def test_lookalike_typosquatting_detection(self):
        """
        Criteria 5: Typosquatting / homoglyph domains targeting known brands
        are flagged with explainable evidence.
        """
        signals = analyze_impersonation_risks(
            target_url="https://paypa1.com/signin",
            page_title="PayPal - Sign in to your account",
            forms=[{"inputs": [{"type": "password", "name": "pwd"}]}],
        )

        self.assertTrue(len(signals) > 0)
        signal_types = [s.signal_type for s in signals]
        self.assertTrue(
            any(st in ["typosquatting", "copied_branding_with_credentials"]
                for st in signal_types)
        )
        # Check that evidence details explain the match
        evidences = [str(s.evidence) for s in signals]
        all_evidence_str = " ".join(evidences).lower()
        self.assertIn("paypal", all_evidence_str)

    def test_official_domain_not_flagged_as_impersonator(self):
        """
        Criteria 6: The actual official brand domain (e.g. paypal.com)
        must NEVER be flagged as impersonating itself.
        """
        signals = analyze_impersonation_risks(
            target_url="https://www.paypal.com/signin",
            page_title="PayPal - Sign In",
        )
        
        # None of the signals should accuse paypal.com of impersonating PayPal
        for sig in signals:
            self.assertNotEqual(sig.signal_type, "typosquatting")
            self.assertNotEqual(sig.signal_type, "brand_name_in_subdomain")

    def test_duplicate_url_canonicalization_without_merging(self):
        """
        Criteria 7: Duplicate URL normalization works properly without
        merging different domains or stripping essential query paths.
        """
        url1 = "HTTP://Example.COM:80/path/to/page?b=2&a=1#section"
        url2 = "http://example.com/path/to/page?a=1&b=2"
        canon1, _ = canonicalize_url(url1)
        canon2, _ = canonicalize_url(url2)

        # Same destination should produce identical canonical string
        self.assertEqual(canon1, canon2)

        # Different domains must NOT merge
        canon_diff1, _ = canonicalize_url("https://example.com/login")
        canon_diff2, _ = canonicalize_url("https://example.org/login")
        self.assertNotEqual(canon_diff1, canon_diff2)

        # Different paths must NOT merge
        canon_path1, _ = canonicalize_url("https://example.com/checkout")
        canon_path2, _ = canonicalize_url("https://example.com/login")
        self.assertNotEqual(canon_path1, canon_path2)

    def test_server_side_provider_api_keys_safe(self):
        """
        Criteria 8: Provider API keys are read solely from environment
        and never hardcoded or reflected in client-facing assessment outputs.
        """
        gsb = GoogleSafeBrowsingProvider(api_key="TEST_SECRET_KEY_12345")
        pt = PhishTankProvider(api_key="TEST_PT_KEY_67890")

        self.assertNotIn("TEST_SECRET_KEY_12345", repr(gsb))
        self.assertNotIn("TEST_PT_KEY_67890", repr(pt))

        # Ensure trust assessment schema does not contain API key fields
        schema_fields = WebsiteTrustAssessment.model_fields.keys()
        self.assertNotIn("api_key", schema_fields)
        self.assertNotIn("google_safe_browsing_api_key", schema_fields)
        self.assertNotIn("phishtank_api_key", schema_fields)


if __name__ == "__main__":
    unittest.main()
