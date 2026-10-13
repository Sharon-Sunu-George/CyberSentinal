"""
Attacker AI Agent Service for CyberQuant.
Orchestrates evidence-based security scanning and deterministic adversarial reasoning.
Strictly separates verified empirical findings from modeled/inferred attack scenarios,
and formats structured outputs ready for the future Defender Agent.
"""

import datetime
import uuid
from typing import List, Dict, Any, Optional

from app.schemas.attacker import (
    AttackerScanRequest,
    AttackerScanResponse,
    AttackerScanSummary,
    InferredAttackScenario,
    VulnerabilityFinding,
)
from app.services.attacker.scanner import EvidenceBasedScanner, SafeHttpClient
from app.services.attacker.ssrf_guard import (
    normalize_target_url,
    TargetAuthorizationError,
    SSRFProtectionError,
)


class AttackerAgentService:
    """
    Deterministic Attacker Agent.
    Analyzes actual scanner results and constructs validated threat models
    without hallucinating vulnerabilities or unverified CVEs.
    """

    def __init__(self, scanner: Optional[EvidenceBasedScanner] = None):
        self.scanner = scanner or EvidenceBasedScanner(SafeHttpClient())

    def run_scan(self, request: AttackerScanRequest) -> AttackerScanResponse:
        # Enforce authorization
        if not request.is_authorized:
            raise TargetAuthorizationError(
                "Unauthorized scan attempt: user must explicitly confirm authorization before initiating assessment."
            )

        # Normalize and validate target URL
        normalized_url, hostname, port, path = normalize_target_url(request.target_url)

        # Execute bounded, evidence-based scan
        findings, scan_meta = self.scanner.scan(normalized_url)

        # Compute summary metrics
        summary = self._compute_summary(findings)

        # Generate deterministic inferred attack paths derived strictly from observed findings
        inferred_scenarios = self._derive_inferred_attack_scenarios(findings, normalized_url)

        # Structure defender handover packet for the future Defender Agent
        defender_handover = self._build_defender_handover(findings, normalized_url, summary)

        scan_id = f"scan-{uuid.uuid4().hex[:10]}"
        scanned_at = datetime.datetime.now(datetime.timezone.utc).isoformat()

        return AttackerScanResponse(
            scan_id=scan_id,
            target_url=request.target_url,
            normalized_url=normalized_url,
            scanned_at=scanned_at,
            status="completed",
            target_ip=scan_meta.get("target_ip"),
            summary=summary,
            findings=findings,
            inferred_attack_scenarios=inferred_scenarios,
            defender_handover=defender_handover,
        )

    @staticmethod
    def _compute_summary(findings: List[VulnerabilityFinding]) -> AttackerScanSummary:
        critical_count = sum(1 for f in findings if f.severity.lower() == "critical")
        high_count = sum(1 for f in findings if f.severity.lower() == "high")
        medium_count = sum(1 for f in findings if f.severity.lower() == "medium")
        low_count = sum(1 for f in findings if f.severity.lower() == "low")
        info_count = sum(1 for f in findings if f.severity.lower() == "info")
        confirmed_count = sum(1 for f in findings if f.is_confirmed)

        return AttackerScanSummary(
            total_findings=len(findings),
            critical_count=critical_count,
            high_count=high_count,
            medium_count=medium_count,
            low_count=low_count,
            info_count=info_count,
            confirmed_count=confirmed_count,
        )

    @staticmethod
    def _derive_inferred_attack_scenarios(
        findings: List[VulnerabilityFinding], target_url: str
    ) -> List[InferredAttackScenario]:
        """
        Derives adversarial threat scenarios strictly based on actual observed findings.
        Every scenario is explicitly marked as 'Inferred Hypothesis' to distinguish
        threat modeling from raw empirical findings.
        """
        scenarios: List[InferredAttackScenario] = []
        finding_ids = {f.id for f in findings}

        # Scenario 1: Transport Insecurity / MITM
        if "VULN-TLS-NO-HTTPS" in finding_ids or "VULN-TLS-MISSING-HSTS" in finding_ids:
            scenarios.append(
                InferredAttackScenario(
                    scenario_title="Adversary In-Path Interception & SSL Stripping",
                    adversary_technique="T1040 - Network Sniffing & T1557 - Adversary-in-the-Middle",
                    preconditions=[
                        "Adversary shares a local network or controls an upstream routing node.",
                        "Target does not enforce strict transport encryption (HSTS or HTTPS).",
                    ],
                    modeled_chain=[
                        "Step 1: Adversary intercepts cleartext ARP or DNS requests to target host.",
                        "Step 2: Adversary strips TLS upgrade or observes cleartext HTTP requests.",
                        "Step 3: Adversary harvests session cookies and unencrypted form submissions.",
                    ],
                    potential_impact="Complete loss of confidentiality for credentials and sensitive data in transit.",
                    confidence="Inferred Hypothesis (Model-Modeled)",
                )
            )

        # Scenario 2: UI Redressing / Clickjacking
        if "VULN-SEC-HDR-NO-XFO" in finding_ids:
            scenarios.append(
                InferredAttackScenario(
                    scenario_title="Cross-Origin Framing & Clickjacking Exploitation",
                    adversary_technique="T1189 - Drive-by Compromise",
                    preconditions=[
                        "Web application allows cross-origin framing without X-Frame-Options or CSP frame-ancestors.",
                        "Target website contains authenticated state-changing actions.",
                    ],
                    modeled_chain=[
                        "Step 1: Attacker constructs phishing landing page embedding target in an opaque iframe.",
                        "Step 2: Attacker overlays misleading UI buttons directly above legitimate target action triggers.",
                        "Step 3: Authenticated user inadvertently executes state changes on the target application.",
                    ],
                    potential_impact="Unauthorized state changes executed on behalf of authenticated victims.",
                    confidence="Inferred Hypothesis (Model-Modeled)",
                )
            )

        # Scenario 3: Cookie Stealing via XSS amplification
        has_cookie_issues = any(f.category == "Session Management" for f in findings)
        if has_cookie_issues and "VULN-SEC-HDR-NO-CSP" in finding_ids:
            scenarios.append(
                InferredAttackScenario(
                    scenario_title="Session Token Exfiltration via Script Injection",
                    adversary_technique="T1539 - Steal Web Session Cookie",
                    preconditions=[
                        "Session cookies lack HttpOnly flag.",
                        "No Content Security Policy to restrict outbound exfiltration destinations.",
                    ],
                    modeled_chain=[
                        "Step 1: Attacker identifies or injects arbitrary client-side script.",
                        "Step 2: Script accesses document.cookie directly because HttpOnly is absent.",
                        "Step 3: Cookie payload is transmitted to external adversary webhook unhindered by CSP.",
                    ],
                    potential_impact="Account takeover and impersonation of active user sessions.",
                    confidence="Inferred Hypothesis (Model-Modeled)",
                )
            )

        # Scenario 4: Known CVE exploitation
        cve_findings = [f for f in findings if f.cve_id is not None]
        for cve in cve_findings:
            scenarios.append(
                InferredAttackScenario(
                    scenario_title=f"Exploitation of Known Vulnerability {cve.cve_id}",
                    adversary_technique="T1190 - Exploit Public-Facing Application",
                    preconditions=[
                        f"Server banner reliably exposes vulnerable component version ({cve.affected_url_or_component}).",
                        "Public exploit documentation or PoC exists for this CVE.",
                    ],
                    modeled_chain=[
                        f"Step 1: Adversary scans external perimeter and identifies disclosed banner.",
                        f"Step 2: Adversary maps target endpoint against known exploit conditions for {cve.cve_id}.",
                        "Step 3: Adversary executes payload to compromise application runtime.",
                    ],
                    potential_impact=cve.potential_impact,
                    confidence="Inferred Hypothesis (Model-Modeled)",
                )
            )

        return scenarios

    @staticmethod
    def _build_defender_handover(
        findings: List[VulnerabilityFinding], target_url: str, summary: AttackerScanSummary
    ) -> Dict[str, Any]:
        """
        Structures empirical scan outputs so the future Defender Agent can immediately
        prescribe and simulate targeted countermeasures.
        """
        recommended_controls = set()
        for f in findings:
            if f.category == "Transport Security":
                recommended_controls.add("enforce_hsts_and_tls")
            elif f.category == "Security Headers":
                recommended_controls.add("deploy_csp_and_frame_options")
            elif f.category == "Session Management":
                recommended_controls.add("harden_cookie_flags")
            elif f.category == "Information Disclosure":
                recommended_controls.add("suppress_server_banners")
            elif f.category == "Outdated Software":
                recommended_controls.add("upgrade_vulnerable_components")

        return {
            "target_url": target_url,
            "total_exposures": summary.total_findings,
            "critical_or_high_count": summary.critical_count + summary.high_count,
            "required_countermeasures": sorted(list(recommended_controls)),
            "finding_ids": [f.id for f in findings],
            "ready_for_defender_agent": True,
        }
