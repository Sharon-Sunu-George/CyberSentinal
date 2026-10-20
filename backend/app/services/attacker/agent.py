"""
Attacker AI Agent Service for CyberSentinal.
Orchestrates evidence-based security scanning and deterministic adversarial reasoning.
Strictly separates verified empirical findings from modeled/inferred attack scenarios,
and formats structured outputs ready for the Defender Agent.
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
from app.services.storage import save_scan_record, get_scan_record, update_scan_status


class AttackerAgentService:
    """
    Deterministic Attacker Agent.
    Analyzes actual scanner results and constructs validated threat models
    without hallucinating vulnerabilities or unverified CVEs.
    """

    def __init__(self, scanner: Optional[EvidenceBasedScanner] = None):
        self.scanner = scanner or EvidenceBasedScanner(SafeHttpClient())

    def run_scan(self, request: AttackerScanRequest, scan_id: Optional[str] = None) -> AttackerScanResponse:
        # Enforce authorization
        if not request.is_authorized:
            raise TargetAuthorizationError(
                "Unauthorized scan attempt: user must explicitly confirm authorization before initiating assessment."
            )

        # Normalize and validate target URL
        normalized_url, hostname, port, path = normalize_target_url(request.target_url)

        # Generate or reuse scan_id
        actual_scan_id = scan_id or f"scan-{uuid.uuid4().hex[:10]}"
        scanned_at = datetime.datetime.now(datetime.timezone.utc).isoformat()

        # Update status to running
        save_scan_record({
            "scan_id": actual_scan_id,
            "target_url": request.target_url,
            "normalized_url": normalized_url,
            "scanned_at": scanned_at,
            "status": "running",
            "scope_limitations": "Safe passive audit in progress.",
            "scanner_info": {"engine": self.scanner.scanner_name},
        })

        # Execute bounded, evidence-based scan
        try:
            findings, scan_meta = self.scanner.scan(normalized_url)
        except Exception as e:
            update_scan_status(actual_scan_id, "failed")
            raise

        # Compute summary metrics
        summary = self._compute_summary(findings)

        # Honest disclaimer if zero findings are detected
        zero_disclaimer = None
        if len(findings) == 0:
            zero_disclaimer = (
                "No vulnerabilities were detected by this passive assessment. "
                "Important: Zero findings does not imply that the target website is 100% secure. "
                "Comprehensive security requires deep authenticated testing, business logic reviews, and application code audits."
            )

        # Generate deterministic inferred attack paths derived strictly from observed findings
        inferred_scenarios = self._derive_inferred_attack_scenarios(findings, normalized_url)

        # Structure defender handover packet for the Defender Agent
        defender_handover = self._build_defender_handover(findings, normalized_url, summary)

        response = AttackerScanResponse(
            scan_id=actual_scan_id,
            target_url=request.target_url,
            normalized_url=normalized_url,
            scanned_at=scanned_at,
            status="completed",
            target_ip=scan_meta.get("target_ip"),
            scanner_info=scan_meta.get("scanner_info", {}),
            scope_limitations=scan_meta.get("scope_limitations", ""),
            zero_findings_disclaimer=zero_disclaimer,
            summary=summary,
            findings=findings,
            inferred_attack_scenarios=inferred_scenarios,
            defender_handover=defender_handover,
        )

        # Persist completed scan record
        save_scan_record({
            "scan_id": actual_scan_id,
            "target_url": request.target_url,
            "normalized_url": normalized_url,
            "scanned_at": scanned_at,
            "status": "completed",
            "target_ip": scan_meta.get("target_ip"),
            "scope_limitations": scan_meta.get("scope_limitations", ""),
            "scanner_info": scan_meta.get("scanner_info", {}),
            "summary": summary.model_dump(),
            "findings": [f.model_dump() for f in findings],
            "inferred_attack_scenarios": [s.model_dump() for s in inferred_scenarios],
        })

        return response

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
        scenarios: List[InferredAttackScenario] = []

        # Scenario 1: Man-In-The-Middle / Transport Interception
        has_tls_issue = any(f.category == "Transport Security" for f in findings)
        if has_tls_issue:
            scenarios.append(
                InferredAttackScenario(
                    scenario_title="Cleartext Interception & Credential Sniffing (MITM)",
                    adversary_technique="T1040 - Network Sniffing",
                    preconditions=[
                        "Target does not enforce end-to-end HTTPS or lacks HSTS preloading.",
                        "Adversary shares an unencrypted local network (e.g. public Wi-Fi) or controls intermediate router.",
                    ],
                    modeled_chain=[
                        "Step 1: Adversary positions between client and gateway (ARP spoofing / rogue AP).",
                        "Step 2: Downgrades user connection to unencrypted HTTP via SSL stripping.",
                        "Step 3: Captures unencrypted session cookies, auth tokens, and POST data.",
                    ],
                    potential_impact="Complete loss of confidentiality for all credentials and session state transmitted in cleartext.",
                    confidence="Inferred Hypothesis (Model-Modeled)",
                )
            )

        # Scenario 2: Clickjacking / Frame Manipulation
        has_clickjack = any(f.id == "VULN-SEC-HDR-NO-XFO" for f in findings)
        if has_clickjack:
            scenarios.append(
                InferredAttackScenario(
                    scenario_title="Unauthorized Action Execution via Clickjacking Framing",
                    adversary_technique="T1204 - User Execution",
                    preconditions=[
                        "Target application fails to declare X-Frame-Options or CSP frame-ancestors.",
                        "User is logged into target in their active browser session.",
                    ],
                    modeled_chain=[
                        "Step 1: Adversary crafts a decoy website containing an invisible iframe of target.",
                        "Step 2: Adversary lures victim to click buttons perfectly aligned with target interface buttons.",
                        "Step 3: Victim inadvertently executes state-changing actions (e.g. account transfer, delete resource).",
                    ],
                    potential_impact="Unauthorized state changes executed on behalf of authenticated users without their knowledge.",
                    confidence="Inferred Hypothesis (Model-Modeled)",
                )
            )

        # Scenario 3: Cross-Site Scripting (XSS) Amplification
        has_no_csp = any(f.id == "VULN-SEC-HDR-NO-CSP" for f in findings)
        has_cookie_no_httponly = any("NO-HTTPONLY" in f.id for f in findings)
        if has_no_csp and has_cookie_no_httponly:
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
            elif f.category == "Access Control":
                recommended_controls.add("restrict_cors_origins")

        return {
            "target_url": target_url,
            "total_exposures": summary.total_findings,
            "critical_or_high_count": summary.critical_count + summary.high_count,
            "required_countermeasures": sorted(list(recommended_controls)),
            "finding_ids": [f.id for f in findings],
            "ready_for_defender_agent": True,
        }
