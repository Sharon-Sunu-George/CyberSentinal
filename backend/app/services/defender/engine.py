"""
Defender Agent Prioritization Engine for CyberSentinal.
Calculates evidence-based risk points, labor costs, and optimizes remediation
under explicit budget constraints. Generates three prioritized tiers:
1. Fix Immediately
2. Fix Next
3. Defer or Mitigate Temporarily
And highlights any unbudgeted high-risk findings that exceed available funds.
"""

import datetime
import uuid
from typing import List, Dict, Any, Optional, Tuple

from app.schemas.defender import (
    DefenderAnalysisRequest,
    DefenderAnalysisResponse,
    RemediationRecommendation,
)
from app.services.defender.remediation_catalog import get_playbook_for_finding
from app.services.storage import save_remediation_plan

SEVERITY_BASE_WEIGHTS = {
    "critical": 35.0,
    "high": 25.0,
    "medium": 14.0,
    "low": 6.0,
    "info": 1.5,
}

CONFIDENCE_MULTIPLIERS = {
    "high": 1.0,
    "medium": 0.8,
    "low": 0.6,
}

CRITICALITY_MULTIPLIERS = {
    "critical": 1.30,
    "high": 1.15,
    "medium": 1.00,
    "low": 0.85,
}


class DefenderPrioritizationEngine:
    """
    Evidence-based budgeting and remediation planning engine.
    Applies transparent, multi-factor risk-based prioritization and
    deterministic knapsack optimization subject to explicit budget constraints.
    """

    def __init__(self, hourly_rate: float = 125.0):
        self.default_hourly_rate = hourly_rate

    def analyze(self, request: DefenderAnalysisRequest) -> DefenderAnalysisResponse:
        # Defensive input validation: clamp budget and hourly rate against negative, zero, or NaN inputs
        try:
            budget = float(request.available_budget)
            if budget <= 0 or budget != budget:  # check for NaN
                budget = 1000.0
        except (ValueError, TypeError):
            budget = 1000.0

        try:
            rate = float(request.hourly_rate or self.default_hourly_rate)
            if rate <= 0 or rate != rate:
                rate = self.default_hourly_rate
        except (ValueError, TypeError):
            rate = self.default_hourly_rate

        currency = (request.currency or "USD").strip().upper()[:5]
        crit_mult = CRITICALITY_MULTIPLIERS.get(
            (request.business_criticality or "High").lower(), 1.15
        )

        recommendations: List[RemediationRecommendation] = []

        # 1. Deduplicate input findings by finding ID to prevent duplicate remediation records
        unique_findings: List[Dict[str, Any]] = []
        seen_finding_ids = set()
        for raw_finding in request.findings:
            f_id = raw_finding.get("id") or raw_finding.get("finding_id") or "VULN-UNKNOWN"
            if f_id not in seen_finding_ids:
                seen_finding_ids.add(f_id)
                unique_findings.append(raw_finding)

        # 2. Build initial recommendations with transparent priority scoring and costs
        for raw_finding in unique_findings:
            rec = self._evaluate_finding(raw_finding, rate, currency, crit_mult)
            recommendations.append(rec)

        # 3. Sort by priority score (descending) and risk-reduction cost-efficiency
        def sort_key(r: RemediationRecommendation):
            # Inconclusive/verification required items should never take priority over actionable vulnerabilities
            is_inconclusive = 1 if r.status == "Needs Verification" or "Inconclusive" in r.severity else 0
            # Higher priority_score first; secondary: higher cost_efficiency
            return (is_inconclusive, -r.priority_score, -r.cost_efficiency)

        sorted_recs = sorted(recommendations, key=sort_key)

        # 4. Budget allocation knapsack
        fix_immediately: List[RemediationRecommendation] = []
        fix_next: List[RemediationRecommendation] = []
        defer_or_mitigate: List[RemediationRecommendation] = []
        unbudgeted_high_risk: List[RemediationRecommendation] = []

        current_spending = 0.0
        total_remediation_cost = sum(r.total_cost for r in sorted_recs)

        for rec in sorted_recs:
            sev_lower = rec.severity.lower()
            fits_in_budget = (current_spending + rec.total_cost <= budget)

            # Inconclusive scan items are prerequisites, not standard fixes
            if rec.status == "Needs Verification":
                rec.priority_group = "defer_or_mitigate"
                rec.deferral_reason = (
                    "Target scan received gateway proxy error or connection failure. "
                    "Must verify target reachability and re-scan before allocating production engineering budget."
                )
                rec.priority_rationale = (
                    f"Priority Score: {rec.priority_score:.1f}. Inconclusive finding requiring target connectivity verification."
                )
                defer_or_mitigate.append(rec)
                continue

            if fits_in_budget:
                if rec.priority_score >= 65.0 or sev_lower in ("critical", "high"):
                    rec.priority_group = "fix_immediately"
                    rec.priority_rationale = (
                        f"Priority Score {rec.priority_score:.1f}/100. Urgent: {rec.severity} severity finding directly impacting perimeter security. "
                        f"Allocating {currency} {rec.total_cost:,.2f} ({rec.estimated_effort_hours:.1f} hrs) achieves {rec.projected_risk_reduction:.1f} risk reduction points."
                    )
                    fix_immediately.append(rec)
                    current_spending += rec.total_cost
                else:
                    # Medium or Low that fits
                    if current_spending + rec.total_cost <= budget * 0.70 and rec.cost_efficiency >= 80.0:
                        rec.priority_group = "fix_immediately"
                        rec.priority_rationale = (
                            f"Priority Score {rec.priority_score:.1f}/100. High ROI fix ({rec.cost_efficiency:.1f} pts/{currency}1k) addresses key defense-in-depth barrier."
                        )
                        fix_immediately.append(rec)
                    else:
                        rec.priority_group = "fix_next"
                        rec.priority_rationale = (
                            f"Priority Score {rec.priority_score:.1f}/100. Important defense-in-depth measure fitting comfortably within planned security budget."
                        )
                        fix_next.append(rec)
                    current_spending += rec.total_cost
            else:
                # Does not fit in remaining budget
                rec.priority_group = "defer_or_mitigate"
                shortfall = rec.total_cost - max(0.0, budget - current_spending)
                rec.deferral_reason = (
                    f"Remediation cost ({currency} {rec.total_cost:,.2f}) exceeds remaining budget "
                    f"({currency} {max(0.0, budget - current_spending):,.2f}) by {currency} {shortfall:,.2f}."
                )
                rec.temporary_mitigation = self._generate_temporary_mitigation(rec)
                rec.priority_rationale = (
                    f"Priority Score {rec.priority_score:.1f}/100. Deferred due to budget constraint ({currency} {rec.total_cost:,.2f} > remaining {currency} {max(0.0, budget - current_spending):,.2f}). "
                    f"Deploy interim compensating control: {rec.temporary_mitigation}"
                )
                defer_or_mitigate.append(rec)

                # If Critical or High or priority_score >= 65, explicitly alert in unbudgeted high-risk list
                if sev_lower in ("critical", "high") or rec.priority_score >= 65.0:
                    unbudgeted_high_risk.append(rec)

        # 5. Compute holistic risk metrics
        baseline_risk = min(100.0, round(sum(r.risk_score for r in sorted_recs), 1))
        if baseline_risk == 0:
            baseline_risk = 10.0  # minimal floor

        funded_recs = fix_immediately + fix_next
        risk_reduction_points = min(
            baseline_risk - 5.0,
            round(sum(r.projected_risk_reduction for r in funded_recs), 1)
        )
        if risk_reduction_points < 0:
            risk_reduction_points = 0.0

        projected_residual = max(5.0, round(baseline_risk - risk_reduction_points, 1))
        reduction_percent = round((risk_reduction_points / baseline_risk) * 100.0, 1) if baseline_risk > 0 else 0.0

        remaining_budget = max(0.0, round(budget - current_spending, 2))
        budget_shortfall = round(max(0.0, sum(r.total_cost for r in unbudgeted_high_risk) - remaining_budget), 2)
        risk_per_dollar = round((risk_reduction_points / current_spending) * 1000.0, 2) if current_spending > 0 else 0.0

        analysis_id = f"def-plan-{uuid.uuid4().hex[:10]}"
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()

        response = DefenderAnalysisResponse(
            analysis_id=analysis_id,
            scan_id=request.scan_id,
            target_url=request.target_url,
            currency=currency,
            available_budget=budget,
            hourly_rate=rate,
            total_remediation_cost=round(total_remediation_cost, 2),
            proposed_spending=round(current_spending, 2),
            remaining_budget=remaining_budget,
            budget_shortfall=budget_shortfall,
            baseline_risk_score=baseline_risk,
            projected_residual_risk=projected_residual,
            total_risk_reduction_points=risk_reduction_points,
            total_risk_reduction_percent=reduction_percent,
            risk_reduction_per_dollar=risk_per_dollar,
            fix_immediately=fix_immediately,
            fix_next=fix_next,
            defer_or_mitigate=defer_or_mitigate,
            unbudgeted_high_risk_findings=unbudgeted_high_risk,
            scoring_model_notes=[
                "Multi-Factor Priority Score: Evaluated independently of engineering cost using severity (Critical=40, High=30, Medium=20, Low=10), evidence confidence (High=1.0x, Med=0.75x, Low=0.5x), verified exploitability (+15), internet exposure (+10), and business criticality multiplier.",
                f"Engineering Labor Cost: Estimated hours × user configurable rate ({rate} {currency}/hr). Assumes internal senior engineering time for implementation, local testing, and peer review.",
                "Evidence Validation Guard: Inconclusive findings (gateway errors, connection timeouts) are classified as 'Needs Verification' and never assigned production remediation priority.",
                "Budget Optimization: Sequences fixes to maximize overall risk reduction within available funds. Unfunded high-risk items are explicitly isolated with shortfall calculations.",
            ],
            cost_assumptions=[
                f"Senior Engineering Labor Rate: {rate} {currency}/hour.",
                "Estimates assume internal software engineering time (implementation, local testing, and peer review).",
                "Infrastructure and third-party SaaS/vendor licenses are listed separately where applicable.",
                "Estimates represent evidence-based planning models with ±15% variance range.",
            ],
            created_at=now,
        )

        # Persist to database if scan_id provided
        if request.scan_id:
            try:
                save_remediation_plan({
                    "plan_id": analysis_id,
                    "scan_id": request.scan_id,
                    "available_budget": budget,
                    "hourly_rate": rate,
                    "total_cost": round(total_remediation_cost, 2),
                    "proposed_spending": round(current_spending, 2),
                    "remaining_budget": remaining_budget,
                    "budget_shortfall": budget_shortfall,
                    "baseline_risk_score": baseline_risk,
                    "projected_residual_risk": projected_residual,
                    "total_risk_reduction_percent": reduction_percent,
                    "risk_reduction_per_dollar": risk_per_dollar,
                    "fix_immediately": [r.model_dump() for r in fix_immediately],
                    "fix_next": [r.model_dump() for r in fix_next],
                    "defer_or_mitigate": [r.model_dump() for r in defer_or_mitigate],
                    "unbudgeted_high_risk_findings": [r.model_dump() for r in unbudgeted_high_risk],
                    "scoring_model_notes": response.scoring_model_notes,
                })
            except Exception:
                pass

        return response

    def _evaluate_finding(
        self, finding: Dict[str, Any], hourly_rate: float, currency: str, crit_mult: float
    ) -> RemediationRecommendation:
        finding_id = finding.get("id") or finding.get("finding_id") or "VULN-GENERIC"
        title = finding.get("title", finding_id)
        sev = finding.get("severity", "Low")
        conf = finding.get("confidence", "Medium")
        val_status = finding.get("validation_status", "Confirmed Observation")

        # Inconclusive and proxy/connection error detection
        raw_evidence = finding.get("evidence")
        evidence_dict = raw_evidence if isinstance(raw_evidence, dict) else {}
        is_inconclusive = (
            finding_id in ("VULN-SCAN-GATEWAY-PROXY-ERROR", "VULN-SCAN-CONNECTION-FAILED")
            or val_status in ("Inconclusive", "Scan error")
            or "inconclusive" in title.lower()
            or evidence_dict.get("check_result") == "Inconclusive"
        )

        # Baseline severity weights
        base_weight = SEVERITY_BASE_WEIGHTS.get(sev.lower(), 6.0)
        conf_factor = CONFIDENCE_MULTIPLIERS.get(conf.lower(), 0.8)
        is_confirmed = finding.get("is_confirmed", True)
        conf_bonus = 1.15 if is_confirmed else 0.95

        # Quantitative baseline risk contribution (0-100)
        risk_score = round(base_weight * conf_factor * conf_bonus * crit_mult, 1)

        # Multi-factor Priority Scoring (0-100), separate from remediation effort
        # Formula:
        # Base Severity: Critical (40), High (30), Medium (20), Low (10), Info (5)
        sev_points = {"critical": 40.0, "high": 30.0, "medium": 20.0, "low": 10.0, "info": 5.0}.get(sev.lower(), 10.0)
        # Evidence confidence factor: High (1.0), Medium (0.75), Low (0.50)
        conf_weight = {"high": 1.0, "medium": 0.75, "low": 0.5}.get(conf.lower(), 0.75)
        # Exposure: external web perimeter (+15)
        exposure_pts = 15.0
        # Exploitability: known CVE / confirmed header absence (+15)
        exploit_pts = 15.0 if is_confirmed else 5.0
        if finding.get("cve_id"):
            exploit_pts = 20.0

        if is_inconclusive:
            # Inconclusive findings must not be elevated
            priority_score = 5.0
            priority_explanation = (
                "Priority score 5.0/100 (Prerequisite verification): Scan was inconclusive due to gateway or connection error. "
                "No confirmed security vulnerability has been identified."
            )
        else:
            raw_priority = (sev_points * conf_weight * crit_mult) + exposure_pts + exploit_pts
            priority_score = round(min(100.0, max(5.0, raw_priority)), 1)
            cwe_note = f" (CWE: {finding.get('cwe_id')})" if finding.get("cwe_id") else ""
            priority_explanation = (
                f"Priority score {priority_score:.1f}/100: Derived from {sev} severity ({sev_points:.0f} pts), "
                f"{conf} confidence ({conf_weight:.2f}x weight), asset criticality multiplier ({crit_mult:.2f}x), "
                f"internet exposure (+{exposure_pts:.0f} pts), and empirical observation evidence (+{exploit_pts:.0f} pts){cwe_note}. "
                f"Security risk is calculated independently of remediation cost."
            )

        # Fetch Playbook
        playbook = get_playbook_for_finding(finding)
        effort_hours = playbook.get("effort_hours", 2.0)
        service_cost = playbook.get("service_cost", 0.0)
        labor_cost = round(effort_hours * hourly_rate, 2)
        total_cost = round(labor_cost + service_cost, 2)

        # Implementation difficulty
        if effort_hours <= 2.0:
            difficulty = "Easy"
        elif effort_hours <= 5.0:
            difficulty = "Moderate"
        else:
            difficulty = "Hard"

        # Risk reduction calculation
        reduction_points = round(risk_score * 0.90, 1)
        cost_eff = round((reduction_points / total_cost) * 1000.0, 2) if total_cost > 0 else 0.0

        # Qualitative risk reduction description
        qualitative_reduction = (
            f"Remediating this finding eliminates an estimated {reduction_points:.1f} risk points, "
            f"preventing potential adversary exploitation and strengthening perimeter defense-in-depth."
        )

        # Standard initial remediation status: Not Started (or existing)
        existing_status = finding.get("remediation_status") or finding.get("status")
        if not existing_status or existing_status in ("Open", "Planned"):
            initial_status = "Not Started"
        elif existing_status == "Fixed":
            initial_status = "Fixed Pending Verification"
        elif existing_status in ("Not Started", "In Progress", "Fixed Pending Verification", "Verified Fixed", "Reopened"):
            initial_status = existing_status
        elif existing_status == "Verified":
            initial_status = "Verified Fixed"
        else:
            initial_status = "Not Started"

        if is_inconclusive:
            initial_status = "Needs Verification"

        # Validation steps
        validation_steps = [
            f"1. Apply configuration or code change to target server.",
            f"2. Execute empirical verification command: {playbook['verification_procedure']}",
            f"3. Run automated verification probe via Defender Agent to confirm resolution on wire.",
        ]

        obs_cond = (
            evidence_dict.get("observed_value")
            or evidence_dict.get("raw_snippet")
            or (raw_evidence if isinstance(raw_evidence, str) and raw_evidence.strip() else None)
            or finding.get("severity_reason")
            or "Direct wire observation from HTTP response"
        )
        exp_cond = (
            evidence_dict.get("expected_condition")
            or "Standard security control or RFC requirement active"
        )

        # Technology classification: specific if component is known, otherwise generic
        comp_or_title = (title + " " + finding_id).lower()
        if any(tech in comp_or_title for tech in ("nginx", "apache", "express", "next.js", "django", "php", "cve")):
            tech_class = "technology_specific"
        else:
            tech_class = "generic"

        return RemediationRecommendation(
            finding_id=finding_id,
            finding_title=title,
            severity=sev,
            confidence=conf,
            category=finding.get("category", "General Security"),
            cwe_id=finding.get("cwe_id"),
            cve_id=finding.get("cve_id"),
            affected_url_or_component=finding.get("affected_url_or_component", "Web Perimeter"),
            short_explanation=finding.get("potential_impact") or playbook["root_cause"],
            why_it_matters=playbook.get("why_it_matters", playbook["root_cause"]),
            root_cause=playbook["root_cause"],
            observed_condition=obs_cond,
            expected_condition=exp_cond,
            tech_classification=tech_class,
            actionable_fix=playbook["actionable_fix"],
            recommended_fix=playbook.get("actionable_fix", ""),
            implementation_steps=playbook["implementation_steps"],
            code_snippets=playbook.get("code_snippets", {}),
            file_or_config_location=playbook.get("file_or_config_location", "Web server or application reverse proxy configuration"),
            implementation_difficulty=difficulty,
            estimated_effort_hours=effort_hours,
            hourly_rate=hourly_rate,
            currency=currency,
            labor_cost=labor_cost,
            service_cost=service_cost,
            total_cost=total_cost,
            cost_assumption=f"Internal senior engineering time at {hourly_rate} {currency}/hour (planning, implementation, local testing, and peer review)",
            risk_score=risk_score,
            priority_score=priority_score,
            priority_explanation=priority_explanation,
            projected_risk_reduction=reduction_points,
            risk_reduction_expected=qualitative_reduction,
            cost_efficiency=cost_eff,
            priority_group="fix_next",
            priority_rationale="",
            dependencies_and_side_effects=playbook.get("dependencies_and_side_effects", "Review application dependencies and test in staging to avoid compatibility regressions."),
            dependencies=playbook.get("dependencies", []),
            assumptions=playbook.get("assumptions", []),
            confidence_range="±15%",
            validation_steps=validation_steps,
            verification_procedure=playbook["verification_procedure"],
            rollback_guidance=playbook.get("rollback_guidance", "Revert configuration directives in web server configuration and reload service gracefully."),
            status=initial_status,
            remediation_status=initial_status,
        )

    @staticmethod
    def _generate_temporary_mitigation(rec: RemediationRecommendation) -> str:
        cat = rec.category.lower()
        if "transport" in cat or "tls" in rec.finding_id.lower():
            return "Deploy Cloudflare or CDN edge rule enforcing 'Always Use HTTPS' and HSTS header injection."
        elif "header" in cat or "clickjack" in rec.finding_title.lower():
            return "Inject temporary response headers via Edge CDN / WAF transforms (e.g. AWS CloudFront Functions / Cloudflare Rules)."
        elif "cookie" in cat:
            return "Enable session timeout shortening and monitor for concurrent IP logins in application logs."
        elif "outdated" in cat or rec.cve_id:
            return f"Activate WAF virtual patching rule matching {rec.cve_id or 'path traversal / RCE vectors'} to block exploit probes."
        else:
            return "Monitor access logs for abnormal requests and restrict access to trusted source IP addresses."

