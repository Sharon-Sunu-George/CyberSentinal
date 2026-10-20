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
    Applies deterministic FAIR-aligned risk reduction optimization
    subject to hard budget constraints.
    """

    def __init__(self, hourly_rate: float = 125.0):
        self.default_hourly_rate = hourly_rate

    def analyze(self, request: DefenderAnalysisRequest) -> DefenderAnalysisResponse:
        rate = request.hourly_rate or self.default_hourly_rate
        budget = request.available_budget
        crit_mult = CRITICALITY_MULTIPLIERS.get(
            (request.business_criticality or "High").lower(), 1.15
        )

        recommendations: List[RemediationRecommendation] = []

        # 1. Build initial recommendations with costs and risk points
        for raw_finding in request.findings:
            rec = self._evaluate_finding(raw_finding, rate, crit_mult)
            recommendations.append(rec)

        # 2. Sort by urgency and cost-efficiency
        # Primary: Critical & High severity first; Secondary: highest risk reduction per dollar
        def sort_key(r: RemediationRecommendation):
            sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(
                r.severity.lower(), 5
            )
            return (sev_rank, -r.cost_efficiency)

        sorted_recs = sorted(recommendations, key=sort_key)

        # 3. Budget allocation knapsack
        fix_immediately: List[RemediationRecommendation] = []
        fix_next: List[RemediationRecommendation] = []
        defer_or_mitigate: List[RemediationRecommendation] = []
        unbudgeted_high_risk: List[RemediationRecommendation] = []

        current_spending = 0.0
        total_remediation_cost = sum(r.total_cost for r in sorted_recs)

        for rec in sorted_recs:
            sev_lower = rec.severity.lower()
            fits_in_budget = (current_spending + rec.total_cost <= budget)

            if fits_in_budget:
                if sev_lower in ("critical", "high"):
                    rec.priority_group = "fix_immediately"
                    rec.priority_rationale = (
                        f"Urgent: {rec.severity} severity finding directly impacting perimeter security. "
                        f"Estimated fix reduces {rec.projected_risk_reduction:.1f} risk points within approved budget."
                    )
                    fix_immediately.append(rec)
                    current_spending += rec.total_cost
                else:
                    # Medium or Low that fits
                    if current_spending + rec.total_cost <= budget * 0.75 and sev_lower == "medium":
                        rec.priority_group = "fix_immediately"
                        rec.priority_rationale = (
                            f"High ROI fix ({rec.cost_efficiency:.1f} pts/$1k) addresses key defense-in-depth barrier."
                        )
                        fix_immediately.append(rec)
                    else:
                        rec.priority_group = "fix_next"
                        rec.priority_rationale = (
                            f"Important defense-in-depth measure fitting comfortably within planned security budget."
                        )
                        fix_next.append(rec)
                    current_spending += rec.total_cost
            else:
                # Does not fit in remaining budget
                rec.priority_group = "defer_or_mitigate"
                shortfall = rec.total_cost - max(0.0, budget - current_spending)
                rec.deferral_reason = (
                    f"Remediation cost (${rec.total_cost:,.2f}) exceeds remaining budget "
                    f"(${max(0.0, budget - current_spending):,.2f}) by ${shortfall:,.2f}."
                )
                rec.temporary_mitigation = self._generate_temporary_mitigation(rec)
                rec.priority_rationale = (
                    f"Deferred due to budget constraint. Deploy interim compensating control: {rec.temporary_mitigation}"
                )
                defer_or_mitigate.append(rec)

                # If Critical or High, explicitly alert in unbudgeted high-risk list
                if sev_lower in ("critical", "high"):
                    unbudgeted_high_risk.append(rec)

        # 4. Compute holistic risk metrics
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
            currency="USD",
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
                "Risk Scoring: Weighted sum of finding severity, confidence factor, and asset criticality multiplier.",
                "Engineering Labor Cost: Estimated engineering hours × configurable engineering rate ($125/hr standard).",
                "Optimization Model: Greedy cost-effectiveness allocation prioritizing urgent exposures while maximizing risk reduction per dollar.",
                "Residual Risk Projection: Measured baseline risk minus cumulative reduction of funded controls, floored at 5.0 points to represent inherent operational uncertainty.",
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
        self, finding: Dict[str, Any], hourly_rate: float, crit_mult: float
    ) -> RemediationRecommendation:
        finding_id = finding.get("id", "VULN-GENERIC")
        sev = finding.get("severity", "Low")
        conf = finding.get("confidence", "Medium")

        base_weight = SEVERITY_BASE_WEIGHTS.get(sev.lower(), 6.0)
        conf_factor = CONFIDENCE_MULTIPLIERS.get(conf.lower(), 0.8)
        is_confirmed = finding.get("is_confirmed", True)
        conf_bonus = 1.15 if is_confirmed else 0.95

        # Risk score calculation
        risk_score = round(base_weight * conf_factor * conf_bonus * crit_mult, 1)

        # Fetch Playbook
        playbook = get_playbook_for_finding(finding)
        effort_hours = playbook.get("effort_hours", 2.0)
        service_cost = playbook.get("service_cost", 0.0)
        labor_cost = round(effort_hours * hourly_rate, 2)
        total_cost = round(labor_cost + service_cost, 2)

        # Risk reduction calculation (fixing an issue eliminates ~85-95% of its risk contribution)
        reduction_points = round(risk_score * 0.90, 1)
        cost_eff = round((reduction_points / total_cost) * 1000.0, 2) if total_cost > 0 else 0.0

        return RemediationRecommendation(
            finding_id=finding_id,
            finding_title=finding.get("title", finding_id),
            severity=sev,
            category=finding.get("category", "General Security"),
            cwe_id=finding.get("cwe_id"),
            cve_id=finding.get("cve_id"),
            affected_url_or_component=finding.get("affected_url_or_component", "Web Perimeter"),
            root_cause=playbook["root_cause"],
            actionable_fix=playbook["actionable_fix"],
            implementation_steps=playbook["implementation_steps"],
            code_snippets=playbook.get("code_snippets", {}),
            estimated_effort_hours=effort_hours,
            hourly_rate=hourly_rate,
            labor_cost=labor_cost,
            service_cost=service_cost,
            total_cost=total_cost,
            risk_score=risk_score,
            projected_risk_reduction=reduction_points,
            cost_efficiency=cost_eff,
            priority_group="fix_next",  # default, will be set during allocation
            priority_rationale="",
            dependencies=playbook.get("dependencies", []),
            assumptions=playbook.get("assumptions", []),
            confidence_range="±15%",
            verification_procedure=playbook["verification_procedure"],
            status=finding.get("remediation_status", "Open"),
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
