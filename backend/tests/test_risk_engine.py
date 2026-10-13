"""Tests for risk_engine module."""

import pytest
from app.schemas.risk import (
    RiskAssessmentRequest,
    ScenarioComparisonRequest,
)
from app.services.risk_engine import RiskEngineService


class TestRiskEngineService:
    """Tests for FAIR risk quantification formulas in risk_engine.py."""

    def test_calculate_single_risk_deterministic_formulas(self):
        """Verify SLE, LEF, ALE, mitigated ALE, risk reduction, and ROI calculations."""
        req = RiskAssessmentRequest(
            scenario_name="Test Ransomware",
            asset_name="Core DB",
            asset_value=5_000_000.0,
            threat_event_frequency=2.0,
            vulnerability_probability=0.35,
            direct_loss=150_000.0,
            indirect_loss=300_000.0,
            proposed_security_cost=50_000.0,
            mitigated_vulnerability_probability=0.10,
        )
        res = RiskEngineService.calculate_single_risk(req)

        # 1. SLE = 150,000 + 300,000 = 450,000
        assert res.metrics.single_loss_expectancy == 450_000.0

        # 2. LEF = 2.0 * 0.35 = 0.70
        assert res.metrics.loss_event_frequency == 0.7

        # 3. Baseline ALE = 0.70 * 450,000 = 315,000
        assert res.metrics.annual_loss_expectancy == 315_000.0

        # 4. Mitigated LEF = 2.0 * 0.10 = 0.20 -> Mitigated ALE = 0.20 * 450,000 = 90,000
        assert res.metrics.mitigated_annual_loss_expectancy == 90_000.0

        # 5. Annual Risk Reduction = 315,000 - 90,000 = 225,000
        assert res.metrics.annual_risk_reduction == 225_000.0

        # 6. Net savings = 225,000 - 50,000 = 175,000
        # ROI % = (175,000 / 50,000) * 100 = 350.0%
        assert res.metrics.security_roi_percentage == 350.0
        assert "RECOMMENDED: Deploy security controls" in res.recommendation

    def test_calculate_single_risk_without_mitigation(self):
        """Verify calculation when no mitigation controls are proposed."""
        req = RiskAssessmentRequest(
            scenario_name="Unmitigated Scenario",
            asset_name="Payment Server",
            asset_value=1_000_000.0,
            threat_event_frequency=1.5,
            vulnerability_probability=0.40,
            direct_loss=100_000.0,
            indirect_loss=50_000.0,
            proposed_security_cost=0.0,
            mitigated_vulnerability_probability=None,
        )
        res = RiskEngineService.calculate_single_risk(req)

        assert res.metrics.single_loss_expectancy == 150_000.0
        assert res.metrics.loss_event_frequency == 0.6
        assert res.metrics.annual_loss_expectancy == 90_000.0
        assert res.metrics.mitigated_annual_loss_expectancy is None
        assert res.metrics.annual_risk_reduction is None
        assert res.metrics.security_roi_percentage is None
        assert "BASELINE RISK: Unmitigated Annual Loss Expectancy is $90,000.00" in res.recommendation

    def test_compare_scenarios(self):
        """Verify scenario comparison aggregates multiple scenarios correctly."""
        req1 = RiskAssessmentRequest(
            scenario_name="Scenario A",
            asset_name="Asset A",
            asset_value=2_000_000.0,
            threat_event_frequency=2.0,
            vulnerability_probability=0.5,
            direct_loss=100_000.0,
            indirect_loss=100_000.0,
            proposed_security_cost=20_000.0,
            mitigated_vulnerability_probability=0.2,
        )
        req2 = RiskAssessmentRequest(
            scenario_name="Scenario B",
            asset_name="Asset B",
            asset_value=1_000_000.0,
            threat_event_frequency=1.0,
            vulnerability_probability=0.25,
            direct_loss=50_000.0,
            indirect_loss=50_000.0,
            proposed_security_cost=10_000.0,
            mitigated_vulnerability_probability=0.1,
        )

        comparison_req = ScenarioComparisonRequest(scenarios=[req1, req2])
        res = RiskEngineService.compare_scenarios(comparison_req)

        # Scenario A: SLE=200k, LEF=1.0, ALE=200k, mit_LEF=0.4, mit_ALE=80k, savings=120k
        # Scenario B: SLE=100k, LEF=0.25, ALE=25k, mit_LEF=0.1, mit_ALE=10k, savings=15k
        # Total baseline ALE = 200k + 25k = 225,000.0
        # Total mitigated ALE = 80k + 10k = 90,000.0
        # Total potential savings = 120k + 15k = 135,000.0
        assert res.total_baseline_ale == 225_000.0
        assert res.total_mitigated_ale == 90_000.0
        assert res.total_potential_savings == 135_000.0
        assert len(res.assessments) == 2
