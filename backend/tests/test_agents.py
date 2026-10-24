import unittest
from app.schemas.simulation import (
    AttackSimulationRequest,
    DefenseSimulationRequest,
)
from app.services.simulation_engine import AgentSimulationService


class TestAgentSimulation(unittest.TestCase):
    def test_attacker_agent_vulnerability_exploitation(self):
        req = AttackSimulationRequest(
            asset_id="a-pay-prod",
            attack_scenario="vulnerability_exploitation",
            threat_intensity="medium"
        )
        res = AgentSimulationService.simulate_attack(req)

        self.assertEqual(res.asset_id, "a-pay-prod")
        self.assertEqual(res.asset_name, "Payment Production Server")
        self.assertTrue(res.is_compromise_modeled)
        self.assertEqual(len(res.stages), 3)
        self.assertGreater(res.simulated_risk_score, res.baseline_risk_score)
        self.assertIn("patching", res.suggested_defenses)
        self.assertGreaterEqual(len(res.affected_assets), 2)

    def test_attacker_agent_unauthorized_access(self):
        req = AttackSimulationRequest(
            asset_id="a-idp",
            attack_scenario="unauthorized_access",
            threat_intensity="high"
        )
        res = AgentSimulationService.simulate_attack(req)

        self.assertEqual(res.asset_id, "a-idp")
        self.assertEqual(len(res.stages), 3)
        self.assertLessEqual(res.simulated_risk_score, 100.0)
        self.assertIn("mfa", res.suggested_defenses)

    def test_defender_agent_remediation_workflow(self):
        # Step 1: Run attack
        attack_req = AttackSimulationRequest(
            asset_id="a-cust-db",
            attack_scenario="vulnerability_exploitation",
            threat_intensity="medium"
        )
        attack_res = AgentSimulationService.simulate_attack(attack_req)

        # Step 2: Run defense using attacker's findings
        defense_req = DefenseSimulationRequest(
            asset_id=attack_res.asset_id,
            baseline_risk_score=attack_res.baseline_risk_score,
            simulated_risk_score=attack_res.simulated_risk_score,
            selected_controls=attack_res.suggested_defenses,
            attack_scenario=attack_res.attack_scenario
        )
        defense_res = AgentSimulationService.simulate_defense(defense_req)

        self.assertEqual(defense_res.asset_id, "a-cust-db")
        self.assertLess(defense_res.residual_risk_score, defense_res.pre_defense_risk_score)
        self.assertGreater(defense_res.absolute_risk_reduction, 0)
        self.assertGreater(defense_res.percentage_risk_reduction, 0)
        self.assertEqual(len(defense_res.applied_controls), len(attack_res.suggested_defenses))
        self.assertGreater(len(defense_res.recommended_next_action), 0)

    def test_defender_agent_partial_controls(self):
        defense_req = DefenseSimulationRequest(
            asset_id="a-pay-api",
            baseline_risk_score=64.0,
            simulated_risk_score=76.0,
            selected_controls=["patching"],
            attack_scenario="vulnerability_exploitation"
        )
        defense_res = AgentSimulationService.simulate_defense(defense_req)

        self.assertEqual(len(defense_res.applied_controls), 1)
        self.assertGreater(len(defense_res.remaining_weaknesses), 0)


if __name__ == "__main__":
    unittest.main()
