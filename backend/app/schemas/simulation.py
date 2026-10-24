from typing import List, Optional, Dict
from pydantic import BaseModel, Field


class AttackSimulationRequest(BaseModel):
    asset_id: str = Field(..., description="ID of the target asset from the dataset, e.g. 'a-pay-prod'")
    attack_scenario: str = Field(
        ...,
        description="Attack scenario type: 'vulnerability_exploitation', 'unauthorized_access', or 'privilege_escalation'"
    )
    threat_intensity: str = Field(
        default="medium",
        description="Threat actor intensity level: 'low', 'medium', or 'high'"
    )


class AttackStage(BaseModel):
    stage_number: int
    name: str
    description: str
    technique: str
    success_likelihood: float
    evidence: str


class AttackSimulationResponse(BaseModel):
    asset_id: str
    asset_name: str
    attack_scenario: str
    threat_intensity: str
    baseline_risk_score: float
    simulated_risk_score: float
    is_compromise_modeled: bool
    stages: List[AttackStage]
    affected_assets: List[str]
    potential_business_impact: str
    exploit_factors: List[str]
    suggested_defenses: List[str]


class DefenseSimulationRequest(BaseModel):
    asset_id: str = Field(..., description="Target asset ID")
    baseline_risk_score: float = Field(..., description="Pre-attack risk score")
    simulated_risk_score: float = Field(..., description="Post-attack risk score")
    selected_controls: List[str] = Field(
        ...,
        description="List of applied controls: 'patching', 'mfa', 'segmentation', 'edr'"
    )
    attack_scenario: Optional[str] = Field(default="vulnerability_exploitation")


class AppliedDefenseImpact(BaseModel):
    control_id: str
    control_name: str
    mitigation_reason: str
    points_reduced: float


class DefenseSimulationResponse(BaseModel):
    asset_id: str
    asset_name: str
    pre_defense_risk_score: float
    residual_risk_score: float
    absolute_risk_reduction: float
    percentage_risk_reduction: float
    applied_controls: List[AppliedDefenseImpact]
    remaining_weaknesses: List[str]
    recommended_next_action: str
