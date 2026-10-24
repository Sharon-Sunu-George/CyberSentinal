from fastapi import APIRouter, status
from app.schemas.simulation import (
    AttackSimulationRequest,
    AttackSimulationResponse,
    DefenseSimulationRequest,
    DefenseSimulationResponse,
)
from app.services.simulation_engine import AgentSimulationService

router = APIRouter()


@router.post(
    "/attack",
    response_model=AttackSimulationResponse,
    status_code=status.HTTP_200_OK,
    summary="Simulate Attacker Agent Scenario",
    description="Evaluates a deterministic attack simulation against a target asset and produces modeled attack stages and risk impact."
)
def simulate_attack(request: AttackSimulationRequest) -> AttackSimulationResponse:
    """
    Simulates attack progression, compromised stages, and initial risk escalation.
    """
    return AgentSimulationService.simulate_attack(request)


@router.post(
    "/defend",
    response_model=DefenseSimulationResponse,
    status_code=status.HTTP_200_OK,
    summary="Simulate Defender Agent Countermeasures",
    description="Evaluates selected defensive controls against modeled attack conditions to compute residual risk and risk reduction."
)
def simulate_defense(request: DefenseSimulationRequest) -> DefenseSimulationResponse:
    """
    Calculates residual risk score and effectiveness of applied defensive safeguards.
    """
    return AgentSimulationService.simulate_defense(request)
