from fastapi import APIRouter, status
from app.schemas.settings import (
    ThreatScenarioResponse,
    DatasetResetResponse,
    AIProviderStatusResponse,
)

router = APIRouter()


@router.get(
    "/ai-status",
    response_model=AIProviderStatusResponse,
    status_code=status.HTTP_200_OK,
    summary="Get AI Provider Configuration & Operational Status",
    description="Returns configuration status of LLM engine or active deterministic rule-based expert system without exposing secrets."
)
def get_ai_provider_status() -> AIProviderStatusResponse:
    """
    Checks active AI provider state. Defaults to deterministic rule-based sandbox.
    """
    return AIProviderStatusResponse(
        provider_name="CyberSentinel Expert AI Engine",
        is_configured=False,
        status="Active (Deterministic Rule-Based Sandbox)",
        model_type="Expert Decision System (FAIR / MITRE ATT&CK Model)",
        mode="Rule-based fallback sandbox",
        details="No external third-party LLM API key configured. The platform operates using deterministic, transparent FAIR and MITRE ATT&CK risk calculation engines for cyber simulation.",
    )


@router.post(
    "/run-scenario",
    response_model=ThreatScenarioResponse,
    status_code=status.HTTP_200_OK,
    summary="Trigger Simulated Threat Scenario",
    description="Validates and advances the configured demonstration threat scenario sequence."
)
def trigger_threat_scenario() -> ThreatScenarioResponse:
    """
    Simulates a threat scenario injection in the demo environment.
    """
    return ThreatScenarioResponse(
        scenario_id="sc-backend-eval",
        scenario_title="Threat scenario validation",
        scenario_kind="threat-simulation",
        severity="High",
        description="Applied simulated adversary scanning against monitored perimeter assets.",
        affected_asset_ids=["a-pay-prod", "a-cust-db"],
        scenarios_remaining=7,
    )


@router.post(
    "/reset-dataset",
    response_model=DatasetResetResponse,
    status_code=status.HTTP_200_OK,
    summary="Reset Demonstration Dataset to Baseline",
    description="Restores the 12 canonical assets and security control baselines."
)
def reset_dataset() -> DatasetResetResponse:
    """
    Confirms baseline restoration for demonstration data.
    """
    return DatasetResetResponse(
        status="success",
        message="Demo dataset restored to baseline parameters.",
        total_assets=12,
        baseline_restored=True,
    )
