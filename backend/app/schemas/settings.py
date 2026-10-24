from typing import List, Optional
from pydantic import BaseModel, Field


class ThreatScenarioResponse(BaseModel):
    scenario_id: str
    scenario_title: str
    scenario_kind: str
    severity: str
    description: str
    affected_asset_ids: List[str]
    scenarios_remaining: int


class DatasetResetResponse(BaseModel):
    status: str
    message: str
    total_assets: int
    baseline_restored: bool


class AIProviderStatusResponse(BaseModel):
    provider_name: str
    is_configured: bool
    status: str
    model_type: str
    mode: str
    details: str
