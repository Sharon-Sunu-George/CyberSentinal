"""
Defender Agent REST Endpoints for CyberSentinal.
Provides:
- POST /api/v1/defender/analyze to prioritize findings under an explicit budget
- PATCH /api/v1/defender/remediation/{scan_id}/{finding_id}/status to update remediation tracking state
- GET /api/v1/defender/scans/{scan_id}/plan to retrieve the persisted remediation plan
- GET /api/v1/defender/settings to retrieve configurable cost rates and model assumptions.
"""

from typing import Dict, Any, Optional
from fastapi import APIRouter, HTTPException, status
from app.schemas.defender import (
    DefenderAnalysisRequest,
    DefenderAnalysisResponse,
    RemediationStatusUpdateRequest,
)
from app.services.defender.engine import DefenderPrioritizationEngine
from app.services.storage import (
    get_latest_remediation_plan,
    update_finding_remediation_status,
    get_scan_record,
)

router = APIRouter()

VALID_REMEDIATION_STATUSES = {
    "Open",
    "Planned",
    "In Progress",
    "Fixed",
    "Accepted Risk",
    "Verified",
}


@router.post(
    "/analyze",
    response_model=DefenderAnalysisResponse,
    status_code=status.HTTP_200_OK,
    summary="Generate Budget-Constrained Remediation Plan",
    description=(
        "Analyzes empirical scan findings produced by the Attacker Agent, calculates technical fixes "
        "and labor costs, and prioritizes remediation actions into three tiers under the specified budget."
    ),
)
def analyze_remediation_budget(request: DefenderAnalysisRequest) -> DefenderAnalysisResponse:
    if request.available_budget <= 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Available budget must be greater than zero.",
        )

    # If findings are empty but scan_id is provided, try loading from stored scan
    findings = request.findings
    if not findings and request.scan_id:
        scan_record = get_scan_record(request.scan_id)
        if scan_record:
            findings = scan_record.get("findings", [])

    if not findings:
        # Return clean empty plan if target has zero findings
        engine = DefenderPrioritizationEngine(hourly_rate=request.hourly_rate or 125.0)
        return engine.analyze(request)

    engine = DefenderPrioritizationEngine(hourly_rate=request.hourly_rate or 125.0)
    try:
        response = engine.analyze(request)
        return response
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Defender prioritization engine error: {str(e)}",
        )


@router.patch(
    "/remediation/{scan_id}/{finding_id}/status",
    summary="Update Finding Remediation Status",
    description="Updates tracking state: 'Open', 'Planned', 'In Progress', 'Fixed', 'Accepted Risk', or 'Verified'.",
)
def update_status(
    scan_id: str, finding_id: str, req: RemediationStatusUpdateRequest
) -> Dict[str, Any]:
    if req.status not in VALID_REMEDIATION_STATUSES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid status '{req.status}'. Must be one of: {sorted(list(VALID_REMEDIATION_STATUSES))}",
        )

    updated = update_finding_remediation_status(
        scan_id=scan_id,
        finding_id=finding_id,
        status=req.status,
        notes=req.notes,
    )

    if not updated:
        # Check if scan exists
        scan = get_scan_record(scan_id)
        if not scan:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Scan '{scan_id}' not found.",
            )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Finding '{finding_id}' not found under scan '{scan_id}'.",
        )

    return {
        "scan_id": scan_id,
        "finding_id": finding_id,
        "remediation_status": req.status,
        "notes": req.notes,
        "updated": True,
    }


@router.get(
    "/scans/{scan_id}/plan",
    response_model=Dict[str, Any],
    summary="Get Persisted Remediation Plan",
    description="Retrieves the latest budget-aware remediation plan calculated for the given scan.",
)
def get_plan(scan_id: str) -> Dict[str, Any]:
    plan = get_latest_remediation_plan(scan_id)
    if not plan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No remediation plan found for scan '{scan_id}'.",
        )
    return plan


@router.get(
    "/settings",
    summary="Defender Configuration and Cost Rates",
    description="Returns default engineering rates, supported currencies, and valid remediation statuses.",
)
def get_defender_settings() -> Dict[str, Any]:
    return {
        "currency": "USD",
        "default_hourly_rate": 125.0,
        "valid_statuses": sorted(list(VALID_REMEDIATION_STATUSES)),
        "cost_assumptions": [
            "Senior Security Engineer rate defaults to $125/hr.",
            "Estimates include implementation, local unit testing, and peer review.",
            "Vendor license and external hardware costs are tracked under service_cost.",
            "Estimates are evidence-based models with ±15% variance.",
        ],
    }
