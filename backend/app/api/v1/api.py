from fastapi import APIRouter
from app.api.v1.endpoints import risk, simulation, settings, attacker, defender, reports

api_router = APIRouter()

# Register risk assessment endpoints under /risk prefix
api_router.include_router(
    risk.router, 
    prefix="/risk", 
    tags=["Cyber Risk Quantification"]
)

# Register AI agent simulation endpoints under /simulation prefix
api_router.include_router(
    simulation.router,
    prefix="/simulation",
    tags=["AI Agent Cyber Simulation"]
)

# Register Settings and System endpoints under /settings prefix
api_router.include_router(
    settings.router,
    prefix="/settings",
    tags=["Settings & System Management"]
)

# Register Attacker Agent endpoints under /attacker prefix
api_router.include_router(
    attacker.router,
    prefix="/attacker",
    tags=["Attacker Agent"]
)

# Register Defender Agent endpoints under /defender prefix
api_router.include_router(
    defender.router,
    prefix="/defender",
    tags=["Defender Agent"]
)

# Register Security Report Analysis endpoints under /reports prefix
api_router.include_router(
    reports.router,
    prefix="/reports",
    tags=["Security Report Analysis"]
)
