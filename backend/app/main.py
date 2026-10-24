from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.v1.api import api_router

app = FastAPI(
    title="CyberQuant API",
    description=(
        "Cyber Risk Quantification and Financial Loss Estimation Engine. "
        "Provides REST endpoints for threat frequency analysis, single loss expectancy (SLE), "
        "annual loss expectancy (ALE), security control ROI, and multi-scenario comparison."
    ),
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

import os

# CORS configuration: Allow specific origins in production via CORS_ORIGINS, or default to all origins
cors_origins_env = os.getenv("CORS_ORIGINS")
allowed_origins = [o.strip() for o in cors_origins_env.split(",") if o.strip()] if cors_origins_env else ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True if allowed_origins != ["*"] else False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include v1 API endpoints under /api/v1
app.include_router(api_router, prefix="/api/v1")


@app.get("/", tags=["Root"])
def root():
    """
    Root endpoint welcome message.
    """
    return {
        "message": "Welcome to CyberQuant Engine API",
        "documentation": "/docs",
        "api_v1_prefix": "/api/v1"
    }


@app.get("/health", tags=["Health"])
def health():
    """
    Operational health and readiness probe.
    Checks application status and database availability.
    """
    from app.services.storage import get_db_connection
    db_status = "healthy"
    try:
        conn = get_db_connection()
        conn.execute("SELECT 1")
        conn.close()
    except Exception as e:
        db_status = f"unhealthy: {str(e)}"

    return {
        "status": "healthy" if db_status == "healthy" else "degraded",
        "app": "CyberSentinal API",
        "version": "1.0.0",
        "database": db_status,
        "mode": "standalone-server",
    }
