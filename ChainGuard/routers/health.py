"""
Health Check Routes

Provides application health status and version/mode information.
"""

from fastapi import APIRouter

from core.config import get_settings
from core.models import HealthResponse

router = APIRouter()


@router.get("/health", response_model=HealthResponse)
async def health_check():
    """Check application health status."""
    settings = get_settings()
    return HealthResponse(
        status="healthy",
        version=settings.app_version,
        demo_mode=settings.use_demo_mode,
    )


@router.get("/api/status")
async def api_status():
    """Lightweight status endpoint distinct from the static-file root."""
    settings = get_settings()
    return {
        "message": "ChainGuard API",
        "version": settings.app_version,
        "demo_mode": settings.use_demo_mode,
        "docs": "/docs",
    }
