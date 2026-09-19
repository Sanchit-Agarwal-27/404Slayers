"""
ChainGuard - Web3 Wallet & Contract Reputation Intelligence

Main FastAPI application entry point.
"""

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from core.config import get_settings
from routers import health, analyze, address, history

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info(f"Starting {settings.app_name} v{settings.app_version}")
    logger.info(f"Debug mode: {settings.debug}")
    logger.info(f"Demo mode enabled: {settings.use_demo_mode}")
    yield
    logger.info(f"Shutting down {settings.app_name}")


app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="Explainable reputation analysis for blockchain wallets and smart contracts.",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# API routers are registered before the static-file mount below, so they
# always take priority over the frontend's catch-all "/" route.
app.include_router(health.router, tags=["health"])
app.include_router(analyze.router, prefix="/api", tags=["analysis"])
app.include_router(address.router, prefix="/api", tags=["addresses"])
app.include_router(history.router, prefix="/api", tags=["history"])

# Serve the frontend as static files, mounted last so it only catches
# requests not matched by an API route above.
frontend_dir = Path(__file__).parent / "frontend"
if frontend_dir.exists():
    app.mount("/", StaticFiles(directory=str(frontend_dir), html=True), name="frontend")
else:
    logger.warning(f"Frontend directory not found at {frontend_dir}; static UI will not be served.")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug,
    )
