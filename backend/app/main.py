"""ARGUS — FastAPI application entry point."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse

from app.api.routes import router as api_router
from app.core.config import get_settings
from app.services.threat_feed import threat_feed

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)
settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup / shutdown lifecycle."""
    logger.info("ARGUS starting up …")

    # Try to initialise external connections (non-fatal if unavailable)
    try:
        from app.core.database import get_redis
        await get_redis()
    except Exception:
        logger.warning("Redis not available – continuing without it.")

    try:
        from app.core.database import get_neo4j_driver
        await get_neo4j_driver()
    except Exception:
        logger.warning("Neo4j not available – continuing without it.")

    # Load ML models (falls back to mock inference if files absent)
    try:
        from app.ml.inference import anomaly_detector
        anomaly_detector.load_models()
    except Exception:
        logger.warning("ML model loading skipped.")

    # Start the synthetic threat feed
    await threat_feed.start()

    yield  # ← application runs here

    # Shutdown
    logger.info("ARGUS shutting down …")
    await threat_feed.stop()

    try:
        from app.core.database import close_redis, close_neo4j
        await close_redis()
        await close_neo4j()
    except Exception:
        pass


app = FastAPI(
    title="ARGUS API",
    description="Open-Source Cyber Threat Detection & Intelligence Platform",
    version="0.1.0",
    lifespan=lifespan,
)

# CORS — wide open for development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routes
app.include_router(api_router)


@app.get("/", include_in_schema=False)
async def root():
    """Redirect root to Swagger docs."""
    return RedirectResponse(url="/docs")
