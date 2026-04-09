import logging
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor

from app.api import router
from app.config import get_settings
from app.telemetry.logging import setup_logging
from app.telemetry.middleware import correlation_id_middleware
from app.telemetry.tracing import setup_tracing


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    settings = get_settings()  # Load settings and cache them
    setup_logging(settings.log_level)
    provider = setup_tracing(settings)
    yield  # Application runs here
    provider.shutdown()


app = FastAPI(
    title="Agentic Engineering Review Platform",
    description="AI-powered code and risk review agent",
    version="0.1.0",
    lifespan=lifespan,
    openapi_tags=[
        {"name": "Review", "description": "Security review and analysis endpoints"}
    ],
)
app.include_router(router.router)
app.middleware("http")(correlation_id_middleware)
FastAPIInstrumentor.instrument_app(app)

logger = logging.getLogger(__name__)


@app.get("/health")
def health_check() -> dict[str, str]:
    logger.info("Health check called")
    return {"status": "healthy", "version": "0.1.0"}
