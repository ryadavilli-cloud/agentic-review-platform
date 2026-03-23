import json
import logging

import pytest
from fastapi.testclient import TestClient
from opentelemetry import trace
from opentelemetry.trace import TracerProvider

from app.config import get_settings
from app.main import app
from app.telemetry.logging import JsonFormatter
from app.telemetry.tracing import get_tracer, setup_tracing


@pytest.mark.unit
def test_telemetry_settings():
    settings = get_settings()
    settings.environment = "development"
    provider = setup_tracing(settings)
    assert isinstance(provider, TracerProvider)
    trace.set_tracer_provider(
        trace.NoOpTracerProvider()
    )  # Reset tracer provider to avoid side effects


@pytest.mark.unit
def test_tracer():
    settings = get_settings()
    settings.environment = "development"
    setup_tracing(settings)
    result = get_tracer("test.module")
    assert result.start_span("test.span") is not None
    trace.set_tracer_provider(trace.NoOpTracerProvider())


@pytest.mark.unit
def test_middleware_correlation_id():
    test_client = TestClient(app)
    response = test_client.get("/health")
    assert response.status_code == 200
    correlation_header = response.headers["X-Correlation-ID"]
    assert len(correlation_header) == 36  # Should be a valid UUID or provided ID


@pytest.mark.unit
def test_jsonformatter():
    formatter = JsonFormatter()
    log_record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname="",
        lineno=0,
        msg="test message",
        args=None,
        exc_info=None,
    )
    result = json.loads(formatter.format(log_record))
    assert result["message"] == "test message"
    assert result["logger"] == "test"
    assert result["level"] == "INFO"
    assert result["correlation_id"] == "no_correlation_id"
    assert result["timestamp"] is not None
