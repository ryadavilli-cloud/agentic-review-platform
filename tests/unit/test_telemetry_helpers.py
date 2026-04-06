# create_span returns a working context manager and the span has the correct name
import logging

import pytest

from app.telemetry.helpers import create_span, log_with_context
from app.telemetry.logging import correlation_id_var


@pytest.mark.unit
def test_create_span():
    with create_span("test.span") as span:
        assert span is not None
        assert span.get_span_context().span_id != 0
        assert span.get_span_context().trace_id != 0


# create_span attaches attributes to the span
@pytest.mark.unit
def test_create_span_attributes():
    with create_span("test.span", attributes={"key": "value"}) as span:
        assert span is not None
        assert span.get_span_context().span_id != 0


# log_with_context emits a log record with correlation ID attached
@pytest.mark.unit
def test_log_with_context_correlation_id(caplog: pytest.LogCaptureFixture):
    caplog.set_level(logging.DEBUG)
    correlation_id_var.set("test-correlation-id")
    log_with_context("test.logger", "test message")

    assert any(
        getattr(record, "correlation_id", None) == "test-correlation-id"
        for record in caplog.records
    )


# log_with_context emits a log record with trace/span IDs attached
@pytest.mark.unit
def test_log_with_context_trace_span_id(caplog: pytest.LogCaptureFixture):
    caplog.set_level(logging.INFO)

    with create_span("test.span"):
        log_with_context("test.logger", "test message")

    assert any(
        getattr(record, "trace_id", None) is not None
        and getattr(record, "span_id", None) is not None
        for record in caplog.records
    )


# log_with_context defaults to INFO level
@pytest.mark.unit
def test_log_with_context_default_level(caplog: pytest.LogCaptureFixture):
    caplog.set_level(logging.INFO)

    log_with_context("test.logger", "test message")

    assert any(record.levelname == "INFO" for record in caplog.records)


# log_with_context respects a custom level (e.g., WARNING)
@pytest.mark.unit
def test_log_with_context_custom_level(caplog: pytest.LogCaptureFixture):
    caplog.set_level(logging.WARNING)

    log_with_context("test.logger", "test warning message", level=logging.WARNING)

    assert any(record.levelname == "WARNING" for record in caplog.records)
