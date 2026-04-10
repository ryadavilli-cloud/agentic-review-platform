import logging
from contextlib import AbstractContextManager
from typing import Any, Literal

from opentelemetry import trace
from opentelemetry.trace import Span, Tracer

from app.telemetry.logging import correlation_id_var
from app.telemetry.metrics import get_meter
from app.telemetry.tracing import get_tracer


def create_span(
    name: str, attributes: dict[str, Any] | None = None
) -> AbstractContextManager[Span]:
    tracer: Tracer = get_tracer(name=name)
    return tracer.start_as_current_span(name, attributes=attributes)


def log_with_context(
    logger_name: str, message: str, *, level: int = logging.INFO, **extra: Any
) -> None:
    logger = logging.getLogger(logger_name)
    correlation_id = correlation_id_var.get()
    span_context = trace.get_current_span().get_span_context()

    dict_extra: dict[str, Any] = {
        "correlation_id": correlation_id,
        "trace_id": span_context.trace_id,
        "span_id": span_context.span_id,
        **extra,
    }

    logger.log(level, message, extra=dict_extra)


METER_NAME = "agentic_review_platform.metrics"

type MetricType = Literal["counter", "histogram"]
type MetricAttributes = dict[str, str | bool | int | float]


def record_metric(
    name: str,
    value: int | float,
    metric_type: MetricType,
    attributes: MetricAttributes | None = None,
) -> None:
    meter = get_meter(METER_NAME)
    metric_attributes = attributes or {}

    if metric_type == "counter":
        if value < 0:
            raise ValueError("Counter metrics must use a non-negative value")

        counter = meter.create_counter(name)
        counter.add(value, attributes=metric_attributes)
        return

    histogram = meter.create_histogram(name)
    histogram.record(value, attributes=metric_attributes)
