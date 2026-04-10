# create_span returns a working context manager and the span has the correct name
import logging
from collections.abc import Generator

import pytest
from opentelemetry.metrics import Meter
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import (
    InMemoryMetricReader,
    NumberDataPoint,
)

from app.telemetry.helpers import create_span, log_with_context, record_metric
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


@pytest.fixture
def get_meter_reader(
    monkeypatch: pytest.MonkeyPatch,
) -> Generator[InMemoryMetricReader, None, None]:
    reader = InMemoryMetricReader()
    provider = MeterProvider(metric_readers=[reader])

    def fake_get_meter(name: str) -> Meter:
        return provider.get_meter(name)

    monkeypatch.setattr("app.telemetry.helpers.get_meter", fake_get_meter)

    yield reader

    provider.shutdown()


def get_metric(reader: InMemoryMetricReader, metric_name: str):
    metrics_data = reader.get_metrics_data()

    if metrics_data is not None:
        for resource_metric in metrics_data.resource_metrics:
            for scope_metric in resource_metric.scope_metrics:
                for metric in scope_metric.metrics:
                    if metric.name == metric_name:
                        return metric

    pytest.fail(f"Metric '{metric_name}' was not found")


@pytest.mark.unit
def test_record_metric_counter_happy_path(
    get_meter_reader: InMemoryMetricReader,
) -> None:
    record_metric("test.counter", 5, "counter")

    metric = get_metric(get_meter_reader, "test.counter")
    data_point = metric.data.data_points[0]

    assert metric.name == "test.counter"
    assert isinstance(data_point, NumberDataPoint)

    assert data_point.value == 5


@pytest.mark.unit
def test_record_metric_histogram_happy_path(
    get_meter_reader: InMemoryMetricReader,
) -> None:
    record_metric("test.histogram", 3.14, "histogram")

    metric = get_metric(get_meter_reader, "test.histogram")

    assert metric.name == "test.histogram"
    assert len(metric.data.data_points) == 1


@pytest.mark.unit
def test_record_metric_counter_negative_value() -> None:
    with pytest.raises(
        ValueError,
        match="Counter metrics must use a non-negative value",
    ):
        record_metric("test.counter", -1, "counter")


@pytest.mark.unit
def test_record_metric_attributes_passed_through(
    get_meter_reader: InMemoryMetricReader,
) -> None:
    record_metric(
        "test.counter",
        5,
        "counter",
        attributes={"method": "GET", "status_code": 200},
    )

    metric = get_metric(get_meter_reader, "test.counter")
    data_point = metric.data.data_points[0]
    metric_attributes = data_point.attributes

    assert metric_attributes is not None

    assert metric_attributes["method"] == "GET"
    assert metric_attributes["status_code"] == 200


@pytest.mark.unit
def test_record_metric_none_attributes_defaults_to_empty(
    get_meter_reader: InMemoryMetricReader,
) -> None:
    record_metric("test.counter.noattrs", 1, "counter")

    metric = get_metric(get_meter_reader, "test.counter.noattrs")
    data_point = metric.data.data_points[0]

    assert data_point.attributes == {}
