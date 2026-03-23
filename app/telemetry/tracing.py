from azure.monitor.opentelemetry.exporter import AzureMonitorTraceExporter
from opentelemetry import trace
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import SpanProcessor, TracerProvider
from opentelemetry.sdk.trace.export import (
    BatchSpanProcessor,
    ConsoleSpanExporter,
    SimpleSpanProcessor,
    SpanExporter,
)

from app.config import Settings


def setup_tracing(settings: Settings) -> TracerProvider:
    # Set up the tracer provider with resource attributes
    resource = Resource(
        attributes={
            "service.name": settings.app_name,
            "service.version": settings.app_version,
        }
    )

    provider = TracerProvider(resource=resource)
    trace.set_tracer_provider(provider)

    exporter: SpanExporter
    span_processor: SpanProcessor

    if (settings.environment == "development") or settings.debug:
        # In development, use a simple console exporter for easier debugging

        exporter = ConsoleSpanExporter()
        span_processor = SimpleSpanProcessor(exporter)
    else:
        # Set up the Azure Monitor exporter
        exporter = AzureMonitorTraceExporter.from_connection_string(
            settings.applicationinsights_connection_string
        )
        span_processor = BatchSpanProcessor(exporter)

    # Add the exporter to the tracer provider
    provider.add_span_processor(span_processor)

    return provider


def get_tracer(name: str) -> trace.Tracer:
    return trace.get_tracer(name)
