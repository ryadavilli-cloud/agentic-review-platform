from azure.monitor.opentelemetry.exporter import AzureMonitorMetricExporter
from opentelemetry import metrics
from opentelemetry.metrics import Meter
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import (
    ConsoleMetricExporter,
    MetricExporter,
    PeriodicExportingMetricReader,
)
from opentelemetry.sdk.resources import Resource

from app.config import Settings


def setup_metrics(settings: Settings) -> MeterProvider:

    resource = Resource.create(
        attributes={
            "service.name": settings.app_name,
            "service.version": settings.app_version,
        }
    )

    exporter: MetricExporter = ConsoleMetricExporter()

    if (settings.environment == "development") or settings.debug:
        # In development, use a simple console exporter for easier debugging

        exporter = ConsoleMetricExporter()
    else:
        # Set up the Azure Monitor exporter
        exporter = AzureMonitorMetricExporter.from_connection_string(
            settings.applicationinsights_connection_string
        )

    reader = PeriodicExportingMetricReader(
        exporter,
        export_interval_millis=5000,
    )

    provider = MeterProvider(
        resource=resource,
        metric_readers=[reader],
    )

    metrics.set_meter_provider(provider)
    return provider


def get_meter(name: str) -> Meter:
    return metrics.get_meter(name)
