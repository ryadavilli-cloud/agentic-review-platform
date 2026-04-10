import uuid
from collections.abc import Awaitable, Callable
from time import perf_counter

from fastapi import Request, Response

from app.telemetry.helpers import MetricAttributes, record_metric
from app.telemetry.logging import correlation_id_var


async def correlation_id_middleware(
    request: Request, call_next: Callable[[Request], Awaitable[Response]]
) -> Response:
    correlation_id = request.headers.get("X-Correlation-ID", str(uuid.uuid4()))
    token = correlation_id_var.set(correlation_id)

    time_start = perf_counter()
    response = await call_next(request)
    elapsed = perf_counter() - time_start
    attributes: MetricAttributes = {
        "http.method": request.method,
        "http.route": request.url.path,
        "http.status_code": response.status_code,
    }
    record_metric(
        "http.server.request.duration",
        elapsed,
        "histogram",
        attributes=attributes,
    )

    record_metric("http.server.request.count", 1, "counter", attributes=attributes)

    response.headers["X-Correlation-ID"] = correlation_id
    correlation_id_var.reset(token)
    return response
