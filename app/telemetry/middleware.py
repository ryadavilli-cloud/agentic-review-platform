import uuid
from collections.abc import Awaitable, Callable

from fastapi import Request, Response

from app.telemetry.logging import correlation_id_var


async def correlation_id_middleware(
    request: Request, call_next: Callable[[Request], Awaitable[Response]]
) -> Response:
    correlation_id = request.headers.get("X-Correlation-ID", str(uuid.uuid4()))
    token = correlation_id_var.set(correlation_id)
    response = await call_next(request)
    response.headers["X-Correlation-ID"] = correlation_id
    correlation_id_var.reset(token)
    return response
