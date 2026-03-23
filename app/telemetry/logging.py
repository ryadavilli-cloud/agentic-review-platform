import json
import logging
from contextvars import ContextVar
from datetime import UTC, datetime

correlation_id_var: ContextVar[str] = ContextVar(
    "correlation_id", default="no_correlation_id"
)


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        log_dict: dict[str, str | int] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "logger": record.name,
            "level": record.levelname,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
            "correlation_id": correlation_id_var.get(),
        }

        if record.exc_info:
            log_dict["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_dict)


def setup_logging(log_level: str) -> None:
    logger = logging.getLogger()
    logger.setLevel(getattr(logging, log_level.upper()))
    logger.handlers.clear()  # Clear existing handlers
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    logger.addHandler(handler)
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("uvicorn.error").setLevel(logging.WARNING)
    logging.getLogger("opentelemetry").setLevel(logging.WARNING)
