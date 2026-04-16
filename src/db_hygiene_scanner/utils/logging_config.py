"""
Structured logging configuration for db-hygiene-scanner.

Provides pre-configured loggers using structlog with:
- Colored console output in development mode
- JSON output in production mode
- Automatic sensitive data filtering
- Request ID tracing for AI API calls
"""

import os
import re
import uuid
from typing import Any

import structlog


# Sensitive patterns to filter from logs
_SENSITIVE_PATTERNS = [
    re.compile(r"(?i)(api[_-]?key|apikey|access[_-]?key)\s*[=:]\s*['\"]?([a-zA-Z0-9\-_.]+)['\"]?"),
    re.compile(r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"]?([^'\";]+)['\"]?"),
    re.compile(r"(?i)(token)\s*[=:]\s*['\"]?([a-zA-Z0-9\-_.]+)['\"]?"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
]


def _filter_sensitive_data(_logger: Any, _method_name: str, event_dict: dict[str, Any]) -> dict[str, Any]:
    """Filter sensitive information from log entries."""
    for key, value in list(event_dict.items()):
        if isinstance(value, str):
            for pattern in _SENSITIVE_PATTERNS:
                value = pattern.sub("***REDACTED***", value)
            event_dict[key] = value
    return event_dict


def _add_timestamp(_logger: Any, _method_name: str, event_dict: dict[str, Any]) -> dict[str, Any]:
    """Add UTC ISO 8601 timestamp to log entries."""
    from datetime import datetime, timezone

    event_dict["timestamp"] = datetime.now(timezone.utc).isoformat()
    return event_dict


def configure_logging(log_level: str = "INFO") -> None:
    """Configure structlog for the application.

    Args:
        log_level: Logging verbosity (DEBUG, INFO, WARNING, ERROR).
    """
    import logging

    logging.basicConfig(format="%(message)s", level=getattr(logging, log_level, logging.INFO))

    shared_processors: list[Any] = [
        structlog.stdlib.add_log_level,
        _add_timestamp,
        _filter_sensitive_data,
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]

    if log_level == "DEBUG":
        renderer: Any = structlog.dev.ConsoleRenderer(colors=True)
    else:
        renderer = structlog.processors.JSONRenderer()

    structlog.configure(
        processors=[
            *shared_processors,
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )


class RequestIDMiddleware:
    """Middleware that attaches a request_id to all log records for tracing.

    Useful for tracing a single scan or fix operation across
    multiple files and API calls.
    """

    def __init__(self, request_id: str | None = None) -> None:
        self.request_id = request_id or str(uuid.uuid4())

    def bind_to_logger(self, log: structlog.BoundLogger) -> structlog.BoundLogger:
        """Bind the request_id to a logger instance."""
        return log.bind(request_id=self.request_id)


def get_logger(name: str) -> structlog.BoundLogger:
    """Get a pre-configured logger for use throughout the application.

    Args:
        name: Logger name, typically __name__ of the calling module.

    Returns:
        A configured structlog BoundLogger.
    """
    log_level = os.getenv("LOG_LEVEL", "INFO")
    configure_logging(log_level)
    return structlog.get_logger(logger_name=name)
