"""Structured, application-scoped logging configuration."""

import json
import logging as stdlib_logging
import sys
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import TextIO

from proofpatch.constants import LOGGER_NAME

LogValue = str | int | float | bool | None


class JsonLogFormatter(stdlib_logging.Formatter):
    """Render one compact JSON object per log record."""

    def format(self, record: stdlib_logging.LogRecord) -> str:
        timestamp = datetime.fromtimestamp(record.created, tz=UTC)
        payload: dict[str, object] = {
            "timestamp_utc": timestamp.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "level": record.levelname.lower(),
            "logger": record.name,
            "message": record.getMessage(),
        }

        event = getattr(record, "event", None)
        if isinstance(event, str):
            payload["event"] = event

        context = getattr(record, "context", None)
        if isinstance(context, Mapping):
            payload["context"] = dict(context)

        if record.exc_info is not None:
            payload["exception"] = self.formatException(record.exc_info)

        return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def configure_logging(
    *,
    verbose: bool = False,
    json_output: bool = False,
    stream: TextIO | None = None,
) -> stdlib_logging.Logger:
    """Configure and return the isolated ProofPatch logger.

    Repeated calls replace ProofPatch's own handlers so tests and CLI entry
    points can configure logging idempotently without altering the root logger.
    """

    logger = stdlib_logging.getLogger(LOGGER_NAME)
    for existing_handler in logger.handlers[:]:
        logger.removeHandler(existing_handler)
        existing_handler.close()
    logger.setLevel(stdlib_logging.DEBUG if verbose else stdlib_logging.INFO)
    logger.disabled = False
    logger.propagate = False

    handler = stdlib_logging.StreamHandler(stream if stream is not None else sys.stderr)
    handler.setLevel(logger.level)
    if json_output:
        handler.setFormatter(JsonLogFormatter())
    else:
        handler.setFormatter(stdlib_logging.Formatter("%(levelname)s %(name)s %(message)s"))
    logger.addHandler(handler)
    return logger


def get_logger(component: str | None = None) -> stdlib_logging.Logger:
    """Return the application logger or one of its component children."""

    if component is None:
        return stdlib_logging.getLogger(LOGGER_NAME)
    return stdlib_logging.getLogger(f"{LOGGER_NAME}.{component}")


def log_event(
    logger: stdlib_logging.Logger,
    level: int,
    event: str,
    message: str,
    *,
    context: Mapping[str, LogValue] | None = None,
) -> None:
    """Write a structured internal event without coupling logs to evidence."""

    logger.log(
        level,
        message,
        extra={"event": event, "context": dict(context or {})},
    )
