"""Tests for isolated plain and structured logging."""

import io
import json
import logging

from proofpatch.logging import configure_logging, get_logger, log_event


def test_json_logging_emits_structured_event() -> None:
    stream = io.StringIO()
    logger = configure_logging(json_output=True, stream=stream)

    log_event(
        logger,
        logging.INFO,
        "phase0.tested",
        "Foundation works",
        context={"attempt": 1, "passed": True},
    )

    payload = json.loads(stream.getvalue())
    assert payload["level"] == "info"
    assert payload["logger"] == "proofpatch"
    assert payload["message"] == "Foundation works"
    assert payload["event"] == "phase0.tested"
    assert payload["context"] == {"attempt": 1, "passed": True}
    assert payload["timestamp_utc"].endswith("Z")


def test_json_logging_includes_formatted_exception() -> None:
    stream = io.StringIO()
    logger = configure_logging(json_output=True, stream=stream)

    try:
        raise ValueError("test failure")
    except ValueError:
        logger.exception("An exception was captured")

    payload = json.loads(stream.getvalue())
    assert payload["message"] == "An exception was captured"
    assert "ValueError: test failure" in payload["exception"]


def test_plain_logging_respects_default_level() -> None:
    stream = io.StringIO()
    logger = configure_logging(stream=stream)

    logger.debug("hidden")
    logger.info("visible")

    assert "hidden" not in stream.getvalue()
    assert stream.getvalue().strip() == "INFO proofpatch visible"


def test_verbose_logging_and_component_logger() -> None:
    stream = io.StringIO()
    configure_logging(verbose=True, stream=stream)
    component_logger = get_logger("foundation")

    component_logger.debug("details")

    assert stream.getvalue().strip() == "DEBUG proofpatch.foundation details"
    assert get_logger().name == "proofpatch"


def test_reconfiguration_replaces_handlers_and_keeps_root_isolated() -> None:
    first_stream = io.StringIO()
    second_stream = io.StringIO()
    logger = configure_logging(stream=first_stream)
    root_handlers = logging.getLogger().handlers[:]

    reconfigured = configure_logging(stream=second_stream)
    reconfigured.info("only once")

    assert reconfigured is logger
    assert len(reconfigured.handlers) == 1
    assert first_stream.getvalue() == ""
    assert second_stream.getvalue().count("only once") == 1
    assert reconfigured.propagate is False
    assert logging.getLogger().handlers == root_handlers
