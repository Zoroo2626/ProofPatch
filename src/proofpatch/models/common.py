"""Shared validation primitives for persistent Phase 1 records."""

import math
import re
from datetime import UTC, datetime
from typing import Annotated

from pydantic import StringConstraints

RUN_ID_PATTERN = re.compile(r"^pp_\d{8}_[0-9a-f]{12}$")
REPOSITORY_ID_PATTERN = re.compile(r"^repo_[0-9a-f]{16}$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
EVENT_ID_PATTERN = re.compile(r"^evt_\d{6,}$")
UTC_TIMESTAMP_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")

RunId = Annotated[str, StringConstraints(pattern=RUN_ID_PATTERN.pattern)]
RepositoryId = Annotated[str, StringConstraints(pattern=REPOSITORY_ID_PATTERN.pattern)]
Sha256 = Annotated[str, StringConstraints(pattern=SHA256_PATTERN.pattern)]

type JsonValue = None | bool | int | float | str | list[JsonValue] | dict[str, JsonValue]


def validate_run_id(value: str) -> str:
    """Return a valid run ID or raise ``ValueError``."""

    if RUN_ID_PATTERN.fullmatch(value) is None:
        raise ValueError("invalid ProofPatch run ID")
    return value


def validate_repository_id(value: str) -> str:
    """Return a valid repository ID or raise ``ValueError``."""

    if REPOSITORY_ID_PATTERN.fullmatch(value) is None:
        raise ValueError("invalid ProofPatch repository ID")
    return value


def validate_utc_timestamp(value: str) -> str:
    """Validate the exact UTC RFC 3339 representation used in evidence."""

    if UTC_TIMESTAMP_PATTERN.fullmatch(value) is None:
        raise ValueError("timestamp must be UTC RFC 3339 with six fractional digits")
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)
    except ValueError as error:
        raise ValueError("timestamp is not a valid UTC date and time") from error
    return value


def format_utc_timestamp(value: datetime | None = None) -> str:
    """Format an aware time as the canonical UTC timestamp."""

    current = datetime.now(UTC) if value is None else value
    if current.tzinfo is None or current.utcoffset() is None:
        raise ValueError("timestamp must be timezone-aware")
    return current.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def validate_json_value(value: JsonValue) -> JsonValue:
    """Reject values that canonical JSON cannot represent deterministically."""

    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError("non-finite floating-point values are not valid canonical JSON")
    if isinstance(value, list):
        for item in value:
            validate_json_value(item)
    elif isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError("canonical JSON object keys must be strings")
            validate_json_value(item)
    return value
