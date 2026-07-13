"""Versioned models for append-only evidence events."""

from typing import Annotated, Literal, Self

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

from proofpatch.models.common import (
    EVENT_ID_PATTERN,
    JsonValue,
    RunId,
    Sha256,
    validate_json_value,
    validate_utc_timestamp,
)

EventId = Annotated[str, StringConstraints(pattern=EVENT_ID_PATTERN.pattern)]
EventType = Annotated[
    str,
    StringConstraints(pattern=r"^[a-z][a-z0-9_.-]{0,127}$"),
]
Actor = Annotated[str, StringConstraints(min_length=1, max_length=64)]


class EvidenceEvent(BaseModel):
    """One canonical record in a run's authoritative hash chain."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: Literal[1] = 1
    sequence: int = Field(ge=1)
    event_id: EventId
    run_id: RunId
    timestamp_utc: str
    type: EventType
    actor: Actor
    payload: dict[str, JsonValue] = Field(default_factory=dict)
    previous_hash: Sha256 | None
    event_hash: Sha256

    @field_validator("timestamp_utc")
    @classmethod
    def timestamp_is_canonical_utc(cls, value: str) -> str:
        return validate_utc_timestamp(value)

    @field_validator("payload")
    @classmethod
    def payload_is_canonical_json(cls, value: dict[str, JsonValue]) -> dict[str, JsonValue]:
        validate_json_value(value)
        return value

    @model_validator(mode="after")
    def event_id_matches_sequence(self) -> Self:
        expected = f"evt_{self.sequence:06d}"
        if self.event_id != expected:
            raise ValueError(f"event_id must be {expected}")
        return self
