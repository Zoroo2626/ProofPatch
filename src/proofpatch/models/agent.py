"""Strict, informational output models for untrusted patch agents."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from proofpatch.models.common import Sha256


class AgentVersionMetadata(BaseModel):
    """Controller-observed provider CLI identity; never a verification input."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: Literal[1] = 1
    adapter: str = Field(min_length=1, max_length=32, pattern=r"^[a-z][a-z0-9_-]*$")
    adapter_version: int = Field(ge=1)
    agent_cli_version: str = Field(min_length=1, max_length=64)
    minimum_cli_version: str = Field(min_length=1, max_length=64)
    agent_model: str = Field(min_length=1, max_length=256)
    stdout_sha256: Sha256
    stderr_sha256: Sha256


class PatchResult(BaseModel):
    """Agent-authored notes that never determine whether a patch is accepted."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: Literal[1] = 1
    summary: str = Field(min_length=1, max_length=8192)
    root_cause: str = Field(min_length=1, max_length=8192)
    changed_files: tuple[str, ...] = Field(max_length=1024)
    commands_run: tuple[tuple[str, ...], ...] = Field(max_length=256)
    known_risks: tuple[str, ...] = Field(max_length=256)

    @field_validator("changed_files", "known_risks", mode="before")
    @classmethod
    def arrays_become_tuples(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("commands_run", mode="before")
    @classmethod
    def commands_become_tuples(cls, value: object) -> object:
        if isinstance(value, list):
            return tuple(tuple(item) if isinstance(item, list) else item for item in value)
        return value

    @field_validator("summary", "root_cause")
    @classmethod
    def narratives_are_safe(cls, value: str) -> str:
        if "\0" in value:
            raise ValueError("patch result narratives must be NUL-free")
        return value

    @field_validator("changed_files", "known_risks")
    @classmethod
    def string_arrays_are_bounded(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if any(not item or len(item) > 4096 or "\0" in item for item in value):
            raise ValueError("patch result string arrays contain an invalid value")
        return value

    @field_validator("commands_run")
    @classmethod
    def commands_are_safe(
        cls,
        value: tuple[tuple[str, ...], ...],
    ) -> tuple[tuple[str, ...], ...]:
        if any(not command or len(command) > 256 for command in value):
            raise ValueError("patch result commands must be bounded nonempty argv arrays")
        if any(not item or "\0" in item for command in value for item in command):
            raise ValueError("patch result command arguments must be nonempty and NUL-free")
        return value
