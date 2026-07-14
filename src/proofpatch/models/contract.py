"""Strict machine-readable failure contracts and investigation outcomes."""

import re
from pathlib import PurePosixPath
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from proofpatch.models.common import Sha256
from proofpatch.models.execution import CommandOracleSpec, OracleExpectation

ENVIRONMENT_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


class ReproductionAsset(BaseModel):
    """One declared regular file below the reproduction directory."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    path: str = Field(min_length=1, max_length=1024)
    sha256: Sha256

    @field_validator("path")
    @classmethod
    def path_is_portable_and_contained(cls, value: str) -> str:
        path = PurePosixPath(value)
        if (
            "\\" in value
            or "\0" in value
            or path.is_absolute()
            or value in {".", ".."}
            or ".." in path.parts
            or "." in path.parts
            or str(path) != value
        ):
            raise ValueError("reproduction asset path must be canonical and relative")
        return value


class FailureSignature(BaseModel):
    """The concise failure marker observed by the investigator."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    kind: str = Field(pattern=r"^[a-z][a-z0-9_-]{0,63}$")
    value: str = Field(min_length=1, max_length=4096)

    @field_validator("value")
    @classmethod
    def value_is_nul_free(cls, value: str) -> str:
        if "\0" in value:
            raise ValueError("failure signature must be NUL-free")
        return value


class ContractCommandOracle(BaseModel):
    """Executable before/after claim expressed using container paths."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    id: str = Field(pattern=r"^[a-z][a-z0-9_-]{0,63}$")
    type: Literal["command"] = "command"
    argv: tuple[str, ...] = Field(min_length=1, max_length=256)
    cwd: str = Field(default="/workspace", min_length=1, max_length=4096)
    timeout_seconds: float = Field(gt=0, le=86400)
    environment: dict[str, str] = Field(default_factory=dict)
    baseline_expectation: OracleExpectation
    fixed_expectation: OracleExpectation

    @field_validator("argv", mode="before")
    @classmethod
    def argv_array_becomes_tuple(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("argv")
    @classmethod
    def argv_is_safe(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if any(not argument or "\0" in argument for argument in value):
            raise ValueError("contract argv entries must be nonempty and NUL-free")
        if sum(len(argument.encode("utf-8")) for argument in value) > 256 * 1024:
            raise ValueError("contract argv exceeds the encoded size limit")
        return value

    @field_validator("cwd")
    @classmethod
    def cwd_stays_in_workspace(cls, value: str) -> str:
        if "\\" in value or "\0" in value:
            raise ValueError("contract cwd must be a canonical container path")
        path = PurePosixPath(value)
        workspace = PurePosixPath("/workspace")
        if (
            not path.is_absolute()
            or ".." in path.parts
            or str(path) != value
            or (path != workspace and workspace not in path.parents)
        ):
            raise ValueError("contract cwd must remain inside /workspace")
        return value

    @field_validator("environment")
    @classmethod
    def environment_is_bounded(cls, value: dict[str, str]) -> dict[str, str]:
        if len(value) > 128:
            raise ValueError("contract environment has too many entries")
        if any(ENVIRONMENT_NAME.fullmatch(name) is None for name in value):
            raise ValueError("contract environment contains an invalid name")
        if any(
            "\0" in item or "\r" in item or "\n" in item for pair in value.items() for item in pair
        ):
            raise ValueError("contract environment must be NUL-free and single-line")
        if sum(len(item.encode("utf-8")) for pair in value.items() for item in pair) > 256 * 1024:
            raise ValueError("contract environment exceeds the encoded size limit")
        return value

    @model_validator(mode="after")
    def expectations_show_a_transition(self) -> Self:
        if self.baseline_expectation == self.fixed_expectation:
            raise ValueError("baseline and fixed expectations must demonstrate a transition")
        return self

    def as_command_spec(self) -> CommandOracleSpec:
        """Convert container-path semantics to the evaluator's relative-cwd model."""

        relative = PurePosixPath(self.cwd).relative_to(PurePosixPath("/workspace"))
        cwd = "." if str(relative) == "." else relative.as_posix()
        return CommandOracleSpec(
            id=self.id,
            argv=self.argv,
            cwd=cwd,
            timeout_seconds=self.timeout_seconds,
            environment=self.environment,
            baseline_expectation=self.baseline_expectation,
            fixed_expectation=self.fixed_expectation,
        )


class FailureContract(BaseModel):
    """The only investigator-produced claim eligible for independent verification."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: Literal[1] = 1
    issue_summary: str = Field(min_length=1, max_length=4096)
    hypothesis: str = Field(min_length=1, max_length=8192)
    oracle: ContractCommandOracle
    reproduction_assets: tuple[ReproductionAsset, ...] = Field(default=(), max_length=256)
    observed_failure_signature: FailureSignature
    notes: str = Field(default="", max_length=16384)

    @field_validator("reproduction_assets", mode="before")
    @classmethod
    def asset_array_becomes_tuple(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("issue_summary", "hypothesis", "notes")
    @classmethod
    def narrative_fields_are_nul_free(cls, value: str) -> str:
        if "\0" in value:
            raise ValueError("contract narrative fields must be NUL-free")
        return value

    @model_validator(mode="after")
    def asset_paths_are_unique(self) -> Self:
        paths = [asset.path for asset in self.reproduction_assets]
        if len(paths) != len(set(paths)):
            raise ValueError("reproduction asset paths must be unique")
        return self


class NotReproducedOutcome(BaseModel):
    """A structured investigator report that never authorizes patching."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: Literal[1] = 1
    explanation: str = Field(min_length=1, max_length=8192)
    commands_attempted: tuple[tuple[str, ...], ...] = Field(default=(), max_length=128)

    @field_validator("commands_attempted", mode="before")
    @classmethod
    def commands_become_tuples(cls, value: object) -> object:
        if isinstance(value, list):
            return tuple(tuple(item) if isinstance(item, list) else item for item in value)
        return value

    @field_validator("commands_attempted")
    @classmethod
    def commands_are_safe(
        cls,
        value: tuple[tuple[str, ...], ...],
    ) -> tuple[tuple[str, ...], ...]:
        if any(not command for command in value):
            raise ValueError("attempted commands must be nonempty argument arrays")
        if any(not item or "\0" in item for command in value for item in command):
            raise ValueError("attempted command arguments must be nonempty and NUL-free")
        if any(len(command) > 256 for command in value):
            raise ValueError("attempted commands have too many arguments")
        if sum(len(item.encode("utf-8")) for command in value for item in command) > 256 * 1024:
            raise ValueError("attempted commands exceed the encoded size limit")
        return value

    @field_validator("explanation")
    @classmethod
    def explanation_is_nul_free(cls, value: str) -> str:
        if "\0" in value:
            raise ValueError("not-reproduced explanation must be NUL-free")
        return value
