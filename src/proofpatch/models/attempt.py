"""Immutable deterministic patch-analysis and attempt records."""

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from proofpatch.models.common import Sha256, validate_utc_timestamp
from proofpatch.models.patch import ChangeKind


class AttemptStatus(StrEnum):
    VERIFIED = "verified"
    REJECTED = "rejected"


class FingerprintPath(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    path: str = Field(min_length=1, max_length=4096)
    old_path: str | None = Field(default=None, min_length=1, max_length=4096)
    status: ChangeKind
    added_line_hashes: tuple[Sha256, ...] = ()
    removed_line_hashes: tuple[Sha256, ...] = ()

    @field_validator("status", mode="before")
    @classmethod
    def status_from_json(cls, value: object) -> object:
        return ChangeKind(value) if isinstance(value, str) else value

    @field_validator("added_line_hashes", "removed_line_hashes", mode="before")
    @classmethod
    def arrays_become_tuples(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value


class PatchFingerprint(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: Literal[1] = 1
    sha256: Sha256
    failure_signature_sha256: Sha256
    paths: tuple[FingerprintPath, ...] = Field(min_length=1)

    @field_validator("paths", mode="before")
    @classmethod
    def paths_become_tuple(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value


class SimilarityWarning(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    code: Literal[
        "PP_PATCH_EXACT_REPEAT",
        "PP_PATCH_HIGH_OVERLAP",
        "PP_HYPOTHESIS_REPEAT",
    ]
    prior_attempt: int = Field(ge=1, le=100)
    path_overlap: float = Field(ge=0, le=1)
    line_overlap: float = Field(ge=0, le=1)
    message: str = Field(min_length=1, max_length=512)


class AttemptRecord(BaseModel):
    """One append-only completed patch attempt."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: Literal[1] = 1
    attempt: int = Field(ge=1, le=100)
    status: AttemptStatus
    started_at_utc: str
    completed_at_utc: str
    patch_sha256: Sha256
    fingerprint: PatchFingerprint
    hypothesis_sha256: Sha256
    changed_paths: tuple[str, ...] = Field(min_length=1)
    warnings: tuple[SimilarityWarning, ...] = ()
    rejection_code: str | None = Field(default=None, min_length=1, max_length=128)
    reproduction_transition_passed: bool
    regressions_passed: bool

    @field_validator("status", mode="before")
    @classmethod
    def status_from_json(cls, value: object) -> object:
        return AttemptStatus(value) if isinstance(value, str) else value

    @field_validator("started_at_utc", "completed_at_utc")
    @classmethod
    def timestamps_are_canonical(cls, value: str) -> str:
        return validate_utc_timestamp(value)

    @field_validator("changed_paths", "warnings", mode="before")
    @classmethod
    def arrays_become_tuples(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("changed_paths")
    @classmethod
    def paths_are_safe(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)) or any(not path or "\0" in path for path in value):
            raise ValueError("attempt changed paths must be unique, nonempty, and NUL-free")
        return value
