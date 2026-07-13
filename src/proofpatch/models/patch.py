"""Versioned repository and patch records for the deterministic Git layer."""

from enum import StrEnum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator

from proofpatch.models.common import RepositoryId, RunId, Sha256

GitObjectId = Annotated[str, StringConstraints(pattern=r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")]


class ChangeKind(StrEnum):
    """Git change categories retained in patch metadata."""

    ADDED = "A"
    COPIED = "C"
    DELETED = "D"
    MODIFIED = "M"
    RENAMED = "R"
    TYPE_CHANGED = "T"


class RepositorySnapshot(BaseModel):
    """Immutable identity and baseline facts captured from the source repository."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: Literal[1] = 1
    repository_id: RepositoryId
    repository_root: str = Field(min_length=1)
    git_common_directory: str = Field(min_length=1)
    baseline_commit: GitObjectId
    branch: str | None = Field(default=None, max_length=1024)
    detached: bool
    remote: str | None = Field(default=None, max_length=255)
    remote_url_redacted: str | None = Field(default=None, max_length=4096)


class ChangedFile(BaseModel):
    """One safely decoded path change from NUL-delimited Git output."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    status: ChangeKind
    path: str = Field(min_length=1, max_length=4096)
    old_path: str | None = Field(default=None, min_length=1, max_length=4096)
    similarity: int | None = Field(default=None, ge=0, le=100)

    @field_validator("status", mode="before")
    @classmethod
    def json_status_becomes_enum(cls, value: object) -> object:
        if isinstance(value, str):
            return ChangeKind(value)
        return value

    @field_validator("path", "old_path")
    @classmethod
    def path_has_no_nul(cls, value: str | None) -> str | None:
        if value is not None and "\0" in value:
            raise ValueError("Git paths must not contain NUL")
        return value


class PatchRecord(BaseModel):
    """Canonical metadata binding exact patch bytes to a run and baseline."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: Literal[1] = 1
    run_id: RunId
    repository_id: RepositoryId
    baseline_commit: GitObjectId
    patch_sha256: Sha256
    patch_size_bytes: int = Field(gt=0)
    changed_files: tuple[ChangedFile, ...] = Field(min_length=1)

    @field_validator("changed_files", mode="before")
    @classmethod
    def json_array_becomes_immutable_tuple(cls, value: object) -> object:
        """Accept the JSON array representation while retaining an immutable model value."""

        if isinstance(value, list):
            return tuple(value)
        return value


class AppliedPatch(BaseModel):
    """Result returned after a verified patch is applied to its source repository."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    run_id: RunId
    branch: str = Field(min_length=1, max_length=1024)
    previous_revision: GitObjectId
    patch_sha256: Sha256
    changed_files: tuple[ChangedFile, ...] = Field(min_length=1)
