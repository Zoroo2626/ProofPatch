"""Persistent and query models for deterministic runs."""

from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from proofpatch.models.common import (
    RepositoryId,
    RunId,
    Sha256,
    validate_repository_id,
    validate_run_id,
    validate_utc_timestamp,
)
from proofpatch.models.events import EvidenceEvent
from proofpatch.models.state import RunState


class RunManifest(BaseModel):
    """Static, canonical identity stored in a run's ``run.json`` file."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: Literal[1] = 1
    run_id: RunId
    repository_id: RepositoryId
    repository_root: str = Field(min_length=1)
    created_at_utc: str

    @field_validator("created_at_utc")
    @classmethod
    def created_at_is_canonical_utc(cls, value: str) -> str:
        return validate_utc_timestamp(value)


class RunRecord(BaseModel):
    """A rebuildable SQLite index record for one run."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: Literal[1] = 1
    run_id: RunId
    repository_id: RepositoryId
    repository_root: str = Field(min_length=1)
    state: RunState
    created_at_utc: str
    updated_at_utc: str
    last_event_sequence: int = Field(ge=1)
    last_event_hash: Sha256
    run_relative_path: str = Field(min_length=1)

    @field_validator("created_at_utc", "updated_at_utc")
    @classmethod
    def timestamps_are_canonical_utc(cls, value: str) -> str:
        return validate_utc_timestamp(value)


class RepositoryLockRecord(BaseModel):
    """The versioned diagnostic record held inside a repository lock file."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: Literal[1] = 1
    run_id: RunId
    pid: int = Field(ge=1)
    hostname: str = Field(min_length=1, max_length=255)
    created_at_utc: str
    process_start_identity: str = Field(min_length=1, max_length=256)

    @field_validator("created_at_utc")
    @classmethod
    def created_at_is_canonical_utc(cls, value: str) -> str:
        return validate_utc_timestamp(value)


@dataclass(frozen=True, slots=True)
class RunPaths:
    """All deterministic files belonging to one run through Phase 6."""

    root: Path
    manifest: Path
    events: Path
    chain: Path
    baseline: Path
    repository: Path
    workspaces: Path
    investigation: Path
    submitted_contract: Path
    contract_sha256: Path
    investigation_not_reproduced: Path
    agent_version: Path
    reproduction_assets: Path
    patch: Path
    patch_diff: Path
    changed_files: Path
    patch_result: Path
    workflow_plan: Path
    environment_identity: Path
    attempts: Path
    verification: Path
    contract: Path
    baseline_result: Path
    baseline_protection: Path
    baseline_not_reproduced: Path
    final_result: Path
    receipt_json: Path
    receipt_markdown: Path


@dataclass(frozen=True, slots=True)
class RunStatus:
    """Verified state derived from evidence plus SQLite consistency metadata."""

    manifest: RunManifest
    state: RunState
    updated_at_utc: str
    event_count: int
    final_event_hash: str
    index_consistent: bool
    events: tuple[EvidenceEvent, ...]


def build_run_paths(data_root: Path, repository_id: str, run_id: str) -> RunPaths:
    """Build run paths exclusively from validated identifiers."""

    validated_repository_id = validate_repository_id(repository_id)
    validated_run_id = validate_run_id(run_id)
    root = data_root / "runs" / validated_repository_id / validated_run_id
    return RunPaths(
        root=root,
        manifest=root / "run.json",
        events=root / "events.jsonl",
        chain=root / "chain.sha256",
        baseline=root / "baseline",
        repository=root / "baseline" / "repository.json",
        workspaces=root / "workspaces",
        investigation=root / "investigation",
        submitted_contract=root / "investigation" / "submitted-contract.json",
        contract_sha256=root / "investigation" / "contract.sha256",
        investigation_not_reproduced=root / "investigation" / "not-reproduced.json",
        agent_version=root / "investigation" / "agent-version.json",
        reproduction_assets=root / "investigation" / "reproduction-assets",
        patch=root / "patch",
        patch_diff=root / "patch" / "patch.diff",
        changed_files=root / "patch" / "changed-files.json",
        patch_result=root / "patch" / "agent-result.json",
        workflow_plan=root / "workflow-plan.json",
        environment_identity=root / "verifier-environment.json",
        attempts=root / "attempts",
        verification=root / "verification",
        contract=root / "verification" / "contract.json",
        baseline_result=root / "baseline" / "result.json",
        baseline_protection=root / "baseline" / "protection.json",
        baseline_not_reproduced=root / "baseline" / "not-reproduced.json",
        final_result=root / "verification" / "result.json",
        receipt_json=root / "receipt.json",
        receipt_markdown=root / "receipt.md",
    )
