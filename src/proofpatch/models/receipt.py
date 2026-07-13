"""Versioned receipts that state only independently observed Phase 3 results."""

from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from proofpatch.models.common import RepositoryId, RunId, Sha256, validate_utc_timestamp
from proofpatch.models.execution import OracleEvaluation, ProtectionAssessment, ProtectionLevel
from proofpatch.models.patch import GitObjectId


class ReceiptAttempt(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    attempt: int = Field(ge=1, le=100)
    status: Literal["verified", "rejected"]
    patch_sha256: Sha256
    fingerprint_sha256: Sha256
    changed_paths: tuple[str, ...] = Field(min_length=1)
    warning_codes: tuple[str, ...] = ()
    rejection_code: str | None = Field(default=None, min_length=1, max_length=128)

    @field_validator("changed_paths", "warning_codes", mode="before")
    @classmethod
    def arrays_become_tuples(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value


class ReceiptProject(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    name: str = Field(min_length=1, max_length=255)
    repository_id: RepositoryId
    baseline_commit: GitObjectId


class ReceiptContract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    id: str = Field(min_length=1, max_length=64)
    sha256: Sha256


class ReceiptBaseline(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    failure_reproduced: bool
    exit_code: int | None
    duration_ms: int = Field(ge=0)


class ReceiptPatch(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    sha256: Sha256
    changed_files: int = Field(gt=0)


class ReceiptVerification(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    reproduction_transition_passed: bool
    regressions_passed: bool
    oracles: tuple[OracleEvaluation, ...]

    @field_validator("oracles", mode="before")
    @classmethod
    def oracle_array_becomes_tuple(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value


class ReceiptEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    decision_chain_hash: Sha256


class VerificationReceipt(BaseModel):
    """Canonical receipt whose protection claim must be backed by an assessment."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: Literal[1] = 1
    proofpatch_version: str = Field(min_length=1)
    run_id: RunId
    status: Literal["verified", "rejected"]
    protection_level: ProtectionLevel = ProtectionLevel.OBSERVATION_ONLY
    backend: Literal["native", "docker"] = "native"
    protection_assessment: ProtectionAssessment | None = None
    created_at_utc: str
    completed_at_utc: str
    project: ReceiptProject
    issue_summary: str = Field(min_length=1, max_length=4096)
    contract: ReceiptContract
    baseline: ReceiptBaseline
    patch: ReceiptPatch | None
    verification: ReceiptVerification
    evidence: ReceiptEvidence
    rejection_code: str | None = None
    attempts: tuple[ReceiptAttempt, ...] = ()

    @field_validator("created_at_utc", "completed_at_utc")
    @classmethod
    def timestamps_are_canonical(cls, value: str) -> str:
        return validate_utc_timestamp(value)

    @field_validator("protection_level", mode="before")
    @classmethod
    def protection_level_from_json(cls, value: object) -> object:
        return ProtectionLevel(value) if isinstance(value, str) else value

    @field_validator("attempts", mode="before")
    @classmethod
    def attempt_array_becomes_tuple(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def protection_claim_has_enforced_facts(self) -> Self:
        if self.protection_level is ProtectionLevel.UNAVAILABLE:
            raise ValueError("receipts cannot use unavailable as a protection level")
        if self.protection_level is ProtectionLevel.PROTECTED:
            if (
                self.backend != "docker"
                or self.protection_assessment is None
                or self.protection_assessment.level is not ProtectionLevel.PROTECTED
                or self.protection_assessment.failures
            ):
                raise ValueError(
                    "protected receipts require a successful Docker protection assessment"
                )
        elif self.backend == "docker":
            raise ValueError("Docker receipts must not make an observation-only claim")
        return self
