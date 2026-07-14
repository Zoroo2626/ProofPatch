"""Evidence-bound inputs for protected verifier environment equivalence."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from proofpatch.models.common import Sha256
from proofpatch.models.patch import GitObjectId


class DependencyLockfileHash(BaseModel):
    """A tracked dependency input captured from the baseline Git tree."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    path: str = Field(min_length=1, max_length=4096)
    sha256: Sha256


class VerifierNetworkIdentity(BaseModel):
    """Network policy enforced for every protected verifier phase."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    setup: Literal["unsupported"] = "unsupported"
    baseline: Literal["none"] = "none"
    verification: Literal["none"] = "none"


class VerifierEnvironmentIdentity(BaseModel):
    """Noncircular hash binding for the exact protected verifier inputs."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: Literal[1] = 1
    base_image_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    base_image_id: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    immutable_image_reference: str = Field(min_length=1, max_length=2048)
    platform: Literal["linux/amd64"] = "linux/amd64"
    architecture: Literal["amd64"] = "amd64"
    baseline_commit: GitObjectId
    prepared_environment_sha256: Sha256
    setup_configuration_sha256: Sha256
    dependency_lockfiles: tuple[DependencyLockfileHash, ...] = ()
    deterministic_environment: dict[str, str]
    oracle_configuration_sha256: Sha256
    network: VerifierNetworkIdentity = VerifierNetworkIdentity()
    scratch_policy: Literal["fresh_container_tmpfs"] = "fresh_container_tmpfs"
    source_mount_policy: Literal["read_only"] = "read_only"
    environment_inputs_sha256: Sha256

    @field_validator("dependency_lockfiles", mode="before")
    @classmethod
    def lockfile_array_becomes_tuple(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value
