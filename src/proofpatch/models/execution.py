"""Strict models shared by controlled processes and deterministic command oracles."""

import re
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from proofpatch.models.common import RunId, Sha256

ENVIRONMENT_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
EXECUTION_ID = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
IMAGE_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
CONTAINER_USER = re.compile(r"^(?P<uid>[0-9]+)(?::(?P<gid>[0-9]+))?$")
DEFAULT_TMPFS_PATH = "/tmp"  # noqa: S108 - path is inside the isolated container
ALLOWED_TMPFS_PATHS = (
    DEFAULT_TMPFS_PATH,
    "/var/tmp",  # noqa: S108 - path is inside the isolated container
    "/run/proofpatch",
)
REQUIRED_PROTECTION_FACTS = frozenset(
    {
        "docker_ready",
        "immutable_image",
        "read_only_root",
        "non_root_user",
        "network_explicit",
        "no_host_network",
        "no_host_pid",
        "not_privileged",
        "automatic_removal",
        "read_only_argument",
        "capabilities_dropped",
        "no_new_privileges",
        "managed_labels",
        "finite_resource_limits",
        "hardened_tmpfs",
        "environment_allowlist",
        "phase_mount_policy",
        "investigation_workspace_read_only",
    }
)


class TerminationKind(StrEnum):
    """How a controlled process ended."""

    EXITED = "exited"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"
    SIGNAL = "signal"


class OraclePhase(StrEnum):
    """The meaning assigned to an oracle execution."""

    BASELINE = "baseline"
    FIXED = "fixed"
    REGRESSION = "regression"
    SETUP = "setup"


class ProtectionLevel(StrEnum):
    """The assurance level an execution backend can truthfully claim."""

    PROTECTED = "protected"
    OBSERVATION_ONLY = "observation_only"
    UNAVAILABLE = "unavailable"


class ExecutionPhase(StrEnum):
    """Container phases with distinct mount and network policies."""

    SETUP = "setup"
    INVESTIGATION = "investigation"
    PATCH = "patch"
    BASELINE = "baseline"
    VERIFICATION = "verification"


class NetworkPolicy(StrEnum):
    """The complete supported network policy set; host mode is unrepresentable."""

    NONE = "none"
    BRIDGE = "bridge"
    AGENT_API = "agent-api"


class MountKind(StrEnum):
    """Purpose of a host path exposed to a container."""

    WORKSPACE = "workspace"
    REPRODUCTION = "reproduction"
    OUTPUT = "output"
    DEPENDENCY_CACHE = "dependency_cache"
    SECRET = "secret"  # noqa: S105 - mount role, never a credential value
    PROMPT = "prompt"
    ISSUE = "issue"


class MountAccess(StrEnum):
    READ_ONLY = "read_only"
    READ_WRITE = "read_write"


class ResolvedImage(BaseModel):
    """A mutable image reference resolved to immutable local and registry identities."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    requested_reference: str = Field(min_length=1, max_length=1024)
    immutable_reference: str = Field(min_length=1, max_length=2048)
    digest: str = Field(pattern=IMAGE_DIGEST.pattern)
    image_id: str = Field(pattern=IMAGE_DIGEST.pattern)
    os: Literal["linux"] = "linux"
    architecture: str = Field(min_length=1, max_length=64)
    pulled: bool = False


class BackendDoctorResult(BaseModel):
    """Non-secret Docker readiness facts used by protected-mode preflight."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    docker_cli: bool
    daemon_responding: bool
    linux_containers: bool
    client_version: str | None = Field(default=None, max_length=64)
    server_version: str | None = Field(default=None, max_length=64)
    error: str | None = Field(default=None, max_length=4096)

    @property
    def healthy(self) -> bool:
        return self.docker_cli and self.daemon_responding and self.linux_containers


class DockerMount(BaseModel):
    """One typed bind mount; phase policy is enforced immediately before building argv."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    source: Path
    destination: str = Field(min_length=1, max_length=4096)
    kind: MountKind
    access: MountAccess

    @field_validator("destination")
    @classmethod
    def destination_is_canonical_absolute_posix(cls, value: str) -> str:
        if "\\" in value or "\0" in value:
            raise ValueError("mount destination must be a NUL-free POSIX path")
        path = PurePosixPath(value)
        if not path.is_absolute() or ".." in path.parts or str(path) != value:
            raise ValueError("mount destination must be a canonical absolute POSIX path")
        return value

    @field_validator("kind", mode="before")
    @classmethod
    def kind_from_json(cls, value: object) -> object:
        return MountKind(value) if isinstance(value, str) else value

    @field_validator("access", mode="before")
    @classmethod
    def access_from_json(cls, value: object) -> object:
        return MountAccess(value) if isinstance(value, str) else value


class TmpfsMount(BaseModel):
    """A bounded non-executable writable in-memory filesystem."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    path: str = Field(min_length=1, max_length=255)
    size_mb: int = Field(ge=1, le=16384)
    executable: Literal[False] = False

    @field_validator("path")
    @classmethod
    def tmpfs_path_is_safe(cls, value: str) -> str:
        path = PurePosixPath(value)
        if (
            "\\" in value
            or "\0" in value
            or not path.is_absolute()
            or ".." in path.parts
            or str(path) != value
            or value == "/"
        ):
            raise ValueError("tmpfs path must be a safe canonical absolute POSIX path")
        return value


class ResourceLimits(BaseModel):
    """Mandatory finite limits for one protected container."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    timeout_seconds: float = Field(gt=0, le=86400)
    memory_mb: int = Field(ge=64, le=1048576)
    cpus: float = Field(gt=0, le=1024)
    pids: int = Field(ge=16, le=1048576)
    output_bytes: int = Field(ge=1024, le=1024 * 1024 * 1024)


class ExecutionRequest(BaseModel):
    """A complete protected execution request with no raw Docker option escape hatch."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    execution_id: str = Field(pattern=EXECUTION_ID.pattern)
    run_id: RunId
    phase: ExecutionPhase
    image: ResolvedImage
    argv: tuple[str, ...] = Field(min_length=1, max_length=256)
    working_directory: str = "/workspace"
    user: str = "1000:1000"
    network: NetworkPolicy
    mounts: tuple[DockerMount, ...]
    environment: dict[str, str] = Field(default_factory=dict)
    environment_allowlist: tuple[str, ...] = ()
    resources: ResourceLimits
    tmpfs: tuple[TmpfsMount, ...] = Field(
        default=(TmpfsMount(path=DEFAULT_TMPFS_PATH, size_mb=1024),),
        min_length=1,
        max_length=8,
    )
    read_only_root: Literal[True] = True
    original_repository: Path
    evidence_directory: Path
    disposable_work_directory: Path | None = None

    @field_validator("phase", mode="before")
    @classmethod
    def phase_from_json(cls, value: object) -> object:
        return ExecutionPhase(value) if isinstance(value, str) else value

    @field_validator("network", mode="before")
    @classmethod
    def network_from_json(cls, value: object) -> object:
        return NetworkPolicy(value) if isinstance(value, str) else value

    @field_validator("argv", "mounts", "environment_allowlist", "tmpfs", mode="before")
    @classmethod
    def arrays_become_tuples(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("argv")
    @classmethod
    def protected_argv_is_safe(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if any(not item or "\0" in item for item in value):
            raise ValueError("execution argv entries must be nonempty and NUL-free")
        if sum(len(item.encode("utf-8")) for item in value) > 256 * 1024:
            raise ValueError("execution argv exceeds the encoded size limit")
        return value

    @field_validator("working_directory")
    @classmethod
    def working_directory_is_container_path(cls, value: str) -> str:
        path = PurePosixPath(value)
        if (
            "\\" in value
            or "\0" in value
            or not path.is_absolute()
            or ".." in path.parts
            or str(path) != value
        ):
            raise ValueError("working directory must be a canonical absolute POSIX path")
        return value

    @field_validator("user")
    @classmethod
    def user_is_non_root_numeric_identity(cls, value: str) -> str:
        match = CONTAINER_USER.fullmatch(value)
        if match is None or int(match.group("uid")) == 0:
            raise ValueError("protected execution requires a non-root numeric user")
        group = match.group("gid")
        if group is not None and int(group) == 0:
            raise ValueError("protected execution requires a non-root numeric group")
        return value

    @field_validator("environment")
    @classmethod
    def environment_is_bounded_and_valid(cls, value: dict[str, str]) -> dict[str, str]:
        if len(value) > 128 or any(ENVIRONMENT_NAME.fullmatch(name) is None for name in value):
            raise ValueError("execution environment contains invalid or excessive names")
        if any("\0" in item for pair in value.items() for item in pair):
            raise ValueError("execution environment must be NUL-free")
        if sum(len(item.encode("utf-8")) for pair in value.items() for item in pair) > 256 * 1024:
            raise ValueError("execution environment exceeds the encoded size limit")
        return value

    @field_validator("environment_allowlist")
    @classmethod
    def allowlist_is_valid(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("environment allowlist contains duplicates")
        if any(ENVIRONMENT_NAME.fullmatch(name) is None for name in value):
            raise ValueError("environment allowlist contains an invalid name")
        return value

    @model_validator(mode="after")
    def protected_policy_is_coherent(self) -> Self:
        unexpected = set(self.environment).difference(self.environment_allowlist)
        if unexpected:
            raise ValueError(
                "environment contains non-allowlisted variables: " + ", ".join(sorted(unexpected))
            )
        if self.phase in {ExecutionPhase.BASELINE, ExecutionPhase.VERIFICATION} and (
            self.network is not NetworkPolicy.NONE
        ):
            raise ValueError("baseline and verification containers require network none")
        tmpfs_paths = tuple(PurePosixPath(item.path) for item in self.tmpfs)
        if len(tmpfs_paths) != len(set(tmpfs_paths)):
            raise ValueError("tmpfs paths must be unique")
        allowed_tmpfs = {PurePosixPath(item) for item in ALLOWED_TMPFS_PATHS}
        if any(path not in allowed_tmpfs for path in tmpfs_paths):
            raise ValueError("tmpfs is permitted only at approved ephemeral paths")
        mount_destinations = tuple(PurePosixPath(item.destination) for item in self.mounts)
        if any(
            tmpfs == destination or tmpfs in destination.parents or destination in tmpfs.parents
            for tmpfs in tmpfs_paths
            for destination in mount_destinations
        ):
            raise ValueError("tmpfs paths must not overlap bind mount destinations")
        return self


class ProtectionAssessment(BaseModel):
    """Auditable reasons behind an execution's protection claim."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    level: ProtectionLevel
    satisfied: tuple[str, ...]
    failures: tuple[str, ...]

    @field_validator("level", mode="before")
    @classmethod
    def level_from_json(cls, value: object) -> object:
        return ProtectionLevel(value) if isinstance(value, str) else value

    @field_validator("satisfied", "failures", mode="before")
    @classmethod
    def fact_arrays_become_tuples(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def claim_matches_complete_fact_set(self) -> Self:
        satisfied = set(self.satisfied)
        failures = set(self.failures)
        if len(satisfied) != len(self.satisfied) or len(failures) != len(self.failures):
            raise ValueError("protection assessment facts must be unique")
        if satisfied.intersection(failures):
            raise ValueError("protection facts cannot be both satisfied and failed")
        if not satisfied.union(failures).issubset(REQUIRED_PROTECTION_FACTS):
            raise ValueError("protection assessment contains an unknown fact")
        if self.level is ProtectionLevel.PROTECTED and (
            failures or not REQUIRED_PROTECTION_FACTS.issubset(satisfied)
        ):
            raise ValueError("protected level requires every mandatory protection fact")
        if self.level is ProtectionLevel.UNAVAILABLE and not failures:
            raise ValueError("unavailable protection assessment must identify a failure")
        if self.level is ProtectionLevel.OBSERVATION_ONLY and (satisfied or failures):
            raise ValueError("observation-only assessments do not claim Docker protection facts")
        return self


@dataclass(frozen=True, slots=True)
class ExecutionResult:
    """Bounded output and cleanup facts returned by an execution backend."""

    execution_id: str
    container_name: str
    redacted_command: tuple[str, ...]
    outcome: object
    protection: ProtectionAssessment
    cleanup_confirmed: bool


class ExitCodeOperator(StrEnum):
    EQUAL = "equal"
    NOT_EQUAL = "not_equal"


class TextOperator(StrEnum):
    CONTAINS = "contains"
    NOT_CONTAINS = "not_contains"
    REGEX = "regex"
    NOT_REGEX = "not_regex"


class ExitCodeMatcherSpec(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    operator: ExitCodeOperator
    value: int

    @field_validator("operator", mode="before")
    @classmethod
    def operator_from_json(cls, value: object) -> object:
        return ExitCodeOperator(value) if isinstance(value, str) else value


class TextMatcherSpec(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    operator: TextOperator
    value: str = Field(min_length=1, max_length=4096)
    multiline: bool = False

    @field_validator("operator", mode="before")
    @classmethod
    def operator_from_json(cls, value: object) -> object:
        return TextOperator(value) if isinstance(value, str) else value


class OracleExpectation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    exit_code: ExitCodeMatcherSpec
    stdout: tuple[TextMatcherSpec, ...] = Field(default=(), max_length=128)
    stderr: tuple[TextMatcherSpec, ...] = Field(default=(), max_length=128)

    @field_validator("stdout", "stderr", mode="before")
    @classmethod
    def arrays_become_tuples(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value


class CommandOracleSpec(BaseModel):
    """A shell-free command and phase-specific deterministic expectations."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: Literal[1] = 1
    id: str = Field(pattern=r"^[a-z][a-z0-9_-]{0,63}$")
    type: Literal["command"] = "command"
    argv: tuple[str, ...] = Field(min_length=1, max_length=256)
    cwd: str = Field(default=".", min_length=1, max_length=4096)
    timeout_seconds: float = Field(gt=0, le=86400)
    environment: dict[str, str] = Field(default_factory=dict)
    stdin: str | None = Field(default=None, max_length=256 * 1024)
    baseline_expectation: OracleExpectation | None = None
    fixed_expectation: OracleExpectation | None = None
    expectation: OracleExpectation | None = None

    @field_validator("argv", mode="before")
    @classmethod
    def argv_array_becomes_tuple(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("argv")
    @classmethod
    def argv_is_safe(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if any(not argument or "\0" in argument for argument in value):
            raise ValueError("oracle argv entries must be nonempty and NUL-free")
        if sum(len(argument.encode("utf-8")) for argument in value) > 256 * 1024:
            raise ValueError("oracle argv exceeds the encoded size limit")
        return value

    @field_validator("cwd")
    @classmethod
    def cwd_stays_in_workspace(cls, value: str) -> str:
        if "\\" in value:
            raise ValueError("oracle cwd must use portable forward slashes")
        path = PurePosixPath(value)
        if path.is_absolute() or ".." in path.parts:
            raise ValueError("oracle cwd must remain inside the workspace")
        return value

    @field_validator("environment")
    @classmethod
    def environment_names_are_safe(cls, value: dict[str, str]) -> dict[str, str]:
        if len(value) > 128:
            raise ValueError("oracle environment has too many entries")
        if any(ENVIRONMENT_NAME.fullmatch(name) is None for name in value):
            raise ValueError("oracle environment contains an invalid variable name")
        if any("\0" in item for pair in value.items() for item in pair):
            raise ValueError("oracle environment must be NUL-free")
        if sum(len(item.encode("utf-8")) for pair in value.items() for item in pair) > 256 * 1024:
            raise ValueError("oracle environment exceeds the encoded size limit")
        return value

    @model_validator(mode="after")
    def expectation_shape_is_unambiguous(self) -> Self:
        reproduction = self.baseline_expectation is not None or self.fixed_expectation is not None
        if reproduction and (
            self.baseline_expectation is None
            or self.fixed_expectation is None
            or self.expectation is not None
        ):
            raise ValueError("reproduction oracles require baseline and fixed expectations only")
        if not reproduction and self.expectation is None:
            raise ValueError("regression oracles require an expectation")
        if (
            reproduction
            and self.baseline_expectation is not None
            and self.baseline_expectation == self.fixed_expectation
        ):
            raise ValueError("baseline and fixed expectations must demonstrate a transition")
        return self


class MatcherResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    field: Literal["exit_code", "stdout", "stderr"]
    operator: str
    expected: int | str
    actual: int | str | None
    passed: bool


class ProcessRecord(BaseModel):
    """Persistable process facts with redacted log hashes instead of raw output."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    termination: TerminationKind
    exit_code: int | None
    signal: int | None = Field(default=None, ge=1)
    duration_ms: int = Field(ge=0)
    timed_out: bool
    cancelled: bool
    stdout_path: str = Field(min_length=1)
    stdout_sha256: Sha256
    stdout_bytes: int = Field(ge=0)
    stderr_path: str = Field(min_length=1)
    stderr_sha256: Sha256
    stderr_bytes: int = Field(ge=0)
    truncated: bool

    @field_validator("termination", mode="before")
    @classmethod
    def termination_from_json(cls, value: object) -> object:
        return TerminationKind(value) if isinstance(value, str) else value


class OracleEvaluation(BaseModel):
    """Canonical result of one independently evaluated command oracle."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    oracle_id: str = Field(pattern=r"^[a-z][a-z0-9_-]{0,63}$")
    phase: OraclePhase
    passed: bool
    process: ProcessRecord
    matcher_results: tuple[MatcherResult, ...]
    failure_code: str | None = None

    @field_validator("phase", mode="before")
    @classmethod
    def phase_from_json(cls, value: object) -> object:
        return OraclePhase(value) if isinstance(value, str) else value

    @field_validator("matcher_results", mode="before")
    @classmethod
    def matcher_array_becomes_tuple(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value
