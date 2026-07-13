"""Strict Phase 6 repository configuration models."""

from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator
from yaml.tokens import AliasToken, AnchorToken

from proofpatch.errors import ConfigurationError, PatchError
from proofpatch.models.execution import ENVIRONMENT_NAME


class _UniqueKeySafeLoader(yaml.SafeLoader):
    """Safe YAML loader that rejects duplicate mapping keys."""


def _construct_unique_mapping(
    loader: _UniqueKeySafeLoader,
    node: yaml.nodes.MappingNode,
    deep: bool = False,
) -> dict[object, object]:
    loader.flatten_mapping(node)
    result: dict[object, object] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in result
        except TypeError as error:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                "mapping key is not hashable",
                key_node.start_mark,
            ) from error
        if duplicate:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"duplicate mapping key: {key}",
                key_node.start_mark,
            )
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_UniqueKeySafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


class StrictConfigModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class ProjectConfig(StrictConfigModel):
    name: str = Field(min_length=1, max_length=255)


class RepositoryConfig(StrictConfigModel):
    require_clean: Literal[True] = True
    allow_submodules: Literal[False] = False
    allow_git_lfs: Literal[False] = False
    maximum_size_mb: int = Field(default=2048, ge=1, le=1048576)
    allowed_patch_paths: tuple[str, ...] = ("**",)
    denied_patch_paths: tuple[str, ...] = (".git/**", ".proofpatch/**", "proofpatch.yml")
    maximum_changed_files: int = Field(default=100, ge=1, le=100)
    maximum_patch_size_mb: int = Field(default=20, ge=1, le=1024)

    @field_validator("allowed_patch_paths", "denied_patch_paths", mode="before")
    @classmethod
    def arrays_become_tuples(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def git_metadata_is_always_denied(self) -> "RepositoryConfig":
        if not any(value in {".git", ".git/**"} for value in self.denied_patch_paths):
            raise ValueError("denied_patch_paths must include .git/**")
        from proofpatch.git.diff import validate_patch_policy_patterns

        try:
            validate_patch_policy_patterns(self.allowed_patch_paths, self.denied_patch_paths)
        except PatchError as error:
            raise ValueError(str(error)) from error
        return self


class RuntimeLimitsConfig(StrictConfigModel):
    timeout_seconds: float = Field(default=1800.0, gt=0, le=86400)
    memory_mb: int = Field(default=4096, ge=64, le=1048576)
    cpus: float = Field(default=2.0, gt=0, le=1024)
    pids: int = Field(default=512, ge=16, le=1048576)
    output_mb: int = Field(default=25, ge=1, le=1024)


class TmpfsConfig(StrictConfigModel):
    path: str
    size_mb: int = Field(ge=1, le=16384)
    exec: Literal[False] = False


class RuntimeConfig(StrictConfigModel):
    image: str = Field(min_length=1, max_length=1024)
    dockerfile: str | None = None
    context: str = "."
    platform: str = "linux/amd64"
    working_directory: Literal["/workspace"] = "/workspace"
    user: str = "1000:1000"
    read_only_root: Literal[True] = True
    tmpfs: tuple[TmpfsConfig, ...] = ()
    limits: RuntimeLimitsConfig = RuntimeLimitsConfig()

    @field_validator("tmpfs", mode="before")
    @classmethod
    def tmpfs_array_becomes_tuple(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("user")
    @classmethod
    def user_is_not_root(cls, value: str) -> str:
        if value in {"0", "0:0", "root"}:
            raise ValueError("protected runtime user must be non-root")
        return value


class NetworkConfig(StrictConfigModel):
    setup: Literal["bridge", "none"] = "bridge"
    investigation: Literal["bridge", "none"] = "bridge"
    patch: Literal["bridge", "none"] = "bridge"
    baseline: Literal["none"] = "none"
    verification: Literal["none"] = "none"


class SetupCommandConfig(StrictConfigModel):
    id: str = Field(pattern=r"^[a-z][a-z0-9_-]{0,63}$")
    argv: tuple[str, ...] = Field(min_length=1, max_length=256)
    timeout_seconds: float = Field(gt=0, le=86400)

    @field_validator("argv", mode="before")
    @classmethod
    def argv_array_becomes_tuple(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value


class SetupConfig(StrictConfigModel):
    commands: tuple[SetupCommandConfig, ...] = Field(default=(), max_length=128)
    environment: dict[str, str] = Field(default_factory=dict)
    readonly_secret_files: tuple[str, ...] = ()

    @field_validator("commands", "readonly_secret_files", mode="before")
    @classmethod
    def arrays_become_tuples(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("environment")
    @classmethod
    def environment_is_safe(cls, value: dict[str, str]) -> dict[str, str]:
        if len(value) > 128 or any(ENVIRONMENT_NAME.fullmatch(name) is None for name in value):
            raise ValueError("setup environment contains invalid or excessive names")
        if any("\0" in item for pair in value.items() for item in pair):
            raise ValueError("setup environment must be NUL-free")
        return value


class AgentFileConfig(StrictConfigModel):
    adapter: Literal["generic", "claude", "codex"] = "generic"
    image: str | None = None
    command: tuple[str, ...] = Field(min_length=1, max_length=256)
    environment_allowlist: tuple[str, ...] = ()
    maximum_attempts: int = Field(default=1, ge=1, le=10)
    investigation_timeout_seconds: float = Field(default=1200.0, gt=0, le=86400)
    patch_timeout_seconds: float = Field(default=1800.0, gt=0, le=86400)

    @field_validator("command", "environment_allowlist", mode="before")
    @classmethod
    def arrays_become_tuples(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("environment_allowlist")
    @classmethod
    def environment_names_are_valid(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("environment allowlist contains duplicates")
        if any(ENVIRONMENT_NAME.fullmatch(item) is None for item in value):
            raise ValueError("environment allowlist contains an invalid name")
        return value


class IssueConfig(StrictConfigModel):
    source: Literal["inline"] = "inline"
    text: str | None = Field(default=None, max_length=4096)


class ReproductionOracleConfig(StrictConfigModel):
    source: Literal["agent-contract"] = "agent-contract"
    required: Literal[True] = True


class RegressionExpectationConfig(StrictConfigModel):
    exit_code: int = 0


class RegressionOracleConfig(StrictConfigModel):
    id: str = Field(pattern=r"^[a-z][a-z0-9_-]{0,63}$")
    type: Literal["command"] = "command"
    argv: tuple[str, ...] = Field(min_length=1, max_length=256)
    cwd: str = "."
    timeout_seconds: float = Field(gt=0, le=86400)
    environment: dict[str, str] = Field(default_factory=dict)
    expect: RegressionExpectationConfig = RegressionExpectationConfig()

    @field_validator("argv", mode="before")
    @classmethod
    def argv_array_becomes_tuple(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value


class OraclesConfig(StrictConfigModel):
    reproduction: ReproductionOracleConfig = ReproductionOracleConfig()
    regressions: tuple[RegressionOracleConfig, ...] = Field(default=(), max_length=128)

    @field_validator("regressions", mode="before")
    @classmethod
    def regressions_array_becomes_tuple(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def regression_ids_are_unique(self) -> "OraclesConfig":
        identifiers = [oracle.id for oracle in self.regressions]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("regression oracle IDs must be unique")
        return self


class VerificationConfig(StrictConfigModel):
    require_baseline_failure: Literal[True] = True
    require_reproduction_transition: Literal[True] = True
    require_all_regressions: Literal[True] = True
    fail_on_contract_change: Literal[True] = True
    flag_test_changes: bool = True
    fail_on_test_deletion: bool = False
    fail_on_skipped_test_addition: bool = False


class EvidenceConfig(StrictConfigModel):
    retain_workspaces: bool = False
    retain_logs: Literal[True] = True
    redact_environment_values: Literal[True] = True
    maximum_log_mb: int = Field(default=25, ge=1, le=1024)


class ApplyConfig(StrictConfigModel):
    require_clean_original: Literal[True] = True
    require_same_head: Literal[True] = True
    create_branch: Literal[True] = True
    branch_prefix: str = "proofpatch/"
    stage_changes: bool = False
    commit: Literal[False] = False


class ProofPatchConfig(StrictConfigModel):
    schema_version: Literal[1] = 1
    project: ProjectConfig
    mode: Literal["protected", "observation"] = "protected"
    repository: RepositoryConfig = RepositoryConfig()
    runtime: RuntimeConfig
    network: NetworkConfig = NetworkConfig()
    setup: SetupConfig = SetupConfig()
    agent: AgentFileConfig
    issue: IssueConfig = IssueConfig()
    oracles: OraclesConfig = OraclesConfig()
    verification: VerificationConfig = VerificationConfig()
    evidence: EvidenceConfig = EvidenceConfig()
    apply: ApplyConfig = ApplyConfig()


def load_configuration(path: Path) -> ProofPatchConfig:
    """Read one bounded YAML mapping and reject aliases, unknowns, and unsafe values."""

    try:
        raw = path.read_bytes()
    except OSError as error:
        raise ConfigurationError(f"Could not read configuration: {path}") from error
    if len(raw) > 1024 * 1024:
        raise ConfigurationError("Configuration exceeds the 1 MiB size limit")
    try:
        text = raw.decode("utf-8")
        if any(isinstance(token, (AliasToken, AnchorToken)) for token in yaml.scan(text)):
            raise ConfigurationError("YAML aliases and anchors are not supported")
        # This loader subclasses SafeLoader; the custom constructor only rejects duplicates.
        document = yaml.load(text, Loader=_UniqueKeySafeLoader)  # noqa: S506
        if not isinstance(document, dict):
            raise ConfigurationError("Configuration must be a YAML mapping")
        return ProofPatchConfig.model_validate(document)
    except ConfigurationError:
        raise
    except (UnicodeDecodeError, yaml.YAMLError, ValidationError) as error:
        raise ConfigurationError(f"Configuration is invalid: {error}") from error


def discover_configuration(repository: Path) -> Path:
    """Return the first supported repository configuration name."""

    for name in ("proofpatch.yml", "proofpatch.yaml", ".proofpatch.yml", ".proofpatch.yaml"):
        candidate = repository / name
        if candidate.is_file():
            return candidate
    raise ConfigurationError("No ProofPatch configuration was found in the repository")
