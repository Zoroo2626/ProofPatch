"""Deterministic starter configuration generation for ``proofpatch init``."""

import os
import secrets
import stat
from contextlib import suppress
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Final

import yaml

from proofpatch.errors import ConfigurationError
from proofpatch.models.config import ProofPatchConfig

CONFIGURATION_NAMES: Final = (
    "proofpatch.yml",
    "proofpatch.yaml",
    ".proofpatch.yml",
    ".proofpatch.yaml",
)
PYTHON_INDICATORS: Final = (
    "pyproject.toml",
    "setup.py",
    "setup.cfg",
    "requirements.txt",
    "Pipfile",
    "poetry.lock",
    "pytest.ini",
    "tox.ini",
)
NODE_INDICATORS: Final = (
    "package.json",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
)
PRIVATE_FILE_MODE: Final = 0o600


class InitMode(StrEnum):
    """Assurance choices accepted by the initialization command."""

    PROTECTED = "protected"
    OBSERVATION = "observation"


class InitTemplate(StrEnum):
    """Conservative starter runtime families."""

    PYTHON = "python"
    NODE = "node"
    MINIMAL = "minimal"


@dataclass(frozen=True, slots=True)
class InitializationResult:
    """The deterministic configuration path and choices written to disk."""

    path: Path
    mode: InitMode
    template: InitTemplate


def detect_project_template(repository: Path) -> InitTemplate:
    """Detect one unambiguous common runtime without reading repository content."""

    root = _repository_directory(repository)
    python = any((root / name).is_file() for name in PYTHON_INDICATORS)
    node = any((root / name).is_file() for name in NODE_INDICATORS)
    if python == node:
        return InitTemplate.MINIMAL
    return InitTemplate.PYTHON if python else InitTemplate.NODE


def initialize_repository(
    repository: Path,
    *,
    mode: InitMode,
    template: InitTemplate | None,
    force: bool,
) -> InitializationResult:
    """Write one model-validated deterministic starter configuration."""

    root = _repository_directory(repository)
    selected_template = detect_project_template(root) if template is None else template
    existing = tuple(root / name for name in CONFIGURATION_NAMES if (root / name).exists())
    if existing and not force:
        raise ConfigurationError(
            f"ProofPatch configuration already exists: {existing[0].name}",
            remediation="Use --force only after reviewing the existing configuration.",
        )
    destination = existing[0] if existing else root / CONFIGURATION_NAMES[0]
    if destination.is_symlink() or destination.is_dir():
        raise ConfigurationError("Configuration output path must be a regular file path")
    document = _starter_document(root.name or "project", mode, selected_template)
    _write_configuration(destination, document, force=force)
    return InitializationResult(destination, mode, selected_template)


def _starter_document(project_name: str, mode: InitMode, template: InitTemplate) -> bytes:
    image, setup_commands, regressions = _template_values(template)
    raw: dict[str, object] = {
        "schema_version": 1,
        "project": {"name": project_name[:255]},
        "mode": mode.value,
        "repository": {
            "require_clean": True,
            "allow_submodules": False,
            "allow_git_lfs": False,
            "maximum_size_mb": 2048,
            "allowed_patch_paths": ["**"],
            "denied_patch_paths": [
                ".git/**",
                ".proofpatch/**",
                *CONFIGURATION_NAMES,
            ],
            "maximum_changed_files": 100,
            "maximum_patch_size_mb": 20,
        },
        "runtime": {
            "image": image,
            "dockerfile": None,
            "context": ".",
            "platform": "linux/amd64",
            "working_directory": "/workspace",
            "user": "1000:1000",
            "read_only_root": True,
            "tmpfs": [
                {"path": "/tmp", "size_mb": 1024, "exec": False}  # noqa: S108
            ],
            "limits": {
                "timeout_seconds": 1800.0,
                "memory_mb": 4096,
                "cpus": 2.0,
                "pids": 512,
                "output_mb": 25,
            },
        },
        "network": {
            "setup": "none",
            "investigation": "bridge",
            "patch": "bridge",
            "baseline": "none",
            "verification": "none",
        },
        "setup": {
            "commands": setup_commands,
            "environment": {},
            "readonly_secret_files": [],
        },
        "agent": {
            "adapter": "generic",
            "image": None,
            "command": ["my-agent", "--non-interactive", "--prompt-file", "{prompt_path}"],
            "environment_allowlist": [],
            "maximum_attempts": 1,
            "investigation_timeout_seconds": 1200.0,
            "patch_timeout_seconds": 1800.0,
        },
        "issue": {"source": "inline", "text": None},
        "oracles": {
            "reproduction": {"source": "agent-contract", "required": True},
            "regressions": regressions,
        },
        "verification": {
            "require_baseline_failure": True,
            "require_reproduction_transition": True,
            "require_all_regressions": True,
            "fail_on_contract_change": True,
            "flag_test_changes": True,
            "fail_on_test_deletion": False,
            "fail_on_skipped_test_addition": False,
        },
        "evidence": {
            "retain_workspaces": False,
            "retain_logs": True,
            "redact_environment_values": True,
            "maximum_log_mb": 25,
        },
        "apply": {
            "require_clean_original": True,
            "require_same_head": True,
            "create_branch": True,
            "branch_prefix": "proofpatch/",
            "stage_changes": False,
            "commit": False,
        },
    }
    validated = ProofPatchConfig.model_validate(raw)
    encoded = yaml.safe_dump(
        validated.model_dump(mode="json"),
        sort_keys=False,
        allow_unicode=False,
        default_flow_style=False,
    ).encode("utf-8")
    if len(encoded) > 1024 * 1024:
        raise ConfigurationError("Generated configuration unexpectedly exceeds 1 MiB")
    return encoded


def _template_values(template: InitTemplate) -> tuple[str, list[object], list[object]]:
    if template is InitTemplate.PYTHON:
        return (
            "python:3.12-slim",
            [],
            [
                {
                    "id": "tests",
                    "type": "command",
                    "argv": ["python", "-m", "pytest", "-q"],
                    "cwd": ".",
                    "timeout_seconds": 1200.0,
                    "environment": {},
                    "expect": {"exit_code": 0},
                }
            ],
        )
    if template is InitTemplate.NODE:
        return (
            "node:22-slim",
            [],
            [
                {
                    "id": "tests",
                    "type": "command",
                    "argv": ["npm", "test"],
                    "cwd": ".",
                    "timeout_seconds": 1200.0,
                    "environment": {},
                    "expect": {"exit_code": 0},
                }
            ],
        )
    return "ubuntu:24.04", [], []


def _repository_directory(repository: Path) -> Path:
    try:
        root = repository.resolve(strict=True)
    except OSError as error:
        raise ConfigurationError(f"Repository directory does not exist: {repository}") from error
    if not root.is_dir():
        raise ConfigurationError(f"Repository path is not a directory: {repository}")
    return root


def _write_configuration(path: Path, content: bytes, *, force: bool) -> None:
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}-{secrets.token_hex(8)}")
    target = temporary if force else path
    descriptor: int | None = None
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        flags |= getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(target, flags, PRIVATE_FILE_MODE)
        file_status = os.fstat(descriptor)
        if not stat.S_ISREG(file_status.st_mode) or file_status.st_nlink != 1:
            raise ConfigurationError("Configuration output is not a private regular file")
        view = memoryview(content)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short configuration write")
            view = view[written:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        if force:
            os.replace(temporary, path)
        os.chmod(path, PRIVATE_FILE_MODE)
    except FileExistsError as error:
        raise ConfigurationError(
            f"ProofPatch configuration already exists: {path.name}",
            remediation="Use --force only after reviewing the existing configuration.",
        ) from error
    except ConfigurationError:
        raise
    except OSError as error:
        raise ConfigurationError(f"Could not safely write configuration: {path}") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if temporary.exists():
            with suppress(OSError):
                temporary.unlink()
