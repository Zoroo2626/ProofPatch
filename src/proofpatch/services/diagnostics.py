"""Structured, non-secret diagnostics for ``proofpatch doctor``."""

import os
import re
import secrets
import stat
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Final

from proofpatch import __version__
from proofpatch.agents.base import AgentConfiguration
from proofpatch.agents.registry import get_agent_adapter
from proofpatch.backends.docker import DockerBackend
from proofpatch.errors import ConfigurationError, ProofPatchError, RepositoryError
from proofpatch.exit_codes import ExitCode
from proofpatch.git.client import GitClient
from proofpatch.models.config import ProofPatchConfig, discover_configuration, load_configuration
from proofpatch.services.configuration import validate_protected_configuration
from proofpatch.services.data_directories import ApplicationDirectories
from proofpatch.services.repository import RepositoryService

PRIVATE_FILE_MODE: Final = 0o600
DOCKER_CHECKS: Final = frozenset(
    {"docker_cli", "docker_daemon", "linux_containers", "image_resolution"}
)
GIT_VERSION_PATTERN: Final = re.compile(
    rb"\Agit version ([0-9]+(?:\.[0-9]+){1,3})(?:[^\r\n]*)?\r?\n?\Z"
)


class DiagnosticLevel(StrEnum):
    """Stable diagnostic severities rendered by the CLI."""

    PASS = "PASS"  # noqa: S105 - diagnostic label, not a credential
    WARNING = "WARNING"
    FAIL = "FAIL"


@dataclass(frozen=True, slots=True)
class DiagnosticCheck:
    """One bounded, non-secret diagnostic result."""

    name: str
    level: DiagnosticLevel
    message: str


@dataclass(frozen=True, slots=True)
class DoctorReport:
    """Ordered doctor results and their stable process exit code."""

    checks: tuple[DiagnosticCheck, ...]

    @property
    def exit_code(self) -> ExitCode:
        failed = {check.name for check in self.checks if check.level is DiagnosticLevel.FAIL}
        if failed & DOCKER_CHECKS:
            return ExitCode.UNSUPPORTED_ENVIRONMENT
        if failed:
            return ExitCode.PREFLIGHT_FAILURE
        return ExitCode.SUCCESS


class DoctorService:
    """Inspect local prerequisites without exposing configured or ambient secret values."""

    def __init__(
        self,
        directories: ApplicationDirectories,
        *,
        backend: DockerBackend | None = None,
        git: GitClient | None = None,
        environment: Mapping[str, str] | None = None,
    ) -> None:
        self.directories = directories
        self.backend = DockerBackend() if backend is None else backend
        self.git = git
        self.environment = os.environ if environment is None else environment

    def check(self, repository: Path, *, config_path: Path | None = None) -> DoctorReport:
        """Run every specified diagnostic and return only controlled messages."""

        checks = [
            DiagnosticCheck("proofpatch", DiagnosticLevel.PASS, f"ProofPatch {__version__}"),
            self._python_check(),
        ]
        checks.extend(self._application_data_checks())
        git = self.git
        if git is None:
            try:
                git = GitClient()
            except RepositoryError:
                git = None
        if git is None:
            checks.append(DiagnosticCheck("git", DiagnosticLevel.FAIL, "Git CLI is unavailable"))
            checks.append(
                DiagnosticCheck(
                    "repository",
                    DiagnosticLevel.FAIL,
                    "Repository status was not checked because Git is unavailable",
                )
            )
        else:
            checks.extend(self._git_and_repository_checks(git, repository))

        config, config_check = self._configuration_check(repository, config_path)
        checks.append(config_check)
        protected_required = config is None or config.mode == "protected"
        if config is not None and config.mode == "protected":
            try:
                validate_protected_configuration(config)
            except ConfigurationError:
                checks[-1] = DiagnosticCheck(
                    "configuration",
                    DiagnosticLevel.FAIL,
                    "Configuration contains unsupported protected-mode settings",
                )
                config = None

        docker = self.backend.doctor()
        docker_level = DiagnosticLevel.FAIL if protected_required else DiagnosticLevel.WARNING
        checks.extend(
            (
                DiagnosticCheck(
                    "docker_cli",
                    DiagnosticLevel.PASS if docker.docker_cli else docker_level,
                    "Docker CLI is available" if docker.docker_cli else "Docker CLI is unavailable",
                ),
                DiagnosticCheck(
                    "docker_daemon",
                    DiagnosticLevel.PASS if docker.daemon_responding else docker_level,
                    "Docker daemon responded"
                    if docker.daemon_responding
                    else "Docker daemon is unavailable",
                ),
                DiagnosticCheck(
                    "linux_containers",
                    DiagnosticLevel.PASS if docker.linux_containers else docker_level,
                    "Docker is using Linux containers"
                    if docker.linux_containers
                    else "Docker Linux-container mode is unavailable",
                ),
            )
        )
        checks.append(self._image_check(config, docker.healthy, protected_required))
        checks.append(self._secret_names_check(config))
        return DoctorReport(tuple(checks))

    @staticmethod
    def _python_check() -> DiagnosticCheck:
        version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
        level = DiagnosticLevel.PASS if sys.version_info >= (3, 12) else DiagnosticLevel.FAIL
        return DiagnosticCheck("python", level, f"Python {version}")

    def _application_data_checks(self) -> tuple[DiagnosticCheck, DiagnosticCheck]:
        try:
            self.directories.ensure_exists()
        except (OSError, ValueError):
            failure = DiagnosticCheck(
                "application_data",
                DiagnosticLevel.FAIL,
                "Application data directory is unavailable or unsafe",
            )
            permissions = DiagnosticCheck(
                "filesystem_permissions",
                DiagnosticLevel.FAIL,
                "Application data permissions could not be verified",
            )
            return failure, permissions
        application_data = DiagnosticCheck(
            "application_data",
            DiagnosticLevel.PASS,
            "Application data directory is available",
        )
        try:
            probe = self.directories.cache / f"doctor-{secrets.token_hex(8)}.probe"
            descriptor: int | None = None
            try:
                flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
                flags |= getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
                descriptor = os.open(probe, flags, PRIVATE_FILE_MODE)
                status = os.fstat(descriptor)
                if not stat.S_ISREG(status.st_mode) or status.st_nlink != 1:
                    raise OSError("unsafe application-data probe")
                if os.write(descriptor, b"proofpatch-doctor\n") != len(b"proofpatch-doctor\n"):
                    raise OSError("short application-data probe write")
                os.fsync(descriptor)
            finally:
                if descriptor is not None:
                    os.close(descriptor)
                if probe.exists():
                    probe.unlink()
        except OSError:
            permissions = DiagnosticCheck(
                "filesystem_permissions",
                DiagnosticLevel.FAIL,
                "Application data directory is not safely writable",
            )
        else:
            permissions = DiagnosticCheck(
                "filesystem_permissions",
                DiagnosticLevel.PASS,
                "Application data permissions support private regular files",
            )
        return application_data, permissions

    def _git_and_repository_checks(
        self,
        git: GitClient,
        repository: Path,
    ) -> tuple[DiagnosticCheck, DiagnosticCheck]:
        try:
            result = git.run(["--version"], operation="version diagnostic")
            matched = GIT_VERSION_PATTERN.fullmatch(result.stdout)
            if matched is None:
                raise RepositoryError("Git returned a malformed version response")
            version = matched.group(1).decode("ascii")
            git_check = DiagnosticCheck("git", DiagnosticLevel.PASS, f"Git {version}")
        except ProofPatchError:
            return (
                DiagnosticCheck("git", DiagnosticLevel.FAIL, "Git CLI check failed"),
                DiagnosticCheck(
                    "repository",
                    DiagnosticLevel.FAIL,
                    "Repository status was not checked because Git failed",
                ),
            )
        try:
            RepositoryService(
                git,
                data_root=self.directories.data,
            ).discover(repository)
        except RepositoryError:
            repository_check = DiagnosticCheck(
                "repository",
                DiagnosticLevel.FAIL,
                "Repository is unavailable, unsafe, or not clean",
            )
        else:
            repository_check = DiagnosticCheck(
                "repository",
                DiagnosticLevel.PASS,
                "Repository is clean and supported",
            )
        return git_check, repository_check

    @staticmethod
    def _configuration_check(
        repository: Path,
        config_path: Path | None,
    ) -> tuple[ProofPatchConfig | None, DiagnosticCheck]:
        if config_path is None:
            try:
                selected = discover_configuration(repository)
            except ConfigurationError:
                return None, DiagnosticCheck(
                    "configuration",
                    DiagnosticLevel.WARNING,
                    "No valid configuration was found; run proofpatch init",
                )
        else:
            selected = config_path
        try:
            config = load_configuration(selected)
        except ConfigurationError:
            return None, DiagnosticCheck(
                "configuration",
                DiagnosticLevel.FAIL,
                "The selected configuration is invalid",
            )
        return config, DiagnosticCheck(
            "configuration",
            DiagnosticLevel.PASS,
            f"Configuration is valid for {config.mode} mode",
        )

    def _image_check(
        self,
        config: ProofPatchConfig | None,
        docker_healthy: bool,
        protected_required: bool,
    ) -> DiagnosticCheck:
        level = DiagnosticLevel.FAIL if protected_required else DiagnosticLevel.WARNING
        if config is None:
            return DiagnosticCheck(
                "image_resolution",
                DiagnosticLevel.WARNING,
                "Image resolution was not checked without a valid configuration",
            )
        if config.mode != "protected":
            return DiagnosticCheck(
                "image_resolution",
                DiagnosticLevel.WARNING,
                "Image resolution is not required for observation mode",
            )
        if not docker_healthy:
            return DiagnosticCheck(
                "image_resolution",
                level,
                "Image resolution was blocked by Docker availability",
            )
        try:
            self.backend.resolve_image(config.runtime.image, pull=False)
        except ProofPatchError:
            return DiagnosticCheck(
                "image_resolution",
                level,
                "Configured image could not be resolved immutably",
            )
        return DiagnosticCheck(
            "image_resolution",
            DiagnosticLevel.PASS,
            "Configured image resolved to an immutable Linux identity",
        )

    def _secret_names_check(self, config: ProofPatchConfig | None) -> DiagnosticCheck:
        if config is None:
            return DiagnosticCheck(
                "required_secrets",
                DiagnosticLevel.WARNING,
                "Required secret names were not checked without a valid configuration",
            )
        try:
            adapter = get_agent_adapter(config.agent.adapter)
            agent = AgentConfiguration(
                command=config.agent.command,
                environment_allowlist=config.agent.environment_allowlist,
            )
            adapter.validate_configuration(agent)
            required = tuple(sorted(adapter.required_secret_names(agent)))
        except ConfigurationError:
            return DiagnosticCheck(
                "required_secrets",
                DiagnosticLevel.FAIL,
                "Agent configuration is invalid",
            )
        if not required:
            return DiagnosticCheck(
                "required_secrets",
                DiagnosticLevel.PASS,
                "No provider secret names are required",
            )
        missing = tuple(name for name in required if not self.environment.get(name))
        if missing:
            return DiagnosticCheck(
                "required_secrets",
                DiagnosticLevel.FAIL,
                "Missing required secret names: " + ", ".join(missing),
            )
        return DiagnosticCheck(
            "required_secrets",
            DiagnosticLevel.PASS,
            "Required secret names are present: " + ", ".join(required),
        )
