"""Docker CLI protected backend with immutable images and label-guarded cleanup."""

import json
import logging
import os
import re
import shutil
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from threading import RLock
from typing import Protocol, cast

from proofpatch.errors import (
    BackendError,
    DockerUnavailableError,
    ImageResolutionError,
)
from proofpatch.execution.docker_command import (
    MANAGED_LABEL,
    RUN_LABEL_PREFIX,
    DockerCommandBuilder,
)
from proofpatch.execution.process import ProcessOutcome, ProcessRequest, ProcessRunner
from proofpatch.logging import get_logger, log_event
from proofpatch.models.common import validate_run_id
from proofpatch.models.execution import (
    BackendDoctorResult,
    ExecutionRequest,
    ExecutionResult,
    ProtectionLevel,
    ResolvedImage,
    TerminationKind,
)
from proofpatch.services.policy import calculate_protection

DOCKER_INSPECT_FORMAT = "{{json .}}"
CONTROL_OUTPUT_LIMIT = 1024 * 1024
CONTROL_TIMEOUT_SECONDS = 30.0
STOP_GRACE_SECONDS = 2
IMAGE_REFERENCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/:@-]{0,1023}$")
IMAGE_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
CONTAINER_ID = re.compile(r"^[0-9a-f]{12,64}$")


class ProcessExecutor(Protocol):
    def run(self, request: ProcessRequest) -> ProcessOutcome: ...


@dataclass(frozen=True, slots=True)
class _ActiveContainer:
    execution_id: str
    name: str
    labels: Mapping[str, str]


@dataclass(frozen=True, slots=True)
class _ContainerDetails:
    container_id: str
    labels: Mapping[str, str]
    running: bool


class DockerBackend:
    """Invoke Docker without a shell while preserving the host-side trust boundary."""

    def __init__(
        self,
        *,
        executable: Path | None = None,
        runner: ProcessExecutor | None = None,
    ) -> None:
        discovered = shutil.which("docker") if executable is None else str(executable)
        self._executable = Path(discovered).resolve(strict=False) if discovered else None
        self._runner = runner or ProcessRunner()
        self._active: dict[str, _ActiveContainer] = {}
        self._lock = RLock()
        self._protection_level = ProtectionLevel.UNAVAILABLE

    @property
    def protection_level(self) -> ProtectionLevel:
        return self._protection_level

    def doctor(self) -> BackendDoctorResult:
        """Check the CLI, daemon, and Linux-container mode without printing secrets."""

        if self._executable is None or not self._executable.is_file():
            self._protection_level = ProtectionLevel.UNAVAILABLE
            return BackendDoctorResult(
                docker_cli=False,
                daemon_responding=False,
                linux_containers=False,
                error="Docker CLI was not found",
            )
        version = self._capture(("version", "--format", DOCKER_INSPECT_FORMAT))
        if version.exit_code != 0 or version.termination is not TerminationKind.EXITED:
            self._protection_level = ProtectionLevel.UNAVAILABLE
            return BackendDoctorResult(
                docker_cli=True,
                daemon_responding=False,
                linux_containers=False,
                error=_safe_error(version.stderr, "Docker daemon did not respond"),
            )
        try:
            version_data = _json_object(version.stdout)
            client = _mapping(version_data.get("Client"))
            server = _mapping(version_data.get("Server"))
            client_version = _optional_string(client.get("Version"))
            server_version = _optional_string(server.get("Version"))
        except (TypeError, ValueError) as error:
            self._protection_level = ProtectionLevel.UNAVAILABLE
            return BackendDoctorResult(
                docker_cli=True,
                daemon_responding=False,
                linux_containers=False,
                error=f"Docker version response was invalid: {error}",
            )

        info = self._capture(("info", "--format", DOCKER_INSPECT_FORMAT))
        if info.exit_code != 0 or info.termination is not TerminationKind.EXITED:
            self._protection_level = ProtectionLevel.UNAVAILABLE
            return BackendDoctorResult(
                docker_cli=True,
                daemon_responding=True,
                linux_containers=False,
                client_version=client_version,
                server_version=server_version,
                error=_safe_error(info.stderr, "Docker info did not respond"),
            )
        try:
            info_data = _json_object(info.stdout)
        except (TypeError, ValueError) as error:
            self._protection_level = ProtectionLevel.UNAVAILABLE
            return BackendDoctorResult(
                docker_cli=True,
                daemon_responding=True,
                linux_containers=False,
                client_version=client_version,
                server_version=server_version,
                error=f"Docker info response was invalid: {error}",
            )
        linux = str(info_data.get("OSType", "")).lower() == "linux"
        self._protection_level = ProtectionLevel.PROTECTED if linux else ProtectionLevel.UNAVAILABLE
        return BackendDoctorResult(
            docker_cli=True,
            daemon_responding=True,
            linux_containers=linux,
            client_version=client_version,
            server_version=server_version,
            error=None if linux else "Docker daemon is not using Linux containers",
        )

    def resolve_image(self, image: str, *, pull: bool = False) -> ResolvedImage:
        """Resolve a tag or digest to an immutable digest accepted by ``docker run``."""

        _validate_image_reference(image)
        self._require_healthy()
        inspected = self._inspect_image(image)
        pulled = False
        if inspected is None:
            if not pull:
                raise ImageResolutionError(
                    f"Docker image is not available locally: {image}",
                    remediation="Pull the image explicitly or allow ProofPatch to pull it.",
                )
            pull_result = self._capture(("pull", image), timeout_seconds=1800.0)
            if pull_result.exit_code != 0 or pull_result.termination is not TerminationKind.EXITED:
                raise ImageResolutionError(
                    f"Docker could not pull image: {image}",
                    remediation=_safe_error(pull_result.stderr, "Check registry access"),
                )
            pulled = True
            inspected = self._inspect_image(image)
        if inspected is None:
            raise ImageResolutionError("Docker image remained unavailable after resolution")
        image_id = str(inspected.get("Id", "")).lower()
        operating_system = str(inspected.get("Os", "")).lower()
        architecture = str(inspected.get("Architecture", "")).lower()
        if IMAGE_DIGEST.fullmatch(image_id) is None:
            raise ImageResolutionError("Docker image has no valid immutable image ID")
        if operating_system != "linux" or not architecture:
            raise ImageResolutionError("Protected execution requires a Linux image")
        repo_digests_raw = inspected.get("RepoDigests") or []
        if not isinstance(repo_digests_raw, list) or any(
            not isinstance(item, str) for item in repo_digests_raw
        ):
            raise ImageResolutionError("Docker image returned malformed repository digests")
        repo_digests = sorted(cast(list[str], repo_digests_raw))
        immutable, digest = _select_immutable_reference(image, repo_digests, image_id)
        return ResolvedImage(
            requested_reference=image,
            immutable_reference=immutable,
            digest=digest,
            image_id=image_id,
            architecture=architecture,
            pulled=pulled,
        )

    def run(self, request: ExecutionRequest) -> ExecutionResult:
        """Execute one disposable container and confirm cleanup on every exit path."""

        doctor = self._require_healthy()
        if self._executable is None:  # pragma: no cover - established by _require_healthy
            raise DockerUnavailableError("Docker CLI was not found")
        command = DockerCommandBuilder(self._executable).build(request)
        protection = calculate_protection(doctor, request, command)
        if protection.level is not ProtectionLevel.PROTECTED:
            raise BackendError(
                "Docker request does not establish every protected-mode restriction: "
                + ", ".join(protection.failures)
            )
        log_event(
            get_logger("docker"),
            logging.INFO,
            "docker.command.prepared",
            "Prepared protected Docker execution command",
            context={
                "run_id": request.run_id,
                "execution_id": request.execution_id,
                "phase": request.phase.value,
                "container_name": command.container_name,
                "command": json.dumps(command.redacted_argv, separators=(",", ":")),
            },
        )
        labels = dict(label.split("=", 1) for label in command.labels)
        active = _ActiveContainer(request.execution_id, command.container_name, labels)
        with self._lock:
            if request.execution_id in self._active:
                raise BackendError("Execution ID is already active")
            self._active[request.execution_id] = active

        outcome: ProcessOutcome | None = None
        cleaned = False
        try:
            outcome = self._runner.run(
                ProcessRequest(
                    argv=command.argv,
                    cwd=Path.cwd(),
                    timeout_seconds=request.resources.timeout_seconds,
                    maximum_output_bytes=request.resources.output_bytes,
                    environment={**_docker_control_environment(), **request.environment},
                    secret_values=tuple(request.environment.values()),
                )
            )
            if outcome.timed_out or outcome.cancelled:
                self.terminate(request.execution_id)
            self.cleanup(request.execution_id)
            cleaned = True
        except BaseException:
            try:
                self.terminate(request.execution_id)
            finally:
                self.cleanup(request.execution_id)
            raise
        finally:
            with self._lock:
                self._active.pop(request.execution_id, None)
        if outcome is None:  # pragma: no cover - defensive invariant
            raise BackendError("Docker execution produced no outcome")
        return ExecutionResult(
            execution_id=request.execution_id,
            container_name=command.container_name,
            redacted_command=command.redacted_argv,
            outcome=outcome,
            protection=protection,
            cleanup_confirmed=cleaned,
        )

    def terminate(self, execution_id: str) -> None:
        """Stop, then kill if needed, only the exact label-verified active container."""

        active = self._get_active(execution_id)
        if active is None:
            return
        details = self._inspect_container(active)
        if details is None or not details.running:
            return
        stopped = self._capture(
            ("stop", "--time", str(STOP_GRACE_SECONDS), details.container_id),
            timeout_seconds=CONTROL_TIMEOUT_SECONDS,
        )
        current = self._inspect_container(active)
        if stopped.exit_code != 0 and current is None:
            return
        if current is not None and current.running:
            killed = self._capture(("kill", current.container_id))
            if killed.exit_code != 0 and self._inspect_container(active) is not None:
                raise BackendError("Could not terminate managed Docker container")

    def cleanup(self, execution_id: str) -> None:
        """Remove only a container whose exact identity carries every expected label."""

        active = self._get_active(execution_id)
        if active is None:
            return
        details = self._inspect_container(active)
        if details is None:
            return
        removed = self._capture(("rm", "--force", details.container_id))
        if removed.exit_code != 0 and self._inspect_container(active) is not None:
            raise BackendError("Could not remove managed Docker container")

    def terminate_run(self, run_id: str) -> None:
        """Stop all containers carrying both exact managed and run labels."""

        selected_run_id = validate_run_id(run_id)
        self._require_healthy()
        listed = self._capture(
            (
                "ps",
                "--all",
                "--filter",
                f"label={MANAGED_LABEL}",
                "--filter",
                f"label={RUN_LABEL_PREFIX}{selected_run_id}",
                "--format",
                "{{.ID}}",
            )
        )
        if listed.termination is not TerminationKind.EXITED or listed.exit_code != 0:
            raise BackendError("Could not list managed containers for the run")
        try:
            identifiers = listed.stdout.decode("ascii", errors="strict").splitlines()
        except UnicodeDecodeError as error:
            raise BackendError("Docker returned non-ASCII managed container IDs") from error
        for container_id in identifiers:
            if CONTAINER_ID.fullmatch(container_id) is None:
                raise BackendError("Docker returned an invalid managed container ID")
            active = _ActiveContainer(
                execution_id="abort",
                name=container_id,
                labels={
                    MANAGED_LABEL.split("=", 1)[0]: MANAGED_LABEL.split("=", 1)[1],
                    RUN_LABEL_PREFIX.rstrip("="): selected_run_id,
                },
            )
            details = self._inspect_container(active)
            if details is None:
                continue
            if details.running:
                stopped = self._capture(
                    ("stop", "--time", str(STOP_GRACE_SECONDS), details.container_id)
                )
                current = self._inspect_container(active)
                if stopped.exit_code != 0 and current is not None and current.running:
                    killed = self._capture(("kill", current.container_id))
                    if killed.exit_code != 0 and self._inspect_container(active) is not None:
                        raise BackendError("Could not stop a managed run container")
            removed = self._capture(("rm", "--force", details.container_id))
            if removed.exit_code != 0 and self._inspect_container(active) is not None:
                raise BackendError("Could not remove a managed run container")

    def _require_healthy(self) -> BackendDoctorResult:
        result = self.doctor()
        if not result.healthy:
            raise DockerUnavailableError(
                result.error or "Docker protected mode is unavailable",
                remediation="Install Docker, start its daemon, and enable Linux containers.",
            )
        return result

    def _inspect_image(self, image: str) -> dict[str, object] | None:
        result = self._capture(("image", "inspect", "--format", DOCKER_INSPECT_FORMAT, image))
        if result.exit_code != 0:
            if _is_not_found(result.stderr):
                return None
            raise ImageResolutionError(_safe_error(result.stderr, "Docker image inspection failed"))
        try:
            return _json_object(result.stdout)
        except (TypeError, ValueError) as error:
            raise ImageResolutionError("Docker image inspection returned invalid JSON") from error

    def _inspect_container(self, active: _ActiveContainer) -> _ContainerDetails | None:
        result = self._capture(("inspect", "--format", DOCKER_INSPECT_FORMAT, active.name))
        if result.exit_code != 0:
            if _is_not_found(result.stderr):
                return None
            raise BackendError(_safe_error(result.stderr, "Docker container inspection failed"))
        try:
            data = _json_object(result.stdout)
            container_id = str(data.get("Id", "")).lower()
            config = _mapping(data.get("Config"))
            labels_raw = _mapping(config.get("Labels"))
            labels = {str(key): str(value) for key, value in labels_raw.items()}
            state = _mapping(data.get("State"))
            running = state.get("Running") is True
        except (TypeError, ValueError) as error:
            raise BackendError("Docker container inspection returned invalid data") from error
        if CONTAINER_ID.fullmatch(container_id) is None:
            raise BackendError("Docker returned an invalid container ID")
        if any(labels.get(key) != value for key, value in active.labels.items()):
            raise BackendError("Refusing to manage a container without exact ProofPatch labels")
        return _ContainerDetails(container_id, labels, running)

    def _get_active(self, execution_id: str) -> _ActiveContainer | None:
        with self._lock:
            return self._active.get(execution_id)

    def _capture(
        self,
        arguments: tuple[str, ...],
        *,
        timeout_seconds: float = CONTROL_TIMEOUT_SECONDS,
    ) -> ProcessOutcome:
        if self._executable is None:
            raise DockerUnavailableError("Docker CLI was not found")
        return self._runner.run(
            ProcessRequest(
                argv=(str(self._executable), *arguments),
                cwd=Path.cwd(),
                timeout_seconds=timeout_seconds,
                maximum_output_bytes=CONTROL_OUTPUT_LIMIT,
                environment=_docker_control_environment(),
            )
        )


def _docker_control_environment() -> dict[str, str]:
    names = ("DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG", "HOME", "USERPROFILE")
    return {name: os.environ[name] for name in names if name in os.environ}


def _validate_image_reference(image: str) -> None:
    if IMAGE_REFERENCE.fullmatch(image) is None or "\0" in image or image.startswith("-"):
        raise ImageResolutionError("Docker image reference is invalid")


def _select_immutable_reference(
    requested: str,
    repo_digests: list[str],
    image_id: str,
) -> tuple[str, str]:
    if "@sha256:" in requested:
        digest = "sha256:" + requested.rsplit("@sha256:", 1)[1]
        if IMAGE_DIGEST.fullmatch(digest) is None:
            raise ImageResolutionError("Configured image digest is invalid")
        matching = [item for item in repo_digests if item.endswith(f"@{digest}")]
        return (matching[0] if matching else requested), digest
    valid = [
        item
        for item in repo_digests
        if "@" in item and IMAGE_DIGEST.fullmatch(item.rsplit("@", 1)[1])
    ]
    if valid:
        immutable = valid[0]
        return immutable, immutable.rsplit("@", 1)[1]
    return image_id, image_id


def _json_object(content: bytes) -> dict[str, object]:
    parsed = json.loads(content.decode("utf-8"))
    if not isinstance(parsed, dict):
        raise TypeError("expected a JSON object")
    return cast(dict[str, object], parsed)


def _mapping(value: object) -> Mapping[object, object]:
    if not isinstance(value, dict):
        raise TypeError("expected an object")
    return cast(dict[object, object], value)


def _optional_string(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def _safe_error(content: bytes, fallback: str) -> str:
    decoded = content.decode("utf-8", errors="replace").strip()
    return decoded[:4096] or fallback


def _is_not_found(content: bytes) -> bool:
    lowered = content.decode("utf-8", errors="replace").lower()
    return (
        "no such image" in lowered or "no such object" in lowered or "no such container" in lowered
    )
