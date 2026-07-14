"""Docker backend integration tests using a deterministic fake Docker CLI boundary."""

import json
from pathlib import Path

import pytest

from proofpatch.backends.docker import DockerBackend
from proofpatch.errors import BackendError, DockerUnavailableError, ImageResolutionError
from proofpatch.execution.process import ProcessOutcome, ProcessRequest
from proofpatch.models.execution import (
    DockerMount,
    ExecutionPhase,
    ExecutionRequest,
    MountAccess,
    MountKind,
    NetworkPolicy,
    ProtectionLevel,
    ResolvedImage,
    ResourceLimits,
    TerminationKind,
)
from proofpatch.services.doctor import DockerDoctorService

RUN_ID = "pp_20260713_a4f92b18ce31"
DIGEST = "sha256:" + "a" * 64
IMAGE_ID = "sha256:" + "b" * 64
CONTAINER_ID = "c" * 64


def _outcome(
    *,
    exit_code: int | None = 0,
    stdout: bytes = b"",
    stderr: bytes = b"",
    termination: TerminationKind = TerminationKind.EXITED,
) -> ProcessOutcome:
    return ProcessOutcome(
        termination=termination,
        exit_code=exit_code,
        signal=None,
        duration_ms=1,
        timed_out=termination is TerminationKind.TIMEOUT,
        cancelled=termination is TerminationKind.CANCELLED,
        stdout=stdout,
        stderr=stderr,
        truncated=False,
    )


class DockerSimulation:
    """Stateful shell-free simulation of the small Docker CLI surface ProofPatch uses."""

    def __init__(self, mode: str = "success") -> None:
        self.mode = mode
        self.requests: list[ProcessRequest] = []
        self.image_present = True
        self.container_exists = False
        self.container_running = False
        self.labels: dict[str, str] = {}
        self.removed: list[str] = []
        self.container_environment_file: bytes | None = None
        self.docker_run_environment: dict[str, str] | None = None

    def run(self, request: ProcessRequest) -> ProcessOutcome:
        self.requests.append(request)
        command = request.argv[1]
        if command == "version":
            if self.mode == "version-fail":
                return _outcome(exit_code=1, stderr=b"daemon unavailable")
            if self.mode == "version-invalid":
                return _outcome(stdout=b"not-json")
            return _outcome(
                stdout=_json({"Client": {"Version": "29.0"}, "Server": {"Version": "29.0"}})
            )
        if command == "info":
            if self.mode == "info-fail":
                return _outcome(exit_code=1, stderr=b"info failed")
            if self.mode == "info-invalid":
                return _outcome(stdout=b"[]")
            return _outcome(
                stdout=_json({"OSType": "windows" if self.mode == "windows" else "linux"})
            )
        if command == "image":
            if not self.image_present:
                return _outcome(exit_code=1, stderr=b"Error: No such image")
            return _outcome(
                stdout=_json(
                    {
                        "Id": IMAGE_ID,
                        "Os": "linux",
                        "Architecture": "amd64",
                        "RepoDigests": [f"example/runtime@{DIGEST}"],
                    }
                )
            )
        if command == "pull":
            if self.mode == "pull-fail":
                return _outcome(exit_code=1, stderr=b"registry denied")
            self.image_present = True
            return _outcome(stdout=b"pulled")
        if command == "run":
            self.docker_run_environment = dict(request.environment)
            if "--env-file" in request.argv:
                environment_path = Path(request.argv[request.argv.index("--env-file") + 1])
                self.container_environment_file = environment_path.read_bytes()
            self.container_exists = True
            self.container_running = True
            self.labels = _labels_from_run(request.argv)
            if self.mode == "interrupt":
                raise KeyboardInterrupt
            if self.mode in {"timeout", "label-mismatch", "stop-fail"}:
                return _outcome(exit_code=None, termination=TerminationKind.TIMEOUT)
            self.container_exists = False  # --rm after either normal exit code
            self.container_running = False
            return _outcome(exit_code=0 if self.mode == "success" else 7, stdout=b"log")
        if command == "ps":
            return _outcome(stdout=(CONTAINER_ID + "\n").encode() if self.container_exists else b"")
        if command == "inspect":
            if not self.container_exists:
                return _outcome(exit_code=1, stderr=b"Error: No such object")
            labels = dict(self.labels)
            if self.mode == "label-mismatch":
                labels["org.proofpatch.managed"] = "false"
            return _outcome(
                stdout=_json(
                    {
                        "Id": CONTAINER_ID,
                        "Config": {"Labels": labels},
                        "State": {"Running": self.container_running},
                    }
                )
            )
        if command == "stop":
            if self.mode == "stop-fail":
                return _outcome(exit_code=1, stderr=b"stop refused")
            self.container_running = False
            return _outcome()
        if command == "kill":
            self.container_running = False
            return _outcome()
        if command == "rm":
            self.removed.append(request.argv[-1])
            self.container_exists = False
            return _outcome()
        raise AssertionError(f"Unexpected fake Docker command: {request.argv}")


def _json(value: object) -> bytes:
    return json.dumps(value, separators=(",", ":")).encode()


def _labels_from_run(argv: tuple[str, ...]) -> dict[str, str]:
    labels: dict[str, str] = {}
    for index, item in enumerate(argv):
        if item == "--label":
            key, value = argv[index + 1].split("=", 1)
            labels[key] = value
    return labels


def _executable(tmp_path: Path) -> Path:
    executable = tmp_path / "docker.exe"
    executable.write_bytes(b"fake")
    return executable


def _request(tmp_path: Path) -> ExecutionRequest:
    original = tmp_path / "original"
    evidence = tmp_path / "evidence"
    workspace = tmp_path / "verification-clone"
    output = tmp_path / "output"
    for path in (original, evidence, workspace, output):
        path.mkdir()
    return ExecutionRequest(
        execution_id="verification-1",
        run_id=RUN_ID,
        phase=ExecutionPhase.VERIFICATION,
        image=ResolvedImage(
            requested_reference="example/runtime:latest",
            immutable_reference=f"example/runtime@{DIGEST}",
            digest=DIGEST,
            image_id=IMAGE_ID,
            architecture="amd64",
        ),
        argv=("python", "-m", "pytest"),
        network=NetworkPolicy.NONE,
        mounts=(
            DockerMount(
                source=workspace,
                destination="/workspace",
                kind=MountKind.WORKSPACE,
                access=MountAccess.READ_ONLY,
            ),
            DockerMount(
                source=output,
                destination="/proofpatch/out",
                kind=MountKind.OUTPUT,
                access=MountAccess.READ_WRITE,
            ),
        ),
        environment={},
        environment_allowlist=(),
        resources=ResourceLimits(
            timeout_seconds=10.0,
            memory_mb=256,
            cpus=1.0,
            pids=64,
            output_bytes=4096,
        ),
        original_repository=original,
        evidence_directory=evidence,
    )


def test_doctor_refuses_missing_docker(tmp_path: Path) -> None:
    backend = DockerBackend(executable=tmp_path / "missing-docker")
    result = backend.doctor()
    assert not result.healthy
    assert backend.protection_level is ProtectionLevel.UNAVAILABLE
    with pytest.raises(DockerUnavailableError):
        backend.resolve_image("example/runtime:latest")


def test_image_resolution_records_digest_and_can_pull(tmp_path: Path) -> None:
    simulation = DockerSimulation()
    backend = DockerBackend(executable=_executable(tmp_path), runner=simulation)
    resolved = backend.resolve_image("example/runtime:latest")
    assert resolved.digest == DIGEST
    assert resolved.immutable_reference == f"example/runtime@{DIGEST}"
    assert not resolved.pulled

    simulation.image_present = False
    pulled = backend.resolve_image("example/runtime:latest", pull=True)
    assert pulled.pulled
    assert any(request.argv[1] == "pull" for request in simulation.requests)


def test_image_resolution_does_not_pull_without_permission(tmp_path: Path) -> None:
    simulation = DockerSimulation()
    simulation.image_present = False
    backend = DockerBackend(executable=_executable(tmp_path), runner=simulation)
    with pytest.raises(ImageResolutionError, match="not available locally"):
        backend.resolve_image("example/runtime:latest")
    assert all(request.argv[1] != "pull" for request in simulation.requests)


def test_image_pull_failure_is_typed(tmp_path: Path) -> None:
    simulation = DockerSimulation("pull-fail")
    simulation.image_present = False
    backend = DockerBackend(executable=_executable(tmp_path), runner=simulation)
    with pytest.raises(ImageResolutionError, match="could not pull"):
        backend.resolve_image("example/runtime:latest", pull=True)


def test_digest_reference_remains_immutable(tmp_path: Path) -> None:
    simulation = DockerSimulation()
    backend = DockerBackend(executable=_executable(tmp_path), runner=simulation)
    reference = f"example/runtime@{DIGEST}"
    resolved = backend.resolve_image(reference)
    assert resolved.immutable_reference == reference
    assert resolved.digest == DIGEST


@pytest.mark.parametrize(
    ("mode", "daemon", "linux"),
    [
        ("version-fail", False, False),
        ("version-invalid", False, False),
        ("info-fail", True, False),
        ("info-invalid", True, False),
        ("windows", True, False),
    ],
)
def test_doctor_fails_closed_on_malformed_or_unsupported_daemon(
    tmp_path: Path,
    mode: str,
    daemon: bool,
    linux: bool,
) -> None:
    backend = DockerBackend(executable=_executable(tmp_path), runner=DockerSimulation(mode))
    result = backend.doctor()
    assert result.daemon_responding is daemon
    assert result.linux_containers is linux
    assert result.error
    with pytest.raises(DockerUnavailableError):
        DockerDoctorService(backend).require_ready()


def test_doctor_service_resolves_an_image_after_readiness(tmp_path: Path) -> None:
    simulation = DockerSimulation()
    service = DockerDoctorService(
        DockerBackend(executable=_executable(tmp_path), runner=simulation)
    )
    assert service.check().healthy
    assert service.require_ready().healthy
    assert service.resolve_image("example/runtime:latest").digest == DIGEST


@pytest.mark.parametrize(("mode", "exit_code"), [("success", 0), ("failure", 7)])
def test_container_cleanup_after_success_and_failure(
    tmp_path: Path,
    mode: str,
    exit_code: int,
) -> None:
    simulation = DockerSimulation(mode)
    backend = DockerBackend(executable=_executable(tmp_path), runner=simulation)
    result = backend.run(_request(tmp_path))
    outcome = result.outcome
    assert isinstance(outcome, ProcessOutcome)
    assert outcome.exit_code == exit_code
    assert result.cleanup_confirmed
    assert result.protection.level is ProtectionLevel.PROTECTED
    assert not simulation.container_exists
    run_request = next(request for request in simulation.requests if request.argv[1] == "run")
    assert str(tmp_path / "original") not in run_request.argv
    assert str(tmp_path / "evidence") not in run_request.argv


def test_container_values_do_not_enter_the_docker_client_environment(tmp_path: Path) -> None:
    simulation = DockerSimulation()
    backend = DockerBackend(executable=_executable(tmp_path), runner=simulation)
    request = ExecutionRequest.model_validate(
        {
            **_request(tmp_path).model_dump(),
            "environment": {"DOCKER_HOST": "container-only", "TOKEN": "secret-value"},
            "environment_allowlist": ("DOCKER_HOST", "TOKEN"),
        }
    )

    result = backend.run(request)

    assert result.cleanup_confirmed
    assert simulation.container_environment_file == (
        b"DOCKER_HOST=container-only\nTOKEN=secret-value\n"
    )
    assert simulation.docker_run_environment is not None
    assert "TOKEN" not in simulation.docker_run_environment
    assert simulation.docker_run_environment.get("DOCKER_HOST") != "container-only"
    environment_path = Path(
        next(
            command.argv[command.argv.index("--env-file") + 1]
            for command in simulation.requests
            if command.argv[1] == "run"
        )
    )
    assert not environment_path.exists()


def test_timeout_stops_and_removes_container(tmp_path: Path) -> None:
    simulation = DockerSimulation("timeout")
    backend = DockerBackend(executable=_executable(tmp_path), runner=simulation)
    result = backend.run(_request(tmp_path))
    outcome = result.outcome
    assert isinstance(outcome, ProcessOutcome)
    assert outcome.timed_out
    assert simulation.removed == [CONTAINER_ID]
    assert not simulation.container_exists
    commands = [request.argv[1] for request in simulation.requests]
    assert "stop" in commands
    assert "rm" in commands


def test_failed_graceful_stop_escalates_to_kill_then_cleanup(tmp_path: Path) -> None:
    simulation = DockerSimulation("stop-fail")
    backend = DockerBackend(executable=_executable(tmp_path), runner=simulation)
    result = backend.run(_request(tmp_path))
    assert result.cleanup_confirmed
    commands = [request.argv[1] for request in simulation.requests]
    assert "stop" in commands
    assert "kill" in commands
    assert "rm" in commands


def test_keyboard_interrupt_still_removes_container(tmp_path: Path) -> None:
    simulation = DockerSimulation("interrupt")
    backend = DockerBackend(executable=_executable(tmp_path), runner=simulation)
    with pytest.raises(KeyboardInterrupt):
        backend.run(_request(tmp_path))
    assert simulation.removed == [CONTAINER_ID]
    assert not simulation.container_exists


def test_cleanup_refuses_container_with_mismatched_labels(tmp_path: Path) -> None:
    simulation = DockerSimulation("label-mismatch")
    backend = DockerBackend(executable=_executable(tmp_path), runner=simulation)
    with pytest.raises(BackendError, match="exact ProofPatch labels"):
        backend.run(_request(tmp_path))
    assert simulation.removed == []
    assert simulation.container_exists


def test_abort_process_discovers_only_exact_label_bound_run_containers(tmp_path: Path) -> None:
    simulation = DockerSimulation()
    simulation.container_exists = True
    simulation.container_running = True
    simulation.labels = {
        "org.proofpatch.managed": "true",
        "org.proofpatch.run_id": RUN_ID,
        "org.proofpatch.phase": "patch",
    }
    backend = DockerBackend(executable=_executable(tmp_path), runner=simulation)

    backend.terminate_run(RUN_ID)

    assert not simulation.container_exists
    assert simulation.removed == [CONTAINER_ID]
    listing = next(request.argv for request in simulation.requests if request.argv[1] == "ps")
    assert f"label=org.proofpatch.run_id={RUN_ID}" in listing
    assert "label=org.proofpatch.managed=true" in listing
