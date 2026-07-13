"""Live protected-backend smoke coverage for Docker-capable CI hosts."""

from pathlib import Path

import pytest

from proofpatch.backends.docker import DockerBackend
from proofpatch.execution.process import ProcessOutcome
from proofpatch.models.execution import (
    DockerMount,
    ExecutionPhase,
    ExecutionRequest,
    MountAccess,
    MountKind,
    NetworkPolicy,
    ProtectionLevel,
    ResourceLimits,
)

RUN_ID = "pp_20260713_d0c0e2e00001"


@pytest.mark.docker_e2e
def test_live_docker_backend_enforces_protected_execution(tmp_path: Path) -> None:
    backend = DockerBackend()
    doctor = backend.doctor()
    if not doctor.healthy:
        pytest.skip(doctor.error or "Linux Docker is unavailable")
    image = backend.resolve_image("alpine:3.20", pull=True)
    original = tmp_path / "original"
    evidence = tmp_path / "evidence"
    workspace = tmp_path / "workspace"
    output = tmp_path / "output"
    for directory in (original, evidence, workspace, output):
        directory.mkdir()
    result = backend.run(
        ExecutionRequest(
            execution_id="docker-e2e",
            run_id=RUN_ID,
            phase=ExecutionPhase.VERIFICATION,
            image=image,
            argv=("/bin/echo", "proofpatch-docker-e2e"),
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
                timeout_seconds=20.0,
                memory_mb=128,
                cpus=1.0,
                pids=32,
                output_bytes=4096,
            ),
            original_repository=original,
            evidence_directory=evidence,
        )
    )
    assert isinstance(result.outcome, ProcessOutcome)
    assert result.outcome.exit_code == 0
    assert result.outcome.stdout == b"proofpatch-docker-e2e\n"
    assert result.cleanup_confirmed
    assert result.protection.level is ProtectionLevel.PROTECTED


@pytest.mark.docker_e2e
def test_live_docker_timeout_removes_labeled_container(tmp_path: Path) -> None:
    backend = DockerBackend()
    doctor = backend.doctor()
    if not doctor.healthy:
        pytest.skip(doctor.error or "Linux Docker is unavailable")
    image = backend.resolve_image("alpine:3.20", pull=True)
    original = tmp_path / "original"
    evidence = tmp_path / "evidence"
    workspace = tmp_path / "workspace"
    for directory in (original, evidence, workspace):
        directory.mkdir()
    result = backend.run(
        ExecutionRequest(
            execution_id="docker-timeout",
            run_id=RUN_ID,
            phase=ExecutionPhase.VERIFICATION,
            image=image,
            argv=("/bin/sleep", "30"),
            network=NetworkPolicy.NONE,
            mounts=(
                DockerMount(
                    source=workspace,
                    destination="/workspace",
                    kind=MountKind.WORKSPACE,
                    access=MountAccess.READ_ONLY,
                ),
            ),
            environment={},
            environment_allowlist=(),
            resources=ResourceLimits(
                timeout_seconds=0.5,
                memory_mb=128,
                cpus=1.0,
                pids=32,
                output_bytes=4096,
            ),
            original_repository=original,
            evidence_directory=evidence,
        )
    )
    assert isinstance(result.outcome, ProcessOutcome)
    assert result.outcome.timed_out
    assert result.cleanup_confirmed
