"""Live protected-backend smoke coverage for Docker-capable CI hosts."""

import _thread
import shutil
import subprocess
from pathlib import Path
from threading import Timer

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
    ResolvedImage,
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
            argv=(
                "/bin/sh",
                "-c",
                'test -n "$DOCKER_HOST" && echo proofpatch-docker-e2e',
            ),
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
            environment={"DOCKER_HOST": "tcp://127.0.0.1:1"},
            environment_allowlist=("DOCKER_HOST",),
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


@pytest.mark.docker_e2e
def test_live_investigation_source_is_read_only(tmp_path: Path) -> None:
    backend, image, original, evidence, workspace = _live_fixture(tmp_path)
    (workspace / "source.txt").write_text("baseline\n", encoding="utf-8")
    result = backend.run(
        _live_request(
            image=image,
            original=original,
            evidence=evidence,
            workspace=workspace,
            execution_id="docker-investigation-read-only",
            phase=ExecutionPhase.INVESTIGATION,
            access=MountAccess.READ_ONLY,
            argv=("/bin/sh", "-c", "printf hostile > /workspace/source.txt"),
        )
    )
    assert isinstance(result.outcome, ProcessOutcome)
    assert result.outcome.exit_code != 0
    assert (workspace / "source.txt").read_text(encoding="utf-8") == "baseline\n"
    assert result.cleanup_confirmed


@pytest.mark.docker_e2e
def test_live_patch_and_final_verification_use_distinct_workspaces(tmp_path: Path) -> None:
    backend, image, original, evidence, patch_workspace = _live_fixture(tmp_path)
    original_source = original / "source.txt"
    original_source.write_text("baseline\n", encoding="utf-8")
    patch_workspace.chmod(0o777)
    (patch_workspace / "source.txt").write_text("baseline\n", encoding="utf-8")
    (patch_workspace / "source.txt").chmod(0o666)
    patched = backend.run(
        _live_request(
            image=image,
            original=original,
            evidence=evidence,
            workspace=patch_workspace,
            execution_id="docker-patch-isolation",
            phase=ExecutionPhase.PATCH,
            access=MountAccess.READ_WRITE,
            argv=("/bin/sh", "-c", "printf '%s\\n' fixed > /workspace/source.txt"),
        )
    )
    assert isinstance(patched.outcome, ProcessOutcome)
    assert patched.outcome.exit_code == 0
    assert original_source.read_text(encoding="utf-8") == "baseline\n"
    assert (patch_workspace / "source.txt").read_text(encoding="utf-8") == "fixed\n"

    final_workspace = tmp_path / "final-workspace"
    final_workspace.mkdir()
    shutil.copy2(patch_workspace / "source.txt", final_workspace / "source.txt")
    verified = backend.run(
        _live_request(
            image=image,
            original=original,
            evidence=evidence,
            workspace=final_workspace,
            execution_id="docker-final-isolation",
            phase=ExecutionPhase.VERIFICATION,
            access=MountAccess.READ_ONLY,
            argv=("/bin/cat", "/workspace/source.txt"),
        )
    )
    assert isinstance(verified.outcome, ProcessOutcome)
    assert verified.outcome.exit_code == 0
    assert verified.outcome.stdout == b"fixed\n"
    assert patch_workspace != final_workspace
    for result in (patched, verified):
        assert all(str(original) not in argument for argument in result.redacted_command)
        assert all(str(evidence) not in argument for argument in result.redacted_command)
        assert result.cleanup_confirmed


@pytest.mark.docker_e2e
def test_live_keyboard_interrupt_removes_labeled_container(tmp_path: Path) -> None:
    backend, image, original, evidence, workspace = _live_fixture(tmp_path)
    interrupt = Timer(0.75, _thread.interrupt_main)
    interrupt.start()
    try:
        with pytest.raises(KeyboardInterrupt):
            backend.run(
                _live_request(
                    image=image,
                    original=original,
                    evidence=evidence,
                    workspace=workspace,
                    execution_id="docker-interruption",
                    phase=ExecutionPhase.VERIFICATION,
                    access=MountAccess.READ_ONLY,
                    argv=("/bin/sleep", "30"),
                )
            )
    finally:
        interrupt.cancel()
        interrupt.join(timeout=2.0)
    docker = shutil.which("docker")
    assert docker is not None
    listed = subprocess.run(  # noqa: S603 - test invokes the discovered Docker CLI without a shell
        [
            docker,
            "ps",
            "-aq",
            "--filter",
            "label=org.proofpatch.managed=true",
            "--filter",
            f"label=org.proofpatch.run_id={RUN_ID}",
        ],
        check=True,
        capture_output=True,
        timeout=10,
        shell=False,
    )
    assert listed.stdout.strip() == b""


def _live_fixture(
    tmp_path: Path,
) -> tuple[DockerBackend, ResolvedImage, Path, Path, Path]:
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
    return backend, image, original, evidence, workspace


def _live_request(
    *,
    image: ResolvedImage,
    original: Path,
    evidence: Path,
    workspace: Path,
    execution_id: str,
    phase: ExecutionPhase,
    access: MountAccess,
    argv: tuple[str, ...],
) -> ExecutionRequest:
    return ExecutionRequest(
        execution_id=execution_id,
        run_id=RUN_ID,
        phase=phase,
        image=image,
        argv=argv,
        network=NetworkPolicy.NONE,
        mounts=(
            DockerMount(
                source=workspace,
                destination="/workspace",
                kind=MountKind.WORKSPACE,
                access=access,
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
