"""End-to-end Phase 5 gate tests with real Git clones and a fake protected backend."""

import hashlib
import json
from dataclasses import replace
from pathlib import Path

import pytest

from proofpatch.backends.docker import _container_environment_file
from proofpatch.errors import ContractError, RepositoryError
from proofpatch.execution.docker_command import DockerCommandBuilder
from proofpatch.execution.process import ProcessOutcome
from proofpatch.git.client import GitClient
from proofpatch.git.clone import CloneKind
from proofpatch.models.execution import (
    REQUIRED_PROTECTION_FACTS,
    BackendDoctorResult,
    ExecutionPhase,
    ExecutionRequest,
    ExecutionResult,
    MountAccess,
    MountKind,
    NetworkPolicy,
    ProtectionAssessment,
    ProtectionLevel,
    ResolvedImage,
    ResourceLimits,
    TerminationKind,
)
from proofpatch.models.state import RunState
from proofpatch.services.coordinator import RunCoordinator
from proofpatch.services.data_directories import ApplicationDirectories
from proofpatch.services.investigation import (
    InvestigationOutcomeKind,
    InvestigationPlan,
    InvestigationService,
    SetupCommand,
)
from proofpatch.services.patching import PatchService

RUN_ID = "pp_20260713_555555555555"
DIGEST = "sha256:" + "a" * 64
IMAGE_ID = "sha256:" + "b" * 64
ASSET = b"raise SystemExit(1)\n"


class FakeProtectedBackend:
    """Simulate only container effects while retaining requests for policy assertions."""

    def __init__(self, mode: str = "contract", *, baseline_exit_code: int = 1) -> None:
        self.mode = mode
        self.baseline_exit_code = baseline_exit_code
        self.requests: list[ExecutionRequest] = []

    @property
    def protection_level(self) -> ProtectionLevel:
        return ProtectionLevel.PROTECTED

    def doctor(self) -> BackendDoctorResult:
        return BackendDoctorResult(
            docker_cli=True,
            daemon_responding=True,
            linux_containers=True,
        )

    def resolve_image(self, image: str, *, pull: bool = False) -> ResolvedImage:
        del image, pull
        return _image()

    def run(self, request: ExecutionRequest) -> ExecutionResult:
        self.requests.append(request)
        exit_code = 0
        stdout = b"untrusted natural-language success claim"
        if request.phase is ExecutionPhase.INVESTIGATION:
            mounts = {mount.kind: mount.source for mount in request.mounts}
            output = mounts[MountKind.OUTPUT]
            reproduction = mounts[MountKind.REPRODUCTION]
            if self.mode in {"contract", "both", "edit-source", "setup-failure"}:
                (reproduction / "reproduce.py").write_bytes(ASSET)
                (output / "failure-contract.json").write_text(
                    json.dumps(_contract()),
                    encoding="utf-8",
                )
            if self.mode in {"not-reproduced", "both"}:
                (output / "not-reproduced.json").write_text(
                    json.dumps(
                        {
                            "schema_version": 1,
                            "explanation": "Could not trigger the report",
                            "commands_attempted": [["python", "diagnose.py"]],
                        }
                    ),
                    encoding="utf-8",
                )
            if self.mode == "edit-source":
                workspace = mounts[MountKind.WORKSPACE]
                (workspace / "source.txt").write_text("agent edit\n", encoding="utf-8")
            if self.mode == "process-failure":
                exit_code = 9
        elif request.phase is ExecutionPhase.BASELINE:
            exit_code = self.baseline_exit_code
            stdout = b"ReportedError\n"
        elif request.phase is ExecutionPhase.SETUP and self.mode == "setup-failure":
            exit_code = 4
        protection = (
            ProtectionAssessment(
                level=ProtectionLevel.OBSERVATION_ONLY,
                satisfied=(),
                failures=(),
            )
            if self.mode == "unprotected"
            else ProtectionAssessment(
                level=ProtectionLevel.PROTECTED,
                satisfied=tuple(sorted(REQUIRED_PROTECTION_FACTS)),
                failures=(),
            )
        )
        return ExecutionResult(
            execution_id=request.execution_id,
            container_name=f"proofpatch-{request.execution_id}",
            redacted_command=request.argv,
            outcome=_outcome(exit_code, stdout),
            protection=protection,
            cleanup_confirmed=True,
        )

    def terminate(self, execution_id: str) -> None:
        del execution_id

    def cleanup(self, execution_id: str) -> None:
        del execution_id


def _outcome(exit_code: int, stdout: bytes) -> ProcessOutcome:
    return ProcessOutcome(
        termination=TerminationKind.EXITED,
        exit_code=exit_code,
        signal=None,
        duration_ms=5,
        timed_out=False,
        cancelled=False,
        stdout=stdout,
        stderr=b"",
        truncated=False,
    )


def _image() -> ResolvedImage:
    return ResolvedImage(
        requested_reference="example/runtime:latest",
        immutable_reference=f"example/runtime@{DIGEST}",
        digest=DIGEST,
        image_id=IMAGE_ID,
        architecture="amd64",
    )


def _limits() -> ResourceLimits:
    return ResourceLimits(
        timeout_seconds=30.0,
        memory_mb=256,
        cpus=1.0,
        pids=64,
        output_bytes=4096,
    )


def _plan(*, setup: bool = False) -> InvestigationPlan:
    return InvestigationPlan(
        investigator_argv=("fake-investigator",),
        investigator_image=_image(),
        verifier_image=_image(),
        investigation_resources=_limits(),
        baseline_resources=_limits(),
        investigator_environment={"AGENT_TOKEN": "agent-secret-value"},
        investigator_environment_allowlist=("AGENT_TOKEN",),
        setup_commands=(SetupCommand("install", ("python", "install.py"), 15.0),) if setup else (),
    )


def _contract() -> dict[str, object]:
    return {
        "schema_version": 1,
        "issue_summary": "Reported failure",
        "hypothesis": "The current behavior raises ReportedError",
        "oracle": {
            "id": "reported-failure",
            "type": "command",
            "argv": ["python", "/proofpatch/repro/reproduce.py"],
            "cwd": "/workspace",
            "timeout_seconds": 20.0,
            "environment": {},
            "baseline_expectation": {
                "exit_code": {"operator": "not_equal", "value": 0},
                "stdout": [],
                "stderr": [],
            },
            "fixed_expectation": {
                "exit_code": {"operator": "equal", "value": 0},
                "stdout": [],
                "stderr": [],
            },
        },
        "reproduction_assets": [
            {"path": "reproduce.py", "sha256": hashlib.sha256(ASSET).hexdigest()}
        ],
        "observed_failure_signature": {"kind": "exception", "value": "ReportedError"},
        "notes": "Minimal reproduction",
    }


def _git(git: GitClient, repository: Path, *arguments: str) -> bytes:
    return git.run(
        ["-C", str(repository), *arguments],
        cwd=repository,
        operation="Phase 5 test repository setup",
    ).stdout


def _repository(tmp_path: Path) -> tuple[GitClient, Path]:
    git = GitClient()
    repository = tmp_path / "source"
    repository.mkdir()
    _git(git, repository, "init", "--initial-branch=main")
    _git(git, repository, "config", "user.name", "ProofPatch Test")
    _git(git, repository, "config", "user.email", "proofpatch@example.invalid")
    (repository / "source.txt").write_text("original\n", encoding="utf-8")
    _git(git, repository, "add", "-A", "--")
    _git(git, repository, "commit", "-m", "baseline")
    return git, repository


def _service(
    tmp_path: Path,
    backend: FakeProtectedBackend,
) -> tuple[InvestigationService, PatchService, Path]:
    git, repository = _repository(tmp_path)
    coordinator = RunCoordinator(ApplicationDirectories(tmp_path / "data"))
    patching = PatchService(coordinator, git)
    return (
        InvestigationService(coordinator, backend, patching=patching),
        patching,
        repository,
    )


def test_valid_contract_is_independently_reproduced_and_unlocks_only_gate_state(
    tmp_path: Path,
) -> None:
    backend = FakeProtectedBackend()
    service, patching, repository = _service(tmp_path, backend)
    original_head = _git(patching.git, repository, "rev-parse", "HEAD")

    result = service.investigate(
        repository,
        "Reported failure",
        _plan(),
        run_id=RUN_ID,
    )

    assert result.kind is InvestigationOutcomeKind.BASELINE_REPRODUCED
    assert result.state is RunState.BASELINE_REPRODUCED
    assert result.baseline is not None and result.baseline.passed
    assert _git(patching.git, repository, "rev-parse", "HEAD") == original_head
    assert _git(patching.git, repository, "status", "--porcelain=v1", "-z") == b""
    investigation, baseline = backend.requests
    with _container_environment_file(investigation.environment) as environment_file:
        DockerCommandBuilder(Path("docker")).build(investigation, environment_file=environment_file)
    with _container_environment_file(baseline.environment) as environment_file:
        DockerCommandBuilder(Path("docker")).build(baseline, environment_file=environment_file)
    assert investigation.phase is ExecutionPhase.INVESTIGATION
    assert (
        next(mount for mount in investigation.mounts if mount.kind is MountKind.WORKSPACE).access
        is MountAccess.READ_ONLY
    )
    assert investigation.evidence_directory not in [mount.source for mount in investigation.mounts]
    assert baseline.phase is ExecutionPhase.BASELINE
    assert baseline.image == _plan().verifier_image
    assert baseline.network is NetworkPolicy.NONE
    assert "AGENT_TOKEN" not in baseline.environment
    assert (
        next(mount for mount in baseline.mounts if mount.kind is MountKind.REPRODUCTION).access
        is MountAccess.READ_ONLY
    )
    assert investigation.mounts[0].source != baseline.mounts[0].source

    status = service.coordinator.status(RUN_ID)
    event_types = [event.type for event in status.events]
    assert "investigation.contract_submitted" in event_types
    assert "contract.validated" in event_types
    assert "baseline.reproduced" in event_types


def test_baseline_that_does_not_match_contract_is_rejected_without_patch_session(
    tmp_path: Path,
) -> None:
    backend = FakeProtectedBackend(baseline_exit_code=0)
    service, patching, repository = _service(tmp_path, backend)
    result = service.investigate(repository, "Reported failure", _plan(), run_id=RUN_ID)

    assert result.kind is InvestigationOutcomeKind.BASELINE_NOT_REPRODUCED
    assert result.state is RunState.REJECTED
    assert service.coordinator.paths_for(RUN_ID).baseline_not_reproduced.is_file()
    with pytest.raises(RepositoryError):
        patching.create_clone(RUN_ID, CloneKind.PATCH)


def test_investigator_not_reproduced_outcome_never_unlocks_patching(tmp_path: Path) -> None:
    backend = FakeProtectedBackend("not-reproduced")
    service, patching, repository = _service(tmp_path, backend)
    result = service.investigate(repository, "Reported failure", _plan(), run_id=RUN_ID)

    assert result.kind is InvestigationOutcomeKind.INVESTIGATOR_NOT_REPRODUCED
    assert result.state is RunState.ERROR
    assert len(backend.requests) == 1
    with pytest.raises(RepositoryError):
        patching.create_clone(RUN_ID, CloneKind.PATCH)


@pytest.mark.parametrize("mode", ["natural-claim", "both", "process-failure"])
def test_natural_claim_ambiguous_files_and_failed_process_are_rejected(
    tmp_path: Path,
    mode: str,
) -> None:
    backend = FakeProtectedBackend(mode)
    service, patching, repository = _service(tmp_path, backend)
    with pytest.raises(ContractError):
        service.investigate(repository, "Reported failure", _plan(), run_id=RUN_ID)
    assert service.coordinator.status(RUN_ID).state is RunState.ERROR
    with pytest.raises(RepositoryError):
        patching.create_clone(RUN_ID, CloneKind.PATCH)


def test_defense_in_depth_detects_investigator_source_write(tmp_path: Path) -> None:
    backend = FakeProtectedBackend("edit-source")
    service, _patching, repository = _service(tmp_path, backend)
    with pytest.raises(ContractError, match="modified"):
        service.investigate(repository, "Reported failure", _plan(), run_id=RUN_ID)
    assert service.coordinator.status(RUN_ID).state is RunState.ERROR


def test_unprotected_backend_result_cannot_enter_contract_gate(tmp_path: Path) -> None:
    backend = FakeProtectedBackend("unprotected")
    service, _patching, repository = _service(tmp_path, backend)
    with pytest.raises(ContractError, match="container failed"):
        service.investigate(repository, "Reported failure", _plan(), run_id=RUN_ID)
    assert service.coordinator.status(RUN_ID).state is RunState.ERROR


def test_protected_setup_is_rejected_before_any_execution() -> None:
    with pytest.raises(ValueError, match="protected setup is unsupported"):
        _plan(setup=True)


def test_network_enabled_setup_is_rejected_even_without_commands() -> None:
    with pytest.raises(ValueError, match="protected setup is unsupported"):
        replace(_plan(), setup_network=NetworkPolicy.BRIDGE)
