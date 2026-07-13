"""Full Phase 6 lifecycle tests using real Git clones and fake protected agents."""

import hashlib
import json
from dataclasses import replace
from pathlib import Path

import pytest

from proofpatch.agents.base import AgentConfiguration
from proofpatch.errors import (
    AgentError,
    AgentTimeoutError,
    EvidenceIntegrityError,
    VerificationError,
)
from proofpatch.execution.process import ProcessOutcome
from proofpatch.git.client import GitClient
from proofpatch.models.execution import (
    REQUIRED_PROTECTION_FACTS,
    BackendDoctorResult,
    CommandOracleSpec,
    ExecutionPhase,
    ExecutionRequest,
    ExecutionResult,
    ExitCodeMatcherSpec,
    ExitCodeOperator,
    MountAccess,
    MountKind,
    NetworkPolicy,
    OracleExpectation,
    ProtectionAssessment,
    ProtectionLevel,
    ResolvedImage,
    ResourceLimits,
    TerminationKind,
)
from proofpatch.models.state import RunState
from proofpatch.services.coordinator import RunCoordinator
from proofpatch.services.data_directories import ApplicationDirectories
from proofpatch.services.evidence import read_canonical_json, write_canonical_json
from proofpatch.services.investigation import SetupCommand
from proofpatch.services.patching import PatchService
from proofpatch.services.workflow import WorkflowPlan, WorkflowService

DIGEST = "sha256:" + "c" * 64
IMAGE_ID = "sha256:" + "d" * 64
ASSET = b"raise SystemExit(1)\n"


class FakeAgentBackend:
    """Apply fake agent effects but return measured protected-backend facts."""

    def __init__(self, mode: str) -> None:
        self.mode = mode
        self.requests: list[ExecutionRequest] = []
        self.terminated: list[str] = []
        self.cleaned: list[str] = []

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
        exit_code: int | None = 0
        termination = TerminationKind.EXITED
        timed_out = False
        stdout = b"untrusted success claim"
        mounts = {mount.kind: mount for mount in request.mounts}
        if request.execution_id == "agent-version":
            assert request.environment == {}
            assert request.network is NetworkPolicy.NONE
            assert tuple(mounts) == (MountKind.WORKSPACE,)
            stdout = (
                b"2.1.201 (Claude Code)\n"
                if request.argv[0] == "claude"
                else b"codex-cli 0.139.0\n"
            )
        elif request.phase is ExecutionPhase.INVESTIGATION:
            assert mounts[MountKind.WORKSPACE].access is MountAccess.READ_ONLY
            assert mounts[MountKind.PROMPT].access is MountAccess.READ_ONLY
            assert mounts[MountKind.ISSUE].access is MountAccess.READ_ONLY
            reproduction = mounts[MountKind.REPRODUCTION].source
            output = mounts[MountKind.OUTPUT].source
            (reproduction / "reproduce.py").write_bytes(ASSET)
            (output / "failure-contract.json").write_text(json.dumps(_contract()), encoding="utf-8")
        elif request.phase is ExecutionPhase.BASELINE:
            assert mounts[MountKind.WORKSPACE].access is MountAccess.READ_ONLY
            exit_code = 1
            stdout = b"ReportedError\n"
        elif request.phase is ExecutionPhase.PATCH:
            assert mounts[MountKind.WORKSPACE].access is MountAccess.READ_WRITE
            assert mounts[MountKind.REPRODUCTION].access is MountAccess.READ_ONLY
            assert mounts[MountKind.PROMPT].access is MountAccess.READ_ONLY
            assert request.evidence_directory not in [mount.source for mount in request.mounts]
            if self.mode == "unexpected":
                raise RuntimeError("unexpected patch backend failure")
            output = mounts[MountKind.OUTPUT].source
            workspace = mounts[MountKind.WORKSPACE].source
            result_document = (
                {"summary": "missing required fields"}
                if self.mode == "invalid-result"
                else {
                    "schema_version": 1,
                    "summary": "Everything is fixed",
                    "root_cause": "Incorrect baseline value",
                    "changed_files": ["source.txt"],
                    "commands_run": [["fake-check"]],
                    "known_risks": [],
                }
            )
            (output / "patch-result.json").write_text(
                json.dumps(result_document),
                encoding="utf-8",
            )
            if self.mode not in {"empty", "failed", "timeout", "invalid-result"}:
                content = (
                    "attempt-one\n"
                    if self.mode == "retry-success" and request.execution_id == "patch-agent"
                    else "fixed\n"
                )
                (workspace / "source.txt").write_text(content, encoding="utf-8")
            if self.mode == "interrupt":
                raise KeyboardInterrupt
            if self.mode == "failed":
                exit_code = 9
            if self.mode == "timeout":
                exit_code = None
                termination = TerminationKind.TIMEOUT
                timed_out = True
        elif request.phase is ExecutionPhase.VERIFICATION:
            assert mounts[MountKind.WORKSPACE].access is MountAccess.READ_ONLY
            if self.mode == "interrupt-verification" and request.execution_id == "fixed-oracle":
                raise KeyboardInterrupt
            if request.execution_id == "fixed-oracle":
                exit_code = 1 if self.mode in {"fake-fix", "repeat", "retry-success"} else 0
            elif "fixed-oracle" in request.execution_id:
                exit_code = 1 if self.mode in {"fake-fix", "repeat"} else 0
            elif request.execution_id.startswith("regression-"):
                exit_code = 1 if self.mode == "regression" else 0
        elif request.phase is ExecutionPhase.SETUP and request.execution_id.startswith("final-"):
            exit_code = 1 if self.mode == "final-setup-failure" else 0
        protection = (
            ProtectionAssessment(
                level=ProtectionLevel.OBSERVATION_ONLY,
                satisfied=(),
                failures=(),
            )
            if self.mode == "unprotected-patch" and request.phase is ExecutionPhase.PATCH
            else _assessment()
        )
        return ExecutionResult(
            execution_id=request.execution_id,
            container_name=f"fake-{request.execution_id}",
            redacted_command=request.argv,
            outcome=ProcessOutcome(
                termination=termination,
                exit_code=exit_code,
                signal=None,
                duration_ms=7,
                timed_out=timed_out,
                cancelled=False,
                stdout=stdout,
                stderr=b"",
                truncated=False,
            ),
            protection=protection,
            cleanup_confirmed=True,
        )

    def terminate(self, execution_id: str) -> None:
        self.terminated.append(execution_id)

    def cleanup(self, execution_id: str) -> None:
        self.cleaned.append(execution_id)


def _assessment() -> ProtectionAssessment:
    return ProtectionAssessment(
        level=ProtectionLevel.PROTECTED,
        satisfied=tuple(sorted(REQUIRED_PROTECTION_FACTS)),
        failures=(),
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


def _contract() -> dict[str, object]:
    return {
        "schema_version": 1,
        "issue_summary": "Reported failure",
        "hypothesis": "The source contains an incorrect baseline value",
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


def _regression() -> CommandOracleSpec:
    return CommandOracleSpec(
        id="unit-tests",
        argv=("python", "-c", "raise SystemExit(0)"),
        timeout_seconds=20.0,
        expectation=OracleExpectation(
            exit_code=ExitCodeMatcherSpec(operator=ExitCodeOperator.EQUAL, value=0)
        ),
    )


def _plan(*, setup: bool = False) -> WorkflowPlan:
    return WorkflowPlan(
        agent=AgentConfiguration(
            command=("fake-agent", "--prompt", "{prompt_path}"),
            environment_allowlist=("AGENT_TOKEN",),
        ),
        agent_image=_image(),
        verifier_image=_image(),
        investigation_resources=_limits(),
        patch_resources=_limits(),
        verifier_resources=_limits(),
        agent_environment={"AGENT_TOKEN": "redacted-by-backend"},
        setup_commands=(SetupCommand("install", ("fake-setup",), 20.0),) if setup else (),
        regressions=(_regression(),),
        project_name="phase6-fixture",
        investigation_network=NetworkPolicy.AGENT_API,
        patch_network=NetworkPolicy.AGENT_API,
    )


def _git(git: GitClient, repository: Path, *arguments: str) -> bytes:
    return git.run(
        ["-C", str(repository), *arguments],
        cwd=repository,
        operation="Phase 6 test repository setup",
    ).stdout


def _service(
    tmp_path: Path,
    mode: str,
) -> tuple[WorkflowService, FakeAgentBackend, PatchService, Path]:
    git = GitClient()
    repository = tmp_path / "source"
    repository.mkdir()
    _git(git, repository, "init", "--initial-branch=main")
    _git(git, repository, "config", "user.name", "ProofPatch Test")
    _git(git, repository, "config", "user.email", "proofpatch@example.invalid")
    (repository / "source.txt").write_text("broken\n", encoding="utf-8")
    _git(git, repository, "add", "-A", "--")
    _git(git, repository, "commit", "-m", "baseline")
    coordinator = RunCoordinator(ApplicationDirectories(tmp_path / "data"))
    backend = FakeAgentBackend(mode)
    patching = PatchService(coordinator, git)
    return WorkflowService(coordinator, backend, patching=patching), backend, patching, repository


def test_successful_fix_completes_full_lifecycle_and_receipt_integrity(tmp_path: Path) -> None:
    service, backend, patching, repository = _service(tmp_path, "success")
    original_head = _git(patching.git, repository, "rev-parse", "HEAD")

    outcome = service.run(repository, "Reported failure", _plan())

    assert outcome.verified
    assert outcome.receipt is not None
    assert outcome.receipt.status == "verified"
    assert outcome.receipt.protection_level is ProtectionLevel.PROTECTED
    assert outcome.receipt.verification.reproduction_transition_passed
    assert outcome.receipt.verification.regressions_passed
    assert outcome.receipt_json is not None and outcome.receipt_json.is_file()
    assert outcome.receipt_markdown is not None and outcome.receipt_markdown.is_file()
    assert service.coordinator.status(outcome.run_id).state is RunState.VERIFIED
    assert _git(patching.git, repository, "rev-parse", "HEAD") == original_head
    assert _git(patching.git, repository, "status", "--porcelain=v1", "-z") == b""
    assert not service.coordinator.paths_for(outcome.run_id).workspaces.exists()
    assert [request.phase for request in backend.requests] == [
        ExecutionPhase.INVESTIGATION,
        ExecutionPhase.BASELINE,
        ExecutionPhase.PATCH,
        ExecutionPhase.VERIFICATION,
        ExecutionPhase.VERIFICATION,
    ]
    resumed = service.resume(outcome.run_id, _plan())
    assert resumed.receipt == outcome.receipt
    assert service.receipts.verify(outcome.run_id) == outcome.receipt
    assert outcome.receipt.patch is not None
    applied = patching.apply_verified(outcome.run_id)
    assert applied.patch_sha256 == outcome.receipt.patch.sha256
    assert service.coordinator.status(outcome.run_id).state is RunState.APPLIED
    assert (repository / "source.txt").read_text(encoding="utf-8") == "fixed\n"
    with pytest.raises(VerificationError, match="never resumed"):
        service.resume(outcome.run_id, _plan())


@pytest.mark.parametrize(
    ("adapter_name", "command", "credential", "version"),
    [
        ("claude", "claude", "ANTHROPIC_API_KEY", "2.1.201"),
        ("codex", "codex", "CODEX_API_KEY", "0.139.0"),
    ],
)
def test_provider_adapters_use_same_protected_lifecycle_and_record_version(
    tmp_path: Path,
    adapter_name: str,
    command: str,
    credential: str,
    version: str,
) -> None:
    service, backend, _patching, repository = _service(tmp_path, "success")
    plan = replace(
        _plan(),
        adapter_name=adapter_name,
        agent=AgentConfiguration((command,), (credential,)),
        agent_environment={credential: "redacted-by-backend"},
    )

    outcome = service.run(repository, "Reported failure", plan)

    assert outcome.verified
    assert backend.requests[0].execution_id == "agent-version"
    assert backend.requests[0].environment == {}
    metadata = read_canonical_json(service.coordinator.paths_for(outcome.run_id).agent_version)
    assert isinstance(metadata, dict)
    assert metadata["adapter"] == adapter_name
    assert metadata["agent_cli_version"] == version
    events = service.coordinator.status(outcome.run_id).events
    assert any(event.type == "agent.version_detected" for event in events)


def test_second_attempt_starts_fresh_and_receipt_contains_timeline(tmp_path: Path) -> None:
    service, backend, _patching, repository = _service(tmp_path, "retry-success")
    plan = replace(_plan(), maximum_attempts=2, retain_workspaces=True)

    outcome = service.run(repository, "Reported failure", plan)

    assert outcome.verified
    assert outcome.receipt is not None
    assert [attempt.status for attempt in outcome.receipt.attempts] == ["rejected", "verified"]
    assert outcome.receipt.attempts[0].rejection_code == "PP_REPRODUCTION_STILL_FAILS"
    patch_requests = [
        request for request in backend.requests if request.phase is ExecutionPhase.PATCH
    ]
    assert len(patch_requests) == 2
    roots = [
        next(mount.source for mount in request.mounts if mount.kind is MountKind.WORKSPACE)
        for request in patch_requests
    ]
    assert roots[0] != roots[1]
    assert all((root / "source.txt").is_file() for root in roots)
    assert outcome.receipt_markdown is not None
    markdown = outcome.receipt_markdown.read_text(encoding="utf-8")
    assert "## Attempt Timeline" in markdown
    assert "PP_REPRODUCTION_STILL_FAILS" in markdown


def test_repeated_patch_is_flagged_and_maximum_attempts_are_enforced(tmp_path: Path) -> None:
    service, backend, _patching, repository = _service(tmp_path, "repeat")

    outcome = service.run(repository, "Reported failure", replace(_plan(), maximum_attempts=2))

    assert outcome.state is RunState.REJECTED
    assert outcome.receipt is not None
    assert len(outcome.receipt.attempts) == 2
    assert "PP_PATCH_EXACT_REPEAT" in outcome.receipt.attempts[1].warning_codes
    assert "PP_HYPOTHESIS_REPEAT" in outcome.receipt.attempts[1].warning_codes
    assert (
        len([request for request in backend.requests if request.phase is ExecutionPhase.PATCH]) == 2
    )
    events = service.coordinator.status(outcome.run_id).events
    attempts = [event for event in events if event.type == "patch.attempt_completed"]
    assert len(attempts) == 2
    assert attempts[-1].payload["warning_codes"] == [
        "PP_PATCH_EXACT_REPEAT",
        "PP_HYPOTHESIS_REPEAT",
    ]


@pytest.mark.parametrize(
    ("mode", "code"),
    [
        ("fake-fix", "PP_REPRODUCTION_STILL_FAILS"),
        ("regression", "PP_REGRESSION_FAILED"),
        ("empty", "PP_PATCH_EMPTY"),
    ],
)
def test_fake_fix_regression_and_empty_patch_are_rejected(
    tmp_path: Path,
    mode: str,
    code: str,
) -> None:
    service, _backend, _patching, repository = _service(tmp_path, mode)

    outcome = service.run(repository, "Reported failure", _plan())

    assert not outcome.verified
    assert outcome.state is RunState.REJECTED
    assert outcome.receipt is not None
    assert outcome.receipt.rejection_code == code
    assert service.coordinator.status(outcome.run_id).state is RunState.REJECTED


@pytest.mark.parametrize(
    ("mode", "error_type", "code"),
    [
        ("failed", AgentError, "PP_AGENT_FAILED"),
        ("timeout", AgentTimeoutError, "PP_AGENT_TIMEOUT"),
    ],
)
def test_failed_and_timed_out_agents_never_reach_verification(
    tmp_path: Path,
    mode: str,
    error_type: type[AgentError],
    code: str,
) -> None:
    service, backend, _patching, repository = _service(tmp_path, mode)

    with pytest.raises(error_type):
        service.run(repository, "Reported failure", _plan())

    status = service.coordinator.list_runs()[0]
    assert status.state is RunState.REJECTED
    transition = [event for event in status.events if event.type == "run.state_changed"][-1]
    assert transition.payload["details"] == {"reason": code}
    assert all(request.phase is not ExecutionPhase.VERIFICATION for request in backend.requests)


@pytest.mark.parametrize("mode", ["invalid-result", "unprotected-patch"])
def test_invalid_agent_result_and_unprotected_execution_fail_closed(
    tmp_path: Path,
    mode: str,
) -> None:
    service, _backend, _patching, repository = _service(tmp_path, mode)
    with pytest.raises(AgentError):
        service.run(repository, "Reported failure", _plan())
    assert service.coordinator.list_runs()[0].state is RunState.REJECTED


def test_interrupted_patch_requires_confirmation_before_resume(tmp_path: Path) -> None:
    service, _backend, _patching, repository = _service(tmp_path, "interrupt")
    with pytest.raises(KeyboardInterrupt):
        service.run(repository, "Reported failure", _plan())
    run_id = service.coordinator.list_runs()[0].manifest.run_id
    assert service.coordinator.status(run_id).state is RunState.PATCHING

    with pytest.raises(AgentError, match="explicit confirmation"):
        service.resume(run_id, _plan())
    with pytest.raises(EvidenceIntegrityError, match="configuration changed"):
        service.resume(run_id, replace(_plan(), project_name="changed"))
    resumed = service.resume(run_id, _plan(), capture_surviving_patch=True)
    assert resumed.verified


def test_incomplete_final_verification_is_quarantined_and_recreated(tmp_path: Path) -> None:
    service, backend, _patching, repository = _service(tmp_path, "interrupt-verification")
    plan = replace(_plan(), retain_workspaces=True)
    with pytest.raises(KeyboardInterrupt):
        service.run(repository, "Reported failure", plan)
    run_id = service.coordinator.list_runs()[0].manifest.run_id
    assert service.coordinator.status(run_id).state is RunState.FINAL_VERIFYING
    backend.mode = "success"

    resumed = service.resume(run_id, plan)

    assert resumed.verified
    workspaces = service.coordinator.paths_for(run_id).workspaces
    assert any(
        path.name.startswith("final-verification-interrupted-") for path in workspaces.iterdir()
    )


def test_abort_stops_known_executions_and_persists_aborted_state(tmp_path: Path) -> None:
    service, _backend, _patching, repository = _service(tmp_path, "interrupt")
    with pytest.raises(KeyboardInterrupt):
        service.run(repository, "Reported failure", _plan())
    run_id = service.coordinator.list_runs()[0].manifest.run_id

    assert service.abort(run_id) is RunState.ABORTED
    assert service.coordinator.status(run_id).state is RunState.ABORTED
    with pytest.raises(VerificationError, match="cannot be aborted"):
        service.abort(run_id)


def test_unexpected_workflow_failure_records_error_and_cleans_workspace(tmp_path: Path) -> None:
    service, backend, _patching, repository = _service(tmp_path, "unexpected")

    with pytest.raises(RuntimeError, match="unexpected patch"):
        service.run(repository, "Reported failure", _plan())

    status = service.coordinator.list_runs()[0]
    assert status.state is RunState.ERROR
    assert any(event.type == "run.error" for event in status.events)
    assert not service.coordinator.paths_for(status.manifest.run_id).workspaces.exists()
    assert "patch-agent" in backend.terminated
    assert backend.terminated == [
        "investigation-1",
        "baseline-oracle",
        "patch-agent",
        "fixed-oracle",
    ]
    assert backend.cleaned == backend.terminated


def test_final_setup_failure_is_rejected_with_receipt(tmp_path: Path) -> None:
    service, _backend, _patching, repository = _service(tmp_path, "final-setup-failure")
    outcome = service.run(repository, "Reported failure", _plan(setup=True))
    assert outcome.receipt is not None
    assert outcome.receipt.rejection_code == "PP_SETUP_FAILED"


def test_receipt_tampering_blocks_apply(tmp_path: Path) -> None:
    service, _backend, patching, repository = _service(tmp_path, "success")
    outcome = service.run(repository, "Reported failure", _plan())
    assert outcome.receipt_json is not None and outcome.receipt is not None
    changed = outcome.receipt.model_copy(update={"issue_summary": "tampered"})
    write_canonical_json(
        outcome.receipt_json,
        changed.model_dump(mode="json"),
        exclusive=False,
    )
    with pytest.raises(EvidenceIntegrityError, match="binding"):
        patching.apply_verified(outcome.run_id)
    with pytest.raises(EvidenceIntegrityError, match="binding"):
        service.resume(outcome.run_id, _plan())


def test_receipt_verification_reconciles_resolved_image_identity(tmp_path: Path) -> None:
    service, _backend, _patching, repository = _service(tmp_path, "success")
    outcome = service.run(repository, "Reported failure", _plan())
    paths = service.coordinator.paths_for(outcome.run_id)
    plan = read_canonical_json(paths.workflow_plan)
    assert isinstance(plan, dict)
    agent = plan["agent_image"]
    assert isinstance(agent, dict)
    agent["digest"] = "sha256:" + "f" * 64
    write_canonical_json(paths.workflow_plan, plan, exclusive=False)

    with pytest.raises(EvidenceIntegrityError, match="image identity"):
        service.receipts.verify(outcome.run_id)


def test_receipt_claim_reconciliation_rejects_semantic_mismatches(tmp_path: Path) -> None:
    service, _backend, _patching, repository = _service(tmp_path, "success")
    outcome = service.run(repository, "Reported failure", _plan())
    assert outcome.receipt is not None and outcome.receipt.patch is not None
    receipt = outcome.receipt
    patch = receipt.patch
    assert patch is not None

    with pytest.raises(EvidenceIntegrityError, match="run state"):
        service.receipts._verify_claims(receipt, RunState.REJECTED)
    rejected = receipt.model_copy(update={"status": "rejected"})
    with pytest.raises(EvidenceIntegrityError, match="run state"):
        service.receipts._verify_claims(rejected, RunState.VERIFIED)
    bad_project = receipt.model_copy(
        update={"project": receipt.project.model_copy(update={"baseline_commit": "f" * 40})}
    )
    with pytest.raises(EvidenceIntegrityError, match="baseline claim"):
        service.receipts._verify_claims(bad_project, RunState.VERIFIED)
    bad_contract = receipt.model_copy(
        update={"contract": receipt.contract.model_copy(update={"sha256": "f" * 64})}
    )
    with pytest.raises(EvidenceIntegrityError, match="contract hash"):
        service.receipts._verify_claims(bad_contract, RunState.VERIFIED)
    bad_patch = receipt.model_copy(update={"patch": patch.model_copy(update={"sha256": "f" * 64})})
    with pytest.raises(EvidenceIntegrityError, match="patch claim"):
        service.receipts._verify_claims(bad_patch, RunState.VERIFIED)
    no_patch = receipt.model_copy(update={"patch": None})
    with pytest.raises(EvidenceIntegrityError, match="no patch"):
        service.receipts._verify_claims(no_patch, RunState.VERIFIED)
    with pytest.raises(EvidenceIntegrityError, match="no patch"):
        service.receipts._verify_verified_transition(no_patch)
    with pytest.raises(EvidenceIntegrityError, match="decision evidence"):
        service.receipts._verify_verified_transition(bad_patch)

    paths = service.coordinator.paths_for(outcome.run_id)
    workflow_plan = read_canonical_json(paths.workflow_plan)
    write_canonical_json(paths.workflow_plan, [], exclusive=False)
    with pytest.raises(EvidenceIntegrityError, match="workflow plan"):
        service.receipts._verify_image_identity(outcome.run_id)
    write_canonical_json(
        paths.workflow_plan, {"agent_image": {}, "verifier_image": None}, exclusive=False
    )
    with pytest.raises(EvidenceIntegrityError, match="resolved image"):
        service.receipts._verify_image_identity(outcome.run_id)
    write_canonical_json(paths.workflow_plan, workflow_plan, exclusive=False)

    service.coordinator.append_event(
        outcome.run_id,
        "receipt.created",
        payload={"status": "verified"},
    )
    with pytest.raises(EvidenceIntegrityError, match="exactly one"):
        service.receipts.verify(outcome.run_id)
