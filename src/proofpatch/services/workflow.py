"""Controller-owned Phase 6 investigation, patch, verification, and receipt lifecycle."""

import hashlib
import os
from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path
from typing import cast

from pydantic import ValidationError

from proofpatch import __version__
from proofpatch.agents.base import AgentConfiguration, AgentPhaseContext
from proofpatch.agents.registry import get_agent_adapter
from proofpatch.backends.base import ExecutionBackend, RunTerminatingBackend
from proofpatch.errors import (
    AgentError,
    AgentTimeoutError,
    BackendError,
    CleanupError,
    EvidenceIntegrityError,
    PatchError,
    ProofPatchError,
    VerificationError,
)
from proofpatch.execution.process import ProcessOutcome
from proofpatch.git.clone import CloneKind, IndependentClone
from proofpatch.git.diff import validate_patch_policy_patterns
from proofpatch.models.agent import PatchResult
from proofpatch.models.attempt import (
    AttemptRecord,
    AttemptStatus,
    PatchFingerprint,
    SimilarityWarning,
)
from proofpatch.models.common import JsonValue, format_utc_timestamp
from proofpatch.models.contract import FailureContract
from proofpatch.models.environment import VerifierEnvironmentIdentity
from proofpatch.models.execution import (
    ENVIRONMENT_NAME,
    CommandOracleSpec,
    DockerMount,
    ExecutionPhase,
    ExecutionRequest,
    MountAccess,
    MountKind,
    NetworkPolicy,
    OracleEvaluation,
    OraclePhase,
    ProtectionAssessment,
    ProtectionLevel,
    ResolvedImage,
    ResourceLimits,
    TerminationKind,
)
from proofpatch.models.patch import PatchRecord
from proofpatch.models.receipt import (
    ReceiptAttempt,
    ReceiptBaseline,
    ReceiptContract,
    ReceiptEvidence,
    ReceiptPatch,
    ReceiptProject,
    ReceiptVerification,
    VerificationReceipt,
)
from proofpatch.models.run import RunPaths
from proofpatch.models.state import VALID_TRANSITIONS, RunState
from proofpatch.oracles.base import OracleExecutionResult
from proofpatch.oracles.command import CommandOracle
from proofpatch.security.workspace import workspace_content_sha256
from proofpatch.services.cleanup import remove_owned_tree
from proofpatch.services.contracts import ContractService
from proofpatch.services.coordinator import RunCoordinator
from proofpatch.services.environment import (
    build_verifier_environment_identity,
    merge_verifier_environment,
    verify_verifier_environment_identity,
)
from proofpatch.services.evidence import (
    canonical_json_bytes,
    read_canonical_json,
    read_json_document,
    write_canonical_json,
)
from proofpatch.services.identifiers import generate_run_id
from proofpatch.services.investigation import (
    InvestigationOutcome,
    InvestigationOutcomeKind,
    InvestigationPlan,
    InvestigationService,
    SetupCommand,
    _limits_with_timeout,
    _protected_process_outcome,
    _write_private_file,
)
from proofpatch.services.locks import RepositoryLock
from proofpatch.services.patch_analysis import AttemptStore, PatchAnalysisService
from proofpatch.services.patching import PatchService
from proofpatch.services.receipt import ReceiptService

PROMPT_PATH = "/proofpatch/prompt.md"
ISSUE_PATH = "/proofpatch/issue.md"
WORKSPACE_PATH = "/workspace"
OUTPUT_PATH = "/proofpatch/out"
REPRODUCTION_PATH = "/proofpatch/repro"


@dataclass(frozen=True, slots=True)
class WorkflowPlan:
    """Validated controller inputs for one generic protected workflow."""

    agent: AgentConfiguration
    agent_image: ResolvedImage
    verifier_image: ResolvedImage
    investigation_resources: ResourceLimits
    patch_resources: ResourceLimits
    verifier_resources: ResourceLimits
    agent_environment: dict[str, str]
    adapter_name: str = "generic"
    contract_environment_allowlist: tuple[str, ...] = ()
    setup_commands: tuple[SetupCommand, ...] = ()
    setup_environment: dict[str, str] = field(default_factory=dict)
    regressions: tuple[CommandOracleSpec, ...] = ()
    allowed_patch_paths: tuple[str, ...] = ("**",)
    denied_patch_paths: tuple[str, ...] = ()
    maximum_patch_bytes: int = 20 * 1024 * 1024
    maximum_changed_files: int = 100
    maximum_repository_bytes: int = 2 * 1024 * 1024 * 1024
    maximum_attempts: int = 1
    flag_test_changes: bool = True
    retain_workspaces: bool = False
    project_name: str | None = None
    investigation_network: NetworkPolicy = NetworkPolicy.AGENT_API
    patch_network: NetworkPolicy = NetworkPolicy.AGENT_API
    setup_network: NetworkPolicy = NetworkPolicy.NONE

    def __post_init__(self) -> None:
        adapter = get_agent_adapter(self.adapter_name)
        adapter.validate_configuration(self.agent)
        if set(self.agent_environment).difference(self.agent.environment_allowlist):
            raise ValueError("Agent environment contains a non-allowlisted name")
        missing = (
            adapter.required_secret_names(self.agent).difference(self.agent_environment)
            if adapter.name != "generic"
            else set()
        )
        if missing:
            raise ValueError(
                "Required agent credentials are missing: " + ", ".join(sorted(missing))
            )
        for environment in (self.agent_environment, self.setup_environment):
            if len(environment) > 128 or any(
                ENVIRONMENT_NAME.fullmatch(name) is None for name in environment
            ):
                raise ValueError("Workflow environment contains invalid or excessive names")
            if any(
                "\0" in item or "\r" in item or "\n" in item
                for pair in environment.items()
                for item in pair
            ):
                raise ValueError("Workflow environment must be NUL-free and single-line")
        if any(spec.baseline_expectation is not None for spec in self.regressions):
            raise ValueError("Regression oracles cannot contain reproduction expectations")
        identifiers = [spec.id for spec in self.regressions]
        if len(self.regressions) > 128 or len(self.setup_commands) > 128:
            raise ValueError("Workflow supports at most 128 setup commands and regressions")
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("Regression oracle IDs must be unique")
        if (
            self.setup_commands
            or self.setup_environment
            or self.setup_network is not NetworkPolicy.NONE
        ):
            raise ValueError(
                "protected setup is unsupported; bake dependencies into the immutable image"
            )
        if self.verifier_image.os != "linux" or self.verifier_image.architecture != "amd64":
            raise ValueError("Protected verification requires a linux/amd64 verifier image")
        if self.project_name is not None and not self.project_name.strip():
            raise ValueError("Project name cannot be blank")
        if (
            self.maximum_patch_bytes <= 0
            or self.maximum_changed_files <= 0
            or self.maximum_repository_bytes <= 0
        ):
            raise ValueError("Patch limits must be positive")
        validate_patch_policy_patterns(self.allowed_patch_paths, self.denied_patch_paths)
        if self.maximum_attempts < 1 or self.maximum_attempts > 10:
            raise ValueError("Maximum attempts must be between 1 and 10")


@dataclass(frozen=True, slots=True)
class WorkflowOutcome:
    run_id: str
    state: RunState
    receipt: VerificationReceipt | None
    receipt_json: Path | None
    receipt_markdown: Path | None

    @property
    def verified(self) -> bool:
        return self.state is RunState.VERIFIED


@dataclass(frozen=True, slots=True)
class _AttemptVerification:
    evaluations: tuple[OracleEvaluation, ...]
    transition_passed: bool
    regressions_passed: bool
    rejection_code: str | None
    assessment: ProtectionAssessment | None

    @property
    def verified(self) -> bool:
        return self.rejection_code is None


class WorkflowService:
    """Make all authorization decisions outside untrusted agent containers."""

    def __init__(
        self,
        coordinator: RunCoordinator,
        backend: ExecutionBackend,
        *,
        patching: PatchService | None = None,
        contracts: ContractService | None = None,
    ) -> None:
        self.coordinator = coordinator
        self.backend = backend
        self.patching = PatchService(coordinator) if patching is None else patching
        self.contracts = ContractService() if contracts is None else contracts
        self.investigations = InvestigationService(
            coordinator,
            backend,
            patching=self.patching,
            contracts=self.contracts,
        )
        self.oracle = CommandOracle()
        self.receipts = ReceiptService(coordinator)
        self.analysis = PatchAnalysisService()

    def run(
        self,
        repository: Path,
        issue_summary: str,
        plan: WorkflowPlan,
        *,
        run_id: str | None = None,
    ) -> WorkflowOutcome:
        """Perform the complete protected lifecycle using one reviewed adapter."""

        selected_run_id = generate_run_id() if run_id is None else run_id
        self.patching.repositories.max_repository_bytes = plan.maximum_repository_bytes
        snapshot = self.patching.repositories.discover(repository)
        with RepositoryLock(
            self.coordinator.directories.locks / "lifecycle",
            snapshot.repository_id,
            selected_run_id,
        ) as lifecycle_lock:
            try:
                outcome = self._run_while_locked(
                    repository,
                    issue_summary,
                    plan,
                    selected_run_id,
                    lifecycle_lock,
                )
            except BaseException as error:
                self._handle_failure(selected_run_id, plan, error)
                raise
        return outcome

    def _run_while_locked(
        self,
        repository: Path,
        issue_summary: str,
        plan: WorkflowPlan,
        run_id: str,
        lifecycle_lock: RepositoryLock,
    ) -> WorkflowOutcome:
        lifecycle_lock.assert_held()
        adapter = get_agent_adapter(plan.adapter_name)
        investigation_invocation = adapter.build_investigation_invocation(
            plan.agent,
            self._agent_context(plan.agent_environment),
        )
        outcome = self.investigations.investigate(
            repository,
            issue_summary,
            InvestigationPlan(
                investigator_argv=investigation_invocation.argv,
                investigator_image=plan.agent_image,
                verifier_image=plan.verifier_image,
                investigation_resources=plan.investigation_resources,
                baseline_resources=plan.verifier_resources,
                investigator_environment=dict(investigation_invocation.environment),
                investigator_environment_allowlist=plan.agent.environment_allowlist,
                contract_environment_allowlist=plan.contract_environment_allowlist,
                setup_commands=plan.setup_commands,
                setup_environment=plan.setup_environment,
                regressions=plan.regressions,
                maximum_repository_bytes=plan.maximum_repository_bytes,
                investigation_network=plan.investigation_network,
                setup_network=plan.setup_network,
                adapter_name=adapter.name,
                adapter_version=adapter.adapter_version,
                version_probe=adapter.build_version_probe(plan.agent),
            ),
            run_id=run_id,
            resolved_configuration=self._plan_evidence(plan),
        )
        lifecycle_lock.assert_held()
        self.coordinator.append_event(
            run_id,
            "repository.lifecycle_lock_confirmed",
            payload={"repository_id": lifecycle_lock.repository_id},
        )
        if outcome.kind is not InvestigationOutcomeKind.BASELINE_REPRODUCED:
            return WorkflowOutcome(outcome.run_id, outcome.state, None, None, None)
        return self._patch_and_verify(issue_summary, plan, outcome)

    def resume(
        self,
        run_id: str,
        plan: WorkflowPlan,
        *,
        capture_surviving_patch: bool = False,
    ) -> WorkflowOutcome:
        """Resume only from evidence-backed checkpoints using conservative recovery rules."""

        status = self.coordinator.status(run_id)
        self.patching.repositories.max_repository_bytes = plan.maximum_repository_bytes
        snapshot = self.patching.load_repository(run_id)
        with RepositoryLock(
            self.coordinator.directories.locks / "lifecycle",
            snapshot.repository_id,
            run_id,
        ) as lifecycle_lock:
            try:
                return self._resume_while_locked(
                    run_id,
                    plan,
                    status.state,
                    capture_surviving_patch,
                    lifecycle_lock,
                )
            except BaseException as error:
                self._handle_failure(run_id, plan, error)
                raise

    def _resume_while_locked(
        self,
        run_id: str,
        plan: WorkflowPlan,
        state: RunState,
        capture_surviving_patch: bool,
        lifecycle_lock: RepositoryLock,
    ) -> WorkflowOutcome:
        lifecycle_lock.assert_held()
        contract, baseline, assessment = self._load_baseline_checkpoint(run_id, plan)
        issue_summary = contract.issue_summary
        outcome = InvestigationOutcome(
            run_id=run_id,
            kind=InvestigationOutcomeKind.BASELINE_REPRODUCED,
            state=RunState.BASELINE_REPRODUCED,
            contract_sha256=self._contract_hash(contract),
            baseline=baseline,
            protection=assessment,
        )
        if state is RunState.BASELINE_REPRODUCED:
            return self._patch_and_verify(issue_summary, plan, outcome)
        if state is RunState.PATCHING:
            if not capture_surviving_patch:
                raise AgentError(
                    "An interrupted patch workspace requires explicit confirmation before capture",
                    remediation="Re-run resume with --capture-surviving-patch after inspecting it.",
                )
            clone = self._load_patch_clone(run_id)
            patch = self._capture_or_reject(run_id, clone, plan, outcome, issue_summary)
            if patch is None:
                return self._finish_rejected(
                    run_id, issue_summary, plan, outcome, None, "PP_PATCH_EMPTY"
                )
            return self._complete_resumed_attempt(run_id, issue_summary, plan, outcome, patch)
        if state in {RunState.PATCH_CAPTURED, RunState.FINAL_VERIFYING}:
            patch = self.patching.load_patch(run_id)
            return self._complete_resumed_attempt(run_id, issue_summary, plan, outcome, patch)
        if state is RunState.VERIFIED:
            return self._existing_receipt(run_id)
        if state is RunState.APPLIED:
            raise VerificationError("An APPLIED run is never resumed or applied automatically")
        raise VerificationError(
            f"Run cannot be resumed safely from {state.value}",
            remediation=(
                "Inspect the evidence and start a new run if no supported checkpoint exists."
            ),
        )

    def _complete_resumed_attempt(
        self,
        run_id: str,
        issue_summary: str,
        plan: WorkflowPlan,
        investigation: InvestigationOutcome,
        patch: PatchRecord,
    ) -> WorkflowOutcome:
        paths = self.coordinator.paths_for(run_id)
        store = AttemptStore(paths.attempts)
        previous = store.load()
        attempt = len(previous) + 1
        if attempt > plan.maximum_attempts:
            raise VerificationError("The configured maximum patch attempt count has been reached")
        root_cause = "interrupted agent result unavailable"
        if paths.patch_result.exists():
            try:
                root_cause = PatchResult.model_validate(
                    read_canonical_json(paths.patch_result)
                ).root_cause
            except (ValidationError, EvidenceIntegrityError) as error:
                raise EvidenceIntegrityError("Interrupted patch result is invalid") from error
        self._record_test_file_changes(run_id, patch, plan.flag_test_changes)
        fingerprint, hypothesis_sha, warnings = self._analyze_attempt(
            run_id,
            patch,
            root_cause,
            investigation,
            previous,
        )
        verification = self._verify_attempt(run_id, plan, investigation, patch, attempt)
        record = AttemptRecord(
            attempt=attempt,
            status=(AttemptStatus.VERIFIED if verification.verified else AttemptStatus.REJECTED),
            started_at_utc=format_utc_timestamp(),
            completed_at_utc=format_utc_timestamp(),
            patch_sha256=patch.patch_sha256,
            fingerprint=fingerprint,
            hypothesis_sha256=hypothesis_sha,
            changed_paths=tuple(sorted(change.path for change in patch.changed_files)),
            warnings=warnings,
            rejection_code=verification.rejection_code,
            reproduction_transition_passed=verification.transition_passed,
            regressions_passed=verification.regressions_passed,
        )
        store.append(record)
        self._record_attempt(run_id, record)
        if verification.verified or attempt == plan.maximum_attempts:
            return self._finish(
                run_id,
                issue_summary,
                plan,
                investigation,
                patch,
                list(verification.evaluations),
                verification.transition_passed,
                verification.regressions_passed,
                verification.rejection_code,
                verification.assessment,
            )
        self._archive_current_patch(paths, attempt)
        return self._patch_and_verify(issue_summary, plan, investigation)

    def abort(self, run_id: str) -> RunState:
        """Best-effort stop known phase executions, then persist ABORTED when valid."""

        status = self.coordinator.status(run_id)
        self._terminate_backend_run(run_id)
        if status.state not in {
            RunState.PREFLIGHT,
            RunState.INVESTIGATING,
            RunState.BASELINE_VERIFYING,
            RunState.PATCHING,
            RunState.FINAL_VERIFYING,
        }:
            raise VerificationError(f"Run cannot be aborted from {status.state.value}")
        self.coordinator.append_event(run_id, "run.abort_requested")
        self.coordinator.transition(run_id, RunState.ABORTED)
        return RunState.ABORTED

    def _handle_failure(
        self,
        run_id: str,
        plan: WorkflowPlan,
        error: BaseException,
    ) -> None:
        with suppress(BackendError):
            self._terminate_backend_run(run_id)
        try:
            status = self.coordinator.status(run_id)
        except Exception:
            return
        if isinstance(error, (KeyboardInterrupt, SystemExit)):
            target: RunState | None = None
        elif isinstance(error, (BackendError, EvidenceIntegrityError)) or not isinstance(
            error, ProofPatchError
        ):
            target = RunState.ERROR
        else:
            target = None
        if target is not None and target in VALID_TRANSITIONS[status.state]:
            self.coordinator.append_event(
                run_id,
                "run.aborted" if target is RunState.ABORTED else "run.error",
                payload={
                    "error_code": getattr(error, "error_code", "PP_INTERNAL_ERROR"),
                    "error_type": type(error).__name__,
                },
            )
            self.coordinator.transition(run_id, target)
            status = self.coordinator.status(run_id)
        if (
            not isinstance(error, (KeyboardInterrupt, SystemExit))
            and not plan.retain_workspaces
            and status.state
            in {
                RunState.REJECTED,
                RunState.ERROR,
                RunState.ABORTED,
            }
        ):
            paths = self.coordinator.paths_for(run_id)
            if paths.workspaces.exists():
                try:
                    remove_owned_tree(self.coordinator.directories.data, paths.workspaces)
                except CleanupError:
                    self.coordinator.append_event(
                        run_id,
                        "cleanup.failed",
                        payload={"target": "workspaces", "error_code": "PP_CLEANUP_FAILED"},
                    )

    def _terminate_backend_run(self, run_id: str) -> None:
        if isinstance(self.backend, RunTerminatingBackend):
            self.backend.terminate_run(run_id)
            return
        for execution_id in (
            "investigation-1",
            "baseline-oracle",
            "patch-agent",
            "fixed-oracle",
        ):
            self.backend.terminate(execution_id)
            self.backend.cleanup(execution_id)

    def _patch_and_verify(
        self,
        issue_summary: str,
        plan: WorkflowPlan,
        investigation: InvestigationOutcome,
    ) -> WorkflowOutcome:
        run_id = investigation.run_id
        self._require_baseline_outcome(investigation)
        snapshot = self.patching.load_repository(run_id)
        self.patching.repositories.assert_matches(snapshot)
        self._validate_environment_identity(run_id, plan)
        paths = self.coordinator.paths_for(run_id)
        store = AttemptStore(paths.attempts)
        previous = store.load()
        if len(previous) >= plan.maximum_attempts:
            raise VerificationError("The configured maximum patch attempt count has been reached")

        for attempt in range(len(previous) + 1, plan.maximum_attempts + 1):
            self.coordinator.transition(
                run_id,
                RunState.PATCH_PREPARING,
                details={"attempt": attempt, "maximum_attempts": plan.maximum_attempts},
            )
            clone = self.patching.create_clone(
                run_id,
                CloneKind.PATCH,
                workspace_name=(None if attempt == 1 else f"patch-attempt-{attempt:03d}"),
            )
            write_canonical_json(
                paths.patch / "clone.json",
                {
                    "kind": clone.kind.value,
                    "root": clone.root.relative_to(paths.root).as_posix(),
                    "git_directory": clone.git_directory.relative_to(paths.root).as_posix(),
                    "baseline_commit": clone.baseline_commit,
                    "configuration_sha256": clone.configuration_sha256,
                    "attempt": attempt,
                },
            )
            self.coordinator.transition(run_id, RunState.PATCHING, details={"attempt": attempt})
            started_at = format_utc_timestamp()
            patch, agent_result = self._run_patch_agent(
                run_id,
                issue_summary,
                plan,
                investigation,
                clone,
                attempt,
                previous,
            )
            if patch is None:
                return self._finish_rejected(
                    run_id, issue_summary, plan, investigation, None, "PP_PATCH_EMPTY"
                )
            self._record_test_file_changes(run_id, patch, plan.flag_test_changes)
            fingerprint, hypothesis_sha, warnings = self._analyze_attempt(
                run_id,
                patch,
                agent_result.root_cause,
                investigation,
                previous,
            )
            verification = self._verify_attempt(
                run_id,
                plan,
                investigation,
                patch,
                attempt,
            )
            record = AttemptRecord(
                attempt=attempt,
                status=(
                    AttemptStatus.VERIFIED if verification.verified else AttemptStatus.REJECTED
                ),
                started_at_utc=started_at,
                completed_at_utc=format_utc_timestamp(),
                patch_sha256=patch.patch_sha256,
                fingerprint=fingerprint,
                hypothesis_sha256=hypothesis_sha,
                changed_paths=tuple(sorted(change.path for change in patch.changed_files)),
                warnings=warnings,
                rejection_code=verification.rejection_code,
                reproduction_transition_passed=verification.transition_passed,
                regressions_passed=verification.regressions_passed,
            )
            store.append(record)
            self._record_attempt(run_id, record)
            previous = (*previous, record)
            if verification.verified or attempt == plan.maximum_attempts:
                return self._finish(
                    run_id,
                    issue_summary,
                    plan,
                    investigation,
                    patch,
                    list(verification.evaluations),
                    verification.transition_passed,
                    verification.regressions_passed,
                    verification.rejection_code,
                    verification.assessment,
                )
            self._archive_current_patch(paths, attempt)

        raise VerificationError("Patch attempt loop terminated without an outcome")

    def _run_patch_agent(
        self,
        run_id: str,
        issue_summary: str,
        plan: WorkflowPlan,
        investigation: InvestigationOutcome,
        clone: IndependentClone,
        attempt: int,
        previous: tuple[AttemptRecord, ...],
    ) -> tuple[PatchRecord | None, PatchResult]:
        paths = self.coordinator.paths_for(run_id)
        contract = self._load_contract(run_id, investigation.contract_sha256)
        baseline = self._require_baseline_outcome(investigation)
        reproduction = paths.workspaces / _attempt_name("patch-reproduction", attempt)
        output = paths.workspaces / _attempt_name("patch-output", attempt)
        controller_input = paths.workspaces / _attempt_name("patch-input", attempt)
        self.contracts.copy_approved_assets(contract, paths.reproduction_assets, reproduction)
        output.mkdir(mode=0o700, exist_ok=False)
        controller_input.mkdir(mode=0o700, exist_ok=False)
        prompt = controller_input / "prompt.md"
        issue = controller_input / "issue.md"
        _write_private_file(
            prompt,
            render_patch_prompt(
                issue_summary,
                contract,
                baseline,
                previous_failures=_previous_failure_summary(previous),
            ).encode("utf-8"),
        )
        _write_private_file(issue, issue_summary.encode("utf-8"))
        adapter = get_agent_adapter(plan.adapter_name)
        invocation = adapter.build_patch_invocation(
            plan.agent,
            self._agent_context(plan.agent_environment),
        )
        self.coordinator.append_event(
            run_id,
            "patch.agent_started",
            payload={
                "adapter": adapter.name,
                "adapter_version": adapter.adapter_version,
                "attempt": attempt,
            },
        )
        try:
            result = self.backend.run(
                ExecutionRequest(
                    execution_id=_attempt_name("patch-agent", attempt),
                    run_id=run_id,
                    phase=ExecutionPhase.PATCH,
                    image=plan.agent_image,
                    argv=invocation.argv,
                    network=plan.patch_network,
                    mounts=(
                        DockerMount(
                            source=clone.root,
                            destination=WORKSPACE_PATH,
                            kind=MountKind.WORKSPACE,
                            access=MountAccess.READ_WRITE,
                        ),
                        DockerMount(
                            source=reproduction,
                            destination=REPRODUCTION_PATH,
                            kind=MountKind.REPRODUCTION,
                            access=MountAccess.READ_ONLY,
                        ),
                        DockerMount(
                            source=output,
                            destination=OUTPUT_PATH,
                            kind=MountKind.OUTPUT,
                            access=MountAccess.READ_WRITE,
                        ),
                        DockerMount(
                            source=prompt,
                            destination=PROMPT_PATH,
                            kind=MountKind.PROMPT,
                            access=MountAccess.READ_ONLY,
                        ),
                        DockerMount(
                            source=issue,
                            destination=ISSUE_PATH,
                            kind=MountKind.ISSUE,
                            access=MountAccess.READ_ONLY,
                        ),
                    ),
                    environment=dict(invocation.environment),
                    environment_allowlist=plan.agent.environment_allowlist,
                    resources=plan.patch_resources,
                    original_repository=Path(self.patching.load_repository(run_id).repository_root),
                    evidence_directory=paths.root,
                    disposable_work_directory=paths.workspaces,
                )
            )
            process = _protected_process_outcome(result)
        except BackendError as error:
            self._reject_patch(run_id, "PP_AGENT_FAILED")
            raise AgentError("Protected patch agent execution failed") from error
        self._persist_agent_logs(run_id, process, attempt=attempt)
        self.coordinator.append_event(
            run_id,
            "patch.agent_exited",
            payload={
                "termination": process.termination.value,
                "exit_code": process.exit_code,
                "timed_out": process.timed_out,
                "truncated": process.truncated,
                "attempt": attempt,
            },
        )
        if process.timed_out or process.termination is TerminationKind.TIMEOUT:
            self._reject_patch(run_id, "PP_AGENT_TIMEOUT")
            raise AgentTimeoutError("Patch agent timed out")
        if process.termination is not TerminationKind.EXITED or process.exit_code is None:
            self._reject_patch(run_id, "PP_AGENT_FAILED")
            raise AgentError("Patch agent did not exit normally")
        classification = adapter.classify_exit(
            process.exit_code,
            process.stdout.decode("utf-8", errors="replace"),
            process.stderr.decode("utf-8", errors="replace"),
        )
        if classification.value != "succeeded":
            self._reject_patch(run_id, "PP_AGENT_FAILED")
            raise AgentError("Patch agent reported failure")
        agent_result = self._capture_patch_result(
            run_id, output / "patch-result.json", attempt=attempt
        )
        self.patching.repositories.assert_matches(self.patching.load_repository(run_id))
        return (
            self._capture_or_reject(run_id, clone, plan, investigation, issue_summary),
            agent_result,
        )

    def _capture_or_reject(
        self,
        run_id: str,
        clone: IndependentClone,
        plan: WorkflowPlan,
        investigation: InvestigationOutcome,
        issue_summary: str,
    ) -> PatchRecord | None:
        del investigation, issue_summary
        try:
            return self.patching.capture(
                run_id,
                clone,
                allowed_paths=plan.allowed_patch_paths,
                denied_paths=plan.denied_patch_paths,
                max_patch_bytes=plan.maximum_patch_bytes,
                max_changed_files=plan.maximum_changed_files,
            )
        except PatchError as error:
            code = error.error_code
            self._reject_patch(run_id, code)
            if code == "PP_PATCH_EMPTY":
                return None
            raise

    def _verify_attempt(
        self,
        run_id: str,
        plan: WorkflowPlan,
        investigation: InvestigationOutcome,
        patch: PatchRecord,
        attempt: int,
    ) -> _AttemptVerification:
        state = self.coordinator.status(run_id).state
        if state is RunState.PATCH_CAPTURED:
            self.coordinator.transition(run_id, RunState.FINAL_VERIFYING)
        elif state is not RunState.FINAL_VERIFYING:
            raise VerificationError(f"Final verification cannot start from {state.value}")
        self._validate_environment_identity(run_id, plan)
        paths = self.coordinator.paths_for(run_id)
        if state is RunState.FINAL_VERIFYING:
            candidate = paths.workspaces / _attempt_name("final-verification", attempt)
            if candidate.exists():
                self._quarantine_path(candidate)
        workspace = self.patching.verify_application(
            run_id,
            workspace_name=(None if attempt == 1 else f"final-verification-attempt-{attempt:03d}"),
        )
        contract = self._load_contract(run_id, investigation.contract_sha256)
        self.contracts.validate_approved_assets(contract, paths.reproduction_assets)
        reproduction = paths.workspaces / _attempt_name("final-reproduction", attempt)
        if reproduction.exists():
            self._quarantine_path(reproduction)
        self.contracts.copy_approved_assets(contract, paths.reproduction_assets, reproduction)
        paths.verification.mkdir(mode=0o700, exist_ok=True)
        if paths.contract.exists():
            stored = FailureContract.model_validate(read_canonical_json(paths.contract))
            if stored != contract:
                raise EvidenceIntegrityError("Final verification contract changed")
        else:
            write_canonical_json(paths.contract, contract.model_dump(mode="json"))

        evaluations: list[OracleEvaluation] = []
        last_assessment = investigation.protection
        for index, setup in enumerate(plan.setup_commands, start=1):
            setup_result = self._run_container(
                run_id,
                plan,
                workspace,
                reproduction,
                setup.argv,
                ExecutionPhase.SETUP,
                (
                    f"final-setup-{index}"
                    if attempt == 1
                    else f"attempt-{attempt:03d}-setup-{index}"
                ),
                _limits_with_timeout(plan.verifier_resources, setup.timeout_seconds),
                plan.setup_network,
                plan.setup_environment,
                tuple(sorted(plan.setup_environment)),
            )
            last_assessment = setup_result[1]
            if (
                setup_result[0].termination is not TerminationKind.EXITED
                or setup_result[0].exit_code != 0
            ):
                self.coordinator.transition(
                    run_id, RunState.REJECTED, details={"reason": "PP_SETUP_FAILED"}
                )
                return _AttemptVerification(
                    evaluations=(),
                    transition_passed=False,
                    regressions_passed=False,
                    rejection_code="PP_SETUP_FAILED",
                    assessment=last_assessment,
                )

        fixed, last_assessment = self._execute_oracle(
            run_id,
            plan,
            workspace,
            reproduction,
            contract.oracle.as_command_spec(),
            OraclePhase.FIXED,
            _attempt_name("fixed-oracle", attempt),
            contract.oracle.environment,
            plan.contract_environment_allowlist,
        )
        evaluations.append(fixed)
        for index, regression in enumerate(plan.regressions, start=1):
            evaluation, last_assessment = self._execute_oracle(
                run_id,
                plan,
                workspace,
                reproduction,
                regression,
                OraclePhase.REGRESSION,
                (
                    f"regression-{index}"
                    if attempt == 1
                    else f"attempt-{attempt:03d}-regression-{index}"
                ),
                regression.environment,
                plan.contract_environment_allowlist,
            )
            evaluations.append(evaluation)

        regressions_passed = all(result.passed for result in evaluations[1:])
        if fixed.passed and regressions_passed:
            self.coordinator.transition(
                run_id,
                RunState.VERIFIED,
                details={
                    "contract_sha256": investigation.contract_sha256,
                    "patch_sha256": patch.patch_sha256,
                    "reproduction_transition_passed": True,
                    "regressions_passed": True,
                },
            )
            return _AttemptVerification(
                evaluations=tuple(evaluations),
                transition_passed=True,
                regressions_passed=True,
                rejection_code=None,
                assessment=last_assessment,
            )
        code = "PP_REPRODUCTION_STILL_FAILS" if not fixed.passed else "PP_REGRESSION_FAILED"
        self.coordinator.transition(run_id, RunState.REJECTED, details={"reason": code})
        return _AttemptVerification(
            evaluations=tuple(evaluations),
            transition_passed=fixed.passed,
            regressions_passed=regressions_passed,
            rejection_code=code,
            assessment=last_assessment,
        )

    def _execute_oracle(
        self,
        run_id: str,
        plan: WorkflowPlan,
        workspace: Path,
        reproduction: Path,
        spec: CommandOracleSpec,
        phase: OraclePhase,
        execution_id: str,
        environment: dict[str, str],
        environment_allowlist: tuple[str, ...],
    ) -> tuple[OracleEvaluation, ProtectionAssessment]:
        self.oracle.validate(spec)
        self.coordinator.append_event(
            run_id,
            "oracle.started",
            payload={"oracle_id": spec.id, "phase": phase.value},
        )
        source_before = workspace_content_sha256(
            workspace,
            maximum_bytes=plan.maximum_repository_bytes,
        )
        process, assessment = self._run_container(
            run_id,
            plan,
            workspace,
            reproduction,
            spec.argv,
            ExecutionPhase.VERIFICATION,
            execution_id,
            _limits_with_timeout(plan.verifier_resources, spec.timeout_seconds),
            NetworkPolicy.NONE,
            environment,
            environment_allowlist,
            working_directory=_container_cwd(spec.cwd),
        )
        source_after = workspace_content_sha256(
            workspace,
            maximum_bytes=plan.maximum_repository_bytes,
        )
        if source_after != source_before:
            self.coordinator.append_event(
                run_id,
                "oracle.source_mutation_detected",
                payload={"oracle_id": spec.id, "phase": phase.value},
            )
            raise EvidenceIntegrityError("Verification oracle modified its read-only source")
        paths = self.coordinator.paths_for(run_id)
        log_directory = paths.verification / execution_id
        log_directory.mkdir(mode=0o700, exist_ok=False)
        stdout = log_directory / "stdout.log"
        stderr = log_directory / "stderr.log"
        _write_private_file(stdout, process.stdout)
        _write_private_file(stderr, process.stderr)
        execution = OracleExecutionResult(
            process,
            stdout.relative_to(paths.root).as_posix(),
            hashlib.sha256(process.stdout).hexdigest(),
            stderr.relative_to(paths.root).as_posix(),
            hashlib.sha256(process.stderr).hexdigest(),
        )
        evaluation = self.oracle.evaluate(spec, phase, execution)
        write_canonical_json(log_directory / "result.json", evaluation.model_dump(mode="json"))
        self.coordinator.append_event(
            run_id,
            "oracle.completed" if evaluation.passed else "oracle.failed",
            payload={
                "oracle_id": spec.id,
                "phase": phase.value,
                "passed": evaluation.passed,
                "failure_code": evaluation.failure_code,
                "process": evaluation.process.model_dump(mode="json"),
            },
        )
        return evaluation, assessment

    def _run_container(
        self,
        run_id: str,
        plan: WorkflowPlan,
        workspace: Path,
        reproduction: Path,
        argv: tuple[str, ...],
        phase: ExecutionPhase,
        execution_id: str,
        resources: ResourceLimits,
        network: NetworkPolicy,
        environment: dict[str, str],
        environment_allowlist: tuple[str, ...],
        *,
        working_directory: str = WORKSPACE_PATH,
    ) -> tuple[ProcessOutcome, ProtectionAssessment]:
        paths = self.coordinator.paths_for(run_id)
        snapshot = self.patching.load_repository(run_id)
        if phase is ExecutionPhase.VERIFICATION:
            environment = merge_verifier_environment(environment)
            environment_allowlist = tuple(sorted(set(environment_allowlist).union(environment)))
        mounts = [
            DockerMount(
                source=workspace,
                destination=WORKSPACE_PATH,
                kind=MountKind.WORKSPACE,
                access=(
                    MountAccess.READ_WRITE
                    if phase is ExecutionPhase.SETUP
                    else MountAccess.READ_ONLY
                ),
            )
        ]
        if phase is ExecutionPhase.VERIFICATION:
            mounts.append(
                DockerMount(
                    source=reproduction,
                    destination=REPRODUCTION_PATH,
                    kind=MountKind.REPRODUCTION,
                    access=MountAccess.READ_ONLY,
                )
            )
        result = self.backend.run(
            ExecutionRequest(
                execution_id=execution_id,
                run_id=run_id,
                phase=phase,
                image=plan.verifier_image,
                argv=argv,
                working_directory=working_directory,
                network=network,
                mounts=tuple(mounts),
                environment=environment,
                environment_allowlist=environment_allowlist,
                resources=resources,
                original_repository=Path(snapshot.repository_root),
                evidence_directory=paths.root,
                disposable_work_directory=paths.workspaces,
            )
        )
        return _protected_process_outcome(result), result.protection

    def _finish_rejected(
        self,
        run_id: str,
        issue_summary: str,
        plan: WorkflowPlan,
        investigation: InvestigationOutcome,
        patch: PatchRecord | None,
        code: str,
        *,
        assessment: ProtectionAssessment | None = None,
    ) -> WorkflowOutcome:
        return self._finish(
            run_id,
            issue_summary,
            plan,
            investigation,
            patch,
            [],
            False,
            False,
            code,
            assessment or investigation.protection,
        )

    def _analyze_attempt(
        self,
        run_id: str,
        patch: PatchRecord,
        root_cause: str,
        investigation: InvestigationOutcome,
        previous: tuple[AttemptRecord, ...],
    ) -> tuple[PatchFingerprint, str, tuple[SimilarityWarning, ...]]:
        contract = self._load_contract(run_id, investigation.contract_sha256)
        fingerprint = self.analysis.fingerprint(
            patch,
            self.coordinator.paths_for(run_id).patch_diff,
            contract.observed_failure_signature.model_dump(mode="json"),
        )
        hypothesis_sha = self.analysis.hypothesis_sha256(root_cause)
        warnings = self.analysis.warnings(
            fingerprint,
            patch.patch_sha256,
            hypothesis_sha,
            previous,
        )
        self.coordinator.append_event(
            run_id,
            "patch.fingerprint_created",
            payload={
                "attempt": len(previous) + 1,
                "fingerprint_sha256": fingerprint.sha256,
                "patch_sha256": patch.patch_sha256,
                "warning_codes": [warning.code for warning in warnings],
            },
        )
        return fingerprint, hypothesis_sha, warnings

    def _record_attempt(self, run_id: str, record: AttemptRecord) -> None:
        paths = self.coordinator.paths_for(run_id)
        path = paths.attempts / f"attempt_{record.attempt:03d}.json"
        document_hash = hashlib.sha256(
            canonical_json_bytes(record.model_dump(mode="json"))
        ).hexdigest()
        self.coordinator.append_event(
            run_id,
            "patch.attempt_completed",
            payload={
                "attempt": record.attempt,
                "status": record.status.value,
                "patch_sha256": record.patch_sha256,
                "fingerprint_sha256": record.fingerprint.sha256,
                "record_path": path.relative_to(paths.root).as_posix(),
                "record_sha256": document_hash,
                "rejection_code": record.rejection_code,
                "warning_codes": [warning.code for warning in record.warnings],
            },
        )

    @staticmethod
    def _archive_current_patch(paths: RunPaths, attempt: int) -> None:
        destination = paths.attempts / f"attempt_{attempt:03d}_artifacts"
        destination.mkdir(mode=0o700, exist_ok=False)
        for source in sorted(paths.patch.iterdir(), key=lambda item: item.name):
            if source.is_symlink() or source.is_junction() or not source.is_file():
                raise EvidenceIntegrityError("Patch attempt artifacts must be regular files")
            source.rename(destination / source.name)

    def _finish(
        self,
        run_id: str,
        issue_summary: str,
        plan: WorkflowPlan,
        investigation: InvestigationOutcome,
        patch: PatchRecord | None,
        evaluations: list[OracleEvaluation],
        transition_passed: bool,
        regressions_passed: bool,
        rejection_code: str | None,
        assessment: ProtectionAssessment | None,
    ) -> WorkflowOutcome:
        baseline = self._require_baseline_outcome(investigation)
        contract = self._load_contract(run_id, investigation.contract_sha256)
        if assessment is None or assessment.level is not ProtectionLevel.PROTECTED:
            raise EvidenceIntegrityError("A protected receipt requires measured protection facts")
        status = self.coordinator.status(run_id)
        snapshot = self.patching.load_repository(run_id)
        try:
            environment_identity = VerifierEnvironmentIdentity.model_validate(
                read_canonical_json(self.coordinator.paths_for(run_id).environment_identity)
            )
        except ValidationError as error:
            raise EvidenceIntegrityError(
                "Protected verifier environment identity is invalid"
            ) from error
        verify_verifier_environment_identity(environment_identity)
        receipt = VerificationReceipt(
            proofpatch_version=__version__,
            run_id=run_id,
            status="verified" if status.state is RunState.VERIFIED else "rejected",
            protection_level=ProtectionLevel.PROTECTED,
            backend="docker",
            protection_assessment=assessment,
            created_at_utc=status.manifest.created_at_utc,
            completed_at_utc=format_utc_timestamp(),
            project=ReceiptProject(
                name=plan.project_name or Path(snapshot.repository_root).name,
                repository_id=snapshot.repository_id,
                baseline_commit=snapshot.baseline_commit,
            ),
            issue_summary=issue_summary,
            contract=ReceiptContract(
                id=contract.oracle.id,
                sha256=self._contract_hash(contract),
            ),
            baseline=ReceiptBaseline(
                failure_reproduced=baseline.passed,
                exit_code=baseline.process.exit_code,
                duration_ms=baseline.process.duration_ms,
            ),
            patch=(
                None
                if patch is None
                else ReceiptPatch(
                    sha256=patch.patch_sha256,
                    changed_files=len(patch.changed_files),
                )
            ),
            verification=ReceiptVerification(
                reproduction_transition_passed=transition_passed,
                regressions_passed=regressions_passed,
                oracles=tuple(evaluations),
            ),
            environment=environment_identity,
            evidence=ReceiptEvidence(decision_chain_hash=status.final_event_hash),
            rejection_code=rejection_code,
            attempts=tuple(
                ReceiptAttempt(
                    attempt=attempt.attempt,
                    status=attempt.status.value,
                    patch_sha256=attempt.patch_sha256,
                    fingerprint_sha256=attempt.fingerprint.sha256,
                    changed_paths=attempt.changed_paths,
                    warning_codes=tuple(warning.code for warning in attempt.warnings),
                    rejection_code=attempt.rejection_code,
                )
                for attempt in AttemptStore(self.coordinator.paths_for(run_id).attempts).load()
            ),
        )
        json_path, markdown_path = self.receipts.generate(receipt)
        if not plan.retain_workspaces:
            paths = self.coordinator.paths_for(run_id)
            if paths.workspaces.exists():
                self.coordinator.append_event(
                    run_id,
                    "cleanup.started",
                    payload={"target": "workspaces"},
                )
                remove_owned_tree(self.coordinator.directories.data, paths.workspaces)
                self.coordinator.append_event(
                    run_id,
                    "cleanup.completed",
                    payload={"target": "workspaces"},
                )
        return WorkflowOutcome(run_id, status.state, receipt, json_path, markdown_path)

    def _record_test_file_changes(
        self,
        run_id: str,
        patch: PatchRecord,
        enabled: bool,
    ) -> None:
        if not enabled:
            return
        paths = sorted(
            change.path for change in patch.changed_files if _looks_like_test_path(change.path)
        )
        if paths:
            json_paths: list[JsonValue] = list(paths)
            self.coordinator.append_event(
                run_id,
                "patch.test_files_changed",
                payload={"paths": json_paths},
            )

    def _load_baseline_checkpoint(
        self,
        run_id: str,
        plan: WorkflowPlan,
    ) -> tuple[FailureContract, OracleEvaluation, ProtectionAssessment]:
        self._validate_environment_identity(run_id, plan)
        paths = self.coordinator.paths_for(run_id)
        contract = FailureContract.model_validate(read_canonical_json(paths.submitted_contract))
        baseline = OracleEvaluation.model_validate(read_canonical_json(paths.baseline_result))
        assessment = ProtectionAssessment.model_validate(
            read_canonical_json(paths.baseline_protection)
        )
        self.contracts.validate_approved_assets(contract, paths.reproduction_assets)
        return contract, baseline, assessment

    def _load_contract(
        self,
        run_id: str,
        expected_hash: str | None,
    ) -> FailureContract:
        if expected_hash is None:
            raise EvidenceIntegrityError("Run has no evidence-bound contract hash")
        paths = self.coordinator.paths_for(run_id)
        try:
            contract = FailureContract.model_validate(read_canonical_json(paths.submitted_contract))
        except ValidationError as error:
            raise EvidenceIntegrityError("Stored failure contract is invalid") from error
        actual = self._contract_hash(contract)
        try:
            recorded = paths.contract_sha256.read_text(encoding="ascii").strip()
        except OSError as error:
            raise EvidenceIntegrityError("Stored contract hash is unavailable") from error
        if actual != expected_hash or recorded != expected_hash:
            raise EvidenceIntegrityError("Failure contract hash changed after baseline")
        self.contracts.validate_approved_assets(contract, paths.reproduction_assets)
        return contract

    def _validate_environment_identity(self, run_id: str, plan: WorkflowPlan) -> None:
        status = self.coordinator.status(run_id)
        paths = self.coordinator.paths_for(run_id)
        plan_document = read_canonical_json(paths.workflow_plan)
        if plan_document != self._plan_evidence(plan):
            raise EvidenceIntegrityError("Resolved workflow configuration changed after preflight")
        configuration_events = [
            event for event in status.events if event.type == "configuration.resolved"
        ]
        if (
            len(configuration_events) != 1
            or configuration_events[0].payload.get("sha256")
            != hashlib.sha256(canonical_json_bytes(plan_document)).hexdigest()
        ):
            raise EvidenceIntegrityError("Resolved workflow configuration is not event-bound")
        expected_agent = plan.agent_image.digest
        expected_verifier = plan.verifier_image.digest
        for event in status.events:
            if event.type != "investigation.started":
                continue
            if (
                event.payload.get("investigator_image_digest") != expected_agent
                or event.payload.get("verifier_image_digest") != expected_verifier
            ):
                raise EvidenceIntegrityError("Resolved image digest changed after investigation")
            break
        else:
            raise EvidenceIntegrityError("Run has no image identity evidence")
        try:
            identity = VerifierEnvironmentIdentity.model_validate(
                read_canonical_json(paths.environment_identity)
            )
            contract = FailureContract.model_validate(read_canonical_json(paths.submitted_contract))
        except ValidationError as error:
            raise EvidenceIntegrityError(
                "Stored verifier environment identity is invalid"
            ) from error
        verify_verifier_environment_identity(identity)
        snapshot = self.patching.load_repository(run_id)
        expected_identity = build_verifier_environment_identity(
            self.patching.git,
            snapshot,
            plan.verifier_image,
            contract.oracle.as_command_spec(),
            plan.regressions,
        )
        if identity != expected_identity:
            raise EvidenceIntegrityError("Verifier environment inputs changed after baseline")
        environment_events = [
            event for event in status.events if event.type == "environment.prepared"
        ]
        if (
            len(environment_events) != 1
            or environment_events[0].payload.get("environment_inputs_sha256")
            != identity.environment_inputs_sha256
        ):
            raise EvidenceIntegrityError("Verifier environment identity is not event-bound")

    def _capture_patch_result(
        self,
        run_id: str,
        source: Path,
        *,
        attempt: int = 1,
    ) -> PatchResult:
        try:
            result = PatchResult.model_validate(
                read_json_document(source, maximum_bytes=1024 * 1024)
            )
        except (ValidationError, EvidenceIntegrityError) as error:
            self._reject_patch(run_id, "PP_AGENT_FAILED")
            raise AgentError("Patch agent did not produce a valid patch-result.json") from error
        paths = self.coordinator.paths_for(run_id)
        write_canonical_json(paths.patch_result, result.model_dump(mode="json"))
        self.coordinator.append_event(
            run_id,
            "patch.result_submitted",
            payload={
                "attempt": attempt,
                "sha256": hashlib.sha256(
                    canonical_json_bytes(result.model_dump(mode="json"))
                ).hexdigest(),
            },
        )
        return result

    def _persist_agent_logs(
        self,
        run_id: str,
        process: ProcessOutcome,
        *,
        attempt: int = 1,
    ) -> None:
        paths = self.coordinator.paths_for(run_id)
        stdout = paths.patch / "agent-stdout.log"
        stderr = paths.patch / "agent-stderr.log"
        _write_private_file(stdout, process.stdout)
        _write_private_file(stderr, process.stderr)
        self.coordinator.append_event(
            run_id,
            "patch.agent_logs_stored",
            payload={
                "stdout_sha256": hashlib.sha256(process.stdout).hexdigest(),
                "stdout_bytes": len(process.stdout),
                "stderr_sha256": hashlib.sha256(process.stderr).hexdigest(),
                "stderr_bytes": len(process.stderr),
                "attempt": attempt,
            },
        )

    def _reject_patch(self, run_id: str, reason: str) -> None:
        if self.coordinator.status(run_id).state is RunState.PATCHING:
            self.coordinator.transition(run_id, RunState.REJECTED, details={"reason": reason})

    def _load_patch_clone(self, run_id: str) -> IndependentClone:
        paths = self.coordinator.paths_for(run_id)
        document = read_canonical_json(paths.patch / "clone.json")
        if not isinstance(document, dict):
            raise EvidenceIntegrityError("Patch clone identity is invalid")
        try:
            root = paths.root / str(document["root"])
            git_directory = paths.root / str(document["git_directory"])
            clone = IndependentClone(
                CloneKind(str(document["kind"])),
                root,
                git_directory,
                str(document["baseline_commit"]),
                str(document["configuration_sha256"]),
            )
        except (KeyError, ValueError) as error:
            raise EvidenceIntegrityError("Patch clone identity is incomplete") from error
        from proofpatch.git.clone import validate_owned_clone

        validate_owned_clone(clone, paths.root)
        return clone

    def _existing_receipt(self, run_id: str) -> WorkflowOutcome:
        paths = self.coordinator.paths_for(run_id)
        receipt = self.receipts.verify(run_id)
        if receipt.run_id != run_id or receipt.status != "verified":
            raise EvidenceIntegrityError("Stored receipt does not match the verified run")
        return WorkflowOutcome(
            run_id, RunState.VERIFIED, receipt, paths.receipt_json, paths.receipt_markdown
        )

    @staticmethod
    def _agent_context(environment: dict[str, str]) -> AgentPhaseContext:
        return AgentPhaseContext(
            prompt_path=PROMPT_PATH,
            workspace_path=WORKSPACE_PATH,
            output_path=OUTPUT_PATH,
            reproduction_path=REPRODUCTION_PATH,
            issue_path=ISSUE_PATH,
            environment=environment,
        )

    @staticmethod
    def _plan_evidence(plan: WorkflowPlan) -> dict[str, JsonValue]:
        """Serialize deterministic settings and secret names, never secret values."""

        adapter = get_agent_adapter(plan.adapter_name)
        setup_environment_names = [cast(JsonValue, name) for name in sorted(plan.setup_environment)]
        return {
            "schema_version": 1,
            "adapter": adapter.name,
            "adapter_version": adapter.adapter_version,
            "agent_command": list(plan.agent.command),
            "agent_environment_names": list(plan.agent.environment_allowlist),
            "agent_image": plan.agent_image.model_dump(mode="json"),
            "verifier_image": plan.verifier_image.model_dump(mode="json"),
            "investigation_resources": plan.investigation_resources.model_dump(mode="json"),
            "patch_resources": plan.patch_resources.model_dump(mode="json"),
            "verifier_resources": plan.verifier_resources.model_dump(mode="json"),
            "contract_environment_names": list(plan.contract_environment_allowlist),
            "setup_commands": [
                {
                    "id": command.id,
                    "argv": list(command.argv),
                    "timeout_seconds": command.timeout_seconds,
                }
                for command in plan.setup_commands
            ],
            "setup_environment_names": setup_environment_names,
            "setup_environment_sha256": hashlib.sha256(
                canonical_json_bytes(plan.setup_environment)
            ).hexdigest(),
            "regressions": [spec.model_dump(mode="json") for spec in plan.regressions],
            "allowed_patch_paths": list(plan.allowed_patch_paths),
            "denied_patch_paths": list(plan.denied_patch_paths),
            "maximum_patch_bytes": plan.maximum_patch_bytes,
            "maximum_changed_files": plan.maximum_changed_files,
            "maximum_repository_bytes": plan.maximum_repository_bytes,
            "maximum_attempts": plan.maximum_attempts,
            "flag_test_changes": plan.flag_test_changes,
            "retain_workspaces": plan.retain_workspaces,
            "project_name": plan.project_name,
            "network": {
                "investigation": plan.investigation_network.value,
                "patch": plan.patch_network.value,
                "setup": plan.setup_network.value,
                "baseline": "none",
                "verification": "none",
            },
        }

    @staticmethod
    def _contract_hash(contract: FailureContract) -> str:
        return hashlib.sha256(canonical_json_bytes(contract.model_dump(mode="json"))).hexdigest()

    @staticmethod
    def _require_baseline_outcome(outcome: InvestigationOutcome) -> OracleEvaluation:
        if outcome.baseline is None or not outcome.baseline.passed:
            raise EvidenceIntegrityError("Patch phase lacks a passing independent baseline result")
        return outcome.baseline

    @staticmethod
    def _quarantine_incomplete_verification_clone(workspaces: Path) -> None:
        candidate = workspaces / CloneKind.FINAL_VERIFICATION.value
        if candidate.exists():
            WorkflowService._quarantine_path(candidate)

    @staticmethod
    def _quarantine_path(path: Path) -> None:
        parent = path.parent.resolve(strict=True)
        resolved = path.resolve(strict=True)
        if resolved.parent != parent or path.is_symlink() or path.is_junction():
            raise EvidenceIntegrityError("Interrupted workspace cannot be quarantined safely")
        suffix = hashlib.sha256(os.urandom(32)).hexdigest()[:12]
        resolved.rename(parent / f"{resolved.name}-interrupted-{suffix}")


def render_patch_prompt(
    issue_summary: str,
    contract: FailureContract,
    baseline: OracleEvaluation,
    *,
    previous_failures: str = "No previous patch attempts.",
) -> str:
    """Render only canonical controller evidence into the untrusted agent prompt."""

    template = (Path(__file__).parent.parent / "prompts" / "patch.md").read_text(encoding="utf-8")
    return (
        template.replace("{issue_summary}", issue_summary)
        .replace(
            "{failure_contract}",
            canonical_json_bytes(contract.model_dump(mode="json")).decode("utf-8"),
        )
        .replace(
            "{baseline_result}",
            canonical_json_bytes(baseline.model_dump(mode="json")).decode("utf-8"),
        )
        + "\n\n## Previous deterministic attempt results\n\n"
        + previous_failures
        + "\n"
    )


def _previous_failure_summary(attempts: tuple[AttemptRecord, ...]) -> str:
    if not attempts:
        return "No previous patch attempts."
    lines = []
    for attempt in attempts:
        warning_codes = ", ".join(warning.code for warning in attempt.warnings) or "none"
        result = attempt.rejection_code or attempt.status.value
        lines.append(
            f"- Attempt {attempt.attempt}: result={result}; "
            f"changed_paths={','.join(attempt.changed_paths)}; warnings={warning_codes}."
        )
    return "\n".join(lines)


def _container_cwd(relative: str) -> str:
    return WORKSPACE_PATH if relative == "." else f"{WORKSPACE_PATH}/{relative}"


def _attempt_name(base: str, attempt: int) -> str:
    return base if attempt == 1 else f"{base}-attempt-{attempt:03d}"


def _looks_like_test_path(path: str) -> bool:
    parts = path.casefold().split("/")
    name = parts[-1]
    return (
        any(part in {"test", "tests", "spec", "specs", "__tests__"} for part in parts[:-1])
        or name.startswith("test_")
        or name.endswith(("_test.py", ".test.js", ".test.ts", ".spec.js", ".spec.ts"))
    )
