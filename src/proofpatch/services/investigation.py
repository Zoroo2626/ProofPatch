"""Host-controlled investigation and independent baseline reproduction gate."""

import hashlib
import os
import stat
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path

from proofpatch.agents.base import AgentVersionProbe
from proofpatch.agents.versioning import parse_and_require_version
from proofpatch.backends.base import ExecutionBackend
from proofpatch.errors import (
    AgentError,
    BackendError,
    ContractError,
    EvidenceIntegrityError,
    RepositoryError,
)
from proofpatch.execution.process import ProcessOutcome
from proofpatch.git.clone import CloneKind, IndependentClone, validate_owned_clone
from proofpatch.models.agent import AgentVersionMetadata
from proofpatch.models.common import JsonValue
from proofpatch.models.contract import FailureContract, NotReproducedOutcome
from proofpatch.models.execution import (
    ENVIRONMENT_NAME,
    CommandOracleSpec,
    DockerMount,
    ExecutionPhase,
    ExecutionRequest,
    ExecutionResult,
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
from proofpatch.models.patch import RepositorySnapshot
from proofpatch.models.state import RunState
from proofpatch.oracles.base import OracleExecutionResult
from proofpatch.oracles.command import CommandOracle
from proofpatch.services.contracts import ContractService, ValidatedContract
from proofpatch.services.coordinator import RunCoordinator
from proofpatch.services.evidence import (
    canonical_json_bytes,
    read_canonical_json,
    write_canonical_json,
)
from proofpatch.services.identifiers import generate_run_id
from proofpatch.services.patching import PatchService

FAILURE_CONTRACT_NAME = "failure-contract.json"
NOT_REPRODUCED_NAME = "not-reproduced.json"
RESERVED_INVESTIGATION_ENVIRONMENT = frozenset({"PROOFPATCH_ISSUE", "PROOFPATCH_INSTRUCTIONS"})
PRIVATE_FILE_MODE = 0o600


@dataclass(frozen=True, slots=True)
class SetupCommand:
    """One shell-free verifier setup command."""

    id: str
    argv: tuple[str, ...]
    timeout_seconds: float

    def __post_init__(self) -> None:
        if not self.id or not self.id.replace("-", "_").isalnum():
            raise ValueError("setup command ID is invalid")
        if not self.argv or any(not item or "\0" in item for item in self.argv):
            raise ValueError("setup command argv must be nonempty and NUL-free")
        if self.timeout_seconds <= 0 or self.timeout_seconds > 86400:
            raise ValueError("setup command timeout must be positive and finite")


@dataclass(frozen=True, slots=True)
class InvestigationPlan:
    """Controller-owned inputs for a generic fake or external investigator command."""

    investigator_argv: tuple[str, ...]
    investigator_image: ResolvedImage
    verifier_image: ResolvedImage
    investigation_resources: ResourceLimits
    baseline_resources: ResourceLimits
    investigator_environment: dict[str, str]
    investigator_environment_allowlist: tuple[str, ...]
    contract_environment_allowlist: tuple[str, ...] = ()
    setup_commands: tuple[SetupCommand, ...] = ()
    setup_environment: dict[str, str] = field(default_factory=dict)
    investigation_network: NetworkPolicy = NetworkPolicy.AGENT_API
    setup_network: NetworkPolicy = NetworkPolicy.BRIDGE
    adapter_name: str = "generic"
    adapter_version: int = 1
    version_probe: AgentVersionProbe | None = None

    def __post_init__(self) -> None:
        if not self.investigator_argv or any(
            not item or "\0" in item for item in self.investigator_argv
        ):
            raise ValueError("investigator argv must be nonempty and NUL-free")
        unexpected = set(self.investigator_environment).difference(
            self.investigator_environment_allowlist
        )
        if unexpected:
            raise ValueError("investigator environment contains non-allowlisted names")
        if RESERVED_INVESTIGATION_ENVIRONMENT.intersection(self.investigator_environment):
            raise ValueError("investigator environment overrides reserved ProofPatch names")
        for environment in (self.investigator_environment, self.setup_environment):
            if len(environment) > 128 or any(
                ENVIRONMENT_NAME.fullmatch(name) is None for name in environment
            ):
                raise ValueError("phase environment contains invalid or excessive names")
            if any("\0" in item for pair in environment.items() for item in pair):
                raise ValueError("phase environment must be NUL-free")
        if len(self.setup_commands) != len({command.id for command in self.setup_commands}):
            raise ValueError("setup command IDs must be unique")
        if not self.adapter_name or self.adapter_version < 1:
            raise ValueError("agent adapter identity is invalid")


class InvestigationOutcomeKind(StrEnum):
    BASELINE_REPRODUCED = "baseline_reproduced"
    INVESTIGATOR_NOT_REPRODUCED = "investigator_not_reproduced"
    BASELINE_NOT_REPRODUCED = "baseline_not_reproduced"


@dataclass(frozen=True, slots=True)
class InvestigationOutcome:
    run_id: str
    kind: InvestigationOutcomeKind
    state: RunState
    contract_sha256: str | None = None
    baseline: OracleEvaluation | None = None
    not_reproduced: NotReproducedOutcome | None = None
    protection: ProtectionAssessment | None = None


class InvestigationService:
    """Treat investigator output as untrusted input and retain sole control of the gate."""

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
        self.command_oracle = CommandOracle()

    def investigate(
        self,
        repository: Path,
        issue_summary: str,
        plan: InvestigationPlan,
        *,
        run_id: str | None = None,
        resolved_configuration: dict[str, JsonValue] | None = None,
    ) -> InvestigationOutcome:
        """Run investigation, validate its file outcome, then independently test the contract."""

        if not issue_summary or len(issue_summary) > 4096 or "\0" in issue_summary:
            raise ContractError("Issue summary must be nonempty, bounded, and NUL-free")
        selected_run_id = generate_run_id() if run_id is None else run_id
        snapshot = self.patching.prepare_run(repository, run_id=selected_run_id)
        paths = self.coordinator.paths_for(selected_run_id)
        if resolved_configuration is not None:
            write_canonical_json(paths.workflow_plan, resolved_configuration)
            configuration_sha256 = hashlib.sha256(
                canonical_json_bytes(resolved_configuration)
            ).hexdigest()
            self.coordinator.append_event(
                selected_run_id,
                "configuration.resolved",
                payload={
                    "sha256": configuration_sha256,
                    "secret_values_serialized": False,
                },
            )
        self.coordinator.transition(selected_run_id, RunState.BASELINE_PREPARING)
        investigation_clone = self.patching.create_clone(
            selected_run_id,
            CloneKind.INVESTIGATION,
        )
        scratch = paths.workspaces / "investigation-reproduction"
        output = paths.workspaces / "investigation-output"
        controller_input = paths.workspaces / "investigation-input"
        scratch.mkdir(mode=0o700, exist_ok=False)
        output.mkdir(mode=0o700, exist_ok=False)
        controller_input.mkdir(mode=0o700, exist_ok=False)
        prompt_file = controller_input / "prompt.md"
        issue_file = controller_input / "issue.md"
        _write_private_file(prompt_file, render_investigation_prompt(issue_summary).encode("utf-8"))
        _write_private_file(issue_file, issue_summary.encode("utf-8"))
        self.coordinator.transition(selected_run_id, RunState.INVESTIGATING)
        self.coordinator.append_event(
            selected_run_id,
            "investigation.started",
            payload={
                "investigator_image_digest": plan.investigator_image.digest,
                "verifier_image_digest": plan.verifier_image.digest,
            },
        )

        if plan.version_probe is not None:
            self._detect_agent_version(
                selected_run_id,
                snapshot,
                plan,
                investigation_clone,
            )

        environment = dict(plan.investigator_environment)
        environment["PROOFPATCH_ISSUE"] = issue_summary
        environment["PROOFPATCH_INSTRUCTIONS"] = render_investigation_prompt(issue_summary)
        allowlist = tuple(
            sorted(
                set(plan.investigator_environment_allowlist).union(
                    RESERVED_INVESTIGATION_ENVIRONMENT
                )
            )
        )
        try:
            result = self.backend.run(
                ExecutionRequest(
                    execution_id="investigation-1",
                    run_id=selected_run_id,
                    phase=ExecutionPhase.INVESTIGATION,
                    image=plan.investigator_image,
                    argv=plan.investigator_argv,
                    network=plan.investigation_network,
                    mounts=(
                        DockerMount(
                            source=investigation_clone.root,
                            destination="/workspace",
                            kind=MountKind.WORKSPACE,
                            access=MountAccess.READ_ONLY,
                        ),
                        DockerMount(
                            source=scratch,
                            destination="/proofpatch/repro",
                            kind=MountKind.REPRODUCTION,
                            access=MountAccess.READ_WRITE,
                        ),
                        DockerMount(
                            source=output,
                            destination="/proofpatch/out",
                            kind=MountKind.OUTPUT,
                            access=MountAccess.READ_WRITE,
                        ),
                        DockerMount(
                            source=prompt_file,
                            destination="/proofpatch/prompt.md",
                            kind=MountKind.PROMPT,
                            access=MountAccess.READ_ONLY,
                        ),
                        DockerMount(
                            source=issue_file,
                            destination="/proofpatch/issue.md",
                            kind=MountKind.ISSUE,
                            access=MountAccess.READ_ONLY,
                        ),
                    ),
                    environment=environment,
                    environment_allowlist=allowlist,
                    resources=plan.investigation_resources,
                    original_repository=Path(snapshot.repository_root),
                    evidence_directory=paths.root,
                    disposable_work_directory=paths.workspaces,
                )
            )
            outcome = _protected_process_outcome(result)
        except BackendError as error:
            self._reject(selected_run_id, "investigator_backend_failed")
            raise ContractError("Investigation container failed") from error
        log_payload = self._persist_investigation_logs(selected_run_id, outcome)
        exit_payload: dict[str, JsonValue] = {
            "phase": ExecutionPhase.INVESTIGATION.value,
            "termination": outcome.termination.value,
            "exit_code": outcome.exit_code,
            "timed_out": outcome.timed_out,
            "truncated": outcome.truncated,
            **log_payload,
        }
        self.coordinator.append_event(
            selected_run_id,
            "container.exited",
            payload=exit_payload,
        )
        if outcome.termination is not TerminationKind.EXITED or outcome.exit_code != 0:
            self._reject(selected_run_id, "investigator_process_failed")
            raise ContractError("Investigator process did not complete successfully")

        try:
            self._assert_investigation_clone_unchanged(investigation_clone, snapshot, paths.root)
            self.patching.repositories.assert_matches(snapshot)
            return self._consume_outcome(
                selected_run_id,
                snapshot,
                plan,
                output,
                scratch,
                issue_summary,
            )
        except BackendError as error:
            state = self.coordinator.status(selected_run_id).state
            if state in {RunState.CONTRACT_SUBMITTED, RunState.BASELINE_VERIFYING}:
                self._reject(selected_run_id, "baseline_backend_failed")
            raise ContractError("Protected baseline execution failed") from error
        except (ContractError, EvidenceIntegrityError, RepositoryError):
            state = self.coordinator.status(selected_run_id).state
            if state in {
                RunState.INVESTIGATING,
                RunState.CONTRACT_SUBMITTED,
                RunState.BASELINE_VERIFYING,
            }:
                self._reject(selected_run_id, "contract_rejected")
            raise

    def _consume_outcome(
        self,
        run_id: str,
        snapshot: RepositorySnapshot,
        plan: InvestigationPlan,
        output: Path,
        scratch: Path,
        issue_summary: str,
    ) -> InvestigationOutcome:
        contract_path = output / FAILURE_CONTRACT_NAME
        not_reproduced_path = output / NOT_REPRODUCED_NAME
        has_contract = _path_exists_without_following(contract_path)
        has_not_reproduced = _path_exists_without_following(not_reproduced_path)
        if has_contract and has_not_reproduced:
            raise ContractError("Investigation outcome is ambiguous because both files exist")
        if has_not_reproduced:
            negative = self.contracts.read_not_reproduced(not_reproduced_path)
            paths = self.coordinator.paths_for(run_id)
            write_canonical_json(
                paths.investigation_not_reproduced,
                negative.model_dump(mode="json"),
            )
            digest = hashlib.sha256(
                canonical_json_bytes(negative.model_dump(mode="json"))
            ).hexdigest()
            self.coordinator.append_event(
                run_id,
                "investigation.not_reproduced",
                payload={"sha256": digest, "commands_attempted": len(negative.commands_attempted)},
            )
            self.coordinator.transition(
                run_id,
                RunState.ERROR,
                details={"reason": "investigator_not_reproduced", "outcome_sha256": digest},
            )
            return InvestigationOutcome(
                run_id,
                InvestigationOutcomeKind.INVESTIGATOR_NOT_REPRODUCED,
                RunState.ERROR,
                not_reproduced=negative,
            )
        if not has_contract:
            raise ContractError("Investigator exited without a valid outcome file")

        paths = self.coordinator.paths_for(run_id)
        validated = self.contracts.validate_and_capture(
            contract_path,
            scratch,
            submitted_contract_destination=paths.submitted_contract,
            contract_hash_destination=paths.contract_sha256,
            approved_assets_destination=paths.reproduction_assets,
            protected_evidence_directory=paths.root,
            environment_allowlist=plan.contract_environment_allowlist,
            expected_issue_summary=issue_summary,
        )
        self._record_contract(run_id, validated)
        return self._verify_baseline(run_id, snapshot, plan, validated)

    def _record_contract(self, run_id: str, validated: ValidatedContract) -> None:
        assets: list[JsonValue] = [
            {"path": asset.path, "sha256": asset.sha256}
            for asset in validated.contract.reproduction_assets
        ]
        self.coordinator.append_event(
            run_id,
            "investigation.contract_submitted",
            payload={
                "contract_sha256": validated.sha256,
                "oracle_id": validated.contract.oracle.id,
                "assets": assets,
                "total_asset_bytes": validated.total_asset_bytes,
            },
        )
        self.coordinator.transition(
            run_id,
            RunState.CONTRACT_SUBMITTED,
            details={"contract_sha256": validated.sha256},
        )
        self.coordinator.append_event(
            run_id,
            "contract.validated",
            payload={
                "contract_sha256": validated.sha256,
                "oracle_id": validated.contract.oracle.id,
            },
        )
        self.coordinator.append_event(
            run_id,
            "contract.assets_validated",
            payload={
                "contract_sha256": validated.sha256,
                "asset_count": len(validated.contract.reproduction_assets),
                "total_asset_bytes": validated.total_asset_bytes,
                "assets": assets,
            },
        )

    def _verify_baseline(
        self,
        run_id: str,
        snapshot: RepositorySnapshot,
        plan: InvestigationPlan,
        validated: ValidatedContract,
    ) -> InvestigationOutcome:
        paths = self.coordinator.paths_for(run_id)
        persisted = FailureContract.model_validate(read_canonical_json(paths.submitted_contract))
        persisted_hash = hashlib.sha256(
            canonical_json_bytes(persisted.model_dump(mode="json"))
        ).hexdigest()
        if persisted_hash != validated.sha256 or persisted != validated.contract:
            raise EvidenceIntegrityError(
                "Validated failure contract changed before baseline execution"
            )
        self.contracts.validate_approved_assets(persisted, paths.reproduction_assets)
        self.coordinator.transition(run_id, RunState.BASELINE_VERIFYING)
        baseline_clone = self.patching.create_clone(run_id, CloneKind.BASELINE_VERIFICATION)
        reproduction_mount = paths.workspaces / "baseline-reproduction"
        self.contracts.copy_approved_assets(
            persisted,
            paths.reproduction_assets,
            reproduction_mount,
        )

        for index, setup in enumerate(plan.setup_commands, start=1):
            setup_result = self.backend.run(
                self._execution_request(
                    run_id,
                    snapshot,
                    plan.verifier_image,
                    baseline_clone.root,
                    reproduction_mount,
                    setup.argv,
                    ExecutionPhase.SETUP,
                    f"setup-{index}",
                    _limits_with_timeout(plan.baseline_resources, setup.timeout_seconds),
                    plan.setup_network,
                    plan.setup_environment,
                    tuple(sorted(plan.setup_environment)),
                )
            )
            setup_outcome = _protected_process_outcome(setup_result)
            if (
                setup_outcome.termination is not TerminationKind.EXITED
                or setup_outcome.exit_code != 0
            ):
                self.coordinator.append_event(
                    run_id,
                    "oracle.failed",
                    payload={"oracle_id": setup.id, "phase": OraclePhase.SETUP.value},
                )
                self.coordinator.transition(
                    run_id,
                    RunState.ERROR,
                    details={"reason": "baseline_setup_failed", "setup_id": setup.id},
                )
                raise ContractError(f"Verifier setup command failed: {setup.id}")

        contract_oracle = persisted.oracle
        spec = contract_oracle.as_command_spec()
        self.command_oracle.validate(spec)
        argv_hash = hashlib.sha256(canonical_json_bytes(list(contract_oracle.argv))).hexdigest()
        self.coordinator.append_event(
            run_id,
            "oracle.started",
            payload={
                "oracle_id": contract_oracle.id,
                "phase": OraclePhase.BASELINE.value,
                "argv_sha256": argv_hash,
            },
        )
        execution = self.backend.run(
            self._execution_request(
                run_id,
                snapshot,
                plan.verifier_image,
                baseline_clone.root,
                reproduction_mount,
                contract_oracle.argv,
                ExecutionPhase.BASELINE,
                "baseline-oracle",
                _limits_with_timeout(
                    plan.baseline_resources,
                    contract_oracle.timeout_seconds,
                ),
                NetworkPolicy.NONE,
                contract_oracle.environment,
                plan.contract_environment_allowlist,
                working_directory=contract_oracle.cwd,
            )
        )
        process = _protected_process_outcome(execution)
        write_canonical_json(
            paths.baseline_protection,
            execution.protection.model_dump(mode="json"),
        )
        evaluation = self._persist_and_evaluate_baseline(run_id, spec, process)
        if evaluation.passed:
            self.coordinator.append_event(
                run_id,
                "baseline.reproduced",
                payload={
                    "contract_sha256": validated.sha256,
                    "oracle_id": evaluation.oracle_id,
                    "exit_code": evaluation.process.exit_code,
                },
            )
            self.coordinator.transition(
                run_id,
                RunState.BASELINE_REPRODUCED,
                details={
                    "contract_sha256": validated.sha256,
                    "oracle_id": evaluation.oracle_id,
                    "exit_code": evaluation.process.exit_code,
                },
            )
            return InvestigationOutcome(
                run_id,
                InvestigationOutcomeKind.BASELINE_REPRODUCED,
                RunState.BASELINE_REPRODUCED,
                validated.sha256,
                evaluation,
                None,
                execution.protection,
            )

        negative = NotReproducedOutcome(
            explanation="Independent baseline execution did not satisfy the failure expectation.",
            commands_attempted=(contract_oracle.argv,),
        )
        write_canonical_json(paths.baseline_not_reproduced, negative.model_dump(mode="json"))
        self.coordinator.append_event(
            run_id,
            "baseline.not_reproduced",
            payload={
                "contract_sha256": validated.sha256,
                "oracle_id": evaluation.oracle_id,
                "failure_code": evaluation.failure_code,
            },
        )
        self.coordinator.transition(
            run_id,
            RunState.BASELINE_NOT_REPRODUCED,
            details={
                "contract_sha256": validated.sha256,
                "oracle_id": evaluation.oracle_id,
                "failure_code": evaluation.failure_code,
            },
        )
        self.coordinator.transition(run_id, RunState.REJECTED)
        return InvestigationOutcome(
            run_id,
            InvestigationOutcomeKind.BASELINE_NOT_REPRODUCED,
            RunState.REJECTED,
            validated.sha256,
            evaluation,
            negative,
            execution.protection,
        )

    def _execution_request(
        self,
        run_id: str,
        snapshot: RepositorySnapshot,
        image: ResolvedImage,
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
        working_directory: str = "/workspace",
    ) -> ExecutionRequest:
        paths = self.coordinator.paths_for(run_id)
        mounts = [
            DockerMount(
                source=workspace,
                destination="/workspace",
                kind=MountKind.WORKSPACE,
                access=(
                    MountAccess.READ_WRITE
                    if phase is ExecutionPhase.SETUP
                    else MountAccess.READ_ONLY
                ),
            )
        ]
        if phase is ExecutionPhase.BASELINE:
            mounts.append(
                DockerMount(
                    source=reproduction,
                    destination="/proofpatch/repro",
                    kind=MountKind.REPRODUCTION,
                    access=MountAccess.READ_ONLY,
                )
            )
        return ExecutionRequest(
            execution_id=execution_id,
            run_id=run_id,
            phase=phase,
            image=image,
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

    def _persist_and_evaluate_baseline(
        self,
        run_id: str,
        spec: CommandOracleSpec,
        outcome: ProcessOutcome,
    ) -> OracleEvaluation:
        paths = self.coordinator.paths_for(run_id)
        stdout = paths.baseline / "stdout.log"
        stderr = paths.baseline / "stderr.log"
        _write_private_file(stdout, outcome.stdout)
        _write_private_file(stderr, outcome.stderr)
        execution = OracleExecutionResult(
            outcome,
            stdout.relative_to(paths.root).as_posix(),
            hashlib.sha256(outcome.stdout).hexdigest(),
            stderr.relative_to(paths.root).as_posix(),
            hashlib.sha256(outcome.stderr).hexdigest(),
        )
        evaluation = self.command_oracle.evaluate(spec, OraclePhase.BASELINE, execution)
        write_canonical_json(paths.baseline_result, evaluation.model_dump(mode="json"))
        if evaluation.process.truncated:
            self.coordinator.append_event(
                run_id,
                "process.output_truncated",
                payload={"oracle_id": spec.id, "phase": OraclePhase.BASELINE.value},
            )
        event_payload: dict[str, JsonValue] = {
            "oracle_id": spec.id,
            "phase": OraclePhase.BASELINE.value,
            "passed": evaluation.passed,
            "failure_code": evaluation.failure_code,
            "process": evaluation.process.model_dump(mode="json"),
        }
        self.coordinator.append_event(
            run_id,
            "oracle.completed" if evaluation.passed else "oracle.failed",
            payload=event_payload,
        )
        return evaluation

    def _assert_investigation_clone_unchanged(
        self,
        clone: IndependentClone,
        snapshot: RepositorySnapshot,
        run_root: Path,
    ) -> None:
        validate_owned_clone(clone, run_root)
        head = self.patching.git.text(
            ["-C", str(clone.root), "rev-parse", "--verify", "HEAD^{commit}"],
            cwd=clone.root,
            operation="investigation clone HEAD validation",
        )
        status = self.patching.git.run(
            ["-C", str(clone.root), "status", "--porcelain=v1", "-z"],
            cwd=clone.root,
            operation="investigation clone write-isolation validation",
        ).stdout
        if head != snapshot.baseline_commit or status:
            raise ContractError("Investigator modified its read-only source workspace")

    def _persist_investigation_logs(
        self,
        run_id: str,
        outcome: ProcessOutcome,
    ) -> dict[str, JsonValue]:
        paths = self.coordinator.paths_for(run_id)
        paths.investigation.mkdir(mode=0o700, exist_ok=True)
        paths.investigation.chmod(0o700)
        stdout = paths.investigation / "agent-stdout.log"
        stderr = paths.investigation / "agent-stderr.log"
        _write_private_file(stdout, outcome.stdout)
        _write_private_file(stderr, outcome.stderr)
        return {
            "stdout_path": stdout.relative_to(paths.root).as_posix(),
            "stdout_sha256": hashlib.sha256(outcome.stdout).hexdigest(),
            "stdout_bytes": len(outcome.stdout),
            "stderr_path": stderr.relative_to(paths.root).as_posix(),
            "stderr_sha256": hashlib.sha256(outcome.stderr).hexdigest(),
            "stderr_bytes": len(outcome.stderr),
        }

    def _detect_agent_version(
        self,
        run_id: str,
        snapshot: RepositorySnapshot,
        plan: InvestigationPlan,
        clone: IndependentClone,
    ) -> AgentVersionMetadata:
        """Probe the CLI in a separate protected, credential-free container."""

        probe = plan.version_probe
        if probe is None:  # pragma: no cover - guarded by caller
            raise AgentError("Agent version probe is unavailable")
        paths = self.coordinator.paths_for(run_id)
        limits = ResourceLimits(
            timeout_seconds=min(30.0, plan.investigation_resources.timeout_seconds),
            memory_mb=plan.investigation_resources.memory_mb,
            cpus=plan.investigation_resources.cpus,
            pids=plan.investigation_resources.pids,
            output_bytes=4096,
        )
        try:
            result = self.backend.run(
                ExecutionRequest(
                    execution_id="agent-version",
                    run_id=run_id,
                    phase=ExecutionPhase.INVESTIGATION,
                    image=plan.investigator_image,
                    argv=probe.argv,
                    network=NetworkPolicy.NONE,
                    mounts=(
                        DockerMount(
                            source=clone.root,
                            destination="/workspace",
                            kind=MountKind.WORKSPACE,
                            access=MountAccess.READ_ONLY,
                        ),
                    ),
                    environment={},
                    environment_allowlist=(),
                    resources=limits,
                    original_repository=Path(snapshot.repository_root),
                    evidence_directory=paths.root,
                    disposable_work_directory=paths.workspaces,
                )
            )
            outcome = _protected_process_outcome(result)
        except BackendError as error:
            self._reject(run_id, "agent_version_probe_failed")
            raise AgentError("Protected agent CLI version detection failed") from error
        if outcome.termination is not TerminationKind.EXITED or outcome.exit_code != 0:
            self._reject(run_id, "agent_version_probe_failed")
            raise AgentError("Agent CLI version command did not complete successfully")
        try:
            version = parse_and_require_version(
                outcome.stdout,
                outcome.stderr,
                probe.minimum_version,
            )
        except AgentError:
            self._reject(run_id, "agent_version_unsupported")
            raise
        paths.investigation.mkdir(mode=0o700, exist_ok=True)
        stdout = paths.investigation / "agent-version-stdout.log"
        stderr = paths.investigation / "agent-version-stderr.log"
        _write_private_file(stdout, outcome.stdout)
        _write_private_file(stderr, outcome.stderr)
        metadata = AgentVersionMetadata(
            adapter=plan.adapter_name,
            adapter_version=plan.adapter_version,
            agent_cli_version=version,
            minimum_cli_version=".".join(str(part) for part in probe.minimum_version),
            agent_model=probe.agent_model,
            stdout_sha256=hashlib.sha256(outcome.stdout).hexdigest(),
            stderr_sha256=hashlib.sha256(outcome.stderr).hexdigest(),
        )
        write_canonical_json(paths.agent_version, metadata.model_dump(mode="json"))
        self.coordinator.append_event(
            run_id,
            "agent.version_detected",
            payload={
                "adapter": metadata.adapter,
                "adapter_version": metadata.adapter_version,
                "agent_cli_version": metadata.agent_cli_version,
                "agent_model": metadata.agent_model,
                "metadata_sha256": hashlib.sha256(
                    canonical_json_bytes(metadata.model_dump(mode="json"))
                ).hexdigest(),
            },
        )
        return metadata

    def _reject(self, run_id: str, reason: str) -> None:
        self.coordinator.append_event(
            run_id,
            "contract.rejected",
            payload={"reason": reason},
        )
        self.coordinator.transition(run_id, RunState.ERROR, details={"reason": reason})


def render_investigation_prompt(issue_summary: str) -> str:
    template = (Path(__file__).parent.parent / "prompts" / "investigation.md").read_text(
        encoding="utf-8"
    )
    return template.replace("{issue_summary}", issue_summary)


def _process_outcome(value: object) -> ProcessOutcome:
    if not isinstance(value, ProcessOutcome):
        raise BackendError("Execution backend returned an invalid process outcome")
    return value


def _protected_process_outcome(result: ExecutionResult) -> ProcessOutcome:
    if (
        result.protection.level is not ProtectionLevel.PROTECTED
        or result.protection.failures
        or not result.cleanup_confirmed
    ):
        raise BackendError("Execution backend did not establish or clean up protected execution")
    return _process_outcome(result.outcome)


def _limits_with_timeout(limits: ResourceLimits, timeout: float) -> ResourceLimits:
    return ResourceLimits(
        timeout_seconds=timeout,
        memory_mb=limits.memory_mb,
        cpus=limits.cpus,
        pids=limits.pids,
        output_bytes=limits.output_bytes,
    )


def _path_exists_without_following(path: Path) -> bool:
    try:
        path.lstat()
    except FileNotFoundError:
        return False
    except OSError as error:
        raise ContractError("Could not inspect investigation outcome") from error
    return True


def _write_private_file(path: Path, content: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags, PRIVATE_FILE_MODE)
        file_status = os.fstat(descriptor)
        if not stat.S_ISREG(file_status.st_mode) or file_status.st_nlink != 1:
            raise OSError("log path is not a private regular file")
        view = memoryview(content)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short log write")
            view = view[written:]
        os.fsync(descriptor)
        os.chmod(path, PRIVATE_FILE_MODE)
    except OSError as error:
        raise EvidenceIntegrityError("Could not persist baseline process log") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
