"""Phase 3 orchestration proving an observed failure-to-success transition."""

import hashlib
from dataclasses import dataclass
from pathlib import Path

from proofpatch import __version__
from proofpatch.errors import (
    ConfigurationError,
    EvidenceIntegrityError,
    PatchError,
    RepositoryError,
)
from proofpatch.execution.process import ProcessRunner
from proofpatch.git.apply import apply_patch_bytes, check_patch_applies
from proofpatch.git.clone import CloneKind
from proofpatch.git.diff import sha256_file, verify_patch_hash
from proofpatch.models.common import JsonValue, format_utc_timestamp
from proofpatch.models.execution import (
    ENVIRONMENT_NAME,
    CommandOracleSpec,
    OracleEvaluation,
    OraclePhase,
)
from proofpatch.models.patch import PatchRecord, RepositorySnapshot
from proofpatch.models.receipt import (
    ReceiptBaseline,
    ReceiptContract,
    ReceiptEvidence,
    ReceiptPatch,
    ReceiptProject,
    ReceiptVerification,
    VerificationReceipt,
)
from proofpatch.models.state import RunState
from proofpatch.oracles.base import OracleExecutionContext
from proofpatch.oracles.registry import OracleRegistry
from proofpatch.security.secrets import SecretRedactor
from proofpatch.services.coordinator import RunCoordinator
from proofpatch.services.evidence import (
    canonical_json_bytes,
    read_canonical_json,
    write_canonical_json,
)
from proofpatch.services.identifiers import generate_run_id
from proofpatch.services.patching import PatchService
from proofpatch.services.receipt import ReceiptService


@dataclass(frozen=True, slots=True)
class VerificationPlan:
    """Immutable reproduction and required regression specifications."""

    reproduction: CommandOracleSpec
    regressions: tuple[CommandOracleSpec, ...] = ()
    maximum_output_bytes: int = 25 * 1024 * 1024

    def __post_init__(self) -> None:
        if self.reproduction.baseline_expectation is None:
            raise ConfigurationError("Reproduction oracle requires baseline and fixed expectations")
        if any(regression.expectation is None for regression in self.regressions):
            raise ConfigurationError("Regression oracles require one fixed expectation")
        ids = [self.reproduction.id, *(regression.id for regression in self.regressions)]
        if len(self.regressions) > 128:
            raise ConfigurationError("Verification supports at most 128 regression oracles")
        if len(ids) != len(set(ids)):
            raise ConfigurationError("Oracle IDs must be unique")
        if self.maximum_output_bytes <= 0:
            raise ConfigurationError("Verification output limit must be positive")


@dataclass(frozen=True, slots=True)
class VerificationOutcome:
    """Final receipt plus its persisted paths."""

    receipt: VerificationReceipt
    json_path: Path
    markdown_path: Path

    @property
    def verified(self) -> bool:
        return self.receipt.status == "verified"


class VerificationService:
    """Never trust a patch producer; execute before and after in separate fresh clones."""

    def __init__(
        self,
        coordinator: RunCoordinator,
        *,
        patching: PatchService | None = None,
        runner: ProcessRunner | None = None,
        registry: OracleRegistry | None = None,
    ) -> None:
        self.coordinator = coordinator
        self.patching = PatchService(coordinator) if patching is None else patching
        self.runner = ProcessRunner() if runner is None else runner
        self.registry = OracleRegistry() if registry is None else registry
        self.receipts = ReceiptService(coordinator)

    def verify_patch(
        self,
        repository: Path,
        candidate_patch: Path,
        plan: VerificationPlan,
        *,
        issue_summary: str,
        project_name: str | None = None,
        run_id: str | None = None,
        secret_environment: dict[str, str] | None = None,
    ) -> VerificationOutcome:
        """Observe baseline failure, exact-patch success, and all required regressions."""

        secrets = {} if secret_environment is None else dict(secret_environment)
        if any(ENVIRONMENT_NAME.fullmatch(name) is None for name in secrets):
            raise ConfigurationError("Secret environment contains an invalid variable name")
        if any(not value or "\0" in value for value in secrets.values()):
            raise ConfigurationError("Secret environment values must be nonempty and NUL-free")
        redactor = SecretRedactor.from_values(list(secrets.values()))
        _reject_secret_in_persisted_value(
            {
                "issue_summary": issue_summary,
                "reproduction": plan.reproduction.model_dump(mode="json"),
                "regressions": [item.model_dump(mode="json") for item in plan.regressions],
            },
            redactor,
        )
        selected_run_id = generate_run_id() if run_id is None else run_id
        snapshot = self.patching.prepare_run(repository, run_id=selected_run_id)
        paths = self.coordinator.paths_for(selected_run_id)
        paths.verification.mkdir(mode=0o700, exist_ok=False)
        contract_value = {
            "schema_version": 1,
            "reproduction": plan.reproduction.model_dump(mode="json"),
            "regressions": [item.model_dump(mode="json") for item in plan.regressions],
            "maximum_output_bytes": plan.maximum_output_bytes,
            "issue_summary": issue_summary,
            "secret_environment_names": sorted(secrets),
        }
        contract_bytes = canonical_json_bytes(contract_value)
        contract_sha256 = hashlib.sha256(contract_bytes).hexdigest()
        write_canonical_json(paths.contract, contract_value)
        self.coordinator.append_event(
            selected_run_id,
            "contract.validated",
            payload={
                "oracle_id": plan.reproduction.id,
                "sha256": contract_sha256,
                "regression_ids": [item.id for item in plan.regressions],
            },
        )

        self.coordinator.transition(selected_run_id, RunState.BASELINE_PREPARING)
        baseline_clone = self.patching.create_clone(
            selected_run_id,
            CloneKind.BASELINE_VERIFICATION,
        )
        self.coordinator.transition(selected_run_id, RunState.BASELINE_VERIFYING)
        baseline = self._execute(
            selected_run_id,
            plan.reproduction,
            OraclePhase.BASELINE,
            baseline_clone.root,
            paths.verification / "baseline" / plan.reproduction.id,
            plan.maximum_output_bytes,
            secrets,
        )
        evaluations: list[OracleEvaluation] = [baseline]
        if not baseline.passed:
            self.coordinator.append_event(
                selected_run_id,
                "baseline.not_reproduced",
                payload={"oracle_id": baseline.oracle_id},
            )
            self.coordinator.transition(
                selected_run_id,
                RunState.BASELINE_NOT_REPRODUCED,
                details={
                    "contract_sha256": contract_sha256,
                    "rejection_code": "PP_BASELINE_NOT_REPRODUCED",
                    "oracle_id": baseline.oracle_id,
                },
            )
            self.coordinator.transition(selected_run_id, RunState.REJECTED)
            return self._finish(
                selected_run_id,
                snapshot,
                issue_summary,
                project_name,
                contract_sha256,
                baseline,
                None,
                evaluations,
                reproduction_passed=False,
                regressions_passed=False,
                rejection_code="PP_BASELINE_NOT_REPRODUCED",
            )

        self.coordinator.append_event(
            selected_run_id,
            "baseline.reproduced",
            payload={"oracle_id": baseline.oracle_id},
        )
        self.coordinator.transition(
            selected_run_id,
            RunState.BASELINE_REPRODUCED,
            details={
                "contract_sha256": contract_sha256,
                "oracle_id": baseline.oracle_id,
                "exit_code": baseline.process.exit_code,
            },
        )
        self.coordinator.transition(selected_run_id, RunState.PATCH_PREPARING)
        patch_clone = self.patching.create_clone(selected_run_id, CloneKind.PATCH)
        self.coordinator.transition(selected_run_id, RunState.PATCHING)
        try:
            candidate_sha256 = sha256_file(candidate_patch)
            check_patch_applies(self.patching.git, patch_clone.root, candidate_patch)
            apply_patch_bytes(self.patching.git, patch_clone.root, candidate_patch)
            verify_patch_hash(candidate_patch, candidate_sha256)
            patch_record = self.patching.capture(selected_run_id, patch_clone)
        except (PatchError, RepositoryError):
            self.coordinator.transition(
                selected_run_id,
                RunState.REJECTED,
                details={"rejection_code": "PP_PATCH_APPLY_FAILED"},
            )
            return self._finish(
                selected_run_id,
                snapshot,
                issue_summary,
                project_name,
                contract_sha256,
                baseline,
                None,
                evaluations,
                reproduction_passed=False,
                regressions_passed=False,
                rejection_code="PP_PATCH_APPLY_FAILED",
            )

        self.coordinator.transition(selected_run_id, RunState.FINAL_VERIFYING)
        self.coordinator.append_event(
            selected_run_id,
            "verification.started",
            payload={
                "contract_sha256": contract_sha256,
                "patch_sha256": patch_record.patch_sha256,
            },
        )
        final_workspace = self.patching.verify_application(selected_run_id)
        stored_contract_hash = hashlib.sha256(
            canonical_json_bytes(read_canonical_json(paths.contract))
        ).hexdigest()
        if stored_contract_hash != contract_sha256:
            raise EvidenceIntegrityError(
                "Verification contract changed between baseline and fixed runs"
            )

        fixed = self._execute(
            selected_run_id,
            plan.reproduction,
            OraclePhase.FIXED,
            final_workspace,
            paths.verification / "fixed" / plan.reproduction.id,
            plan.maximum_output_bytes,
            secrets,
        )
        evaluations.append(fixed)
        regression_results: list[OracleEvaluation] = []
        for regression in plan.regressions:
            result = self._execute(
                selected_run_id,
                regression,
                OraclePhase.REGRESSION,
                final_workspace,
                paths.verification / "regressions" / regression.id,
                plan.maximum_output_bytes,
                secrets,
            )
            regression_results.append(result)
            evaluations.append(result)

        regressions_passed = all(result.passed for result in regression_results)
        if fixed.passed and regressions_passed:
            rejection_code = None
            self.coordinator.transition(
                selected_run_id,
                RunState.VERIFIED,
                details={
                    "contract_sha256": contract_sha256,
                    "patch_sha256": patch_record.patch_sha256,
                    "reproduction_transition_passed": True,
                    "regressions_passed": True,
                },
            )
            self.coordinator.append_event(
                selected_run_id,
                "verification.completed",
                payload={
                    "contract_sha256": contract_sha256,
                    "patch_sha256": patch_record.patch_sha256,
                    "regressions": len(regression_results),
                },
            )
            self.coordinator.append_event(
                selected_run_id,
                "run.verified",
                payload={"patch_sha256": patch_record.patch_sha256},
            )
        else:
            rejection_code = _verification_rejection_code(fixed, regression_results)
            self.coordinator.transition(
                selected_run_id,
                RunState.REJECTED,
                details={
                    "contract_sha256": contract_sha256,
                    "patch_sha256": patch_record.patch_sha256,
                    "rejection_code": rejection_code,
                },
            )
            self.coordinator.append_event(
                selected_run_id,
                "verification.rejected",
                payload={
                    "rejection_code": rejection_code,
                    "patch_sha256": patch_record.patch_sha256,
                },
            )
        return self._finish(
            selected_run_id,
            snapshot,
            issue_summary,
            project_name,
            contract_sha256,
            baseline,
            patch_record,
            evaluations,
            reproduction_passed=fixed.passed,
            regressions_passed=regressions_passed,
            rejection_code=rejection_code,
        )

    def _execute(
        self,
        run_id: str,
        spec: CommandOracleSpec,
        phase: OraclePhase,
        workspace: Path,
        log_directory: Path,
        maximum_output_bytes: int,
        secret_environment: dict[str, str],
    ) -> OracleEvaluation:
        oracle = self.registry.get(spec.type)
        oracle.validate(spec)
        argv_hash = hashlib.sha256(canonical_json_bytes(list(spec.argv))).hexdigest()
        self.coordinator.append_event(
            run_id,
            "oracle.started",
            payload={"oracle_id": spec.id, "phase": phase.value, "argv_sha256": argv_hash},
        )
        execution = oracle.execute(
            spec,
            OracleExecutionContext(
                workspace=workspace,
                run_root=self.coordinator.paths_for(run_id).root,
                log_directory=log_directory,
                runner=self.runner,
                maximum_output_bytes=maximum_output_bytes,
                secret_environment=secret_environment,
            ),
        )
        evaluation = oracle.evaluate(spec, phase, execution)
        write_canonical_json(
            log_directory / "result.json",
            evaluation.model_dump(mode="json"),
        )
        if evaluation.process.truncated:
            self.coordinator.append_event(
                run_id,
                "process.output_truncated",
                payload={"oracle_id": spec.id, "phase": phase.value},
            )
        event_payload: dict[str, JsonValue] = {
            "oracle_id": spec.id,
            "phase": phase.value,
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

    def _finish(
        self,
        run_id: str,
        snapshot: RepositorySnapshot,
        issue_summary: str,
        project_name: str | None,
        contract_sha256: str,
        baseline: OracleEvaluation,
        patch: PatchRecord | None,
        evaluations: list[OracleEvaluation],
        *,
        reproduction_passed: bool,
        regressions_passed: bool,
        rejection_code: str | None,
    ) -> VerificationOutcome:
        status = self.coordinator.status(run_id)
        receipt = VerificationReceipt(
            proofpatch_version=__version__,
            run_id=run_id,
            status="verified" if status.state is RunState.VERIFIED else "rejected",
            created_at_utc=status.manifest.created_at_utc,
            completed_at_utc=format_utc_timestamp(),
            project=ReceiptProject(
                name=Path(snapshot.repository_root).name if project_name is None else project_name,
                repository_id=snapshot.repository_id,
                baseline_commit=snapshot.baseline_commit,
            ),
            issue_summary=issue_summary,
            contract=ReceiptContract(id=baseline.oracle_id, sha256=contract_sha256),
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
                reproduction_transition_passed=reproduction_passed,
                regressions_passed=regressions_passed,
                oracles=tuple(evaluations),
            ),
            evidence=ReceiptEvidence(decision_chain_hash=status.final_event_hash),
            rejection_code=rejection_code,
        )
        json_path, markdown_path = self.receipts.generate(receipt)
        return VerificationOutcome(receipt, json_path, markdown_path)


def _verification_rejection_code(
    fixed: OracleEvaluation,
    regressions: list[OracleEvaluation],
) -> str:
    if fixed.failure_code == "PP_VERIFICATION_TIMEOUT" or any(
        result.failure_code == "PP_VERIFICATION_TIMEOUT" for result in regressions
    ):
        return "PP_VERIFICATION_TIMEOUT"
    if not fixed.passed:
        return "PP_REPRODUCTION_STILL_FAILS"
    return "PP_REGRESSION_FAILED"


def _reject_secret_in_persisted_value(value: object, redactor: SecretRedactor) -> None:
    if isinstance(value, str):
        if redactor.contains_secret(value):
            raise ConfigurationError("A configured secret appears in persisted verification input")
    elif isinstance(value, dict):
        for key, item in value.items():
            _reject_secret_in_persisted_value(key, redactor)
            _reject_secret_in_persisted_value(item, redactor)
    elif isinstance(value, list):
        for item in value:
            _reject_secret_in_persisted_value(item, redactor)
