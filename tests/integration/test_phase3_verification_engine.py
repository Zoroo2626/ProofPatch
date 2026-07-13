"""End-to-end Phase 3 proof tests over deterministic fixture repositories."""

import shutil
import sys
from pathlib import Path

import pytest

from proofpatch.git.client import GitClient
from proofpatch.models.execution import (
    CommandOracleSpec,
    ExitCodeMatcherSpec,
    ExitCodeOperator,
    OracleExpectation,
    TextMatcherSpec,
    TextOperator,
)
from proofpatch.models.receipt import VerificationReceipt
from proofpatch.models.state import RunState
from proofpatch.services.coordinator import RunCoordinator
from proofpatch.services.data_directories import ApplicationDirectories
from proofpatch.services.evidence import read_canonical_json
from proofpatch.services.patching import PatchService
from proofpatch.services.verification import VerificationPlan, VerificationService

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "repos"


def _git(git: GitClient, repository: Path, *args: str) -> bytes:
    return git.run(
        ["-C", str(repository), *args],
        cwd=repository,
        operation="Phase 3 fixture setup",
    ).stdout


def _repository_and_patch(
    tmp_path: Path,
    target_fixture: str,
    *,
    baseline_fixture: str = "failing_bug",
) -> tuple[Path, Path, GitClient]:
    repository = tmp_path / "repository"
    shutil.copytree(FIXTURES / baseline_fixture, repository)
    git = GitClient()
    _git(git, repository, "init", "--initial-branch=main")
    _git(git, repository, "config", "user.name", "ProofPatch Test")
    _git(git, repository, "config", "user.email", "proofpatch@example.invalid")
    _git(git, repository, "add", "-A", "--")
    _git(git, repository, "commit", "-m", "baseline")

    target = FIXTURES / target_fixture
    for source in target.iterdir():
        if source.is_file():
            shutil.copy2(source, repository / source.name)
    patch_bytes = _git(
        git,
        repository,
        "diff",
        "--binary",
        "--full-index",
        "--no-ext-diff",
        "--no-textconv",
        "HEAD",
        "--",
    )
    candidate = tmp_path / "candidate.diff"
    candidate.write_bytes(patch_bytes if patch_bytes else b"unused baseline rejection fixture\n")
    _git(git, repository, "reset", "--hard", "HEAD", "--")
    return repository, candidate, git


def _plan() -> VerificationPlan:
    reproduction = CommandOracleSpec(
        id="calculator-add",
        argv=(sys.executable, "reproduce.py"),
        timeout_seconds=10,
        baseline_expectation=OracleExpectation(
            exit_code=ExitCodeMatcherSpec(operator=ExitCodeOperator.NOT_EQUAL, value=0),
            stdout=(TextMatcherSpec(operator=TextOperator.CONTAINS, value="add(2, 3)="),),
        ),
        fixed_expectation=OracleExpectation(
            exit_code=ExitCodeMatcherSpec(operator=ExitCodeOperator.EQUAL, value=0),
            stdout=(TextMatcherSpec(operator=TextOperator.REGEX, value=r"add\(2, 3\)=5"),),
        ),
    )
    regression = CommandOracleSpec(
        id="calculator-regression",
        argv=(sys.executable, "regression.py"),
        timeout_seconds=10,
        expectation=OracleExpectation(
            exit_code=ExitCodeMatcherSpec(operator=ExitCodeOperator.EQUAL, value=0)
        ),
    )
    return VerificationPlan(
        reproduction=reproduction,
        regressions=(regression,),
        maximum_output_bytes=1024 * 1024,
    )


def _service(tmp_path: Path, git: GitClient) -> VerificationService:
    coordinator = RunCoordinator(ApplicationDirectories(tmp_path / "data"))
    patching = PatchService(coordinator, git)
    return VerificationService(coordinator, patching=patching)


def test_valid_patch_proves_failure_to_success_and_generates_exact_receipt(
    tmp_path: Path,
) -> None:
    repository, candidate, git = _repository_and_patch(tmp_path, "fixed_bug")
    service = _service(tmp_path, git)
    run_id = "pp_20260713_444444444444"
    outcome = service.verify_patch(
        repository,
        candidate,
        _plan(),
        issue_summary="Calculator addition returns subtraction",
        run_id=run_id,
    )

    assert outcome.verified
    assert outcome.receipt.status == "verified"
    assert outcome.receipt.protection_level == "observation_only"
    assert outcome.receipt.baseline.failure_reproduced
    assert outcome.receipt.verification.reproduction_transition_passed
    assert outcome.receipt.verification.regressions_passed
    assert service.coordinator.status(run_id).state is RunState.VERIFIED
    persisted = VerificationReceipt.model_validate(read_canonical_json(outcome.json_path))
    assert persisted == outcome.receipt
    assert service.receipts.verify(outcome.receipt.run_id) == outcome.receipt
    markdown = outcome.markdown_path.read_text(encoding="utf-8").lower()
    assert "observation only" in markdown
    assert "bug free" not in markdown
    assert "secure" not in markdown
    assert "correct" not in markdown
    event_types = {event.type for event in service.coordinator.status(run_id).events}
    assert {
        "baseline.reproduced",
        "oracle.started",
        "oracle.completed",
        "verification.started",
        "verification.completed",
        "run.verified",
        "receipt.created",
    } <= event_types


@pytest.mark.parametrize(
    ("target_fixture", "expected_code"),
    [
        ("fake_fix", "PP_REGRESSION_FAILED"),
        ("regression_failure", "PP_REGRESSION_FAILED"),
    ],
)
def test_fake_fix_and_regression_failure_are_rejected(
    tmp_path: Path,
    target_fixture: str,
    expected_code: str,
) -> None:
    repository, candidate, git = _repository_and_patch(tmp_path, target_fixture)
    service = _service(tmp_path, git)
    outcome = service.verify_patch(
        repository,
        candidate,
        _plan(),
        issue_summary="Calculator fixture",
        run_id="pp_20260713_555555555555",
    )
    assert not outcome.verified
    assert outcome.receipt.rejection_code == expected_code
    assert outcome.receipt.verification.reproduction_transition_passed
    assert not outcome.receipt.verification.regressions_passed
    assert service.coordinator.status(outcome.receipt.run_id).state is RunState.REJECTED


def test_known_passing_baseline_is_rejected_as_not_reproduced(tmp_path: Path) -> None:
    repository, candidate, git = _repository_and_patch(
        tmp_path,
        "fixed_bug",
        baseline_fixture="fixed_bug",
    )
    service = _service(tmp_path, git)
    outcome = service.verify_patch(
        repository,
        candidate,
        _plan(),
        issue_summary="Already passing fixture",
        run_id="pp_20260713_666666666666",
    )
    assert not outcome.verified
    assert outcome.receipt.rejection_code == "PP_BASELINE_NOT_REPRODUCED"
    assert outcome.receipt.patch is None
    assert service.coordinator.status(outcome.receipt.run_id).state is RunState.REJECTED
