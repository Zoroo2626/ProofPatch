"""Phase 9 receipt publishing and GitHub workflow security tests."""

import re
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml
from typer.testing import CliRunner

import proofpatch.cli as cli
import proofpatch.integrations.github as github_integration
from proofpatch.errors import ConfigurationError, EvidenceIntegrityError
from proofpatch.integrations.github import (
    ARTIFACT_FILENAMES,
    GitHubReceiptExport,
    GitHubReceiptExporter,
    append_github_environment_file,
    append_github_outputs,
    escape_github_markdown,
    render_github_comment,
    render_github_summary,
)
from proofpatch.models.execution import ProtectionLevel
from proofpatch.models.receipt import (
    ReceiptBaseline,
    ReceiptContract,
    ReceiptEvidence,
    ReceiptProject,
    ReceiptVerification,
    VerificationReceipt,
)
from proofpatch.services.coordinator import RunCoordinator
from proofpatch.services.data_directories import ApplicationDirectories
from proofpatch.services.receipt import ReceiptService, _read_private_file, _write_private_file
from proofpatch.services.verification import VerificationOutcome

PROJECT_ROOT = Path(__file__).resolve().parents[2]
RUNNER = CliRunner()


def test_private_receipt_io_rejects_missing_existing_oversized_and_short_writes(
    tmp_path: Path,
) -> None:
    missing = tmp_path / "missing.md"
    with pytest.raises(EvidenceIntegrityError, match="safely read"):
        _read_private_file(missing)

    existing = tmp_path / "existing.md"
    existing.write_bytes(b"content")
    with pytest.raises(EvidenceIntegrityError, match="safely write"):
        _write_private_file(existing, b"replacement")

    oversized = tmp_path / "oversized.md"
    oversized.write_bytes(b"x" * (1024 * 1024 + 1))
    with pytest.raises(EvidenceIntegrityError, match="size limit"):
        _read_private_file(oversized)

    short = tmp_path / "short.md"
    with (
        patch("proofpatch.services.receipt.os.write", return_value=0),
        pytest.raises(EvidenceIntegrityError, match="safely write"),
    ):
        _write_private_file(short, b"content")

    non_regular = tmp_path / "non-regular.md"
    with (
        patch("proofpatch.services.receipt.os.fstat", return_value=tmp_path.stat()),
        pytest.raises(EvidenceIntegrityError, match="private regular file"),
    ):
        _write_private_file(non_regular, b"content")


def _receipt(issue: str = "Wrong result") -> VerificationReceipt:
    return VerificationReceipt(
        proofpatch_version="0.1.0",
        run_id="pp_20260713_999999999999",
        status="verified",
        protection_level=ProtectionLevel.OBSERVATION_ONLY,
        backend="native",
        created_at_utc="2026-07-13T10:00:00.000000Z",
        completed_at_utc="2026-07-13T10:01:00.000000Z",
        project=ReceiptProject(
            name="fixture",
            repository_id="repo_9999999999999999",
            baseline_commit="a" * 40,
        ),
        issue_summary=issue,
        contract=ReceiptContract(id="verification-plan", sha256="b" * 64),
        baseline=ReceiptBaseline(failure_reproduced=True, exit_code=1, duration_ms=10),
        patch=None,
        verification=ReceiptVerification(
            reproduction_transition_passed=True,
            regressions_passed=True,
            oracles=(),
        ),
        evidence=ReceiptEvidence(decision_chain_hash="c" * 64),
    )


def test_export_contains_only_verified_receipts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    receipt = _receipt()
    monkeypatch.setattr(ReceiptService, "verify", lambda _self, _run_id: receipt)
    coordinator = RunCoordinator(ApplicationDirectories(tmp_path / "data"))
    output = (tmp_path / "artifact").resolve()

    exported = GitHubReceiptExporter(coordinator).export(receipt.run_id, output)

    assert {path.name for path in output.iterdir()} == ARTIFACT_FILENAMES
    assert exported.receipt_json.read_text(encoding="utf-8").endswith("\n")
    assert "repository source and patch content are not uploaded" in exported.summary
    with pytest.raises(ConfigurationError, match="must not already exist"):
        GitHubReceiptExporter(coordinator).export(receipt.run_id, output)


def test_github_text_escapes_active_untrusted_markdown() -> None:
    issue = "@maintainer <img src=x> [click](https://evil.invalid) `code`"
    receipt = _receipt(issue)

    summary = render_github_summary(receipt)
    comment = render_github_comment(receipt)

    assert "@maintainer" not in summary
    assert "<img" not in summary
    assert "[click](" not in summary
    assert "@maintainer" not in comment
    assert comment.startswith("<!-- proofpatch-receipt -->")
    assert escape_github_markdown("# x") == r"\# x"


def test_environment_file_requires_absolute_existing_regular_file(tmp_path: Path) -> None:
    output = tmp_path / "GITHUB_STEP_SUMMARY"
    output.write_text("", encoding="utf-8")

    append_github_environment_file(output.resolve(), "safe\n")

    assert output.read_text(encoding="utf-8") == "safe\n"
    with pytest.raises(ConfigurationError, match="must be absolute"):
        append_github_environment_file(Path("relative"), "unsafe")


def test_action_outputs_use_safe_multiline_environment_protocol(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    receipt = _receipt()
    monkeypatch.setattr(ReceiptService, "verify", lambda _self, _run_id: receipt)
    coordinator = RunCoordinator(ApplicationDirectories(tmp_path / "data"))
    exported = GitHubReceiptExporter(coordinator).export(
        receipt.run_id, (tmp_path / "artifact").resolve()
    )
    output = tmp_path / "GITHUB_OUTPUT"
    output.write_text("", encoding="utf-8")

    append_github_outputs(output.resolve(), exported)

    content = output.read_text(encoding="utf-8")
    assert f"run-id={receipt.run_id}" in content
    assert "verified=true" in content
    assert re.search(r"comment-body<<proofpatch_[0-9a-f]{32}", content) is not None


def test_github_publication_rejects_relative_paths_and_unbounded_text(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    receipt = _receipt()
    monkeypatch.setattr(ReceiptService, "verify", lambda _self, _run_id: receipt)
    coordinator = RunCoordinator(ApplicationDirectories(tmp_path / "data"))

    with pytest.raises(ConfigurationError, match="must be absolute"):
        GitHubReceiptExporter(coordinator).export(receipt.run_id, Path("artifact"))
    with pytest.raises(ConfigurationError, match="exceeds 60 KiB"):
        append_github_environment_file((tmp_path / "missing").resolve(), "x" * 70000)
    with pytest.raises(ConfigurationError, match="Could not write"):
        append_github_environment_file((tmp_path / "missing").resolve(), "bounded")


def test_export_fails_closed_if_staging_gains_an_unexpected_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    receipt = _receipt()
    monkeypatch.setattr(ReceiptService, "verify", lambda _self, _run_id: receipt)
    original_write = github_integration._write_new_file

    def write_with_intruder(path: Path, content: bytes) -> None:
        original_write(path, content)
        if path.name == "receipt.md":
            (path.parent / "source.py").write_text("must not upload", encoding="utf-8")

    monkeypatch.setattr(github_integration, "_write_new_file", write_with_intruder)
    coordinator = RunCoordinator(ApplicationDirectories(tmp_path / "data"))
    output = (tmp_path / "artifact").resolve()

    with pytest.raises(EvidenceIntegrityError, match="non-receipt file"):
        GitHubReceiptExporter(coordinator).export(receipt.run_id, output)

    assert not (output / "receipt.json").exists()
    assert not (output / "receipt.md").exists()
    assert (output / "source.py").is_file()


def test_rejected_receipt_summary_states_unobserved_results() -> None:
    receipt = _receipt().model_copy(
        update={
            "status": "rejected",
            "baseline": ReceiptBaseline(
                failure_reproduced=False,
                exit_code=0,
                duration_ms=10,
            ),
            "verification": ReceiptVerification(
                reproduction_transition_passed=False,
                regressions_passed=False,
                oracles=(),
            ),
            "rejection_code": "PP_BASELINE_NOT_REPRODUCED",
        }
    )

    summary = render_github_summary(receipt)
    comment = render_github_comment(receipt)

    assert "Not reproduced" in summary
    assert "Required transition not observed" in summary
    assert "| Regressions | Failed |" in summary
    assert "**REJECTED**" in comment


def test_primary_action_uploads_only_allowlisted_receipt_paths() -> None:
    action = yaml.safe_load((PROJECT_ROOT / "action.yml").read_text(encoding="utf-8"))
    steps = action["runs"]["steps"]
    upload = next(step for step in steps if step.get("id") == "upload")
    upload_paths = {line.strip() for line in upload["with"]["path"].splitlines() if line.strip()}

    assert upload_paths == {
        "${{ steps.verify.outputs.receipt-json }}",
        "${{ steps.verify.outputs.receipt-markdown }}",
    }
    assert "patch" not in upload["with"]["path"].lower()
    assert "token" not in action["inputs"]
    assert re.fullmatch(r"[0-9a-f]{40}", upload["uses"].rsplit("@", 1)[1])


def test_comment_action_is_separate_and_scopes_token_to_post_step() -> None:
    comment_path = PROJECT_ROOT / ".github" / "actions" / "comment" / "action.yml"
    action = yaml.safe_load(comment_path.read_text(encoding="utf-8"))
    step = action["runs"]["steps"][0]

    assert action["inputs"]["token"]["required"] is True
    assert step["env"]["GH_TOKEN"] == "${{ inputs.token }}"  # noqa: S105
    assert "checkout" not in comment_path.read_text(encoding="utf-8").lower()


def test_verify_patch_cli_publishes_github_files_before_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    receipt = _receipt()
    persisted_json = tmp_path / "persisted.json"
    persisted_markdown = tmp_path / "persisted.md"
    patch = tmp_path / "candidate.diff"
    patch.write_text("patch", encoding="utf-8")
    summary = tmp_path / "GITHUB_STEP_SUMMARY"
    output = tmp_path / "GITHUB_OUTPUT"
    summary.write_text("", encoding="utf-8")
    output.write_text("", encoding="utf-8")
    artifact = (tmp_path / "artifact").resolve()
    exported = GitHubReceiptExport(
        run_id=receipt.run_id,
        receipt_json=artifact / "receipt.json",
        receipt_markdown=artifact / "receipt.md",
        summary="safe summary\n",
        comment="safe comment",
        verified=True,
    )

    class FakeVerificationService:
        def verify_patch(self, *_args: object, **_kwargs: object) -> VerificationOutcome:
            return VerificationOutcome(receipt, persisted_json, persisted_markdown)

    class FakeExporter:
        def __init__(self, _coordinator: object) -> None:
            pass

        def export(self, run_id: str, directory: Path) -> GitHubReceiptExport:
            assert run_id == receipt.run_id
            assert directory == artifact
            return exported

    monkeypatch.setattr(cli, "_verification_service", FakeVerificationService)
    monkeypatch.setattr(cli, "_coordinator", object)
    monkeypatch.setattr(cli, "GitHubReceiptExporter", FakeExporter)

    result = RUNNER.invoke(
        cli.app,
        [
            "verify-patch",
            "--baseline-command",
            "python reproduce.py",
            "--patch-file",
            str(patch),
            "--repository",
            str(tmp_path),
            "--github-artifact-directory",
            str(artifact),
            "--github-summary-file",
            str(summary),
            "--github-output-file",
            str(output),
        ],
    )

    assert result.exit_code == 0
    assert "Observed transition" in result.output
    assert summary.read_text(encoding="utf-8") == "safe summary\n"
    assert "verified=true" in output.read_text(encoding="utf-8")


def test_verify_patch_cli_rejects_partial_github_publication_options(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    receipt = _receipt()
    patch = tmp_path / "candidate.diff"
    patch.write_text("patch", encoding="utf-8")

    class FakeVerificationService:
        def verify_patch(self, *_args: object, **_kwargs: object) -> VerificationOutcome:
            return VerificationOutcome(receipt, tmp_path / "receipt.json", tmp_path / "receipt.md")

    monkeypatch.setattr(cli, "_verification_service", FakeVerificationService)
    result = RUNNER.invoke(
        cli.app,
        [
            "verify-patch",
            "--baseline-command",
            "python reproduce.py",
            "--patch-file",
            str(patch),
            "--repository",
            str(tmp_path),
            "--github-artifact-directory",
            str(tmp_path / "artifact"),
        ],
    )

    assert result.exit_code != 0
    assert "All three GitHub publication paths" in str(result.exception)
