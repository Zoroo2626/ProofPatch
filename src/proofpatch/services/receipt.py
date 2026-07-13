"""Canonical JSON and plain Markdown generation for observed verification results."""

import hashlib
import os
import stat
from pathlib import Path
from typing import Final

from pydantic import ValidationError

from proofpatch.errors import EvidenceIntegrityError, PatchError
from proofpatch.git.diff import verify_patch_hash
from proofpatch.models.contract import FailureContract
from proofpatch.models.execution import OracleEvaluation, OraclePhase, ProtectionLevel
from proofpatch.models.patch import PatchRecord, RepositorySnapshot
from proofpatch.models.receipt import VerificationReceipt
from proofpatch.models.state import RunState
from proofpatch.services.coordinator import RunCoordinator
from proofpatch.services.evidence import (
    canonical_json_bytes,
    read_canonical_json,
    write_canonical_json,
)

PRIVATE_FILE_MODE: Final = 0o600
MAX_RECEIPT_BYTES: Final = 8 * 1024 * 1024


class ReceiptService:
    """Persist a receipt and bind its exact hashes into the run event chain."""

    def __init__(self, coordinator: RunCoordinator) -> None:
        self.coordinator = coordinator

    def generate(self, receipt: VerificationReceipt) -> tuple[Path, Path]:
        paths = self.coordinator.paths_for(receipt.run_id)
        json_bytes = canonical_json_bytes(receipt.model_dump(mode="json")) + b"\n"
        markdown = render_markdown(receipt).encode("utf-8")
        write_canonical_json(paths.receipt_json, receipt.model_dump(mode="json"))
        _write_private_file(paths.receipt_markdown, markdown)
        self.coordinator.append_event(
            receipt.run_id,
            "receipt.created",
            payload={
                "status": receipt.status,
                "protection_level": receipt.protection_level,
                "json_path": paths.receipt_json.relative_to(paths.root).as_posix(),
                "json_sha256": hashlib.sha256(json_bytes).hexdigest(),
                "markdown_path": paths.receipt_markdown.relative_to(paths.root).as_posix(),
                "markdown_sha256": hashlib.sha256(markdown).hexdigest(),
            },
        )
        return paths.receipt_json, paths.receipt_markdown

    def verify(self, run_id: str) -> VerificationReceipt:
        """Verify receipt files, event binding, and the decision-chain checkpoint."""

        paths = self.coordinator.paths_for(run_id)
        try:
            receipt = VerificationReceipt.model_validate(
                read_canonical_json(paths.receipt_json, maximum_bytes=MAX_RECEIPT_BYTES)
            )
        except (ValidationError, EvidenceIntegrityError) as error:
            raise EvidenceIntegrityError("Verification receipt JSON is invalid") from error
        if receipt.run_id != run_id:
            raise EvidenceIntegrityError("Verification receipt belongs to another run")
        json_bytes = canonical_json_bytes(receipt.model_dump(mode="json")) + b"\n"
        markdown = _read_private_file(paths.receipt_markdown)
        status = self.coordinator.status(run_id)
        events = tuple(event for event in status.events if event.type == "receipt.created")
        if len(events) != 1:
            raise EvidenceIntegrityError("Verification receipt must have exactly one chain binding")
        event = events[0]
        if (
            event.previous_hash != receipt.evidence.decision_chain_hash
            or event.payload.get("json_sha256") != hashlib.sha256(json_bytes).hexdigest()
            or event.payload.get("markdown_sha256") != hashlib.sha256(markdown).hexdigest()
            or event.payload.get("status") != receipt.status
            or event.payload.get("protection_level") != receipt.protection_level.value
        ):
            raise EvidenceIntegrityError("Verification receipt event binding is invalid")
        self._verify_claims(receipt, status.state)
        return receipt

    def _verify_claims(self, receipt: VerificationReceipt, state: RunState) -> None:
        paths = self.coordinator.paths_for(receipt.run_id)
        if receipt.status == "verified":
            if state not in {RunState.VERIFIED, RunState.APPLIED}:
                raise EvidenceIntegrityError("Verified receipt conflicts with the run state")
        elif state is not RunState.REJECTED:
            raise EvidenceIntegrityError("Rejected receipt conflicts with the run state")
        try:
            snapshot = RepositorySnapshot.model_validate(read_canonical_json(paths.repository))
        except (ValidationError, EvidenceIntegrityError) as error:
            raise EvidenceIntegrityError("Receipt baseline artifacts are invalid") from error
        if paths.baseline_result.exists():
            try:
                baseline = OracleEvaluation.model_validate(
                    read_canonical_json(paths.baseline_result)
                )
            except (ValidationError, EvidenceIntegrityError) as error:
                raise EvidenceIntegrityError("Receipt baseline result is invalid") from error
        else:
            candidates = tuple(
                item for item in receipt.verification.oracles if item.phase is OraclePhase.BASELINE
            )
            if len(candidates) != 1:
                raise EvidenceIntegrityError("Receipt has no unique baseline observation")
            baseline = candidates[0]
            self._verify_oracle_event(receipt.run_id, baseline)
        if (
            receipt.project.repository_id != snapshot.repository_id
            or receipt.project.baseline_commit != snapshot.baseline_commit
            or receipt.baseline.failure_reproduced != baseline.passed
            or receipt.baseline.exit_code != baseline.process.exit_code
            or receipt.baseline.duration_ms != baseline.process.duration_ms
            or receipt.contract.id != baseline.oracle_id
        ):
            raise EvidenceIntegrityError("Receipt baseline claim does not match stored evidence")

        contract_path = (
            paths.submitted_contract if paths.submitted_contract.exists() else paths.contract
        )
        try:
            contract_document = read_canonical_json(contract_path)
            if contract_path == paths.submitted_contract:
                FailureContract.model_validate(contract_document)
        except (ValidationError, EvidenceIntegrityError) as error:
            raise EvidenceIntegrityError("Receipt contract artifact is invalid") from error
        if (
            hashlib.sha256(canonical_json_bytes(contract_document)).hexdigest()
            != receipt.contract.sha256
        ):
            raise EvidenceIntegrityError("Receipt contract hash does not match stored evidence")

        if receipt.patch is not None:
            try:
                patch = PatchRecord.model_validate(read_canonical_json(paths.changed_files))
                verify_patch_hash(paths.patch_diff, patch.patch_sha256)
            except (ValidationError, EvidenceIntegrityError, PatchError) as error:
                raise EvidenceIntegrityError("Receipt patch artifact is invalid") from error
            if (
                receipt.patch.sha256 != patch.patch_sha256
                or receipt.patch.changed_files != len(patch.changed_files)
                or patch.baseline_commit != snapshot.baseline_commit
            ):
                raise EvidenceIntegrityError("Receipt patch claim does not match stored evidence")
        if receipt.status == "verified":
            self._verify_verified_transition(receipt)
        if receipt.protection_level is ProtectionLevel.PROTECTED:
            self._verify_image_identity(receipt.run_id)

    def _verify_verified_transition(self, receipt: VerificationReceipt) -> None:
        if receipt.patch is None:
            raise EvidenceIntegrityError("Verified receipt has no patch claim")
        status = self.coordinator.status(receipt.run_id)
        matches = [
            event
            for event in status.events
            if event.type == "run.state_changed"
            and event.payload.get("to_state") == RunState.VERIFIED.value
        ]
        if len(matches) != 1:
            raise EvidenceIntegrityError("Verified receipt lacks one verified state transition")
        details = matches[0].payload.get("details")
        if not isinstance(details, dict) or (
            details.get("patch_sha256") != receipt.patch.sha256
            or details.get("contract_sha256") != receipt.contract.sha256
            or details.get("reproduction_transition_passed") is not True
            or details.get("regressions_passed") is not True
        ):
            raise EvidenceIntegrityError("Verified receipt conflicts with decision evidence")

    def _verify_image_identity(self, run_id: str) -> None:
        paths = self.coordinator.paths_for(run_id)
        plan = read_canonical_json(paths.workflow_plan)
        if not isinstance(plan, dict):
            raise EvidenceIntegrityError("Protected receipt workflow plan is invalid")
        agent = plan.get("agent_image")
        verifier = plan.get("verifier_image")
        if not isinstance(agent, dict) or not isinstance(verifier, dict):
            raise EvidenceIntegrityError("Protected receipt has no resolved image identities")
        status = self.coordinator.status(run_id)
        matches = [event for event in status.events if event.type == "investigation.started"]
        if len(matches) != 1 or (
            matches[0].payload.get("investigator_image_digest") != agent.get("digest")
            or matches[0].payload.get("verifier_image_digest") != verifier.get("digest")
        ):
            raise EvidenceIntegrityError("Protected receipt image identity binding is invalid")

    def _verify_oracle_event(self, run_id: str, evaluation: OracleEvaluation) -> None:
        status = self.coordinator.status(run_id)
        matches = [
            event
            for event in status.events
            if event.type in {"oracle.completed", "oracle.failed"}
            and event.payload.get("oracle_id") == evaluation.oracle_id
            and event.payload.get("phase") == evaluation.phase.value
        ]
        if len(matches) != 1 or (
            matches[0].payload.get("passed") != evaluation.passed
            or matches[0].payload.get("failure_code") != evaluation.failure_code
            or matches[0].payload.get("process") != evaluation.process.model_dump(mode="json")
        ):
            raise EvidenceIntegrityError("Receipt oracle observation is not event-bound")


def render_markdown(receipt: VerificationReceipt) -> str:
    """Render a receipt whose assurance label comes from validated execution facts."""

    status = receipt.status.upper()
    baseline = "Failure reproduced" if receipt.baseline.failure_reproduced else "Not reproduced"
    transition = (
        "Observed" if receipt.verification.reproduction_transition_passed else "Not observed"
    )
    regressions = "Passed" if receipt.verification.regressions_passed else "Failed"
    lines = [
        "# ProofPatch Receipt",
        "",
        f"**Status:** {status}  ",
        f"**Protection:** {receipt.protection_level.value.replace('_', ' ').upper()}  ",
        f"**Run:** `{receipt.run_id}`",
        "",
        "## Observed Claim",
        "",
        receipt.issue_summary,
        "",
        "## Baseline",
        "",
        f"**Result:** {baseline} at `{receipt.project.baseline_commit}`.",
        "",
        "## Verification",
        "",
        "| Check | Result |",
        "|---|---|",
        f"| Reproduction failure-to-success transition | {transition} |",
        f"| Required regressions | {regressions} |",
        "",
        "## Integrity",
        "",
        f"- Contract SHA-256: `{receipt.contract.sha256}`",
        f"- Evidence decision chain: `{receipt.evidence.decision_chain_hash}`",
    ]
    if receipt.patch is not None:
        lines.extend(
            [
                f"- Patch SHA-256: `{receipt.patch.sha256}`",
                f"- Changed files: {receipt.patch.changed_files}",
            ]
        )
    if receipt.rejection_code is not None:
        lines.extend(["", f"**Rejection code:** `{receipt.rejection_code}`"])
    if receipt.attempts:
        lines.extend(
            [
                "",
                "## Attempt Timeline",
                "",
                "| Attempt | Status | Patch fingerprint | Warnings | Result |",
                "|---:|---|---|---|---|",
            ]
        )
        for attempt in receipt.attempts:
            warnings = ", ".join(attempt.warning_codes) or "None"
            result = attempt.rejection_code or "Verified"
            lines.append(
                f"| {attempt.attempt} | {attempt.status.upper()} | "
                f"`{attempt.fingerprint_sha256}` | {warnings} | {result} |"
            )
    lines.extend(
        [
            "",
            "This receipt records only the commands and expectations that ProofPatch observed.",
            "",
        ]
    )
    return "\n".join(lines)


def _write_private_file(path: Path, content: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags, PRIVATE_FILE_MODE)
        file_status = os.fstat(descriptor)
        if not stat.S_ISREG(file_status.st_mode) or file_status.st_nlink != 1:
            raise EvidenceIntegrityError("Receipt path is not a private regular file")
        view = memoryview(content)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short receipt write")
            view = view[written:]
        os.fsync(descriptor)
        os.chmod(path, PRIVATE_FILE_MODE)
    except EvidenceIntegrityError:
        raise
    except OSError as error:
        raise EvidenceIntegrityError(f"Could not safely write receipt file: {path.name}") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _read_private_file(path: Path) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags)
        file_status = os.fstat(descriptor)
        path_status = path.lstat()
        if (
            not stat.S_ISREG(file_status.st_mode)
            or file_status.st_nlink != 1
            or (file_status.st_dev, file_status.st_ino) != (path_status.st_dev, path_status.st_ino)
        ):
            raise EvidenceIntegrityError("Receipt Markdown is not a private regular file")
        content = os.read(descriptor, 1024 * 1024 + 1)
        if len(content) > 1024 * 1024:
            raise EvidenceIntegrityError("Receipt Markdown exceeds the size limit")
        return content
    except EvidenceIntegrityError:
        raise
    except OSError as error:
        raise EvidenceIntegrityError("Could not safely read receipt Markdown") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
