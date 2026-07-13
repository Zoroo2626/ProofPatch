"""Safe, receipt-only GitHub Actions publishing helpers."""

import os
import re
import secrets
import stat
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from proofpatch.errors import ConfigurationError, EvidenceIntegrityError
from proofpatch.models.receipt import VerificationReceipt
from proofpatch.services.coordinator import RunCoordinator
from proofpatch.services.evidence import canonical_json_bytes
from proofpatch.services.receipt import ReceiptService, render_markdown

MAX_GITHUB_TEXT_BYTES: Final = 60 * 1024
ARTIFACT_FILENAMES: Final = frozenset({"receipt.json", "receipt.md"})
_MARKDOWN_SPECIAL: Final = re.compile(r"([\\`*_{}\[\]()#+.!|>~-])")


@dataclass(frozen=True, slots=True)
class GitHubReceiptExport:
    """Exact allowlisted receipt paths and sanitized GitHub presentation text."""

    run_id: str
    receipt_json: Path
    receipt_markdown: Path
    summary: str
    comment: str
    verified: bool


class GitHubReceiptExporter:
    """Verify evidence, then stage only canonical receipt files for upload."""

    def __init__(self, coordinator: RunCoordinator) -> None:
        self.coordinator = coordinator
        self.receipts = ReceiptService(coordinator)

    def export(self, run_id: str, output_directory: Path) -> GitHubReceiptExport:
        """Create a new, receipt-only directory after full evidence verification."""

        if not output_directory.is_absolute():
            raise ConfigurationError("GitHub artifact output directory must be absolute")
        if output_directory.exists() or output_directory.is_symlink():
            raise ConfigurationError("GitHub artifact output directory must not already exist")

        receipt = self.receipts.verify(run_id)
        try:
            output_directory.mkdir(mode=0o700, parents=True, exist_ok=False)
            _validate_directory(output_directory)
            json_path = output_directory / "receipt.json"
            markdown_path = output_directory / "receipt.md"
            _write_new_file(
                json_path,
                canonical_json_bytes(receipt.model_dump(mode="json")) + b"\n",
            )
            _write_new_file(markdown_path, render_markdown(receipt).encode("utf-8"))
        except (OSError, EvidenceIntegrityError):
            _remove_incomplete_export(output_directory)
            raise

        exported_names = {path.name for path in output_directory.iterdir()}
        if exported_names != ARTIFACT_FILENAMES:
            _remove_incomplete_export(output_directory)
            raise EvidenceIntegrityError("GitHub export contains a non-receipt file")
        return GitHubReceiptExport(
            run_id=run_id,
            receipt_json=json_path,
            receipt_markdown=markdown_path,
            summary=render_github_summary(receipt),
            comment=render_github_comment(receipt),
            verified=receipt.status == "verified",
        )


def render_github_summary(receipt: VerificationReceipt) -> str:
    """Render bounded Markdown without active content from the untrusted issue text."""

    before = "Failure reproduced" if receipt.baseline.failure_reproduced else "Not reproduced"
    after = (
        "Failure no longer reproduced"
        if receipt.verification.reproduction_transition_passed
        else "Required transition not observed"
    )
    regressions = "Passed" if receipt.verification.regressions_passed else "Failed"
    issue = escape_github_markdown(receipt.issue_summary)
    text = "\n".join(
        (
            "# ProofPatch verification",
            "",
            f"**Result:** {receipt.status.upper()}  ",
            f"**Protection:** {receipt.protection_level.value.replace('_', ' ').upper()}  ",
            f"**Run:** `{receipt.run_id}`",
            "",
            "| Observation | Result |",
            "|---|---|",
            f"| Before | {before} |",
            f"| After | {after} |",
            f"| Regressions | {regressions} |",
            "",
            "**Issue:**",
            "",
            issue,
            "",
            "The downloadable artifact contains only `receipt.json` and `receipt.md`; "
            "repository source and patch content are not uploaded.",
            "",
        )
    )
    return _bounded_github_text(text)


def render_github_comment(receipt: VerificationReceipt) -> str:
    """Build a sanitized opt-in PR comment; it cannot mention users or embed links."""

    before = "failure reproduced" if receipt.baseline.failure_reproduced else "not reproduced"
    after = (
        "failure no longer reproduced"
        if receipt.verification.reproduction_transition_passed
        else "required transition not observed"
    )
    issue = escape_github_markdown(receipt.issue_summary)
    text = "\n".join(
        (
            "<!-- proofpatch-receipt -->",
            "## ProofPatch verification",
            "",
            f"**{receipt.status.upper()}** — before: {before}; after: {after}.",
            f"Run `{receipt.run_id}` · protection: "
            f"{receipt.protection_level.value.replace('_', ' ')}.",
            "",
            issue,
            "",
            "See the workflow receipt artifact for integrity hashes and full observed results.",
        )
    )
    return _bounded_github_text(text)


def escape_github_markdown(value: str) -> str:
    """Make untrusted issue text inert in summaries and comments."""

    normalized = "".join(
        character if character in "\n\t" or ord(character) >= 0x20 else "�" for character in value
    )
    escaped = _MARKDOWN_SPECIAL.sub(r"\\\1", normalized)
    return escaped.replace("<", "&lt;").replace(">", "&gt;").replace("@", "&#64;")


def append_github_environment_file(path: Path, content: str) -> None:
    """Append bounded UTF-8 content to a runner-owned environment file."""

    if not path.is_absolute() or "\0" in str(path):
        raise ConfigurationError("GitHub environment-file path must be absolute and NUL-free")
    encoded = _bounded_github_text(content).encode("utf-8")
    flags = os.O_WRONLY | os.O_APPEND | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags)
        file_status = os.fstat(descriptor)
        if not stat.S_ISREG(file_status.st_mode) or file_status.st_nlink != 1:
            raise EvidenceIntegrityError("GitHub environment file is not a regular file")
        view = memoryview(encoded)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short GitHub environment-file write")
            view = view[written:]
        os.fsync(descriptor)
    except OSError as error:
        raise ConfigurationError("Could not write the GitHub environment file") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def append_github_outputs(path: Path, export: GitHubReceiptExport) -> None:
    """Emit fixed action outputs using the environment-file multiline protocol."""

    delimiter = f"proofpatch_{secrets.token_hex(16)}"
    while delimiter in export.comment:
        delimiter = f"proofpatch_{secrets.token_hex(16)}"
    values = (
        f"run-id={export.run_id}\n"
        f"receipt-json={export.receipt_json}\n"
        f"receipt-markdown={export.receipt_markdown}\n"
        f"verified={'true' if export.verified else 'false'}\n"
        f"comment-body<<{delimiter}\n{export.comment}\n{delimiter}\n"
    )
    append_github_environment_file(path, values)


def _bounded_github_text(value: str) -> str:
    if "\0" in value or len(value.encode("utf-8")) > MAX_GITHUB_TEXT_BYTES:
        raise ConfigurationError("GitHub presentation text is invalid or exceeds 60 KiB")
    return value


def _validate_directory(path: Path) -> None:
    file_status = path.lstat()
    attributes = getattr(file_status, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    if (
        not stat.S_ISDIR(file_status.st_mode)
        or stat.S_ISLNK(file_status.st_mode)
        or bool(attributes & reparse_flag)
    ):
        raise EvidenceIntegrityError("GitHub artifact directory is not a real directory")


def _write_new_file(path: Path, content: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags, 0o600)
        file_status = os.fstat(descriptor)
        if not stat.S_ISREG(file_status.st_mode) or file_status.st_nlink != 1:
            raise EvidenceIntegrityError("GitHub artifact path is not a regular file")
        view = memoryview(content)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short GitHub artifact write")
            view = view[written:]
        os.fsync(descriptor)
    except OSError as error:
        raise EvidenceIntegrityError("Could not safely create a GitHub receipt artifact") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _remove_incomplete_export(path: Path) -> None:
    if not path.is_dir() or path.is_symlink():
        return
    for name in ARTIFACT_FILENAMES:
        candidate = path / name
        if candidate.is_file() and not candidate.is_symlink():
            candidate.unlink()
    with suppress(OSError):
        path.rmdir()
