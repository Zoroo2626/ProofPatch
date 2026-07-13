"""Deterministic patch fingerprints, overlap warnings, and append-only attempt storage."""

import hashlib
import os
import stat
import unicodedata
from pathlib import Path

from pydantic import ValidationError

from proofpatch.errors import EvidenceIntegrityError
from proofpatch.models.attempt import (
    AttemptRecord,
    FingerprintPath,
    PatchFingerprint,
    SimilarityWarning,
)
from proofpatch.models.common import JsonValue
from proofpatch.models.patch import PatchRecord
from proofpatch.services.evidence import (
    canonical_json_bytes,
    read_canonical_json,
)

HIGH_OVERLAP_THRESHOLD = 0.80
MAXIMUM_PATCH_ANALYSIS_BYTES = 50 * 1024 * 1024
MAXIMUM_RETAINED_LINE_HASHES = 4000


class PatchAnalysisService:
    """Compute advisory signals without changing exact patch evidence."""

    def fingerprint(
        self,
        record: PatchRecord,
        patch_path: Path,
        failure_signature: JsonValue,
    ) -> PatchFingerprint:
        patch = _read_bounded_regular_file(patch_path, MAXIMUM_PATCH_ANALYSIS_BYTES)
        line_changes = _line_hashes_by_change(patch, len(record.changed_files))
        paths = tuple(
            sorted(
                (
                    FingerprintPath(
                        path=change.path,
                        old_path=change.old_path,
                        status=change.status,
                        added_line_hashes=tuple(sorted(line_changes[index][0])),
                        removed_line_hashes=tuple(sorted(line_changes[index][1])),
                    )
                    for index, change in enumerate(record.changed_files)
                ),
                key=lambda item: (item.path, item.old_path or "", item.status.value),
            )
        )
        signature_hash = hashlib.sha256(canonical_json_bytes(failure_signature)).hexdigest()
        document: dict[str, JsonValue] = {
            "schema_version": 1,
            "failure_signature_sha256": signature_hash,
            "paths": [path.model_dump(mode="json") for path in paths],
        }
        return PatchFingerprint(
            sha256=hashlib.sha256(canonical_json_bytes(document)).hexdigest(),
            failure_signature_sha256=signature_hash,
            paths=paths,
        )

    def warnings(
        self,
        current: PatchFingerprint,
        patch_sha256: str,
        hypothesis_sha256: str,
        previous: tuple[AttemptRecord, ...],
    ) -> tuple[SimilarityWarning, ...]:
        warnings: list[SimilarityWarning] = []
        for prior in previous:
            path_overlap = _jaccard(_path_tokens(current), _path_tokens(prior.fingerprint))
            line_overlap = _jaccard(_line_tokens(current), _line_tokens(prior.fingerprint))
            if patch_sha256 == prior.patch_sha256:
                warnings.append(
                    SimilarityWarning(
                        code="PP_PATCH_EXACT_REPEAT",
                        prior_attempt=prior.attempt,
                        path_overlap=path_overlap,
                        line_overlap=line_overlap,
                        message="This attempt has the same deterministic patch fingerprint.",
                    )
                )
            elif path_overlap >= HIGH_OVERLAP_THRESHOLD and line_overlap >= HIGH_OVERLAP_THRESHOLD:
                warnings.append(
                    SimilarityWarning(
                        code="PP_PATCH_HIGH_OVERLAP",
                        prior_attempt=prior.attempt,
                        path_overlap=path_overlap,
                        line_overlap=line_overlap,
                        message=(
                            "Changed paths and normalized lines highly overlap a prior attempt."
                        ),
                    )
                )
            if hypothesis_sha256 == prior.hypothesis_sha256:
                warnings.append(
                    SimilarityWarning(
                        code="PP_HYPOTHESIS_REPEAT",
                        prior_attempt=prior.attempt,
                        path_overlap=path_overlap,
                        line_overlap=line_overlap,
                        message=(
                            "The normalized agent root-cause hypothesis repeats a prior attempt."
                        ),
                    )
                )
        return tuple(warnings)

    @staticmethod
    def hypothesis_sha256(text: str) -> str:
        normalized = " ".join(unicodedata.normalize("NFKC", text).casefold().split())
        return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


class AttemptStore:
    """Persist each completed attempt once and refuse replacement or gaps."""

    def __init__(self, attempts_directory: Path) -> None:
        self.directory = attempts_directory

    def append(self, record: AttemptRecord) -> Path:
        self.directory.mkdir(mode=0o700, exist_ok=True)
        existing = self.load()
        if record.attempt != len(existing) + 1:
            raise EvidenceIntegrityError("Attempt records must be contiguous and append-only")
        path = self.directory / f"attempt_{record.attempt:03d}.json"
        _write_exclusive(path, canonical_json_bytes(record.model_dump(mode="json")) + b"\n")
        return path

    def load(self) -> tuple[AttemptRecord, ...]:
        if not self.directory.exists():
            return ()
        if self.directory.is_symlink() or self.directory.is_junction():
            raise EvidenceIntegrityError("Attempt directory cannot be a link")
        records: list[AttemptRecord] = []
        entries = sorted(self.directory.glob("attempt_*.json"))
        for expected, path in enumerate(entries, start=1):
            if path.name != f"attempt_{expected:03d}.json":
                raise EvidenceIntegrityError("Attempt record sequence contains a gap")
            try:
                record = AttemptRecord.model_validate(read_canonical_json(path))
            except (ValidationError, EvidenceIntegrityError) as error:
                raise EvidenceIntegrityError("Stored attempt record is invalid") from error
            if record.attempt != expected:
                raise EvidenceIntegrityError("Stored attempt identity does not match its path")
            records.append(record)
        return tuple(records)


def _line_hashes_by_change(
    patch: bytes,
    change_count: int,
) -> list[tuple[list[str], list[str]]]:
    result: list[tuple[list[str], list[str]]] = [([], []) for _ in range(change_count)]
    current = -1
    in_hunk = False
    section_count = 0
    retained_hashes = 0
    for line in patch.splitlines():
        if line.startswith(b"diff --git "):
            current += 1
            section_count += 1
            in_hunk = False
            continue
        if line.startswith(b"@@"):
            in_hunk = True
            continue
        if current < 0 or current >= change_count or not in_hunk:
            continue
        if line.startswith(b"+") and not line.startswith(b"+++ "):
            if retained_hashes < MAXIMUM_RETAINED_LINE_HASHES:
                result[current][0].append(_normalized_line_hash(line[1:]))
                retained_hashes += 1
        elif (
            line.startswith(b"-")
            and not line.startswith(b"--- ")
            and retained_hashes < MAXIMUM_RETAINED_LINE_HASHES
        ):
            result[current][1].append(_normalized_line_hash(line[1:]))
            retained_hashes += 1
    if section_count != change_count:
        raise EvidenceIntegrityError("Patch sections do not match captured changed-file metadata")
    return result


def _normalized_line_hash(line: bytes) -> str:
    normalized = b"".join(line.split())
    return hashlib.sha256(normalized).hexdigest()


def _path_tokens(fingerprint: PatchFingerprint) -> set[str]:
    return {f"{path.status.value}:{path.old_path or ''}:{path.path}" for path in fingerprint.paths}


def _line_tokens(fingerprint: PatchFingerprint) -> set[str]:
    return {
        f"{prefix}:{digest}"
        for path in fingerprint.paths
        for prefix, hashes in (
            ("+", path.added_line_hashes),
            ("-", path.removed_line_hashes),
        )
        for digest in hashes
    }


def _jaccard(first: set[str], second: set[str]) -> float:
    union = first | second
    return 1.0 if not union else len(first & second) / len(union)


def _read_bounded_regular_file(path: Path, maximum: int) -> bytes:
    try:
        status = path.lstat()
        if (
            not stat.S_ISREG(status.st_mode)
            or status.st_nlink != 1
            or path.is_symlink()
            or path.is_junction()
        ):
            raise EvidenceIntegrityError("Patch analysis input is not a private regular file")
        content = path.read_bytes()
    except OSError as error:
        raise EvidenceIntegrityError("Could not read patch analysis input") from error
    if len(content) == 0 or len(content) > maximum:
        raise EvidenceIntegrityError("Patch analysis input is empty or exceeds the limit")
    return content


def _write_exclusive(path: Path, content: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags, 0o600)
        status = os.fstat(descriptor)
        if not stat.S_ISREG(status.st_mode) or status.st_nlink != 1:
            raise EvidenceIntegrityError("Attempt record is not a private regular file")
        view = memoryview(content)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short attempt record write")
            view = view[written:]
        os.fsync(descriptor)
        os.chmod(path, 0o600)
    except FileExistsError as error:
        raise EvidenceIntegrityError(
            "Attempt record already exists and cannot be replaced"
        ) from error
    except OSError as error:
        raise EvidenceIntegrityError("Could not safely persist attempt record") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
