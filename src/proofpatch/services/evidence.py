"""Canonical append-only evidence storage and complete chain verification."""

import hashlib
import hmac
import json
import math
import os
import secrets
import stat
import time
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from pydantic import ValidationError

from proofpatch.errors import EvidenceIntegrityError
from proofpatch.models.common import JsonValue, format_utc_timestamp, validate_run_id
from proofpatch.models.events import EvidenceEvent

PRIVATE_FILE_MODE: Final = 0o600
MAX_EVENT_BYTES: Final = 1024 * 1024
MAX_EVIDENCE_BYTES: Final = 64 * 1024 * 1024
MAX_JSON_NESTING: Final = 64
SNAPSHOT_ATTEMPTS: Final = 3
SNAPSHOT_RETRY_SECONDS: Final = 0.01


@dataclass(frozen=True, slots=True)
class VerifiedEvidence:
    """The fully validated contents and terminal hash of an evidence chain."""

    events: tuple[EvidenceEvent, ...]
    final_hash: str


def canonical_json_bytes(value: object) -> bytes:
    """Encode a JSON-compatible value using ProofPatch's canonical form."""

    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
        return encoded.encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError, RecursionError) as error:
        raise ValueError("value cannot be represented as canonical JSON") from error


def write_canonical_json(path: Path, value: object, *, exclusive: bool = True) -> None:
    """Durably write one private canonical JSON document."""

    _validate_private_directory(path.parent)
    try:
        _validate_json_nesting(value)
        data = canonical_json_bytes(value) + b"\n"
    except ValueError as error:
        raise EvidenceIntegrityError(
            "Canonical JSON document is invalid or too deeply nested"
        ) from error
    destination = (
        path
        if exclusive
        else path.with_name(f".{path.name}.{os.getpid()}.{secrets.token_hex(8)}.tmp")
    )
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(destination, flags, PRIVATE_FILE_MODE)
        _validate_open_regular_file(destination, descriptor)
        _write_all(descriptor, data)
        os.fsync(descriptor)
        os.chmod(destination, PRIVATE_FILE_MODE)
        if exclusive:
            _sync_parent_directory(path)
        else:
            os.close(descriptor)
            descriptor = None
            os.replace(destination, path)
            os.chmod(path, PRIVATE_FILE_MODE)
            _sync_parent_directory(path)
    except OSError as error:
        raise EvidenceIntegrityError(f"Could not safely write canonical file: {path}") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if destination != path:
            with suppress(OSError):
                destination.unlink(missing_ok=True)


def read_canonical_json(path: Path, *, maximum_bytes: int = MAX_EVENT_BYTES) -> object:
    """Read a private canonical JSON document, rejecting ambiguous encodings."""

    if maximum_bytes <= 0 or maximum_bytes > MAX_EVIDENCE_BYTES:
        raise ValueError("Canonical JSON size limit is outside the supported range")
    raw = _read_regular_file(path, maximum_bytes=maximum_bytes)
    if not raw.endswith(b"\n") or raw.count(b"\n") != 1:
        raise EvidenceIntegrityError(f"Canonical JSON file has invalid framing: {path}")
    value = _decode_json_without_duplicates(raw[:-1], path)
    if canonical_json_bytes(value) + b"\n" != raw:
        raise EvidenceIntegrityError(f"Canonical JSON file is not canonical: {path}")
    return value


def read_json_document(path: Path, *, maximum_bytes: int = MAX_EVENT_BYTES) -> object:
    """Safely read untrusted JSON without requiring canonical serialization."""

    if maximum_bytes <= 0 or maximum_bytes > MAX_EVIDENCE_BYTES:
        raise ValueError("JSON document size limit is outside the supported range")
    raw = _read_regular_file(path, maximum_bytes=maximum_bytes)
    return _decode_json_without_duplicates(raw, path)


class EvidenceWriter:
    """Append events only after verifying the entire existing chain."""

    def __init__(self, events_path: Path, chain_path: Path, run_id: str) -> None:
        self.events_path = events_path
        self.chain_path = chain_path
        self.run_id = validate_run_id(run_id)

    def append(
        self,
        event_type: str,
        *,
        payload: dict[str, JsonValue] | None = None,
        actor: str = "proofpatch",
        timestamp_utc: str | None = None,
    ) -> EvidenceEvent:
        """Append and durably checkpoint one canonical chained event."""

        self.events_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        _validate_private_directory(self.events_path.parent)
        self.events_path.parent.chmod(0o700)
        flags = os.O_RDWR | os.O_CREAT | os.O_APPEND
        flags |= getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor: int | None = None
        try:
            descriptor = os.open(self.events_path, flags, PRIVATE_FILE_MODE)
            _validate_open_regular_file(self.events_path, descriptor)
            raw = _read_descriptor(descriptor, maximum_bytes=MAX_EVIDENCE_BYTES)
            if raw:
                verified = _verify_content(
                    raw,
                    _read_regular_file(self.chain_path, maximum_bytes=65),
                    expected_run_id=self.run_id,
                    source=self.events_path,
                )
                sequence = len(verified.events) + 1
                previous_hash: str | None = verified.final_hash
            else:
                if self.chain_path.exists() or self.chain_path.is_symlink():
                    raise EvidenceIntegrityError("Chain checkpoint exists without evidence events")
                sequence = 1
                previous_hash = None

            event_without_hash: dict[str, object] = {
                "schema_version": 1,
                "sequence": sequence,
                "event_id": f"evt_{sequence:06d}",
                "run_id": self.run_id,
                "timestamp_utc": (
                    format_utc_timestamp() if timestamp_utc is None else timestamp_utc
                ),
                "type": event_type,
                "actor": actor,
                "payload": {} if payload is None else payload,
                "previous_hash": previous_hash,
            }
            _validate_json_nesting(event_without_hash)
            event_hash = hashlib.sha256(canonical_json_bytes(event_without_hash)).hexdigest()
            event = EvidenceEvent.model_validate({**event_without_hash, "event_hash": event_hash})
            line = canonical_json_bytes(event.model_dump(mode="json")) + b"\n"
            if len(line) > MAX_EVENT_BYTES:
                raise EvidenceIntegrityError("Evidence event exceeds the maximum encoded size")

            _write_all(descriptor, line)
            os.fsync(descriptor)
            os.chmod(self.events_path, PRIVATE_FILE_MODE)
            _replace_chain_checkpoint(self.chain_path, event_hash)
            return event
        except EvidenceIntegrityError:
            raise
        except (OSError, ValidationError, ValueError) as error:
            raise EvidenceIntegrityError("Could not append a valid evidence event") from error
        finally:
            if descriptor is not None:
                os.close(descriptor)


def verify_event_chain(
    events_path: Path,
    chain_path: Path,
    *,
    expected_run_id: str | None = None,
) -> VerifiedEvidence:
    """Verify framing, canonical JSON, schemas, hashes, links, and checkpoint."""

    if expected_run_id is not None:
        validate_run_id(expected_run_id)
    last_error: EvidenceIntegrityError | None = None
    for attempt in range(SNAPSHOT_ATTEMPTS):
        try:
            raw = _read_regular_file(events_path, maximum_bytes=MAX_EVIDENCE_BYTES)
            chain = _read_regular_file(chain_path, maximum_bytes=65)
            second_raw = _read_regular_file(events_path, maximum_bytes=MAX_EVIDENCE_BYTES)
            if not hmac.compare_digest(raw, second_raw):
                raise EvidenceIntegrityError("Evidence changed while it was being inspected")
            return _verify_content(
                raw,
                chain,
                expected_run_id=expected_run_id,
                source=events_path,
            )
        except EvidenceIntegrityError as error:
            last_error = error
            if attempt + 1 < SNAPSHOT_ATTEMPTS:
                time.sleep(SNAPSHOT_RETRY_SECONDS)
    if last_error is None:
        raise EvidenceIntegrityError("Evidence inspection did not produce a result")
    raise last_error


def _verify_content(
    raw: bytes,
    chain_checkpoint: bytes,
    *,
    expected_run_id: str | None,
    source: Path,
) -> VerifiedEvidence:
    if not raw:
        raise EvidenceIntegrityError("Evidence chain contains no events")
    if not raw.endswith(b"\n"):
        raise EvidenceIntegrityError("Evidence chain ends with a partial event")

    events: list[EvidenceEvent] = []
    previous_hash: str | None = None
    chain_run_id = expected_run_id
    for sequence, line_with_newline in enumerate(raw.splitlines(keepends=True), start=1):
        if not line_with_newline.endswith(b"\n"):
            raise EvidenceIntegrityError(f"Evidence event {sequence} has invalid framing")
        line = line_with_newline[:-1]
        if not line or len(line_with_newline) > MAX_EVENT_BYTES:
            raise EvidenceIntegrityError(f"Evidence event {sequence} has an invalid size")
        value = _decode_json_without_duplicates(line, source)
        if not isinstance(value, dict):
            raise EvidenceIntegrityError(f"Evidence event {sequence} is not a JSON object")
        if canonical_json_bytes(value) != line:
            raise EvidenceIntegrityError(f"Evidence event {sequence} is not canonical JSON")

        try:
            event = EvidenceEvent.model_validate(value)
        except ValidationError as error:
            raise EvidenceIntegrityError(
                f"Evidence event {sequence} has an invalid schema"
            ) from error
        if event.sequence != sequence:
            raise EvidenceIntegrityError(f"Evidence event {sequence} has the wrong sequence")
        if chain_run_id is None:
            chain_run_id = event.run_id
        if event.run_id != chain_run_id:
            raise EvidenceIntegrityError(f"Evidence event {sequence} belongs to another run")
        if event.previous_hash != previous_hash:
            raise EvidenceIntegrityError(f"Evidence event {sequence} has a broken previous hash")

        hash_input = dict(value)
        del hash_input["event_hash"]
        calculated_hash = hashlib.sha256(canonical_json_bytes(hash_input)).hexdigest()
        if not hmac.compare_digest(event.event_hash, calculated_hash):
            raise EvidenceIntegrityError(f"Evidence event {sequence} has an invalid hash")
        previous_hash = event.event_hash
        events.append(event)

    if previous_hash is None:
        raise EvidenceIntegrityError("Evidence chain has no terminal hash")
    expected_checkpoint = f"{previous_hash}\n".encode()
    if not hmac.compare_digest(chain_checkpoint, expected_checkpoint):
        raise EvidenceIntegrityError("Evidence chain checkpoint does not match its final event")
    return VerifiedEvidence(events=tuple(events), final_hash=previous_hash)


def _decode_json_without_duplicates(raw: bytes, source: Path) -> object:
    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    def reject_nonstandard_constant(value: str) -> object:
        raise ValueError(f"non-standard JSON constant: {value}")

    def parse_finite_float(value: str) -> float:
        parsed = float(value)
        if not math.isfinite(parsed):
            raise ValueError("JSON floating-point value is outside the finite range")
        return parsed

    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=reject_duplicates,
            parse_constant=reject_nonstandard_constant,
            parse_float=parse_finite_float,
        )
        _validate_json_nesting(value)
        return value
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as error:
        raise EvidenceIntegrityError(f"Invalid JSON in evidence file: {source}") from error


def _validate_json_nesting(value: object) -> None:
    stack: list[tuple[object, int]] = [(value, 0)]
    while stack:
        current, depth = stack.pop()
        if depth > MAX_JSON_NESTING:
            raise ValueError("JSON nesting exceeds the supported maximum")
        if isinstance(current, dict):
            for key in current:
                if not isinstance(key, str):
                    raise ValueError("JSON object keys must be strings")
                _validate_unicode_scalar_string(key)
            stack.extend((item, depth + 1) for item in current.values())
        elif isinstance(current, list):
            stack.extend((item, depth + 1) for item in current)
        elif isinstance(current, str):
            _validate_unicode_scalar_string(current)


def _validate_unicode_scalar_string(value: str) -> None:
    if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
        raise ValueError("JSON strings must not contain unpaired surrogate code points")


def _read_regular_file(path: Path, *, maximum_bytes: int) -> bytes:
    _validate_private_directory(path.parent)
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags)
        _validate_open_regular_file(path, descriptor)
        return _read_descriptor(descriptor, maximum_bytes=maximum_bytes)
    except EvidenceIntegrityError:
        raise
    except OSError as error:
        raise EvidenceIntegrityError(f"Could not safely read evidence file: {path}") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _read_descriptor(descriptor: int, *, maximum_bytes: int) -> bytes:
    os.lseek(descriptor, 0, os.SEEK_SET)
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = os.read(descriptor, min(64 * 1024, maximum_bytes + 1 - total))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        if total > maximum_bytes:
            raise EvidenceIntegrityError("Evidence file exceeds the maximum supported size")
    return b"".join(chunks)


def _write_all(descriptor: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError("short write while persisting evidence")
        view = view[written:]


def _validate_open_regular_file(path: Path, descriptor: int) -> None:
    file_status = os.fstat(descriptor)
    try:
        path_status = path.lstat()
    except OSError as error:
        raise EvidenceIntegrityError(f"Evidence path changed while opening: {path}") from error
    attributes = getattr(path_status, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    if (
        not stat.S_ISREG(file_status.st_mode)
        or bool(attributes & reparse_flag)
        or file_status.st_nlink != 1
        or (path_status.st_dev, path_status.st_ino) != (file_status.st_dev, file_status.st_ino)
    ):
        raise EvidenceIntegrityError(f"Evidence path is not a private regular file: {path}")


def _replace_chain_checkpoint(path: Path, event_hash: str) -> None:
    _validate_private_directory(path.parent)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{secrets.token_hex(8)}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(temporary, flags, PRIVATE_FILE_MODE)
        _write_all(descriptor, f"{event_hash}\n".encode())
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        os.replace(temporary, path)
        os.chmod(path, PRIVATE_FILE_MODE)
        _sync_parent_directory(path)
    except OSError as error:
        raise EvidenceIntegrityError("Could not durably update the chain checkpoint") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
        with suppress(OSError):
            temporary.unlink(missing_ok=True)


def _sync_parent_directory(path: Path) -> None:
    if os.name == "nt":
        return
    descriptor = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _validate_private_directory(path: Path) -> None:
    try:
        file_status = path.lstat()
    except OSError as error:
        raise EvidenceIntegrityError(f"Could not inspect evidence directory: {path}") from error
    attributes = getattr(file_status, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    if (
        not stat.S_ISDIR(file_status.st_mode)
        or stat.S_ISLNK(file_status.st_mode)
        or bool(attributes & reparse_flag)
    ):
        raise EvidenceIntegrityError(f"Evidence directory is a link or reparse point: {path}")
