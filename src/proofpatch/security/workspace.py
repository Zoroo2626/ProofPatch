"""Race-aware hashing for verifier source immutability checks."""

import hashlib
import os
import stat
from pathlib import Path
from typing import Protocol

from proofpatch.errors import EvidenceIntegrityError


class _HashWriter(Protocol):
    def update(self, value: bytes, /) -> object: ...


def workspace_content_sha256(root: Path, *, maximum_bytes: int) -> str:
    """Hash a workspace without following links or trusting Git metadata."""

    if maximum_bytes <= 0:
        raise ValueError("workspace hash limit must be positive")
    try:
        root_status = root.lstat()
    except OSError as error:
        raise EvidenceIntegrityError("Verifier workspace is unavailable") from error
    if not stat.S_ISDIR(root_status.st_mode) or _is_reparse(root_status):
        raise EvidenceIntegrityError("Verifier workspace is not a private directory")

    digest = hashlib.sha256()
    total = 0
    for directory, names, files in os.walk(root, topdown=True, followlinks=False):
        parent = Path(directory)
        if parent == root and ".git" in names:
            names.remove(".git")
        names.sort()
        files.sort()
        for name in names:
            path = parent / name
            status = _lstat(path)
            if not stat.S_ISDIR(status.st_mode) or _is_reparse(status):
                raise EvidenceIntegrityError("Verifier workspace contains an unsafe directory")
            _update(digest, b"D", path.relative_to(root).as_posix().encode("utf-8"))
        for name in files:
            path = parent / name
            relative = path.relative_to(root).as_posix().encode("utf-8")
            status = _lstat(path)
            if stat.S_ISLNK(status.st_mode):
                try:
                    target = os.readlink(path).encode("utf-8")
                except (OSError, UnicodeEncodeError) as error:
                    raise EvidenceIntegrityError("Could not hash a workspace symlink") from error
                _update(digest, b"L", relative, target)
                continue
            if _is_reparse(status):
                raise EvidenceIntegrityError("Verifier workspace contains a reparse point")
            if not stat.S_ISREG(status.st_mode) or status.st_nlink != 1:
                raise EvidenceIntegrityError("Verifier workspace contains an unsafe file")
            content_size, content_sha256 = _hash_regular(path, status, maximum_bytes - total)
            total += content_size
            if total > maximum_bytes:
                raise EvidenceIntegrityError("Verifier workspace exceeds the configured size limit")
            executable = b"1" if status.st_mode & 0o111 else b"0"
            _update(digest, b"F", relative, executable, content_sha256)
    return digest.hexdigest()


def _hash_regular(path: Path, expected: os.stat_result, remaining: int) -> tuple[int, bytes]:
    if remaining < 0:
        raise EvidenceIntegrityError("Verifier workspace exceeds the configured size limit")
    descriptor: int | None = None
    try:
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or (opened.st_dev, opened.st_ino) != (expected.st_dev, expected.st_ino)
        ):
            raise EvidenceIntegrityError("Verifier workspace file identity changed")
        content_digest = hashlib.sha256()
        total = 0
        while True:
            chunk = os.read(descriptor, min(64 * 1024, remaining + 1 - total))
            if not chunk:
                break
            content_digest.update(chunk)
            total += len(chunk)
            if total > remaining:
                raise EvidenceIntegrityError("Verifier workspace exceeds the configured size limit")
        completed = os.fstat(descriptor)
        current = path.lstat()
        if (
            (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino)
            or completed.st_size != opened.st_size
            or completed.st_mtime_ns != opened.st_mtime_ns
            or completed.st_ctime_ns != opened.st_ctime_ns
        ):
            raise EvidenceIntegrityError("Verifier workspace file changed while hashing")
        return total, content_digest.digest()
    except EvidenceIntegrityError:
        raise
    except OSError as error:
        raise EvidenceIntegrityError("Could not safely hash verifier workspace") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _lstat(path: Path) -> os.stat_result:
    try:
        return path.lstat()
    except OSError as error:
        raise EvidenceIntegrityError("Could not inspect verifier workspace") from error


def _is_reparse(value: os.stat_result) -> bool:
    attributes = getattr(value, "st_file_attributes", 0)
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return bool(attributes & reparse)


def _update(digest: _HashWriter, *parts: bytes) -> None:
    for part in parts:
        digest.update(len(part).to_bytes(8, "big"))
        digest.update(part)
