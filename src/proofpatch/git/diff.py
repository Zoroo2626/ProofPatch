"""Exact binary patch capture and NUL-safe changed-path parsing."""

import hashlib
import hmac
import os
import re
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path, PurePosixPath
from typing import BinaryIO, Final

from proofpatch.errors import (
    PatchEmptyError,
    PatchError,
    PatchPathDeniedError,
    PatchTooLargeError,
    PatchTooManyFilesError,
    RepositoryError,
)
from proofpatch.git.client import GitClient, GitCommandError
from proofpatch.git.clone import IndependentClone, validate_owned_clone
from proofpatch.models.patch import ChangedFile, ChangeKind

DEFAULT_MAX_PATCH_BYTES: Final = 50 * 1024 * 1024
DEFAULT_MAX_CHANGED_FILES: Final = 1000
PRIVATE_FILE_MODE: Final = 0o600


def capture_binary_patch(
    git: GitClient,
    clone: IndependentClone,
    run_root: Path,
    output: Path,
    *,
    allowed_paths: tuple[str, ...] = ("**",),
    denied_paths: tuple[str, ...] = (),
    allow_symlinks: bool = False,
    max_patch_bytes: int = DEFAULT_MAX_PATCH_BYTES,
    max_changed_files: int = DEFAULT_MAX_CHANGED_FILES,
) -> tuple[str, int, tuple[ChangedFile, ...]]:
    """Stage the effective tree and capture its exact binary full-index diff."""

    validate_owned_clone(clone, run_root)
    if clone.kind.value != "patch":
        raise PatchError("Effective changes may only be captured from the patch clone")
    _require_baseline_ancestor(git, clone)
    git.run(
        [
            "-C",
            str(clone.root),
            "fsck",
            "--connectivity-only",
            "--no-dangling",
            clone.baseline_commit,
        ],
        cwd=clone.root,
        operation="patch repository integrity validation",
    )
    git.run(
        ["-C", str(clone.root), "reset", "--mixed", clone.baseline_commit, "--"],
        cwd=clone.root,
        operation="effective-tree reset",
    )
    git.run(
        ["-C", str(clone.root), "add", "-A", "--"],
        cwd=clone.root,
        operation="effective-tree staging",
    )
    changed_raw = git.run(
        [
            "-C",
            str(clone.root),
            "diff",
            "--cached",
            "--name-status",
            "-z",
            "--find-renames",
            clone.baseline_commit,
            "--",
        ],
        cwd=clone.root,
        operation="changed-file detection",
    ).stdout
    changed = parse_name_status_z(changed_raw)
    if not changed:
        raise PatchEmptyError("Candidate patch is empty")
    if len(changed) > max_changed_files:
        raise PatchTooManyFilesError("Candidate patch exceeds the maximum changed-file count")
    validate_changed_paths(
        changed,
        allowed_paths=allowed_paths,
        denied_paths=denied_paths,
    )
    _validate_staged_object_types(git, clone, changed, allow_symlinks=allow_symlinks)

    output.parent.mkdir(mode=0o700, parents=False, exist_ok=True)
    if output.exists() or output.is_symlink():
        raise PatchError("Patch artifact already exists")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(output, flags, PRIVATE_FILE_MODE)
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            descriptor = None
            git.run_to_file(
                [
                    "-C",
                    str(clone.root),
                    "diff",
                    "--cached",
                    "--binary",
                    "--full-index",
                    "--no-ext-diff",
                    "--no-textconv",
                    clone.baseline_commit,
                    "--",
                ],
                stream,
                cwd=clone.root,
                operation="binary patch capture",
                maximum_output_bytes=max_patch_bytes,
            )
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(output, PRIVATE_FILE_MODE)
    except (OSError, RepositoryError) as error:
        output.unlink(missing_ok=True)
        if isinstance(error, PatchError):
            raise
        raise PatchError("Could not capture the binary patch safely") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)

    size = output.stat().st_size
    if size <= 0:
        output.unlink(missing_ok=True)
        raise PatchEmptyError("Candidate patch is empty")
    if size > max_patch_bytes:
        output.unlink(missing_ok=True)
        raise PatchTooLargeError("Candidate patch exceeds the maximum patch size")
    return sha256_file(output, maximum_bytes=max_patch_bytes), size, changed


def parse_name_status_z(raw: bytes) -> tuple[ChangedFile, ...]:
    """Parse Git's NUL-delimited name-status format without line splitting."""

    if not raw:
        return ()
    if not raw.endswith(b"\0"):
        raise PatchError("Git changed-path output has invalid NUL framing")
    tokens = raw[:-1].split(b"\0")
    changes: list[ChangedFile] = []
    index = 0
    while index < len(tokens):
        status_text = _decode_git_token(tokens[index], "status")
        index += 1
        if not status_text:
            raise PatchError("Git returned an empty change status")
        code = status_text[0]
        try:
            kind = ChangeKind(code)
        except ValueError as error:
            raise PatchError(f"Unsupported Git change status: {status_text}") from error
        similarity: int | None = None
        if kind in (ChangeKind.RENAMED, ChangeKind.COPIED):
            if index + 1 >= len(tokens):
                raise PatchError("Git rename/copy output is incomplete")
            old_path = _decode_git_token(tokens[index], "path")
            path = _decode_git_token(tokens[index + 1], "path")
            index += 2
            suffix = status_text[1:]
            if not suffix.isdigit():
                raise PatchError("Git rename/copy similarity is invalid")
            similarity = int(suffix)
        else:
            if status_text != code or index >= len(tokens):
                raise PatchError(f"Unsupported Git change status: {status_text}")
            old_path = None
            path = _decode_git_token(tokens[index], "path")
            index += 1
        changes.append(
            ChangedFile(status=kind, path=path, old_path=old_path, similarity=similarity)
        )
    return tuple(changes)


def validate_changed_paths(
    changes: tuple[ChangedFile, ...],
    *,
    allowed_paths: tuple[str, ...] = ("**",),
    denied_paths: tuple[str, ...] = (),
) -> None:
    """Reject paths that are ambiguous, escaping, Git metadata, or policy-denied."""

    allowed = _compile_policy_patterns(allowed_paths, label="allowed")
    denied = _compile_policy_patterns(denied_paths, label="denied")
    if not allowed:
        raise PatchPathDeniedError("Patch policy has no allowed paths")
    for change in changes:
        for candidate in (change.old_path, change.path):
            if candidate is None:
                continue
            normalized = _normalized_git_path(candidate)
            if normalized == ".git" or normalized.startswith(".git/"):
                raise PatchPathDeniedError("Patch attempts to modify Git metadata")
            if normalized == ".proofpatch" or normalized.startswith(".proofpatch/"):
                raise PatchPathDeniedError("Patch attempts to modify ProofPatch-owned files")
            if not any(pattern.fullmatch(normalized) for pattern in allowed):
                raise PatchPathDeniedError(
                    f"Patch modifies path outside the allowlist: {candidate}"
                )
            if any(pattern.fullmatch(normalized) for pattern in denied):
                raise PatchPathDeniedError(f"Patch modifies denied path: {candidate}")


def validate_patch_policy_patterns(
    allowed_paths: tuple[str, ...],
    denied_paths: tuple[str, ...],
) -> None:
    """Validate path policies before any repository or container operation."""

    if not _compile_policy_patterns(allowed_paths, label="allowed"):
        raise PatchPathDeniedError("Patch policy has no allowed paths")
    _compile_policy_patterns(denied_paths, label="denied")


def sha256_file(path: Path, *, maximum_bytes: int = DEFAULT_MAX_PATCH_BYTES) -> str:
    """Hash exact file bytes while enforcing a hard read limit."""

    digest = hashlib.sha256()
    total = 0
    with open_patch_file(path) as stream:
        while chunk := stream.read(64 * 1024):
            total += len(chunk)
            if total > maximum_bytes:
                raise PatchTooLargeError("Patch exceeds the maximum patch size")
            digest.update(chunk)
    if total == 0:
        raise PatchEmptyError("Patch artifact is empty")
    return digest.hexdigest()


@contextmanager
def open_patch_file(path: Path) -> Iterator[BinaryIO]:
    """Open one private regular patch file without following a substituted link."""

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    stream: BinaryIO | None = None
    try:
        descriptor = os.open(path, flags)
        file_status = os.fstat(descriptor)
        path_status = path.lstat()
        attributes = getattr(path_status, "st_file_attributes", 0)
        reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
        if (
            not stat.S_ISREG(file_status.st_mode)
            or file_status.st_nlink != 1
            or bool(attributes & reparse)
            or (file_status.st_dev, file_status.st_ino) != (path_status.st_dev, path_status.st_ino)
        ):
            raise PatchError("Patch artifact is not a private regular file")
        stream = os.fdopen(descriptor, "rb", closefd=True)
        descriptor = None
        yield stream
    except PatchError:
        raise
    except OSError as error:
        raise PatchError("Could not safely open the patch artifact") from error
    finally:
        if stream is not None:
            stream.close()
        if descriptor is not None:
            os.close(descriptor)


def verify_patch_hash(
    path: Path,
    expected: str,
    *,
    maximum_bytes: int = DEFAULT_MAX_PATCH_BYTES,
) -> None:
    """Compare the exact patch bytes with a persisted SHA-256 value."""

    actual = sha256_file(path, maximum_bytes=maximum_bytes)
    if not hmac.compare_digest(actual, expected):
        raise PatchError("Patch bytes do not match the recorded SHA-256 hash")


def _require_baseline_ancestor(git: GitClient, clone: IndependentClone) -> None:
    result = git.run(
        ["-C", str(clone.root), "merge-base", "--is-ancestor", clone.baseline_commit, "HEAD"],
        cwd=clone.root,
        check=False,
        operation="baseline ancestry validation",
    )
    if result.returncode == 1:
        raise PatchError("Patch clone HEAD no longer descends from the baseline")
    if result.returncode != 0:
        raise GitCommandError("baseline ancestry validation", result)


def _validate_staged_object_types(
    git: GitClient,
    clone: IndependentClone,
    changes: tuple[ChangedFile, ...],
    *,
    allow_symlinks: bool,
) -> None:
    paths = [change.path for change in changes if change.status is not ChangeKind.DELETED]
    if not paths:
        return
    raw = git.run(
        ["-C", str(clone.root), "ls-files", "--stage", "-z", "--", *paths],
        cwd=clone.root,
        operation="staged object-type validation",
    ).stdout
    for record in raw.split(b"\0"):
        if not record:
            continue
        mode = record.split(b" ", 1)[0]
        if mode == b"160000":
            raise PatchPathDeniedError("Patch introduces a submodule or nested repository")
        if mode == b"120000" and not allow_symlinks:
            raise PatchPathDeniedError("Patch introduces a symbolic link, which policy disallows")
        if mode not in {b"100644", b"100755", b"120000"}:
            raise PatchPathDeniedError(f"Patch introduces unsupported Git object mode: {mode!r}")


def _decode_git_token(value: bytes, label: str) -> str:
    try:
        return value.decode("utf-8")
    except UnicodeDecodeError as error:
        raise PatchError(f"Git {label} is not valid UTF-8") from error


def _normalized_git_path(path: str) -> str:
    if "\0" in path or "\\" in path or path.startswith("/"):
        raise PatchError(f"Unsafe changed path: {path!r}")
    pure = PurePosixPath(path)
    if not path or pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
        raise PatchError(f"Unsafe changed path: {path!r}")
    normalized = pure.as_posix()
    if normalized != path:
        raise PatchError(f"Noncanonical changed path: {path!r}")
    return normalized


def _normalized_policy_path(path: str) -> str:
    if not path or path.endswith("/") or "\0" in path or "\\" in path or path.startswith("/"):
        raise PatchPathDeniedError(f"Unsafe patch policy pattern: {path!r}")
    parts = path.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise PatchPathDeniedError(f"Unsafe patch policy pattern: {path!r}")
    if any("[" in part or "]" in part for part in parts):
        raise PatchPathDeniedError("Patch policy character classes are not supported")
    if "***" in path:
        raise PatchPathDeniedError("Patch policy contains an ambiguous wildcard")
    return path


def _compile_policy_patterns(
    patterns: tuple[str, ...], *, label: str
) -> tuple[re.Pattern[str], ...]:
    compiled: list[re.Pattern[str]] = []
    for value in patterns:
        if not isinstance(value, str):
            raise PatchPathDeniedError(f"Patch {label} policy contains a non-string pattern")
        pattern = _normalized_policy_path(value)
        expression: list[str] = ["^"]
        index = 0
        while index < len(pattern):
            if pattern.startswith("**/", index):
                expression.append("(?:.*/)?")
                index += 3
            elif pattern.startswith("**", index):
                expression.append(".*")
                index += 2
            elif pattern[index] == "*":
                expression.append("[^/]*")
                index += 1
            elif pattern[index] == "?":
                expression.append("[^/]")
                index += 1
            else:
                expression.append(re.escape(pattern[index]))
                index += 1
        if "*" not in pattern and "?" not in pattern:
            expression.append("(?:/.*)?")
        expression.append("$")
        compiled.append(re.compile("".join(expression)))
    return tuple(compiled)
