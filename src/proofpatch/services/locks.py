"""Cross-platform, per-repository operating-system locks."""

import os
import secrets
import socket
import stat
import sys
from contextlib import AbstractContextManager
from pathlib import Path
from types import TracebackType
from typing import BinaryIO, ClassVar, Final, Self

from proofpatch.errors import RepositoryError
from proofpatch.models.common import format_utc_timestamp, validate_repository_id, validate_run_id
from proofpatch.models.run import RepositoryLockRecord
from proofpatch.services.evidence import canonical_json_bytes

PRIVATE_FILE_MODE: Final = 0o600
PROCESS_START_IDENTITY: Final = f"{os.getpid()}-{secrets.token_hex(16)}"


class RepositoryLock(AbstractContextManager["RepositoryLock"]):
    """A nonblocking OS lock whose file record is diagnostic, not authoritative."""

    _held_paths: ClassVar[set[Path]] = set()

    def __init__(self, locks_directory: Path, repository_id: str, run_id: str) -> None:
        self.repository_id = validate_repository_id(repository_id)
        self.run_id = validate_run_id(run_id)
        self.locks_directory = locks_directory
        self.path = locks_directory / f"{self.repository_id}.lock"
        self._file: BinaryIO | None = None
        self._held = False
        self._file_identity: tuple[int, int] | None = None

    def acquire(self) -> Self:
        """Acquire the lock or fail without trusting a possibly stale record."""

        self.locks_directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            directory_status = self.locks_directory.lstat()
        except OSError as error:
            raise RepositoryError("Could not inspect repository lock directory") from error
        if not stat.S_ISDIR(directory_status.st_mode) or _is_reparse_point(directory_status):
            raise RepositoryError("Repository lock directory must not be a link or junction")
        self.locks_directory.chmod(0o700)
        resolved_path = self.path.absolute()
        if resolved_path in self._held_paths:
            raise _busy_error(self.repository_id)
        if _is_link_or_junction(self.path):
            raise RepositoryError("Repository lock path must not be a link or junction")

        descriptor: int | None = None
        lock_file: BinaryIO | None = None
        try:
            flags = os.O_RDWR | os.O_CREAT
            flags |= getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(self.path, flags, PRIVATE_FILE_MODE)
            lock_file = os.fdopen(descriptor, "r+b")
            descriptor = None
            os.chmod(self.path, PRIVATE_FILE_MODE)
            file_status = os.fstat(lock_file.fileno())
            path_status = self.path.lstat()
            if (
                not stat.S_ISREG(file_status.st_mode)
                or _is_reparse_point(path_status)
                or file_status.st_nlink != 1
                or (path_status.st_dev, path_status.st_ino)
                != (file_status.st_dev, file_status.st_ino)
            ):
                raise RepositoryError("Repository lock path is not a regular file")
            if file_status.st_size == 0:
                lock_file.write(b"\0")
                lock_file.flush()
                os.fsync(lock_file.fileno())
            lock_file.seek(0)
            _acquire_os_lock(lock_file)
        except BlockingIOError as error:
            if descriptor is not None:
                os.close(descriptor)
            if lock_file is not None:
                lock_file.close()
            raise _busy_error(self.repository_id) from error
        except RepositoryError:
            if descriptor is not None:
                os.close(descriptor)
            if lock_file is not None:
                lock_file.close()
            raise
        except OSError as error:
            if descriptor is not None:
                os.close(descriptor)
            if lock_file is not None:
                lock_file.close()
            raise RepositoryError("Could not safely acquire the repository lock") from error
        except BaseException:
            if descriptor is not None:
                os.close(descriptor)
            if lock_file is not None:
                lock_file.close()
            raise

        self._file = lock_file
        self._held = True
        self._file_identity = (file_status.st_dev, file_status.st_ino)
        self._held_paths.add(resolved_path)
        try:
            record = RepositoryLockRecord(
                run_id=self.run_id,
                pid=os.getpid(),
                hostname=socket.gethostname(),
                created_at_utc=format_utc_timestamp(),
                process_start_identity=PROCESS_START_IDENTITY,
            )
            encoded = canonical_json_bytes(record.model_dump(mode="json")) + b"\n"
            lock_file.seek(0)
            lock_file.truncate()
            lock_file.write(encoded)
            lock_file.flush()
            os.fsync(lock_file.fileno())
            self.assert_held()
        except BaseException:
            self.release()
            raise
        return self

    def assert_held(self) -> None:
        """Fail if the live lock path was removed or substituted after acquisition."""

        if not self._held or self._file is None or self._file_identity is None:
            raise RepositoryError("Repository lock is not held by this process")
        try:
            file_status = os.fstat(self._file.fileno())
            path_status = self.path.lstat()
        except OSError as error:
            raise RepositoryError("Live repository lock path was removed") from error
        identity = (file_status.st_dev, file_status.st_ino)
        if (
            identity != self._file_identity
            or (path_status.st_dev, path_status.st_ino) != identity
            or file_status.st_nlink != 1
            or _is_reparse_point(path_status)
        ):
            raise RepositoryError("Live repository lock path was substituted")

    def release(self) -> None:
        """Release the OS lock while retaining its last-owner diagnostic record."""

        if not self._held or self._file is None:
            return
        lock_file = self._file
        try:
            lock_file.seek(0)
            _release_os_lock(lock_file)
        finally:
            lock_file.close()
            self._held_paths.discard(self.path.absolute())
            self._file = None
            self._held = False
            self._file_identity = None

    def __enter__(self) -> Self:
        return self.acquire()

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        del exc_type, exc_value, traceback
        self.release()


def _busy_error(repository_id: str) -> RepositoryError:
    return RepositoryError(
        f"Another mutating ProofPatch run holds the lock for {repository_id}",
        remediation="Wait for that run to finish; read-only status and inspect remain available.",
    )


def _is_link_or_junction(path: Path) -> bool:
    try:
        return path.is_symlink() or path.is_junction()
    except OSError:
        return True


def _is_reparse_point(file_status: os.stat_result) -> bool:
    attributes = getattr(file_status, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return bool(attributes & reparse_flag)


if sys.platform == "win32":
    import msvcrt

    def _acquire_os_lock(lock_file: BinaryIO) -> None:
        lock_file.seek(0)
        try:
            msvcrt.locking(lock_file.fileno(), msvcrt.LK_NBLCK, 1)
        except OSError as error:
            raise BlockingIOError from error

    def _release_os_lock(lock_file: BinaryIO) -> None:
        lock_file.seek(0)
        msvcrt.locking(lock_file.fileno(), msvcrt.LK_UNLCK, 1)

else:
    import fcntl

    def _acquire_os_lock(lock_file: BinaryIO) -> None:
        try:
            fcntl.flock(
                lock_file.fileno(),
                fcntl.LOCK_EX | fcntl.LOCK_NB,
            )
        except OSError as error:
            raise BlockingIOError from error

    def _release_os_lock(lock_file: BinaryIO) -> None:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
