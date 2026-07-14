"""Fail-closed deletion of validated ProofPatch-owned disposable trees."""

import os
import secrets
import shutil
import stat
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from proofpatch.errors import CleanupError
from proofpatch.models.common import JsonValue
from proofpatch.models.run import RunStatus
from proofpatch.models.state import RunState
from proofpatch.security.paths import (
    CleanupTargetKind,
    ValidatedCleanupTarget,
    revalidate_cleanup_target,
    validate_cleanup_target,
    validate_proofpatch_data_path,
)
from proofpatch.services.coordinator import RunCoordinator
from proofpatch.services.locks import RepositoryLock
from proofpatch.services.receipt import ReceiptService

COMPLETED_STATES = frozenset(
    {
        RunState.VERIFIED,
        RunState.REJECTED,
        RunState.ABORTED,
        RunState.ERROR,
        RunState.APPLIED,
    }
)


@dataclass(frozen=True, slots=True)
class RunCleanupPlan:
    """An evidence-verified cleanup decision with captured target identities."""

    run_id: str
    state: RunState
    updated_at_utc: str
    targets: tuple[ValidatedCleanupTarget, ...]


def remove_owned_tree(
    data_root: Path,
    target: Path,
    *,
    expected: ValidatedCleanupTarget | None = None,
) -> None:
    """Atomically quarantine and remove a run descendant without following links."""

    if expected is not None and expected.path != target:
        raise CleanupError("Cleanup target does not match its validated identity")
    validated = (
        validate_cleanup_target(data_root, target)
        if expected is None
        else revalidate_cleanup_target(data_root, expected)
    )
    if validated.kind is not CleanupTargetKind.RUN_DESCENDANT:
        raise CleanupError("Only a ProofPatch run descendant may be removed by this operation")
    if not validated.path.is_dir():
        raise CleanupError("Cleanup target must be a directory")
    _reject_linked_descendants(validated.path)
    revalidate_cleanup_target(data_root, validated)
    cache = validate_proofpatch_data_path(data_root, data_root / "cache")
    quarantine = cache / f"q-{secrets.token_hex(8)}"
    try:
        os.rename(validated.path, quarantine)
        moved = quarantine.lstat()
        if (moved.st_dev, moved.st_ino) != (validated.device, validated.inode):
            raise CleanupError("Cleanup target identity changed during quarantine")
        _reject_linked_descendants(quarantine)
        shutil.rmtree(quarantine, onexc=_remove_readonly)
    except CleanupError:
        raise
    except OSError as error:
        raise CleanupError("Could not safely remove the ProofPatch-owned tree") from error


def _reject_linked_descendants(root: Path) -> None:
    try:
        for directory, names, files in os.walk(root, topdown=True, followlinks=False):
            parent = Path(directory)
            for name in (*names, *files):
                path = parent / name
                status = path.lstat()
                attributes = getattr(status, "st_file_attributes", 0)
                reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
                if stat.S_ISLNK(status.st_mode) or bool(attributes & reparse):
                    raise CleanupError("Cleanup tree contains a link or reparse point")
                if stat.S_ISREG(status.st_mode) and status.st_nlink != 1:
                    raise CleanupError("Cleanup tree contains a hardlinked file")
    except CleanupError:
        raise
    except OSError as error:
        raise CleanupError("Could not inspect the cleanup tree safely") from error


def _remove_readonly(function: Callable[..., object], path: str, error: BaseException) -> None:
    del error
    os.chmod(path, stat.S_IWRITE)
    function(path)


class RunCleanupService:
    """Preview or clean terminal runs while holding their repository lock."""

    def __init__(self, coordinator: RunCoordinator) -> None:
        self.coordinator = coordinator

    def preview(self, run_id: str) -> RunCleanupPlan:
        """Return a stable cleanup plan without deleting or appending evidence."""

        status = self.coordinator.status(run_id)
        with self._lock(status):
            return self._plan(self.coordinator.status(run_id))

    def clean(self, run_id: str) -> RunCleanupPlan:
        """Clean disposable workspace data and transition the terminal run to CLEANED."""

        initial = self.coordinator.status(run_id)
        with self._lock(initial) as repository_lock:
            plan = self._plan(self.coordinator.status(run_id))
            relative_targets: list[JsonValue] = [target.path.name for target in plan.targets]
            self.coordinator.append_event_while_locked(
                run_id,
                "cleanup.started",
                repository_lock,
                payload={"targets": relative_targets},
            )
            try:
                for target in plan.targets:
                    repository_lock.assert_held()
                    remove_owned_tree(
                        self.coordinator.directories.data,
                        target.path,
                        expected=target,
                    )
            except CleanupError:
                self.coordinator.append_event_while_locked(
                    run_id,
                    "cleanup.failed",
                    repository_lock,
                    payload={"targets": relative_targets, "error_code": "PP_CLEANUP_FAILED"},
                )
                raise
            self.coordinator.append_event_while_locked(
                run_id,
                "cleanup.completed",
                repository_lock,
                payload={"targets": relative_targets},
            )
            self.coordinator.transition_while_locked(
                run_id,
                RunState.CLEANED,
                repository_lock,
                details={"targets": relative_targets},
            )
            return plan

    def completed_before(
        self,
        older_than: timedelta,
        *,
        now: datetime | None = None,
    ) -> tuple[RunStatus, ...]:
        """Select terminal non-cleaned runs whose last evidence predates the cutoff."""

        if older_than <= timedelta(0):
            raise CleanupError("Cleanup age must be positive")
        current = datetime.now(UTC) if now is None else now
        if current.tzinfo is None or current.utcoffset() is None:
            raise CleanupError("Cleanup comparison time must be timezone-aware")
        cutoff = current.astimezone(UTC) - older_than
        selected = []
        for status in self.coordinator.list_runs():
            updated = datetime.strptime(
                status.updated_at_utc,
                "%Y-%m-%dT%H:%M:%S.%fZ",
            ).replace(tzinfo=UTC)
            if status.state in COMPLETED_STATES and updated <= cutoff:
                selected.append(status)
        return tuple(selected)

    def _plan(self, status: RunStatus) -> RunCleanupPlan:
        if status.state not in COMPLETED_STATES:
            if status.state is RunState.CLEANED:
                raise CleanupError(f"Run is already cleaned: {status.manifest.run_id}")
            raise CleanupError(
                f"Active run cannot be cleaned from state {status.state.value}",
                remediation="Abort or finish the run before cleaning disposable workspaces.",
            )
        paths = self.coordinator.paths_for(status.manifest.run_id)
        if status.state in {RunState.VERIFIED, RunState.APPLIED} or (
            paths.receipt_json.exists() or paths.receipt_markdown.exists()
        ):
            ReceiptService(self.coordinator).verify(status.manifest.run_id)
        targets: list[ValidatedCleanupTarget] = []
        try:
            paths.workspaces.lstat()
        except FileNotFoundError:
            pass
        except OSError as error:
            raise CleanupError("Could not inspect run workspace cleanup target") from error
        else:
            validated = validate_cleanup_target(
                self.coordinator.directories.data,
                paths.workspaces,
            )
            if validated.kind is not CleanupTargetKind.RUN_DESCENDANT:
                raise CleanupError("Run workspace cleanup target has an invalid ownership kind")
            targets.append(validated)
        return RunCleanupPlan(
            run_id=status.manifest.run_id,
            state=status.state,
            updated_at_utc=status.updated_at_utc,
            targets=tuple(targets),
        )

    def _lock(self, status: RunStatus) -> RepositoryLock:
        return RepositoryLock(
            self.coordinator.directories.locks,
            status.manifest.repository_id,
            status.manifest.run_id,
        )


__all__ = [
    "CleanupTargetKind",
    "RunCleanupPlan",
    "RunCleanupService",
    "ValidatedCleanupTarget",
    "remove_owned_tree",
    "revalidate_cleanup_target",
    "validate_cleanup_target",
]
