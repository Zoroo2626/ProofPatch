"""Fail-closed deletion of validated ProofPatch-owned disposable trees."""

import os
import secrets
import shutil
import stat
from collections.abc import Callable
from pathlib import Path

from proofpatch.errors import CleanupError
from proofpatch.security.paths import (
    CleanupTargetKind,
    ValidatedCleanupTarget,
    revalidate_cleanup_target,
    validate_cleanup_target,
    validate_proofpatch_data_path,
)


def remove_owned_tree(data_root: Path, target: Path) -> None:
    """Atomically quarantine and remove a run descendant without following links."""

    validated = validate_cleanup_target(data_root, target)
    if validated.kind is not CleanupTargetKind.RUN_DESCENDANT:
        raise CleanupError("Only a ProofPatch run descendant may be removed by this operation")
    if not validated.path.is_dir():
        raise CleanupError("Cleanup target must be a directory")
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
    except CleanupError:
        raise
    except OSError as error:
        raise CleanupError("Could not inspect the cleanup tree safely") from error


def _remove_readonly(function: Callable[..., object], path: str, error: BaseException) -> None:
    del error
    os.chmod(path, stat.S_IWRITE)
    function(path)


__all__ = [
    "CleanupTargetKind",
    "ValidatedCleanupTarget",
    "remove_owned_tree",
    "revalidate_cleanup_target",
    "validate_cleanup_target",
]
