"""Fail-closed ownership checks for destructive cleanup targets."""

import os
import stat
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from pydantic import ValidationError

from proofpatch.errors import CleanupError, EvidenceIntegrityError, InternalInvariantError
from proofpatch.models.common import validate_repository_id, validate_run_id
from proofpatch.models.run import RunManifest
from proofpatch.services.evidence import read_canonical_json


class CleanupTargetKind(StrEnum):
    """ProofPatch-owned categories that may be cleaned independently."""

    RUN = "run"
    RUN_DESCENDANT = "run_descendant"
    CACHE_DESCENDANT = "cache_descendant"


@dataclass(frozen=True, slots=True)
class ValidatedCleanupTarget:
    """A resolved path and identity whose ownership was proven at validation time."""

    path: Path
    kind: CleanupTargetKind
    device: int
    inode: int


def validate_cleanup_target(data_root: Path, target: Path) -> ValidatedCleanupTarget:
    """Validate containment, link safety, and a persistent ownership marker."""

    try:
        root_absolute = data_root.absolute()
        target_absolute = target.absolute()
        if not root_absolute.exists() or not root_absolute.is_dir():
            raise CleanupError("ProofPatch data root does not exist or is not a directory")
        if not target_absolute.exists():
            raise CleanupError("Cleanup target does not exist")
        if target_absolute == root_absolute:
            raise CleanupError("Refusing to clean the ProofPatch data root")
        lexical_relative = target_absolute.relative_to(root_absolute)
    except ValueError as error:
        raise CleanupError("Cleanup target is outside the ProofPatch data root") from error

    _reject_link_components(root_absolute, lexical_relative)
    try:
        root_resolved = root_absolute.resolve(strict=True)
        target_resolved = target_absolute.resolve(strict=True)
        relative = target_resolved.relative_to(root_resolved)
    except (OSError, ValueError) as error:
        raise CleanupError(
            "Cleanup target does not resolve inside the ProofPatch data root"
        ) from error

    if relative.parts[0] == "cache":
        if len(relative.parts) == 1:
            raise CleanupError("Refusing to clean the entire ProofPatch cache root")
        return _validated_cleanup_target(
            target_resolved,
            CleanupTargetKind.CACHE_DESCENDANT,
        )

    if relative.parts[0] != "runs" or len(relative.parts) < 3:
        raise CleanupError("Cleanup target lacks a ProofPatch run ownership marker")
    repository_id, run_id = relative.parts[1:3]
    try:
        validate_repository_id(repository_id)
        validate_run_id(run_id)
    except ValueError as error:
        raise CleanupError("Cleanup target has invalid ProofPatch identifiers") from error

    run_root = root_resolved / "runs" / repository_id / run_id
    manifest_path = run_root / "run.json"
    try:
        manifest = RunManifest.model_validate(read_canonical_json(manifest_path))
    except (EvidenceIntegrityError, ValidationError) as error:
        raise CleanupError("Cleanup target has no valid canonical run ownership marker") from error
    if manifest.repository_id != repository_id or manifest.run_id != run_id:
        raise CleanupError("Cleanup target ownership marker does not match its path")

    kind = CleanupTargetKind.RUN if len(relative.parts) == 3 else CleanupTargetKind.RUN_DESCENDANT
    return _validated_cleanup_target(target_resolved, kind)


def revalidate_cleanup_target(
    data_root: Path,
    target: ValidatedCleanupTarget,
) -> ValidatedCleanupTarget:
    """Reject a cleanup target replaced after its original ownership check."""

    current = validate_cleanup_target(data_root, target.path)
    if (
        current.path != target.path
        or current.kind is not target.kind
        or current.device != target.device
        or current.inode != target.inode
    ):
        raise CleanupError("Cleanup target changed after validation")
    return current


def validate_proofpatch_data_path(
    data_root: Path,
    target: Path,
    *,
    allow_missing: bool = False,
) -> Path:
    """Prove a data path is contained and has no linked/reparse components."""

    root_absolute = data_root.absolute()
    target_absolute = target.absolute()
    try:
        relative = target_absolute.relative_to(root_absolute)
    except ValueError as error:
        raise InternalInvariantError("ProofPatch data path escapes its data root") from error

    current = root_absolute
    missing_component = False
    for part in (".", *relative.parts):
        if part != ".":
            current /= part
        try:
            file_status = current.lstat()
        except FileNotFoundError:
            if allow_missing:
                missing_component = True
                continue
            raise InternalInvariantError(
                f"ProofPatch data path does not exist: {current}"
            ) from None
        except OSError as error:
            raise InternalInvariantError(
                f"Could not inspect ProofPatch data path: {current}"
            ) from error
        if missing_component:
            raise InternalInvariantError("ProofPatch data path changed during validation")
        if _is_link_or_reparse(file_status):
            raise InternalInvariantError(
                f"ProofPatch data path contains a link or reparse point: {current}"
            )

    try:
        root_resolved = root_absolute.resolve(strict=True)
        if missing_component:
            return root_resolved.joinpath(relative)
        target_resolved = target_absolute.resolve(strict=True)
        target_resolved.relative_to(root_resolved)
    except (OSError, ValueError) as error:
        raise InternalInvariantError(
            "ProofPatch data path resolves outside its data root"
        ) from error
    return target_resolved


def _reject_link_components(root: Path, relative: Path) -> None:
    current = root
    for part in (".", *relative.parts):
        if part != ".":
            current /= part
        try:
            file_status = current.lstat()
        except OSError as error:
            raise CleanupError(f"Could not inspect cleanup path component: {current}") from error
        if _is_link_or_reparse(file_status):
            raise CleanupError(f"Cleanup path contains a link or junction: {current}")


def _validated_cleanup_target(path: Path, kind: CleanupTargetKind) -> ValidatedCleanupTarget:
    try:
        file_status = path.lstat()
    except OSError as error:
        raise CleanupError(f"Could not capture cleanup target identity: {path}") from error
    if _is_link_or_reparse(file_status):
        raise CleanupError(f"Cleanup target is a link or reparse point: {path}")
    return ValidatedCleanupTarget(
        path=path,
        kind=kind,
        device=file_status.st_dev,
        inode=file_status.st_ino,
    )


def _is_link_or_reparse(file_status: os.stat_result) -> bool:
    attributes = getattr(file_status, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return stat.S_ISLNK(file_status.st_mode) or bool(attributes & reparse_flag)
