"""Creation and validation of run-owned, non-hardlinked Git clones."""

import hashlib
import os
import stat
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from proofpatch.errors import RepositoryError
from proofpatch.git.client import GitClient
from proofpatch.models.patch import RepositorySnapshot
from proofpatch.security.paths import validate_proofpatch_data_path


class CloneKind(StrEnum):
    """Distinct disposable workspaces required by the architecture."""

    INVESTIGATION = "investigation"
    BASELINE_VERIFICATION = "baseline-verification"
    PATCH = "patch"
    FINAL_VERIFICATION = "final-verification"


@dataclass(frozen=True, slots=True)
class IndependentClone:
    """A validated clone rooted inside one ProofPatch run."""

    kind: CloneKind
    root: Path
    git_directory: Path
    baseline_commit: str
    configuration_sha256: str


def create_independent_clone(
    git: GitClient,
    repository: RepositorySnapshot,
    run_root: Path,
    kind: CloneKind,
    *,
    workspace_name: str | None = None,
) -> IndependentClone:
    """Clone with ``--no-local`` and prove baseline, cleanliness, and object independence."""

    validated_run = validate_proofpatch_data_path(run_root.parent.parent.parent, run_root)
    destination_parent = validated_run / "workspaces"
    destination_parent.mkdir(mode=0o700, exist_ok=True)
    validate_proofpatch_data_path(run_root.parent.parent.parent, destination_parent)
    selected_name = kind.value if workspace_name is None else workspace_name
    if (
        not selected_name
        or len(selected_name) > 128
        or not selected_name.replace("-", "").replace("_", "").isalnum()
    ):
        raise RepositoryError("Independent clone workspace name is invalid")
    destination = destination_parent / selected_name
    if destination.exists() or destination.is_symlink():
        raise RepositoryError(f"Independent clone destination already exists: {selected_name}")

    source = Path(repository.repository_root)
    git.run(
        [
            "clone",
            "--no-local",
            "--no-checkout",
            "--",
            str(source),
            str(destination),
        ],
        cwd=destination_parent,
        operation=f"{kind.value} clone creation",
    )
    validated_destination = validate_proofpatch_data_path(
        run_root.parent.parent.parent,
        destination,
    )
    git.run(
        [
            "-C",
            str(validated_destination),
            "checkout",
            "--detach",
            "--force",
            repository.baseline_commit,
            "--",
        ],
        cwd=validated_destination,
        operation=f"{kind.value} baseline checkout",
    )
    git.run(
        ["-C", str(validated_destination), "remote", "remove", "origin"],
        cwd=validated_destination,
        operation=f"{kind.value} source detachment",
    )
    git_directory = Path(
        git.text(
            [
                "-C",
                str(validated_destination),
                "rev-parse",
                "--path-format=absolute",
                "--git-dir",
            ],
            cwd=validated_destination,
            operation=f"{kind.value} Git-directory validation",
        )
    ).resolve(strict=True)
    try:
        git_directory.relative_to(validated_destination)
    except ValueError as error:
        raise RepositoryError("Independent clone Git directory escapes its workspace") from error
    _reject_alternates(git_directory)
    _reject_hardlinked_objects(Path(repository.git_common_directory), git_directory)
    configuration_sha256 = _configuration_hash(git_directory)

    head = git.text(
        ["-C", str(validated_destination), "rev-parse", "--verify", "HEAD^{commit}"],
        cwd=validated_destination,
        operation=f"{kind.value} baseline validation",
    )
    status = git.run(
        ["-C", str(validated_destination), "status", "--porcelain=v1", "-z"],
        cwd=validated_destination,
        operation=f"{kind.value} cleanliness validation",
    ).stdout
    if head != repository.baseline_commit or status:
        raise RepositoryError("Independent clone does not exactly match the clean baseline")
    return IndependentClone(
        kind,
        validated_destination,
        git_directory,
        head,
        configuration_sha256,
    )


def validate_owned_clone(clone: IndependentClone, run_root: Path) -> None:
    """Revalidate clone containment and Git-directory ownership before mutation."""

    data_root = run_root.parent.parent.parent
    root = validate_proofpatch_data_path(data_root, clone.root)
    git_directory = validate_proofpatch_data_path(data_root, clone.git_directory)
    try:
        root.relative_to(run_root / "workspaces")
        git_directory.relative_to(root)
    except ValueError as error:
        raise RepositoryError("Clone is not owned by the current ProofPatch run") from error
    current_hash = _configuration_hash(git_directory)
    if current_hash != clone.configuration_sha256:
        raise RepositoryError("Clone Git configuration changed after ProofPatch created it")


def _reject_alternates(git_directory: Path) -> None:
    alternates = git_directory / "objects" / "info" / "alternates"
    if alternates.exists() or alternates.is_symlink():
        raise RepositoryError("Independent clone uses an alternate Git object store")


def _reject_hardlinked_objects(source_common: Path, clone_git: Path) -> None:
    source_objects = source_common / "objects"
    clone_objects = clone_git / "objects"
    if not source_objects.is_dir() or not clone_objects.is_dir():
        raise RepositoryError("Git object storage is missing")
    for directory, _names, files in os.walk(clone_objects, followlinks=False):
        current = Path(directory)
        relative_directory = current.relative_to(clone_objects)
        for name in files:
            clone_object = current / name
            source_object = source_objects / relative_directory / name
            if source_object.is_file():
                try:
                    same = os.path.samefile(source_object, clone_object)
                except OSError as error:
                    raise RepositoryError("Could not verify clone object independence") from error
                if same:
                    raise RepositoryError("Independent clone contains hardlinked Git objects")


def _configuration_hash(git_directory: Path) -> str:
    config = git_directory / "config"
    try:
        path_status = config.lstat()
        if (
            not stat.S_ISREG(path_status.st_mode)
            or path_status.st_nlink != 1
            or config.is_symlink()
            or config.is_junction()
        ):
            raise RepositoryError("Clone Git configuration is not a private regular file")
        return hashlib.sha256(config.read_bytes()).hexdigest()
    except OSError as error:
        raise RepositoryError("Could not validate clone Git configuration") from error
