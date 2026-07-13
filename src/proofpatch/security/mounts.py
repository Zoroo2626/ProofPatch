"""Fail-closed bind-mount validation for the Docker protected backend."""

import os
import stat
from collections.abc import Iterable
from pathlib import Path, PurePosixPath

from proofpatch.errors import ConfigurationError
from proofpatch.models.execution import (
    DockerMount,
    ExecutionPhase,
    MountAccess,
    MountKind,
)

DOCKER_SOCKET_PATHS = {
    "/var/run/docker.sock",
    "/run/docker.sock",
    "//./pipe/docker_engine",
}

_DESTINATION_ROOTS = {
    MountKind.WORKSPACE: PurePosixPath("/workspace"),
    MountKind.REPRODUCTION: PurePosixPath("/proofpatch/repro"),
    MountKind.OUTPUT: PurePosixPath("/proofpatch/out"),
    MountKind.DEPENDENCY_CACHE: PurePosixPath("/proofpatch/cache"),
    MountKind.SECRET: PurePosixPath("/run/secrets"),
    MountKind.PROMPT: PurePosixPath("/proofpatch/prompt.md"),
    MountKind.ISSUE: PurePosixPath("/proofpatch/issue.md"),
}

_PHASE_ACCESS: dict[ExecutionPhase, dict[MountKind, frozenset[MountAccess]]] = {
    ExecutionPhase.SETUP: {
        MountKind.WORKSPACE: frozenset({MountAccess.READ_WRITE}),
        MountKind.OUTPUT: frozenset({MountAccess.READ_WRITE}),
        MountKind.DEPENDENCY_CACHE: frozenset({MountAccess.READ_ONLY, MountAccess.READ_WRITE}),
        MountKind.SECRET: frozenset({MountAccess.READ_ONLY}),
    },
    ExecutionPhase.INVESTIGATION: {
        MountKind.WORKSPACE: frozenset({MountAccess.READ_ONLY}),
        MountKind.REPRODUCTION: frozenset({MountAccess.READ_WRITE}),
        MountKind.OUTPUT: frozenset({MountAccess.READ_WRITE}),
        MountKind.DEPENDENCY_CACHE: frozenset({MountAccess.READ_ONLY, MountAccess.READ_WRITE}),
        MountKind.SECRET: frozenset({MountAccess.READ_ONLY}),
        MountKind.PROMPT: frozenset({MountAccess.READ_ONLY}),
        MountKind.ISSUE: frozenset({MountAccess.READ_ONLY}),
    },
    ExecutionPhase.PATCH: {
        MountKind.WORKSPACE: frozenset({MountAccess.READ_WRITE}),
        MountKind.REPRODUCTION: frozenset({MountAccess.READ_ONLY}),
        MountKind.OUTPUT: frozenset({MountAccess.READ_WRITE}),
        MountKind.DEPENDENCY_CACHE: frozenset({MountAccess.READ_ONLY, MountAccess.READ_WRITE}),
        MountKind.SECRET: frozenset({MountAccess.READ_ONLY}),
        MountKind.PROMPT: frozenset({MountAccess.READ_ONLY}),
        MountKind.ISSUE: frozenset({MountAccess.READ_ONLY}),
    },
    ExecutionPhase.BASELINE: {
        MountKind.WORKSPACE: frozenset({MountAccess.READ_ONLY}),
        MountKind.REPRODUCTION: frozenset({MountAccess.READ_ONLY}),
        MountKind.OUTPUT: frozenset({MountAccess.READ_WRITE}),
        MountKind.DEPENDENCY_CACHE: frozenset({MountAccess.READ_ONLY, MountAccess.READ_WRITE}),
    },
    ExecutionPhase.VERIFICATION: {
        MountKind.WORKSPACE: frozenset({MountAccess.READ_ONLY}),
        MountKind.REPRODUCTION: frozenset({MountAccess.READ_ONLY}),
        MountKind.OUTPUT: frozenset({MountAccess.READ_WRITE}),
        MountKind.DEPENDENCY_CACHE: frozenset({MountAccess.READ_ONLY, MountAccess.READ_WRITE}),
    },
}


def validate_mounts(
    mounts: Iterable[DockerMount],
    *,
    phase: ExecutionPhase,
    original_repository: Path,
    evidence_directory: Path,
    disposable_work_directory: Path | None = None,
    working_directory: str,
) -> tuple[DockerMount, ...]:
    """Validate every host path and its exact phase-specific exposure."""

    selected = tuple(mounts)
    if not selected:
        raise ConfigurationError("Protected execution requires an explicit workspace mount")

    original = _resolve_existing(original_repository, "original repository")
    evidence = _resolve_existing(evidence_directory, "evidence directory")
    work = (
        None
        if disposable_work_directory is None
        else _validated_disposable_work_directory(disposable_work_directory, evidence)
    )
    destinations: list[PurePosixPath] = []
    sources: list[Path] = []
    workspace_count = 0

    for mount in selected:
        source = _resolve_mount_source(mount.source)
        destination = PurePosixPath(mount.destination)
        _reject_docker_socket(source, destination)
        _reject_sensitive_host_source(source)
        _reject_intersection(source, original, "original repository")
        _reject_evidence_exposure(source, evidence, work)
        _validate_destination(mount, destination)
        _validate_phase_access(mount, phase)

        if mount.kind is MountKind.WORKSPACE:
            workspace_count += 1
        if any(_paths_overlap(destination, existing) for existing in destinations):
            raise ConfigurationError("Container mount destinations overlap or are duplicated")
        if source in sources:
            raise ConfigurationError("A host mount source may be exposed only once")
        destinations.append(destination)
        sources.append(source)

    if workspace_count != 1:
        raise ConfigurationError("Protected execution requires exactly one workspace mount")
    cwd = PurePosixPath(working_directory)
    workspace = _DESTINATION_ROOTS[MountKind.WORKSPACE]
    if cwd != workspace and workspace not in cwd.parents:
        raise ConfigurationError("Container working directory must remain inside /workspace")
    return selected


def _validate_destination(mount: DockerMount, destination: PurePosixPath) -> None:
    root = _DESTINATION_ROOTS[mount.kind]
    if mount.kind in {
        MountKind.WORKSPACE,
        MountKind.REPRODUCTION,
        MountKind.OUTPUT,
        MountKind.PROMPT,
        MountKind.ISSUE,
    }:
        if destination != root:
            raise ConfigurationError(f"{mount.kind.value} must mount exactly at {root}")
    elif destination == root or root not in destination.parents:
        raise ConfigurationError(f"{mount.kind.value} destination must be below {root}")


def _validate_phase_access(mount: DockerMount, phase: ExecutionPhase) -> None:
    allowed = _PHASE_ACCESS[phase].get(mount.kind)
    if allowed is None:
        raise ConfigurationError(f"{mount.kind.value} mounts are forbidden during {phase.value}")
    if mount.access not in allowed:
        raise ConfigurationError(
            f"{mount.kind.value} cannot be {mount.access.value} during {phase.value}"
        )


def _resolve_mount_source(source: Path) -> Path:
    resolved = _resolve_existing(source, "mount source")
    _reject_link_components(source.absolute())
    if not resolved.is_file() and not resolved.is_dir():
        raise ConfigurationError("Mount source must be a regular file or directory")
    if resolved.is_file() and resolved.stat().st_nlink != 1:
        raise ConfigurationError("Mount source files must have exactly one hard link")
    return resolved


def _resolve_existing(path: Path, label: str) -> Path:
    try:
        return path.resolve(strict=True)
    except OSError as error:
        raise ConfigurationError(
            f"{label.capitalize()} does not exist or cannot be resolved"
        ) from error


def _reject_link_components(path: Path) -> None:
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        try:
            status = current.lstat()
        except OSError as error:
            raise ConfigurationError("Could not inspect mount source path components") from error
        attributes = getattr(status, "st_file_attributes", 0)
        reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
        if stat.S_ISLNK(status.st_mode) or bool(attributes & reparse):
            raise ConfigurationError("Mount source contains a symlink, junction, or reparse point")


def _reject_docker_socket(source: Path, destination: PurePosixPath) -> None:
    source_text = str(source).replace("\\", "/").lower()
    destination_text = str(destination).lower()
    if source_text in DOCKER_SOCKET_PATHS or destination_text in DOCKER_SOCKET_PATHS:
        raise ConfigurationError("Docker socket mounts are forbidden")
    if source_text.endswith("/docker.sock") or destination_text.endswith("/docker.sock"):
        raise ConfigurationError("Docker socket mounts are forbidden")
    if "docker_engine" in source_text or "docker_engine" in destination_text:
        raise ConfigurationError("Docker engine named-pipe mounts are forbidden")


def _reject_sensitive_host_source(source: Path) -> None:
    homes = {
        Path(value).resolve(strict=False)
        for name in ("HOME", "USERPROFILE")
        if (value := os.environ.get(name))
    }
    sensitive_names = (
        ".ssh",
        ".aws",
        ".azure",
        ".kube",
        ".docker",
        ".gitconfig",
        ".git-credentials",
        ".config/gcloud",
    )
    for home in homes:
        if source == home or source in home.parents:
            raise ConfigurationError("User home mounts are forbidden")
        for name in sensitive_names:
            sensitive = home.joinpath(*name.split("/"))
            if _paths_overlap(source, sensitive):
                raise ConfigurationError("Credential and user configuration mounts are forbidden")


def _reject_intersection(source: Path, protected: Path, label: str) -> None:
    if _paths_overlap(source, protected):
        raise ConfigurationError(f"Mount source exposes the protected {label}")


def _validated_disposable_work_directory(path: Path, evidence: Path) -> Path:
    work = _resolve_existing(path, "disposable work directory")
    try:
        relative = work.relative_to(evidence)
    except ValueError as error:
        raise ConfigurationError(
            "Disposable work directory must be inside the run directory"
        ) from error
    if not relative.parts:
        raise ConfigurationError("Disposable work directory cannot be the run directory")
    return work


def _reject_evidence_exposure(source: Path, evidence: Path, work: Path | None) -> None:
    if source == evidence or source in evidence.parents:
        raise ConfigurationError("Mount source exposes the protected evidence directory")
    if evidence not in source.parents:
        return
    if work is None or source == work or work not in source.parents:
        raise ConfigurationError("Only a phase-specific disposable work path may be mounted")


def _paths_overlap(first: Path | PurePosixPath, second: Path | PurePosixPath) -> bool:
    return first == second or first in second.parents or second in first.parents
