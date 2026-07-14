"""Construction and verification of immutable protected verifier inputs."""

import hashlib
from collections.abc import Mapping
from pathlib import PurePosixPath
from typing import Final

from proofpatch.errors import ConfigurationError, EvidenceIntegrityError
from proofpatch.git.client import GitClient
from proofpatch.models.environment import (
    DependencyLockfileHash,
    VerifierEnvironmentIdentity,
    VerifierNetworkIdentity,
)
from proofpatch.models.execution import CommandOracleSpec, ResolvedImage
from proofpatch.models.patch import RepositorySnapshot
from proofpatch.services.evidence import canonical_json_bytes

DETERMINISTIC_VERIFIER_ENVIRONMENT: Final[dict[str, str]] = {
    "LANG": "C",
    "LC_ALL": "C",
    "PYTHONHASHSEED": "0",
    "TZ": "UTC",
}
LOCKFILE_NAMES: Final = frozenset(
    {
        "bun.lock",
        "bun.lockb",
        "cargo.lock",
        "composer.lock",
        "go.sum",
        "npm-shrinkwrap.json",
        "package-lock.json",
        "pipfile.lock",
        "pnpm-lock.yaml",
        "poetry.lock",
        "uv.lock",
        "yarn.lock",
    }
)
EMPTY_SETUP_CONFIGURATION: Final[dict[str, object]] = {
    "commands": [],
    "environment": {},
    "network": "unsupported",
}


def merge_verifier_environment(configured: Mapping[str, str]) -> dict[str, str]:
    """Apply fixed non-secret verifier variables and reject conflicting overrides."""

    conflicts = {
        name
        for name, value in configured.items()
        if name in DETERMINISTIC_VERIFIER_ENVIRONMENT
        and value != DETERMINISTIC_VERIFIER_ENVIRONMENT[name]
    }
    if conflicts:
        raise ConfigurationError(
            "Protected verifier environment cannot override: " + ", ".join(sorted(conflicts))
        )
    return {**configured, **DETERMINISTIC_VERIFIER_ENVIRONMENT}


def build_verifier_environment_identity(
    git: GitClient,
    snapshot: RepositorySnapshot,
    image: ResolvedImage,
    reproduction: CommandOracleSpec,
    regressions: tuple[CommandOracleSpec, ...],
) -> VerifierEnvironmentIdentity:
    """Hash the immutable image and every controller-owned verifier input."""

    if image.os != "linux" or image.architecture != "amd64":
        raise ConfigurationError("Protected verification requires a linux/amd64 image identity")
    lockfiles = _dependency_lockfiles(git, snapshot)
    setup_hash = _sha256(EMPTY_SETUP_CONFIGURATION)
    oracle_hash = _sha256(
        {
            "reproduction": reproduction.model_dump(mode="json"),
            "regressions": [item.model_dump(mode="json") for item in regressions],
        }
    )
    prepared_hash = _sha256(
        {
            "base_image_digest": image.digest,
            "base_image_id": image.image_id,
            "immutable_image_reference": image.immutable_reference,
            "platform": "linux/amd64",
            "architecture": image.architecture,
            "setup_configuration_sha256": setup_hash,
            "deterministic_environment": DETERMINISTIC_VERIFIER_ENVIRONMENT,
        }
    )
    document: dict[str, object] = {
        "schema_version": 1,
        "base_image_digest": image.digest,
        "base_image_id": image.image_id,
        "immutable_image_reference": image.immutable_reference,
        "platform": "linux/amd64",
        "architecture": image.architecture,
        "baseline_commit": snapshot.baseline_commit,
        "prepared_environment_sha256": prepared_hash,
        "setup_configuration_sha256": setup_hash,
        "dependency_lockfiles": [item.model_dump(mode="json") for item in lockfiles],
        "deterministic_environment": DETERMINISTIC_VERIFIER_ENVIRONMENT,
        "oracle_configuration_sha256": oracle_hash,
        "network": VerifierNetworkIdentity().model_dump(mode="json"),
        "scratch_policy": "fresh_container_tmpfs",
        "source_mount_policy": "read_only",
    }
    return VerifierEnvironmentIdentity.model_validate(
        {**document, "environment_inputs_sha256": _sha256(document)}
    )


def verify_verifier_environment_identity(identity: VerifierEnvironmentIdentity) -> None:
    """Recompute both noncircular hashes and reject altered identity documents."""

    prepared = {
        "base_image_digest": identity.base_image_digest,
        "base_image_id": identity.base_image_id,
        "immutable_image_reference": identity.immutable_image_reference,
        "platform": identity.platform,
        "architecture": identity.architecture,
        "setup_configuration_sha256": identity.setup_configuration_sha256,
        "deterministic_environment": identity.deterministic_environment,
    }
    if _sha256(prepared) != identity.prepared_environment_sha256:
        raise EvidenceIntegrityError("Prepared verifier environment identity is invalid")
    document = identity.model_dump(mode="json", exclude={"environment_inputs_sha256"})
    if _sha256(document) != identity.environment_inputs_sha256:
        raise EvidenceIntegrityError("Verifier environment input binding is invalid")
    if identity.setup_configuration_sha256 != _sha256(EMPTY_SETUP_CONFIGURATION):
        raise EvidenceIntegrityError("Protected verifier identity contains unsupported setup")
    if identity.deterministic_environment != DETERMINISTIC_VERIFIER_ENVIRONMENT:
        raise EvidenceIntegrityError("Protected verifier deterministic environment changed")


def _dependency_lockfiles(
    git: GitClient,
    snapshot: RepositorySnapshot,
) -> tuple[DependencyLockfileHash, ...]:
    root = snapshot.repository_root
    raw = git.run(
        ["-C", root, "ls-files", "-z", "--cached"],
        operation="dependency lockfile discovery",
    ).stdout
    paths = raw.split(b"\0")
    if paths and paths[-1] == b"":
        paths.pop()
    selected: list[str] = []
    for encoded in paths:
        try:
            path = encoded.decode("utf-8", errors="strict")
        except UnicodeDecodeError as error:
            raise EvidenceIntegrityError("Dependency lockfile path is not valid UTF-8") from error
        name = PurePosixPath(path).name.lower()
        if name in LOCKFILE_NAMES or (name.startswith("requirements") and name.endswith(".txt")):
            selected.append(path)
    lockfiles = []
    for path in sorted(selected):
        content = git.run(
            ["-C", root, "cat-file", "blob", f"{snapshot.baseline_commit}:{path}"],
            operation="dependency lockfile hashing",
        ).stdout
        lockfiles.append(
            DependencyLockfileHash(path=path, sha256=hashlib.sha256(content).hexdigest())
        )
    return tuple(lockfiles)


def _sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()
