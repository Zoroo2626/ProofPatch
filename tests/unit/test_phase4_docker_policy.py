"""Adversarial tests for the central Docker protected-mode policy."""

from pathlib import Path

import pytest
from pydantic import ValidationError

from proofpatch.backends.docker import _container_environment_file
from proofpatch.errors import ConfigurationError
from proofpatch.execution.docker_command import DockerCommandBuilder
from proofpatch.models.execution import (
    BackendDoctorResult,
    DockerMount,
    ExecutionPhase,
    ExecutionRequest,
    MountAccess,
    MountKind,
    NetworkPolicy,
    ProtectionAssessment,
    ProtectionLevel,
    ResolvedImage,
    ResourceLimits,
    TmpfsMount,
)
from proofpatch.security.mounts import validate_mounts
from proofpatch.services.policy import calculate_protection, require_same_verification_image

RUN_ID = "pp_20260713_a4f92b18ce31"
DIGEST = "sha256:" + "a" * 64
IMAGE_ID = "sha256:" + "b" * 64


def _image(*, digest: str = DIGEST) -> ResolvedImage:
    return ResolvedImage(
        requested_reference="example/runtime:latest",
        immutable_reference=f"example/runtime@{digest}",
        digest=digest,
        image_id=IMAGE_ID,
        architecture="amd64",
    )


def _limits() -> ResourceLimits:
    return ResourceLimits(
        timeout_seconds=10.0,
        memory_mb=256,
        cpus=1.0,
        pids=64,
        output_bytes=4096,
    )


def _paths(tmp_path: Path) -> dict[str, Path]:
    paths = {
        name: tmp_path / name
        for name in ("original", "evidence", "workspace", "workspace-two", "output", "secret")
    }
    for name, path in paths.items():
        if name == "secret":
            path.write_text("credential", encoding="utf-8")
        else:
            path.mkdir()
    return paths


def _request(
    tmp_path: Path,
    *,
    phase: ExecutionPhase = ExecutionPhase.INVESTIGATION,
    access: MountAccess = MountAccess.READ_ONLY,
    network: NetworkPolicy = NetworkPolicy.BRIDGE,
    mounts: tuple[DockerMount, ...] | None = None,
    environment: dict[str, str] | None = None,
    allowlist: tuple[str, ...] = (),
) -> ExecutionRequest:
    paths = _paths(tmp_path)
    selected = mounts or (
        DockerMount(
            source=paths["workspace"],
            destination="/workspace",
            kind=MountKind.WORKSPACE,
            access=access,
        ),
        DockerMount(
            source=paths["output"],
            destination="/proofpatch/out",
            kind=MountKind.OUTPUT,
            access=MountAccess.READ_WRITE,
        ),
    )
    return ExecutionRequest(
        execution_id="investigate-1",
        run_id=RUN_ID,
        phase=phase,
        image=_image(),
        argv=("python", "check.py"),
        network=network,
        mounts=selected,
        environment=environment or {},
        environment_allowlist=allowlist,
        resources=_limits(),
        original_repository=paths["original"],
        evidence_directory=paths["evidence"],
    )


def test_builder_enforces_every_required_restriction_and_redacts_environment(
    tmp_path: Path,
) -> None:
    request = _request(
        tmp_path,
        environment={"API_TOKEN": "super-secret-value"},
        allowlist=("API_TOKEN",),
    )
    with _container_environment_file(request.environment) as environment_file:
        command = DockerCommandBuilder(Path("docker")).build(
            request, environment_file=environment_file
        )

    assert command.argv[:3] == ("docker", "run", "--rm")
    assert "--read-only" in command.argv
    assert "--cap-drop=ALL" in command.argv
    assert "--security-opt=no-new-privileges" in command.argv
    assert "--pids-limit" in command.argv
    assert "--memory" in command.argv
    assert "--cpus" in command.argv
    assert "--network" in command.argv
    assert command.argv[command.argv.index("--network") + 1] == "bridge"
    assert "--user" in command.argv
    assert "--privileged" not in command.argv
    assert "--pid=host" not in command.argv
    assert "super-secret-value" not in command.argv
    assert "--env" not in command.argv
    assert command.argv[command.argv.index("--env-file") + 1] == str(environment_file)
    assert request.image.immutable_reference in command.argv
    workspace_option = next(item for item in command.argv if "dst=/workspace" in item)
    assert workspace_option.endswith(",readonly")
    assert all(label in command.argv for label in command.labels)


def test_environment_keys_are_sorted_deterministically() -> None:
    with _container_environment_file(
        {"Z_TOKEN": "long-secret-z", "A_TOKEN": "long-secret-a"}
    ) as environment_file:
        assert environment_file is not None
        assert environment_file.read_bytes() == (b"A_TOKEN=long-secret-a\nZ_TOKEN=long-secret-z\n")
        parent = environment_file.parent
    assert not environment_file.exists()
    assert not parent.exists()


def test_builder_requires_private_indirect_environment_file(tmp_path: Path) -> None:
    request = _request(tmp_path, environment={"TOKEN": "secret"}, allowlist=("TOKEN",))
    with pytest.raises(ConfigurationError, match="private environment file"):
        DockerCommandBuilder(Path("docker")).build(request)


def test_container_environment_values_must_be_single_line(tmp_path: Path) -> None:
    with pytest.raises(ValidationError, match="single-line"):
        _request(tmp_path, environment={"TOKEN": "line-one\nline-two"}, allowlist=("TOKEN",))


@pytest.mark.parametrize(
    ("kind", "destination", "access"),
    [
        (MountKind.WORKSPACE, "/var/run/docker.sock", MountAccess.READ_ONLY),
        (MountKind.WORKSPACE, "/workspace", MountAccess.READ_WRITE),
        (MountKind.SECRET, "/run/secrets/token", MountAccess.READ_WRITE),
    ],
)
def test_blocked_mounts_and_permissions(
    tmp_path: Path,
    kind: MountKind,
    destination: str,
    access: MountAccess,
) -> None:
    paths = _paths(tmp_path)
    source = paths["secret"] if kind is MountKind.SECRET else paths["workspace"]
    mounts = (
        DockerMount(
            source=source,
            destination=destination,
            kind=kind,
            access=access,
        ),
    )
    with pytest.raises(ConfigurationError):
        validate_mounts(
            mounts,
            phase=ExecutionPhase.INVESTIGATION,
            original_repository=paths["original"],
            evidence_directory=paths["evidence"],
            working_directory="/workspace",
        )


@pytest.mark.parametrize("protected_name", ["original", "evidence"])
def test_original_and_evidence_directories_cannot_be_mounted(
    tmp_path: Path,
    protected_name: str,
) -> None:
    paths = _paths(tmp_path)
    mount = DockerMount(
        source=paths[protected_name],
        destination="/workspace",
        kind=MountKind.WORKSPACE,
        access=MountAccess.READ_ONLY,
    )
    with pytest.raises(ConfigurationError, match=protected_name):
        validate_mounts(
            (mount,),
            phase=ExecutionPhase.INVESTIGATION,
            original_repository=paths["original"],
            evidence_directory=paths["evidence"],
            working_directory="/workspace",
        )


def test_parent_directory_cannot_expose_original_or_evidence(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    mount = DockerMount(
        source=tmp_path,
        destination="/workspace",
        kind=MountKind.WORKSPACE,
        access=MountAccess.READ_ONLY,
    )
    with pytest.raises(ConfigurationError):
        validate_mounts(
            (mount,),
            phase=ExecutionPhase.INVESTIGATION,
            original_repository=paths["original"],
            evidence_directory=paths["evidence"],
            working_directory="/workspace",
        )


def test_duplicate_or_overlapping_destinations_are_rejected(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    mounts = (
        DockerMount(
            source=paths["workspace"],
            destination="/workspace",
            kind=MountKind.WORKSPACE,
            access=MountAccess.READ_ONLY,
        ),
        DockerMount(
            source=paths["workspace-two"],
            destination="/workspace",
            kind=MountKind.WORKSPACE,
            access=MountAccess.READ_ONLY,
        ),
    )
    with pytest.raises(ConfigurationError, match="overlap"):
        validate_mounts(
            mounts,
            phase=ExecutionPhase.INVESTIGATION,
            original_repository=paths["original"],
            evidence_directory=paths["evidence"],
            working_directory="/workspace",
        )


def test_non_allowlisted_environment_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ValidationError, match="non-allowlisted"):
        _request(tmp_path, environment={"UNEXPECTED": "secret"})


def test_host_network_and_root_identity_are_unrepresentable(tmp_path: Path) -> None:
    request = _request(tmp_path)
    data = request.model_dump()
    data["network"] = "host"
    with pytest.raises(ValidationError):
        ExecutionRequest.model_validate(data)
    data["network"] = NetworkPolicy.BRIDGE
    data["user"] = "0:0"
    with pytest.raises(ValidationError, match="non-root"):
        ExecutionRequest.model_validate(data)


def test_verification_network_must_be_none(tmp_path: Path) -> None:
    with pytest.raises(ValidationError, match="network none"):
        _request(
            tmp_path,
            phase=ExecutionPhase.VERIFICATION,
            access=MountAccess.READ_WRITE,
            network=NetworkPolicy.BRIDGE,
        )


def test_tmpfs_cannot_shadow_workspace(tmp_path: Path) -> None:
    request = _request(tmp_path)
    data = request.model_dump()
    data["tmpfs"] = [
        TmpfsMount(path="/tmp", size_mb=64),  # noqa: S108 - container path
        {"path": "/workspace", "size_mb": 64, "executable": False},
    ]
    with pytest.raises(ValidationError):
        ExecutionRequest.model_validate(data)


def test_protection_requires_all_facts(tmp_path: Path) -> None:
    request = _request(tmp_path)
    command = DockerCommandBuilder(Path("docker")).build(request)
    healthy = BackendDoctorResult(
        docker_cli=True,
        daemon_responding=True,
        linux_containers=True,
    )
    protected = calculate_protection(healthy, request, command)
    unavailable = calculate_protection(
        healthy.model_copy(update={"linux_containers": False}), request, command
    )
    assert protected.level is ProtectionLevel.PROTECTED
    assert not protected.failures
    assert unavailable.level is ProtectionLevel.UNAVAILABLE
    assert "docker_ready" in unavailable.failures

    with pytest.raises(ValidationError, match="every mandatory"):
        ProtectionAssessment(
            level=ProtectionLevel.PROTECTED,
            satisfied=("docker_ready",),
            failures=(),
        )


@pytest.mark.parametrize(
    ("level", "satisfied", "failures", "message"),
    [
        (
            ProtectionLevel.UNAVAILABLE,
            ("docker_ready", "docker_ready"),
            ("immutable_image",),
            "unique",
        ),
        (
            ProtectionLevel.UNAVAILABLE,
            ("docker_ready",),
            ("docker_ready",),
            "both satisfied and failed",
        ),
        (
            ProtectionLevel.UNAVAILABLE,
            (),
            ("invented_fact",),
            "unknown fact",
        ),
        (ProtectionLevel.UNAVAILABLE, (), (), "identify a failure"),
        (
            ProtectionLevel.OBSERVATION_ONLY,
            ("docker_ready",),
            (),
            "do not claim",
        ),
    ],
)
def test_protection_assessment_rejects_inconsistent_claims(
    level: ProtectionLevel,
    satisfied: tuple[str, ...],
    failures: tuple[str, ...],
    message: str,
) -> None:
    with pytest.raises(ValidationError, match=message):
        ProtectionAssessment(level=level, satisfied=satisfied, failures=failures)


def test_baseline_and_verification_must_share_exact_resolved_image() -> None:
    require_same_verification_image(_image(), _image())
    with pytest.raises(ConfigurationError, match="same resolved image"):
        require_same_verification_image(_image(), _image(digest="sha256:" + "c" * 64))


def test_builder_rejects_image_reference_not_bound_to_digest(tmp_path: Path) -> None:
    request = _request(tmp_path)
    bad_image = request.image.model_copy(update={"immutable_reference": IMAGE_ID})
    with pytest.raises(ConfigurationError, match="not bound"):
        DockerCommandBuilder(Path("docker")).build(request.model_copy(update={"image": bad_image}))


def test_mount_source_with_comma_fails_closed(tmp_path: Path) -> None:
    request = _request(tmp_path)
    comma_workspace = tmp_path / "workspace,escaped"
    comma_workspace.mkdir()
    mounts = tuple(
        mount.model_copy(update={"source": comma_workspace})
        if mount.kind is MountKind.WORKSPACE
        else mount
        for mount in request.mounts
    )
    with pytest.raises(ConfigurationError, match="comma"):
        DockerCommandBuilder(Path("docker")).build(request.model_copy(update={"mounts": mounts}))


def test_user_home_mount_is_rejected(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    mount = DockerMount(
        source=home,
        destination="/workspace",
        kind=MountKind.WORKSPACE,
        access=MountAccess.READ_ONLY,
    )
    with pytest.raises(ConfigurationError, match="User home"):
        validate_mounts(
            (mount,),
            phase=ExecutionPhase.INVESTIGATION,
            original_repository=paths["original"],
            evidence_directory=paths["evidence"],
            working_directory="/workspace",
        )


def test_verifier_cannot_receive_secret_mount(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    mounts = (
        DockerMount(
            source=paths["workspace"],
            destination="/workspace",
            kind=MountKind.WORKSPACE,
            access=MountAccess.READ_ONLY,
        ),
        DockerMount(
            source=paths["secret"],
            destination="/run/secrets/token",
            kind=MountKind.SECRET,
            access=MountAccess.READ_ONLY,
        ),
    )
    with pytest.raises(ConfigurationError, match="forbidden"):
        validate_mounts(
            mounts,
            phase=ExecutionPhase.VERIFICATION,
            original_repository=paths["original"],
            evidence_directory=paths["evidence"],
            working_directory="/workspace",
        )


def test_dependency_cache_is_forbidden(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    mounts = (
        DockerMount(
            source=paths["workspace"],
            destination="/workspace",
            kind=MountKind.WORKSPACE,
            access=MountAccess.READ_ONLY,
        ),
        DockerMount(
            source=paths["workspace-two"],
            destination="/proofpatch/cache/npm",
            kind=MountKind.DEPENDENCY_CACHE,
            access=MountAccess.READ_ONLY,
        ),
    )
    with pytest.raises(ConfigurationError, match="forbidden"):
        validate_mounts(
            mounts,
            phase=ExecutionPhase.INVESTIGATION,
            original_repository=paths["original"],
            evidence_directory=paths["evidence"],
            working_directory="/workspace",
        )


def test_protected_setup_phase_is_rejected_at_mount_boundary(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    mounts = (
        DockerMount(
            source=paths["workspace"],
            destination="/workspace",
            kind=MountKind.WORKSPACE,
            access=MountAccess.READ_WRITE,
        ),
    )
    with pytest.raises(ConfigurationError, match="setup execution is unsupported"):
        validate_mounts(
            mounts,
            phase=ExecutionPhase.SETUP,
            original_repository=paths["original"],
            evidence_directory=paths["evidence"],
            working_directory="/workspace",
        )


def test_workspace_mount_is_mandatory(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    output = DockerMount(
        source=paths["output"],
        destination="/proofpatch/out",
        kind=MountKind.OUTPUT,
        access=MountAccess.READ_WRITE,
    )
    with pytest.raises(ConfigurationError, match="exactly one workspace"):
        validate_mounts(
            (output,),
            phase=ExecutionPhase.INVESTIGATION,
            original_repository=paths["original"],
            evidence_directory=paths["evidence"],
            working_directory="/workspace",
        )
