"""Protection claims derived from enforced execution facts."""

from proofpatch.errors import ConfigurationError
from proofpatch.execution.docker_command import DockerCommand
from proofpatch.models.execution import (
    BackendDoctorResult,
    ExecutionPhase,
    ExecutionRequest,
    MountAccess,
    MountKind,
    ProtectionAssessment,
    ProtectionLevel,
    ResolvedImage,
)
from proofpatch.security.mounts import validate_mounts


def calculate_protection(
    doctor: BackendDoctorResult,
    request: ExecutionRequest,
    command: DockerCommand,
) -> ProtectionAssessment:
    """Report protected only when every required Docker restriction is established."""

    satisfied: list[str] = []
    failures: list[str] = []

    _fact(doctor.healthy, "docker_ready", satisfied, failures)
    _fact(
        request.image.digest in request.image.immutable_reference,
        "immutable_image",
        satisfied,
        failures,
    )
    _fact(request.read_only_root, "read_only_root", satisfied, failures)
    _fact(not request.user.startswith("0"), "non_root_user", satisfied, failures)
    _fact(
        bool(_option_values(command.argv, "--network")),
        "network_explicit",
        satisfied,
        failures,
    )
    _fact(
        "host" not in _option_values(command.argv, "--network"),
        "no_host_network",
        satisfied,
        failures,
    )
    _fact("host" not in _option_values(command.argv, "--pid"), "no_host_pid", satisfied, failures)
    _fact("--privileged" not in command.argv, "not_privileged", satisfied, failures)
    _fact("--rm" in command.argv, "automatic_removal", satisfied, failures)
    _fact("--read-only" in command.argv, "read_only_argument", satisfied, failures)
    _fact("--cap-drop=ALL" in command.argv, "capabilities_dropped", satisfied, failures)
    _fact(
        "--security-opt=no-new-privileges" in command.argv,
        "no_new_privileges",
        satisfied,
        failures,
    )
    _fact(_has_required_labels(command), "managed_labels", satisfied, failures)
    _fact(_has_finite_limits(command), "finite_resource_limits", satisfied, failures)
    _fact(_tmpfs_is_hardened(command), "hardened_tmpfs", satisfied, failures)
    _fact(_environment_is_name_only(command), "environment_allowlist", satisfied, failures)
    try:
        validate_mounts(
            request.mounts,
            phase=request.phase,
            original_repository=request.original_repository,
            evidence_directory=request.evidence_directory,
            disposable_work_directory=request.disposable_work_directory,
            working_directory=request.working_directory,
        )
    except ConfigurationError:
        _fact(False, "phase_mount_policy", satisfied, failures)
    else:
        _fact(True, "phase_mount_policy", satisfied, failures)
    investigation_mount = next(
        (mount for mount in request.mounts if mount.kind is MountKind.WORKSPACE), None
    )
    _fact(
        request.phase is not ExecutionPhase.INVESTIGATION
        or (
            investigation_mount is not None and investigation_mount.access is MountAccess.READ_ONLY
        ),
        "investigation_workspace_read_only",
        satisfied,
        failures,
    )
    level = ProtectionLevel.PROTECTED if not failures else ProtectionLevel.UNAVAILABLE
    return ProtectionAssessment(
        level=level,
        satisfied=tuple(satisfied),
        failures=tuple(failures),
    )


def require_same_verification_image(
    baseline: ResolvedImage,
    verification: ResolvedImage,
) -> None:
    """Bind before and after verification to exactly one immutable image identity."""

    if (
        baseline.digest != verification.digest
        or baseline.image_id != verification.image_id
        or baseline.immutable_reference != verification.immutable_reference
    ):
        raise ConfigurationError(
            "Baseline and final verification must use the same resolved image digest"
        )


def _fact(
    condition: bool,
    name: str,
    satisfied: list[str],
    failures: list[str],
) -> None:
    (satisfied if condition else failures).append(name)


def _option_values(argv: tuple[str, ...], option: str) -> set[str]:
    values: set[str] = set()
    for index, item in enumerate(argv):
        if item == option and index + 1 < len(argv):
            values.add(argv[index + 1])
        elif item.startswith(f"{option}="):
            values.add(item.partition("=")[2])
    return values


def _has_required_labels(command: DockerCommand) -> bool:
    return (
        "org.proofpatch.managed=true" in command.labels
        and any(label.startswith("org.proofpatch.run_id=pp_") for label in command.labels)
        and any(label.startswith("org.proofpatch.phase=") for label in command.labels)
    )


def _has_finite_limits(command: DockerCommand) -> bool:
    return all(option in command.argv for option in ("--pids-limit", "--memory", "--cpus"))


def _tmpfs_is_hardened(command: DockerCommand) -> bool:
    values = _option_values(command.argv, "--tmpfs")
    return bool(values) and all(
        all(flag in value for flag in ("noexec", "nosuid", "nodev", "size=")) for value in values
    )


def _environment_is_name_only(command: DockerCommand) -> bool:
    return all("=" not in value for value in _option_values(command.argv, "--env"))
