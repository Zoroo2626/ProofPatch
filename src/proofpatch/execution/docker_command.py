"""Central, deterministic Docker argv construction for protected execution."""

import hashlib
from dataclasses import dataclass
from pathlib import Path

from proofpatch.errors import ConfigurationError
from proofpatch.models.execution import ExecutionRequest, MountAccess, NetworkPolicy
from proofpatch.security.mounts import validate_mounts

MANAGED_LABEL = "org.proofpatch.managed=true"
RUN_LABEL_PREFIX = "org.proofpatch.run_id="
PHASE_LABEL_PREFIX = "org.proofpatch.phase="


@dataclass(frozen=True, slots=True)
class DockerCommand:
    """Executable argv plus the non-secret representation safe for evidence logs."""

    argv: tuple[str, ...]
    redacted_argv: tuple[str, ...]
    container_name: str
    labels: tuple[str, ...]


class DockerCommandBuilder:
    """Build Docker commands without exposing arbitrary daemon flags to callers."""

    def __init__(self, executable: Path) -> None:
        self.executable = executable

    def build(self, request: ExecutionRequest) -> DockerCommand:
        mounts = validate_mounts(
            request.mounts,
            phase=request.phase,
            original_repository=request.original_repository,
            evidence_directory=request.evidence_directory,
            disposable_work_directory=request.disposable_work_directory,
            working_directory=request.working_directory,
        )
        if request.image.digest not in request.image.immutable_reference:
            raise ConfigurationError(
                "Execution image reference is not bound to its resolved digest"
            )

        name = _container_name(request)
        labels = (
            MANAGED_LABEL,
            f"{RUN_LABEL_PREFIX}{request.run_id}",
            f"{PHASE_LABEL_PREFIX}{request.phase.value}",
        )
        argv = [str(self.executable), "run", "--rm", "--name", name]
        for label in labels:
            argv.extend(("--label", label))
        argv.extend(
            (
                "--read-only",
                "--cap-drop=ALL",
                "--security-opt=no-new-privileges",
                "--pids-limit",
                str(request.resources.pids),
                "--memory",
                f"{request.resources.memory_mb}m",
                "--cpus",
                _format_cpus(request.resources.cpus),
                "--network",
                _docker_network(request.network),
                "--user",
                request.user,
                "--workdir",
                request.working_directory,
            )
        )
        for tmpfs in sorted(request.tmpfs, key=lambda item: item.path):
            argv.extend(
                (
                    "--tmpfs",
                    f"{tmpfs.path}:rw,noexec,nosuid,nodev,size={tmpfs.size_mb}m",
                )
            )
        for name_key in sorted(request.environment):
            # Docker reads the value from the tightly controlled CLI environment. It is never argv.
            argv.extend(("--env", name_key))
        for mount in sorted(mounts, key=lambda item: item.destination):
            source = str(mount.source.resolve(strict=True))
            if "," in source:
                raise ConfigurationError("Mount source containing a comma cannot be encoded safely")
            option = f"type=bind,src={source},dst={mount.destination}"
            if mount.access is MountAccess.READ_ONLY:
                option += ",readonly"
            argv.extend(("--mount", option))
        argv.append(request.image.immutable_reference)
        argv.extend(request.argv)
        command = tuple(argv)
        return DockerCommand(
            argv=command,
            redacted_argv=command,
            container_name=name,
            labels=labels,
        )


def _container_name(request: ExecutionRequest) -> str:
    run_token = request.run_id.removeprefix("pp_").replace("_", "-")
    identity = f"{request.run_id}\0{request.phase.value}\0{request.execution_id}".encode()
    suffix = hashlib.sha256(identity).hexdigest()[:12]
    return f"proofpatch-{run_token}-{request.phase.value}-{suffix}"[:128]


def _docker_network(network: NetworkPolicy) -> str:
    if network is NetworkPolicy.NONE:
        return "none"
    if network in {NetworkPolicy.BRIDGE, NetworkPolicy.AGENT_API}:
        return "bridge"
    raise ConfigurationError("Unsupported protected network policy")


def _format_cpus(value: float) -> str:
    return format(value, ".12g")
