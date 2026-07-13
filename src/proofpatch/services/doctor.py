"""Protected-backend preflight diagnostics."""

from proofpatch.backends.docker import DockerBackend
from proofpatch.errors import DockerUnavailableError
from proofpatch.models.execution import BackendDoctorResult, ResolvedImage


class DockerDoctorService:
    """Expose Docker readiness and optional immutable image resolution."""

    def __init__(self, backend: DockerBackend | None = None) -> None:
        self.backend = backend or DockerBackend()

    def check(self) -> BackendDoctorResult:
        return self.backend.doctor()

    def require_ready(self) -> BackendDoctorResult:
        result = self.check()
        if not result.healthy:
            raise DockerUnavailableError(
                result.error or "Docker protected mode is unavailable",
                remediation="Install Docker, start its daemon, and enable Linux containers.",
            )
        return result

    def resolve_image(self, image: str, *, pull: bool = False) -> ResolvedImage:
        self.require_ready()
        return self.backend.resolve_image(image, pull=pull)
