"""Common execution backend interface."""

from typing import Protocol, runtime_checkable

from proofpatch.models.execution import (
    BackendDoctorResult,
    ExecutionRequest,
    ExecutionResult,
    ProtectionLevel,
    ResolvedImage,
)


class ExecutionBackend(Protocol):
    """Operations required from protected and observation execution backends."""

    @property
    def protection_level(self) -> ProtectionLevel: ...

    def doctor(self) -> BackendDoctorResult: ...

    def resolve_image(self, image: str, *, pull: bool = False) -> ResolvedImage: ...

    def run(self, request: ExecutionRequest) -> ExecutionResult: ...

    def terminate(self, execution_id: str) -> None: ...

    def cleanup(self, execution_id: str) -> None: ...


@runtime_checkable
class RunTerminatingBackend(Protocol):
    """Optional capability used by a separate abort command process."""

    def terminate_run(self, run_id: str) -> None: ...
