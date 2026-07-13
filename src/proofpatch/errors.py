"""Typed exceptions and their stable CLI-facing error metadata."""

from typing import ClassVar

from proofpatch.exit_codes import ExitCode


class ProofPatchError(Exception):
    """Base class for expected ProofPatch failures."""

    error_code: ClassVar[str] = "PP_INTERNAL_ERROR"
    exit_code: ClassVar[ExitCode] = ExitCode.INTERNAL_ERROR

    def __init__(self, message: str, *, remediation: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.remediation = remediation

    def as_dict(self) -> dict[str, str | int | None]:
        """Return stable, machine-readable details for CLI and logging callers."""

        return {
            "error_code": self.error_code,
            "exit_code": int(self.exit_code),
            "message": self.message,
            "remediation": self.remediation,
        }


class UserInputError(ProofPatchError):
    """A command-line value cannot be accepted."""

    error_code = "PP_USER_INPUT_INVALID"
    exit_code = ExitCode.INVALID_COMMAND_OR_CONFIGURATION


class ConfigurationError(ProofPatchError):
    """Configuration is missing, malformed, or unsupported."""

    error_code = "PP_CONFIGURATION_INVALID"
    exit_code = ExitCode.INVALID_COMMAND_OR_CONFIGURATION


class PreflightError(ProofPatchError):
    """A required precondition for a run is not satisfied."""

    error_code = "PP_PREFLIGHT_FAILED"
    exit_code = ExitCode.PREFLIGHT_FAILURE


class RepositoryError(ProofPatchError):
    """The target repository cannot be used safely."""

    error_code = "PP_REPOSITORY_INVALID"
    exit_code = ExitCode.PREFLIGHT_FAILURE


class BackendError(ProofPatchError):
    """An execution backend cannot satisfy the requested operation."""

    error_code = "PP_BACKEND_FAILED"
    exit_code = ExitCode.UNSUPPORTED_ENVIRONMENT


class DockerUnavailableError(ProofPatchError):
    """Docker protected mode is unavailable."""

    error_code = "PP_DOCKER_UNAVAILABLE"
    exit_code = ExitCode.UNSUPPORTED_ENVIRONMENT


class ImageResolutionError(ProofPatchError):
    """A configured execution image cannot be resolved immutably."""

    error_code = "PP_IMAGE_RESOLUTION_FAILED"
    exit_code = ExitCode.UNSUPPORTED_ENVIRONMENT


class ExecutionError(ProofPatchError):
    """A controlled external process failed unexpectedly."""

    error_code = "PP_EXECUTION_FAILED"


class ExecutionTimeoutError(ProofPatchError):
    """A controlled external process exceeded its timeout."""

    error_code = "PP_EXECUTION_TIMEOUT"


class AgentError(ProofPatchError):
    """An untrusted agent timed out, failed, or produced no usable result."""

    error_code = "PP_AGENT_FAILED"
    exit_code = ExitCode.AGENT_FAILURE


class AgentTimeoutError(AgentError):
    """An agent exceeded its controller-enforced deadline."""

    error_code = "PP_AGENT_TIMEOUT"


class ContractError(ProofPatchError):
    """A submitted failure contract cannot unlock the patch phase."""

    error_code = "PP_CONTRACT_INVALID"
    exit_code = ExitCode.BASELINE_NOT_REPRODUCED


class OracleError(ProofPatchError):
    """A deterministic oracle could not be evaluated."""

    error_code = "PP_ORACLE_FAILED"
    exit_code = ExitCode.VERIFICATION_FAILED


class PatchError(ProofPatchError):
    """A candidate patch cannot be accepted."""

    error_code = "PP_PATCH_REJECTED"
    exit_code = ExitCode.PATCH_REJECTED


class PatchEmptyError(PatchError):
    """A candidate contains no effective changes."""

    error_code = "PP_PATCH_EMPTY"


class PatchPathDeniedError(PatchError):
    """A candidate changes a path or object forbidden by policy."""

    error_code = "PP_PATCH_PATH_DENIED"


class PatchTooLargeError(PatchError):
    """A candidate exceeds the configured byte limit."""

    error_code = "PP_PATCH_TOO_LARGE"


class PatchTooManyFilesError(PatchError):
    """A candidate exceeds the configured changed-file limit."""

    error_code = "PP_PATCH_TOO_MANY_FILES"


class VerificationError(ProofPatchError):
    """Independent verification did not satisfy required checks."""

    error_code = "PP_VERIFICATION_FAILED"
    exit_code = ExitCode.VERIFICATION_FAILED


class EvidenceIntegrityError(ProofPatchError):
    """Persisted evidence failed an integrity check."""

    error_code = "PP_EVIDENCE_INTEGRITY_FAILED"
    exit_code = ExitCode.EVIDENCE_INTEGRITY_FAILED


class ApplyError(ProofPatchError):
    """A verified patch could not be applied safely."""

    error_code = "PP_APPLY_FAILED"
    exit_code = ExitCode.APPLY_FAILED


class CleanupError(ProofPatchError):
    """ProofPatch-owned temporary data could not be cleaned safely."""

    error_code = "PP_CLEANUP_FAILED"


class InternalInvariantError(ProofPatchError):
    """An internal deterministic invariant was violated."""

    error_code = "PP_INTERNAL_INVARIANT_FAILED"


class InvalidStateTransition(ProofPatchError):
    """A requested run-state transition is not part of the state machine."""

    error_code = "PP_INVALID_STATE_TRANSITION"
