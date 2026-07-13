"""Tests for typed errors and their public exit mappings."""

import pytest

from proofpatch.errors import (
    ApplyError,
    BackendError,
    CleanupError,
    ConfigurationError,
    ContractError,
    DockerUnavailableError,
    EvidenceIntegrityError,
    ExecutionError,
    ExecutionTimeoutError,
    ImageResolutionError,
    InternalInvariantError,
    InvalidStateTransition,
    OracleError,
    PatchError,
    PreflightError,
    ProofPatchError,
    RepositoryError,
    UserInputError,
    VerificationError,
)
from proofpatch.exit_codes import ExitCode

ERROR_TYPES = (
    ProofPatchError,
    UserInputError,
    ConfigurationError,
    PreflightError,
    RepositoryError,
    BackendError,
    DockerUnavailableError,
    ImageResolutionError,
    ExecutionError,
    ExecutionTimeoutError,
    ContractError,
    OracleError,
    PatchError,
    VerificationError,
    EvidenceIntegrityError,
    ApplyError,
    CleanupError,
    InternalInvariantError,
    InvalidStateTransition,
)


@pytest.mark.parametrize("error_type", ERROR_TYPES)
def test_all_public_errors_have_stable_metadata(error_type: type[ProofPatchError]) -> None:
    error = error_type("Something failed", remediation="Try a safe action")

    assert isinstance(error, ProofPatchError)
    assert isinstance(error.exit_code, ExitCode)
    assert error.error_code.startswith("PP_")
    assert str(error) == "Something failed"
    assert error.as_dict() == {
        "error_code": error.error_code,
        "exit_code": int(error.exit_code),
        "message": "Something failed",
        "remediation": "Try a safe action",
    }


def test_remediation_is_optional() -> None:
    error = UserInputError("Bad value")

    assert error.remediation is None
    assert error.as_dict()["remediation"] is None


def test_error_hierarchy_matches_the_specification() -> None:
    assert all(error_type.__bases__ == (ProofPatchError,) for error_type in ERROR_TYPES[1:])
