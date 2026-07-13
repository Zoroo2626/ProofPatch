"""Tests that protect the CLI's public numeric exit interface."""

from proofpatch.exit_codes import ExitCode


def test_exit_codes_match_the_specification() -> None:
    assert {member.name: member.value for member in ExitCode} == {
        "SUCCESS": 0,
        "INVALID_COMMAND_OR_CONFIGURATION": 2,
        "PREFLIGHT_FAILURE": 3,
        "BASELINE_NOT_REPRODUCED": 4,
        "AGENT_FAILURE": 5,
        "PATCH_REJECTED": 6,
        "VERIFICATION_FAILED": 7,
        "APPLY_FAILED": 8,
        "EVIDENCE_INTEGRITY_FAILED": 9,
        "INTERRUPTED": 10,
        "UNSUPPORTED_ENVIRONMENT": 11,
        "INTERNAL_ERROR": 12,
    }


def test_exit_code_values_are_unique() -> None:
    values = [member.value for member in ExitCode]

    assert len(values) == len(set(values))
