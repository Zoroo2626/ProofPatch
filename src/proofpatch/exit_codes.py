"""Stable process exit codes exposed by the ProofPatch CLI."""

from enum import IntEnum


class ExitCode(IntEnum):
    """Public CLI exit codes.

    These numeric values are part of ProofPatch's public interface and must not
    be renumbered without an explicit compatibility decision.
    """

    SUCCESS = 0
    INVALID_COMMAND_OR_CONFIGURATION = 2
    PREFLIGHT_FAILURE = 3
    BASELINE_NOT_REPRODUCED = 4
    AGENT_FAILURE = 5
    PATCH_REJECTED = 6
    VERIFICATION_FAILED = 7
    APPLY_FAILED = 8
    EVIDENCE_INTEGRITY_FAILED = 9
    INTERRUPTED = 10
    UNSUPPORTED_ENVIRONMENT = 11
    INTERNAL_ERROR = 12
