"""The deterministic ProofPatch run state machine."""

from collections.abc import Mapping
from enum import StrEnum
from types import MappingProxyType

from proofpatch.errors import InvalidStateTransition


class RunState(StrEnum):
    """Every persisted lifecycle state defined by the specification."""

    CREATED = "CREATED"
    PREFLIGHT = "PREFLIGHT"
    BASELINE_PREPARING = "BASELINE_PREPARING"
    INVESTIGATING = "INVESTIGATING"
    CONTRACT_SUBMITTED = "CONTRACT_SUBMITTED"
    BASELINE_VERIFYING = "BASELINE_VERIFYING"
    BASELINE_REPRODUCED = "BASELINE_REPRODUCED"
    BASELINE_NOT_REPRODUCED = "BASELINE_NOT_REPRODUCED"
    PATCH_PREPARING = "PATCH_PREPARING"
    PATCHING = "PATCHING"
    PATCH_CAPTURED = "PATCH_CAPTURED"
    FINAL_VERIFYING = "FINAL_VERIFYING"
    VERIFIED = "VERIFIED"
    REJECTED = "REJECTED"
    APPLIED = "APPLIED"
    ABORTED = "ABORTED"
    ERROR = "ERROR"
    CLEANED = "CLEANED"


_TRANSITIONS: dict[RunState, frozenset[RunState]] = {
    RunState.CREATED: frozenset({RunState.PREFLIGHT, RunState.ERROR, RunState.ABORTED}),
    RunState.PREFLIGHT: frozenset({RunState.BASELINE_PREPARING, RunState.ERROR, RunState.ABORTED}),
    RunState.BASELINE_PREPARING: frozenset(
        {RunState.INVESTIGATING, RunState.BASELINE_VERIFYING, RunState.ERROR, RunState.ABORTED}
    ),
    RunState.INVESTIGATING: frozenset(
        {RunState.CONTRACT_SUBMITTED, RunState.ABORTED, RunState.ERROR}
    ),
    RunState.CONTRACT_SUBMITTED: frozenset(
        {RunState.BASELINE_VERIFYING, RunState.REJECTED, RunState.ERROR, RunState.ABORTED}
    ),
    RunState.BASELINE_VERIFYING: frozenset(
        {
            RunState.BASELINE_REPRODUCED,
            RunState.BASELINE_NOT_REPRODUCED,
            RunState.ERROR,
            RunState.ABORTED,
        }
    ),
    RunState.BASELINE_NOT_REPRODUCED: frozenset({RunState.REJECTED}),
    RunState.BASELINE_REPRODUCED: frozenset(
        {RunState.PATCH_PREPARING, RunState.ERROR, RunState.ABORTED}
    ),
    RunState.PATCH_PREPARING: frozenset({RunState.PATCHING, RunState.ERROR, RunState.ABORTED}),
    RunState.PATCHING: frozenset(
        {RunState.PATCH_CAPTURED, RunState.REJECTED, RunState.ABORTED, RunState.ERROR}
    ),
    RunState.PATCH_CAPTURED: frozenset(
        {RunState.FINAL_VERIFYING, RunState.ERROR, RunState.ABORTED}
    ),
    RunState.FINAL_VERIFYING: frozenset(
        {RunState.VERIFIED, RunState.REJECTED, RunState.ERROR, RunState.ABORTED}
    ),
    RunState.VERIFIED: frozenset({RunState.APPLIED, RunState.CLEANED}),
    RunState.REJECTED: frozenset({RunState.PATCH_PREPARING, RunState.CLEANED}),
    RunState.ABORTED: frozenset({RunState.CLEANED}),
    RunState.ERROR: frozenset({RunState.CLEANED}),
    RunState.APPLIED: frozenset({RunState.CLEANED}),
    RunState.CLEANED: frozenset(),
}

VALID_TRANSITIONS: Mapping[RunState, frozenset[RunState]] = MappingProxyType(_TRANSITIONS)


def can_transition(current: RunState, target: RunState) -> bool:
    """Return whether the state machine permits ``current -> target``."""

    return target in VALID_TRANSITIONS[current]


def validate_transition(current: RunState, target: RunState) -> None:
    """Fail closed when a requested state transition is not permitted."""

    if not can_transition(current, target):
        raise InvalidStateTransition(f"Invalid run state transition: {current} -> {target}")
