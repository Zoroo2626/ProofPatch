# ADR 0006: Terminal transitions from every active checkpoint

## Status

Accepted.

## Decision

Every active controller checkpoint permits `ERROR` and `ABORTED` as appropriate. An unexpected
exception records only its stable error code and type, attempts labeled-container termination,
and then moves the run to `ERROR`. A process interruption terminates the active container but
preserves the evidence-backed checkpoint so the explicit resume or abort command remains possible.

## Rationale

The original transition table left small windows such as `PATCH_CAPTURED` where a host failure
could strand a run in an apparently active state. The specification separately requires unexpected
errors and interruptions to preserve evidence and reach a terminal state. These terminal edges
make that requirement enforceable without granting agents any transition authority.
