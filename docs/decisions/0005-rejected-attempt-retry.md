# ADR 0005: Controller-owned retries after rejected attempts

## Status

Accepted.

## Decision

`REJECTED -> PATCH_PREPARING` is permitted only for the deterministic repeated-attempt workflow.
The host controller must have a validated baseline checkpoint, an append-only record of the rejected
attempt, and remaining configured attempts. Agents cannot request or perform this transition.

## Rationale

The original state table treated `REJECTED` as terminal. Phase 8 added bounded repeated attempts,
which requires a fresh patch clone after a failed independent verification. Recording this exception
prevents the security-relevant state-machine change from being implicit. Once the configured attempt
limit is reached, rejection remains terminal except for cleanup.
