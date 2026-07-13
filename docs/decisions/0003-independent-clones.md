# ADR 0003: Independent Clones

- **Status:** Accepted, implemented in Phase 2
- **Date:** 2026-07-13

## Decision

Use separate, non-hardlinked Git clones for investigation, baseline reproduction, patch generation,
and final verification. Never convert an investigation clone into a writable patch clone or verify
directly in an agent's mutable clone.

## Consequences

The original repository can remain outside execution mounts and unchanged until explicit apply.
Runs will consume additional time and disk space, which is accepted in favor of isolation.
