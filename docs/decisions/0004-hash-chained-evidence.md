# ADR 0004: Hash-Chained Evidence

- **Status:** Accepted, implemented in Phase 1
- **Date:** 2026-07-13

## Decision

Use append-only canonical JSON Lines as the authoritative evidence chain and SQLite as a rebuildable
query index. Link events using SHA-256 hashes and keep evidence outside all agent-accessible mounts.

`chain.sha256` contains the final event hash followed by one line feed. Readers verify every event,
not only that checkpoint. Event appends are flushed before the checkpoint is atomically replaced;
an interruption that leaves the two inconsistent fails closed instead of being silently repaired.
State is reconstructed from `run.created` and valid `run.state_changed` events.

## Consequences

Modification of an existing event will be detectable within the documented host trust model. Local
hash chaining is not a signature and does not protect evidence from a malicious host administrator.
The exact receipt-hashing order must still be specified before receipt implementation to avoid
circular self-hash dependencies.
