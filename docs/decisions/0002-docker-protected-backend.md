# ADR 0002: Docker Protected Backend

- **Status:** Accepted, implemented in Phase 4
- **Date:** 2026-07-13

## Decision

Use Docker with Linux containers as the initial protected execution backend. Native subprocess
execution will be observation-only. The Docker CLI will be invoked with argument arrays generated
by one central policy builder; adapters cannot create their own unrestricted Docker commands.

## Consequences

Docker installation is required for protected runs. ProofPatch will not claim protection
from the Docker daemon, host administrators, root users, or container runtime vulnerabilities.

The implementation resolves images to immutable digests, validates every phase-specific bind
mount, constructs all Docker arguments centrally, applies finite CPU/memory/PID/time/output limits,
uses a read-only root filesystem with bounded hardened tmpfs mounts, and runs as a numeric non-root
user with all capabilities dropped and no-new-privileges. Host networking, host PID mode,
privileged execution, Docker sockets, user homes, credentials, original repositories, and evidence
directories are not representable through the protected request model or are rejected before the
Docker CLI starts.

Every container is named deterministically and carries the managed, run ID, and phase labels.
Cleanup inspects the exact stored name, verifies all labels, then performs graceful stop, forced
kill when necessary, and removal. It refuses to remove a container whose labels do not match.
