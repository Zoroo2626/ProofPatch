# ADR 0007: Fail closed on mutable verifier setup

## Status

Accepted for the current pre-alpha release audit.

## Context

The initial workflow executed configured setup commands independently in the baseline clone and
again in the final-verification clone. Setup could use Docker bridge networking. Matching command
configuration and a matching mutable image tag did not prove that both installations produced the
same dependencies or files. A transient registry response could therefore create a false
failure-to-success transition.

## Decision

Protected mode rejects setup commands, setup environment values, and setup networking. Required
dependencies must be baked into the verifier image. The controller resolves that image to an
immutable digest and local image ID once per run and executes both baseline and final oracles with
that exact identity and `network none`.

The controller records a versioned verifier-environment document containing the image identities,
linux/amd64 platform, baseline commit, tracked dependency-lockfile SHA-256 values, empty setup
configuration hash, fixed non-secret environment values, oracle-configuration hash, network
policy, read-only source policy, and fresh-tmpfs policy. The prepared-environment hash excludes
itself. The complete input hash excludes only itself and includes the prepared hash. Both are bound
to the event chain and protected receipt.

## Consequences

Stock language images that require package installation are not sufficient for protected mode;
users must publish or build an appropriate immutable verifier image before running ProofPatch.
This is less convenient but fails closed. Network record-and-replay and a controller-built,
content-addressed prepared image remain future work. Until one is implemented and tested,
network-dependent protected verification is unsupported.

The fixed environment does not control wall-clock reads, arbitrary random sources, test ordering,
parallel scheduling, or filesystem enumeration, so documentation must not claim complete runtime
determinism.
