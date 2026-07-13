# Threat Model

The planned design considers buggy or destructive agents, hostile repository scripts, false success
claims, test weakening, evidence tampering attempts, hostile paths and symlinks, unbounded output,
and hanging commands.

Protected assets include the original repository and Git metadata, host files outside approved
mounts, non-allowlisted credentials, reproduction evidence, the captured patch, verification
results, and their baseline-to-receipt mapping.

Out of scope are malicious administrators or root users, a compromised Docker daemon, container
escapes, malicious kernels, physical attacks, and secrets intentionally exposed by the user.

The complete testable threat model will be developed with the protected backend. Phase 0 creates no
security boundary.
