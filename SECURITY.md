# Security Policy

## Current status

ProofPatch is pre-alpha and is implemented through Phase 9. The Docker protected backend, strict
generic agent adapter, investigation gate, patch workflow, fresh verification, protected receipts,
resume, abort, and guarded explicit application are implemented. Native `verify-patch` execution
remains explicitly `OBSERVATION ONLY` and provides no sandbox security boundary. Claude and Codex
adapters, deterministic repeated-attempt analysis, and the least-privilege GitHub receipt
integration are implemented.

Protected verifier setup and live-network oracles are intentionally unsupported. Dependencies must
be baked into the resolved immutable verifier image so baseline and final verification cannot drift
through independent installation. ProofPatch fixes a small set of locale/timezone/hash-seed inputs
but does not claim complete runtime determinism or network record-and-replay.

## Intended threat model

The planned protected mode treats coding agents, repository contents, configured commands, and
their output as untrusted. Its intended assets include the original repository, Git metadata,
credentials, host files, captured patches, and an evidence store kept outside agent-accessible
mounts.

The design does not claim protection against a malicious host administrator, root user,
compromised Docker daemon, container escape, malicious kernel, or secrets intentionally passed to
an agent. It is not intended to be a general malware sandbox.

## Supported versions

There is no stable supported release yet. Security fixes are applied to the current development
line until a versioned support policy is published.

## Reporting a vulnerability

Please use the repository's private vulnerability-reporting feature in its **Security** section.
If private reporting is not available, contact the maintainers privately before opening a public
issue. Do not include secrets, exploit payloads, or sensitive repository contents in public reports.

Include the affected version, operating system, reproduction steps, observed impact, and whether
the issue crosses an intended trust boundary.

## Credential warning

The generic agent command may transmit source context to its configured provider. ProofPatch's own
data handling and an agent provider's data handling are separate concerns. Never place secrets
in configuration, command arguments, logs, issue text, or reproduction assets.

## GitHub Actions warning

The pull-request action is intentionally credential-free and requires only `contents: read`.
Do not pass `github.token`, provider keys, or other secrets to its job. Do not use
`pull_request_target` to check out and execute pull-request code. Optional comments belong in the
documented separate same-repository-only job with only `pull-requests: write`; that job must not
check out or execute pull-request code. The action uploads only receipt JSON and Markdown, but
receipts can contain issue text and repository metadata. Review retention and repository
visibility before enabling artifacts.
