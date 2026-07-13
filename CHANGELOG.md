# Changelog

All notable changes to ProofPatch will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and released versions
will follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Phase 9 secret-free GitHub pull-request verification, receipt-only artifacts, job summaries,
  and a separately privileged opt-in comment action.
- GitHub fork-safety, least-privilege, source-upload, and active-Markdown security tests and
  documentation.

- Phase 0 Python package and CLI foundation.
- Stable typed errors and public process exit codes.
- Cross-platform application-directory service.
- Plain and structured JSON internal logging.
- Test, lint, type-check, build, and CI configuration.
- Phase 1 run and repository identifier generation.
- Exact deterministic run state machine and transition enforcement.
- Versioned canonical events with append-only SHA-256 chaining and complete integrity verification.
- Rebuildable SQLite run metadata and evidence-derived stale-index recovery.
- Cross-process per-repository operating-system locks with versioned diagnostic records.
- Evidence-backed `list`, `status`, and `inspect --events` commands.
- Fail-closed cleanup containment, link, junction, and ownership-marker validation.
- Stable interruption handling using public exit code 10.
- Phase 2 repository preflight, full baseline capture, independent non-hardlinked clones, binary
  patch capture, changed-path policy, exact patch hashing, fresh-clone apply verification, and the
  evidence-gated `proofpatch apply` command.
- Phase 3 command-oracle interface, exit/substrings/bounded-regex matchers, controlled concurrent
  process runner, timeout and cancellation outcomes, output limits, secret redaction, independent
  baseline/fixed/regression execution, observation-only receipts, and `verify-patch` CLI flow.
- Phase 4 Docker readiness diagnostics, immutable image resolution, central secure argv generation,
  phase-specific mount and environment enforcement, finite resource limits, non-root/read-only
  execution, hardened tmpfs, network/capability restrictions, bounded stream capture, timeout and
  interruption termination, label-verified cleanup, and complete protection-level assessment.
- Adversarial Docker tests covering prohibited mounts and permissions, host/root policy rejection,
  image and daemon failures, successful and failing exits, timeouts, interruption, forced-kill
  escalation, and forged cleanup labels.
- Phase 5 strict failure-contract and not-reproduced schemas, bounded reproduction-asset capture,
  canonical contract hashing, read-only protected investigation, fresh verifier-image baseline
  reproduction, immutable contract/asset revalidation, and controller-only patch gating.
- Adversarial investigation tests covering path traversal, duplicate JSON keys, missing and
  undeclared assets, symlinks, hardlinks, hash changes, evidence/output references, environment and
  repository-configuration attempts, ambiguous or natural-language-only outcomes, source-write
  attempts, unprotected backend results, and baseline expectation failure.
- Phase 6 strict generic adapter with five approved placeholders, read-only prompt and issue mounts,
  explicit environment allowlisting, canonical secret-free resolved configuration evidence,
  repository-wide lifecycle leases, writable independent patch clones, strict agent result files,
  exact patch capture, fresh protected fixed/regression verification, and full protected receipts.
- `proofpatch run`, `resume`, and `abort`, including explicit interrupted-patch capture confirmation,
  recreation of incomplete verification, cross-process exact-label container termination, and
  idempotent verified-receipt recovery.
- Receipt/event/decision-chain verification and receipt patch-hash enforcement before explicit
  application to the original repository.
- Fake-agent coverage for successful fixes, false success claims, regressions, empty patches,
  invalid output, nonzero exits, timeouts, interruptions, unprotected execution, and setup failure.
- Security hardening for strict finite JSON, bounded nesting, manifest/event binding, controller-only
  state authorization, SQLite redirect resistance, linked parent paths, cleanup replacement checks,
  remote credential removal, and live lock-path substitution detection.
- Phase 7 fixed Claude Code and Codex CLI adapters with reviewed noninteractive arguments,
  provider-specific API-key allowlists, credential-free protected version probes, minimum tested
  version enforcement, provider transcript capture, mock adapter tests, real-lifecycle fake backend
  tests, provider data-handling documentation, and a manual protected smoke-test wrapper.
- Phase 8 canonical patch fingerprints, append-only attempt tracking, configured retry limits,
  fresh baseline clones per attempt, exact repeat and deterministic Jaccard-overlap warnings,
  normalized root-cause repetition signals, prior failure prompt summaries, archived prior attempt
  artifacts, and JSON/Markdown receipt timelines without embeddings.
