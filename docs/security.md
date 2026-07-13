# Security Architecture

Protected mode uses Docker with Linux containers as its initial operating-system enforcement
boundary. Agent adapters cannot customize or weaken the central container policy.

Enforced boundaries include read-only investigation source, independent clones, no original
repository mount, no evidence-store mount, no Docker socket, no host home or credentials directory,
an explicit environment allowlist, a non-root user, dropped capabilities, no-new-privileges,
resource limits, timeouts, and output limits.

Native execution will be labeled `OBSERVATION ONLY` and will not be described as isolated or
protected. A protected label will be emitted only when every required restriction is established.

Phase 4 invokes the Docker CLI only with argument arrays and a controlled host environment. Images
are inspected and resolved to an immutable digest before execution. The central builder always
adds automatic removal, a read-only root, all-capability drop, no-new-privileges, numeric non-root
identity, explicit network policy, bounded hardened tmpfs, and finite CPU, memory, PID, timeout, and
output limits. Bind mounts are phase-typed, canonicalized, link-checked, and rejected when they
expose the original repository, evidence directory, Docker socket, user home, or common credential
directories. Tmpfs and bind destinations may not overlap.

Cleanup is fail-closed: ProofPatch inspects only the exact active container name, verifies its
managed/run/phase labels, attempts graceful termination, escalates to a kill if needed, and removes
the container. A label mismatch is never deleted. Protection is calculated from all enforced facts;
a receipt model cannot claim `protected` without the complete successful assessment.

Phase 5 treats every investigator-created file as untrusted. The source clone is mounted read-only,
then its HEAD, status, ownership, and Git configuration are checked again after container removal.
The original repository is independently revalidated as well. The investigator receives no run or
evidence mount and cannot write a state transition.

Contract JSON is bounded and parsed with duplicate-key, encoding, nesting, finite-number, and strict
schema checks. Asset paths are relative and canonical; every path component and submitted entry is
type-checked without following links. Only declared single-link regular files with matching hashes
are copied into evidence, under count and byte limits. Approved assets are rehashed immediately
before copying to a fresh baseline-verification mount. Natural-language output, missing outcomes,
ambiguous outcomes, invalid contracts, changed source, and failed independent reproduction never
unlock patch preparation.

Phase 6 mounts controller-authored prompts and issue text read-only and expands only five approved
container-path placeholders. Secret values are selected at execution time from an explicit
environment-name allowlist and are never serialized into resolved configuration evidence. A
separate lifecycle OS lease spans the full workflow so another cooperating ProofPatch process
cannot start a competing run for the same repository.

The patch agent receives only a writable independent clone, read-only approved assets, read-only
controller inputs, and a dedicated output directory. It receives neither the original repository
nor evidence. Its result file is informational: host-side Git capture, immutable contract checks,
fresh-clone patch recapture, fixed expectation, and all regressions determine the outcome. Resume
never assumes a container survived; capture of an interrupted patch clone requires explicit user
confirmation, and incomplete verification is recreated. Cross-process abort filters and reinspects
exact managed/run labels before removal. Resume, receipt display, inspect, and apply verify the
single receipt event, decision checkpoint, baseline, contract, patch bytes, verified transition,
and protected image identities before trusting a receipt or changing the original.

Phase 7 provider adapters are fixed command templates, not arbitrary provider flag pass-throughs.
Claude receives only `ANTHROPIC_API_KEY`; Codex receives only `CODEX_API_KEY`; missing, extra, or
renamed credential variables fail before agent execution. Version probes are credential-free,
network-disabled protected executions. Provider home/config/session mounts and dangerous bypass
flags are absent by construction. Claude runs without session persistence in bare mode. Codex runs
ephemerally without user config or repository rule loading, with an inner phase-appropriate
sandbox that cannot expand the outer Docker boundary. Provider JSON/transcript output remains
untrusted, bounded, secret-redacted, privately stored, and incapable of bypassing evidence or
verification gates.

Phase 8 retry authorization remains controller-owned and is capped at ten configured attempts.
Each patch and final-verification workspace is a fresh independent baseline clone with a unique
run-owned path. Later agents cannot mount the evidence-backed attempt directory or prior patch
workspace. Completed attempt records are exclusive-create files with contiguous identities and
event-chain hashes. Exact-repeat detection compares exact patch SHA-256 values. Similarity removes
whitespace only in separate line-hash metadata and never changes the original patch bytes or hash.
Path/line overlap and normalized root-cause repetition are deterministic warnings, not verification
results or automatic rejection reasons. No embeddings, external similarity service, or agent
self-assessment participates in these signals.

Phase 9 treats GitHub Actions as orchestration and publication, not verification authority. The
basic pull-request action runs deterministic native observation without secrets, with a read-only
token and non-persisted checkout credentials. Before publication it re-verifies the receipt's
evidence binding, then creates a new directory containing exactly `receipt.json` and `receipt.md`.
The artifact uploader receives those two exact paths; source, patch bytes, command logs, disposable
clones, and the evidence directory are not uploaded.

Issue and pull-request text is untrusted. It is bounded by the existing receipt schema and escaped
before use in a workflow summary or comment, including neutralizing HTML, links, Markdown control
characters, and user mentions. The original text remains part of the downloadable receipt. A
comment token is never accepted by the verification action. Optional commenting uses a separate
job/action with only `pull-requests: write`, a same-repository guard, no checkout, and no execution
of PR artifacts. The documented workflow uses `pull_request`, never `pull_request_target`, and
does not expose provider credentials to forked or same-repository PR code.

Phase 1 does enforce local integrity boundaries for its own deterministic data:

- Evidence is canonical, append-only through the service, size-bounded, hash-linked, and completely
  reverified before append or inspection. Duplicate JSON keys, torn lines, noncanonical encodings,
  non-finite numbers, excessive nesting, schema coercion, broken sequences, identity substitution,
  and stale checkpoints fail closed.
- SQLite cannot authorize, locate, or override a run because it is only a rebuildable index. Run
  storage is discovered from validated on-disk identifiers and evidence.
- Mutations use a per-repository operating-system lock. PID metadata is diagnostic only; ProofPatch
  does not infer lock ownership from a reusable PID. The holder also checks that the live lock path
  still names the locked file before an evidence mutation.
- Private application directories and files are created with restrictive modes where the operating
  system supports them.
- Cleanup validation checks resolved containment, rejects symlink and junction components, and
  requires a matching versioned ownership marker before a run target is considered eligible. Its
  result includes the target's filesystem identity. Default workspace cleanup revalidates that
  identity, rejects linked descendants, atomically quarantines the tree, and only then removes it.

Phase 2 does not execute repository hooks. Git is invoked with argument arrays, `shell=False`,
bounded pipe draining, optional locks disabled, an empty hooks path, no pager, no global or system
configuration, and a minimal environment. Repository configuration capable of launching hooks,
filters, pagers, diff commands, aliases, includes, or credential helpers is rejected, and a clone's Git
configuration is hashed and rechecked before host-side staging. Source inspection and cloning do
not intentionally write the original Git directory. Patch staging occurs only in a run-owned
clone; the original is changed only after an explicit apply command. Independent clones use
`--no-local`, remove their source remote, reject alternates, and compare Git object file identities
to reject hardlinks back to the source.

Phase 3 native oracle commands execute with the current host user's authority and therefore are not
a sandbox boundary. Receipts label this mode `OBSERVATION ONLY`. The runner does not invoke a
shell, supplies a small explicit host-environment base, drains stdout and stderr concurrently,
enforces monotonic timeouts and a combined output limit, and terminates process groups or trees
where the platform permits. Exact configured secret values are removed before logs are persisted;
derived, encoded, fragmented, or transformed secrets may still be disclosed by a repository
process. Secret values in command arguments are rejected when detected. Protected baseline and
final oracle containers instead receive a read-only source mount after the separate writable setup
phase.

Disk limits are layered: repository size, patch bytes, changed-file count, process output, event
chain size, reproduction assets, and attempt count are bounded. With `retain_workspaces: false`,
completed clones are removed. Enabling retention can consume several multiples of the configured
repository limit, so users must provision and monitor that storage explicitly. Per-command logs
and retained workspaces do not share a single global run quota; a configuration with many oracles
can therefore multiply the per-command bound.

The SHA-256 chain is not signed. Anyone with sufficient host-account access to rewrite both the
events and checkpoint can construct a new chain. ProofPatch does not claim protection from a
malicious administrator, root user, compromised kernel, or physical attacker.

Similarly, OS locks coordinate cooperating ProofPatch processes; they are not protection from a
malicious process already running as the same host user and able to rewrite the private application
data directory. Agent and repository processes must never receive access to that directory.
