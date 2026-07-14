# Architecture

ProofPatch is designed as a deterministic host controller around untrusted coding agents. The
controller, not an agent or language model, owns state transitions and decides whether a gate
passes.

The planned lifecycle is:

```text
read-only investigation clone
    -> machine-readable failure contract
    -> fresh independent baseline reproduction
    -> separate writable patch clone
    -> exact patch capture
    -> fresh baseline-plus-patch verification clone
    -> deterministic reproduction transition and regressions
    -> hash-chained evidence and receipt
    -> explicit user-controlled apply
```

The host control plane will contain the CLI, coordinator, policy engine, repository service,
execution backends, oracle engine, evidence writer, receipt generator, patch analyzer, and agent
adapter registry. Execution environments will be phase-specific and disposable.

## Implemented through Phase 9

The deterministic run core is implemented as four layers:

1. Pydantic models define versioned run manifests, events, lock records, and SQLite records. The
   state enum and transition graph encode the lifecycle plus the documented retry and terminal
   failure edges in ADRs 0005 and 0006.
2. The evidence service writes canonical JSON Lines. Each event hashes every field except its own
   hash and links to the prior event hash. `chain.sha256` checkpoints the terminal event hash. A
   reader verifies framing, canonical encoding, schema, sequence, identity, every hash link, and the
   checkpoint before returning data.
3. SQLite stores query metadata only. Status is always derived again from verified evidence, and
   transitions reconcile stale index rows after an evidence append. SQLite is not used to choose a
   run's authoritative repository directory.
4. The coordinator holds a per-repository operating-system lock for mutations. Read-only list,
   status, and inspection do not take that lock. Stable evidence snapshots prevent a concurrent
   append from being misreported as corruption.

Run evidence lives under the platform application data directory at
`runs/<repository-id>/<run-id>`. Lock files and the SQLite index are siblings of `runs/`, never
repository files. Cleanup validation accepts only a run carrying a matching canonical `run.json`
marker or a descendant below the ProofPatch cache. Run access rejects symlink, junction, and Windows
reparse-point components. Cleanup validation returns a filesystem identity for replacement checks.
Completed workflow workspaces are moved atomically into the shorter application cache path and
removed only after a second identity check and complete no-link scan. Evidence and patch artifacts
are retained.

The Phase 2 Git layer discovers and validates a clean original without optional Git locks, records
the full baseline commit and redacted remote identity, and creates each workspace with `git clone
--no-local --no-checkout`. Clone alternates and object hardlinks are rejected. Effective changes
are staged only in the disposable patch clone and captured as an exact binary, full-index diff.
Changed paths are parsed from NUL-delimited output and checked for traversal, denied paths,
submodules, nested repositories, and disallowed symlinks. Patch bytes and canonical metadata are
bound into the state-event chain. A separate final-verification clone must apply and recapture the
same patch hash.

`proofpatch apply` is the only implemented operation that mutates the original. It requires a
VERIFIED run, intact evidence and patch bytes, matching repository identity and HEAD, a clean tree,
and a successful apply check. It creates a dedicated branch and leaves changes unstaged unless
`--stage` is requested.

The Phase 3 native verifier creates a separate baseline-verification clone, executes the baseline
expectation, applies and recaptures the candidate through the Phase 2 patch clone, and creates a
distinct final-verification clone. The same canonical reproduction specification is evaluated with
its fixed expectation, followed by all required regressions. Agent output is not an input to any
gate.

The controlled process layer uses argument arrays, concurrent stdout/stderr draining, a monotonic
deadline, cancellation, total output limits, process-group termination where supported, and exact
secret-value redaction before private logs are written. Command oracles support exit-code,
substring, and time-bounded regex matchers. Truncated output cannot satisfy a required oracle.

Receipts are canonical JSON plus Markdown and state only the observed transition, regression
results, hashes, and an evidence-backed protection level. Receipt hashing is noncircular: the
receipt records the decision-chain hash immediately before `receipt.created`; that event then
records the hashes of the completed JSON and Markdown. The verifier environment uses two other
noncircular hashes: `prepared_environment_sha256` hashes the immutable image, platform, empty setup
configuration, and fixed environment; `environment_inputs_sha256` then hashes the complete
environment document with that prepared hash but without hashing itself. Verification reconciles
receipt files with the baseline, contract, reproduction assets, patch, stored oracle results,
verified transition, workflow-plan event, environment event, resolved image identities, and
complete chain.

The Phase 4 Docker backend checks daemon readiness and Linux-container mode, resolves mutable image
references to immutable digests, and routes every container through one central argument builder.
The request model has no raw Docker flag escape hatch. It enforces a read-only root, bounded
non-executable tmpfs, non-root user, all-capability drop, no-new-privileges, explicit non-host
network, finite CPU/memory/PID/time/output limits, deterministic names, and managed/run/phase
labels. Environment values are delivered through a private, short-lived Docker environment file,
so the host Docker client never inherits container values. Only the environment-file path appears
in recorded argv; the file is removed after container cleanup.

Mount validation is phase-specific. Investigation source is read-only; patch workspaces are
writable independent clones; reproduction assets reverse access as required; oracle source is
read-only; verifier phases have no network or secret mounts. Protected setup commands are rejected
until one setup result can be reused as an immutable prepared environment. Dependencies must be
baked into the resolved verifier image. The validator
rejects overlapping destinations, link or reparse
sources, original/evidence path intersections, Docker sockets, user homes, and common credential
locations. Cleanup inspects an exact active name and verifies all ownership labels before graceful
stop, forced kill, or removal.

The Phase 5 investigation gate creates a dedicated independent clone and exposes it read-only to a
generic untrusted investigator command. Only separate reproduction scratch and outcome directories
are writable. The controller selects an outcome exclusively from `failure-contract.json` or
`not-reproduced.json`; stdout is never authoritative and both files are rejected as ambiguous.

Contracts use strict versioned models with structured argv, distinct baseline/fixed expectations,
container-contained working directories, and explicit environment names. Reproduction files are
declared by canonical relative path and SHA-256. The controller rejects traversal, links, reparse
points, hardlinks, special files, missing or undeclared files, hash mismatches, excessive count or
size, repository-configuration attempts, evidence references, and investigator-output-dependent
oracles. Valid bytes are copied into controller-owned evidence and revalidated before use.

Baseline reproduction always uses another fresh independent clone, the exact immutable verifier
image also used for final verification, network `none`, no agent credentials, and a read-only copy
of approved assets. The controller binds the image digest and local ID, linux/amd64 platform,
baseline commit, dependency-lockfile hashes, fixed locale/timezone/hash-seed inputs, oracle inputs,
network policy, and fresh-tmpfs policy into evidence and the receipt. The exact contract oracle is
evaluated by ProofPatch. Only a passing baseline expectation produces `BASELINE_REPRODUCED`; all
other outcomes remain unable to create a patch clone. Contract, asset, process-log, oracle, and
gate-decision facts are bound into the hash-chained evidence.

The Phase 6 generic adapter expands only `{prompt_path}`, `{workspace_path}`, `{output_path}`,
`{reproduction_path}`, and `{issue_path}` in a structured command. Controller-authored prompt and
issue files are mounted read-only. Adapter code cannot add mounts, Docker options, network modes,
or environment names. Resolved non-secret configuration is canonicalized and hash-bound before a
clone or container is created; only environment names are stored.

After independent baseline reproduction, a distinct writable clone is exposed to the patch agent
alongside read-only approved reproduction assets. The agent result is informational. ProofPatch
revalidates the original, captures the effective Git tree as an exact binary patch, rejects an
empty or denied patch, applies that patch to another fresh clone, reruns the immutable contract's
fixed expectation, and runs every required regression. Only those controller observations can
produce `VERIFIED`.

Each oracle receives a new container and hardened `/tmp` tmpfs. Source and reproduction mounts are
read-only, and the host hashes every non-Git workspace entry before and after each oracle to detect
backend-policy failures or source mutation. No cache or scratch mount is shared between baseline
and final verification.

These controls reduce drift but are not a claim of complete runtime determinism. ProofPatch does
not freeze wall-clock time, application random sources, process scheduling, test order, parallel
execution, or filesystem enumeration order. It has no network record-and-replay facility; live
network-dependent protected oracles and network-enabled dependency setup are unsupported.

A separate repository-wide lifecycle lease prevents overlapping full workflows while the existing
operation lock protects individual evidence mutations. Resume uses only evidence-backed
checkpoints: an interrupted patch clone requires explicit capture confirmation, incomplete final
verification is quarantined and recreated, and a verified receipt is reused idempotently. Abort
discovers containers by exact managed/run labels, verifies those labels again, removes only those
containers, then records `ABORTED`. Apply now verifies the receipt/event binding and receipt patch
hash first.

Phase 7 adds fixed Claude Code and Codex CLI templates behind the same adapter protocol. Each
provider is version-probed in a separate credential-free, network-disabled protected container.
Only the reviewed provider API-key name is forwarded to agent executions. The adapter produces no
mount or policy fields, so its own permission or sandbox options cannot widen ProofPatch's outer
Docker boundary. Provider transcripts and JSON streams are captured as untrusted, bounded,
secret-redacted logs; the evidence and verification services remain the only gate authorities.

Phase 8 permits `REJECTED -> PATCH_PREPARING` only for a controller-scheduled attempt within the
configured maximum. Every retry receives a newly independent clone of the original baseline, not
the preceding attempt. Completed attempt records are written once under the run's `attempts`
directory and hash-bound into the event chain. Before another attempt, the prior patch artifacts
are moved into a distinct controller-owned archive that is never mounted into a later agent.

Patch fingerprints hash canonical changed-path/status data, whitespace-normalized added and removed
line hashes, and the immutable failure signature. Exact repeats use the byte-exact patch SHA-256;
high similarity uses deterministic Jaccard overlap over path and normalized-line token sets.
Normalized root-cause text can signal a repeated hypothesis. These signals appear in receipts but
do not replace or bypass fresh oracle verification.
