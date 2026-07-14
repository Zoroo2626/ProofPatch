# ProofPatch

ProofPatch is an agent-independent verification gate for AI-generated bug fixes.

> **Development status:** Phase 9 GitHub integration. The full investigation-to-receipt lifecycle
> supports generic commands plus constrained Claude Code and Codex CLI adapters.

The intended product requires a reported failure to be reproduced independently before an agent
receives a writable disposable clone. A patch is successful only when ProofPatch independently
observes the configured failure-to-success transition and required regression checks in another
fresh clone. The user's original repository remains unchanged until explicit acceptance.

## Requirements

- Python 3.12 or newer
- Git
- Docker with Linux containers (required for protected execution)
- A verifier image with all required dependencies already installed; protected setup commands are
  rejected until ProofPatch can reuse one immutable prepared environment

## Install the development foundation

```console
python -m pip install -e .
proofpatch --version
proofpatch --help
proofpatch init --template python
proofpatch doctor
proofpatch list
proofpatch status pp_20260713_a4f92b18ce31
proofpatch inspect pp_20260713_a4f92b18ce31 --events
proofpatch inspect pp_20260713_a4f92b18ce31 --patch
proofpatch receipt pp_20260713_a4f92b18ce31 --verify-integrity
proofpatch apply pp_20260713_a4f92b18ce31
proofpatch run --config proofpatch.yml --issue "Reported failure" --yes
proofpatch resume pp_20260713_a4f92b18ce31 --config proofpatch.yml --yes
proofpatch abort pp_20260713_a4f92b18ce31
proofpatch clean pp_20260713_a4f92b18ce31
proofpatch clean --completed --older-than 30d --yes
proofpatch verify-patch --baseline-command "python reproduce.py" --patch-file candidate.diff
```

Install development tools with:

```console
python -m pip install --upgrade pip
python -m pip install --group dev -e .
```

## Development checks

```console
ruff check .
ruff format --check .
mypy src tests
pytest
python -m build
python -m twine check dist/*
```

## Implemented deterministic core

Phase 1 provides versioned run metadata, the complete specified state graph, canonical JSON Lines
events linked with SHA-256, full-chain verification, a rebuildable SQLite query index,
per-repository operating-system locks, and fail-closed cleanup-target ownership validation. The
event chain is authoritative; a stale or missing SQLite row cannot change the state reported by
`status` or `inspect`.

Phase 2 adds read-only repository preflight, full baseline capture, separate `--no-local`
independent clones, binary full-index patch capture, NUL-delimited changed-path parsing, exact
SHA-256 patch binding, fresh-clone apply/recapture validation, and explicit application of VERIFIED
runs on a new branch. The original repository is modified only by `proofpatch apply`.

Phase 3 independently runs the same structured reproduction oracle before and after the exact
captured patch, then runs every required regression. Commands use argument arrays, concurrent
bounded output draining, explicit timeouts, and exact secret-value redaction. JSON and Markdown
receipts contain observed exit codes, matcher results, log hashes, the contract hash, patch hash,
and evidence-chain hash.

Phase 4 adds Docker readiness checks, immutable image resolution, a single secure argument builder,
phase-specific mount validation, explicit network and environment policies, non-root execution,
read-only roots, hardened tmpfs, capability removal, no-new-privileges, finite resource limits,
bounded stream capture, and timeout/interruption cleanup. Cleanup verifies exact ProofPatch labels
before stopping or removing a container. Protected receipts require a complete successful
restriction assessment.

Allowlisted container credentials are delivered through a private, short-lived environment file.
They are not inherited by the host Docker client, placed in Docker arguments, or serialized into
evidence; the temporary file is removed after container cleanup.

Phase 5 adds the machine-readable failure-contract schema, bounded reproduction assets, strict
path/type/hash validation, the read-only investigation container workflow, and independent
baseline reproduction in a fresh clone using the verifier image without agent credentials. An
investigator's stdout or self-reported success cannot authorize patching. Only a validated,
unchanged contract whose baseline expectation passes independently reaches `BASELINE_REPRODUCED`.

Phase 6 adds the strict generic adapter, read-only prompt/issue mounts, environment-name
allowlisting, a repository-wide lifecycle lease, a fresh writable patch clone, informational
`patch-result.json` validation, exact patch capture, protected fixed/regression execution in a
fresh clone, protected JSON/Markdown receipts, safe checkpoint resume, cross-process label-bound
abort, and receipt-integrity enforcement before apply. Copy `proofpatch.example.yml` to
`proofpatch.yml` and replace its image and agent command. Passing `--yes` is required before agent
network access or configured environment forwarding.

Protected baseline and final verification use the same resolved immutable verifier image and fixed
`TZ=UTC`, `LANG=C`, `LC_ALL=C`, and `PYTHONHASHSEED=0` inputs. Setup commands and setup networking
fail preflight; dependencies must be baked into that image. The receipt binds the image digest and
ID, platform, baseline commit, dependency-lockfile hashes, oracle-configuration hash, network
policy, scratch policy, and the noncircular verifier-input identity. Live-network oracles are not
supported. ProofPatch does not claim control over application randomness, wall-clock reads, test
ordering, parallel scheduling, or filesystem ordering.

Phase 7 adds fixed, noninteractive Claude Code and Codex CLI adapters, provider credential
allowlists, credential-free protected version probes, minimum tested CLI enforcement, and bounded
provider transcript capture. Provider adapters cannot add mounts or Docker flags and cannot alter
evidence, reproduction, verification, or receipt decisions. See
[agent adapter development](docs/adapter-development.md) for current commands, credentials, tested
versions, and provider data handling.

Phase 8 adds deterministic patch fingerprints, append-only attempt records, bounded retry budgets,
exact patch-repeat detection, normalized path/line overlap warnings, repeated root-cause signals,
fresh baseline clones for every attempt, previous failure summaries in later prompts, and complete
attempt timelines in JSON and Markdown receipts. Similarity signals are advisory and use no
embeddings or model-based comparison.

Phase 9 adds a secret-free pull-request action, receipt-only workflow artifacts, sanitized
before/after job summaries, and an opt-in comment action kept in a separate write-scoped job. The
verification action accepts issue text or a pull-request body but never uploads the repository,
patch, logs, or evidence directory. See [GitHub Actions integration](docs/github-actions.md) for
the least-privilege workflow and fork-safety rules.

## Security status

Native oracle execution remains unisolated and its receipts are labeled `OBSERVATION ONLY`.
The Docker backend may report `PROTECTED` only when every required restriction has been established;
it does not protect against a compromised Docker daemon, container escape, or malicious host
administrator. Hash chaining detects modification but is not a digital signature. See
[SECURITY.md](SECURITY.md) and the [architecture](docs/architecture.md) for the implemented
boundaries and explicit non-claims.

ProofPatch does not implement network record-and-replay. Protected baseline and final oracles
always use `network none`; a workflow that needs live external network access is unsupported rather
than silently downgraded.

Completed protected workflows remove disposable clones by default while retaining receipts,
evidence, patch artifacts, and attempt records. Set `evidence.retain_workspaces: true` only when
the additional disk use is intentional.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Architectural decisions that alter the authoritative
specification require an ADR under `docs/decisions/`.

## License

Apache License 2.0. See [LICENSE](LICENSE).
