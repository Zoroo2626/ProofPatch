# ProofPatch

A verification layer for AI coding agents that checks whether a patch actually fixes a bug before accepting it.

AI agents can write code quickly, but "fixed" does not always mean fixed. ProofPatch creates a controlled workflow where bugs are reproduced, patches are applied, and results are verified. "It works on my machine" was already a shaky standard before the machine started writing the patch.

## How it works

```text
Bug report
    ↓
Baseline reproduction
    ↓
Agent patch
    ↓
Isolated verification
    ↓
Proof receipt
```

1. **Bug report:** ProofPatch turns the reported failure into a testable contract.
2. **Baseline reproduction:** The failure must be observed before patching is allowed.
3. **Agent patch:** The configured agent works in a disposable Git clone, not the original repository.
4. **Isolated verification:** A fresh workspace checks that the failure is gone and regression checks still pass.
5. **Proof receipt:** ProofPatch records the patch and verification evidence for later inspection.

## Features

- Isolated patch verification
- Evidence and receipt tracking
- Docker protected execution
- Git patch isolation
- Agent adapter support
- Regression checking
- Security focused workflow

## Installation

Requirements:

- Python 3.12 or newer
- Git
- Docker with Linux containers for protected execution

Clone the repository:

```bash
git clone <repo-url>
cd ProofPatch
```

Create a virtual environment:

```bash
python -m venv .venv
```

On Windows Command Prompt:

```bat
.venv\Scripts\activate
```

On Linux or macOS:

```bash
source .venv/bin/activate
```

Install ProofPatch:

```bash
pip install -e .
proofpatch --help
```

## Quick example

From the project you want to check, create a starter configuration and inspect the environment:

```bash
proofpatch init --template python --mode protected
proofpatch doctor
```

Review the generated `proofpatch.yml`. Set the agent command and use a verifier image that already contains your project's dependencies. Then start a run:

```bash
proofpatch run --config proofpatch.yml --issue "Tests fail when an empty name is submitted" --yes
```

The command prints a run ID. Use it to inspect the result and verify the stored receipt:

```bash
proofpatch status <run-id>
proofpatch receipt <run-id> --verify-integrity
```

If the run is verified and the patch looks right, apply it to a new branch in the original repository:

```bash
proofpatch apply <run-id>
```

## Development

Install the development dependencies, then run the usual checks:

```bash
pip install --group dev -e .
pytest
ruff format --check .
ruff check .
mypy src tests
```

CI runs the test, lint, and type-checking jobs across Linux, macOS, and Windows.

## Why?

AI coding agents are useful, but verification should not depend on trusting the agent's own report. ProofPatch keeps patch generation and verification separate, then leaves an evidence trail you can inspect.

## License

ProofPatch is licensed under the [Apache License 2.0](LICENSE).
