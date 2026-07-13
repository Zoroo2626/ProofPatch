# Contributing to ProofPatch

ProofPatch is being implemented one specification phase at a time. A contribution must remain
within the active phase and must not replace a technical boundary with prompt instructions.

## Development setup

Use Python 3.12 or newer in an isolated environment:

```console
python -m venv .venv
```

Activate the environment using the command appropriate for your shell, then install the project:

```console
python -m pip install --upgrade pip
python -m pip install --group dev -e .
```

## Required checks

Run every check before submitting a change:

```console
ruff format --check .
ruff check .
mypy src tests
pytest
python -m build
python -m twine check dist/*
```

To apply formatting locally, run `ruff format .`.

## Change discipline

- Add typed models and validate inputs.
- Test success, user error, and interruption where a public command can be interrupted.
- Add integration tests for external processes.
- Keep logs and fixtures free of secrets.
- Preserve stable exit codes and machine-readable error codes.
- Document public behavior.
- Do not begin a later phase while an earlier phase's acceptance criteria fail.
- Record architectural changes in `docs/decisions/` instead of changing a foundational decision
  silently.
