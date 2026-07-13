# ADR 0001: Python Core

- **Status:** Accepted
- **Date:** 2026-07-13

## Decision

Implement the initial ProofPatch host controller in Python 3.12 or newer, packaged with a `src/`
layout. Use Typer for the CLI, Pydantic for future schemas, PyYAML for repository configuration, and
platformdirs for application-owned paths.

## Consequences

The project can provide a typed, cross-platform CLI with mature filesystem, process, hashing, JSON,
and SQLite support. Python 3.11 and older are not supported.
