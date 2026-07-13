"""Common interface and context for independent deterministic oracles."""

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from proofpatch.execution.process import ProcessOutcome, ProcessRunner
from proofpatch.models.execution import CommandOracleSpec, OracleEvaluation, OraclePhase


@dataclass(frozen=True, slots=True)
class OracleExecutionContext:
    """Controller-owned paths and secrets for one oracle execution."""

    workspace: Path
    run_root: Path
    log_directory: Path
    runner: ProcessRunner
    maximum_output_bytes: int
    secret_environment: dict[str, str]


@dataclass(frozen=True, slots=True)
class OracleExecutionResult:
    """Observed process output plus its persisted, redacted log metadata."""

    outcome: ProcessOutcome
    stdout_path: str
    stdout_sha256: str
    stderr_path: str
    stderr_sha256: str


class Oracle(Protocol):
    """Every oracle validates, executes independently, and evaluates deterministically."""

    type_name: str

    def validate(self, spec: CommandOracleSpec) -> None: ...

    def execute(
        self,
        spec: CommandOracleSpec,
        context: OracleExecutionContext,
    ) -> OracleExecutionResult: ...

    def evaluate(
        self,
        spec: CommandOracleSpec,
        phase: OraclePhase,
        result: OracleExecutionResult,
    ) -> OracleEvaluation: ...
