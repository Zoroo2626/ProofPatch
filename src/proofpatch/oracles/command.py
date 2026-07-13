"""Shell-free command oracle backed by the controlled native process runner."""

import hashlib
import os
import stat
from pathlib import Path
from typing import Final

from proofpatch.errors import OracleError
from proofpatch.execution.process import ProcessRequest
from proofpatch.models.execution import (
    CommandOracleSpec,
    OracleEvaluation,
    OracleExpectation,
    OraclePhase,
    ProcessRecord,
)
from proofpatch.oracles.base import OracleExecutionContext, OracleExecutionResult
from proofpatch.oracles.matchers import (
    evaluate_exit_code,
    evaluate_text,
    validate_text_matcher,
)

PRIVATE_FILE_MODE: Final = 0o600


class CommandOracle:
    """Execute one argument-array command and evaluate controller-owned expectations."""

    type_name = "command"

    def validate(self, spec: CommandOracleSpec) -> None:
        for expectation in (
            spec.baseline_expectation,
            spec.fixed_expectation,
            spec.expectation,
        ):
            if expectation is None:
                continue
            for matcher in (*expectation.stdout, *expectation.stderr):
                validate_text_matcher(matcher)

    def execute(
        self,
        spec: CommandOracleSpec,
        context: OracleExecutionContext,
    ) -> OracleExecutionResult:
        self.validate(spec)
        workspace = context.workspace.resolve(strict=True)
        cwd = (workspace / Path(spec.cwd)).resolve(strict=True)
        try:
            cwd.relative_to(workspace)
        except ValueError as error:
            raise OracleError(
                "Oracle working directory escapes the verification workspace"
            ) from error
        if not cwd.is_dir():
            raise OracleError("Oracle working directory is not a directory")
        environment = dict(spec.environment)
        overlap = environment.keys() & context.secret_environment.keys()
        if overlap:
            raise OracleError(f"Oracle environment overrides secret variable: {sorted(overlap)[0]}")
        environment.update(context.secret_environment)
        outcome = context.runner.run(
            ProcessRequest(
                argv=spec.argv,
                cwd=cwd,
                timeout_seconds=spec.timeout_seconds,
                maximum_output_bytes=context.maximum_output_bytes,
                environment=environment,
                stdin_text=spec.stdin,
                secret_values=tuple(context.secret_environment.values()),
            )
        )

        context.log_directory.mkdir(mode=0o700, parents=True, exist_ok=False)
        stdout = context.log_directory / "stdout.log"
        stderr = context.log_directory / "stderr.log"
        _write_private_log(stdout, outcome.stdout)
        _write_private_log(stderr, outcome.stderr)
        return OracleExecutionResult(
            outcome=outcome,
            stdout_path=_relative_log_path(stdout, context.run_root),
            stdout_sha256=hashlib.sha256(outcome.stdout).hexdigest(),
            stderr_path=_relative_log_path(stderr, context.run_root),
            stderr_sha256=hashlib.sha256(outcome.stderr).hexdigest(),
        )

    def evaluate(
        self,
        spec: CommandOracleSpec,
        phase: OraclePhase,
        result: OracleExecutionResult,
    ) -> OracleEvaluation:
        expectation = _expectation_for_phase(spec, phase)
        matchers = [evaluate_exit_code(expectation.exit_code, result.outcome.exit_code)]
        matchers.extend(
            evaluate_text("stdout", matcher, result.outcome.stdout)
            for matcher in expectation.stdout
        )
        matchers.extend(
            evaluate_text("stderr", matcher, result.outcome.stderr)
            for matcher in expectation.stderr
        )
        if result.outcome.timed_out:
            failure_code = "PP_VERIFICATION_TIMEOUT"
        elif result.outcome.cancelled:
            failure_code = "PP_VERIFICATION_CANCELLED"
        elif result.outcome.truncated:
            failure_code = "PP_ORACLE_OUTPUT_TRUNCATED"
        elif all(matcher.passed for matcher in matchers):
            failure_code = None
        else:
            failure_code = "PP_ORACLE_EXPECTATION_FAILED"
        process = ProcessRecord(
            termination=result.outcome.termination,
            exit_code=result.outcome.exit_code,
            signal=result.outcome.signal,
            duration_ms=result.outcome.duration_ms,
            timed_out=result.outcome.timed_out,
            cancelled=result.outcome.cancelled,
            stdout_path=result.stdout_path,
            stdout_sha256=result.stdout_sha256,
            stdout_bytes=len(result.outcome.stdout),
            stderr_path=result.stderr_path,
            stderr_sha256=result.stderr_sha256,
            stderr_bytes=len(result.outcome.stderr),
            truncated=result.outcome.truncated,
        )
        return OracleEvaluation(
            oracle_id=spec.id,
            phase=phase,
            passed=failure_code is None,
            process=process,
            matcher_results=tuple(matchers),
            failure_code=failure_code,
        )


def _expectation_for_phase(spec: CommandOracleSpec, phase: OraclePhase) -> OracleExpectation:
    if phase is OraclePhase.BASELINE:
        expectation = spec.baseline_expectation
    elif phase is OraclePhase.FIXED:
        expectation = spec.fixed_expectation
    else:
        expectation = spec.expectation
    if expectation is None:
        raise OracleError(f"Oracle {spec.id} has no expectation for phase {phase.value}")
    return expectation


def _write_private_log(path: Path, content: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags, PRIVATE_FILE_MODE)
        file_status = os.fstat(descriptor)
        if not stat.S_ISREG(file_status.st_mode) or file_status.st_nlink != 1:
            raise OracleError("Oracle log path is not a private regular file")
        view = memoryview(content)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short oracle log write")
            view = view[written:]
        os.fsync(descriptor)
        os.chmod(path, PRIVATE_FILE_MODE)
    except OracleError:
        raise
    except OSError as error:
        raise OracleError(f"Could not safely write oracle log: {path.name}") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _relative_log_path(path: Path, run_root: Path) -> str:
    try:
        return path.relative_to(run_root).as_posix()
    except ValueError as error:
        raise OracleError("Oracle log path escapes the run evidence directory") from error
