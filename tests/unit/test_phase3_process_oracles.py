"""Unit and component tests for bounded execution, redaction, and oracle evaluation."""

import hashlib
import sys
from dataclasses import replace
from io import BytesIO
from pathlib import Path
from threading import Thread
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

import proofpatch.cli as cli
from proofpatch.errors import ConfigurationError, ExecutionError, OracleError
from proofpatch.execution.output import OutputBudget
from proofpatch.execution.process import (
    ProcessOutcome,
    ProcessRequest,
    ProcessRunner,
    _drain_pipe,
    _limit_redacted_output,
    _start_stdin_writer,
)
from proofpatch.execution.timeout import CancellationToken, Deadline
from proofpatch.models.execution import (
    CommandOracleSpec,
    ExitCodeMatcherSpec,
    ExitCodeOperator,
    OracleExpectation,
    OraclePhase,
    TerminationKind,
    TextMatcherSpec,
    TextOperator,
)
from proofpatch.oracles.base import OracleExecutionContext, OracleExecutionResult
from proofpatch.oracles.command import CommandOracle, _relative_log_path
from proofpatch.oracles.matchers import (
    MAX_REGEX_PATTERN_LENGTH,
    evaluate_exit_code,
    evaluate_text,
    validate_text_matcher,
)
from proofpatch.oracles.registry import OracleRegistry
from proofpatch.security.secrets import REDACTION_MARKER, SecretRedactor
from proofpatch.services.verification import VerificationPlan, _reject_secret_in_persisted_value


def _request(tmp_path: Path, code: str, **changes: object) -> ProcessRequest:
    values: dict[str, object] = {
        "argv": (sys.executable, "-c", code),
        "cwd": tmp_path,
        "timeout_seconds": 5.0,
        "maximum_output_bytes": 1024 * 1024,
        "environment": {},
    }
    values.update(changes)
    return ProcessRequest(**values)  # type: ignore[arg-type]


def _expectation(code: int = 0) -> OracleExpectation:
    return OracleExpectation(
        exit_code=ExitCodeMatcherSpec(operator=ExitCodeOperator.EQUAL, value=code)
    )


def test_process_runner_preserves_exit_output_stdin_and_redacts_secrets(tmp_path: Path) -> None:
    outcome = ProcessRunner().run(
        _request(
            tmp_path,
            (
                "import os,sys; data=sys.stdin.read(); print(data); "
                "print(os.environ['TOKEN'], file=sys.stderr); sys.exit(7)"
            ),
            stdin_text="hello",
            secret_values=("token-value",),
            environment={"TOKEN": "token-value"},
        )
    )
    assert outcome.termination is TerminationKind.EXITED
    assert outcome.exit_code == 7
    assert outcome.stdout == b"hello\r\n" or outcome.stdout == b"hello\n"
    assert REDACTION_MARKER in outcome.stderr
    assert b"token-value" not in outcome.stderr
    assert not outcome.truncated


def test_process_runner_timeout_is_distinct_and_kills_child(tmp_path: Path) -> None:
    outcome = ProcessRunner().run(
        _request(
            tmp_path,
            "import time; print('started', flush=True); time.sleep(30)",
            timeout_seconds=0.1,
        )
    )
    assert outcome.termination is TerminationKind.TIMEOUT
    assert outcome.timed_out
    assert outcome.exit_code is None
    assert b"started" in outcome.stdout


def test_process_runner_cancellation_is_distinct(tmp_path: Path) -> None:
    token = CancellationToken()
    token.cancel()
    outcome = ProcessRunner().run(
        _request(
            tmp_path,
            "import time; time.sleep(30)",
            cancellation=token,
        )
    )
    assert outcome.termination is TerminationKind.CANCELLED
    assert outcome.cancelled
    assert not outcome.timed_out
    assert outcome.exit_code is None


def test_output_limit_drains_both_streams_without_deadlock(tmp_path: Path) -> None:
    code = (
        "import sys; "
        "sys.stdout.write('o'*2000000); sys.stdout.flush(); "
        "sys.stderr.write('e'*2000000); sys.stderr.flush()"
    )
    outcome = ProcessRunner().run(_request(tmp_path, code, maximum_output_bytes=4096))
    assert outcome.exit_code == 0
    assert outcome.truncated
    assert len(outcome.stdout) + len(outcome.stderr) <= 4096


def test_process_request_and_secret_argument_validation(tmp_path: Path) -> None:
    for changes in (
        {"argv": ()},
        {"timeout_seconds": 0.0},
        {"maximum_output_bytes": 0},
        {"environment": {"BAD-NAME": "x"}},
        {"environment": {"OK": "bad\0value"}},
        {"stdin_text": "x" * (1024 * 1024 + 1)},
    ):
        with pytest.raises(ConfigurationError):
            _request(tmp_path, "pass", **changes)
    with pytest.raises(ConfigurationError, match="secret value appears"):
        ProcessRunner().run(
            _request(
                tmp_path,
                "pass",
                argv=(sys.executable, "token-value"),
                secret_values=("token-value",),
            )
        )


def test_output_budget_deadline_cancellation_and_redactor_helpers() -> None:
    budget = OutputBudget(3)
    assert budget.retain(b"ab") == b"ab"
    assert budget.retain(b"cd") == b"c"
    assert budget.truncated
    with pytest.raises(ValueError):
        OutputBudget(0)

    times = iter((10.0, 10.5, 12.0))
    deadline = Deadline.after(1.0, clock=lambda: next(times))
    assert deadline.remaining == 0.5
    assert deadline.expired
    with pytest.raises(ValueError):
        Deadline.after(0)

    token = CancellationToken()
    Thread(target=token.cancel).start()
    token._event.wait(1)
    assert token.cancelled

    redactor = SecretRedactor.from_values(["short", "shorter"])
    assert redactor.redact(b"shorter short") == REDACTION_MARKER + b" " + REDACTION_MARKER
    assert redactor.contains_secret("a-short-value")
    with pytest.raises(ConfigurationError):
        SecretRedactor.from_values([""])


def test_matchers_cover_exit_substring_regex_and_timeout() -> None:
    equal = ExitCodeMatcherSpec(operator=ExitCodeOperator.EQUAL, value=0)
    different = ExitCodeMatcherSpec(operator=ExitCodeOperator.NOT_EQUAL, value=0)
    assert evaluate_exit_code(equal, 0).passed
    assert evaluate_exit_code(different, 2).passed
    assert not evaluate_exit_code(equal, None).passed

    contains = TextMatcherSpec(operator=TextOperator.CONTAINS, value="hello")
    absent = TextMatcherSpec(operator=TextOperator.NOT_CONTAINS, value="FAILED")
    pattern = TextMatcherSpec(operator=TextOperator.REGEX, value=r"^hello$", multiline=True)
    negative = TextMatcherSpec(operator=TextOperator.NOT_REGEX, value="failure")
    assert evaluate_text("stdout", contains, b"hello").passed
    assert evaluate_text("stdout", absent, b"hello").passed
    assert evaluate_text("stderr", pattern, b"other\nhello\n").passed
    assert evaluate_text("stderr", negative, b"ok").passed
    with patch("proofpatch.oracles.matchers.regex.search", side_effect=TimeoutError):
        assert not evaluate_text("stdout", pattern, b"hello").passed
    with pytest.raises(ValueError):
        evaluate_text("other", contains, b"hello")
    with pytest.raises(OracleError, match="invalid"):
        validate_text_matcher(TextMatcherSpec(operator=TextOperator.REGEX, value="("))
    with pytest.raises(OracleError, match="length"):
        validate_text_matcher(
            TextMatcherSpec(operator=TextOperator.REGEX, value="x" * (MAX_REGEX_PATTERN_LENGTH + 1))
        )


def test_command_oracle_executes_logs_and_evaluates_without_agent_claims(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    run_root = tmp_path / "run"
    run_root.mkdir()
    spec = CommandOracleSpec(
        id="probe",
        argv=(sys.executable, "-c", "print('expected output')"),
        timeout_seconds=5,
        expectation=OracleExpectation(
            exit_code=ExitCodeMatcherSpec(operator=ExitCodeOperator.EQUAL, value=0),
            stdout=(TextMatcherSpec(operator=TextOperator.CONTAINS, value="expected"),),
        ),
    )
    oracle = CommandOracle()
    execution = oracle.execute(
        spec,
        OracleExecutionContext(
            workspace=workspace,
            run_root=run_root,
            log_directory=run_root / "oracle",
            runner=ProcessRunner(),
            maximum_output_bytes=1024,
            secret_environment={},
        ),
    )
    evaluation = oracle.evaluate(spec, OraclePhase.REGRESSION, execution)
    assert evaluation.passed
    assert evaluation.process.stdout_sha256 == hashlib.sha256(execution.outcome.stdout).hexdigest()
    assert (run_root / evaluation.process.stdout_path).read_bytes() == execution.outcome.stdout


def test_oracle_validation_models_and_registry_fail_closed() -> None:
    with pytest.raises(ValidationError):
        CommandOracleSpec(
            id="bad",
            argv=("python",),
            cwd="../escape",
            timeout_seconds=1,
            expectation=_expectation(),
        )
    with pytest.raises(ValidationError, match="demonstrate a transition"):
        CommandOracleSpec(
            id="same",
            argv=("python",),
            timeout_seconds=1,
            baseline_expectation=_expectation(),
            fixed_expectation=_expectation(),
        )
    assert OracleRegistry().get("command").type_name == "command"
    with pytest.raises(OracleError, match="Unsupported"):
        OracleRegistry().get("unknown")


def test_verify_patch_cli_builds_structured_oracles_and_reports_observation_only(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    candidate = tmp_path / "candidate.diff"
    candidate.write_text("patch", encoding="utf-8")
    receipt_path = tmp_path / "receipt.json"

    class FakeVerificationService:
        def verify_patch(
            self,
            selected_repository: Path,
            selected_patch: Path,
            plan: VerificationPlan,
            *,
            issue_summary: str,
        ) -> SimpleNamespace:
            assert selected_repository == repository
            assert selected_patch == candidate
            assert issue_summary == "Observed calculator behavior"
            assert plan.reproduction.argv == (sys.executable, "reproduce.py")
            assert len(plan.regressions) == 1
            return SimpleNamespace(
                verified=True,
                json_path=receipt_path,
                receipt=SimpleNamespace(rejection_code=None),
            )

    monkeypatch.setattr(cli, "_verification_service", FakeVerificationService)
    command = f'"{sys.executable}" reproduce.py'
    result = CliRunner().invoke(
        cli.app,
        [
            "verify-patch",
            "--baseline-command",
            command,
            "--patch-file",
            str(candidate),
            "--repository",
            str(repository),
            "--regression-command",
            command.replace("reproduce", "regression"),
            "--timeout-seconds",
            "2",
            "--output-mb",
            "1",
            "--issue-summary",
            "Observed calculator behavior",
        ],
    )
    assert result.exit_code == 0
    assert "OBSERVATION ONLY" in result.output
    assert "baseline failure -> patched success" in result.output
    with pytest.raises(ConfigurationError, match="empty"):
        cli._parse_command("")
    with pytest.raises(ConfigurationError, match="parsed"):
        cli._parse_command('"unterminated')


def test_additional_process_validation_and_start_failures(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError, match="too many"):
        _request(tmp_path, "pass", environment={f"KEY_{index}": "x" for index in range(129)})
    with pytest.raises(ConfigurationError, match="environment exceeds"):
        _request(tmp_path, "pass", environment={"VALUE": "x" * (256 * 1024 + 1)})
    with pytest.raises(ConfigurationError, match="valid Unicode"):
        _request(tmp_path, "pass", stdin_text="\ud800")
    with pytest.raises(ExecutionError, match="does not exist"):
        ProcessRunner().run(_request(tmp_path / "missing", "pass"))
    file_cwd = tmp_path / "file"
    file_cwd.write_text("x", encoding="utf-8")
    with pytest.raises(ExecutionError, match="not a directory"):
        ProcessRunner().run(_request(file_cwd, "pass"))
    with pytest.raises(ExecutionError, match="Could not start"):
        ProcessRunner().run(_request(tmp_path, "pass", argv=(str(tmp_path / "missing.exe"),)))


def test_secrets_cannot_enter_persisted_verification_inputs() -> None:
    redactor = SecretRedactor.from_values(["private-value"])
    _reject_secret_in_persisted_value({"safe": ["public"]}, redactor)
    with pytest.raises(ConfigurationError, match="persisted verification"):
        _reject_secret_in_persisted_value(
            {"oracle": {"argv": ["tool", "private-value"]}},
            redactor,
        )


def test_pipe_helpers_fail_closed_and_bound_redaction_expansion() -> None:
    class BrokenReader:
        def read(self, _size: int) -> bytes:
            raise OSError("read failed")

    errors: list[BaseException] = []
    _drain_pipe(BrokenReader(), [], OutputBudget(10), errors)  # type: ignore[arg-type]
    assert isinstance(errors[0], OSError)
    assert _start_stdin_writer(None, b"data", errors) is None
    assert _start_stdin_writer(BytesIO(), None, errors) is None
    stdout, stderr, truncated = _limit_redacted_output(b"abcdef", b"gh", 5)
    assert (stdout, stderr, truncated) == (b"abcde", b"", True)


def test_oracle_models_cover_all_validation_branches() -> None:
    base = {
        "id": "validation",
        "argv": ("python",),
        "timeout_seconds": 1,
        "expectation": _expectation(),
    }
    invalid_updates = (
        {"argv": ("bad\0argument",)},
        {"cwd": "dir\\child"},
        {"environment": {f"KEY_{index}": "x" for index in range(129)}},
        {"environment": {"BAD-NAME": "x"}},
        {"environment": {"OK": "bad\0value"}},
        {"environment": {"OK": "x" * (256 * 1024 + 1)}},
        {"expectation": None},
        {
            "expectation": _expectation(),
            "baseline_expectation": _expectation(1),
        },
    )
    for update in invalid_updates:
        with pytest.raises(ValidationError):
            CommandOracleSpec(**(base | update))  # type: ignore[arg-type]


def test_oracle_evaluation_failure_classification_and_context_guards(tmp_path: Path) -> None:
    spec = CommandOracleSpec(
        id="classification",
        argv=(sys.executable, "-c", "pass"),
        timeout_seconds=1,
        expectation=_expectation(),
    )
    base_outcome = ProcessOutcome(
        termination=TerminationKind.EXITED,
        exit_code=1,
        signal=None,
        duration_ms=1,
        timed_out=False,
        cancelled=False,
        stdout=b"",
        stderr=b"",
        truncated=False,
    )

    def execution(outcome: ProcessOutcome) -> OracleExecutionResult:
        return OracleExecutionResult(outcome, "stdout.log", "0" * 64, "stderr.log", "0" * 64)

    oracle = CommandOracle()
    assert oracle.evaluate(spec, OraclePhase.REGRESSION, execution(base_outcome)).failure_code == (
        "PP_ORACLE_EXPECTATION_FAILED"
    )
    timed_out = replace(base_outcome, timed_out=True, termination=TerminationKind.TIMEOUT)
    assert oracle.evaluate(spec, OraclePhase.REGRESSION, execution(timed_out)).failure_code == (
        "PP_VERIFICATION_TIMEOUT"
    )
    cancelled = replace(base_outcome, cancelled=True, termination=TerminationKind.CANCELLED)
    assert oracle.evaluate(spec, OraclePhase.REGRESSION, execution(cancelled)).failure_code == (
        "PP_VERIFICATION_CANCELLED"
    )
    truncated = replace(base_outcome, truncated=True)
    assert oracle.evaluate(spec, OraclePhase.REGRESSION, execution(truncated)).failure_code == (
        "PP_ORACLE_OUTPUT_TRUNCATED"
    )
    invalid = spec.model_copy(update={"expectation": None})
    with pytest.raises(OracleError, match="no expectation"):
        oracle.evaluate(invalid, OraclePhase.REGRESSION, execution(base_outcome))

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    file_cwd = workspace / "file"
    file_cwd.write_text("x", encoding="utf-8")
    invalid_cwd = spec.model_copy(update={"cwd": "file"})
    context = OracleExecutionContext(
        workspace,
        tmp_path,
        tmp_path / "logs",
        ProcessRunner(),
        1024,
        {},
    )
    with pytest.raises(OracleError, match="not a directory"):
        oracle.execute(invalid_cwd, context)
    overlap = spec.model_copy(update={"environment": {"TOKEN": "public"}})
    secret_context = replace(context, secret_environment={"TOKEN": "private"})
    with pytest.raises(OracleError, match="overrides secret"):
        oracle.execute(overlap, secret_context)
    with pytest.raises(OracleError, match="escapes"):
        _relative_log_path(tmp_path / "outside.log", workspace)
