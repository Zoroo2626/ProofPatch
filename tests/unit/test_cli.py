"""Tests for the Phase 0 Typer application."""

from collections.abc import Callable

import pytest
from typer.testing import CliRunner

from proofpatch import __version__
from proofpatch.cli import _run_application, app
from proofpatch.constants import DISPLAY_NAME
from proofpatch.errors import ProofPatchError, UserInputError
from proofpatch.exit_codes import ExitCode

runner = CliRunner()


def test_help_succeeds() -> None:
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == ExitCode.SUCCESS
    assert "Independently verify" in result.output
    assert "version" in result.output


def test_version_flag_succeeds() -> None:
    result = runner.invoke(app, ["--version"])

    assert result.exit_code == ExitCode.SUCCESS
    assert result.output.strip() == f"{DISPLAY_NAME} {__version__}"


def test_version_command_succeeds() -> None:
    result = runner.invoke(app, ["version"])

    assert result.exit_code == ExitCode.SUCCESS
    assert result.output.strip() == f"{DISPLAY_NAME} {__version__}"


def test_unknown_command_is_a_user_error() -> None:
    result = runner.invoke(app, ["does-not-exist"])

    assert result.exit_code == ExitCode.INVALID_COMMAND_OR_CONFIGURATION
    assert "No such command" in result.output


@pytest.mark.parametrize(
    ("error_factory", "expected_remediation"),
    [
        (lambda: UserInputError("Bad input"), None),
        (lambda: UserInputError("Bad input", remediation="Use a safe value"), "Use a safe value"),
    ],
)
def test_typed_errors_use_stable_exit_codes_without_tracebacks(
    error_factory: Callable[[], ProofPatchError],
    expected_remediation: str | None,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def failing_application() -> None:
        raise error_factory()

    with pytest.raises(SystemExit) as raised:
        _run_application(failing_application)

    captured = capsys.readouterr()
    assert raised.value.code == ExitCode.INVALID_COMMAND_OR_CONFIGURATION
    assert captured.out == ""
    assert "Error [PP_USER_INPUT_INVALID]: Bad input" in captured.err
    assert "Traceback" not in captured.err
    if expected_remediation is None:
        assert "Remediation:" not in captured.err
    else:
        assert f"Remediation: {expected_remediation}" in captured.err


def test_unexpected_errors_are_not_misclassified() -> None:
    def failing_application() -> None:
        raise RuntimeError("unexpected")

    with pytest.raises(RuntimeError, match="unexpected"):
        _run_application(failing_application)
