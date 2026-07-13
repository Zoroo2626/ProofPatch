"""Deterministic exit-code, substring, and bounded-regex oracle matchers."""

from typing import Final

import regex

from proofpatch.errors import OracleError
from proofpatch.models.execution import (
    ExitCodeMatcherSpec,
    ExitCodeOperator,
    MatcherResult,
    TextMatcherSpec,
    TextOperator,
)

MAX_REGEX_PATTERN_LENGTH: Final = 1024
MAX_REGEX_INPUT_CHARACTERS: Final = 1024 * 1024
REGEX_TIMEOUT_SECONDS: Final = 0.1


def evaluate_exit_code(spec: ExitCodeMatcherSpec, actual: int | None) -> MatcherResult:
    """Evaluate an exact integer exit-code predicate."""

    if actual is None:
        passed = False
    elif spec.operator is ExitCodeOperator.EQUAL:
        passed = actual == spec.value
    else:
        passed = actual != spec.value
    return MatcherResult(
        field="exit_code",
        operator=spec.operator.value,
        expected=spec.value,
        actual=actual,
        passed=passed,
    )


def validate_text_matcher(spec: TextMatcherSpec) -> None:
    """Compile regex matchers up front and enforce the pattern limit."""

    if spec.operator not in {TextOperator.REGEX, TextOperator.NOT_REGEX}:
        return
    if len(spec.value) > MAX_REGEX_PATTERN_LENGTH:
        raise OracleError("Oracle regex pattern exceeds the supported length")
    try:
        regex.compile(spec.value, flags=_regex_flags(spec))
    except regex.error as error:
        raise OracleError(f"Oracle regex pattern is invalid: {error}") from error


def evaluate_text(
    field: str,
    spec: TextMatcherSpec,
    actual: bytes,
) -> MatcherResult:
    """Evaluate text with explicit UTF-8 replacement and bounded regex input/time."""

    if field not in {"stdout", "stderr"}:
        raise ValueError("text matcher field must be stdout or stderr")
    text = actual.decode("utf-8", errors="replace")
    if spec.operator is TextOperator.CONTAINS:
        matched = spec.value in text
        passed = matched
    elif spec.operator is TextOperator.NOT_CONTAINS:
        matched = spec.value in text
        passed = not matched
    else:
        validate_text_matcher(spec)
        if len(text) > MAX_REGEX_INPUT_CHARACTERS:
            return MatcherResult(
                field=field,  # type: ignore[arg-type]
                operator=spec.operator.value,
                expected=spec.value,
                actual="regex input limit exceeded",
                passed=False,
            )
        try:
            matched = (
                regex.search(
                    spec.value,
                    text,
                    flags=_regex_flags(spec),
                    timeout=REGEX_TIMEOUT_SECONDS,
                )
                is not None
            )
        except TimeoutError:
            matched = False
            passed = False
        else:
            passed = matched if spec.operator is TextOperator.REGEX else not matched
    return MatcherResult(
        field=field,  # type: ignore[arg-type]
        operator=spec.operator.value,
        expected=spec.value,
        actual="matched" if matched else "not matched",
        passed=passed,
    )


def _regex_flags(spec: TextMatcherSpec) -> int:
    flags: int = regex.VERSION1
    if spec.multiline:
        flags |= regex.MULTILINE
    return flags
