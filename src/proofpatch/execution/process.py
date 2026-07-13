"""Shell-free process execution with concurrent draining, limits, and tree termination."""

import os
import re
import signal
import subprocess
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from threading import Thread
from typing import IO, BinaryIO, Final, cast

from proofpatch.errors import ConfigurationError, ExecutionError
from proofpatch.execution.output import OutputBudget
from proofpatch.execution.timeout import CancellationToken, Deadline
from proofpatch.models.execution import TerminationKind
from proofpatch.security.secrets import SecretRedactor

ENVIRONMENT_NAME: Final = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
READ_SIZE: Final = 64 * 1024
POLL_SECONDS: Final = 0.05
TERMINATION_GRACE_SECONDS: Final = 2.0
MAX_STDIN_BYTES: Final = 1024 * 1024


@dataclass(frozen=True, slots=True)
class ProcessRequest:
    """Validated input to one controlled native process."""

    argv: tuple[str, ...]
    cwd: Path
    timeout_seconds: float
    maximum_output_bytes: int
    environment: Mapping[str, str]
    stdin_text: str | None = None
    secret_values: tuple[str, ...] = ()
    cancellation: CancellationToken | None = None

    def __post_init__(self) -> None:
        if not self.argv or any(not item or "\0" in item for item in self.argv):
            raise ConfigurationError("Process argv must contain nonempty NUL-free arguments")
        if self.timeout_seconds <= 0:
            raise ConfigurationError("Process timeout must be positive")
        if self.maximum_output_bytes <= 0:
            raise ConfigurationError("Process output limit must be positive")
        if any(ENVIRONMENT_NAME.fullmatch(name) is None for name in self.environment):
            raise ConfigurationError("Process environment contains an invalid variable name")
        if any("\0" in item for pair in self.environment.items() for item in pair):
            raise ConfigurationError("Process environment must be NUL-free")
        if len(self.environment) > 128:
            raise ConfigurationError("Process environment has too many entries")
        if (
            sum(len(item.encode("utf-8")) for pair in self.environment.items() for item in pair)
            > 256 * 1024
        ):
            raise ConfigurationError("Process environment exceeds the safety limit")
        if self.stdin_text is not None:
            try:
                encoded = self.stdin_text.encode("utf-8")
            except UnicodeEncodeError as error:
                raise ConfigurationError("Process stdin must be valid Unicode text") from error
            if len(encoded) > MAX_STDIN_BYTES:
                raise ConfigurationError("Process stdin exceeds the safety limit")


@dataclass(frozen=True, slots=True)
class ProcessOutcome:
    """In-memory redacted result; raw output never leaves the runner."""

    termination: TerminationKind
    exit_code: int | None
    signal: int | None
    duration_ms: int
    timed_out: bool
    cancelled: bool
    stdout: bytes
    stderr: bytes
    truncated: bool


class ProcessRunner:
    """Run native commands without a shell while bounding and draining both output streams."""

    def run(self, request: ProcessRequest) -> ProcessOutcome:
        redactor = SecretRedactor.from_values(list(request.secret_values))
        for argument in request.argv:
            if redactor.contains_secret(argument):
                raise ConfigurationError("A configured secret value appears in process argv")
        try:
            cwd = request.cwd.resolve(strict=True)
        except OSError as error:
            raise ExecutionError(
                f"Process working directory does not exist: {request.cwd}"
            ) from error
        if not cwd.is_dir():
            raise ExecutionError(f"Process working directory is not a directory: {request.cwd}")

        environment = _controlled_environment(request.environment)
        stdin_bytes = request.stdin_text.encode("utf-8") if request.stdin_text is not None else None
        creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) if os.name == "nt" else 0
        start = time.monotonic()
        try:
            process = subprocess.Popen(  # noqa: S603 - validated argv and shell=False
                list(request.argv),
                cwd=cwd,
                env=environment,
                stdin=subprocess.PIPE if stdin_bytes is not None else subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                creationflags=creationflags,
                start_new_session=os.name != "nt",
                close_fds=True,
            )
        except OSError as error:
            raise ExecutionError(
                f"Could not start controlled process: {request.argv[0]}"
            ) from error
        if process.stdout is None or process.stderr is None:
            _force_kill_process_tree(process)
            raise ExecutionError("Controlled process did not expose output pipes")

        budget = OutputBudget(request.maximum_output_bytes)
        stdout_chunks: list[bytes] = []
        stderr_chunks: list[bytes] = []
        reader_errors: list[BaseException] = []
        readers = (
            Thread(
                target=_drain_pipe,
                args=(process.stdout, stdout_chunks, budget, reader_errors),
                daemon=True,
            ),
            Thread(
                target=_drain_pipe,
                args=(process.stderr, stderr_chunks, budget, reader_errors),
                daemon=True,
            ),
        )
        for reader in readers:
            reader.start()
        writer = _start_stdin_writer(process.stdin, stdin_bytes, reader_errors)

        deadline = Deadline.after(request.timeout_seconds)
        timed_out = False
        cancelled = False
        try:
            while process.poll() is None:
                if request.cancellation is not None and request.cancellation.cancelled:
                    cancelled = True
                    _terminate_process_tree(process)
                    break
                if deadline.expired:
                    timed_out = True
                    _terminate_process_tree(process)
                    break
                try:
                    process.wait(timeout=min(POLL_SECONDS, deadline.remaining))
                except subprocess.TimeoutExpired:
                    continue
            if timed_out or cancelled:
                try:
                    process.wait(timeout=TERMINATION_GRACE_SECONDS)
                except subprocess.TimeoutExpired:
                    _force_kill_process_tree(process)
                    process.wait()
            else:
                process.wait()
        finally:
            if process.poll() is None:
                _force_kill_process_tree(process)
                process.wait()
            if writer is not None:
                writer.join(timeout=TERMINATION_GRACE_SECONDS)
            for reader in readers:
                reader.join(timeout=TERMINATION_GRACE_SECONDS)
            process.stdout.close()
            process.stderr.close()
            if process.stdin is not None:
                process.stdin.close()

        if any(reader.is_alive() for reader in readers) or (
            writer is not None and writer.is_alive()
        ):
            raise ExecutionError("Controlled process pipe threads did not terminate")
        if reader_errors:
            raise ExecutionError("Controlled process pipe handling failed") from reader_errors[0]

        stdout = redactor.redact(b"".join(stdout_chunks))
        stderr = redactor.redact(b"".join(stderr_chunks))
        stdout, stderr, redaction_truncated = _limit_redacted_output(
            stdout,
            stderr,
            request.maximum_output_bytes,
        )
        duration_ms = max(0, round((time.monotonic() - start) * 1000))
        return_code = process.returncode
        signal_number = -return_code if return_code is not None and return_code < 0 else None
        if timed_out:
            termination = TerminationKind.TIMEOUT
            exit_code = None
        elif cancelled:
            termination = TerminationKind.CANCELLED
            exit_code = None
        elif signal_number is not None:
            termination = TerminationKind.SIGNAL
            exit_code = return_code
        else:
            termination = TerminationKind.EXITED
            exit_code = return_code
        return ProcessOutcome(
            termination=termination,
            exit_code=exit_code,
            signal=signal_number,
            duration_ms=duration_ms,
            timed_out=timed_out,
            cancelled=cancelled,
            stdout=stdout,
            stderr=stderr,
            truncated=budget.truncated or redaction_truncated,
        )


def _controlled_environment(values: Mapping[str, str]) -> dict[str, str]:
    allowed_host_names = (
        "PATH",
        "PATHEXT",
        "SYSTEMROOT",
        "WINDIR",
        "COMSPEC",
        "TEMP",
        "TMP",
        "LANG",
        "LC_ALL",
    )
    environment = {name: os.environ[name] for name in allowed_host_names if name in os.environ}
    environment.update(values)
    environment["PYTHONUNBUFFERED"] = "1"
    return environment


def _drain_pipe(
    pipe: BinaryIO,
    chunks: list[bytes],
    budget: OutputBudget,
    errors: list[BaseException],
) -> None:
    try:
        while data := pipe.read(READ_SIZE):
            retained = budget.retain(data)
            if retained:
                chunks.append(retained)
    except BaseException as error:
        errors.append(error)


def _start_stdin_writer(
    pipe: IO[bytes] | None,
    data: bytes | None,
    errors: list[BaseException],
) -> Thread | None:
    if pipe is None or data is None:
        return None

    def write() -> None:
        try:
            pipe.write(data)
            pipe.flush()
        except BrokenPipeError:
            pass
        except BaseException as error:
            errors.append(error)
        finally:
            pipe.close()

    writer = Thread(target=write, daemon=True)
    writer.start()
    return writer


def _limit_redacted_output(stdout: bytes, stderr: bytes, maximum: int) -> tuple[bytes, bytes, bool]:
    if len(stdout) + len(stderr) <= maximum:
        return stdout, stderr, False
    stdout_length = min(len(stdout), maximum)
    retained_stdout = stdout[:stdout_length]
    retained_stderr = stderr[: maximum - stdout_length]
    return retained_stdout, retained_stderr, True


def _terminate_process_tree(process: subprocess.Popen[bytes]) -> None:
    try:
        if os.name == "nt":
            _taskkill_process_tree(process, force=False)
            if process.poll() is None:
                process.terminate()
        else:
            _kill_process_group(process.pid, signal.SIGTERM)
    except (OSError, ProcessLookupError):
        pass


def _force_kill_process_tree(process: subprocess.Popen[bytes]) -> None:
    try:
        if os.name == "nt":
            _taskkill_process_tree(process, force=True)
            if process.poll() is None:
                process.kill()
        else:
            _kill_process_group(process.pid, getattr(signal, "SIGKILL", signal.SIGTERM))
    except (OSError, ProcessLookupError, subprocess.TimeoutExpired):
        if process.poll() is None:
            process.kill()


def _kill_process_group(pid: int, selected_signal: int) -> None:
    killpg = cast(Callable[[int, int], None], os.killpg)  # type: ignore[attr-defined]
    killpg(pid, selected_signal)


def _taskkill_process_tree(process: subprocess.Popen[bytes], *, force: bool) -> None:
    taskkill = Path(os.environ.get("SYSTEMROOT", r"C:\Windows")) / "System32" / "taskkill.exe"
    argv = [str(taskkill), "/PID", str(process.pid), "/T"]
    if force:
        argv.append("/F")
    subprocess.run(  # noqa: S603 - fixed Windows system utility, shell=False
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
        shell=False,
        timeout=TERMINATION_GRACE_SECONDS,
    )
