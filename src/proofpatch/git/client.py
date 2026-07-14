"""A narrow Git CLI wrapper that never invokes a command shell."""

import os
import shutil
import signal
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from threading import Thread
from typing import BinaryIO, Final

from proofpatch.errors import RepositoryError

DEFAULT_TIMEOUT_SECONDS: Final = 120.0
MAX_CAPTURED_OUTPUT: Final = 16 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class GitResult:
    """Exact result of one Git invocation."""

    argv: tuple[str, ...]
    returncode: int
    stdout: bytes
    stderr: bytes


class GitCommandError(RepositoryError):
    """A controlled Git command returned a nonzero status."""

    error_code = "PP_GIT_COMMAND_FAILED"

    def __init__(self, operation: str, result: GitResult) -> None:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        if len(detail) > 2000:
            detail = f"{detail[:2000]}…"
        message = f"Git {operation} failed with exit code {result.returncode}"
        if detail:
            message = f"{message}: {detail}"
        super().__init__(message)
        self.result = result


class GitClient:
    """Execute Git with argument arrays and a sanitized ambient Git environment."""

    def __init__(self, executable: str | None = None) -> None:
        selected = shutil.which("git") if executable is None else executable
        if selected is None:
            raise RepositoryError(
                "Git is not installed or is not available on PATH",
                remediation="Install Git and make the git executable available on PATH.",
            )
        self.executable = selected

    def run(
        self,
        args: tuple[str, ...] | list[str],
        *,
        cwd: Path | None = None,
        check: bool = True,
        operation: str = "command",
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        stdin: BinaryIO | None = None,
    ) -> GitResult:
        """Run Git without a shell and capture bounded diagnostic output."""

        argv = self._argv(args)
        result = self._execute_bounded(
            argv,
            cwd=cwd,
            operation=operation,
            timeout=timeout,
            stdin=stdin,
        )
        if check and result.returncode != 0:
            raise GitCommandError(operation, result)
        return result

    def run_to_file(
        self,
        args: tuple[str, ...] | list[str],
        output: BinaryIO,
        *,
        cwd: Path,
        operation: str,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        maximum_output_bytes: int = MAX_CAPTURED_OUTPUT,
    ) -> GitResult:
        """Stream stdout directly to an already safely opened artifact file."""

        argv = self._argv(args)
        result = self._execute_bounded(
            argv,
            cwd=cwd,
            operation=operation,
            timeout=timeout,
            stdout_target=output,
            maximum_output_bytes=maximum_output_bytes,
        )
        if result.returncode != 0:
            raise GitCommandError(operation, result)
        return result

    def text(self, args: tuple[str, ...] | list[str], *, cwd: Path, operation: str) -> str:
        """Return one UTF-8 textual Git result without its trailing line break."""

        raw = self.run(args, cwd=cwd, operation=operation).stdout
        try:
            return raw.decode("utf-8").rstrip("\r\n")
        except UnicodeDecodeError as error:
            raise RepositoryError(f"Git {operation} returned non-UTF-8 metadata") from error

    def _argv(self, args: tuple[str, ...] | list[str]) -> list[str]:
        if not args or any(not isinstance(value, str) or "\0" in value for value in args):
            raise RepositoryError("Git arguments must be nonempty NUL-free strings")
        return [
            self.executable,
            "--no-pager",
            "--no-optional-locks",
            "-c",
            "core.hooksPath=",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.longpaths=true",
            *args,
        ]

    @staticmethod
    def _environment() -> dict[str, str]:
        allowed = (
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
        environment = {key: os.environ[key] for key in allowed if key in os.environ}
        environment.update(
            {
                "GIT_ATTR_NOSYSTEM": "1",
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_GLOBAL": os.devnull,
                "GIT_OPTIONAL_LOCKS": "0",
                "GIT_PAGER": "cat",
                "GIT_TERMINAL_PROMPT": "0",
                "PAGER": "cat",
            }
        )
        return environment

    def _execute_bounded(
        self,
        argv: list[str],
        *,
        cwd: Path | None,
        operation: str,
        timeout: float,
        stdin: BinaryIO | None = None,
        stdout_target: BinaryIO | None = None,
        maximum_output_bytes: int = MAX_CAPTURED_OUTPUT,
    ) -> GitResult:
        if timeout <= 0 or maximum_output_bytes <= 0:
            raise RepositoryError("Git execution limits must be positive")
        creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) if os.name == "nt" else 0
        try:
            process = subprocess.Popen(  # noqa: S603 - fixed executable and shell=False
                argv,
                cwd=cwd,
                env=self._environment(),
                stdin=stdin if stdin is not None else subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                creationflags=creationflags,
                start_new_session=os.name != "nt",
                close_fds=True,
            )
        except OSError as error:
            raise RepositoryError(f"Could not execute Git {operation} safely") from error
        if process.stdout is None or process.stderr is None:
            _kill_git_process(process)
            raise RepositoryError(f"Could not capture Git {operation} output safely")

        stdout = bytearray()
        stderr = bytearray()
        stdout_size = [0]
        stderr_size = [0]
        overflow: list[bool] = []
        errors: list[BaseException] = []
        readers = (
            Thread(
                target=_drain_git_pipe,
                args=(
                    process.stdout,
                    stdout,
                    stdout_size,
                    maximum_output_bytes,
                    overflow,
                    errors,
                    stdout_target,
                ),
                daemon=True,
            ),
            Thread(
                target=_drain_git_pipe,
                args=(
                    process.stderr,
                    stderr,
                    stderr_size,
                    maximum_output_bytes,
                    overflow,
                    errors,
                    None,
                ),
                daemon=True,
            ),
        )
        for reader in readers:
            reader.start()
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired as error:
            _kill_git_process(process)
            process.wait()
            raise RepositoryError(f"Could not execute Git {operation} safely") from error
        finally:
            for reader in readers:
                reader.join(timeout=2.0)
            process.stdout.close()
            process.stderr.close()
        if any(reader.is_alive() for reader in readers):
            _kill_git_process(process)
            raise RepositoryError(f"Git {operation} output pipes did not terminate")
        if errors:
            raise RepositoryError(f"Could not capture Git {operation} output safely") from errors[0]
        if overflow:
            raise RepositoryError(f"Git {operation} output exceeded the safety limit")
        return GitResult(
            tuple(argv),
            process.returncode,
            b"" if stdout_target is not None else bytes(stdout),
            bytes(stderr),
        )


def _drain_git_pipe(
    pipe: BinaryIO,
    captured: bytearray,
    captured_size: list[int],
    maximum: int,
    overflow: list[bool],
    errors: list[BaseException],
    target: BinaryIO | None,
) -> None:
    try:
        while chunk := pipe.read(64 * 1024):
            remaining = maximum - captured_size[0]
            retained = chunk[: max(0, remaining)]
            if target is not None:
                view = memoryview(retained)
                while view:
                    written = target.write(view)
                    if written is None or written <= 0:
                        raise OSError("short Git output write")
                    view = view[written:]
            else:
                captured.extend(retained)
            captured_size[0] += len(retained)
            if len(chunk) > len(retained):
                overflow.append(True)
    except BaseException as error:
        errors.append(error)


def _kill_git_process(process: subprocess.Popen[bytes]) -> None:
    try:
        if sys.platform == "win32":
            taskkill = (
                Path(os.environ.get("SYSTEMROOT", r"C:\Windows")) / "System32" / "taskkill.exe"
            )
            subprocess.run(  # noqa: S603 - fixed Windows system utility, shell=False
                [str(taskkill), "/PID", str(process.pid), "/T", "/F"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
                shell=False,
                timeout=2.0,
            )
            if process.poll() is None:
                process.kill()
        else:
            os.killpg(process.pid, getattr(signal, "SIGKILL", signal.SIGTERM))
    except (OSError, ProcessLookupError, subprocess.TimeoutExpired):
        if process.poll() is None:
            process.kill()
