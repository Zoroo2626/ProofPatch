"""Integration tests for installed/module CLI entry points."""

import os
import subprocess
import sys
from pathlib import Path

from proofpatch import __version__
from proofpatch.exit_codes import ExitCode
from proofpatch.services.coordinator import RunCoordinator
from proofpatch.services.data_directories import DATA_DIRECTORY_ENV, ApplicationDirectories

RUN_ID = "pp_20260713_a4f92b18ce31"
REPOSITORY_ID = "repo_9c06a0e7e84b6f78"


def test_python_module_version_entrypoint() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "proofpatch", "--version"],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert result.returncode == 0
    assert result.stdout.strip() == f"ProofPatch {__version__}"
    assert result.stderr == ""


def test_phase1_commands_work_through_the_module_entrypoint(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    data = tmp_path / "data"
    RunCoordinator(ApplicationDirectories(data)).create_run(
        REPOSITORY_ID,
        repository,
        run_id=RUN_ID,
    )
    environment = {**os.environ, DATA_DIRECTORY_ENV: str(data)}

    listed = subprocess.run(
        [sys.executable, "-m", "proofpatch", "list"],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
        env=environment,
    )
    status = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "proofpatch", "status", RUN_ID],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
        env=environment,
    )
    inspected = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "proofpatch", "inspect", RUN_ID, "--events"],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
        env=environment,
    )
    invalid = subprocess.run(
        [sys.executable, "-m", "proofpatch", "status", "invalid"],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
        env=environment,
    )

    assert listed.returncode == status.returncode == inspected.returncode == ExitCode.SUCCESS
    assert RUN_ID in listed.stdout
    assert "State: CREATED" in status.stdout
    assert '"type":"run.created"' in inspected.stdout
    assert invalid.returncode == ExitCode.INVALID_COMMAND_OR_CONFIGURATION
    assert "PP_USER_INPUT_INVALID" in invalid.stderr
