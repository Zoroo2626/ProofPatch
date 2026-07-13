"""Lifecycle and CLI tests for the deterministic Phase 1 run core."""

import sqlite3
from collections.abc import Callable
from pathlib import Path

import pytest
from typer.testing import CliRunner

import proofpatch.cli as cli
from proofpatch.errors import (
    EvidenceIntegrityError,
    InternalInvariantError,
    InvalidStateTransition,
    RepositoryError,
    UserInputError,
)
from proofpatch.exit_codes import ExitCode
from proofpatch.models.run import build_run_paths
from proofpatch.models.state import RunState
from proofpatch.services.coordinator import RunCoordinator
from proofpatch.services.data_directories import DATA_DIRECTORY_ENV, ApplicationDirectories
from proofpatch.services.evidence import EvidenceWriter, write_canonical_json

RUN_ID = "pp_20260713_a4f92b18ce31"
REPOSITORY_ID = "repo_9c06a0e7e84b6f78"
OTHER_REPOSITORY_ID = "repo_bbbbbbbbbbbbbbbb"


@pytest.fixture
def coordinator(tmp_path: Path) -> tuple[RunCoordinator, Path]:
    repository = tmp_path / "repository"
    repository.mkdir()
    directories = ApplicationDirectories(tmp_path / "data")
    return RunCoordinator(directories), repository


def test_create_transition_inspect_and_list_are_evidence_backed(
    coordinator: tuple[RunCoordinator, Path],
) -> None:
    service, repository = coordinator
    created = service.create_run(REPOSITORY_ID, repository, run_id=RUN_ID)
    assert created.state is RunState.CREATED
    assert created.event_count == 1
    assert created.index_consistent

    states = (
        RunState.PREFLIGHT,
        RunState.BASELINE_PREPARING,
        RunState.BASELINE_VERIFYING,
        RunState.BASELINE_NOT_REPRODUCED,
        RunState.REJECTED,
        RunState.CLEANED,
    )
    for state in states:
        result = service.transition(RUN_ID, state, details={"test": state.value})
        assert result.state is state
        assert result.events[-1].type == "run.state_changed"
        assert result.events[-1].payload["to_state"] == state.value

    inspected = service.inspect(RUN_ID)
    assert inspected.event_count == 1 + len(states)
    assert inspected.final_event_hash == inspected.events[-1].event_hash
    assert service.list_runs() == (inspected,)


def test_invalid_transition_does_not_append_event(
    coordinator: tuple[RunCoordinator, Path],
) -> None:
    service, repository = coordinator
    service.create_run(REPOSITORY_ID, repository, run_id=RUN_ID)
    with pytest.raises(InvalidStateTransition):
        service.transition(RUN_ID, RunState.VERIFIED)
    assert service.status(RUN_ID).event_count == 1


def test_stale_or_missing_sqlite_never_overrides_evidence(
    coordinator: tuple[RunCoordinator, Path],
) -> None:
    service, repository = coordinator
    service.create_run(REPOSITORY_ID, repository, run_id=RUN_ID)
    with sqlite3.connect(service.directories.index) as connection:
        connection.execute("UPDATE runs SET state = 'ERROR' WHERE run_id = ?", (RUN_ID,))
    stale = service.status(RUN_ID)
    assert stale.state is RunState.CREATED
    assert not stale.index_consistent

    with sqlite3.connect(service.directories.index) as connection:
        connection.execute("DELETE FROM runs WHERE run_id = ?", (RUN_ID,))
    missing = service.inspect(RUN_ID)
    assert missing.state is RunState.CREATED
    assert not missing.index_consistent

    transitioned = service.transition(RUN_ID, RunState.PREFLIGHT)
    assert transitioned.index_consistent
    assert service.store.get(RUN_ID) is not None


def test_invalid_sqlite_row_cannot_block_inspection_and_is_repaired(
    coordinator: tuple[RunCoordinator, Path],
) -> None:
    service, repository = coordinator
    service.create_run(REPOSITORY_ID, repository, run_id=RUN_ID)
    with sqlite3.connect(service.directories.index) as connection:
        connection.execute("UPDATE runs SET state = 'NOT_A_STATE' WHERE run_id = ?", (RUN_ID,))

    status = service.inspect(RUN_ID)
    assert status.state is RunState.CREATED
    assert not status.index_consistent
    repaired = service.transition(RUN_ID, RunState.PREFLIGHT)
    assert repaired.index_consistent


def test_sqlite_repository_redirect_cannot_choose_authoritative_run_storage(
    coordinator: tuple[RunCoordinator, Path],
) -> None:
    service, repository = coordinator
    service.create_run(REPOSITORY_ID, repository, run_id=RUN_ID)
    with sqlite3.connect(service.directories.index) as connection:
        connection.execute(
            "UPDATE runs SET repository_id = ? WHERE run_id = ?",
            (OTHER_REPOSITORY_ID, RUN_ID),
        )
    status = service.status(RUN_ID)
    assert status.manifest.repository_id == REPOSITORY_ID
    assert not status.index_consistent


def test_non_state_event_leaves_state_unchanged_and_marks_index_stale(
    coordinator: tuple[RunCoordinator, Path],
) -> None:
    service, repository = coordinator
    service.create_run(REPOSITORY_ID, repository, run_id=RUN_ID)
    paths = build_run_paths(service.directories.data, REPOSITORY_ID, RUN_ID)
    EvidenceWriter(paths.events, paths.chain, RUN_ID).append(
        "preflight.started",
        payload={"source": "unit-test"},
    )

    status = service.status(RUN_ID)
    assert status.state is RunState.CREATED
    assert status.event_count == 2
    assert not status.index_consistent


def test_semantically_invalid_but_rehashed_state_event_is_rejected(
    coordinator: tuple[RunCoordinator, Path],
) -> None:
    service, repository = coordinator
    service.create_run(REPOSITORY_ID, repository, run_id=RUN_ID)
    paths = build_run_paths(service.directories.data, REPOSITORY_ID, RUN_ID)
    EvidenceWriter(paths.events, paths.chain, RUN_ID).append(
        "run.state_changed",
        payload={"from_state": "CREATED", "to_state": "VERIFIED"},
    )
    with pytest.raises(EvidenceIntegrityError, match="invalid state transition"):
        service.status(RUN_ID)


def test_non_controller_actor_cannot_authorize_a_state_transition(
    coordinator: tuple[RunCoordinator, Path],
) -> None:
    service, repository = coordinator
    service.create_run(REPOSITORY_ID, repository, run_id=RUN_ID)
    paths = build_run_paths(service.directories.data, REPOSITORY_ID, RUN_ID)
    EvidenceWriter(paths.events, paths.chain, RUN_ID).append(
        "run.state_changed",
        actor="agent",
        payload={"from_state": "CREATED", "to_state": "PREFLIGHT"},
    )
    with pytest.raises(EvidenceIntegrityError, match="unauthorized actor"):
        service.status(RUN_ID)


def test_manifest_identity_tampering_is_rejected(
    coordinator: tuple[RunCoordinator, Path],
) -> None:
    service, repository = coordinator
    status = service.create_run(REPOSITORY_ID, repository, run_id=RUN_ID)
    paths = build_run_paths(service.directories.data, REPOSITORY_ID, RUN_ID)
    changed = status.manifest.model_copy(update={"run_id": "pp_20260713_bbbbbbbbbbbb"})
    write_canonical_json(paths.manifest, changed.model_dump(mode="json"), exclusive=False)
    with pytest.raises(EvidenceIntegrityError, match="identifiers"):
        service.status(RUN_ID)


def test_manifest_creation_timestamp_tampering_is_rejected(
    coordinator: tuple[RunCoordinator, Path],
) -> None:
    service, repository = coordinator
    status = service.create_run(REPOSITORY_ID, repository, run_id=RUN_ID)
    paths = build_run_paths(service.directories.data, REPOSITORY_ID, RUN_ID)
    changed = status.manifest.model_copy(update={"created_at_utc": "2000-01-01T00:00:00.000000Z"})
    write_canonical_json(paths.manifest, changed.model_dump(mode="json"), exclusive=False)
    with pytest.raises(EvidenceIntegrityError, match="timestamp"):
        service.status(RUN_ID)


def test_runtime_string_cannot_bypass_strict_state_target_validation(
    coordinator: tuple[RunCoordinator, Path],
) -> None:
    service, repository = coordinator
    service.create_run(REPOSITORY_ID, repository, run_id=RUN_ID)
    with pytest.raises(InvalidStateTransition, match="target"):
        service.transition(RUN_ID, "PREFLIGHT")  # type: ignore[arg-type]
    assert service.status(RUN_ID).event_count == 1


def test_create_collision_unknown_ids_and_duplicate_locations_fail_closed(
    coordinator: tuple[RunCoordinator, Path],
) -> None:
    service, repository = coordinator
    service.create_run(REPOSITORY_ID, repository, run_id=RUN_ID)
    with pytest.raises(InternalInvariantError, match="already exists"):
        service.create_run(REPOSITORY_ID, repository, run_id=RUN_ID)
    with pytest.raises(UserInputError, match="Invalid"):
        service.status("bad-id")
    with pytest.raises(UserInputError, match="Unknown"):
        service.status("pp_20260713_cccccccccccc")
    with pytest.raises(UserInputError, match="repository ID"):
        service.create_run("invalid", repository)
    with pytest.raises(RepositoryError, match="does not exist"):
        service.create_run(REPOSITORY_ID, repository / "missing")

    with sqlite3.connect(service.directories.index) as connection:
        connection.execute("DELETE FROM runs WHERE run_id = ?", (RUN_ID,))
    duplicate = service.directories.runs / OTHER_REPOSITORY_ID / RUN_ID
    duplicate.mkdir(parents=True)
    with pytest.raises(InternalInvariantError, match="multiple repositories"):
        service.status(RUN_ID)


def test_empty_list_and_invalid_storage_names_are_ignored(tmp_path: Path) -> None:
    service = RunCoordinator(ApplicationDirectories(tmp_path / "data"))
    assert service.list_runs() == ()


def test_run_creation_rejects_linked_repository_data_directory_when_supported(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    service = RunCoordinator(ApplicationDirectories(tmp_path / "data"))
    outside = tmp_path / "outside"
    outside.mkdir()
    repository_data = service.directories.runs / REPOSITORY_ID
    try:
        repository_data.symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("symbolic links are unavailable for this Windows account")

    with pytest.raises(EvidenceIntegrityError, match="Unsafe ProofPatch run storage"):
        service.create_run(REPOSITORY_ID, repository, run_id=RUN_ID)
    assert list(outside.iterdir()) == []
    (service.directories.runs / "not-a-repo" / "not-a-run").mkdir(parents=True)
    assert service.list_runs() == ()


def test_phase1_cli_commands_show_verified_status_and_events(
    coordinator: tuple[RunCoordinator, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, repository = coordinator
    service.create_run(REPOSITORY_ID, repository, run_id=RUN_ID)
    monkeypatch.setattr(cli, "_coordinator", lambda: service)
    runner = CliRunner()

    listed = runner.invoke(cli.app, ["list"])
    status = runner.invoke(cli.app, ["status", RUN_ID])
    inspected = runner.invoke(cli.app, ["inspect", RUN_ID, "--events"])

    assert listed.exit_code == status.exit_code == inspected.exit_code == ExitCode.SUCCESS
    assert f"{RUN_ID}  CREATED" in listed.output
    assert "State: CREATED" in status.output
    assert '"type":"run.created"' in inspected.output
    assert "Metadata index: current" in inspected.output


def test_phase1_cli_list_handles_no_runs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = RunCoordinator(ApplicationDirectories(tmp_path / "data"))
    monkeypatch.setattr(cli, "_coordinator", lambda: service)
    result = CliRunner().invoke(cli.app, ["list"])
    assert result.exit_code == ExitCode.SUCCESS
    assert result.output.strip() == "No runs found."


@pytest.mark.parametrize(
    "application",
    [
        lambda: (_ for _ in ()).throw(KeyboardInterrupt()),
        lambda: (_ for _ in ()).throw(SystemExit(130)),
    ],
)
def test_interruptions_map_to_the_public_exit_code(
    application: Callable[[], object],
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as raised:
        cli._run_application(application)
    assert raised.value.code == ExitCode.INTERRUPTED
    assert "PP_INTERRUPTED" in capsys.readouterr().err


def test_non_interrupt_system_exit_is_preserved() -> None:
    with pytest.raises(SystemExit) as raised:
        cli._run_application(lambda: (_ for _ in ()).throw(SystemExit(2)))
    assert raised.value.code == 2


@pytest.mark.parametrize(
    "command",
    [
        cli.list_command,
        lambda: cli.status_command(RUN_ID),
        lambda: cli.inspect_command(RUN_ID),
    ],
)
def test_each_phase1_command_handles_interruption(
    command: Callable[[], object],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    class InterruptedCoordinator:
        def __getattr__(self, _name: str) -> Callable[..., object]:
            return lambda *_args, **_kwargs: (_ for _ in ()).throw(KeyboardInterrupt())

    monkeypatch.setattr(cli, "_coordinator", InterruptedCoordinator)
    with pytest.raises(SystemExit) as raised:
        cli._run_application(command)
    assert raised.value.code == ExitCode.INTERRUPTED
    assert "PP_INTERRUPTED" in capsys.readouterr().err


def test_list_maps_invalid_data_directory_configuration_as_user_error(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv(DATA_DIRECTORY_ENV, "relative/path")
    with pytest.raises(SystemExit) as raised:
        cli._run_application(cli.list_command)
    assert raised.value.code == ExitCode.INVALID_COMMAND_OR_CONFIGURATION
    assert "PP_CONFIGURATION_INVALID" in capsys.readouterr().err
