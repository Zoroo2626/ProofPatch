"""Specification-level tests for init, doctor, clean, and explicit CLI options."""

import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import cast
from unittest.mock import patch

import pytest
import yaml
from typer.testing import CliRunner

import proofpatch.cli as cli
import proofpatch.services.diagnostics as diagnostic_module
from proofpatch.backends.docker import DockerBackend
from proofpatch.cli import app
from proofpatch.errors import (
    CleanupError,
    ConfigurationError,
    ImageResolutionError,
    RepositoryError,
)
from proofpatch.exit_codes import ExitCode
from proofpatch.git.client import GitClient, GitResult
from proofpatch.models.config import load_configuration
from proofpatch.models.execution import BackendDoctorResult, ResolvedImage
from proofpatch.models.state import RunState
from proofpatch.security.paths import validate_cleanup_target
from proofpatch.services.cleanup import RunCleanupService, remove_owned_tree
from proofpatch.services.coordinator import RunCoordinator
from proofpatch.services.data_directories import DATA_DIRECTORY_ENV, ApplicationDirectories
from proofpatch.services.diagnostics import (
    DiagnosticCheck,
    DiagnosticLevel,
    DoctorReport,
    DoctorService,
)
from proofpatch.services.initialization import (
    InitMode,
    InitTemplate,
    _write_configuration,
    initialize_repository,
)
from proofpatch.services.repository import RepositoryService

RUN_ID = "pp_20260714_aaaaaaaaaaaa"
RUN_ID_2 = "pp_20260714_bbbbbbbbbbbb"
REPOSITORY_ID = "repo_aaaaaaaaaaaaaaaa"


class _HealthyDocker:
    def doctor(self) -> BackendDoctorResult:
        return BackendDoctorResult(
            docker_cli=True,
            daemon_responding=True,
            linux_containers=True,
            client_version="1",
            server_version="1",
        )

    def resolve_image(self, image: str, *, pull: bool = False) -> ResolvedImage:
        del pull
        digest = "sha256:" + "a" * 64
        return ResolvedImage(
            requested_reference=image,
            immutable_reference=f"example.invalid/runtime@{digest}",
            digest=digest,
            image_id="sha256:" + "b" * 64,
            architecture="amd64",
        )


class _HealthyGit:
    def run(self, args: list[str], **kwargs: object) -> GitResult:
        del kwargs
        assert args == ["--version"]
        return GitResult(("git", "--version"), 0, b"git version 2.50.0\n", b"")


def _terminal_run(tmp_path: Path, *, run_id: str = RUN_ID) -> tuple[RunCoordinator, Path]:
    repository = tmp_path / f"repository-{run_id[-1]}"
    repository.mkdir()
    coordinator = RunCoordinator(ApplicationDirectories(tmp_path / "data"))
    coordinator.create_run(REPOSITORY_ID, repository, run_id=run_id)
    for state in (
        RunState.PREFLIGHT,
        RunState.BASELINE_PREPARING,
        RunState.BASELINE_VERIFYING,
        RunState.BASELINE_NOT_REPRODUCED,
        RunState.REJECTED,
    ):
        coordinator.transition(run_id, state)
    workspace = coordinator.paths_for(run_id).workspaces
    workspace.mkdir()
    (workspace / "content.txt").write_text("content\n", encoding="utf-8")
    return coordinator, workspace


def test_init_success_is_valid_deterministic_and_supports_observation(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text("[project]\nname='example'\n", encoding="utf-8")
    created = initialize_repository(
        tmp_path,
        mode=InitMode.PROTECTED,
        template=None,
        force=False,
    )
    first = created.path.read_bytes()
    loaded = load_configuration(created.path)
    assert created.template is InitTemplate.PYTHON
    assert loaded.mode == "protected"
    assert loaded.runtime.image == "python:3.12-slim"
    assert loaded.setup.commands == ()
    assert loaded.network.setup == "none"

    replaced = initialize_repository(
        tmp_path,
        mode=InitMode.PROTECTED,
        template=InitTemplate.PYTHON,
        force=True,
    )
    assert replaced.path.read_bytes() == first

    observation = tmp_path / "observation"
    observation.mkdir()
    result = initialize_repository(
        observation,
        mode=InitMode.OBSERVATION,
        template=InitTemplate.MINIMAL,
        force=False,
    )
    assert load_configuration(result.path).mode == "observation"


def test_init_refuses_overwrite_without_force_and_cli_reports_next_step(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    existing = tmp_path / "proofpatch.yml"
    existing.write_text("user content\n", encoding="utf-8")
    with pytest.raises(ConfigurationError, match="already exists"):
        initialize_repository(
            tmp_path,
            mode=InitMode.PROTECTED,
            template=InitTemplate.MINIMAL,
            force=False,
        )
    assert existing.read_text(encoding="utf-8") == "user content\n"

    cli_root = tmp_path / "cli"
    cli_root.mkdir()
    monkeypatch.chdir(cli_root)
    result = CliRunner().invoke(
        app,
        ["init", "--template", "node", "--mode", "protected"],
    )
    assert result.exit_code == 0
    assert "Next:" in result.output
    assert load_configuration(cli_root / "proofpatch.yml").runtime.image == "node:22-slim"


@pytest.mark.parametrize(
    ("indicators", "expected"),
    [
        (("package.json",), InitTemplate.NODE),
        (("pyproject.toml",), InitTemplate.PYTHON),
        (("package.json", "pyproject.toml"), InitTemplate.MINIMAL),
        ((), InitTemplate.MINIMAL),
    ],
)
def test_init_project_detection_is_conservative(
    tmp_path: Path,
    indicators: tuple[str, ...],
    expected: InitTemplate,
) -> None:
    for indicator in indicators:
        (tmp_path / indicator).touch()
    result = initialize_repository(
        tmp_path,
        mode=InitMode.PROTECTED,
        template=None,
        force=False,
    )
    assert result.template is expected


def test_init_fails_closed_for_unsafe_paths_and_writes(tmp_path: Path) -> None:
    output = tmp_path / "proofpatch.yml"
    output.mkdir()
    with pytest.raises(ConfigurationError, match="regular file"):
        initialize_repository(
            tmp_path,
            mode=InitMode.PROTECTED,
            template=InitTemplate.MINIMAL,
            force=True,
        )
    with pytest.raises(ConfigurationError, match="does not exist"):
        initialize_repository(
            tmp_path / "missing",
            mode=InitMode.PROTECTED,
            template=InitTemplate.MINIMAL,
            force=False,
        )
    source_file = tmp_path / "not-a-directory"
    source_file.write_text("value", encoding="utf-8")
    with pytest.raises(ConfigurationError, match="not a directory"):
        initialize_repository(
            source_file,
            mode=InitMode.PROTECTED,
            template=InitTemplate.MINIMAL,
            force=False,
        )

    short = tmp_path / "short.yml"
    with (
        patch("proofpatch.services.initialization.os.write", return_value=0),
        pytest.raises(ConfigurationError, match="safely write"),
    ):
        _write_configuration(short, b"content", force=False)

    non_regular = tmp_path / "non-regular.yml"
    with (
        patch("proofpatch.services.initialization.os.fstat", return_value=tmp_path.stat()),
        pytest.raises(ConfigurationError, match="private regular"),
    ):
        _write_configuration(non_regular, b"content", force=False)


def test_doctor_reports_all_categories_without_secret_values(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = initialize_repository(
        tmp_path,
        mode=InitMode.PROTECTED,
        template=InitTemplate.MINIMAL,
        force=False,
    ).path
    document = yaml.safe_load(config.read_text(encoding="utf-8"))
    document["agent"].update(
        {
            "adapter": "claude",
            "command": ["claude"],
            "environment_allowlist": ["ANTHROPIC_API_KEY"],
        }
    )
    config.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
    monkeypatch.setattr(RepositoryService, "discover", lambda *_args: SimpleNamespace())
    report = DoctorService(
        ApplicationDirectories(tmp_path / "data"),
        backend=cast(DockerBackend, _HealthyDocker()),
        git=cast(GitClient, _HealthyGit()),
        environment={"ANTHROPIC_API_KEY": "do-not-print-this-value"},
    ).check(tmp_path, config_path=config)
    rendered = "\n".join(check.message for check in report.checks)
    assert report.exit_code is ExitCode.SUCCESS
    assert all(check.level is DiagnosticLevel.PASS for check in report.checks)
    assert "Git 2.50.0" in rendered
    assert "ANTHROPIC_API_KEY" in rendered
    assert "do-not-print-this-value" not in rendered


def test_doctor_distinguishes_docker_unavailable_from_invalid_configuration(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = initialize_repository(
        tmp_path,
        mode=InitMode.PROTECTED,
        template=InitTemplate.MINIMAL,
        force=False,
    ).path
    monkeypatch.setattr(RepositoryService, "discover", lambda *_args: SimpleNamespace())

    class MissingDocker(_HealthyDocker):
        def doctor(self) -> BackendDoctorResult:
            return BackendDoctorResult(
                docker_cli=False,
                daemon_responding=False,
                linux_containers=False,
            )

    unavailable = DoctorService(
        ApplicationDirectories(tmp_path / "unavailable-data"),
        backend=cast(DockerBackend, MissingDocker()),
        git=cast(GitClient, _HealthyGit()),
        environment={},
    ).check(tmp_path, config_path=config)
    assert unavailable.exit_code is ExitCode.UNSUPPORTED_ENVIRONMENT

    document = yaml.safe_load(config.read_text(encoding="utf-8"))
    document["runtime"]["platform"] = "linux/arm64"
    config.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
    invalid = DoctorService(
        ApplicationDirectories(tmp_path / "invalid-data"),
        backend=cast(DockerBackend, _HealthyDocker()),
        git=cast(GitClient, _HealthyGit()),
        environment={},
    ).check(tmp_path, config_path=config)
    assert invalid.exit_code is ExitCode.PREFLIGHT_FAILURE
    assert (
        next(check for check in invalid.checks if check.name == "configuration").level
        is DiagnosticLevel.FAIL
    )


def test_doctor_cli_groups_levels_and_returns_stable_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report = DoctorReport(
        (
            DiagnosticCheck("version", DiagnosticLevel.PASS, "ok"),
            DiagnosticCheck("config", DiagnosticLevel.WARNING, "missing"),
            DiagnosticCheck("docker_cli", DiagnosticLevel.FAIL, "unavailable"),
        )
    )

    class FakeDoctor:
        def __init__(self, _directories: object) -> None:
            pass

        def check(self, _repository: Path) -> DoctorReport:
            return report

    monkeypatch.setattr(cli, "DoctorService", FakeDoctor)
    result = CliRunner().invoke(app, ["doctor"])
    assert result.exit_code == ExitCode.UNSUPPORTED_ENVIRONMENT
    assert "PASS:" in result.output
    assert "WARNING:" in result.output
    assert "FAIL:" in result.output

    only_pass = DoctorReport((DiagnosticCheck("version", DiagnosticLevel.PASS, "ok"),))
    cli._print_doctor_report(only_pass)


def test_doctor_failure_and_observation_branches_are_controlled(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class BrokenDirectories:
        data = tmp_path / "broken-data"
        cache = data / "cache"

        def ensure_exists(self) -> None:
            raise ValueError("unsafe")

    class MissingDocker(_HealthyDocker):
        def doctor(self) -> BackendDoctorResult:
            return BackendDoctorResult(
                docker_cli=False,
                daemon_responding=False,
                linux_containers=False,
            )

    monkeypatch.setattr(
        diagnostic_module,
        "GitClient",
        lambda: (_ for _ in ()).throw(RepositoryError("missing")),
    )
    missing = DoctorService(
        cast(ApplicationDirectories, BrokenDirectories()),
        backend=cast(DockerBackend, MissingDocker()),
        environment={},
    ).check(tmp_path)
    assert (
        next(check for check in missing.checks if check.name == "git").level is DiagnosticLevel.FAIL
    )
    assert (
        next(check for check in missing.checks if check.name == "filesystem_permissions").level
        is DiagnosticLevel.FAIL
    )

    observation = initialize_repository(
        tmp_path,
        mode=InitMode.OBSERVATION,
        template=InitTemplate.MINIMAL,
        force=False,
    ).path
    monkeypatch.setattr(RepositoryService, "discover", lambda *_args: SimpleNamespace())
    observed = DoctorService(
        ApplicationDirectories(tmp_path / "observation-data"),
        backend=cast(DockerBackend, MissingDocker()),
        git=cast(GitClient, _HealthyGit()),
        environment={},
    ).check(tmp_path, config_path=observation)
    assert observed.exit_code is ExitCode.SUCCESS
    assert (
        next(check for check in observed.checks if check.name == "image_resolution").level
        is DiagnosticLevel.WARNING
    )


def test_doctor_controls_git_repository_image_config_and_missing_secret_failures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = initialize_repository(
        tmp_path,
        mode=InitMode.PROTECTED,
        template=InitTemplate.MINIMAL,
        force=False,
    ).path

    class FailingGit(_HealthyGit):
        def run(self, args: list[str], **kwargs: object) -> GitResult:
            del args, kwargs
            raise RepositoryError("failed")

    git_failure = DoctorService(
        ApplicationDirectories(tmp_path / "git-data"),
        backend=cast(DockerBackend, _HealthyDocker()),
        git=cast(GitClient, FailingGit()),
        environment={},
    ).check(tmp_path, config_path=config)
    assert (
        next(check for check in git_failure.checks if check.name == "git").level
        is DiagnosticLevel.FAIL
    )

    class MalformedGit(_HealthyGit):
        def run(self, args: list[str], **kwargs: object) -> GitResult:
            del args, kwargs
            return GitResult(("git", "--version"), 0, b"do-not-print-this-value\n", b"")

    malformed_git = DoctorService(
        ApplicationDirectories(tmp_path / "malformed-git-data"),
        backend=cast(DockerBackend, _HealthyDocker()),
        git=cast(GitClient, MalformedGit()),
        environment={},
    ).check(tmp_path, config_path=config)
    git_check = next(check for check in malformed_git.checks if check.name == "git")
    assert git_check.level is DiagnosticLevel.FAIL
    assert "do-not-print-this-value" not in git_check.message

    monkeypatch.setattr(
        RepositoryService,
        "discover",
        lambda *_args: (_ for _ in ()).throw(RepositoryError("dirty")),
    )
    repository_failure = DoctorService(
        ApplicationDirectories(tmp_path / "repository-data"),
        backend=cast(DockerBackend, _HealthyDocker()),
        git=cast(GitClient, _HealthyGit()),
        environment={},
    ).check(tmp_path, config_path=config)
    assert (
        next(check for check in repository_failure.checks if check.name == "repository").level
        is DiagnosticLevel.FAIL
    )

    class MissingImage(_HealthyDocker):
        def resolve_image(self, image: str, *, pull: bool = False) -> ResolvedImage:
            del image, pull
            raise ImageResolutionError("missing")

    image_failure = DoctorService(
        ApplicationDirectories(tmp_path / "image-data"),
        backend=cast(DockerBackend, MissingImage()),
        git=cast(GitClient, _HealthyGit()),
        environment={},
    ).check(tmp_path, config_path=config)
    assert (
        next(check for check in image_failure.checks if check.name == "image_resolution").level
        is DiagnosticLevel.FAIL
    )

    document = yaml.safe_load(config.read_text(encoding="utf-8"))
    document["agent"].update(
        {
            "adapter": "claude",
            "command": ["claude"],
            "environment_allowlist": ["ANTHROPIC_API_KEY"],
        }
    )
    config.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
    missing_secret = DoctorService(
        ApplicationDirectories(tmp_path / "secret-data"),
        backend=cast(DockerBackend, _HealthyDocker()),
        git=cast(GitClient, _HealthyGit()),
        environment={},
    ).check(tmp_path, config_path=config)
    secret_check = next(
        check for check in missing_secret.checks if check.name == "required_secrets"
    )
    assert secret_check.level is DiagnosticLevel.FAIL
    assert secret_check.message.endswith("ANTHROPIC_API_KEY")

    invalid = tmp_path / "invalid.yml"
    invalid.write_text("not: a-proofpatch-config\n", encoding="utf-8")
    invalid_report = DoctorService(
        ApplicationDirectories(tmp_path / "config-data"),
        backend=cast(DockerBackend, _HealthyDocker()),
        git=cast(GitClient, _HealthyGit()),
        environment={},
    ).check(tmp_path, config_path=invalid)
    assert (
        next(check for check in invalid_report.checks if check.name == "configuration").level
        is DiagnosticLevel.FAIL
    )

    invalid.replace(tmp_path / "proofpatch.yml")
    discovered_invalid_report = DoctorService(
        ApplicationDirectories(tmp_path / "discovered-config-data"),
        backend=cast(DockerBackend, _HealthyDocker()),
        git=cast(GitClient, _HealthyGit()),
        environment={},
    ).check(tmp_path)
    assert (
        next(
            check for check in discovered_invalid_report.checks if check.name == "configuration"
        ).level
        is DiagnosticLevel.FAIL
    )


def test_clean_preview_execution_and_evidence(tmp_path: Path) -> None:
    coordinator, workspace = _terminal_run(tmp_path)
    service = RunCleanupService(coordinator)
    preview = service.preview(RUN_ID)
    assert workspace.exists()
    assert preview.targets[0].path == workspace

    executed = service.clean(RUN_ID)
    assert executed.targets[0].path == workspace
    assert not workspace.exists()
    status = coordinator.status(RUN_ID)
    assert status.state is RunState.CLEANED
    assert any(event.type == "cleanup.started" for event in status.events)
    assert any(event.type == "cleanup.completed" for event in status.events)
    with pytest.raises(CleanupError, match="already cleaned"):
        service.preview(RUN_ID)


def test_clean_rejects_replaced_targets_hardlinks_active_runs_and_live_locks(
    tmp_path: Path,
) -> None:
    coordinator, workspace = _terminal_run(tmp_path)
    validated = validate_cleanup_target(coordinator.directories.data, workspace)
    original = workspace.with_name("original-workspaces")
    workspace.rename(original)
    workspace.mkdir()
    with pytest.raises(CleanupError, match="changed after validation"):
        remove_owned_tree(
            coordinator.directories.data,
            workspace,
            expected=validated,
        )
    assert workspace.exists()

    workspace.rmdir()
    original.rename(workspace)
    outside = tmp_path / "outside.txt"
    outside.write_text("outside\n", encoding="utf-8")
    os.link(outside, workspace / "hardlink.txt")
    with pytest.raises(CleanupError, match="hardlinked"):
        RunCleanupService(coordinator).clean(RUN_ID)
    assert outside.read_text(encoding="utf-8") == "outside\n"
    assert coordinator.status(RUN_ID).state is RunState.REJECTED

    active_root = tmp_path / "active"
    active_root.mkdir()
    active = RunCoordinator(ApplicationDirectories(tmp_path / "active-data"))
    active.create_run(REPOSITORY_ID, active_root, run_id=RUN_ID_2)
    with pytest.raises(CleanupError, match="Active run"):
        RunCleanupService(active).preview(RUN_ID_2)

    from proofpatch.services.locks import RepositoryLock

    status = coordinator.status(RUN_ID)
    with (
        RepositoryLock(
            coordinator.directories.locks,
            status.manifest.repository_id,
            status.manifest.run_id,
        ),
        pytest.raises(RepositoryError, match="holds the lock"),
    ):
        RunCleanupService(coordinator).preview(RUN_ID)


def test_clean_completed_age_selection_and_cli_preview_then_yes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    coordinator, workspace = _terminal_run(tmp_path)
    service = RunCleanupService(coordinator)
    future = datetime.now(UTC) + timedelta(days=31)
    assert service.completed_before(timedelta(days=30), now=future)[0].manifest.run_id == RUN_ID
    with pytest.raises(CleanupError, match="positive"):
        service.completed_before(timedelta(0), now=future)
    with pytest.raises(CleanupError, match="timezone-aware"):
        service.completed_before(timedelta(days=1), now=datetime.now())

    monkeypatch.setenv(DATA_DIRECTORY_ENV, str(coordinator.directories.data))
    runner = CliRunner()
    preview = runner.invoke(app, ["clean", RUN_ID])
    assert preview.exit_code == 0
    assert "Would clean" in preview.output
    assert workspace.exists()
    execute = runner.invoke(app, ["clean", RUN_ID, "--yes"])
    assert execute.exit_code == 0
    assert "Cleaned" in execute.output
    assert not workspace.exists()


def test_clean_completed_cli_reports_an_empty_age_selection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    coordinator, _workspace = _terminal_run(tmp_path)
    monkeypatch.setenv(DATA_DIRECTORY_ENV, str(coordinator.directories.data))
    result = CliRunner().invoke(
        app,
        ["clean", "--completed", "--older-than", "30d"],
    )
    assert result.exit_code == 0
    assert "No completed runs" in result.output


def test_clean_without_retained_workspace_still_records_terminal_cleanup(tmp_path: Path) -> None:
    coordinator, workspace = _terminal_run(tmp_path)
    remove_owned_tree(coordinator.directories.data, workspace)
    plan = RunCleanupService(coordinator).clean(RUN_ID)
    assert plan.targets == ()
    assert coordinator.status(RUN_ID).state is RunState.CLEANED


def test_cleanup_rejects_mismatched_expected_identity_path(tmp_path: Path) -> None:
    coordinator, workspace = _terminal_run(tmp_path)
    expected = validate_cleanup_target(coordinator.directories.data, workspace)
    with pytest.raises(CleanupError, match="does not match"):
        remove_owned_tree(
            coordinator.directories.data,
            workspace.with_name("other"),
            expected=expected,
        )


def test_explicit_run_and_inspect_options_are_exposed() -> None:
    runner = CliRunner()
    run_help = runner.invoke(app, ["run", "--help"], terminal_width=240, color=False)
    inspect_help = runner.invoke(app, ["inspect", "--help"], terminal_width=240, color=False)
    assert run_help.exit_code == inspect_help.exit_code == 0
    for option in ("--keep-workspaces", "--json", "--verbose", "--no-color"):
        assert option in run_help.output
    for option in ("--patch", "--logs"):
        assert option in inspect_help.output


def test_clean_cli_selection_and_duration_options_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(DATA_DIRECTORY_ENV, str(tmp_path / "data"))
    runner = CliRunner()
    assert runner.invoke(app, ["clean"]).exit_code != 0
    assert runner.invoke(app, ["clean", RUN_ID, "--completed"]).exit_code != 0
    assert runner.invoke(app, ["clean", "--completed"]).exit_code != 0
    assert runner.invoke(app, ["clean", "--completed", "--older-than", "0d"]).exit_code != 0
    assert (
        runner.invoke(
            app,
            ["clean", "--completed", "--older-than", "4000d"],
        ).exit_code
        != 0
    )


def test_inspect_logs_are_bounded_to_verified_regular_run_files(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    coordinator, _workspace = _terminal_run(tmp_path)
    verification = coordinator.paths_for(RUN_ID).verification
    log = verification / "fixed" / "reproduction" / "stdout.log"
    log.parent.mkdir(parents=True)
    log.write_text("redacted output\n", encoding="utf-8")
    monkeypatch.setenv(DATA_DIRECTORY_ENV, str(coordinator.directories.data))
    result = CliRunner().invoke(app, ["inspect", RUN_ID, "--logs", "verification"])
    assert result.exit_code == 0
    assert "verification/fixed/reproduction/stdout.log" in result.output
    assert "redacted output" in result.output

    hardlink = verification / "hardlink.log"
    os.link(log, hardlink)
    rejected = CliRunner().invoke(app, ["inspect", RUN_ID, "--logs", "verification"])
    assert rejected.exit_code != 0


def test_inspect_log_categories_and_byte_limits_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    coordinator, _workspace = _terminal_run(tmp_path)
    monkeypatch.setenv(DATA_DIRECTORY_ENV, str(coordinator.directories.data))
    runner = CliRunner()
    missing = runner.invoke(app, ["inspect", RUN_ID, "--logs", "investigation"])
    assert missing.exit_code == 0
    assert "No persisted investigation logs" in missing.output

    investigation = coordinator.paths_for(RUN_ID).investigation
    investigation.mkdir()
    no_logs = runner.invoke(app, ["inspect", RUN_ID, "--logs", "investigation"])
    assert no_logs.exit_code == 0
    assert "No persisted investigation logs" in no_logs.output
    assert runner.invoke(app, ["inspect", RUN_ID, "--logs", "unknown"]).exit_code != 0

    bounded = investigation / "bounded.log"
    bounded.write_bytes(b"xx")
    with pytest.raises(ConfigurationError, match="8 MiB"):
        cli._read_inspection_log(bounded, 0)
    with pytest.raises(ConfigurationError, match="8 MiB"):
        cli._read_inspection_log(bounded, 1)
