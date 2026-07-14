"""Strict configuration and Phase 6 CLI surface tests."""

from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

import proofpatch.cli as cli
from proofpatch.backends.docker import DockerBackend
from proofpatch.cli import app
from proofpatch.errors import AgentError, ConfigurationError, VerificationError
from proofpatch.models.config import (
    ProofPatchConfig,
    SetupCommandConfig,
    discover_configuration,
    load_configuration,
)
from proofpatch.models.execution import (
    BackendDoctorResult,
    CommandOracleSpec,
    ExitCodeMatcherSpec,
    ExitCodeOperator,
    OracleExpectation,
    ResolvedImage,
)
from proofpatch.models.state import RunState
from proofpatch.services.workflow import WorkflowOutcome


def _document() -> str:
    return """\
schema_version: 1
project:
  name: example
mode: protected
repository:
  denied_patch_paths: [".git/**", ".proofpatch/**", "proofpatch.yml"]
runtime:
  image: example/runtime@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  limits:
    timeout_seconds: 60.0
    memory_mb: 256
    cpus: 1.0
    pids: 64
    output_mb: 2
network:
  setup: none
  investigation: bridge
  patch: bridge
  baseline: none
  verification: none
agent:
  adapter: generic
  command: ["fake-agent", "--prompt", "{prompt_path}"]
  environment_allowlist: [AGENT_TOKEN]
  maximum_attempts: 1
  investigation_timeout_seconds: 30.0
  patch_timeout_seconds: 30.0
issue:
  source: inline
  text: Reported failure
oracles:
  reproduction:
    source: agent-contract
    required: true
  regressions:
    - id: tests
      type: command
      argv: ["pytest", "-q"]
      cwd: "."
      timeout_seconds: 30.0
      expect:
        exit_code: 0
"""


def test_configuration_loads_full_phase6_inputs_and_discovers_priority(tmp_path: Path) -> None:
    low_priority = tmp_path / ".proofpatch.yaml"
    selected = tmp_path / "proofpatch.yml"
    low_priority.write_text(_document(), encoding="utf-8")
    selected.write_text(_document(), encoding="utf-8")

    config = load_configuration(selected)

    assert config.project.name == "example"
    assert config.agent.command[-1] == "{prompt_path}"
    assert config.oracles.regressions[0].expect.exit_code == 0
    assert discover_configuration(tmp_path) == selected


@pytest.mark.parametrize(
    "replacement",
    [
        "schema_version: 2",
        "unknown: true",
    ],
)
def test_configuration_rejects_wrong_schema_unknowns_and_unprotected_mode(
    tmp_path: Path,
    replacement: str,
) -> None:
    path = tmp_path / "proofpatch.yml"
    path.write_text(_document() + f"\n{replacement}\n", encoding="utf-8")
    with pytest.raises(ConfigurationError):
        load_configuration(path)


def test_configuration_rejects_aliases_missing_files_and_unsafe_git_policy(
    tmp_path: Path,
) -> None:
    alias = tmp_path / "alias.yml"
    alias.write_text("project: &p {name: x}\ncopy: *p\n", encoding="utf-8")
    with pytest.raises(ConfigurationError, match="aliases"):
        load_configuration(alias)
    with pytest.raises(ConfigurationError, match="No ProofPatch"):
        discover_configuration(tmp_path / "missing")
    with pytest.raises(ValidationError, match="git"):
        ProofPatchConfig.model_validate(
            {
                "project": {"name": "example"},
                "runtime": {"image": "example/runtime"},
                "agent": {"command": ["agent"]},
                "repository": {"denied_patch_paths": ["proofpatch.yml"]},
            }
        )


def test_cli_exposes_run_resume_abort_and_receipt_commands() -> None:
    output = CliRunner().invoke(app, ["--help"])
    assert output.exit_code == 0
    assert "run" in output.output
    assert "resume" in output.output
    assert "abort" in output.output
    assert "receipt" in output.output


class _FakeDocker:
    def doctor(self) -> BackendDoctorResult:
        return BackendDoctorResult(
            docker_cli=True,
            daemon_responding=True,
            linux_containers=True,
        )

    def resolve_image(self, image: str, *, pull: bool = False) -> ResolvedImage:
        del pull
        digest = "sha256:" + "a" * 64
        return ResolvedImage(
            requested_reference=image,
            immutable_reference=f"example/runtime@{digest}",
            digest=digest,
            image_id="sha256:" + "b" * 64,
            architecture="amd64",
        )


def test_cli_plan_issue_and_outcome_helpers_are_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "proofpatch.yml"
    path.write_text(_document(), encoding="utf-8")
    config = load_configuration(path)
    backend = cast(DockerBackend, _FakeDocker())
    with pytest.raises(ConfigurationError, match="Confirmation"):
        cli._workflow_plan(config, backend, yes=False)
    monkeypatch.setenv("AGENT_TOKEN", "secret")
    plan = cli._workflow_plan(config, backend, yes=True)
    assert plan.agent_environment == {"AGENT_TOKEN": "secret"}
    assert plan.regressions[0].id == "tests"
    assert plan.allowed_patch_paths == ("**",)
    assert plan.maximum_repository_bytes == 2048 * 1024 * 1024
    assert not plan.retain_workspaces
    assert plan.flag_test_changes
    assert cli._resolve_issue(config, " command line issue ", None) == "command line issue"
    issue_file = tmp_path / "issue.txt"
    issue_file.write_text(" file issue \n", encoding="utf-8")
    assert cli._resolve_issue(config, None, issue_file) == "file issue"
    with pytest.raises(ConfigurationError, match="either"):
        cli._resolve_issue(config, "one", issue_file)
    with pytest.raises(ConfigurationError, match="required"):
        cli._resolve_issue(
            config.model_copy(update={"issue": config.issue.model_copy(update={"text": None})}),
            None,
            None,
        )
    with pytest.raises(VerificationError):
        cli._print_workflow_outcome(
            WorkflowOutcome("pp_20260713_aaaaaaaaaaaa", RunState.REJECTED, None, None, None)
        )


def test_run_resume_and_abort_cli_commands_delegate_to_workflow(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = tmp_path / "proofpatch.yml"
    config.write_text(_document(), encoding="utf-8")
    run_id = "pp_20260713_aaaaaaaaaaaa"
    outcome = WorkflowOutcome(run_id, RunState.VERIFIED, None, None, None)
    calls: list[str] = []

    class FakeWorkflow:
        def __init__(self, coordinator: object, backend: object) -> None:
            del coordinator, backend

        def run(self, repository: Path, issue: str, plan: object) -> WorkflowOutcome:
            del repository, issue
            calls.append(f"run:{getattr(plan, 'retain_workspaces', None)}")
            return outcome

        def resume(
            self,
            selected_run_id: str,
            plan: object,
            *,
            capture_surviving_patch: bool,
        ) -> WorkflowOutcome:
            del selected_run_id, plan, capture_surviving_patch
            calls.append("resume")
            return outcome

        def abort(self, selected_run_id: str) -> RunState:
            del selected_run_id
            calls.append("abort")
            return RunState.ABORTED

    coordinator = SimpleNamespace(
        status=lambda _run_id: SimpleNamespace(
            manifest=SimpleNamespace(repository_root=str(tmp_path))
        )
    )
    monkeypatch.setattr(cli, "DockerBackend", _FakeDocker)
    monkeypatch.setattr(cli, "WorkflowService", FakeWorkflow)
    monkeypatch.setattr(cli, "_coordinator", lambda: coordinator)
    runner = CliRunner()
    run = runner.invoke(
        app,
        [
            "run",
            "--repository",
            str(tmp_path),
            "--config",
            str(config),
            "--issue",
            "Reported failure",
            "--yes",
            "--keep-workspaces",
            "--json",
            "--verbose",
            "--no-color",
        ],
    )
    resume = runner.invoke(
        app,
        ["resume", run_id, "--config", str(config), "--yes"],
    )
    abort = runner.invoke(app, ["abort", run_id])
    assert run.exit_code == resume.exit_code == abort.exit_code == 0
    assert '"verified":true' in run.output
    assert calls == ["run:True", "resume", "abort"]


def test_configuration_exercises_nested_arrays_and_rejects_edge_cases(tmp_path: Path) -> None:
    path = tmp_path / "proofpatch.yml"
    expanded = (
        _document()
        .replace(
            "  limits:\n",
            "  tmpfs:\n    - path: /tmp\n      size_mb: 64\n      exec: false\n  limits:\n",
        )
        .replace(
            "agent:\n",
            "setup:\n  commands:\n    - id: install\n      argv: [python, install.py]\n"
            "      timeout_seconds: 10.0\n  environment: {}\n"
            "  readonly_secret_files: [secret.txt]\nagent:\n",
        )
    )
    path.write_text(expanded, encoding="utf-8")
    loaded = load_configuration(path)
    assert loaded.runtime.tmpfs[0].path == "/tmp"  # noqa: S108 - container tmpfs path
    assert loaded.setup.commands[0].argv == ("python", "install.py")
    assert loaded.setup.readonly_secret_files == ("secret.txt",)

    unhashable = tmp_path / "unhashable.yml"
    unhashable.write_text("? [a, b]\n: value\n", encoding="utf-8")
    with pytest.raises(ConfigurationError, match="hashable"):
        load_configuration(unhashable)
    non_mapping = tmp_path / "array.yml"
    non_mapping.write_text("[]\n", encoding="utf-8")
    with pytest.raises(ConfigurationError, match="mapping"):
        load_configuration(non_mapping)
    with pytest.raises(ConfigurationError, match="Could not read"):
        load_configuration(tmp_path / "absent.yml")
    too_large = tmp_path / "large.yml"
    too_large.write_bytes(b" " * (1024 * 1024 + 1))
    with pytest.raises(ConfigurationError, match="1 MiB"):
        load_configuration(too_large)


def test_configuration_and_workflow_plan_reject_unsafe_combinations(tmp_path: Path) -> None:
    path = tmp_path / "proofpatch.yml"
    path.write_text(_document(), encoding="utf-8")
    config = load_configuration(path)
    backend = cast(DockerBackend, _FakeDocker())
    plan = cli._workflow_plan(config, backend, yes=True)
    with pytest.raises(ValidationError, match="non-root"):
        type(config.runtime).model_validate({**config.runtime.model_dump(), "user": "root"})
    with pytest.raises(ValueError, match="non-allowlisted"):
        replace(plan, agent_environment={"OTHER": "value"})
    reproduction = CommandOracleSpec(
        id="repro",
        argv=("test",),
        timeout_seconds=1.0,
        baseline_expectation=OracleExpectation(
            exit_code=ExitCodeMatcherSpec(operator=ExitCodeOperator.NOT_EQUAL, value=0)
        ),
        fixed_expectation=OracleExpectation(
            exit_code=ExitCodeMatcherSpec(operator=ExitCodeOperator.EQUAL, value=0)
        ),
    )
    with pytest.raises(ValueError, match="Regression"):
        replace(plan, regressions=(reproduction,))
    with pytest.raises(ValueError, match="unique"):
        replace(plan, regressions=(plan.regressions[0], plan.regressions[0]))
    with pytest.raises(ValueError, match="blank"):
        replace(plan, project_name=" ")
    with pytest.raises(ValueError, match="Maximum attempts"):
        replace(plan, maximum_attempts=0)
    with pytest.raises(ValidationError):
        type(config.agent).model_validate({**config.agent.model_dump(), "maximum_attempts": 11})


def test_cli_helper_error_branches(tmp_path: Path) -> None:
    path = tmp_path / "proofpatch.yml"
    path.write_text(_document(), encoding="utf-8")
    config = load_configuration(path)

    class UnhealthyDocker(_FakeDocker):
        def doctor(self) -> BackendDoctorResult:
            return BackendDoctorResult(
                docker_cli=False,
                daemon_responding=False,
                linux_containers=False,
            )

    with pytest.raises(ConfigurationError, match="unavailable"):
        cli._workflow_plan(config, cast(DockerBackend, UnhealthyDocker()), yes=True)
    large_issue = tmp_path / "large-issue.txt"
    large_issue.write_bytes(b"x" * (64 * 1024 + 1))
    with pytest.raises(ConfigurationError, match="64 KiB"):
        cli._resolve_issue(config, None, large_issue)
    with pytest.raises(ConfigurationError, match="Could not read"):
        cli._resolve_issue(config, None, tmp_path / "missing.txt")
    with pytest.raises(ConfigurationError, match="nonempty"):
        cli._resolve_issue(config, "\0", None)

    receipt = SimpleNamespace(rejection_code="PP_AGENT_TIMEOUT")
    with pytest.raises(AgentError, match="Agent workflow failed"):
        cli._print_workflow_outcome(
            WorkflowOutcome(
                "pp_20260713_aaaaaaaaaaaa",
                RunState.REJECTED,
                cast(Any, receipt),
                tmp_path / "receipt.json",
                None,
            )
        )


def test_provider_credentials_fail_before_docker_is_contacted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "proofpatch.yml"
    path.write_text(_document(), encoding="utf-8")
    loaded = load_configuration(path)
    provider = loaded.agent.model_copy(
        update={
            "adapter": "codex",
            "command": ("codex",),
            "environment_allowlist": ("CODEX_API_KEY",),
        }
    )
    loaded = loaded.model_copy(update={"agent": provider})
    monkeypatch.delenv("CODEX_API_KEY", raising=False)

    class UntouchedDocker:
        def doctor(self) -> BackendDoctorResult:
            raise AssertionError("Docker must not be contacted before credential validation")

    with pytest.raises(ConfigurationError, match="CODEX_API_KEY"):
        cli._workflow_plan(loaded, cast(DockerBackend, UntouchedDocker()), yes=True)


def test_security_relevant_unsupported_configuration_fails_preflight(tmp_path: Path) -> None:
    path = tmp_path / "proofpatch.yml"
    path.write_text(_document(), encoding="utf-8")
    loaded = load_configuration(path)
    backend = cast(DockerBackend, _FakeDocker())
    variants = (
        loaded.model_copy(
            update={"runtime": loaded.runtime.model_copy(update={"dockerfile": "Dockerfile"})}
        ),
        loaded.model_copy(
            update={"runtime": loaded.runtime.model_copy(update={"platform": "linux/arm64"})}
        ),
        loaded.model_copy(
            update={"runtime": loaded.runtime.model_copy(update={"user": "1001:1001"})}
        ),
        loaded.model_copy(
            update={
                "verification": loaded.verification.model_copy(
                    update={"fail_on_test_deletion": True}
                )
            }
        ),
        loaded.model_copy(
            update={"apply": loaded.apply.model_copy(update={"branch_prefix": "other/"})}
        ),
        loaded.model_copy(
            update={"setup": loaded.setup.model_copy(update={"readonly_secret_files": ("token",)})}
        ),
        loaded.model_copy(
            update={"network": loaded.network.model_copy(update={"setup": "bridge"})}
        ),
        loaded.model_copy(
            update={
                "setup": loaded.setup.model_copy(
                    update={
                        "commands": (
                            SetupCommandConfig(
                                id="install",
                                argv=("python", "install.py"),
                                timeout_seconds=30.0,
                            ),
                        )
                    }
                )
            }
        ),
    )
    for variant in variants:
        with pytest.raises(ConfigurationError):
            cli._workflow_plan(variant, backend, yes=True)
