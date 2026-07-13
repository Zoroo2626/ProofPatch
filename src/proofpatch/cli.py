"""Phase 0 command-line application foundation."""

import os
import re
import shlex
import stat
from collections.abc import Callable
from datetime import timedelta
from pathlib import Path
from typing import Annotated

import typer

from proofpatch import __version__
from proofpatch.agents.base import AgentConfiguration
from proofpatch.agents.generic import environment_from_allowlist
from proofpatch.backends.docker import DockerBackend
from proofpatch.constants import DISPLAY_NAME
from proofpatch.errors import AgentError, ConfigurationError, ProofPatchError, VerificationError
from proofpatch.exit_codes import ExitCode
from proofpatch.integrations.github import (
    GitHubReceiptExporter,
    append_github_environment_file,
    append_github_outputs,
)
from proofpatch.logging import configure_logging
from proofpatch.models.config import ProofPatchConfig, discover_configuration, load_configuration
from proofpatch.models.execution import (
    CommandOracleSpec,
    ExitCodeMatcherSpec,
    ExitCodeOperator,
    NetworkPolicy,
    OracleExpectation,
    ResourceLimits,
)
from proofpatch.models.run import RunStatus
from proofpatch.security.paths import validate_proofpatch_data_path
from proofpatch.services.cleanup import RunCleanupPlan, RunCleanupService
from proofpatch.services.configuration import validate_protected_configuration
from proofpatch.services.coordinator import RunCoordinator
from proofpatch.services.data_directories import get_app_directories
from proofpatch.services.diagnostics import DiagnosticLevel, DoctorReport, DoctorService
from proofpatch.services.evidence import canonical_json_bytes
from proofpatch.services.initialization import (
    InitMode,
    InitTemplate,
    initialize_repository,
)
from proofpatch.services.investigation import SetupCommand
from proofpatch.services.patching import PatchService
from proofpatch.services.receipt import ReceiptService
from proofpatch.services.verification import VerificationPlan, VerificationService
from proofpatch.services.workflow import WorkflowOutcome, WorkflowPlan, WorkflowService

app = typer.Typer(
    name="proofpatch",
    help="Independently verify explicit before-and-after claims for generated patches.",
    add_completion=False,
    no_args_is_help=True,
    context_settings={"help_option_names": ["-h", "--help"]},
)


def _print_version() -> None:
    typer.echo(f"{DISPLAY_NAME} {__version__}")


def _version_callback(value: bool) -> None:
    if value:
        _print_version()
        raise typer.Exit()


@app.callback()
def root(
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            callback=_version_callback,
            is_eager=True,
            help="Show the installed ProofPatch version and exit.",
        ),
    ] = False,
) -> None:
    """ProofPatch's deterministic host-controller CLI."""

    del version


@app.command("version")
def version_command() -> None:
    """Show the installed ProofPatch version."""

    _print_version()


@app.command("init")
def init_command(
    mode: Annotated[
        InitMode,
        typer.Option("--mode", help="Starter assurance mode: protected or observation."),
    ] = InitMode.PROTECTED,
    template: Annotated[
        InitTemplate | None,
        typer.Option(
            "--template",
            help="Starter runtime: python, node, or minimal; otherwise detect conservatively.",
        ),
    ] = None,
    force: Annotated[
        bool,
        typer.Option("--force", help="Replace an existing regular configuration file."),
    ] = False,
) -> None:
    """Create a deterministic, model-validated starter configuration."""

    result = initialize_repository(Path.cwd(), mode=mode, template=template, force=force)
    typer.echo(f"Created {result.path.name} ({result.mode.value}, {result.template.value})")
    typer.echo("Next: review the configuration, then run proofpatch doctor")


@app.command("doctor")
def doctor_command() -> None:
    """Check local protected-execution prerequisites without printing secret values."""

    report = DoctorService(get_app_directories()).check(Path.cwd())
    _print_doctor_report(report)
    if report.exit_code is not ExitCode.SUCCESS:
        raise typer.Exit(code=int(report.exit_code))


@app.command("list")
def list_command() -> None:
    """List evidence-backed runs, including runs missing from the metadata index."""

    statuses = _coordinator().list_runs()
    if not statuses:
        typer.echo("No runs found.")
        return
    for status in statuses:
        index_label = "current" if status.index_consistent else "stale"
        typer.echo(
            f"{status.manifest.run_id}  {status.state.value}  "
            f"{status.manifest.repository_id}  index={index_label}"
        )


@app.command("status")
def status_command(run_id: Annotated[str, typer.Argument(help="ProofPatch run ID.")]) -> None:
    """Verify and show the current state of one run."""

    _print_status(_coordinator().status(run_id))


@app.command("inspect")
def inspect_command(
    run_id: Annotated[str, typer.Argument(help="ProofPatch run ID.")],
    events: Annotated[
        bool,
        typer.Option("--events", help="Print every canonical evidence event."),
    ] = False,
    patch: Annotated[
        bool,
        typer.Option("--patch", help="Print integrity-checked patch metadata and changed paths."),
    ] = False,
    logs: Annotated[
        str | None,
        typer.Option(
            "--logs", help="Print persisted logs for investigation, patch, or verification."
        ),
    ] = None,
) -> None:
    """Verify a run and optionally print its complete evidence chain."""

    coordinator = _coordinator()
    status = coordinator.inspect(run_id)
    paths = coordinator.paths_for(run_id)
    if paths.receipt_json.exists() or paths.receipt_markdown.exists():
        ReceiptService(coordinator).verify(run_id)
    _print_status(status)
    if events:
        for event in status.events:
            typer.echo(canonical_json_bytes(event.model_dump(mode="json")).decode("utf-8"))
    if patch:
        patch_record = PatchService(coordinator).load_patch(run_id)
        typer.echo(canonical_json_bytes(patch_record.model_dump(mode="json")).decode("utf-8"))
    if logs is not None:
        _print_inspection_logs(coordinator, run_id, logs)


@app.command("receipt")
def receipt_command(
    run_id: Annotated[str, typer.Argument(help="ProofPatch run ID.")],
    output_format: Annotated[
        str,
        typer.Option("--format", help="Receipt format: markdown or json."),
    ] = "markdown",
    verify_integrity: Annotated[
        bool,
        typer.Option(
            "--verify-integrity",
            help="Explicitly request integrity verification (always performed).",
        ),
    ] = False,
) -> None:
    """Verify every receipt binding before printing the requested representation."""

    del verify_integrity
    coordinator = _coordinator()
    receipt = ReceiptService(coordinator).verify(run_id)
    if output_format == "json":
        typer.echo(canonical_json_bytes(receipt.model_dump(mode="json")).decode("utf-8"))
        return
    if output_format != "markdown":
        raise ConfigurationError("Receipt format must be 'markdown' or 'json'")
    paths = coordinator.paths_for(run_id)
    try:
        typer.echo(paths.receipt_markdown.read_text(encoding="utf-8"), nl=False)
    except OSError as error:
        raise ConfigurationError("Could not read the verified receipt Markdown") from error


@app.command("apply")
def apply_command(
    run_id: Annotated[str, typer.Argument(help="Verified ProofPatch run ID.")],
    stage: Annotated[
        bool,
        typer.Option("--stage", help="Stage the applied changes after successful application."),
    ] = False,
) -> None:
    """Apply an evidence-bound VERIFIED patch on a new ProofPatch branch."""

    result = _patch_service().apply_verified(run_id, stage=stage)
    typer.echo(f"Applied {run_id} on branch {result.branch}")
    typer.echo(f"Patch SHA-256: {result.patch_sha256}")
    typer.echo("Changed paths:")
    for change in result.changed_files:
        if change.old_path is None:
            typer.echo(f"  {change.status.value}  {change.path}")
        else:
            typer.echo(f"  {change.status.value}  {change.old_path} -> {change.path}")
    typer.echo("Changes are staged." if stage else "Changes are left unstaged.")


@app.command("run")
def run_command(
    context: typer.Context,
    repository: Annotated[
        Path,
        typer.Option(
            "--repository",
            exists=True,
            file_okay=False,
            dir_okay=True,
            resolve_path=True,
            help="Clean baseline Git repository.",
        ),
    ] = Path("."),
    config: Annotated[
        Path | None,
        typer.Option("--config", file_okay=True, dir_okay=False, resolve_path=True),
    ] = None,
    issue: Annotated[str | None, typer.Option("--issue", help="Reported issue text.")] = None,
    issue_file: Annotated[
        Path | None,
        typer.Option("--issue-file", file_okay=True, dir_okay=False, resolve_path=True),
    ] = None,
    agent: Annotated[str | None, typer.Option("--agent", help="Agent adapter name.")] = None,
    mode: Annotated[
        InitMode,
        typer.Option("--mode", help="Execution assurance mode: protected or observation."),
    ] = InitMode.PROTECTED,
    yes: Annotated[
        bool,
        typer.Option(
            "--yes",
            help="Confirm configured secret forwarding and agent network access.",
        ),
    ] = False,
    keep_workspaces: Annotated[
        bool,
        typer.Option("--keep-workspaces", help="Retain disposable workspaces after completion."),
    ] = False,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Print the final workflow result as canonical JSON."),
    ] = False,
    verbose: Annotated[
        bool,
        typer.Option("--verbose", help="Enable verbose ProofPatch controller logs."),
    ] = False,
    no_color: Annotated[
        bool,
        typer.Option("--no-color", help="Disable terminal color output."),
    ] = False,
) -> None:
    """Run investigation, reproduction, patching, and fresh protected verification."""

    if mode is not InitMode.PROTECTED:
        raise ConfigurationError("The full workflow requires protected mode")
    if no_color or json_output:
        context.color = False
    configure_logging(verbose=verbose, json_output=json_output)
    selected = discover_configuration(repository) if config is None else config
    loaded = load_configuration(selected)
    if agent is not None:
        from proofpatch.agents.registry import get_agent_adapter

        get_agent_adapter(agent)
        loaded = loaded.model_copy(
            update={"agent": loaded.agent.model_copy(update={"adapter": agent})}
        )
    if keep_workspaces:
        loaded = loaded.model_copy(
            update={"evidence": loaded.evidence.model_copy(update={"retain_workspaces": True})}
        )
    issue_summary = _resolve_issue(loaded, issue, issue_file)
    backend = DockerBackend()
    plan = _workflow_plan(loaded, backend, yes=yes)
    outcome = WorkflowService(_coordinator(), backend).run(repository, issue_summary, plan)
    _print_workflow_outcome(outcome, json_output=json_output)


@app.command("resume")
def resume_command(
    run_id: Annotated[str, typer.Argument(help="Interrupted ProofPatch run ID.")],
    config: Annotated[
        Path | None,
        typer.Option("--config", file_okay=True, dir_okay=False, resolve_path=True),
    ] = None,
    capture_surviving_patch: Annotated[
        bool,
        typer.Option(
            "--capture-surviving-patch",
            help="Explicitly confirm capture of an interrupted patch workspace.",
        ),
    ] = False,
    yes: Annotated[
        bool,
        typer.Option(
            "--yes",
            help="Confirm configured secret forwarding and agent network access.",
        ),
    ] = False,
) -> None:
    """Resume from a safe evidence-backed Phase 6 checkpoint."""

    coordinator = _coordinator()
    status = coordinator.status(run_id)
    repository = Path(status.manifest.repository_root)
    selected = discover_configuration(repository) if config is None else config
    backend = DockerBackend()
    plan = _workflow_plan(load_configuration(selected), backend, yes=yes)
    outcome = WorkflowService(coordinator, backend).resume(
        run_id,
        plan,
        capture_surviving_patch=capture_surviving_patch,
    )
    _print_workflow_outcome(outcome)


@app.command("abort")
def abort_command(run_id: Annotated[str, typer.Argument(help="Active ProofPatch run ID.")]) -> None:
    """Stop known protected executions and mark an active run aborted."""

    state = WorkflowService(_coordinator(), DockerBackend()).abort(run_id)
    typer.echo(f"Run {run_id}: {state.value}")


@app.command("clean")
def clean_command(
    run_id: Annotated[
        str | None,
        typer.Argument(help="Terminal ProofPatch run ID to clean."),
    ] = None,
    completed: Annotated[
        bool,
        typer.Option("--completed", help="Select completed runs older than the requested age."),
    ] = False,
    older_than: Annotated[
        str | None,
        typer.Option("--older-than", help="Minimum completed age, such as 30d, 12h, or 45m."),
    ] = None,
    yes: Annotated[
        bool,
        typer.Option("--yes", help="Perform the displayed cleanup without a preview-only run."),
    ] = False,
) -> None:
    """Preview or clean disposable workspaces from evidence-verified terminal runs."""

    if (run_id is None) == (not completed):
        raise ConfigurationError("Choose either one run ID or --completed")
    service = RunCleanupService(_coordinator())
    if run_id is not None:
        if older_than is not None:
            raise ConfigurationError("--older-than is valid only with --completed")
        plan = service.clean(run_id) if yes else service.preview(run_id)
        _print_cleanup_plan(plan, executed=yes)
        return
    if older_than is None:
        raise ConfigurationError("--completed requires --older-than")
    age = _parse_duration(older_than)
    statuses = service.completed_before(age)
    if not statuses:
        typer.echo("No completed runs matched the requested age.")
        return
    for status in statuses:
        plan = (
            service.clean(status.manifest.run_id)
            if yes
            else service.preview(status.manifest.run_id)
        )
        _print_cleanup_plan(plan, executed=yes)


@app.command("verify-patch")
def verify_patch_command(
    baseline_command: Annotated[
        str,
        typer.Option(
            "--baseline-command",
            help="Reproduction command expected to fail before and pass after the patch.",
        ),
    ],
    patch_file: Annotated[
        Path,
        typer.Option(
            "--patch-file",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            resolve_path=True,
            help="Candidate Git patch to verify independently.",
        ),
    ],
    repository: Annotated[
        Path,
        typer.Option(
            "--repository",
            exists=True,
            file_okay=False,
            dir_okay=True,
            resolve_path=True,
            help="Clean baseline Git repository.",
        ),
    ] = Path("."),
    regression_command: Annotated[
        list[str] | None,
        typer.Option(
            "--regression-command",
            help="Required passing regression command; repeat for multiple commands.",
        ),
    ] = None,
    timeout_seconds: Annotated[
        float,
        typer.Option(
            "--timeout-seconds",
            min=0.001,
            max=86400,
            help="Timeout for each oracle command.",
        ),
    ] = 120.0,
    output_mb: Annotated[
        int,
        typer.Option(
            "--output-mb",
            min=1,
            max=1024,
            help="Combined stdout/stderr limit per command.",
        ),
    ] = 25,
    issue_summary: Annotated[
        str,
        typer.Option("--issue-summary", help="Exact claim this verification is observing."),
    ] = "Candidate patch failure-to-success transition",
    github_artifact_directory: Annotated[
        Path | None,
        typer.Option(
            "--github-artifact-directory",
            file_okay=False,
            dir_okay=True,
            resolve_path=False,
            help="Create a new receipt-only artifact directory for GitHub Actions.",
        ),
    ] = None,
    github_summary_file: Annotated[
        Path | None,
        typer.Option(
            "--github-summary-file",
            file_okay=True,
            dir_okay=False,
            resolve_path=False,
            help="Append the sanitized result to the GitHub job-summary environment file.",
        ),
    ] = None,
    github_output_file: Annotated[
        Path | None,
        typer.Option(
            "--github-output-file",
            file_okay=True,
            dir_okay=False,
            resolve_path=False,
            help="Append stable outputs to the GitHub action-output environment file.",
        ),
    ] = None,
) -> None:
    """Observe a failure-to-success transition in independent native clones."""

    reproduction = CommandOracleSpec(
        id="reproduction",
        argv=_parse_command(baseline_command),
        timeout_seconds=timeout_seconds,
        baseline_expectation=OracleExpectation(
            exit_code=ExitCodeMatcherSpec(operator=ExitCodeOperator.NOT_EQUAL, value=0)
        ),
        fixed_expectation=OracleExpectation(
            exit_code=ExitCodeMatcherSpec(operator=ExitCodeOperator.EQUAL, value=0)
        ),
    )
    regressions = tuple(
        CommandOracleSpec(
            id=f"regression-{index}",
            argv=_parse_command(command),
            timeout_seconds=timeout_seconds,
            expectation=OracleExpectation(
                exit_code=ExitCodeMatcherSpec(operator=ExitCodeOperator.EQUAL, value=0)
            ),
        )
        for index, command in enumerate(regression_command or (), start=1)
    )
    outcome = _verification_service().verify_patch(
        repository,
        patch_file,
        VerificationPlan(
            reproduction=reproduction,
            regressions=regressions,
            maximum_output_bytes=output_mb * 1024 * 1024,
        ),
        issue_summary=issue_summary,
    )
    if (
        github_artifact_directory is not None
        or github_summary_file is not None
        or github_output_file is not None
    ):
        if (
            github_artifact_directory is None
            or github_summary_file is None
            or github_output_file is None
        ):
            raise ConfigurationError("All three GitHub publication paths must be provided together")
        exported = GitHubReceiptExporter(_coordinator()).export(
            outcome.receipt.run_id,
            github_artifact_directory,
        )
        append_github_environment_file(github_summary_file, exported.summary)
        append_github_outputs(github_output_file, exported)
    typer.echo(f"Receipt: {outcome.json_path}")
    typer.echo("Protection: OBSERVATION ONLY (native execution)")
    if not outcome.verified:
        raise VerificationError(
            f"Patch was rejected: {outcome.receipt.rejection_code}",
            remediation=f"Inspect the receipt at {outcome.json_path}",
        )
    typer.echo("Observed transition: baseline failure -> patched success")


def main() -> None:
    """Run the CLI and map typed application errors to stable exit codes."""

    _run_application(app)


def _run_application(application: Callable[[], object]) -> None:
    """Run a CLI application with stable handling for expected errors."""

    try:
        application()
    except KeyboardInterrupt:
        typer.echo("Error [PP_INTERRUPTED]: Operation interrupted.", err=True)
        raise SystemExit(int(ExitCode.INTERRUPTED)) from None
    except SystemExit as error:
        if error.code == 130:
            typer.echo("Error [PP_INTERRUPTED]: Operation interrupted.", err=True)
            raise SystemExit(int(ExitCode.INTERRUPTED)) from None
        raise
    except ProofPatchError as error:
        typer.echo(f"Error [{error.error_code}]: {error.message}", err=True)
        if error.remediation is not None:
            typer.echo(f"Remediation: {error.remediation}", err=True)
        raise SystemExit(int(error.exit_code)) from None


def _coordinator() -> RunCoordinator:
    try:
        directories = get_app_directories()
        return RunCoordinator(directories)
    except ValueError as error:
        raise ConfigurationError(str(error)) from error


def _patch_service() -> PatchService:
    """Build the Phase 2 service from the same validated application directories."""

    return PatchService(_coordinator())


def _verification_service() -> VerificationService:
    return VerificationService(_coordinator())


def _workflow_plan(
    config: ProofPatchConfig,
    backend: DockerBackend,
    *,
    yes: bool,
) -> WorkflowPlan:
    """Resolve immutable images and convert validated non-secret configuration."""

    from proofpatch.agents.registry import get_agent_adapter

    validate_protected_configuration(config)
    agent_configuration = AgentConfiguration(
        command=config.agent.command,
        environment_allowlist=config.agent.environment_allowlist,
    )
    adapter = get_agent_adapter(config.agent.adapter)
    adapter.validate_configuration(agent_configuration)
    agent_environment = environment_from_allowlist(
        config.agent.environment_allowlist,
        os.environ,
    )
    missing_credentials = adapter.required_secret_names(agent_configuration).difference(
        agent_environment
    )
    if adapter.name != "generic" and missing_credentials:
        raise ConfigurationError(
            "Required agent credentials are missing: " + ", ".join(sorted(missing_credentials)),
            remediation="Set the documented provider API key in the ProofPatch process.",
        )
    if not backend.doctor().healthy:
        raise ConfigurationError("Docker protected mode is unavailable")
    broad_agent_network = (
        config.network.investigation == "bridge" or config.network.patch == "bridge"
    )
    if (config.agent.environment_allowlist or broad_agent_network) and not yes:
        raise ConfigurationError(
            "Confirmation is required before forwarding agent secrets or enabling network access",
            remediation="Review the configuration and pass --yes to confirm.",
        )
    runtime_image = backend.resolve_image(config.runtime.image)
    agent_image = (
        runtime_image
        if config.agent.image is None or config.agent.image == config.runtime.image
        else backend.resolve_image(config.agent.image)
    )
    limits = config.runtime.limits
    output_bytes = min(limits.output_mb, config.evidence.maximum_log_mb) * 1024 * 1024

    def resources(timeout_seconds: float) -> ResourceLimits:
        return ResourceLimits(
            timeout_seconds=timeout_seconds,
            memory_mb=limits.memory_mb,
            cpus=limits.cpus,
            pids=limits.pids,
            output_bytes=output_bytes,
        )

    regressions = tuple(
        CommandOracleSpec(
            id=oracle.id,
            argv=oracle.argv,
            cwd=oracle.cwd,
            timeout_seconds=oracle.timeout_seconds,
            environment=oracle.environment,
            expectation=OracleExpectation(
                exit_code=ExitCodeMatcherSpec(
                    operator=ExitCodeOperator.EQUAL,
                    value=oracle.expect.exit_code,
                )
            ),
        )
        for oracle in config.oracles.regressions
    )
    setup = tuple(
        SetupCommand(command.id, command.argv, command.timeout_seconds)
        for command in config.setup.commands
    )
    return WorkflowPlan(
        agent=agent_configuration,
        agent_image=agent_image,
        verifier_image=runtime_image,
        investigation_resources=resources(config.agent.investigation_timeout_seconds),
        patch_resources=resources(config.agent.patch_timeout_seconds),
        verifier_resources=resources(limits.timeout_seconds),
        agent_environment=agent_environment,
        adapter_name=config.agent.adapter,
        setup_commands=setup,
        setup_environment=config.setup.environment,
        regressions=regressions,
        allowed_patch_paths=config.repository.allowed_patch_paths,
        denied_patch_paths=config.repository.denied_patch_paths,
        maximum_patch_bytes=config.repository.maximum_patch_size_mb * 1024 * 1024,
        maximum_changed_files=config.repository.maximum_changed_files,
        maximum_repository_bytes=config.repository.maximum_size_mb * 1024 * 1024,
        maximum_attempts=config.agent.maximum_attempts,
        flag_test_changes=config.verification.flag_test_changes,
        retain_workspaces=config.evidence.retain_workspaces,
        project_name=config.project.name,
        investigation_network=NetworkPolicy(config.network.investigation),
        patch_network=NetworkPolicy(config.network.patch),
        setup_network=NetworkPolicy(config.network.setup),
    )


def _resolve_issue(
    config: ProofPatchConfig,
    issue: str | None,
    issue_file: Path | None,
) -> str:
    if issue is not None and issue_file is not None:
        raise ConfigurationError("Use either --issue or --issue-file, not both")
    if issue_file is not None:
        try:
            if issue_file.stat().st_size > 64 * 1024:
                raise ConfigurationError("Issue file exceeds the 64 KiB size limit")
            selected = issue_file.read_text(encoding="utf-8")
        except OSError as error:
            raise ConfigurationError(f"Could not read issue file: {issue_file}") from error
    elif issue is not None:
        selected = issue
    elif config.issue.text is not None:
        selected = config.issue.text
    else:
        raise ConfigurationError("An issue is required via --issue, --issue-file, or config")
    selected = selected.strip()
    if not selected or len(selected) > 4096 or "\0" in selected:
        raise ConfigurationError("Issue text must be nonempty, bounded, and NUL-free")
    return selected


def _print_workflow_outcome(
    outcome: WorkflowOutcome,
    *,
    json_output: bool = False,
) -> None:
    rejection_code = outcome.receipt.rejection_code if outcome.receipt is not None else None
    if json_output:
        typer.echo(
            canonical_json_bytes(
                {
                    "protection_level": "protected",
                    "receipt": str(outcome.receipt_json)
                    if outcome.receipt_json is not None
                    else None,
                    "rejection_code": rejection_code,
                    "run_id": outcome.run_id,
                    "state": outcome.state.value,
                    "verified": outcome.verified,
                }
            ).decode("utf-8")
        )
        if not outcome.verified:
            if rejection_code in {"PP_AGENT_FAILED", "PP_AGENT_TIMEOUT"}:
                raise AgentError(f"Agent workflow failed: {rejection_code}")
            raise VerificationError(f"Patch was not verified: {rejection_code or 'unknown'}")
        return
    typer.echo(f"Run: {outcome.run_id}")
    typer.echo(f"State: {outcome.state.value}")
    if outcome.receipt_json is not None:
        typer.echo(f"Receipt: {outcome.receipt_json}")
    if not outcome.verified:
        code = rejection_code or "unknown"
        if code in {"PP_AGENT_FAILED", "PP_AGENT_TIMEOUT"}:
            raise AgentError(f"Agent workflow failed: {code}")
        raise VerificationError(f"Patch was not verified: {code}")
    typer.echo("Observed transition: baseline failure -> patched success")
    typer.echo("Protection: PROTECTED")


def _parse_command(value: str) -> tuple[str, ...]:
    try:
        argv = tuple(shlex.split(value, posix=True))
    except ValueError as error:
        raise ConfigurationError(f"Command could not be parsed: {error}") from error
    if not argv:
        raise ConfigurationError("Command must not be empty")
    return argv


def _print_status(status: RunStatus) -> None:
    index_label = "current" if status.index_consistent else "stale"
    typer.echo(f"Run: {status.manifest.run_id}")
    typer.echo(f"Repository: {status.manifest.repository_id}")
    typer.echo(f"State: {status.state.value}")
    typer.echo(f"Events: {status.event_count}")
    typer.echo(f"Final event hash: {status.final_event_hash}")
    typer.echo(f"Metadata index: {index_label}")


def _print_doctor_report(report: DoctorReport) -> None:
    for level in DiagnosticLevel:
        typer.echo(f"{level.value}:")
        matching = tuple(check for check in report.checks if check.level is level)
        if not matching:
            typer.echo("  (none)")
        for check in matching:
            typer.echo(f"  {check.name}: {check.message}")


def _print_cleanup_plan(plan: RunCleanupPlan, *, executed: bool) -> None:
    verb = "Cleaned" if executed else "Would clean"
    targets = ", ".join(target.path.name for target in plan.targets) or "no disposable workspaces"
    typer.echo(f"{verb} {plan.run_id} ({plan.state.value}): {targets}")


def _parse_duration(value: str) -> timedelta:
    matched = re.fullmatch(r"([1-9][0-9]*)([smhdw])", value)
    if matched is None:
        raise ConfigurationError("Duration must be a positive integer followed by s, m, h, d, or w")
    amount = int(matched.group(1))
    unit = matched.group(2)
    seconds = amount * {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}[unit]
    if seconds > 10 * 365 * 86400:
        raise ConfigurationError("Cleanup duration cannot exceed ten years")
    return timedelta(seconds=seconds)


def _print_inspection_logs(coordinator: RunCoordinator, run_id: str, category: str) -> None:
    paths = coordinator.paths_for(run_id)
    roots = {
        "investigation": paths.investigation,
        "patch": paths.patch,
        "verification": paths.verification,
    }
    root = roots.get(category)
    if root is None:
        raise ConfigurationError("Log category must be investigation, patch, or verification")
    if not root.exists():
        typer.echo(f"No persisted {category} logs found.")
        return
    validate_proofpatch_data_path(coordinator.directories.data, root)
    logs: list[Path] = []
    for directory, names, files in os.walk(
        root,
        topdown=True,
        onerror=_raise_log_walk_error,
        followlinks=False,
    ):
        parent = Path(directory)
        for name in (*names, *files):
            candidate = parent / name
            try:
                status = candidate.lstat()
            except OSError as error:
                raise ConfigurationError("Could not safely inspect persisted logs") from error
            attributes = getattr(status, "st_file_attributes", 0)
            reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
            if stat.S_ISLNK(status.st_mode) or bool(attributes & reparse):
                raise ConfigurationError("Persisted log tree contains an unsafe linked path")
        logs.extend(parent / name for name in files if name.endswith(".log"))
    if not logs:
        typer.echo(f"No persisted {category} logs found.")
        return
    remaining = 8 * 1024 * 1024
    for path in sorted(logs):
        relative = path.relative_to(paths.root).as_posix()
        content = _read_inspection_log(path, remaining)
        remaining -= len(content)
        typer.echo(f"== {relative} ==")
        typer.echo(content.decode("utf-8", errors="replace"), nl=not content.endswith(b"\n"))


def _read_inspection_log(path: Path, maximum_bytes: int) -> bytes:
    if maximum_bytes <= 0:
        raise ConfigurationError("Persisted logs exceed the 8 MiB inspection limit")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        current = path.lstat()
        attributes = getattr(current, "st_file_attributes", 0)
        reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or stat.S_ISLNK(current.st_mode)
            or bool(attributes & reparse)
            or (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino)
        ):
            raise ConfigurationError("Persisted log is not a private regular file")
        content = bytearray()
        while chunk := os.read(descriptor, min(64 * 1024, maximum_bytes + 1 - len(content))):
            content.extend(chunk)
            if len(content) > maximum_bytes:
                raise ConfigurationError("Persisted logs exceed the 8 MiB inspection limit")
        return bytes(content)
    except ConfigurationError:
        raise
    except OSError as error:
        raise ConfigurationError("Could not safely read a persisted log") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _raise_log_walk_error(error: OSError) -> None:
    raise ConfigurationError("Could not safely inspect persisted logs") from error
