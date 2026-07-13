"""Constrained Codex CLI adapter based on the official noninteractive interface."""

from proofpatch.agents.base import (
    AgentConfiguration,
    AgentExitClassification,
    AgentInvocation,
    AgentPhaseContext,
    AgentVersionProbe,
)
from proofpatch.agents.claude import _validate_provider_configuration
from proofpatch.errors import ConfigurationError

CODEX_API_KEY = "CODEX_API_KEY"
MINIMUM_CODEX_VERSION = (0, 139, 0)
INVESTIGATION_OUTCOMES = (
    "/proofpatch/out/failure-contract.json",
    "/proofpatch/out/not-reproduced.json",
)
PATCH_OUTCOMES = ("/proofpatch/out/patch-result.json",)


class CodexAgentAdapter:
    """Invoke ``codex exec`` without persisted sessions or user configuration."""

    name = "codex"
    adapter_version = 1

    def validate_configuration(self, config: AgentConfiguration) -> None:
        _validate_provider_configuration(config, "Codex", CODEX_API_KEY)

    def required_secret_names(self, config: AgentConfiguration) -> set[str]:
        self.validate_configuration(config)
        return {CODEX_API_KEY}

    def build_version_probe(self, config: AgentConfiguration) -> AgentVersionProbe:
        self.validate_configuration(config)
        return AgentVersionProbe((*config.command, "--version"), MINIMUM_CODEX_VERSION)

    def build_investigation_invocation(
        self,
        config: AgentConfiguration,
        context: AgentPhaseContext,
    ) -> AgentInvocation:
        return self._build(config, context, "read-only", INVESTIGATION_OUTCOMES)

    def build_patch_invocation(
        self,
        config: AgentConfiguration,
        context: AgentPhaseContext,
    ) -> AgentInvocation:
        return self._build(config, context, "workspace-write", PATCH_OUTCOMES)

    def classify_exit(
        self,
        exit_code: int,
        stdout: str,
        stderr: str,
    ) -> AgentExitClassification:
        del stdout, stderr
        return (
            AgentExitClassification.SUCCEEDED if exit_code == 0 else AgentExitClassification.FAILED
        )

    def _build(
        self,
        config: AgentConfiguration,
        context: AgentPhaseContext,
        sandbox: str,
        outcomes: tuple[str, ...],
    ) -> AgentInvocation:
        self.validate_configuration(config)
        if set(context.environment) != {CODEX_API_KEY}:
            raise ConfigurationError("Codex received missing or non-allowlisted environment names")
        values = (
            context.prompt_path,
            context.workspace_path,
            context.output_path,
            context.reproduction_path,
            context.issue_path,
        )
        if any(not value or "\0" in value for value in values):
            raise ConfigurationError("Codex phase paths must be nonempty and NUL-free")
        argv = (
            *config.command,
            "exec",
            "--ephemeral",
            "--ignore-user-config",
            "--ignore-rules",
            "--json",
            "--color",
            "never",
            "--cd",
            context.workspace_path,
            "--sandbox",
            sandbox,
            f"Read and follow {context.prompt_path} exactly; write the required result files.",
        )
        return AgentInvocation(argv, dict(context.environment), None, outcomes)
