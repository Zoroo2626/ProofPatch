"""Constrained Claude Code CLI adapter based on the official noninteractive interface."""

from proofpatch.agents.base import (
    AgentConfiguration,
    AgentExitClassification,
    AgentInvocation,
    AgentPhaseContext,
    AgentVersionProbe,
)
from proofpatch.errors import ConfigurationError

CLAUDE_API_KEY = "ANTHROPIC_API_KEY"
MINIMUM_CLAUDE_VERSION = (2, 1, 201)
INVESTIGATION_OUTCOMES = (
    "/proofpatch/out/failure-contract.json",
    "/proofpatch/out/not-reproduced.json",
)
PATCH_OUTCOMES = ("/proofpatch/out/patch-result.json",)


class ClaudeAgentAdapter:
    """Invoke Claude without sessions, host settings, MCP, or permission bypasses."""

    name = "claude"
    adapter_version = 1

    def validate_configuration(self, config: AgentConfiguration) -> None:
        _validate_provider_configuration(config, "Claude", CLAUDE_API_KEY)

    def required_secret_names(self, config: AgentConfiguration) -> set[str]:
        self.validate_configuration(config)
        return {CLAUDE_API_KEY}

    def build_version_probe(self, config: AgentConfiguration) -> AgentVersionProbe:
        self.validate_configuration(config)
        return AgentVersionProbe((*config.command, "--version"), MINIMUM_CLAUDE_VERSION)

    def build_investigation_invocation(
        self,
        config: AgentConfiguration,
        context: AgentPhaseContext,
    ) -> AgentInvocation:
        return self._build(config, context, INVESTIGATION_OUTCOMES)

    def build_patch_invocation(
        self,
        config: AgentConfiguration,
        context: AgentPhaseContext,
    ) -> AgentInvocation:
        return self._build(config, context, PATCH_OUTCOMES)

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
        outcomes: tuple[str, ...],
    ) -> AgentInvocation:
        self.validate_configuration(config)
        _validate_context(context)
        argv = (
            *config.command,
            "--print",
            "--output-format",
            "json",
            "--input-format",
            "text",
            "--no-session-persistence",
            "--bare",
            "--permission-mode",
            "acceptEdits",
            "--system-prompt-file",
            context.prompt_path,
            "Follow the ProofPatch system prompt and write the required result files.",
        )
        return AgentInvocation(argv, dict(context.environment), None, outcomes)


def _validate_provider_configuration(
    config: AgentConfiguration,
    provider: str,
    credential_name: str,
) -> None:
    if len(config.command) != 1 or not config.command[0] or "\0" in config.command[0]:
        raise ConfigurationError(
            f"{provider} command must contain only its executable",
            remediation=(
                "Remove all provider CLI flags; ProofPatch supplies a fixed safe invocation."
            ),
        )
    if config.command[0].startswith("-"):
        raise ConfigurationError(f"{provider} executable cannot begin with a flag prefix")
    if config.environment_allowlist != (credential_name,):
        raise ConfigurationError(
            f"{provider} requires exactly the {credential_name} credential allowlist"
        )


def _validate_context(context: AgentPhaseContext) -> None:
    if set(context.environment) != {CLAUDE_API_KEY}:
        raise ConfigurationError("Claude received missing or non-allowlisted environment names")
    values = (
        context.prompt_path,
        context.workspace_path,
        context.output_path,
        context.reproduction_path,
        context.issue_path,
    )
    if any(not value or "\0" in value for value in values):
        raise ConfigurationError("Claude phase paths must be nonempty and NUL-free")
