"""Strict generic adapter for user-configured noninteractive commands."""

import string
from collections.abc import Mapping

from proofpatch.agents.base import (
    AgentConfiguration,
    AgentExitClassification,
    AgentInvocation,
    AgentPhaseContext,
    AgentVersionProbe,
)
from proofpatch.errors import ConfigurationError
from proofpatch.models.execution import ENVIRONMENT_NAME

APPROVED_PLACEHOLDERS = frozenset(
    {
        "prompt_path",
        "workspace_path",
        "output_path",
        "reproduction_path",
        "issue_path",
    }
)
INVESTIGATION_OUTCOMES = (
    "/proofpatch/out/failure-contract.json",
    "/proofpatch/out/not-reproduced.json",
)
PATCH_OUTCOMES = ("/proofpatch/out/patch-result.json",)


class GenericAgentAdapter:
    """Expand only documented path placeholders into a structured argv."""

    name = "generic"
    adapter_version = 1

    def validate_configuration(self, config: AgentConfiguration) -> None:
        if not config.command:
            raise ConfigurationError("Generic agent command must not be empty")
        if len(config.command) > 256:
            raise ConfigurationError("Generic agent command has too many arguments")
        if len(config.environment_allowlist) != len(set(config.environment_allowlist)):
            raise ConfigurationError("Agent environment allowlist contains duplicates")
        if any(ENVIRONMENT_NAME.fullmatch(name) is None for name in config.environment_allowlist):
            raise ConfigurationError("Agent environment allowlist contains an invalid name")
        for argument in config.command:
            if not argument or "\0" in argument:
                raise ConfigurationError("Agent command arguments must be nonempty and NUL-free")
            self._validate_template(argument)

    def required_secret_names(self, config: AgentConfiguration) -> set[str]:
        self.validate_configuration(config)
        return set(config.environment_allowlist)

    def build_version_probe(self, config: AgentConfiguration) -> AgentVersionProbe | None:
        self.validate_configuration(config)
        return None

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
        values = {
            "prompt_path": context.prompt_path,
            "workspace_path": context.workspace_path,
            "output_path": context.output_path,
            "reproduction_path": context.reproduction_path,
            "issue_path": context.issue_path,
        }
        argv = tuple(argument.format_map(values) for argument in config.command)
        if any(not argument or "\0" in argument for argument in argv):
            raise ConfigurationError("Expanded agent command is invalid")
        unexpected = set(context.environment).difference(config.environment_allowlist)
        if unexpected:
            raise ConfigurationError(
                "Agent environment contains non-allowlisted names: " + ", ".join(sorted(unexpected))
            )
        return AgentInvocation(argv, dict(context.environment), None, outcomes)

    @staticmethod
    def _validate_template(value: str) -> None:
        try:
            parsed = tuple(string.Formatter().parse(value))
        except ValueError as error:
            raise ConfigurationError("Agent command contains malformed placeholders") from error
        for _, field, format_spec, conversion in parsed:
            if field is None:
                continue
            if field not in APPROVED_PLACEHOLDERS:
                raise ConfigurationError(f"Unknown agent command placeholder: {{{field}}}")
            if format_spec or conversion:
                raise ConfigurationError("Agent command placeholders cannot use formatting")


def environment_from_allowlist(
    allowlist: tuple[str, ...],
    source: Mapping[str, str],
) -> dict[str, str]:
    """Select values by exact configured names without persisting absent values."""

    return {name: source[name] for name in allowlist if name in source}
