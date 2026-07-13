"""Trust-minimized interfaces for noninteractive agent command adapters."""

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol


@dataclass(frozen=True, slots=True)
class AgentConfiguration:
    """Non-secret generic agent settings supplied by the user."""

    command: tuple[str, ...]
    environment_allowlist: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class AgentPhaseContext:
    """Controller paths and prompt content available to an adapter."""

    prompt_path: str
    workspace_path: str
    output_path: str
    reproduction_path: str
    issue_path: str
    environment: Mapping[str, str]


@dataclass(frozen=True, slots=True)
class AgentInvocation:
    """A shell-free invocation; adapters cannot influence container policy."""

    argv: tuple[str, ...]
    environment: Mapping[str, str]
    stdin_text: str | None
    expected_contract_paths: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class AgentVersionProbe:
    """A bounded, credential-free CLI version query executed by the controller."""

    argv: tuple[str, ...]
    minimum_version: tuple[int, int, int]
    agent_model: str = "unknown"


class AgentExitClassification(StrEnum):
    SUCCEEDED = "succeeded"
    FAILED = "failed"


class AgentAdapter(Protocol):
    name: str
    adapter_version: int

    def validate_configuration(self, config: AgentConfiguration) -> None: ...

    def required_secret_names(self, config: AgentConfiguration) -> set[str]: ...

    def build_version_probe(self, config: AgentConfiguration) -> AgentVersionProbe | None: ...

    def build_investigation_invocation(
        self,
        config: AgentConfiguration,
        context: AgentPhaseContext,
    ) -> AgentInvocation: ...

    def build_patch_invocation(
        self,
        config: AgentConfiguration,
        context: AgentPhaseContext,
    ) -> AgentInvocation: ...

    def classify_exit(
        self,
        exit_code: int,
        stdout: str,
        stderr: str,
    ) -> AgentExitClassification: ...
