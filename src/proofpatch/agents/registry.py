"""Closed registry of reviewed agent adapters."""

from proofpatch.agents.base import AgentAdapter
from proofpatch.agents.claude import ClaudeAgentAdapter
from proofpatch.agents.codex import CodexAgentAdapter
from proofpatch.agents.generic import GenericAgentAdapter
from proofpatch.errors import ConfigurationError


def get_agent_adapter(name: str) -> AgentAdapter:
    """Return only reviewed adapters; unknown names fail closed."""

    if name == "generic":
        return GenericAgentAdapter()
    if name == "claude":
        return ClaudeAgentAdapter()
    if name == "codex":
        return CodexAgentAdapter()
    raise ConfigurationError(
        f"Agent adapter is not available in this release: {name}",
        remediation="Select generic, claude, or codex.",
    )
