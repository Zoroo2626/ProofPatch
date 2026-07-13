"""Provider adapter contract tests based on current official CLI behavior."""

from collections.abc import Callable

import pytest

from proofpatch.agents.base import AgentConfiguration, AgentPhaseContext
from proofpatch.agents.claude import ClaudeAgentAdapter
from proofpatch.agents.codex import CodexAgentAdapter
from proofpatch.agents.registry import get_agent_adapter
from proofpatch.agents.versioning import parse_and_require_version
from proofpatch.errors import AgentError, ConfigurationError

FORBIDDEN = {
    "--add-dir",
    "--allow-dangerously-skip-permissions",
    "--dangerously-bypass-approvals-and-sandbox",
    "--dangerously-skip-permissions",
    "--privileged",
    "--yolo",
}


def _context(credential: str) -> AgentPhaseContext:
    return AgentPhaseContext(
        prompt_path="/proofpatch/prompt.md",
        workspace_path="/workspace",
        output_path="/proofpatch/out",
        reproduction_path="/proofpatch/repro",
        issue_path="/proofpatch/issue.md",
        environment={credential: "secret"},
    )


def test_claude_invocation_is_noninteractive_isolated_and_captured() -> None:
    adapter = ClaudeAgentAdapter()
    config = AgentConfiguration(("claude",), ("ANTHROPIC_API_KEY",))

    investigation = adapter.build_investigation_invocation(config, _context("ANTHROPIC_API_KEY"))
    patch = adapter.build_patch_invocation(config, _context("ANTHROPIC_API_KEY"))

    assert investigation.argv[:2] == ("claude", "--print")
    assert "--output-format" in investigation.argv
    assert investigation.argv[investigation.argv.index("--output-format") + 1] == "json"
    assert "--no-session-persistence" in investigation.argv
    assert "--bare" in investigation.argv
    assert "--system-prompt-file" in investigation.argv
    assert not FORBIDDEN.intersection(investigation.argv)
    assert patch.argv == investigation.argv
    assert adapter.required_secret_names(config) == {"ANTHROPIC_API_KEY"}
    assert adapter.build_version_probe(config).argv == ("claude", "--version")


def test_codex_invocation_is_ephemeral_config_free_and_phase_scoped() -> None:
    adapter = CodexAgentAdapter()
    config = AgentConfiguration(("codex",), ("CODEX_API_KEY",))

    investigation = adapter.build_investigation_invocation(config, _context("CODEX_API_KEY"))
    patch = adapter.build_patch_invocation(config, _context("CODEX_API_KEY"))

    assert investigation.argv[:2] == ("codex", "exec")
    assert {"--ephemeral", "--ignore-user-config", "--ignore-rules", "--json"}.issubset(
        investigation.argv
    )
    assert investigation.argv[investigation.argv.index("--sandbox") + 1] == "read-only"
    assert patch.argv[patch.argv.index("--sandbox") + 1] == "workspace-write"
    assert not FORBIDDEN.intersection(investigation.argv)
    assert not FORBIDDEN.intersection(patch.argv)
    assert adapter.required_secret_names(config) == {"CODEX_API_KEY"}
    assert adapter.build_version_probe(config).argv == ("codex", "--version")


@pytest.mark.parametrize(
    ("adapter", "credential"),
    [
        (ClaudeAgentAdapter(), "ANTHROPIC_API_KEY"),
        (CodexAgentAdapter(), "CODEX_API_KEY"),
    ],
)
def test_provider_configuration_cannot_inject_flags_or_credentials(
    adapter: ClaudeAgentAdapter | CodexAgentAdapter,
    credential: str,
) -> None:
    for config in (
        AgentConfiguration((adapter.name, "--dangerous"), (credential,)),
        AgentConfiguration((adapter.name,), ()),
        AgentConfiguration((adapter.name,), (credential, "HOME")),
    ):
        with pytest.raises(ConfigurationError):
            adapter.validate_configuration(config)
    with pytest.raises(ConfigurationError, match=r"missing|non-allowlisted"):
        adapter.build_patch_invocation(
            AgentConfiguration((adapter.name,), (credential,)),
            _context("OTHER_SECRET"),
        )


@pytest.mark.parametrize(
    ("output", "minimum", "expected"),
    [
        (b"2.1.201 (Claude Code)\n", (2, 1, 201), "2.1.201"),
        (b"codex-cli 0.139.0\n", (0, 139, 0), "0.139.0"),
    ],
)
def test_version_detection_parses_mock_cli_output(
    output: bytes,
    minimum: tuple[int, int, int],
    expected: str,
) -> None:
    detector: Callable[[bytes, bytes, tuple[int, int, int]], str] = parse_and_require_version
    assert detector(output, b"", minimum) == expected


@pytest.mark.parametrize(
    "output",
    [b"not a version", b"0.1.0 and 0.2.0", b"0.138.9", b"bad\0 0.139.0", b"x" * 4097],
)
def test_version_detection_fails_closed_on_mocked_bad_output(output: bytes) -> None:
    with pytest.raises(AgentError):
        parse_and_require_version(output, b"", (0, 139, 0))


def test_registry_exposes_only_reviewed_provider_adapters() -> None:
    assert isinstance(get_agent_adapter("claude"), ClaudeAgentAdapter)
    assert isinstance(get_agent_adapter("codex"), CodexAgentAdapter)
