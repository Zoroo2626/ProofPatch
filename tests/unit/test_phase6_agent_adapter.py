"""Phase 6 generic adapter and patch-result validation tests."""

import pytest
from pydantic import ValidationError

from proofpatch.agents.base import AgentConfiguration, AgentExitClassification, AgentPhaseContext
from proofpatch.agents.claude import ClaudeAgentAdapter
from proofpatch.agents.generic import GenericAgentAdapter, environment_from_allowlist
from proofpatch.agents.registry import get_agent_adapter
from proofpatch.errors import ConfigurationError
from proofpatch.models.agent import PatchResult


def _context() -> AgentPhaseContext:
    return AgentPhaseContext(
        prompt_path="/proofpatch/prompt.md",
        workspace_path="/workspace",
        output_path="/proofpatch/out",
        reproduction_path="/proofpatch/repro",
        issue_path="/proofpatch/issue.md",
        environment={"TOKEN": "secret"},
    )


def test_generic_adapter_expands_only_approved_placeholders() -> None:
    adapter = GenericAgentAdapter()
    config = AgentConfiguration(
        command=("fake-agent", "--prompt", "{prompt_path}", "--root={workspace_path}"),
        environment_allowlist=("TOKEN",),
    )

    investigation = adapter.build_investigation_invocation(config, _context())
    patch = adapter.build_patch_invocation(config, _context())

    assert investigation.argv == (
        "fake-agent",
        "--prompt",
        "/proofpatch/prompt.md",
        "--root=/workspace",
    )
    assert investigation.expected_contract_paths == (
        "/proofpatch/out/failure-contract.json",
        "/proofpatch/out/not-reproduced.json",
    )
    assert patch.expected_contract_paths == ("/proofpatch/out/patch-result.json",)
    assert patch.environment == {"TOKEN": "secret"}
    assert patch.stdin_text is None
    assert adapter.required_secret_names(config) == {"TOKEN"}
    assert adapter.classify_exit(0, "claim", "") is AgentExitClassification.SUCCEEDED
    assert adapter.classify_exit(2, "", "error") is AgentExitClassification.FAILED


@pytest.mark.parametrize(
    "command",
    [
        (),
        ("",),
        ("agent\0bad",),
        ("{unknown}",),
        ("{prompt_path!r}",),
        ("{prompt_path:>10}",),
        ("{broken",),
    ],
)
def test_generic_adapter_rejects_ambiguous_or_unsafe_commands(
    command: tuple[str, ...],
) -> None:
    with pytest.raises(ConfigurationError):
        GenericAgentAdapter().validate_configuration(AgentConfiguration(command=command))


def test_generic_adapter_rejects_environment_bypass_and_unavailable_adapters() -> None:
    adapter = GenericAgentAdapter()
    with pytest.raises(ConfigurationError, match="non-allowlisted"):
        adapter.build_patch_invocation(
            AgentConfiguration(command=("agent",)),
            _context(),
        )
    with pytest.raises(ConfigurationError, match="duplicates"):
        adapter.validate_configuration(
            AgentConfiguration(command=("agent",), environment_allowlist=("TOKEN", "TOKEN"))
        )
    with pytest.raises(ConfigurationError, match="invalid name"):
        adapter.validate_configuration(
            AgentConfiguration(command=("agent",), environment_allowlist=("BAD-NAME",))
        )
    assert isinstance(get_agent_adapter("generic"), GenericAgentAdapter)
    assert isinstance(get_agent_adapter("claude"), ClaudeAgentAdapter)
    with pytest.raises(ConfigurationError, match="not available"):
        get_agent_adapter("unknown")


def test_environment_selection_and_patch_result_are_strict() -> None:
    assert environment_from_allowlist(("A", "MISSING"), {"A": "1", "B": "2"}) == {"A": "1"}
    result = PatchResult(
        summary="Fixed behavior",
        root_cause="Incorrect constant",
        changed_files=("source.txt",),
        commands_run=(("pytest", "-q"),),
        known_risks=(),
    )
    assert result.schema_version == 1
    with pytest.raises(ValidationError):
        PatchResult.model_validate(
            {
                "summary": "claim",
                "root_cause": "cause",
                "changed_files": ["source.txt"],
                "commands_run": [[]],
                "known_risks": [],
            }
        )
    base = {
        "summary": "claim",
        "root_cause": "cause",
        "changed_files": ["source.txt"],
        "commands_run": [["pytest"]],
        "known_risks": [],
    }
    for changed in (
        {**base, "summary": "bad\0summary"},
        {**base, "changed_files": [""]},
        {**base, "commands_run": [["bad\0argument"]]},
    ):
        with pytest.raises(ValidationError):
            PatchResult.model_validate(changed)


def test_generic_adapter_rejects_excessive_command_and_bad_expansion() -> None:
    adapter = GenericAgentAdapter()
    with pytest.raises(ConfigurationError, match="too many"):
        adapter.validate_configuration(AgentConfiguration(command=("x",) * 257))
    context = _context()
    unsafe = AgentPhaseContext(
        prompt_path="bad\0path",
        workspace_path=context.workspace_path,
        output_path=context.output_path,
        reproduction_path=context.reproduction_path,
        issue_path=context.issue_path,
        environment={},
    )
    with pytest.raises(ConfigurationError, match="Expanded"):
        adapter.build_patch_invocation(
            AgentConfiguration(command=("{prompt_path}",)),
            unsafe,
        )
