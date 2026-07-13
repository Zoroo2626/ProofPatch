"""Guard the Phase 0 repository and CI security foundation."""

import re
from pathlib import Path

import pytest
import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[2]

REQUIRED_LAYOUT_DIRECTORIES = (
    "examples/python-bug",
    "examples/node-bug",
    "tests/unit",
    "tests/integration",
    "tests/e2e",
    "tests/adversarial",
    "tests/fixtures/repos",
    "tests/fixtures/contracts",
    "tests/fixtures/agents",
)

REQUIRED_LAYOUT_FILES = (
    ".github/ISSUE_TEMPLATE/bug.yml",
    ".github/ISSUE_TEMPLATE/feature.yml",
    ".github/workflows/ci.yml",
    ".github/workflows/docker-e2e.yml",
    ".github/workflows/release.yml",
    "docs/architecture.md",
    "docs/security.md",
    "docs/threat-model.md",
    "docs/adapter-development.md",
    "docs/oracle-development.md",
    "docs/decisions/0001-python-core.md",
    "docs/decisions/0002-docker-protected-backend.md",
    "docs/decisions/0003-independent-clones.md",
    "docs/decisions/0004-hash-chained-evidence.md",
    "examples/proofpatch.python.yml",
    "examples/proofpatch.node.yml",
    "src/proofpatch/__init__.py",
    "src/proofpatch/__main__.py",
    "src/proofpatch/cli.py",
    "src/proofpatch/constants.py",
    "src/proofpatch/errors.py",
    "src/proofpatch/exit_codes.py",
    "src/proofpatch/logging.py",
    "src/proofpatch/models/config.py",
    "src/proofpatch/models/contract.py",
    "src/proofpatch/models/events.py",
    "src/proofpatch/models/execution.py",
    "src/proofpatch/models/patch.py",
    "src/proofpatch/models/receipt.py",
    "src/proofpatch/models/run.py",
    "src/proofpatch/models/state.py",
    "src/proofpatch/services/coordinator.py",
    "src/proofpatch/services/doctor.py",
    "src/proofpatch/services/evidence.py",
    "src/proofpatch/services/repository.py",
    "src/proofpatch/services/patching.py",
    "src/proofpatch/services/verification.py",
    "src/proofpatch/services/policy.py",
    "src/proofpatch/services/receipt.py",
    "src/proofpatch/services/cleanup.py",
    "src/proofpatch/services/locks.py",
    "src/proofpatch/backends/base.py",
    "src/proofpatch/backends/docker.py",
    "src/proofpatch/backends/native.py",
    "src/proofpatch/agents/base.py",
    "src/proofpatch/agents/generic.py",
    "src/proofpatch/agents/claude.py",
    "src/proofpatch/agents/codex.py",
    "src/proofpatch/agents/registry.py",
    "src/proofpatch/oracles/base.py",
    "src/proofpatch/oracles/command.py",
    "src/proofpatch/oracles/matchers.py",
    "src/proofpatch/oracles/registry.py",
    "src/proofpatch/git/client.py",
    "src/proofpatch/git/clone.py",
    "src/proofpatch/git/diff.py",
    "src/proofpatch/git/apply.py",
    "src/proofpatch/execution/process.py",
    "src/proofpatch/execution/output.py",
    "src/proofpatch/execution/timeout.py",
    "src/proofpatch/execution/docker_command.py",
    "src/proofpatch/security/mounts.py",
    "src/proofpatch/security/paths.py",
    "src/proofpatch/security/secrets.py",
    "src/proofpatch/security/validation.py",
    "src/proofpatch/prompts/investigation.md",
    "src/proofpatch/prompts/patch.md",
    "src/proofpatch/templates/receipt.md.j2",
    "src/proofpatch/templates/config.yml",
    "tests/conftest.py",
    "pyproject.toml",
    "README.md",
    "SECURITY.md",
    "CONTRIBUTING.md",
    "CHANGELOG.md",
    "LICENSE",
    "proofpatch.example.yml",
    "action.yml",
    ".github/actions/comment/action.yml",
    "docs/github-actions.md",
)

WORKFLOW_FILES = tuple(sorted((PROJECT_ROOT / ".github" / "workflows").glob("*.yml")))
ACTION_REFERENCE = re.compile(r"^\s*uses:\s*[^@\s]+@(?P<ref>[^\s#]+)", re.MULTILINE)
FULL_COMMIT_SHA = re.compile(r"[0-9a-f]{40}")


def test_authoritative_repository_layout_exists() -> None:
    missing = [path for path in REQUIRED_LAYOUT_FILES if not (PROJECT_ROOT / path).is_file()]

    assert missing == []


def test_authoritative_repository_directories_exist() -> None:
    missing = [path for path in REQUIRED_LAYOUT_DIRECTORIES if not (PROJECT_ROOT / path).is_dir()]

    assert missing == []


@pytest.mark.parametrize("workflow_path", WORKFLOW_FILES, ids=lambda path: path.name)
def test_workflow_yaml_is_well_formed(workflow_path: Path) -> None:
    assert yaml.compose(workflow_path.read_text(encoding="utf-8")) is not None


@pytest.mark.parametrize("workflow_path", WORKFLOW_FILES, ids=lambda path: path.name)
def test_external_actions_are_pinned_to_full_commit_shas(workflow_path: Path) -> None:
    content = workflow_path.read_text(encoding="utf-8")

    for match in ACTION_REFERENCE.finditer(content):
        assert FULL_COMMIT_SHA.fullmatch(match.group("ref")) is not None
