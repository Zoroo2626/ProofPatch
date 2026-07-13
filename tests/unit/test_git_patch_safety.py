"""Focused failure-mode tests for Phase 2 Git and patch primitives."""

import io
import subprocess
from pathlib import Path
from unittest.mock import Mock, patch

import pytest
from typer.testing import CliRunner

import proofpatch.cli as cli
from proofpatch.errors import PatchError, RepositoryError
from proofpatch.git.apply import _bounded_hash, apply_patch_bytes, check_patch_applies
from proofpatch.git.client import GitClient, GitCommandError, GitResult, _kill_git_process
from proofpatch.git.clone import _configuration_hash, _reject_alternates, _reject_hardlinked_objects
from proofpatch.git.diff import (
    parse_name_status_z,
    sha256_file,
    validate_changed_paths,
    verify_patch_hash,
)
from proofpatch.models.patch import AppliedPatch, ChangedFile, ChangeKind


def test_name_status_parser_handles_nul_paths_and_renames() -> None:
    changes = parse_name_status_z(b"M\0space name.txt\0R091\0old.txt\0new.txt\0")
    assert changes == (
        ChangedFile(status=ChangeKind.MODIFIED, path="space name.txt"),
        ChangedFile(
            status=ChangeKind.RENAMED,
            path="new.txt",
            old_path="old.txt",
            similarity=91,
        ),
    )


@pytest.mark.parametrize(
    "raw",
    [b"M\0path", b"X\0path\0", b"Rxx\0old\0new\0", b"R100\0old\0"],
)
def test_name_status_parser_rejects_malformed_or_unsupported_data(raw: bytes) -> None:
    with pytest.raises(PatchError):
        parse_name_status_z(raw)


@pytest.mark.parametrize("path", ["../escape", "/absolute", "dir\\ambiguous", ".git/config"])
def test_changed_path_validation_fails_closed(path: str) -> None:
    change = ChangedFile(status=ChangeKind.MODIFIED, path=path)
    with pytest.raises(PatchError):
        validate_changed_paths((change,))


def test_git_client_always_uses_argument_array_and_shell_false(tmp_path: Path) -> None:
    process = Mock(
        returncode=0,
        stdout=io.BytesIO(b"ok\n"),
        stderr=io.BytesIO(b""),
    )
    process.wait.return_value = 0
    with patch("proofpatch.git.client.subprocess.Popen", return_value=process) as invoked:
        result = GitClient(executable="git").run(["version"], cwd=tmp_path)
    assert result.stdout == b"ok\n"
    positional, keywords = invoked.call_args
    assert positional and isinstance(positional[0], list)
    assert keywords["shell"] is False
    assert "--shared" not in positional[0]
    assert "--reference" not in positional[0]


def test_git_client_rejects_ambient_or_invalid_arguments(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GIT_DIR", "hostile")
    environment = GitClient._environment()
    assert "GIT_DIR" not in environment
    assert environment["GIT_OPTIONAL_LOCKS"] == "0"
    with pytest.raises(RepositoryError, match="arguments"):
        GitClient(executable="git").run(["bad\0argument"])


def test_git_client_failure_timeout_limits_and_decoding(tmp_path: Path) -> None:
    failure = GitResult(("git", "status"), 2, b"", b"fatal: bad")
    with (
        patch.object(GitClient, "_execute_bounded", return_value=failure),
        pytest.raises(GitCommandError, match="fatal: bad"),
    ):
        GitClient(executable="git").run(["status"], cwd=tmp_path)
    with (
        patch.object(GitClient, "_execute_bounded", side_effect=RepositoryError("safely")),
        pytest.raises(RepositoryError, match="safely"),
    ):
        GitClient(executable="git").run(["status"], cwd=tmp_path)
    verbose_failure = GitResult(("git", "status"), 2, b"", b"x" * 3000)
    assert "…" in str(GitCommandError("status", verbose_failure))
    process = Mock(returncode=0, stdout=io.BytesIO(b"xx"), stderr=io.BytesIO(b""))
    process.wait.return_value = 0
    client = GitClient(executable="git")
    with (
        patch("proofpatch.git.client.subprocess.Popen", return_value=process),
        pytest.raises(RepositoryError, match="safety limit"),
    ):
        client._execute_bounded(
            client._argv(["status"]),
            cwd=tmp_path,
            operation="status",
            timeout=1,
            maximum_output_bytes=1,
        )
    undecodable = GitResult(("git", "status"), 0, b"\xff", b"")
    with (
        patch.object(GitClient, "_execute_bounded", return_value=undecodable),
        pytest.raises(RepositoryError, match="non-UTF-8"),
    ):
        GitClient(executable="git").text(["status"], cwd=tmp_path, operation="text")


def test_git_process_tree_kill_is_bounded_and_has_a_fallback() -> None:
    process = Mock(pid=123)
    process.poll.return_value = None
    with patch("proofpatch.git.client.subprocess.run") as taskkill:
        _kill_git_process(process)
    taskkill.assert_called_once()
    process.kill.assert_called_once()

    process.reset_mock()
    process.poll.return_value = None
    timeout = subprocess.TimeoutExpired(["taskkill"], 2.0)
    with patch("proofpatch.git.client.subprocess.run", side_effect=timeout):
        _kill_git_process(process)
    process.kill.assert_called_once()


def test_git_client_streaming_failures_and_missing_executable(tmp_path: Path) -> None:
    with (
        patch("proofpatch.git.client.shutil.which", return_value=None),
        pytest.raises(RepositoryError, match="not installed"),
    ):
        GitClient()
    output = io.BytesIO()
    failure = GitResult(("git", "diff"), 1, b"", b"stream failed")
    with (
        patch.object(GitClient, "_execute_bounded", return_value=failure),
        pytest.raises(GitCommandError, match="stream failed"),
    ):
        GitClient(executable="git").run_to_file(["diff"], output, cwd=tmp_path, operation="stream")


def test_git_bounded_runner_handles_start_timeout_pipe_and_write_failures(tmp_path: Path) -> None:
    client = GitClient(executable="git")
    with pytest.raises(RepositoryError, match="limits"):
        client._execute_bounded(
            client._argv(["version"]),
            cwd=tmp_path,
            operation="version",
            timeout=0,
        )
    with (
        patch("proofpatch.git.client.subprocess.Popen", side_effect=OSError("no process")),
        pytest.raises(RepositoryError, match="safely"),
    ):
        client.run(["version"], cwd=tmp_path)

    missing_pipe = Mock(stdout=None, stderr=io.BytesIO(), pid=123)
    with (
        patch("proofpatch.git.client.subprocess.Popen", return_value=missing_pipe),
        patch("proofpatch.git.client._kill_git_process"),
        pytest.raises(RepositoryError, match="capture"),
    ):
        client.run(["version"], cwd=tmp_path)

    timed_out = Mock(
        stdout=io.BytesIO(b""),
        stderr=io.BytesIO(b""),
        returncode=-1,
        pid=123,
    )
    timed_out.wait.side_effect = [subprocess.TimeoutExpired(["git"], 0.1), 0]
    with (
        patch("proofpatch.git.client.subprocess.Popen", return_value=timed_out),
        patch("proofpatch.git.client._kill_git_process"),
        pytest.raises(RepositoryError, match="safely"),
    ):
        client.run(["version"], cwd=tmp_path, timeout=0.1)

    short_writer = Mock()
    short_writer.write.return_value = 0

    process = Mock(
        stdout=io.BytesIO(b"patch"),
        stderr=io.BytesIO(b""),
        returncode=0,
        pid=123,
    )
    process.wait.return_value = 0
    with (
        patch("proofpatch.git.client.subprocess.Popen", return_value=process),
        pytest.raises(RepositoryError, match="capture"),
    ):
        client.run_to_file(
            ["diff"],
            short_writer,
            cwd=tmp_path,
            operation="stream",
        )
    with (
        patch.object(GitClient, "_execute_bounded", side_effect=RepositoryError("safely")),
        pytest.raises(RepositoryError, match="safely"),
    ):
        GitClient(executable="git").run_to_file(
            ["diff"], io.BytesIO(), cwd=tmp_path, operation="stream"
        )


def test_patch_parser_and_hash_additional_fail_closed_cases(tmp_path: Path) -> None:
    assert parse_name_status_z(b"") == ()
    copied = parse_name_status_z(b"C100\0old\0new\0")
    assert copied[0].status is ChangeKind.COPIED
    for raw in (b"\0path\0", b"M1\0path\0", b"M\0\xff\0"):
        with pytest.raises(PatchError):
            parse_name_status_z(raw)

    patch_file = tmp_path / "patch.diff"
    patch_file.write_bytes(b"patch")
    digest = sha256_file(patch_file)
    verify_patch_hash(patch_file, digest)
    with pytest.raises(PatchError, match="SHA-256"):
        verify_patch_hash(patch_file, "0" * 64)
    with pytest.raises(PatchError, match="maximum"):
        sha256_file(patch_file, maximum_bytes=1)
    patch_file.write_bytes(b"")
    with pytest.raises(PatchError, match="empty"):
        sha256_file(patch_file)


def test_proofpatch_and_explicit_policy_paths_are_denied() -> None:
    with pytest.raises(PatchError, match="ProofPatch-owned"):
        validate_changed_paths((ChangedFile(status=ChangeKind.ADDED, path=".proofpatch/out"),))
    with pytest.raises(PatchError, match="denied path"):
        validate_changed_paths(
            (
                ChangedFile(
                    status=ChangeKind.RENAMED,
                    old_path="secret/a",
                    path="safe",
                    similarity=90,
                ),
            ),
            denied_paths=("secret",),
        )


def test_patch_path_globs_enforce_allowlist_and_recursive_denials() -> None:
    validate_changed_paths(
        (ChangedFile(status=ChangeKind.MODIFIED, path="src/nested/module.py"),),
        allowed_paths=("src/**",),
        denied_paths=("src/generated/**", "**/*.pem"),
    )
    for path in ("README.md", "src/generated/client.py", "src/key.pem"):
        with pytest.raises(PatchError):
            validate_changed_paths(
                (ChangedFile(status=ChangeKind.MODIFIED, path=path),),
                allowed_paths=("src/**",),
                denied_paths=("src/generated/**", "**/*.pem"),
            )


@pytest.mark.parametrize("pattern", ("../src/**", "src\\**", "src/***", "src/[ab]"))
def test_patch_path_policy_rejects_ambiguous_patterns(pattern: str) -> None:
    with pytest.raises(PatchError, match="policy"):
        validate_changed_paths(
            (ChangedFile(status=ChangeKind.MODIFIED, path="src/a.py"),),
            allowed_paths=(pattern,),
        )


def test_apply_file_errors_and_bounded_recapture_hash(tmp_path: Path) -> None:
    missing = tmp_path / "missing.diff"
    git = GitClient(executable="git")
    with pytest.raises(PatchError, match="patch artifact"):
        check_patch_applies(git, tmp_path, missing)
    with pytest.raises(PatchError, match="patch artifact"):
        apply_patch_bytes(git, tmp_path, missing)
    artifact = tmp_path / "artifact"
    artifact.write_bytes(b"xx")
    with pytest.raises(PatchError, match="maximum"):
        _bounded_hash(artifact, 1)
    artifact.write_bytes(b"")
    with pytest.raises(PatchError, match="empty"):
        _bounded_hash(artifact, 1)


def test_clone_storage_guards_reject_alternates_missing_objects_and_bad_config(
    tmp_path: Path,
) -> None:
    git_directory = tmp_path / "clone-git"
    alternates = git_directory / "objects" / "info" / "alternates"
    alternates.parent.mkdir(parents=True)
    alternates.write_text("outside", encoding="utf-8")
    with pytest.raises(RepositoryError, match="alternate"):
        _reject_alternates(git_directory)
    with pytest.raises(RepositoryError, match="storage is missing"):
        _reject_hardlinked_objects(tmp_path / "source", tmp_path / "clone")
    config = git_directory / "config"
    config.mkdir()
    with pytest.raises(RepositoryError, match="private regular"):
        _configuration_hash(git_directory)


def test_apply_cli_prints_changed_paths_and_stage_state(monkeypatch: pytest.MonkeyPatch) -> None:
    result = AppliedPatch(
        run_id="pp_20260713_333333333333",
        branch="proofpatch/333333333333",
        previous_revision="a" * 40,
        patch_sha256="b" * 64,
        changed_files=(
            ChangedFile(status=ChangeKind.MODIFIED, path="one.txt"),
            ChangedFile(
                status=ChangeKind.RENAMED,
                old_path="old.txt",
                path="new.txt",
                similarity=100,
            ),
        ),
    )

    class FakePatchService:
        def apply_verified(self, run_id: str, *, stage: bool = False) -> AppliedPatch:
            assert run_id == result.run_id
            assert stage
            return result

    monkeypatch.setattr(cli, "_patch_service", FakePatchService)
    invoked = CliRunner().invoke(cli.app, ["apply", result.run_id, "--stage"])
    assert invoked.exit_code == 0
    assert "M  one.txt" in invoked.output
    assert "old.txt -> new.txt" in invoked.output
    assert "Changes are staged" in invoked.output
