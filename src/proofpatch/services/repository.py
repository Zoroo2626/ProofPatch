"""Read-only repository discovery and Phase 2 Git preflight checks."""

import os
from pathlib import Path
from typing import Final

from proofpatch.errors import RepositoryError
from proofpatch.git.client import GitClient
from proofpatch.models.patch import RepositorySnapshot
from proofpatch.services.identifiers import (
    generate_repository_id,
    normalize_identity_path,
    sanitize_remote_url,
)

DEFAULT_MAX_REPOSITORY_BYTES: Final = 2 * 1024 * 1024 * 1024


class RepositoryService:
    """Discover and validate an original repository without mutating its Git metadata."""

    def __init__(
        self,
        git: GitClient | None = None,
        *,
        data_root: Path | None = None,
        max_repository_bytes: int = DEFAULT_MAX_REPOSITORY_BYTES,
    ) -> None:
        if max_repository_bytes <= 0:
            raise ValueError("maximum repository size must be positive")
        self.git = GitClient() if git is None else git
        self.data_root = data_root
        self.max_repository_bytes = max_repository_bytes

    def discover(self, location: Path) -> RepositorySnapshot:
        """Return a full baseline snapshot after every Phase 2 preflight passes."""

        try:
            candidate = location.resolve(strict=True)
        except OSError as error:
            raise RepositoryError(f"Repository path does not exist: {location}") from error
        if candidate.is_file():
            candidate = candidate.parent
        bare = self.git.text(
            ["-C", str(candidate), "rev-parse", "--is-bare-repository"],
            cwd=candidate,
            operation="repository discovery",
        )
        if bare != "false":
            raise RepositoryError("Bare repositories are not supported")
        root = Path(
            self.git.text(
                [
                    "-C",
                    str(candidate),
                    "rev-parse",
                    "--path-format=absolute",
                    "--show-toplevel",
                ],
                cwd=candidate,
                operation="repository root discovery",
            )
        ).resolve(strict=True)
        common = Path(
            self.git.text(
                [
                    "-C",
                    str(root),
                    "rev-parse",
                    "--path-format=absolute",
                    "--git-common-dir",
                ],
                cwd=root,
                operation="Git common-directory discovery",
            )
        ).resolve(strict=True)
        self._validate_location_separation(root)
        self._validate_local_config(root)
        self._validate_clean(root)
        self._validate_no_operation(common)
        self._validate_no_submodules(root)
        self._validate_no_nested_repositories(root)
        self._validate_size(root)

        commit = self.git.text(
            ["-C", str(root), "rev-parse", "--verify", "HEAD^{commit}"],
            cwd=root,
            operation="baseline commit resolution",
        )
        if len(commit) not in (40, 64) or any(
            character not in "0123456789abcdef" for character in commit
        ):
            raise RepositoryError("HEAD did not resolve to a full Git commit object ID")
        branch_result = self.git.run(
            ["-C", str(root), "symbolic-ref", "--quiet", "--short", "HEAD"],
            cwd=root,
            check=False,
            operation="branch discovery",
        )
        branch = (
            self._optional_text(branch_result.stdout, "branch")
            if branch_result.returncode == 0
            else None
        )
        remote_result = self.git.run(
            ["-C", str(root), "remote", "get-url", "origin"],
            cwd=root,
            check=False,
            operation="remote discovery",
        )
        remote_url = (
            self._optional_text(remote_result.stdout, "remote URL")
            if remote_result.returncode == 0
            else None
        )
        repository_id = generate_repository_id(root, common, remote_url)
        return RepositorySnapshot(
            repository_id=repository_id,
            repository_root=normalize_identity_path(root),
            git_common_directory=normalize_identity_path(common),
            baseline_commit=commit,
            branch=branch,
            detached=branch is None,
            remote="origin" if remote_url is not None else None,
            remote_url_redacted=sanitize_remote_url(remote_url),
        )

    def assert_matches(self, expected: RepositorySnapshot) -> RepositorySnapshot:
        """Rediscover the original and require identity and baseline equality."""

        current = self.discover(Path(expected.repository_root))
        if current.repository_id != expected.repository_id:
            raise RepositoryError("Current repository identity does not match the run repository")
        if current.baseline_commit != expected.baseline_commit:
            raise RepositoryError("Current HEAD no longer equals the run baseline commit")
        return current

    def _validate_clean(self, root: Path) -> None:
        status = self.git.run(
            ["-C", str(root), "status", "--porcelain=v1", "-z", "--untracked-files=all"],
            cwd=root,
            operation="clean working-tree validation",
        )
        if status.stdout:
            raise RepositoryError(
                "Repository working tree is not clean or contains untracked files",
                remediation="Commit, stash, or remove local changes before continuing.",
            )

    def _validate_local_config(self, root: Path) -> None:
        raw = self.git.run(
            ["-C", str(root), "config", "--local", "--null", "--name-only", "--list"],
            cwd=root,
            operation="repository configuration validation",
        ).stdout
        try:
            names = [item.decode("utf-8").lower() for item in raw.split(b"\0") if item]
        except UnicodeDecodeError as error:
            raise RepositoryError("Repository Git configuration contains invalid names") from error
        denied_exact = {
            "core.fsmonitor",
            "core.hookspath",
            "core.sshcommand",
            "core.askpass",
            "core.editor",
            "core.pager",
            "core.attributesfile",
            "core.excludesfile",
            "core.worktree",
            "core.alternaterefscommand",
            "uploadpack.packobjectshook",
            "protocol.ext.allow",
            "diff.external",
            "interactive.difffilter",
        }
        denied_fragments = (
            ".clean",
            ".smudge",
            ".process",
            ".command",
            ".driver",
            ".uploadpack",
            ".receivepack",
        )
        denied_prefixes = ("include.", "includeif.", "credential.", "alias.", "pager.")
        unsafe = [
            name
            for name in names
            if name in denied_exact
            or name.startswith(denied_prefixes)
            or any(fragment in name for fragment in denied_fragments)
        ]
        if unsafe:
            raise RepositoryError(
                f"Repository Git configuration contains executable behavior: {unsafe[0]}"
            )

    @staticmethod
    def _optional_text(value: bytes, label: str) -> str:
        try:
            return value.decode("utf-8").rstrip("\r\n")
        except UnicodeDecodeError as error:
            raise RepositoryError(f"Repository {label} is not valid UTF-8") from error

    @staticmethod
    def _validate_no_operation(common: Path) -> None:
        markers = {
            "MERGE_HEAD": common / "MERGE_HEAD",
            "rebase": common / "rebase-merge",
            "rebase apply": common / "rebase-apply",
            "cherry-pick": common / "CHERRY_PICK_HEAD",
            "bisect": common / "BISECT_LOG",
        }
        active = [name for name, marker in markers.items() if marker.exists()]
        if active:
            raise RepositoryError(f"Repository has an active {', '.join(active)} operation")

    def _validate_no_submodules(self, root: Path) -> None:
        staged = self.git.run(
            ["-C", str(root), "ls-files", "--stage", "-z"],
            cwd=root,
            operation="submodule detection",
        ).stdout
        if any(record.startswith(b"160000 ") for record in staged.split(b"\0") if record):
            raise RepositoryError("Git submodules are not supported in ProofPatch version 0.1")

    @staticmethod
    def _validate_no_nested_repositories(root: Path) -> None:
        for directory, names, files in os.walk(root, topdown=True, followlinks=False):
            current = Path(directory)
            if current == root:
                names[:] = [name for name in names if name != ".git"]
                files = [name for name in files if name != ".git"]
            if current != root and (".git" in names or ".git" in files):
                raise RepositoryError(f"Nested Git repository is not supported: {current}")
            names[:] = [
                name for name in names if name != ".git" and not (current / name).is_symlink()
            ]

    def _validate_size(self, root: Path) -> None:
        total = 0
        for directory, names, files in os.walk(root, topdown=True, followlinks=False):
            current = Path(directory)
            names[:] = [name for name in names if not (current / name).is_symlink()]
            for name in files:
                path = current / name
                try:
                    if path.is_symlink():
                        continue
                    total += path.stat().st_size
                except OSError as error:
                    raise RepositoryError(f"Could not measure repository file: {path}") from error
                if total > self.max_repository_bytes:
                    raise RepositoryError("Repository exceeds the configured size limit")

    def _validate_location_separation(self, root: Path) -> None:
        if self.data_root is None:
            return
        try:
            data = self.data_root.resolve(strict=False)
            root.relative_to(data)
        except ValueError:
            pass
        else:
            raise RepositoryError("Repository must not be inside the ProofPatch data directory")
        try:
            data.relative_to(root)
        except ValueError:
            return
        raise RepositoryError("ProofPatch data directory must not be inside the repository")
