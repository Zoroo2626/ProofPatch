"""Check, apply, and independently recapture exact Git patches."""

import hashlib
import hmac
from pathlib import Path

from proofpatch.errors import PatchError
from proofpatch.git.client import GitClient
from proofpatch.git.clone import CloneKind, create_independent_clone
from proofpatch.git.diff import DEFAULT_MAX_PATCH_BYTES, open_patch_file, verify_patch_hash
from proofpatch.models.patch import RepositorySnapshot


def check_patch_applies(git: GitClient, repository: Path, patch: Path) -> None:
    """Run Git's binary apply check without changing the target working tree."""

    with open_patch_file(patch) as stream:
        git.run(
            ["-C", str(repository), "apply", "--check", "--binary", "-"],
            cwd=repository,
            stdin=stream,
            operation="patch apply check",
        )


def apply_patch_bytes(git: GitClient, repository: Path, patch: Path) -> None:
    """Apply exact patch bytes from stdin so the filename cannot be interpreted as an option."""

    with open_patch_file(patch) as stream:
        git.run(
            ["-C", str(repository), "apply", "--binary", "-"],
            cwd=repository,
            stdin=stream,
            operation="binary patch application",
        )


def verify_patch_in_fresh_clone(
    git: GitClient,
    repository: RepositorySnapshot,
    run_root: Path,
    patch: Path,
    expected_sha256: str,
    *,
    max_patch_bytes: int = DEFAULT_MAX_PATCH_BYTES,
    workspace_name: str | None = None,
) -> Path:
    """Apply and recapture the patch in a distinct final-verification clone."""

    verify_patch_hash(patch, expected_sha256, maximum_bytes=max_patch_bytes)
    clone = create_independent_clone(
        git,
        repository,
        run_root,
        CloneKind.FINAL_VERIFICATION,
        workspace_name=workspace_name,
    )
    check_patch_applies(git, clone.root, patch)
    apply_patch_bytes(git, clone.root, patch)
    git.run(
        ["-C", str(clone.root), "add", "-A", "--"],
        cwd=clone.root,
        operation="verification-tree staging",
    )
    recaptured = clone.root / ".git" / "proofpatch-recaptured.diff"
    try:
        with recaptured.open("xb") as stream:
            git.run_to_file(
                [
                    "-C",
                    str(clone.root),
                    "diff",
                    "--cached",
                    "--binary",
                    "--full-index",
                    "--no-ext-diff",
                    "--no-textconv",
                    clone.baseline_commit,
                    "--",
                ],
                stream,
                cwd=clone.root,
                operation="verified patch recapture",
            )
        actual = _bounded_hash(recaptured, max_patch_bytes)
    except OSError as error:
        raise PatchError("Could not recapture applied patch") from error
    finally:
        recaptured.unlink(missing_ok=True)
    if not hmac.compare_digest(actual, expected_sha256):
        raise PatchError("Fresh-clone staged diff does not match the captured patch hash")
    return clone.root


def _bounded_hash(path: Path, maximum: int) -> str:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        while chunk := stream.read(64 * 1024):
            size += len(chunk)
            if size > maximum:
                raise PatchError("Recaptured patch exceeds the maximum patch size")
            digest.update(chunk)
    if size == 0:
        raise PatchError("Recaptured patch is empty")
    return digest.hexdigest()
