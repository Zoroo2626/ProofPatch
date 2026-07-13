"""Phase 2 integration tests using real temporary Git repositories."""

import hashlib
from pathlib import Path

import pytest

from proofpatch.errors import ApplyError, EvidenceIntegrityError, PatchError, RepositoryError
from proofpatch.git.client import GitClient
from proofpatch.git.clone import CloneKind
from proofpatch.models.patch import ChangeKind
from proofpatch.models.state import RunState
from proofpatch.services.coordinator import RunCoordinator
from proofpatch.services.data_directories import ApplicationDirectories
from proofpatch.services.patching import PatchService

RUN_ID = "pp_20260713_111111111111"


def _git(git: GitClient, repository: Path, *args: str) -> bytes:
    return git.run(
        ["-C", str(repository), *args],
        cwd=repository,
        operation="test repository setup",
    ).stdout


def _repository(tmp_path: Path) -> tuple[GitClient, Path]:
    git = GitClient()
    repository = tmp_path / "source"
    repository.mkdir()
    _git(git, repository, "init", "--initial-branch=main")
    _git(git, repository, "config", "user.name", "ProofPatch Test")
    _git(git, repository, "config", "user.email", "proofpatch@example.invalid")
    (repository / "modified.txt").write_text("before\n", encoding="utf-8")
    (repository / "deleted.txt").write_text("delete me\n", encoding="utf-8")
    (repository / "renamed-old.txt").write_text("rename me\n", encoding="utf-8")
    (repository / "binary.bin").write_bytes(bytes(range(256)) * 4)
    _git(git, repository, "add", "-A", "--")
    _git(git, repository, "commit", "-m", "baseline")
    return git, repository


def _service(tmp_path: Path, git: GitClient) -> PatchService:
    return PatchService(RunCoordinator(ApplicationDirectories(tmp_path / "data")), git)


def _advance_to_patching(service: PatchService, run_id: str) -> None:
    for state in (
        RunState.BASELINE_PREPARING,
        RunState.BASELINE_VERIFYING,
        RunState.BASELINE_REPRODUCED,
        RunState.PATCH_PREPARING,
    ):
        service.coordinator.transition(run_id, state)


def _capture_fixture(
    tmp_path: Path,
    *,
    run_id: str = RUN_ID,
) -> tuple[PatchService, Path]:
    git, repository = _repository(tmp_path)
    service = _service(tmp_path, git)
    service.prepare_run(repository, run_id=run_id)
    _advance_to_patching(service, run_id)
    clone = service.create_clone(run_id, CloneKind.PATCH)
    service.coordinator.transition(run_id, RunState.PATCHING)
    (clone.root / "modified.txt").write_text("after\n", encoding="utf-8")
    (clone.root / "added.txt").write_text("new\n", encoding="utf-8")
    (clone.root / "deleted.txt").unlink()
    (clone.root / "renamed-old.txt").rename(clone.root / "renamed-new.txt")
    (clone.root / "binary.bin").write_bytes(b"\x00proofpatch\xff" * 150)
    service.capture(run_id, clone)
    return service, repository


def _verify_fixture(service: PatchService, run_id: str = RUN_ID) -> None:
    service.verify_application(run_id)
    service.coordinator.transition(run_id, RunState.FINAL_VERIFYING)
    service.coordinator.transition(run_id, RunState.VERIFIED)


def _content_snapshot(root: Path) -> dict[str, str]:
    return {
        path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in root.rglob("*")
        if path.is_file()
    }


def test_capture_verify_and_apply_all_git_change_types(tmp_path: Path) -> None:
    git, repository = _repository(tmp_path)
    before = _content_snapshot(repository)
    service = _service(tmp_path, git)
    snapshot = service.prepare_run(repository, run_id=RUN_ID)
    assert snapshot.baseline_commit == _git(git, repository, "rev-parse", "HEAD").decode().strip()
    _advance_to_patching(service, RUN_ID)
    clone = service.create_clone(RUN_ID, CloneKind.PATCH)
    assert _content_snapshot(repository) == before
    service.coordinator.transition(RUN_ID, RunState.PATCHING)

    (clone.root / "modified.txt").write_text("after\n", encoding="utf-8")
    (clone.root / "added.txt").write_text("new\n", encoding="utf-8")
    (clone.root / "deleted.txt").unlink()
    (clone.root / "renamed-old.txt").rename(clone.root / "renamed-new.txt")
    (clone.root / "binary.bin").write_bytes(b"\x00proofpatch\xff" * 150)
    record = service.capture(RUN_ID, clone)

    assert _content_snapshot(repository) == before
    assert {change.status for change in record.changed_files} >= {
        ChangeKind.ADDED,
        ChangeKind.DELETED,
        ChangeKind.MODIFIED,
        ChangeKind.RENAMED,
    }
    paths = service.coordinator.paths_for(RUN_ID)
    assert b"GIT binary patch" in paths.patch_diff.read_bytes()
    verified_root = service.verify_application(RUN_ID)
    assert (verified_root / "modified.txt").read_text(encoding="utf-8") == "after\n"
    assert _content_snapshot(repository) == before

    service.coordinator.transition(RUN_ID, RunState.FINAL_VERIFYING)
    service.coordinator.transition(RUN_ID, RunState.VERIFIED)
    applied = service.apply_verified(RUN_ID, require_receipt=False)
    assert applied.branch.startswith("proofpatch/")
    assert (repository / "added.txt").read_text(encoding="utf-8") == "new\n"
    assert not (repository / "deleted.txt").exists()
    assert (repository / "renamed-new.txt").exists()
    assert _git(git, repository, "diff", "--cached", "--quiet").strip() == b""
    assert service.coordinator.status(RUN_ID).state is RunState.APPLIED
    with pytest.raises(ApplyError, match="already been applied"):
        service.apply_verified(RUN_ID, require_receipt=False)


def test_dirty_original_and_denied_patch_path_are_rejected(tmp_path: Path) -> None:
    git, repository = _repository(tmp_path)
    service = _service(tmp_path, git)
    (repository / "untracked.txt").write_text("dirty", encoding="utf-8")
    with pytest.raises(RepositoryError, match="not clean"):
        service.prepare_run(repository, run_id=RUN_ID)
    (repository / "untracked.txt").unlink()

    service.prepare_run(repository, run_id=RUN_ID)
    _advance_to_patching(service, RUN_ID)
    clone = service.create_clone(RUN_ID, CloneKind.PATCH)
    service.coordinator.transition(RUN_ID, RunState.PATCHING)
    denied = clone.root / ".github" / "workflows"
    denied.mkdir(parents=True)
    (denied / "ci.yml").write_text("name: bypass\n", encoding="utf-8")
    with pytest.raises(PatchError, match="denied path"):
        service.capture(RUN_ID, clone, denied_paths=(".github",))


def test_changed_original_head_prevents_apply(tmp_path: Path) -> None:
    service, repository = _capture_fixture(tmp_path)
    _verify_fixture(service)
    git = service.git
    (repository / "later.txt").write_text("later\n", encoding="utf-8")
    _git(git, repository, "add", "later.txt")
    _git(git, repository, "commit", "-m", "move head")

    with pytest.raises(ApplyError, match="HEAD no longer equals"):
        service.apply_verified(RUN_ID, require_receipt=False)
    assert service.coordinator.status(RUN_ID).state is RunState.VERIFIED


def test_stage_option_stages_applied_patch(tmp_path: Path) -> None:
    run_id = "pp_20260713_222222222222"
    service, repository = _capture_fixture(tmp_path, run_id=run_id)
    _verify_fixture(service, run_id)
    service.apply_verified(run_id, stage=True, require_receipt=False)
    assert _git(service.git, repository, "diff", "--cached", "--name-only").strip()


def test_repository_preflight_rejects_git_operations_config_nested_and_size(
    tmp_path: Path,
) -> None:
    git, repository = _repository(tmp_path)
    service = _service(tmp_path, git)
    git_directory = Path(_git(git, repository, "rev-parse", "--git-dir").decode().strip())
    if not git_directory.is_absolute():
        git_directory = repository / git_directory
    head = _git(git, repository, "rev-parse", "HEAD").decode().strip()
    (git_directory / "MERGE_HEAD").write_text(head, encoding="ascii")
    with pytest.raises(RepositoryError, match="active MERGE_HEAD"):
        service.repositories.discover(repository)
    (git_directory / "MERGE_HEAD").unlink()

    _git(git, repository, "config", "alias.danger", "!echo unsafe")
    with pytest.raises(RepositoryError, match="executable behavior"):
        service.repositories.discover(repository)
    _git(git, repository, "config", "--unset", "alias.danger")

    for name in ("diff.external", "interactive.diffFilter", "pager.status", "core.hooksPath"):
        _git(git, repository, "config", name, "hostile-command")
        with pytest.raises(RepositoryError, match="executable behavior"):
            service.repositories.discover(repository)
        _git(git, repository, "config", "--unset", name)

    (repository / ".gitignore").write_text("nested/.git\n", encoding="utf-8")
    _git(git, repository, "add", ".gitignore")
    _git(git, repository, "commit", "-m", "ignore nested marker")
    nested = repository / "nested" / ".git"
    nested.mkdir(parents=True)
    with pytest.raises(RepositoryError, match="Nested Git"):
        service.repositories.discover(repository)
    nested.rmdir()

    tiny = service.repositories.__class__(git, max_repository_bytes=1)
    with pytest.raises(RepositoryError, match="size limit"):
        tiny.discover(repository)


def test_repository_preflight_rejects_missing_bare_and_data_overlap(tmp_path: Path) -> None:
    git = GitClient()
    service = _service(tmp_path, git)
    with pytest.raises(RepositoryError, match="does not exist"):
        service.repositories.discover(tmp_path / "missing")

    bare = tmp_path / "bare.git"
    bare.mkdir()
    _git(git, bare, "init", "--bare")
    with pytest.raises(RepositoryError, match="Bare"):
        service.repositories.discover(bare)

    repository = tmp_path / "parent"
    repository.mkdir()
    _git(git, repository, "init", "--initial-branch=main")
    _git(git, repository, "config", "user.name", "ProofPatch Test")
    _git(git, repository, "config", "user.email", "proofpatch@example.invalid")
    (repository / "file").write_text("x", encoding="utf-8")
    _git(git, repository, "add", "file")
    _git(git, repository, "commit", "-m", "baseline")
    overlapping = PatchService(
        RunCoordinator(ApplicationDirectories(repository / "proofpatch-data")), git
    )
    with pytest.raises(RepositoryError, match="data directory"):
        overlapping.repositories.discover(repository)


def test_clone_configuration_tampering_and_invalid_phase_are_rejected(tmp_path: Path) -> None:
    git, repository = _repository(tmp_path)
    service = _service(tmp_path, git)
    service.prepare_run(repository, run_id=RUN_ID)
    with pytest.raises(RepositoryError, match="Cannot create patch"):
        service.create_clone(RUN_ID, CloneKind.PATCH)
    _advance_to_patching(service, RUN_ID)
    clone = service.create_clone(RUN_ID, CloneKind.PATCH)
    service.coordinator.transition(RUN_ID, RunState.PATCHING)
    (clone.root / "modified.txt").write_text("changed\n", encoding="utf-8")
    with (clone.git_directory / "config").open("a", encoding="utf-8") as stream:
        stream.write('\n[filter "hostile"]\n\tclean = calc.exe\n')
    with pytest.raises(RepositoryError, match="configuration changed"):
        service.capture(RUN_ID, clone)


def test_patch_service_rejects_wrong_states_and_tampered_patch(tmp_path: Path) -> None:
    git, repository = _repository(tmp_path)
    service = _service(tmp_path, git)
    service.prepare_run(repository, run_id=RUN_ID)
    with pytest.raises(PatchError, match="PATCHING"):
        service.capture(RUN_ID, MockClone())  # type: ignore[arg-type]
    with pytest.raises(PatchError, match="captured patch"):
        service.verify_application(RUN_ID)
    with pytest.raises(ApplyError, match="Only a VERIFIED"):
        service.apply_verified(RUN_ID, require_receipt=False)

    second = tmp_path / "second"
    second.mkdir()
    service, _repository_path = _capture_fixture(second)
    paths = service.coordinator.paths_for(RUN_ID)
    paths.patch_diff.write_bytes(paths.patch_diff.read_bytes() + b"tamper")
    with pytest.raises(EvidenceIntegrityError, match="integrity"):
        service.load_patch(RUN_ID)


def test_apply_branch_collision_and_safe_branch_restoration(tmp_path: Path) -> None:
    service, repository = _capture_fixture(tmp_path)
    _verify_fixture(service)
    collision = f"proofpatch/{RUN_ID[-12:]}"
    _git(service.git, repository, "branch", collision)
    with pytest.raises(ApplyError, match="already exists"):
        service.apply_verified(RUN_ID, require_receipt=False)
    _git(service.git, repository, "branch", "-D", collision)

    snapshot = service.load_repository(RUN_ID)
    temporary = "proofpatch/temporary"
    _git(service.git, repository, "switch", "-c", temporary)
    service._restore_branch_if_clean(repository, snapshot, temporary)
    assert _git(service.git, repository, "branch", "--show-current").decode().strip() == "main"


def test_empty_patch_and_duplicate_clone_destination_are_rejected(tmp_path: Path) -> None:
    git, repository = _repository(tmp_path)
    service = _service(tmp_path, git)
    service.prepare_run(repository, run_id=RUN_ID)
    _advance_to_patching(service, RUN_ID)
    clone = service.create_clone(RUN_ID, CloneKind.PATCH)
    with pytest.raises(RepositoryError, match="already exists"):
        service.create_clone(RUN_ID, CloneKind.PATCH)
    service.coordinator.transition(RUN_ID, RunState.PATCHING)
    with pytest.raises(PatchError, match="empty"):
        service.capture(RUN_ID, clone)


def test_missing_patch_evidence_binding_is_rejected(tmp_path: Path) -> None:
    service, _repository_path = _capture_fixture(tmp_path)
    record = service.load_patch(RUN_ID)
    with pytest.raises(EvidenceIntegrityError, match="not bound"):
        service._verify_patch_binding((), record)


class MockClone:
    """Never inspected because the state precondition fails first."""
