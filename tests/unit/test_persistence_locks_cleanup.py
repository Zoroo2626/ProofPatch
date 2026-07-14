"""Tests for SQLite indexing, OS locks, and destructive-path validation."""

import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

from proofpatch.errors import CleanupError, InternalInvariantError, RepositoryError
from proofpatch.models.run import RepositoryLockRecord, RunManifest, RunRecord
from proofpatch.models.state import RunState
from proofpatch.security.paths import validate_proofpatch_data_path
from proofpatch.services.cleanup import (
    CleanupTargetKind,
    remove_owned_tree,
    revalidate_cleanup_target,
    validate_cleanup_target,
)
from proofpatch.services.data_directories import (
    DATA_DIRECTORY_ENV,
    ApplicationDirectories,
    get_app_directories,
)
from proofpatch.services.evidence import read_canonical_json, write_canonical_json
from proofpatch.services.locks import RepositoryLock
from proofpatch.services.run_store import RunStore

RUN_ID = "pp_20260713_a4f92b18ce31"
RUN_ID_2 = "pp_20260713_bbbbbbbbbbbb"
REPOSITORY_ID = "repo_9c06a0e7e84b6f78"
TIMESTAMP = "2026-07-13T10:00:00.000000Z"
HASH = "a" * 64


def _record(*, run_id: str = RUN_ID, state: RunState = RunState.CREATED) -> RunRecord:
    return RunRecord(
        run_id=run_id,
        repository_id=REPOSITORY_ID,
        repository_root="C:/repository",
        state=state,
        created_at_utc=TIMESTAMP,
        updated_at_utc=TIMESTAMP,
        last_event_sequence=1,
        last_event_hash=HASH,
        run_relative_path=f"runs/{REPOSITORY_ID}/{run_id}",
    )


def test_sqlite_store_crud_ordering_and_rebuild(tmp_path: Path) -> None:
    database = tmp_path / "index.sqlite3"
    store = RunStore(database)
    first = _record()
    second = _record(run_id=RUN_ID_2)

    assert store.get(RUN_ID) is None
    store.insert(first)
    store.insert(second)
    assert store.get(RUN_ID) == first
    assert store.list() == (second, first)

    updated = first.model_copy(
        update={
            "state": RunState.PREFLIGHT,
            "last_event_sequence": 2,
            "last_event_hash": "b" * 64,
        }
    )
    store.upsert(updated)
    assert store.get(RUN_ID) == updated
    with sqlite3.connect(database) as connection:
        assert int(connection.execute("PRAGMA user_version").fetchone()[0]) == 1
    if os.name == "posix":
        assert database.stat().st_mode & 0o777 == 0o600


def test_sqlite_store_separates_read_and_write_lock_lifetimes(tmp_path: Path) -> None:
    database = tmp_path / "index.sqlite3"
    store = RunStore(database)

    with store._connect() as reader:
        assert str(reader.execute("PRAGMA journal_mode").fetchone()[0]).lower() == "wal"
        assert int(reader.execute("PRAGMA synchronous").fetchone()[0]) == 1
        assert not reader.in_transaction
        reader.execute("SELECT COUNT(*) FROM runs").fetchone()
        assert not reader.in_transaction
    with pytest.raises(sqlite3.ProgrammingError, match="closed"):
        reader.execute("SELECT 1")

    with store._connect(write=True) as writer:
        assert writer.in_transaction
        writer.execute("SELECT COUNT(*) FROM runs").fetchone()
    with pytest.raises(sqlite3.ProgrammingError, match="closed"):
        writer.execute("SELECT 1")

    store.insert(_record())
    with (
        pytest.raises(RuntimeError, match="interrupted metadata update"),
        store._connect(write=True) as interrupted,
    ):
        interrupted.execute("UPDATE runs SET state = 'PREFLIGHT' WHERE run_id = ?", (RUN_ID,))
        raise RuntimeError("interrupted metadata update")
    assert store.get(RUN_ID) == _record()


def test_sqlite_reader_does_not_wait_for_an_active_writer(tmp_path: Path) -> None:
    database = tmp_path / "index.sqlite3"
    store = RunStore(database)
    store.insert(_record())

    with sqlite3.connect(database, isolation_level=None) as writer:
        writer.execute("PRAGMA synchronous = NORMAL")
        writer.execute("BEGIN IMMEDIATE")
        writer.execute("UPDATE runs SET state = 'PREFLIGHT' WHERE run_id = ?", (RUN_ID,))
        assert store.get(RUN_ID) == _record()
        writer.rollback()

    assert store.get(RUN_ID) == _record()


def test_sqlite_store_rejects_duplicate_unsupported_and_invalid_rows(tmp_path: Path) -> None:
    database = tmp_path / "index.sqlite3"
    store = RunStore(database)
    store.insert(_record())
    with pytest.raises(InternalInvariantError, match="already exists"):
        store.insert(_record())

    with sqlite3.connect(database) as connection:
        connection.execute("UPDATE runs SET state = 'NOT_A_STATE' WHERE run_id = ?", (RUN_ID,))
    with pytest.raises(InternalInvariantError, match="invalid schema"):
        store.get(RUN_ID)

    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA user_version = 99")
    with pytest.raises(InternalInvariantError, match="Unsupported SQLite"):
        RunStore(database)


def test_sqlite_store_rejects_symlink_index_when_supported(tmp_path: Path) -> None:
    target = tmp_path / "real.sqlite3"
    target.touch()
    link = tmp_path / "linked.sqlite3"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("symbolic links are unavailable for this Windows account")
    with pytest.raises(InternalInvariantError, match="link or junction"):
        RunStore(link)


def test_sqlite_store_rejects_hardlink_index(tmp_path: Path) -> None:
    target = tmp_path / "real.sqlite3"
    target.touch()
    link = tmp_path / "linked.sqlite3"
    os.link(target, link)
    with pytest.raises(InternalInvariantError, match="private regular file"):
        RunStore(link)


def test_repository_lock_records_owner_and_blocks_same_process(tmp_path: Path) -> None:
    locks = tmp_path / "locks"
    lock = RepositoryLock(locks, REPOSITORY_ID, RUN_ID)
    with lock, pytest.raises(RepositoryError, match="Another mutating"):
        RepositoryLock(locks, REPOSITORY_ID, RUN_ID_2).acquire()
    record = RepositoryLockRecord.model_validate(
        read_canonical_json(locks / f"{REPOSITORY_ID}.lock")
    )
    assert record.run_id == RUN_ID
    assert record.pid == os.getpid()
    lock.release()

    with RepositoryLock(locks, REPOSITORY_ID, RUN_ID_2):
        pass
    replacement = RepositoryLockRecord.model_validate(
        read_canonical_json(locks / f"{REPOSITORY_ID}.lock")
    )
    assert replacement.run_id == RUN_ID_2


def test_repository_os_lock_blocks_another_process(tmp_path: Path) -> None:
    locks = tmp_path / "locks"
    script = """
import sys
from pathlib import Path
from proofpatch.errors import RepositoryError
from proofpatch.services.locks import RepositoryLock
try:
    with RepositoryLock(Path(sys.argv[1]), sys.argv[2], sys.argv[3]):
        pass
except RepositoryError:
    raise SystemExit(23)
"""
    arguments = [sys.executable, "-c", script, str(locks), REPOSITORY_ID, RUN_ID_2]
    with RepositoryLock(locks, REPOSITORY_ID, RUN_ID):
        blocked = subprocess.run(arguments, check=False, timeout=10)  # noqa: S603
    acquired = subprocess.run(arguments, check=False, timeout=10)  # noqa: S603

    assert blocked.returncode == 23
    assert acquired.returncode == 0


def test_repository_lock_overwrites_stale_diagnostic_record(tmp_path: Path) -> None:
    locks = tmp_path / "locks"
    locks.mkdir()
    path = locks / f"{REPOSITORY_ID}.lock"
    path.write_bytes(b"stale and malformed\n")
    with RepositoryLock(locks, REPOSITORY_ID, RUN_ID):
        pass
    record = RepositoryLockRecord.model_validate(read_canonical_json(path))
    assert record.run_id == RUN_ID


def test_interruption_during_lock_record_write_releases_os_lock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    locks = tmp_path / "locks"
    with monkeypatch.context() as interruption:
        interruption.setattr(
            "proofpatch.services.locks.canonical_json_bytes",
            lambda _value: (_ for _ in ()).throw(KeyboardInterrupt()),
        )
        with pytest.raises(KeyboardInterrupt):
            RepositoryLock(locks, REPOSITORY_ID, RUN_ID).acquire()
    with RepositoryLock(locks, REPOSITORY_ID, RUN_ID_2):
        pass


def test_repository_lock_rejects_symlink_when_supported(tmp_path: Path) -> None:
    locks = tmp_path / "locks"
    locks.mkdir()
    target = tmp_path / "target"
    target.touch()
    link = locks / f"{REPOSITORY_ID}.lock"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("symbolic links are unavailable for this Windows account")
    with pytest.raises(RepositoryError, match="link or junction"):
        RepositoryLock(locks, REPOSITORY_ID, RUN_ID).acquire()


def test_repository_lock_rejects_hardlinks_without_modifying_target(tmp_path: Path) -> None:
    locks = tmp_path / "locks"
    locks.mkdir()
    target = tmp_path / "outside-target"
    target.write_bytes(b"outside-data")
    os.link(target, locks / f"{REPOSITORY_ID}.lock")
    with pytest.raises(RepositoryError, match="regular file"):
        RepositoryLock(locks, REPOSITORY_ID, RUN_ID).acquire()
    assert target.read_bytes() == b"outside-data"


def test_repository_lock_rejects_linked_lock_directory_when_supported(tmp_path: Path) -> None:
    real_locks = tmp_path / "real-locks"
    real_locks.mkdir()
    linked_locks = tmp_path / "linked-locks"
    try:
        linked_locks.symlink_to(real_locks, target_is_directory=True)
    except OSError:
        pytest.skip("symbolic links are unavailable for this Windows account")
    with pytest.raises(RepositoryError, match="lock directory"):
        RepositoryLock(linked_locks, REPOSITORY_ID, RUN_ID).acquire()


def test_live_repository_lock_detects_path_identity_substitution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    locks = tmp_path / "locks"
    lock = RepositoryLock(locks, REPOSITORY_ID, RUN_ID)
    with lock:
        original_lstat = Path.lstat
        original_status = lock.path.lstat()

        def substituted_lstat(path: Path) -> os.stat_result:
            status = original_lstat(path)
            if path == lock.path:
                values = list(status)
                values[1] = status.st_ino + 1
                return os.stat_result(values)
            return status

        monkeypatch.setattr(Path, "lstat", substituted_lstat)
        with pytest.raises(RepositoryError, match="substituted"):
            lock.assert_held()
        monkeypatch.setattr(Path, "lstat", original_lstat)
        assert original_status.st_ino == lock.path.lstat().st_ino


def _owned_run(data_root: Path) -> Path:
    run_root = data_root / "runs" / REPOSITORY_ID / RUN_ID
    run_root.mkdir(parents=True)
    manifest = RunManifest(
        run_id=RUN_ID,
        repository_id=REPOSITORY_ID,
        repository_root="C:/repository",
        created_at_utc=TIMESTAMP,
    )
    write_canonical_json(run_root / "run.json", manifest.model_dump(mode="json"))
    return run_root


def test_cleanup_accepts_only_owned_run_and_cache_descendants(tmp_path: Path) -> None:
    data = tmp_path / "data"
    cache_item = data / "cache" / "item"
    cache_item.mkdir(parents=True)
    run_root = _owned_run(data)
    work = run_root / "work"
    work.mkdir()

    assert validate_cleanup_target(data, cache_item).kind is CleanupTargetKind.CACHE_DESCENDANT
    assert validate_cleanup_target(data, run_root).kind is CleanupTargetKind.RUN
    assert validate_cleanup_target(data, work).kind is CleanupTargetKind.RUN_DESCENDANT


def test_cleanup_revalidation_rejects_a_replaced_target(tmp_path: Path) -> None:
    data = tmp_path / "data"
    target = data / "cache" / "item"
    target.mkdir(parents=True)
    validated = validate_cleanup_target(data, target)
    old_target = data / "cache" / "old-item"
    target.rename(old_target)
    target.mkdir()

    with pytest.raises(CleanupError, match="changed after validation"):
        revalidate_cleanup_target(data, validated)


def test_cleanup_revalidation_accepts_the_unchanged_target(tmp_path: Path) -> None:
    data = tmp_path / "data"
    target = data / "cache" / "item"
    target.mkdir(parents=True)
    validated = validate_cleanup_target(data, target)
    assert revalidate_cleanup_target(data, validated) == validated


def test_cleanup_removes_only_an_owned_link_free_run_descendant(tmp_path: Path) -> None:
    data = tmp_path / "data"
    (data / "cache").mkdir(parents=True)
    target = _owned_run(data) / "workspaces"
    nested = target / "clone" / "objects"
    nested.mkdir(parents=True)
    (nested / "pack").write_bytes(b"data")

    remove_owned_tree(data, target)

    assert not target.exists()
    assert list((data / "cache").iterdir()) == []


def test_cleanup_removal_rejects_run_root_file_and_rename_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data = tmp_path / "data"
    (data / "cache").mkdir(parents=True)
    run = _owned_run(data)
    with pytest.raises(CleanupError, match="descendant"):
        remove_owned_tree(data, run)
    artifact = run / "artifact"
    artifact.write_text("data", encoding="utf-8")
    with pytest.raises(CleanupError, match="directory"):
        remove_owned_tree(data, artifact)
    target = run / "workspaces"
    target.mkdir()
    monkeypatch.setattr(os, "rename", lambda *_args: (_ for _ in ()).throw(OSError("no")))
    with pytest.raises(CleanupError, match="safely remove"):
        remove_owned_tree(data, target)


def test_cleanup_descendant_scan_and_readonly_retry_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from proofpatch.services.cleanup import _reject_linked_descendants, _remove_readonly

    root = tmp_path / "scan"
    root.mkdir()
    monkeypatch.setattr(os, "walk", lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError()))
    with pytest.raises(CleanupError, match="inspect the cleanup tree"):
        _reject_linked_descendants(root)

    target = tmp_path / "readonly"
    target.write_text("value", encoding="utf-8")
    called: list[str] = []
    _remove_readonly(lambda path: called.append(path), str(target), OSError("readonly"))
    assert called == [str(target)]


def test_internal_data_path_validation_is_contained_and_fail_closed(tmp_path: Path) -> None:
    data = tmp_path / "data"
    existing = data / "runs"
    existing.mkdir(parents=True)
    assert validate_proofpatch_data_path(data, existing) == existing.resolve()

    missing = existing / "missing"
    assert validate_proofpatch_data_path(data, missing, allow_missing=True) == missing.resolve()
    with pytest.raises(InternalInvariantError, match="does not exist"):
        validate_proofpatch_data_path(data, missing)

    outside = tmp_path / "outside"
    outside.mkdir()
    with pytest.raises(InternalInvariantError, match="escapes"):
        validate_proofpatch_data_path(data, outside)


def test_cleanup_component_inspection_errors_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data = tmp_path / "data"
    target = data / "cache" / "item"
    target.mkdir(parents=True)
    original_lstat = Path.lstat

    def failing_lstat(path: Path) -> os.stat_result:
        if path == target:
            raise OSError("simulated metadata failure")
        return original_lstat(path)

    monkeypatch.setattr(Path, "lstat", failing_lstat)
    with pytest.raises(CleanupError, match="inspect cleanup path"):
        validate_cleanup_target(data, target)


def test_cleanup_rejects_roots_outside_missing_and_unowned_paths(tmp_path: Path) -> None:
    data = tmp_path / "data"
    data.mkdir()
    (data / "cache").mkdir()
    (data / "runs" / REPOSITORY_ID).mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.mkdir()

    rejected = (
        data,
        data / "cache",
        data / "runs",
        data / "runs" / REPOSITORY_ID,
        outside,
        data / "missing",
    )
    for target in rejected:
        with pytest.raises(CleanupError):
            validate_cleanup_target(data, target)

    with pytest.raises(CleanupError, match="data root"):
        validate_cleanup_target(tmp_path / "missing-data", outside)


def test_cleanup_rejects_bad_or_mismatched_ownership_markers(tmp_path: Path) -> None:
    data = tmp_path / "data"
    bad_id_run = data / "runs" / "repo_bad" / RUN_ID
    bad_id_run.mkdir(parents=True)
    with pytest.raises(CleanupError, match="invalid ProofPatch identifiers"):
        validate_cleanup_target(data, bad_id_run)

    run_root = _owned_run(data)
    manifest = RunManifest(
        run_id=RUN_ID_2,
        repository_id=REPOSITORY_ID,
        repository_root="C:/repository",
        created_at_utc=TIMESTAMP,
    )
    write_canonical_json(
        run_root / "run.json",
        manifest.model_dump(mode="json"),
        exclusive=False,
    )
    with pytest.raises(CleanupError, match="does not match"):
        validate_cleanup_target(data, run_root)

    (run_root / "run.json").write_bytes(b"not-json\n")
    with pytest.raises(CleanupError, match="no valid canonical"):
        validate_cleanup_target(data, run_root)


def test_cleanup_rejects_link_components_when_supported(tmp_path: Path) -> None:
    data = tmp_path / "data"
    real = data / "cache" / "real"
    real.mkdir(parents=True)
    link = data / "cache" / "link"
    try:
        link.symlink_to(real, target_is_directory=True)
    except OSError:
        pytest.skip("symbolic links are unavailable for this Windows account")
    with pytest.raises(CleanupError, match="link or junction"):
        validate_cleanup_target(data, link)


def test_application_directory_override_and_derived_paths(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    selected = tmp_path / "data"
    monkeypatch.setenv(DATA_DIRECTORY_ENV, str(selected))
    directories = get_app_directories()
    assert directories == ApplicationDirectories(selected)
    assert directories.index == selected / "index.sqlite3"
    assert directories.locks == selected / "locks"
    assert directories.runs == selected / "runs"
    directories.ensure_exists()
    assert all(path.is_dir() for path in (directories.cache, directories.locks, directories.runs))

    monkeypatch.setenv(DATA_DIRECTORY_ENV, "relative/path")
    with pytest.raises(ValueError, match="absolute"):
        get_app_directories()
