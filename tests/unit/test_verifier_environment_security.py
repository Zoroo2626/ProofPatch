"""Adversarial coverage for verifier workspace and environment boundaries."""

import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from proofpatch.backends.docker import _container_environment_file
from proofpatch.errors import BackendError, ConfigurationError, EvidenceIntegrityError
from proofpatch.security.workspace import _hash_regular, _lstat, workspace_content_sha256
from proofpatch.services.environment import merge_verifier_environment


def test_workspace_hash_is_deterministic_and_content_bound(tmp_path: Path) -> None:
    root = tmp_path / "workspace"
    nested = root / "nested"
    nested.mkdir(parents=True)
    (root / "one.txt").write_bytes(b"one")
    (nested / "two.txt").write_bytes(b"two")

    first = workspace_content_sha256(root, maximum_bytes=64)
    assert workspace_content_sha256(root, maximum_bytes=64) == first
    (nested / "two.txt").write_bytes(b"changed")
    assert workspace_content_sha256(root, maximum_bytes=64) != first


def test_workspace_hash_rejects_invalid_roots_and_size_limits(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="positive"):
        workspace_content_sha256(tmp_path, maximum_bytes=0)
    with pytest.raises(EvidenceIntegrityError, match="unavailable"):
        workspace_content_sha256(tmp_path / "missing", maximum_bytes=10)
    file_root = tmp_path / "file-root"
    file_root.write_bytes(b"content")
    with pytest.raises(EvidenceIntegrityError, match="private directory"):
        workspace_content_sha256(file_root, maximum_bytes=10)
    root = tmp_path / "too-large"
    root.mkdir()
    (root / "large.bin").write_bytes(b"12345")
    with pytest.raises(EvidenceIntegrityError, match="size limit"):
        workspace_content_sha256(root, maximum_bytes=4)


def test_workspace_hash_rejects_hardlinks_and_symlinks(tmp_path: Path) -> None:
    root = tmp_path / "hardlinks"
    root.mkdir()
    first = root / "first"
    first.write_bytes(b"same inode")
    os.link(first, root / "second")
    with pytest.raises(EvidenceIntegrityError, match="unsafe file"):
        workspace_content_sha256(root, maximum_bytes=100)

    target = tmp_path / "target"
    target.write_text("target", encoding="utf-8")
    link_root = tmp_path / "links"
    link_root.mkdir()
    try:
        (link_root / "link").symlink_to(target)
    except OSError:
        return
    digest = workspace_content_sha256(link_root, maximum_bytes=100)
    target.write_text("changed outside workspace", encoding="utf-8")
    assert workspace_content_sha256(link_root, maximum_bytes=100) == digest


def test_regular_file_hash_detects_races_and_read_failures(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "file"
    path.write_bytes(b"content")
    expected = path.lstat()
    real_fstat = os.fstat
    calls = 0

    def changed_fstat(descriptor: int) -> object:
        nonlocal calls
        calls += 1
        status = real_fstat(descriptor)
        if calls == 1:
            return status
        return SimpleNamespace(
            st_mode=status.st_mode,
            st_nlink=status.st_nlink,
            st_dev=status.st_dev,
            st_ino=status.st_ino,
            st_size=status.st_size,
            st_mtime_ns=status.st_mtime_ns + 1,
            st_ctime_ns=status.st_ctime_ns,
        )

    monkeypatch.setattr("proofpatch.security.workspace.os.fstat", changed_fstat)
    with pytest.raises(EvidenceIntegrityError, match="changed while hashing"):
        _hash_regular(path, expected, 100)
    monkeypatch.setattr("proofpatch.security.workspace.os.fstat", real_fstat)
    with pytest.raises(EvidenceIntegrityError, match="size limit"):
        _hash_regular(path, expected, -1)
    with pytest.raises(EvidenceIntegrityError, match="safely hash"):
        _hash_regular(tmp_path / "missing", expected, 100)

    def mismatched_fstat(descriptor: int) -> object:
        status = real_fstat(descriptor)
        return SimpleNamespace(
            st_mode=status.st_mode,
            st_nlink=status.st_nlink,
            st_dev=status.st_dev,
            st_ino=status.st_ino + 1,
        )

    monkeypatch.setattr("proofpatch.security.workspace.os.fstat", mismatched_fstat)
    with pytest.raises(EvidenceIntegrityError, match="identity changed"):
        _hash_regular(path, expected, 100)
    monkeypatch.setattr("proofpatch.security.workspace.os.fstat", real_fstat)

    def fail_read(_descriptor: int, _size: int) -> bytes:
        raise OSError("read failed")

    monkeypatch.setattr("proofpatch.security.workspace.os.read", fail_read)
    with pytest.raises(EvidenceIntegrityError, match="safely hash"):
        _hash_regular(path, expected, 100)
    with pytest.raises(EvidenceIntegrityError, match="inspect"):
        _lstat(tmp_path / "absent")


def test_container_environment_file_empty_and_creation_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with _container_environment_file({}) as path:
        assert path is None

    def fail_creation(*_args: object, **_kwargs: object) -> str:
        raise OSError("no private temp directory")

    monkeypatch.setattr("proofpatch.backends.docker.tempfile.mkdtemp", fail_creation)
    with (
        pytest.raises(BackendError, match="private container environment"),
        _container_environment_file({"TOKEN": "value"}),
    ):
        pass


def test_container_environment_file_short_write_is_cleaned_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("proofpatch.backends.docker.os.write", lambda *_args: 0)
    with (
        pytest.raises(BackendError, match="private container environment"),
        _container_environment_file({"TOKEN": "value"}),
    ):
        pass


def test_fixed_verifier_environment_rejects_conflicting_overrides() -> None:
    assert merge_verifier_environment({"CUSTOM": "value"})["TZ"] == "UTC"
    with pytest.raises(ConfigurationError, match="cannot override"):
        merge_verifier_environment({"TZ": "local"})
