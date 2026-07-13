"""Tests for cross-platform application directory resolution."""

import os
from pathlib import Path

import pytest

from proofpatch.services import ApplicationDirectories, get_app_directories


def test_platform_directories_are_resolved_without_creation() -> None:
    directories = get_app_directories()

    assert isinstance(directories.data, Path)
    assert isinstance(directories.cache, Path)
    assert directories.data.name.lower() == "proofpatch"
    assert directories.cache == directories.data / "cache"


def test_application_directories_are_created_idempotently(tmp_path: Path) -> None:
    directories = ApplicationDirectories(data=tmp_path / "nested" / "data")

    directories.ensure_exists()
    directories.ensure_exists()

    assert directories.data.is_dir()
    assert directories.cache.is_dir()

    if os.name == "posix":
        assert directories.data.stat().st_mode & 0o777 == 0o700
        assert directories.cache.stat().st_mode & 0o777 == 0o700


def test_application_data_root_rejects_links_when_supported(tmp_path: Path) -> None:
    real = tmp_path / "real-data"
    real.mkdir()
    linked = tmp_path / "linked-data"
    try:
        linked.symlink_to(real, target_is_directory=True)
    except OSError:
        pytest.skip("symbolic links are unavailable for this Windows account")

    with pytest.raises(ValueError, match="not a private directory"):
        ApplicationDirectories(linked).ensure_exists()
