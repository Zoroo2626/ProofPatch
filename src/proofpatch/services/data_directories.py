"""Cross-platform locations for ProofPatch-owned application data."""

import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from platformdirs import PlatformDirs

from proofpatch.constants import APPLICATION_NAME

PRIVATE_DIRECTORY_MODE: Final = 0o700
DATA_DIRECTORY_ENV: Final = "PROOFPATCH_DATA_DIR"


@dataclass(frozen=True, slots=True)
class ApplicationDirectories:
    """The platform-selected ProofPatch data root and its derived paths."""

    data: Path

    @property
    def cache(self) -> Path:
        """Return the cache location inside the authoritative data root."""

        return self.data / "cache"

    @property
    def index(self) -> Path:
        """Return the rebuildable SQLite metadata index path."""

        return self.data / "index.sqlite3"

    @property
    def locks(self) -> Path:
        """Return the directory containing per-repository OS locks."""

        return self.data / "locks"

    @property
    def runs(self) -> Path:
        """Return the authoritative run evidence directory."""

        return self.data / "runs"

    def ensure_exists(self) -> None:
        """Create the application directories without deleting existing data."""

        for path in (self.data, self.cache, self.locks, self.runs):
            path.mkdir(mode=PRIVATE_DIRECTORY_MODE, parents=True, exist_ok=True)
            file_status = path.lstat()
            attributes = getattr(file_status, "st_file_attributes", 0)
            reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
            if (
                not stat.S_ISDIR(file_status.st_mode)
                or stat.S_ISLNK(file_status.st_mode)
                or bool(attributes & reparse_flag)
            ):
                raise ValueError(
                    f"ProofPatch application directory is not a private directory: {path}"
                )
            path.chmod(PRIVATE_DIRECTORY_MODE)


def get_app_directories() -> ApplicationDirectories:
    """Resolve platform-appropriate directories without creating them."""

    override = os.environ.get(DATA_DIRECTORY_ENV)
    if override is not None:
        path = Path(override)
        if not path.is_absolute():
            raise ValueError(f"{DATA_DIRECTORY_ENV} must be an absolute path")
        return ApplicationDirectories(data=path)
    directories = PlatformDirs(appname=APPLICATION_NAME, appauthor=False, roaming=False)
    return ApplicationDirectories(data=Path(directories.user_data_path))
