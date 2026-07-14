"""Rebuildable SQLite metadata for authoritative evidence-backed runs."""

import os
import sqlite3
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Final

from proofpatch.errors import InternalInvariantError
from proofpatch.models.run import RunRecord
from proofpatch.models.state import RunState

DATABASE_SCHEMA_VERSION: Final = 1
PRIVATE_FILE_MODE: Final = 0o600

_SCHEMA_STATEMENTS = (
    """CREATE TABLE IF NOT EXISTS runs (
        schema_version INTEGER NOT NULL CHECK (schema_version = 1),
        run_id TEXT PRIMARY KEY,
        repository_id TEXT NOT NULL,
        repository_root TEXT NOT NULL,
        state TEXT NOT NULL,
        created_at_utc TEXT NOT NULL,
        updated_at_utc TEXT NOT NULL,
        last_event_sequence INTEGER NOT NULL CHECK (last_event_sequence >= 1),
        last_event_hash TEXT NOT NULL,
        run_relative_path TEXT NOT NULL
    )""",
    """CREATE INDEX IF NOT EXISTS runs_repository_updated
        ON runs(repository_id, updated_at_utc DESC)""",
)

_COLUMNS = """
schema_version, run_id, repository_id, repository_root, state,
created_at_utc, updated_at_utc, last_event_sequence, last_event_hash,
run_relative_path
"""


class RunStore:
    """Own SQLite access without treating the index as evidence."""

    def __init__(self, database_path: Path) -> None:
        self.database_path = database_path
        self.database_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        _validate_database_path(self.database_path)
        self._initialize()

    def insert(self, record: RunRecord) -> None:
        """Insert a newly created run without overwriting an existing identity."""

        values = _record_values(record)
        try:
            with self._connect(write=True) as connection:
                connection.execute(
                    f"INSERT INTO runs ({_COLUMNS}) VALUES ({','.join('?' for _ in values)})",  # noqa: S608
                    values,
                )
        except sqlite3.IntegrityError as error:
            raise InternalInvariantError(
                f"Run ID already exists in metadata: {record.run_id}"
            ) from error

    def upsert(self, record: RunRecord) -> None:
        """Rebuild or reconcile a metadata row from verified evidence."""

        values = _record_values(record)
        updates = ", ".join(
            f"{column}=excluded.{column}"
            for column in (
                "schema_version",
                "repository_id",
                "repository_root",
                "state",
                "created_at_utc",
                "updated_at_utc",
                "last_event_sequence",
                "last_event_hash",
                "run_relative_path",
            )
        )
        with self._connect(write=True) as connection:
            connection.execute(
                f"""INSERT INTO runs ({_COLUMNS})
                VALUES ({",".join("?" for _ in values)})
                ON CONFLICT(run_id) DO UPDATE SET {updates}""",  # noqa: S608
                values,
            )

    def get(self, run_id: str) -> RunRecord | None:
        """Return an indexed run, or ``None`` when the index has no row."""

        with self._connect() as connection:
            row = connection.execute(
                f"SELECT {_COLUMNS} FROM runs WHERE run_id = ?",  # noqa: S608
                (run_id,),
            ).fetchone()
        return None if row is None else _record_from_row(row)

    def list(self) -> tuple[RunRecord, ...]:
        """Return indexed runs in deterministic newest-first order."""

        with self._connect() as connection:
            rows = connection.execute(
                f"SELECT {_COLUMNS} FROM runs ORDER BY updated_at_utc DESC, run_id DESC"  # noqa: S608
            ).fetchall()
        return tuple(_record_from_row(row) for row in rows)

    def _initialize(self) -> None:
        self._configure_journal()
        os.chmod(self.database_path, PRIVATE_FILE_MODE)
        with self._connect(write=True) as connection:
            current = int(connection.execute("PRAGMA user_version").fetchone()[0])
            if current not in (0, DATABASE_SCHEMA_VERSION):
                raise InternalInvariantError(
                    f"Unsupported SQLite schema version: {current}",
                    remediation="Upgrade ProofPatch before reading this metadata index.",
                )
            for statement in _SCHEMA_STATEMENTS:
                connection.execute(statement)
            connection.execute(f"PRAGMA user_version = {DATABASE_SCHEMA_VERSION}")
        os.chmod(self.database_path, PRIVATE_FILE_MODE)

    def _configure_journal(self) -> None:
        """Select WAL once instead of renegotiating it for every operation."""

        with self._connect() as connection:
            current = str(connection.execute("PRAGMA journal_mode").fetchone()[0]).lower()
            if current == "wal":
                return
            selected = str(connection.execute("PRAGMA journal_mode = WAL").fetchone()[0]).lower()
            if selected != "wal":
                raise InternalInvariantError("SQLite metadata index could not enable WAL mode")

    @contextmanager
    def _connect(self, *, write: bool = False) -> Iterator[sqlite3.Connection]:
        _validate_database_path(self.database_path)
        try:
            connection = sqlite3.connect(
                self.database_path,
                timeout=5.0,
                isolation_level=None,
            )
        except sqlite3.Error as error:
            raise InternalInvariantError("Could not open the SQLite metadata index") from error
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA synchronous = NORMAL")
            connection.execute("PRAGMA foreign_keys = ON")
            if write:
                connection.execute("BEGIN IMMEDIATE")
            yield connection
            if write:
                connection.commit()
        except sqlite3.IntegrityError:
            _rollback(connection)
            raise
        except sqlite3.Error as error:
            _rollback(connection)
            raise InternalInvariantError("SQLite metadata operation failed") from error
        except BaseException:
            _rollback(connection)
            raise
        finally:
            connection.close()


def _rollback(connection: sqlite3.Connection) -> None:
    if connection.in_transaction:
        connection.rollback()


def _record_values(record: RunRecord) -> tuple[object, ...]:
    return (
        record.schema_version,
        record.run_id,
        record.repository_id,
        record.repository_root,
        record.state.value,
        record.created_at_utc,
        record.updated_at_utc,
        record.last_event_sequence,
        record.last_event_hash,
        record.run_relative_path,
    )


def _record_from_row(row: sqlite3.Row) -> RunRecord:
    try:
        values = dict(row)
        values["state"] = RunState(values["state"])
        return RunRecord.model_validate(values)
    except ValueError as error:
        raise InternalInvariantError("SQLite metadata row has an invalid schema") from error


def _validate_database_path(path: Path) -> None:
    try:
        if path.is_symlink() or path.is_junction():
            raise InternalInvariantError("SQLite index path must not be a link or junction")
        if not path.exists():
            return
        file_status = path.lstat()
    except OSError as error:
        raise InternalInvariantError("Could not validate the SQLite index path") from error
    attributes = getattr(file_status, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    if (
        not stat.S_ISREG(file_status.st_mode)
        or bool(attributes & reparse_flag)
        or file_status.st_nlink != 1
    ):
        raise InternalInvariantError("SQLite index path must be a private regular file")
