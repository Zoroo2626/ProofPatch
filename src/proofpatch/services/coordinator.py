"""Phase 1 run lifecycle coordinated around authoritative verified evidence."""

from pathlib import Path

from pydantic import ValidationError

from proofpatch.errors import (
    EvidenceIntegrityError,
    InternalInvariantError,
    InvalidStateTransition,
    RepositoryError,
    UserInputError,
)
from proofpatch.models.common import (
    JsonValue,
    format_utc_timestamp,
    validate_repository_id,
    validate_run_id,
)
from proofpatch.models.events import EvidenceEvent
from proofpatch.models.run import (
    RunManifest,
    RunPaths,
    RunRecord,
    RunStatus,
    build_run_paths,
)
from proofpatch.models.state import RunState, validate_transition
from proofpatch.security.paths import validate_proofpatch_data_path
from proofpatch.services.data_directories import ApplicationDirectories
from proofpatch.services.evidence import (
    EvidenceWriter,
    read_canonical_json,
    verify_event_chain,
    write_canonical_json,
)
from proofpatch.services.identifiers import generate_run_id, normalize_identity_path
from proofpatch.services.locks import RepositoryLock
from proofpatch.services.run_store import RunStore


class RunCoordinator:
    """Create, transition, and inspect runs without executing project commands."""

    def __init__(self, directories: ApplicationDirectories) -> None:
        self.directories = directories
        directories.ensure_exists()
        self.store = RunStore(directories.index)

    def create_run(
        self,
        repository_id: str,
        repository_root: Path,
        *,
        run_id: str | None = None,
    ) -> RunStatus:
        """Create an evidence-backed run in the initial ``CREATED`` state."""

        selected_run_id = generate_run_id() if run_id is None else _validated_run_id(run_id)
        selected_repository_id = _validated_repository_id(repository_id)
        try:
            normalized_root = normalize_identity_path(repository_root)
        except (OSError, RuntimeError) as error:
            raise RepositoryError(f"Repository root does not exist: {repository_root}") from error
        paths = build_run_paths(
            self.directories.data,
            selected_repository_id,
            selected_run_id,
        )
        self._validated_data_path(paths.root, allow_missing=True)
        with RepositoryLock(
            self.directories.locks,
            selected_repository_id,
            selected_run_id,
        ) as repository_lock:
            repository_lock.assert_held()
            try:
                paths.root.mkdir(mode=0o700, parents=True, exist_ok=False)
                paths.root.chmod(0o700)
            except FileExistsError as error:
                raise InternalInvariantError(
                    f"Run storage already exists: {selected_run_id}"
                ) from error
            self._validated_data_path(paths.root)

            created_at = format_utc_timestamp()
            manifest = RunManifest(
                run_id=selected_run_id,
                repository_id=selected_repository_id,
                repository_root=normalized_root,
                created_at_utc=created_at,
            )
            write_canonical_json(paths.manifest, manifest.model_dump(mode="json"))
            repository_lock.assert_held()
            event = EvidenceWriter(paths.events, paths.chain, selected_run_id).append(
                "run.created",
                timestamp_utc=created_at,
                payload={
                    "repository_id": selected_repository_id,
                    "repository_root": normalized_root,
                    "state": RunState.CREATED.value,
                },
            )
            record = _make_record(
                manifest,
                RunState.CREATED,
                event.timestamp_utc,
                event.sequence,
                event.event_hash,
                paths,
                self.directories.data,
            )
            self.store.insert(record)
        return self.status(selected_run_id)

    def transition(
        self,
        run_id: str,
        target: RunState,
        *,
        details: dict[str, JsonValue] | None = None,
    ) -> RunStatus:
        """Persist one valid state change while holding the repository lock."""

        if not isinstance(target, RunState):
            raise InvalidStateTransition(f"Invalid run state target: {target!r}")
        paths = self._locate_run(_validated_run_id(run_id))
        manifest = _read_manifest(paths)
        with RepositoryLock(
            self.directories.locks,
            manifest.repository_id,
            manifest.run_id,
        ) as repository_lock:
            self._persist_transition_while_locked(paths, manifest, target, repository_lock, details)
        return self.status(run_id)

    def transition_while_locked(
        self,
        run_id: str,
        target: RunState,
        repository_lock: RepositoryLock,
        *,
        details: dict[str, JsonValue] | None = None,
    ) -> RunStatus:
        """Persist a transition using the caller's already-held matching repository lock."""

        if not isinstance(target, RunState):
            raise InvalidStateTransition(f"Invalid run state target: {target!r}")
        paths = self._locate_run(_validated_run_id(run_id))
        manifest = _read_manifest(paths)
        if (
            repository_lock.repository_id != manifest.repository_id
            or repository_lock.run_id != manifest.run_id
        ):
            raise RepositoryError("Repository lock identity does not match the run")
        self._persist_transition_while_locked(paths, manifest, target, repository_lock, details)
        return self._verified_status(paths)

    def paths_for(self, run_id: str) -> RunPaths:
        """Return validated run-owned paths only after authoritative evidence verifies."""

        paths = self._locate_run(_validated_run_id(run_id))
        self._verified_status(paths)
        return paths

    def status(self, run_id: str) -> RunStatus:
        """Inspect authoritative evidence without acquiring a mutating lock."""

        paths = self._locate_run(_validated_run_id(run_id))
        return self._verified_status(paths)

    def append_event(
        self,
        run_id: str,
        event_type: str,
        *,
        payload: dict[str, JsonValue] | None = None,
    ) -> EvidenceEvent:
        """Append a non-state controller event and keep the query index synchronized."""

        paths = self._locate_run(_validated_run_id(run_id))
        manifest = _read_manifest(paths)
        with RepositoryLock(
            self.directories.locks,
            manifest.repository_id,
            manifest.run_id,
        ) as repository_lock:
            repository_lock.assert_held()
            current = self._verified_status(paths)
            event = EvidenceWriter(paths.events, paths.chain, manifest.run_id).append(
                event_type,
                payload=payload,
            )
            self.store.upsert(
                _make_record(
                    manifest,
                    current.state,
                    event.timestamp_utc,
                    event.sequence,
                    event.event_hash,
                    paths,
                    self.directories.data,
                )
            )
            return event

    def append_event_while_locked(
        self,
        run_id: str,
        event_type: str,
        repository_lock: RepositoryLock,
        *,
        payload: dict[str, JsonValue] | None = None,
    ) -> EvidenceEvent:
        """Append an event using a caller-held matching repository lock."""

        paths = self._locate_run(_validated_run_id(run_id))
        manifest = _read_manifest(paths)
        if (
            repository_lock.repository_id != manifest.repository_id
            or repository_lock.run_id != manifest.run_id
        ):
            raise RepositoryError("Repository lock identity does not match the run")
        repository_lock.assert_held()
        current = self._verified_status(paths)
        event = EvidenceWriter(paths.events, paths.chain, manifest.run_id).append(
            event_type,
            payload=payload,
        )
        self.store.upsert(
            _make_record(
                manifest,
                current.state,
                event.timestamp_utc,
                event.sequence,
                event.event_hash,
                paths,
                self.directories.data,
            )
        )
        return event

    def inspect(self, run_id: str) -> RunStatus:
        """Return verified run details, including every event."""

        return self.status(run_id)

    def list_runs(self) -> tuple[RunStatus, ...]:
        """List every valid on-disk run, including runs absent from SQLite."""

        statuses: list[RunStatus] = []
        self._validated_data_path(self.directories.runs)
        for repository_directory in self.directories.runs.iterdir():
            try:
                validate_repository_id(repository_directory.name)
            except ValueError:
                continue
            validated_repository_directory = self._validated_data_path(repository_directory)
            if not validated_repository_directory.is_dir():
                continue
            for run_directory in repository_directory.iterdir():
                try:
                    run_id = validate_run_id(run_directory.name)
                except ValueError:
                    continue
                validated_run_directory = self._validated_data_path(run_directory)
                if not validated_run_directory.is_dir():
                    continue
                statuses.append(self.status(run_id))
        return tuple(
            sorted(
                statuses,
                key=lambda status: (status.updated_at_utc, status.manifest.run_id),
                reverse=True,
            )
        )

    def _verified_status(self, paths: RunPaths) -> RunStatus:
        self._validated_data_path(paths.root)
        manifest = _read_manifest(paths)
        verified = verify_event_chain(
            paths.events,
            paths.chain,
            expected_run_id=manifest.run_id,
        )
        state = _derive_state(manifest, verified.events)
        last_event = verified.events[-1]
        expected_record = _make_record(
            manifest,
            state,
            last_event.timestamp_utc,
            last_event.sequence,
            last_event.event_hash,
            paths,
            self.directories.data,
        )
        indexed_record = self._safe_index_get(manifest.run_id)
        return RunStatus(
            manifest=manifest,
            state=state,
            updated_at_utc=last_event.timestamp_utc,
            event_count=len(verified.events),
            final_event_hash=verified.final_hash,
            index_consistent=indexed_record == expected_record,
            events=verified.events,
        )

    def _persist_transition_while_locked(
        self,
        paths: RunPaths,
        manifest: RunManifest,
        target: RunState,
        repository_lock: RepositoryLock,
        details: dict[str, JsonValue] | None,
    ) -> None:
        repository_lock.assert_held()
        current_status = self._verified_status(paths)
        validate_transition(current_status.state, target)
        payload: dict[str, JsonValue] = {
            "from_state": current_status.state.value,
            "to_state": target.value,
        }
        if details is not None:
            payload["details"] = details
        repository_lock.assert_held()
        event = EvidenceWriter(paths.events, paths.chain, manifest.run_id).append(
            "run.state_changed",
            payload=payload,
        )
        record = _make_record(
            manifest,
            target,
            event.timestamp_utc,
            event.sequence,
            event.event_hash,
            paths,
            self.directories.data,
        )
        self.store.upsert(record)

    def _locate_run(self, run_id: str) -> RunPaths:
        matches: list[RunPaths] = []
        self._validated_data_path(self.directories.runs)
        for repository_directory in self.directories.runs.iterdir():
            try:
                validate_repository_id(repository_directory.name)
            except ValueError:
                continue
            validated_repository_directory = self._validated_data_path(repository_directory)
            if not validated_repository_directory.is_dir():
                continue
            candidate = repository_directory / run_id
            if not self._path_exists(candidate):
                continue
            validated_candidate = self._validated_data_path(candidate)
            if validated_candidate.is_dir():
                matches.append(
                    build_run_paths(
                        self.directories.data,
                        repository_directory.name,
                        run_id,
                    )
                )
        if not matches:
            raise UserInputError(f"Unknown ProofPatch run ID: {run_id}")
        if len(matches) > 1:
            raise InternalInvariantError(f"Run ID appears under multiple repositories: {run_id}")
        return matches[0]

    def _safe_index_get(self, run_id: str) -> RunRecord | None:
        try:
            return self.store.get(run_id)
        except InternalInvariantError:
            return None

    def _validated_data_path(self, path: Path, *, allow_missing: bool = False) -> Path:
        try:
            return validate_proofpatch_data_path(
                self.directories.data,
                path,
                allow_missing=allow_missing,
            )
        except InternalInvariantError as error:
            raise EvidenceIntegrityError(f"Unsafe ProofPatch run storage path: {path}") from error

    def _path_exists(self, path: Path) -> bool:
        try:
            path.lstat()
        except FileNotFoundError:
            return False
        except OSError as error:
            raise EvidenceIntegrityError(
                f"Could not inspect ProofPatch run storage path: {path}"
            ) from error
        return True


def _derive_state(manifest: RunManifest, events: tuple[EvidenceEvent, ...]) -> RunState:
    if not events:
        raise EvidenceIntegrityError("Evidence chain has no typed events")
    first = events[0]
    if first.type != "run.created" or first.payload.get("state") != RunState.CREATED.value:
        raise EvidenceIntegrityError("First evidence event must create the run in CREATED state")
    if first.actor != "proofpatch":
        raise EvidenceIntegrityError("Run creation event has an unauthorized actor")
    if first.payload.get("repository_id") != manifest.repository_id:
        raise EvidenceIntegrityError(
            "Run creation event repository identity does not match manifest"
        )
    if first.payload.get("repository_root") != manifest.repository_root:
        raise EvidenceIntegrityError("Run creation event repository root does not match manifest")
    if first.timestamp_utc != manifest.created_at_utc:
        raise EvidenceIntegrityError("Run creation event timestamp does not match manifest")

    state = RunState.CREATED
    for event in events[1:]:
        if event.type == "run.created":
            raise EvidenceIntegrityError("Evidence chain contains more than one run creation event")
        if event.type != "run.state_changed":
            continue
        if event.actor != "proofpatch":
            raise EvidenceIntegrityError("State-change evidence has an unauthorized actor")
        from_state = event.payload.get("from_state")
        to_state = event.payload.get("to_state")
        if from_state != state.value or not isinstance(to_state, str):
            raise EvidenceIntegrityError("State-change evidence does not match the derived state")
        try:
            target = RunState(to_state)
            validate_transition(state, target)
        except (ValueError, InvalidStateTransition) as error:
            raise EvidenceIntegrityError("Evidence contains an invalid state transition") from error
        state = target
    return state


def _read_manifest(paths: RunPaths) -> RunManifest:
    try:
        manifest = RunManifest.model_validate(read_canonical_json(paths.manifest))
    except (ValidationError, EvidenceIntegrityError) as error:
        raise EvidenceIntegrityError(f"Run manifest is invalid: {paths.manifest}") from error
    if manifest.run_id != paths.root.name or manifest.repository_id != paths.root.parent.name:
        raise EvidenceIntegrityError("Run manifest identifiers do not match its storage path")
    return manifest


def _make_record(
    manifest: RunManifest,
    state: RunState,
    updated_at_utc: str,
    sequence: int,
    event_hash: str,
    paths: RunPaths,
    data_root: Path,
) -> RunRecord:
    try:
        relative = paths.root.relative_to(data_root).as_posix()
    except ValueError as error:
        raise InternalInvariantError("Run path is outside the application data root") from error
    return RunRecord(
        run_id=manifest.run_id,
        repository_id=manifest.repository_id,
        repository_root=manifest.repository_root,
        state=state,
        created_at_utc=manifest.created_at_utc,
        updated_at_utc=updated_at_utc,
        last_event_sequence=sequence,
        last_event_hash=event_hash,
        run_relative_path=relative,
    )


def _validated_run_id(run_id: str) -> str:
    try:
        return validate_run_id(run_id)
    except ValueError as error:
        raise UserInputError(f"Invalid ProofPatch run ID: {run_id}") from error


def _validated_repository_id(repository_id: str) -> str:
    try:
        return validate_repository_id(repository_id)
    except ValueError as error:
        raise UserInputError(f"Invalid ProofPatch repository ID: {repository_id}") from error
