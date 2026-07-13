"""Evidence-bound orchestration for repository baselines, patches, and apply."""

from pathlib import Path

from pydantic import ValidationError

from proofpatch.errors import ApplyError, EvidenceIntegrityError, PatchError, RepositoryError
from proofpatch.git.apply import apply_patch_bytes, check_patch_applies, verify_patch_in_fresh_clone
from proofpatch.git.client import GitClient
from proofpatch.git.clone import CloneKind, IndependentClone, create_independent_clone
from proofpatch.git.diff import capture_binary_patch, validate_changed_paths, verify_patch_hash
from proofpatch.models.common import JsonValue
from proofpatch.models.patch import AppliedPatch, PatchRecord, RepositorySnapshot
from proofpatch.models.run import RunPaths
from proofpatch.models.state import RunState
from proofpatch.security.paths import validate_proofpatch_data_path
from proofpatch.services.coordinator import RunCoordinator
from proofpatch.services.evidence import read_canonical_json, write_canonical_json
from proofpatch.services.locks import RepositoryLock
from proofpatch.services.receipt import ReceiptService
from proofpatch.services.repository import RepositoryService


class PatchService:
    """Coordinate Phase 2 operations under Phase 1 evidence and repository locks."""

    def __init__(self, coordinator: RunCoordinator, git: GitClient | None = None) -> None:
        self.coordinator = coordinator
        self.git = GitClient() if git is None else git
        self.repositories = RepositoryService(
            self.git,
            data_root=coordinator.directories.data,
        )

    def prepare_run(self, repository: Path, *, run_id: str | None = None) -> RepositorySnapshot:
        """Discover a clean baseline, create its run, and persist immutable repository facts."""

        snapshot = self.repositories.discover(repository)
        status = self.coordinator.create_run(
            snapshot.repository_id,
            Path(snapshot.repository_root),
            run_id=run_id,
        )
        paths = self.coordinator.paths_for(status.manifest.run_id)
        with RepositoryLock(
            self.coordinator.directories.locks,
            snapshot.repository_id,
            status.manifest.run_id,
        ) as repository_lock:
            for directory in (paths.baseline, paths.workspaces, paths.patch):
                directory.mkdir(mode=0o700, exist_ok=False)
            write_canonical_json(paths.repository, snapshot.model_dump(mode="json"))
            self.coordinator.transition_while_locked(
                status.manifest.run_id,
                RunState.PREFLIGHT,
                repository_lock,
                details={
                    "baseline_commit": snapshot.baseline_commit,
                    "branch": snapshot.branch,
                    "detached": snapshot.detached,
                    "remote": snapshot.remote,
                    "remote_url_redacted": snapshot.remote_url_redacted,
                },
            )
        return snapshot

    def create_clone(
        self,
        run_id: str,
        kind: CloneKind,
        *,
        workspace_name: str | None = None,
    ) -> IndependentClone:
        """Create a state-appropriate independent clone owned by the run."""

        status = self.coordinator.status(run_id)
        allowed = {
            CloneKind.INVESTIGATION: {
                RunState.BASELINE_PREPARING,
                RunState.INVESTIGATING,
            },
            CloneKind.BASELINE_VERIFICATION: {
                RunState.BASELINE_PREPARING,
                RunState.BASELINE_VERIFYING,
            },
            CloneKind.PATCH: {RunState.PATCH_PREPARING, RunState.PATCHING},
            CloneKind.FINAL_VERIFICATION: {
                RunState.PATCH_CAPTURED,
                RunState.FINAL_VERIFYING,
            },
        }
        if status.state not in allowed[kind]:
            raise RepositoryError(
                f"Cannot create {kind.value} clone while run is {status.state.value}"
            )
        paths = self.coordinator.paths_for(run_id)
        snapshot = self.load_repository(run_id)
        with RepositoryLock(
            self.coordinator.directories.locks,
            snapshot.repository_id,
            run_id,
        ) as repository_lock:
            repository_lock.assert_held()
            return create_independent_clone(
                self.git,
                snapshot,
                paths.root,
                kind,
                workspace_name=workspace_name,
            )

    def capture(
        self,
        run_id: str,
        clone: IndependentClone,
        *,
        allowed_paths: tuple[str, ...] = ("**",),
        denied_paths: tuple[str, ...] = (),
        max_patch_bytes: int = 50 * 1024 * 1024,
        max_changed_files: int = 1000,
    ) -> PatchRecord:
        """Capture and evidence-bind all effective changes from the disposable patch clone."""

        status = self.coordinator.status(run_id)
        if status.state is not RunState.PATCHING:
            raise PatchError(f"Patch capture requires PATCHING state, not {status.state.value}")
        paths = self.coordinator.paths_for(run_id)
        snapshot = self.load_repository(run_id)
        with RepositoryLock(
            self.coordinator.directories.locks,
            snapshot.repository_id,
            run_id,
        ) as repository_lock:
            repository_lock.assert_held()
            digest, size, changes = capture_binary_patch(
                self.git,
                clone,
                paths.root,
                paths.patch_diff,
                allowed_paths=allowed_paths,
                denied_paths=denied_paths,
                max_patch_bytes=max_patch_bytes,
                max_changed_files=max_changed_files,
            )
            record = PatchRecord(
                run_id=run_id,
                repository_id=snapshot.repository_id,
                baseline_commit=snapshot.baseline_commit,
                patch_sha256=digest,
                patch_size_bytes=size,
                changed_files=changes,
            )
            write_canonical_json(paths.changed_files, record.model_dump(mode="json"))
            details = _patch_evidence_details(record)
            self.coordinator.transition_while_locked(
                run_id,
                RunState.PATCH_CAPTURED,
                repository_lock,
                details=details,
            )
            return record

    def verify_application(
        self,
        run_id: str,
        *,
        workspace_name: str | None = None,
    ) -> Path:
        """Apply and exactly recapture the patch in the fresh final-verification clone."""

        status = self.coordinator.status(run_id)
        if status.state not in {RunState.PATCH_CAPTURED, RunState.FINAL_VERIFYING}:
            raise PatchError("Fresh patch verification requires a captured patch")
        paths = self.coordinator.paths_for(run_id)
        record = self.load_patch(run_id)
        self._verify_patch_binding(status.events, record)
        return verify_patch_in_fresh_clone(
            self.git,
            self.load_repository(run_id),
            paths.root,
            paths.patch_diff,
            record.patch_sha256,
            workspace_name=workspace_name,
        )

    def apply_verified(
        self,
        run_id: str,
        *,
        stage: bool = False,
        require_receipt: bool = True,
    ) -> AppliedPatch:
        """Apply a VERIFIED, evidence-bound patch to the clean matching original repository."""

        initial = self.coordinator.status(run_id)
        if initial.state is RunState.APPLIED:
            raise ApplyError("This ProofPatch run has already been applied")
        if initial.state is not RunState.VERIFIED:
            raise ApplyError(
                f"Only a VERIFIED run can be applied; current state is {initial.state.value}"
            )
        if require_receipt:
            receipt = ReceiptService(self.coordinator).verify(run_id)
            if receipt.status != "verified" or receipt.patch is None:
                raise EvidenceIntegrityError("Receipt does not authorize a verified patch")
        paths = self.coordinator.paths_for(run_id)
        snapshot = self.load_repository(run_id)
        record = self.load_patch(run_id)
        if require_receipt and (
            receipt.patch is None or receipt.patch.sha256 != record.patch_sha256
        ):
            raise EvidenceIntegrityError("Receipt patch hash does not match captured patch")
        self._verify_patch_binding(initial.events, record)
        allowed_paths: tuple[str, ...] = ("**",)
        denied_paths: tuple[str, ...] = ()
        if paths.workflow_plan.exists():
            plan = read_canonical_json(paths.workflow_plan)
            if not isinstance(plan, dict):
                raise EvidenceIntegrityError("Stored workflow path policy is invalid")
            raw_allowed = plan.get("allowed_patch_paths")
            raw_denied = plan.get("denied_patch_paths")
            if (
                not isinstance(raw_allowed, list)
                or not isinstance(raw_denied, list)
                or any(not isinstance(item, str) for item in (*raw_allowed, *raw_denied))
            ):
                raise EvidenceIntegrityError("Stored workflow path policy is invalid")
            allowed_paths = tuple(raw_allowed)
            denied_paths = tuple(raw_denied)
        validate_changed_paths(
            record.changed_files,
            allowed_paths=allowed_paths,
            denied_paths=denied_paths,
        )

        with RepositoryLock(
            self.coordinator.directories.locks,
            snapshot.repository_id,
            run_id,
        ) as repository_lock:
            current = self.coordinator.status(run_id)
            if current.state is not RunState.VERIFIED:
                raise ApplyError("Run state changed before patch application")
            try:
                self.repositories.assert_matches(snapshot)
                verify_patch_hash(paths.patch_diff, record.patch_sha256)
                check_patch_applies(self.git, Path(snapshot.repository_root), paths.patch_diff)
                result = self._apply_on_new_branch(paths, snapshot, record, stage=stage)
            except (PatchError, RepositoryError) as error:
                raise ApplyError(str(error)) from error
            repository_lock.assert_held()
            self.coordinator.transition_while_locked(
                run_id,
                RunState.APPLIED,
                repository_lock,
                details={
                    "branch": result.branch,
                    "previous_revision": result.previous_revision,
                    "patch_sha256": result.patch_sha256,
                    "staged": stage,
                    "working_tree_state": "staged" if stage else "unstaged",
                },
            )
            return result

    def load_repository(self, run_id: str) -> RepositorySnapshot:
        paths = self.coordinator.paths_for(run_id)
        self._validate_artifact_path(paths.repository)
        try:
            snapshot = RepositorySnapshot.model_validate(read_canonical_json(paths.repository))
        except (ValidationError, EvidenceIntegrityError) as error:
            raise EvidenceIntegrityError("Stored repository baseline is invalid") from error
        status = self.coordinator.status(run_id)
        if (
            snapshot.repository_id != status.manifest.repository_id
            or snapshot.repository_root != status.manifest.repository_root
        ):
            raise EvidenceIntegrityError("Stored repository baseline does not match the run")
        return snapshot

    def load_patch(self, run_id: str) -> PatchRecord:
        paths = self.coordinator.paths_for(run_id)
        self._validate_artifact_path(paths.changed_files)
        self._validate_artifact_path(paths.patch_diff)
        try:
            record = PatchRecord.model_validate(read_canonical_json(paths.changed_files))
        except (ValidationError, EvidenceIntegrityError) as error:
            raise EvidenceIntegrityError("Stored patch metadata is invalid") from error
        if record.run_id != run_id:
            raise EvidenceIntegrityError("Stored patch metadata belongs to another run")
        try:
            verify_patch_hash(paths.patch_diff, record.patch_sha256)
        except PatchError as error:
            raise EvidenceIntegrityError(
                "Stored patch bytes failed integrity validation"
            ) from error
        return record

    def _apply_on_new_branch(
        self,
        paths: RunPaths,
        snapshot: RepositorySnapshot,
        record: PatchRecord,
        *,
        stage: bool,
    ) -> AppliedPatch:
        root = Path(snapshot.repository_root)
        branch = f"proofpatch/{record.run_id[-12:]}"
        exists = self.git.run(
            ["-C", str(root), "show-ref", "--verify", "--quiet", f"refs/heads/{branch}"],
            cwd=root,
            check=False,
            operation="apply branch collision check",
        )
        if exists.returncode == 0:
            raise ApplyError(f"Apply branch already exists: {branch}")
        if exists.returncode != 1:
            raise RepositoryError("Could not determine whether the apply branch exists")
        self.git.run(
            ["-C", str(root), "switch", "-c", branch],
            cwd=root,
            operation="apply branch creation",
        )
        try:
            apply_patch_bytes(self.git, root, paths.patch_diff)
            if stage:
                self.git.run(
                    ["-C", str(root), "add", "-A", "--"],
                    cwd=root,
                    operation="applied patch staging",
                )
        except (PatchError, RepositoryError):
            self._restore_branch_if_clean(root, snapshot, branch)
            raise
        return AppliedPatch(
            run_id=record.run_id,
            branch=branch,
            previous_revision=snapshot.baseline_commit,
            patch_sha256=record.patch_sha256,
            changed_files=record.changed_files,
        )

    def _restore_branch_if_clean(
        self,
        root: Path,
        snapshot: RepositorySnapshot,
        created_branch: str,
    ) -> None:
        status = self.git.run(
            ["-C", str(root), "status", "--porcelain=v1", "-z", "--untracked-files=all"],
            cwd=root,
            operation="failed-apply cleanup validation",
        )
        if status.stdout:
            return
        target = snapshot.branch if snapshot.branch is not None else snapshot.baseline_commit
        command = ["-C", str(root), "switch", target]
        if snapshot.branch is None:
            command = ["-C", str(root), "checkout", "--detach", snapshot.baseline_commit, "--"]
        self.git.run(command, cwd=root, operation="failed-apply branch restoration")
        self.git.run(
            ["-C", str(root), "branch", "-D", created_branch],
            cwd=root,
            operation="failed-apply branch removal",
        )

    def _validate_artifact_path(self, path: Path) -> None:
        try:
            validate_proofpatch_data_path(self.coordinator.directories.data, path)
        except Exception as error:
            if isinstance(error, EvidenceIntegrityError):
                raise
            raise EvidenceIntegrityError(f"Unsafe Phase 2 artifact path: {path}") from error

    @staticmethod
    def _verify_patch_binding(events: tuple[object, ...], record: PatchRecord) -> None:
        expected = _patch_evidence_details(record)
        for event in events:
            payload = getattr(event, "payload", None)
            if (
                isinstance(payload, dict)
                and payload.get("to_state") == RunState.PATCH_CAPTURED.value
                and payload.get("details") == expected
            ):
                return
        raise EvidenceIntegrityError("Patch metadata is not bound to PATCH_CAPTURED evidence")


def _patch_evidence_details(record: PatchRecord) -> dict[str, JsonValue]:
    return {
        "baseline_commit": record.baseline_commit,
        "patch_sha256": record.patch_sha256,
        "patch_size_bytes": record.patch_size_bytes,
        "changed_files": [change.model_dump(mode="json") for change in record.changed_files],
    }
