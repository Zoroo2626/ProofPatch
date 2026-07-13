"""Validation and immutable capture of untrusted failure-contract submissions."""

import hashlib
import os
import stat
from dataclasses import dataclass
from pathlib import Path

from pydantic import ValidationError

from proofpatch.errors import ContractError, EvidenceIntegrityError
from proofpatch.models.contract import FailureContract, NotReproducedOutcome, ReproductionAsset
from proofpatch.services.evidence import (
    canonical_json_bytes,
    read_json_document,
    write_canonical_json,
)

PRIVATE_FILE_MODE = 0o600
PRIVATE_DIRECTORY_MODE = 0o700


@dataclass(frozen=True, slots=True)
class ContractLimits:
    """Finite controller-owned limits applied after schema validation."""

    maximum_contract_bytes: int = 1024 * 1024
    maximum_assets: int = 32
    maximum_asset_bytes: int = 5 * 1024 * 1024
    maximum_total_asset_bytes: int = 10 * 1024 * 1024
    maximum_timeout_seconds: float = 1800.0

    def __post_init__(self) -> None:
        values = (
            self.maximum_contract_bytes,
            self.maximum_assets,
            self.maximum_asset_bytes,
            self.maximum_total_asset_bytes,
        )
        if any(value <= 0 for value in values) or self.maximum_timeout_seconds <= 0:
            raise ValueError("contract limits must be positive and finite")
        if self.maximum_asset_bytes > self.maximum_total_asset_bytes:
            raise ValueError("individual asset limit cannot exceed the total asset limit")


@dataclass(frozen=True, slots=True)
class ValidatedContract:
    """Controller-captured contract facts safe to bind into evidence."""

    contract: FailureContract
    sha256: str
    total_asset_bytes: int


class ContractService:
    """Turn untrusted outcome files into immutable controller-owned evidence."""

    def __init__(self, limits: ContractLimits | None = None) -> None:
        self.limits = ContractLimits() if limits is None else limits

    def validate_and_capture(
        self,
        contract_path: Path,
        submitted_assets: Path,
        *,
        submitted_contract_destination: Path,
        contract_hash_destination: Path,
        approved_assets_destination: Path,
        protected_evidence_directory: Path,
        environment_allowlist: tuple[str, ...] = (),
        expected_issue_summary: str | None = None,
    ) -> ValidatedContract:
        """Validate everything before persisting the canonical contract or approved assets."""

        try:
            raw = read_json_document(
                contract_path,
                maximum_bytes=self.limits.maximum_contract_bytes,
            )
            contract = FailureContract.model_validate(raw)
        except (EvidenceIntegrityError, ValidationError, ValueError) as error:
            raise ContractError("Failure contract JSON or schema is invalid") from error

        if expected_issue_summary is not None and contract.issue_summary != expected_issue_summary:
            raise ContractError("Failure contract does not match the reported issue summary")

        self._validate_policy(contract, protected_evidence_directory, environment_allowlist)
        captured_assets = self._validate_assets(contract.reproduction_assets, submitted_assets)
        total_bytes = sum(len(content) for _, content in captured_assets)
        digest = hashlib.sha256(canonical_json_bytes(contract.model_dump(mode="json"))).hexdigest()

        try:
            submitted_contract_destination.parent.mkdir(
                mode=PRIVATE_DIRECTORY_MODE,
                parents=True,
                exist_ok=True,
            )
            _validate_private_directory(submitted_contract_destination.parent)
            write_canonical_json(
                submitted_contract_destination,
                contract.model_dump(mode="json"),
            )
            _write_private_file(contract_hash_destination, f"{digest}\n".encode())
            approved_assets_destination.mkdir(
                mode=PRIVATE_DIRECTORY_MODE,
                parents=False,
                exist_ok=False,
            )
            approved_assets_destination.chmod(PRIVATE_DIRECTORY_MODE)
            for asset, content in captured_assets:
                destination = approved_assets_destination.joinpath(*asset.path.split("/"))
                destination.parent.mkdir(
                    mode=PRIVATE_DIRECTORY_MODE,
                    parents=True,
                    exist_ok=True,
                )
                destination.parent.chmod(PRIVATE_DIRECTORY_MODE)
                _write_private_file(destination, content)
        except OSError as error:
            raise EvidenceIntegrityError("Could not persist validated failure contract") from error
        return ValidatedContract(contract, digest, total_bytes)

    def validate_approved_assets(
        self,
        contract: FailureContract,
        approved_assets: Path,
    ) -> int:
        """Recheck immutable assets immediately before copying them to a verifier mount."""

        captured = self._validate_assets(contract.reproduction_assets, approved_assets)
        return sum(len(content) for _, content in captured)

    def copy_approved_assets(
        self,
        contract: FailureContract,
        approved_assets: Path,
        destination: Path,
    ) -> None:
        """Revalidate and copy only declared bytes into a fresh disposable mount directory."""

        captured = self._validate_assets(contract.reproduction_assets, approved_assets)
        try:
            destination.mkdir(mode=PRIVATE_DIRECTORY_MODE, parents=False, exist_ok=False)
            destination.chmod(PRIVATE_DIRECTORY_MODE)
            for asset, content in captured:
                target = destination.joinpath(*asset.path.split("/"))
                target.parent.mkdir(
                    mode=PRIVATE_DIRECTORY_MODE,
                    parents=True,
                    exist_ok=True,
                )
                target.parent.chmod(PRIVATE_DIRECTORY_MODE)
                _write_private_file(target, content)
        except OSError as error:
            raise EvidenceIntegrityError("Could not prepare reproduction assets") from error

    def read_not_reproduced(self, path: Path) -> NotReproducedOutcome:
        """Read a bounded structured negative outcome; stdout claims are irrelevant."""

        try:
            value = read_json_document(
                path,
                maximum_bytes=self.limits.maximum_contract_bytes,
            )
            return NotReproducedOutcome.model_validate(value)
        except (EvidenceIntegrityError, ValidationError, ValueError) as error:
            raise ContractError("Not-reproduced outcome JSON or schema is invalid") from error

    def _validate_policy(
        self,
        contract: FailureContract,
        protected_evidence_directory: Path,
        environment_allowlist: tuple[str, ...],
    ) -> None:
        if len(contract.reproduction_assets) > self.limits.maximum_assets:
            raise ContractError("Failure contract declares too many reproduction assets")
        if contract.oracle.timeout_seconds > self.limits.maximum_timeout_seconds:
            raise ContractError("Failure contract timeout exceeds the configured maximum")
        unexpected = set(contract.oracle.environment).difference(environment_allowlist)
        if unexpected:
            raise ContractError(
                "Failure contract contains disallowed environment names: "
                + ", ".join(sorted(unexpected))
            )
        if any(
            name.startswith("GIT_CONFIG") or name in {"GIT_DIR", "GIT_WORK_TREE"}
            for name in contract.oracle.environment
        ):
            raise ContractError("Failure contract may not alter repository configuration")
        argv_lower = tuple(item.lower() for item in contract.oracle.argv)
        executable = Path(argv_lower[0]).name
        if executable in {"git", "git.exe"} and (
            "config" in argv_lower[1:]
            or any(item == "-c" or item.startswith("-c=") for item in argv_lower[1:])
        ):
            raise ContractError("Failure contract may not alter repository configuration")
        joined = "\0".join(argv_lower)
        if ".git/config" in joined or ".git\\config" in joined or "git config" in joined:
            raise ContractError("Failure contract may not alter repository configuration")
        evidence = str(protected_evidence_directory.resolve(strict=True))
        evidence_variants = {evidence.lower(), evidence.replace("\\", "/").lower()}
        contract_value = contract.model_dump(mode="json")
        strings = tuple(item.lower() for item in _iter_strings(contract_value))
        if any(
            protected and protected in submitted
            for protected in evidence_variants
            for submitted in strings
        ):
            raise ContractError("Failure contract references the protected evidence directory")
        if any("/proofpatch/out" in item for item in strings):
            raise ContractError("Failure oracle may not depend on investigator output files")

    def _validate_assets(
        self,
        declared: tuple[ReproductionAsset, ...],
        source: Path,
    ) -> tuple[tuple[ReproductionAsset, bytes], ...]:
        root = _validated_directory(source)
        discovered = _discover_regular_files(root)
        declared_paths = {asset.path for asset in declared}
        if discovered != declared_paths:
            missing = declared_paths.difference(discovered)
            extra = discovered.difference(declared_paths)
            if missing:
                raise ContractError("Declared reproduction asset is missing: " + sorted(missing)[0])
            raise ContractError("Undeclared reproduction asset was submitted: " + sorted(extra)[0])

        captured: list[tuple[ReproductionAsset, bytes]] = []
        total = 0
        for asset in declared:
            path = root.joinpath(*asset.path.split("/"))
            content = _read_regular_asset(path, self.limits.maximum_asset_bytes)
            digest = hashlib.sha256(content).hexdigest()
            if digest != asset.sha256:
                raise ContractError(f"Reproduction asset hash mismatch: {asset.path}")
            total += len(content)
            if total > self.limits.maximum_total_asset_bytes:
                raise ContractError("Reproduction assets exceed the total size limit")
            captured.append((asset, content))
        return tuple(captured)


def _validated_directory(path: Path) -> Path:
    _reject_link_components(path.absolute())
    try:
        status = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise ContractError("Reproduction asset directory is missing or inaccessible") from error
    if not stat.S_ISDIR(status.st_mode) or _is_link_or_reparse(status):
        raise ContractError("Reproduction asset directory must not be a link or reparse point")
    return resolved


def _reject_link_components(path: Path) -> None:
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        try:
            status = current.lstat()
        except OSError as error:
            raise ContractError("Could not inspect reproduction directory path") from error
        if _is_link_or_reparse(status):
            raise ContractError("Reproduction directory path contains a link or reparse point")


def _validate_private_directory(path: Path) -> None:
    try:
        status = path.lstat()
    except OSError as error:
        raise EvidenceIntegrityError("Could not inspect contract evidence directory") from error
    if not stat.S_ISDIR(status.st_mode) or _is_link_or_reparse(status):
        raise EvidenceIntegrityError("Contract evidence directory is a link or reparse point")
    path.chmod(PRIVATE_DIRECTORY_MODE)


def _discover_regular_files(root: Path) -> set[str]:
    files: set[str] = set()
    pending = [root]
    while pending:
        current = pending.pop()
        try:
            entries = list(os.scandir(current))
        except OSError as error:
            raise ContractError("Could not inspect reproduction assets") from error
        for entry in entries:
            try:
                status = entry.stat(follow_symlinks=False)
            except OSError as error:
                raise ContractError("Could not inspect a reproduction asset") from error
            if _is_link_or_reparse(status):
                raise ContractError("Reproduction assets must not contain links or reparse points")
            path = Path(entry.path)
            if stat.S_ISDIR(status.st_mode):
                pending.append(path)
            elif stat.S_ISREG(status.st_mode):
                files.add(path.relative_to(root).as_posix())
            else:
                raise ContractError("Reproduction assets must be regular files")
    return files


def _read_regular_asset(path: Path, maximum_bytes: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        current = path.lstat()
        if (
            not stat.S_ISREG(opened.st_mode)
            or _is_link_or_reparse(current)
            or opened.st_nlink != 1
            or (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino)
        ):
            raise ContractError("Reproduction asset is not a stable single-link regular file")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(64 * 1024, maximum_bytes + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > maximum_bytes:
                raise ContractError("A reproduction asset exceeds the individual size limit")
        return b"".join(chunks)
    except ContractError:
        raise
    except OSError as error:
        raise ContractError("Could not safely read a reproduction asset") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _write_private_file(path: Path, content: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags, PRIVATE_FILE_MODE)
        status = os.fstat(descriptor)
        if not stat.S_ISREG(status.st_mode) or status.st_nlink != 1:
            raise OSError("destination is not a single-link regular file")
        view = memoryview(content)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short write")
            view = view[written:]
        os.fsync(descriptor)
        os.chmod(path, PRIVATE_FILE_MODE)
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _is_link_or_reparse(status: os.stat_result) -> bool:
    attributes = getattr(status, "st_file_attributes", 0)
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return stat.S_ISLNK(status.st_mode) or bool(attributes & reparse)


def _iter_strings(value: object) -> tuple[str, ...]:
    strings: list[str] = []
    pending = [value]
    while pending:
        current = pending.pop()
        if isinstance(current, str):
            strings.append(current)
        elif isinstance(current, dict):
            pending.extend(current.keys())
            pending.extend(current.values())
        elif isinstance(current, list):
            pending.extend(current)
    return tuple(strings)
