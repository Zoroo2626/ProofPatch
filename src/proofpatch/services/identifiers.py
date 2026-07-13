"""Deterministic repository identity and unpredictable run identifiers."""

import hashlib
import json
import os
import secrets
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import SplitResult, urlsplit, urlunsplit

from proofpatch.models.common import validate_repository_id, validate_run_id


def generate_run_id(*, now: datetime | None = None, random_hex: str | None = None) -> str:
    """Create a UTC-date run ID with 48 bits of cryptographic randomness."""

    timestamp = datetime.now(UTC) if now is None else now
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise ValueError("run ID time must be timezone-aware")
    suffix = secrets.token_hex(6) if random_hex is None else random_hex
    return validate_run_id(f"pp_{timestamp.astimezone(UTC):%Y%m%d}_{suffix}")


def sanitize_remote_url(remote_url: str | None) -> str | None:
    """Return repository identity material with URL credentials removed."""

    if remote_url is None:
        return None
    value = remote_url.strip()
    if not value:
        return None

    if "://" not in value:
        scp_identity = _sanitize_scp_remote(value)
        if scp_identity is not None:
            return scp_identity
        if "@" in value:
            return None
        return value

    parsed = urlsplit(value)
    hostname = parsed.hostname
    if hostname is None:
        return None
    host = hostname.lower()
    if ":" in host:
        host = f"[{host}]"
    netloc = host
    if parsed.port is not None:
        netloc = f"{netloc}:{parsed.port}"
    sanitized = SplitResult(
        scheme=parsed.scheme.lower(),
        netloc=netloc,
        path=parsed.path,
        query="",
        fragment="",
    )
    return urlunsplit(sanitized)


def _sanitize_scp_remote(value: str) -> str | None:
    host_start = value.rfind("@") + 1
    if host_start >= len(value):
        return None
    if value[host_start] == "[":
        closing_bracket = value.find("]", host_start + 1)
        if closing_bracket < 0 or closing_bracket + 1 >= len(value):
            return None
        separator = closing_bracket + 1
        if value[separator] != ":":
            return None
    else:
        separator = value.find(":", host_start)
        if separator < 0:
            return None
    host = value[host_start:separator]
    remote_path = value[separator + 1 :]
    if not host or not remote_path or "/" in host or "@" in host:
        return None
    return f"{host.lower()}:{remote_path}"


def normalize_identity_path(path: Path) -> str:
    """Normalize an existing filesystem path for stable local identity."""

    return os.path.normcase(os.path.normpath(str(path.resolve(strict=True))))


def generate_repository_id(
    repository_root: Path,
    git_common_directory: Path,
    primary_remote_url: str | None = None,
) -> str:
    """Hash all specification-defined repository identity inputs."""

    material = {
        "git_common_directory": normalize_identity_path(git_common_directory),
        "primary_remote_url": sanitize_remote_url(primary_remote_url),
        "repository_root": normalize_identity_path(repository_root),
    }
    canonical = json.dumps(material, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]
    return validate_repository_id(f"repo_{digest}")
