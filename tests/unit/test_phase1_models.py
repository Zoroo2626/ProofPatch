"""Unit tests for Phase 1 identifiers, schemas, and state invariants."""

import math
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from proofpatch.errors import InvalidStateTransition
from proofpatch.models.common import (
    JsonValue,
    format_utc_timestamp,
    validate_json_value,
    validate_repository_id,
    validate_run_id,
    validate_utc_timestamp,
)
from proofpatch.models.events import EvidenceEvent
from proofpatch.models.run import RunManifest, RunRecord, build_run_paths
from proofpatch.models.state import VALID_TRANSITIONS, RunState, can_transition, validate_transition
from proofpatch.services.identifiers import (
    generate_repository_id,
    generate_run_id,
    normalize_identity_path,
    sanitize_remote_url,
)

RUN_ID = "pp_20260713_a4f92b18ce31"
REPOSITORY_ID = "repo_9c06a0e7e84b6f78"
TIMESTAMP = "2026-07-13T10:00:00.000000Z"
HASH = "a" * 64


def test_run_and_repository_identifier_validation() -> None:
    assert validate_run_id(RUN_ID) == RUN_ID
    assert validate_repository_id(REPOSITORY_ID) == REPOSITORY_ID
    with pytest.raises(ValueError, match="run ID"):
        validate_run_id("pp_20260713_UPPER")
    with pytest.raises(ValueError, match="repository ID"):
        validate_repository_id("repo_bad")


def test_timestamp_validation_and_formatting() -> None:
    assert validate_utc_timestamp(TIMESTAMP) == TIMESTAMP
    value = datetime(2026, 7, 13, 13, tzinfo=UTC) + timedelta(hours=3)
    assert format_utc_timestamp(value) == "2026-07-13T16:00:00.000000Z"
    assert format_utc_timestamp().endswith("Z")
    with pytest.raises(ValueError, match="six fractional"):
        validate_utc_timestamp("2026-07-13T10:00:00Z")
    with pytest.raises(ValueError, match="valid UTC"):
        validate_utc_timestamp("2026-02-30T10:00:00.000000Z")
    with pytest.raises(ValueError, match="timezone-aware"):
        format_utc_timestamp(datetime(2026, 1, 1))


def test_json_value_validation_walks_nested_values() -> None:
    value: JsonValue = {"nested": [None, True, 3, 1.5, "text"]}
    assert validate_json_value(value) is value
    for invalid in (math.nan, math.inf, -math.inf):
        with pytest.raises(ValueError, match="non-finite"):
            validate_json_value({"nested": [invalid]})
    with pytest.raises(ValueError, match="keys"):
        validate_json_value({1: "invalid"})  # type: ignore[dict-item]


def test_every_declared_state_transition_and_every_rejection() -> None:
    assert set(VALID_TRANSITIONS) == set(RunState)
    for current in RunState:
        for target in RunState:
            expected = target in VALID_TRANSITIONS[current]
            assert can_transition(current, target) is expected
            if expected:
                validate_transition(current, target)
            else:
                with pytest.raises(InvalidStateTransition):
                    validate_transition(current, target)


def test_event_model_enforces_ids_timestamp_payload_and_immutability() -> None:
    event = EvidenceEvent(
        sequence=1,
        event_id="evt_000001",
        run_id=RUN_ID,
        timestamp_utc=TIMESTAMP,
        type="run.created",
        actor="proofpatch",
        payload={"ok": True},
        previous_hash=None,
        event_hash=HASH,
    )
    assert event.schema_version == 1
    with pytest.raises(ValidationError, match="event_id must be"):
        EvidenceEvent.model_validate({**event.model_dump(), "event_id": "evt_000002"})
    with pytest.raises(ValidationError):
        EvidenceEvent.model_validate({**event.model_dump(), "timestamp_utc": "yesterday"})
    with pytest.raises(ValidationError):
        EvidenceEvent.model_validate({**event.model_dump(), "payload": {"bad": math.nan}})
    with pytest.raises(ValidationError):
        EvidenceEvent.model_validate({**event.model_dump(), "extra": True})
    with pytest.raises(ValidationError):
        event.actor = "other"


def test_run_models_and_path_builder_validate_persistent_fields(tmp_path: Path) -> None:
    manifest = RunManifest(
        run_id=RUN_ID,
        repository_id=REPOSITORY_ID,
        repository_root=str(tmp_path),
        created_at_utc=TIMESTAMP,
    )
    record = RunRecord(
        run_id=RUN_ID,
        repository_id=REPOSITORY_ID,
        repository_root=str(tmp_path),
        state=RunState.CREATED,
        created_at_utc=TIMESTAMP,
        updated_at_utc=TIMESTAMP,
        last_event_sequence=1,
        last_event_hash=HASH,
        run_relative_path=f"runs/{REPOSITORY_ID}/{RUN_ID}",
    )
    paths = build_run_paths(tmp_path, REPOSITORY_ID, RUN_ID)
    assert manifest.schema_version == record.schema_version == 1
    assert paths.root == tmp_path / "runs" / REPOSITORY_ID / RUN_ID
    assert paths.events.name == "events.jsonl"
    with pytest.raises(ValueError):
        build_run_paths(tmp_path, "bad", RUN_ID)
    with pytest.raises(ValidationError):
        RunRecord.model_validate({**record.model_dump(), "last_event_sequence": 0})


def test_run_id_generation_is_utc_and_rejects_bad_inputs() -> None:
    local = datetime(2026, 7, 14, 1, tzinfo=UTC) - timedelta(hours=3)
    assert generate_run_id(now=local, random_hex="abcdef123456") == ("pp_20260713_abcdef123456")
    generated = generate_run_id()
    assert validate_run_id(generated) == generated
    with pytest.raises(ValueError, match="timezone-aware"):
        generate_run_id(now=datetime(2026, 7, 13), random_hex="abcdef123456")
    with pytest.raises(ValueError, match="run ID"):
        generate_run_id(now=datetime(2026, 7, 13, tzinfo=UTC), random_hex="not-hex")


@pytest.mark.parametrize(
    ("remote", "expected"),
    [
        (None, None),
        ("  ", None),
        ("git@Example.COM:owner/repo.git", "example.com:owner/repo.git"),
        ("user:secret@Example.COM:owner/repo.git", "example.com:owner/repo.git"),
        ("user:p@ss@Example.COM:owner/repo.git", "example.com:owner/repo.git"),
        (
            "https://token:secret@Example.COM:8443/owner/repo.git?token=bad#fragment",
            "https://example.com:8443/owner/repo.git",
        ),
        ("ssh://git@[2001:db8::1]/owner/repo.git", "ssh://[2001:db8::1]/owner/repo.git"),
        ("local/path", "local/path"),
        ("user:secret@example.com", None),
        ("not-a-url://", None),
    ],
)
def test_remote_sanitization_never_keeps_url_credentials(
    remote: str | None,
    expected: str | None,
) -> None:
    assert sanitize_remote_url(remote) == expected


def test_repository_id_is_stable_and_uses_all_sanitized_identity_inputs(
    tmp_path: Path,
) -> None:
    root = tmp_path / "repo"
    common = root / ".git"
    common.mkdir(parents=True)
    first = generate_repository_id(root, common, "https://secret@example.com/a.git")
    same = generate_repository_id(root, common, "https://other@example.com/a.git")
    different = generate_repository_id(root, common, "https://example.com/b.git")

    assert first == same
    assert first != different
    assert first.startswith("repo_")
    assert normalize_identity_path(root) == os.path.normcase(str(root.resolve()))
