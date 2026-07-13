"""Adversarial tests for canonical, hash-chained Phase 1 evidence."""

import hashlib
import json
import math
import os
import stat
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from proofpatch.errors import EvidenceIntegrityError
from proofpatch.services import evidence
from proofpatch.services.evidence import (
    EvidenceWriter,
    canonical_json_bytes,
    read_canonical_json,
    verify_event_chain,
    write_canonical_json,
)

RUN_ID = "pp_20260713_a4f92b18ce31"
OTHER_RUN_ID = "pp_20260713_bbbbbbbbbbbb"
TIMESTAMP = "2026-07-13T10:00:00.000000Z"


@pytest.fixture
def evidence_paths(tmp_path: Path) -> tuple[Path, Path]:
    return tmp_path / "events.jsonl", tmp_path / "chain.sha256"


def _write_two_events(events_path: Path, chain_path: Path) -> None:
    writer = EvidenceWriter(events_path, chain_path, RUN_ID)
    writer.append("run.created", payload={"state": "CREATED"}, timestamp_utc=TIMESTAMP)
    writer.append(
        "run.state_changed",
        payload={"from_state": "CREATED", "to_state": "PREFLIGHT"},
        timestamp_utc="2026-07-13T10:00:01.000000Z",
    )


def _objects(events_path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in events_path.read_text(encoding="utf-8").splitlines()]


def _rehash(value: dict[str, Any]) -> str:
    target = dict(value)
    target.pop("event_hash", None)
    digest = hashlib.sha256(canonical_json_bytes(target)).hexdigest()
    value["event_hash"] = digest
    return digest


def _write_objects(
    events_path: Path,
    chain_path: Path,
    values: list[dict[str, Any]],
) -> None:
    events_path.write_bytes(b"".join(canonical_json_bytes(value) + b"\n" for value in values))
    chain_path.write_bytes(f"{values[-1]['event_hash']}\n".encode("ascii"))


def test_writer_and_verifier_create_exact_hash_links(
    evidence_paths: tuple[Path, Path],
) -> None:
    events_path, chain_path = evidence_paths
    _write_two_events(events_path, chain_path)

    verified = verify_event_chain(events_path, chain_path, expected_run_id=RUN_ID)

    assert len(verified.events) == 2
    assert verified.events[0].previous_hash is None
    assert verified.events[1].previous_hash == verified.events[0].event_hash
    assert verified.final_hash == verified.events[1].event_hash
    assert chain_path.read_text(encoding="ascii") == f"{verified.final_hash}\n"
    for raw_line in events_path.read_bytes().splitlines():
        assert canonical_json_bytes(json.loads(raw_line)) == raw_line
    if os.name == "posix":
        assert events_path.stat().st_mode & 0o777 == 0o600
        assert chain_path.stat().st_mode & 0o777 == 0o600


def test_canonical_json_rejects_unsupported_and_nonfinite_values() -> None:
    assert canonical_json_bytes({"é": [2, 1]}) == b'{"\xc3\xa9":[2,1]}'
    with pytest.raises(ValueError, match="canonical JSON"):
        canonical_json_bytes({"bad": object()})
    with pytest.raises(ValueError, match="canonical JSON"):
        canonical_json_bytes({"bad": math.nan})


def test_changed_payload_breaks_hash_verification(evidence_paths: tuple[Path, Path]) -> None:
    events_path, chain_path = evidence_paths
    _write_two_events(events_path, chain_path)
    values = _objects(events_path)
    values[0]["payload"] = {"tampered": True}
    _write_objects(events_path, chain_path, values)

    with pytest.raises(EvidenceIntegrityError, match="invalid hash"):
        verify_event_chain(events_path, chain_path)


def test_rehashed_broken_previous_link_is_rejected(evidence_paths: tuple[Path, Path]) -> None:
    events_path, chain_path = evidence_paths
    _write_two_events(events_path, chain_path)
    values = _objects(events_path)
    values[1]["previous_hash"] = "f" * 64
    _rehash(values[1])
    _write_objects(events_path, chain_path, values)

    with pytest.raises(EvidenceIntegrityError, match="broken previous"):
        verify_event_chain(events_path, chain_path)


def test_rehashed_wrong_sequence_is_rejected(evidence_paths: tuple[Path, Path]) -> None:
    events_path, chain_path = evidence_paths
    _write_two_events(events_path, chain_path)
    values = _objects(events_path)
    values[1]["sequence"] = 3
    values[1]["event_id"] = "evt_000003"
    _rehash(values[1])
    _write_objects(events_path, chain_path, values)

    with pytest.raises(EvidenceIntegrityError, match="wrong sequence"):
        verify_event_chain(events_path, chain_path)


def test_rehashed_other_run_is_rejected(evidence_paths: tuple[Path, Path]) -> None:
    events_path, chain_path = evidence_paths
    _write_two_events(events_path, chain_path)
    values = _objects(events_path)
    values[1]["run_id"] = OTHER_RUN_ID
    _rehash(values[1])
    _write_objects(events_path, chain_path, values)

    with pytest.raises(EvidenceIntegrityError, match="another run"):
        verify_event_chain(events_path, chain_path)
    fresh_events = events_path.parent / "fresh.jsonl"
    fresh_chain = events_path.parent / "fresh.sha256"
    _write_two_events(fresh_events, fresh_chain)
    with pytest.raises(EvidenceIntegrityError, match="another run"):
        verify_event_chain(fresh_events, fresh_chain, expected_run_id=OTHER_RUN_ID)


def test_invalid_event_schema_is_rejected(evidence_paths: tuple[Path, Path]) -> None:
    events_path, chain_path = evidence_paths
    _write_two_events(events_path, chain_path)
    values = _objects(events_path)
    values[1]["actor"] = ""
    _rehash(values[1])
    _write_objects(events_path, chain_path, values)

    with pytest.raises(EvidenceIntegrityError, match="invalid schema"):
        verify_event_chain(events_path, chain_path)


@pytest.mark.parametrize(
    ("raw", "message"),
    [
        (b"[]\n", "not a JSON object"),
        (b'{"a":1,"a":2}\n', "Invalid JSON"),
        (b'{"value":NaN}\n', "Invalid JSON"),
        (b'{"value":Infinity}\n', "Invalid JSON"),
        (b'{"value":1e400}\n', "Invalid JSON"),
        (b'{"value":"\\ud800"}\n', "Invalid JSON"),
        (b'{ "a":1}\n', "not canonical"),
        (b"\xff\n", "Invalid JSON"),
        (b"{}", "partial event"),
        (b"\n", "invalid size"),
        (b"", "contains no events"),
    ],
)
def test_malformed_event_framing_and_json_are_rejected(
    evidence_paths: tuple[Path, Path],
    raw: bytes,
    message: str,
) -> None:
    events_path, chain_path = evidence_paths
    events_path.write_bytes(raw)
    chain_path.write_bytes(f"{'a' * 64}\n".encode("ascii"))
    with pytest.raises(EvidenceIntegrityError, match=message):
        verify_event_chain(events_path, chain_path)


def test_checkpoint_tampering_is_rejected(evidence_paths: tuple[Path, Path]) -> None:
    events_path, chain_path = evidence_paths
    _write_two_events(events_path, chain_path)
    chain_path.write_bytes(f"{'0' * 64}\n".encode("ascii"))
    with pytest.raises(EvidenceIntegrityError, match="checkpoint"):
        verify_event_chain(events_path, chain_path)


def test_excessive_json_nesting_is_a_typed_integrity_failure(
    evidence_paths: tuple[Path, Path],
) -> None:
    events_path, chain_path = evidence_paths
    events_path.write_bytes(b"[" * 2000 + b"0" + b"]" * 2000 + b"\n")
    chain_path.write_bytes(f"{'a' * 64}\n".encode("ascii"))
    with pytest.raises(EvidenceIntegrityError, match="Invalid JSON"):
        verify_event_chain(events_path, chain_path)


def test_writers_refuse_json_the_reader_would_reject(
    evidence_paths: tuple[Path, Path],
    tmp_path: Path,
) -> None:
    nested: Any = 0
    for _ in range(70):
        nested = [nested]
    with pytest.raises(EvidenceIntegrityError, match="too deeply nested"):
        write_canonical_json(tmp_path / "deep.json", {"nested": nested})

    events_path, chain_path = evidence_paths
    with pytest.raises(EvidenceIntegrityError, match="valid evidence event"):
        EvidenceWriter(events_path, chain_path, RUN_ID).append(
            "test.deep",
            payload={"nested": nested},
        )


def test_numeric_string_sequence_is_not_coerced_into_a_valid_schema(
    evidence_paths: tuple[Path, Path],
) -> None:
    events_path, chain_path = evidence_paths
    _write_two_events(events_path, chain_path)
    values = _objects(events_path)
    values[1]["sequence"] = "2"
    _rehash(values[1])
    _write_objects(events_path, chain_path, values)
    with pytest.raises(EvidenceIntegrityError, match="invalid schema"):
        verify_event_chain(events_path, chain_path)


def test_verifier_retries_a_concurrent_snapshot_change(
    evidence_paths: tuple[Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events_path, chain_path = evidence_paths
    _write_two_events(events_path, chain_path)
    original_reader = evidence._read_regular_file
    event_reads = 0

    def unstable_reader(path: Path, *, maximum_bytes: int) -> bytes:
        nonlocal event_reads
        result = original_reader(path, maximum_bytes=maximum_bytes)
        if path == events_path:
            event_reads += 1
            if event_reads == 2:
                return result + b"transient-change"
        return result

    monkeypatch.setattr(evidence, "_read_regular_file", unstable_reader)
    monkeypatch.setattr("proofpatch.services.evidence.time.sleep", lambda _seconds: None)
    verified = verify_event_chain(events_path, chain_path)
    assert len(verified.events) == 2
    assert event_reads == 4


def test_writer_reverifies_existing_chain_before_append(
    evidence_paths: tuple[Path, Path],
) -> None:
    events_path, chain_path = evidence_paths
    _write_two_events(events_path, chain_path)
    events_path.write_bytes(events_path.read_bytes().replace(b"PREFLIGHT", b"PREFLIGHX"))
    original = events_path.read_bytes()

    with pytest.raises(EvidenceIntegrityError):
        EvidenceWriter(events_path, chain_path, RUN_ID).append("test.event")
    assert events_path.read_bytes() == original


def test_writer_rejects_checkpoint_without_events(evidence_paths: tuple[Path, Path]) -> None:
    events_path, chain_path = evidence_paths
    chain_path.write_text(f"{'a' * 64}\n", encoding="ascii")
    with pytest.raises(EvidenceIntegrityError, match="without evidence"):
        EvidenceWriter(events_path, chain_path, RUN_ID).append("run.created")


def test_writer_rejects_invalid_event_and_oversize_event(
    evidence_paths: tuple[Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events_path, chain_path = evidence_paths
    with pytest.raises(EvidenceIntegrityError, match="valid evidence"):
        EvidenceWriter(events_path, chain_path, RUN_ID).append("INVALID TYPE")
    events_path.unlink()
    monkeypatch.setattr(evidence, "MAX_EVENT_BYTES", 64)
    with pytest.raises(EvidenceIntegrityError, match="maximum encoded size"):
        EvidenceWriter(events_path, chain_path, RUN_ID).append(
            "test.event",
            payload={"large": "x" * 100},
        )


def test_reader_enforces_file_size_and_regular_files(
    evidence_paths: tuple[Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events_path, chain_path = evidence_paths
    _write_two_events(events_path, chain_path)
    monkeypatch.setattr(evidence, "MAX_EVIDENCE_BYTES", 10)
    with pytest.raises(EvidenceIntegrityError, match="exceeds"):
        verify_event_chain(events_path, chain_path)
    with pytest.raises(EvidenceIntegrityError, match=r"regular file|safely read"):
        verify_event_chain(events_path.parent, chain_path)
    with pytest.raises(EvidenceIntegrityError, match="safely read"):
        verify_event_chain(events_path.parent / "missing", chain_path)


def test_reader_and_writer_reject_non_regular_descriptors(
    evidence_paths: tuple[Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events_path, chain_path = evidence_paths
    events_path.touch()
    monkeypatch.setattr(
        "proofpatch.services.evidence.os.fstat",
        lambda _descriptor: SimpleNamespace(st_mode=stat.S_IFDIR),
    )
    with pytest.raises(EvidenceIntegrityError, match="regular file"):
        EvidenceWriter(events_path, chain_path, RUN_ID).append("run.created")
    with pytest.raises(EvidenceIntegrityError, match="regular file"):
        evidence._read_regular_file(events_path, maximum_bytes=100)


def test_evidence_rejects_hardlinks_and_canonical_overwrite_replaces_them(
    tmp_path: Path,
) -> None:
    target = tmp_path / "outside-target"
    target.write_bytes(b"outside-data")
    linked_events = tmp_path / "events.jsonl"
    os.link(target, linked_events)

    with pytest.raises(EvidenceIntegrityError, match="private regular file"):
        EvidenceWriter(linked_events, tmp_path / "chain.sha256", RUN_ID).append("run.created")
    with pytest.raises(EvidenceIntegrityError, match="private regular file"):
        evidence._read_regular_file(linked_events, maximum_bytes=100)
    assert target.read_bytes() == b"outside-data"

    write_canonical_json(linked_events, {"owned": True}, exclusive=False)
    assert target.read_bytes() == b"outside-data"
    assert read_canonical_json(linked_events) == {"owned": True}


def test_canonical_document_round_trip_and_rejections(tmp_path: Path) -> None:
    path = tmp_path / "record.json"
    write_canonical_json(path, {"schema_version": 1, "name": "value"})
    assert read_canonical_json(path) == {"name": "value", "schema_version": 1}
    with pytest.raises(EvidenceIntegrityError, match="safely write"):
        write_canonical_json(path, {})
    write_canonical_json(path, {"updated": True}, exclusive=False)
    assert read_canonical_json(path) == {"updated": True}

    path.write_bytes(b'{"a":1,"a":2}\n')
    with pytest.raises(EvidenceIntegrityError, match="Invalid JSON"):
        read_canonical_json(path)
    path.write_bytes(b'{ "a":1}\n')
    with pytest.raises(EvidenceIntegrityError, match="not canonical"):
        read_canonical_json(path)
    path.write_bytes(b"{}")
    with pytest.raises(EvidenceIntegrityError, match="framing"):
        read_canonical_json(path)


def test_low_level_write_failures_are_wrapped(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "record.json"
    monkeypatch.setattr("proofpatch.services.evidence.os.write", lambda _fd, _data: 0)
    with pytest.raises(EvidenceIntegrityError, match="safely write"):
        write_canonical_json(path, {})


def test_checkpoint_replace_failure_is_fail_closed(
    evidence_paths: tuple[Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events_path, chain_path = evidence_paths

    def fail_replace(_source: Path, _target: Path) -> None:
        raise OSError("simulated checkpoint failure")

    monkeypatch.setattr("proofpatch.services.evidence.os.replace", fail_replace)
    with pytest.raises(EvidenceIntegrityError, match="checkpoint"):
        EvidenceWriter(events_path, chain_path, RUN_ID).append("run.created")
    assert events_path.exists()
    assert not chain_path.exists()


def test_checkpoint_write_failure_closes_temporary_descriptor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "proofpatch.services.evidence.os.fsync",
        lambda _descriptor: (_ for _ in ()).throw(OSError("simulated fsync failure")),
    )
    with pytest.raises(EvidenceIntegrityError, match="checkpoint"):
        evidence._replace_chain_checkpoint(tmp_path / "chain.sha256", "a" * 64)


def test_posix_directory_sync_path_is_exercised(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, int]] = []
    monkeypatch.setattr("proofpatch.services.evidence.os.name", "posix")
    monkeypatch.setattr(
        "proofpatch.services.evidence.os.open",
        lambda _path, _flags: 42,
    )
    monkeypatch.setattr(
        "proofpatch.services.evidence.os.fsync",
        lambda descriptor: calls.append(("fsync", descriptor)),
    )
    monkeypatch.setattr(
        "proofpatch.services.evidence.os.close",
        lambda descriptor: calls.append(("close", descriptor)),
    )
    evidence._sync_parent_directory(tmp_path / "chain.sha256")
    assert calls == [("fsync", 42), ("close", 42)]


def test_snapshot_attempt_invariant_is_fail_closed(
    evidence_paths: tuple[Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(evidence, "SNAPSHOT_ATTEMPTS", 0)
    with pytest.raises(EvidenceIntegrityError, match="did not produce"):
        verify_event_chain(*evidence_paths)
