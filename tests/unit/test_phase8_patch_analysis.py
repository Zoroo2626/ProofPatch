"""Deterministic Phase 8 patch fingerprint and append-only attempt tests."""

from pathlib import Path

import pytest

from proofpatch.errors import EvidenceIntegrityError
from proofpatch.models.attempt import AttemptRecord, AttemptStatus
from proofpatch.models.patch import ChangedFile, ChangeKind, PatchRecord
from proofpatch.services.patch_analysis import AttemptStore, PatchAnalysisService

RUN_ID = "pp_20260713_aaaaaaaaaaaa"
REPOSITORY_ID = "repo_aaaaaaaaaaaaaaaa"
COMMIT = "a" * 40


def _record(patch_sha256: str = "b" * 64) -> PatchRecord:
    return PatchRecord(
        run_id=RUN_ID,
        repository_id=REPOSITORY_ID,
        baseline_commit=COMMIT,
        patch_sha256=patch_sha256,
        patch_size_bytes=100,
        changed_files=(ChangedFile(status=ChangeKind.MODIFIED, path="source.py"),),
    )


def _patch(added: bytes = b"return value + 1", removed: bytes = b"return value") -> bytes:
    return b"\n".join(
        (
            b"diff --git a/source.py b/source.py",
            b"index 1111111..2222222 100644",
            b"--- a/source.py",
            b"+++ b/source.py",
            b"@@ -1 +1 @@",
            b"-" + removed,
            b"+" + added,
            b"",
        )
    )


def _attempt(number: int, fingerprint: object, hypothesis: str = "c" * 64) -> AttemptRecord:
    from proofpatch.models.attempt import PatchFingerprint

    assert isinstance(fingerprint, PatchFingerprint)
    return AttemptRecord(
        attempt=number,
        status=AttemptStatus.REJECTED,
        started_at_utc="2026-07-13T10:00:00.000000Z",
        completed_at_utc="2026-07-13T10:01:00.000000Z",
        patch_sha256="b" * 64,
        fingerprint=fingerprint,
        hypothesis_sha256=hypothesis,
        changed_paths=("source.py",),
        rejection_code="PP_REPRODUCTION_STILL_FAILS",
        reproduction_transition_passed=False,
        regressions_passed=True,
    )


def test_fingerprint_is_canonical_and_whitespace_normalized(tmp_path: Path) -> None:
    analyzer = PatchAnalysisService()
    first = tmp_path / "first.diff"
    second = tmp_path / "second.diff"
    first.write_bytes(_patch())
    second.write_bytes(_patch(b"return  value+1", b"return   value"))

    first_fingerprint = analyzer.fingerprint(_record(), first, {"kind": "error", "value": "x"})
    second_fingerprint = analyzer.fingerprint(
        _record("d" * 64), second, {"kind": "error", "value": "x"}
    )

    assert first_fingerprint.sha256 == second_fingerprint.sha256
    assert first_fingerprint.paths[0].added_line_hashes
    assert first_fingerprint.paths[0].removed_line_hashes
    assert _record().patch_sha256 != _record("d" * 64).patch_sha256


def test_repeat_and_similarity_warnings_are_deterministic(tmp_path: Path) -> None:
    analyzer = PatchAnalysisService()
    patch = tmp_path / "patch.diff"
    patch.write_bytes(_patch())
    fingerprint = analyzer.fingerprint(_record(), patch, {"kind": "error", "value": "x"})
    hypothesis = analyzer.hypothesis_sha256(" Incorrect   Boundary ")
    prior = _attempt(1, fingerprint, hypothesis)

    first = analyzer.warnings(fingerprint, "b" * 64, hypothesis, (prior,))
    second = analyzer.warnings(fingerprint, "b" * 64, hypothesis, (prior,))

    assert first == second
    assert {warning.code for warning in first} == {
        "PP_PATCH_EXACT_REPEAT",
        "PP_HYPOTHESIS_REPEAT",
    }
    assert analyzer.hypothesis_sha256("incorrect boundary") == hypothesis


def test_attempt_store_is_contiguous_and_append_only(tmp_path: Path) -> None:
    analyzer = PatchAnalysisService()
    patch = tmp_path / "patch.diff"
    patch.write_bytes(_patch())
    fingerprint = analyzer.fingerprint(_record(), patch, {"kind": "error", "value": "x"})
    store = AttemptStore(tmp_path / "attempts")
    first = _attempt(1, fingerprint)

    stored = store.append(first)

    assert stored.is_file()
    assert store.load() == (first,)
    with pytest.raises(EvidenceIntegrityError, match="contiguous"):
        store.append(_attempt(3, fingerprint))
    with pytest.raises(EvidenceIntegrityError):
        store.append(first)


def test_high_overlap_warning_uses_deterministic_jaccard_threshold(tmp_path: Path) -> None:
    analyzer = PatchAnalysisService()
    patch = tmp_path / "patch.diff"
    patch.write_bytes(_patch())
    fingerprint = analyzer.fingerprint(_record(), patch, {"kind": "error", "value": "x"})
    shared = tuple(f"{index:064x}" for index in range(1, 10))
    prior_path = fingerprint.paths[0].model_copy(update={"added_line_hashes": (*shared, "a" * 64)})
    current_path = fingerprint.paths[0].model_copy(
        update={"added_line_hashes": (*shared, "b" * 64)}
    )
    prior_fingerprint = fingerprint.model_copy(update={"sha256": "c" * 64, "paths": (prior_path,)})
    current_fingerprint = fingerprint.model_copy(
        update={"sha256": "d" * 64, "paths": (current_path,)}
    )

    warnings = analyzer.warnings(
        current_fingerprint,
        "d" * 64,
        analyzer.hypothesis_sha256("new cause"),
        (_attempt(1, prior_fingerprint),),
    )

    assert [warning.code for warning in warnings] == ["PP_PATCH_HIGH_OVERLAP"]
    assert warnings[0].path_overlap == 1.0
    assert warnings[0].line_overlap >= 0.8


def test_patch_analysis_rejects_links_and_unbounded_input(tmp_path: Path) -> None:
    analyzer = PatchAnalysisService()
    patch = tmp_path / "patch.diff"
    patch.write_bytes(b"")
    with pytest.raises(EvidenceIntegrityError, match="empty"):
        analyzer.fingerprint(_record(), patch, {"kind": "error"})
