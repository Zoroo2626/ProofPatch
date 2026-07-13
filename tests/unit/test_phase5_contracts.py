"""Unit and adversarial tests for failure contracts and reproduction assets."""

import hashlib
import json
import os
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from proofpatch.errors import ContractError
from proofpatch.models.contract import FailureContract, NotReproducedOutcome, ReproductionAsset
from proofpatch.models.execution import ResolvedImage, ResourceLimits
from proofpatch.services.contracts import ContractLimits, ContractService, ValidatedContract
from proofpatch.services.investigation import InvestigationPlan, SetupCommand


def _expectation(operator: str, value: int) -> dict[str, object]:
    return {
        "exit_code": {"operator": operator, "value": value},
        "stdout": [],
        "stderr": [],
    }


def _contract(asset_content: bytes = b"reproduce") -> dict[str, object]:
    return {
        "schema_version": 1,
        "issue_summary": "Reported failure",
        "hypothesis": "A deterministic defect exists",
        "oracle": {
            "id": "reported-failure",
            "type": "command",
            "argv": ["python", "/proofpatch/repro/reproduce.py"],
            "cwd": "/workspace",
            "timeout_seconds": 30.0,
            "environment": {},
            "baseline_expectation": _expectation("not_equal", 0),
            "fixed_expectation": _expectation("equal", 0),
        },
        "reproduction_assets": [
            {
                "path": "reproduce.py",
                "sha256": hashlib.sha256(asset_content).hexdigest(),
            }
        ],
        "observed_failure_signature": {"kind": "exception", "value": "ReportedError"},
        "notes": "Independent reproduction",
    }


def _submission(
    tmp_path: Path,
    contract: dict[str, object] | None = None,
    asset_content: bytes = b"reproduce",
) -> tuple[Path, Path, Path]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    output = tmp_path / "output"
    assets = tmp_path / "assets"
    evidence = tmp_path / "evidence"
    output.mkdir()
    assets.mkdir()
    evidence.mkdir()
    (output / "failure-contract.json").write_text(
        json.dumps(_contract(asset_content) if contract is None else contract, indent=2),
        encoding="utf-8",
    )
    (assets / "reproduce.py").write_bytes(asset_content)
    return output, assets, evidence


def _capture(
    service: ContractService,
    output: Path,
    assets: Path,
    evidence: Path,
) -> ValidatedContract:
    return service.validate_and_capture(
        output / "failure-contract.json",
        assets,
        submitted_contract_destination=evidence / "investigation" / "submitted-contract.json",
        contract_hash_destination=evidence / "investigation" / "contract.sha256",
        approved_assets_destination=evidence / "investigation" / "reproduction-assets",
        protected_evidence_directory=evidence,
        expected_issue_summary="Reported failure",
    )


def test_valid_contract_is_canonicalized_hashed_and_assets_are_copied(tmp_path: Path) -> None:
    output, assets, evidence = _submission(tmp_path)
    validated = _capture(ContractService(), output, assets, evidence)
    submitted = evidence / "investigation" / "submitted-contract.json"
    approved = evidence / "investigation" / "reproduction-assets" / "reproduce.py"

    assert validated.contract.issue_summary == "Reported failure"
    assert validated.total_asset_bytes == len(b"reproduce")
    assert approved.read_bytes() == b"reproduce"
    assert submitted.read_bytes().endswith(b"\n")
    assert (evidence / "investigation" / "contract.sha256").read_text().strip() == validated.sha256


@pytest.mark.parametrize(
    "asset_path",
    ["../escape.py", "/absolute.py", "sub\\windows.py", "sub/../escape.py", "."],
)
def test_asset_path_traversal_is_rejected(asset_path: str) -> None:
    with pytest.raises(ValidationError):
        ReproductionAsset(path=asset_path, sha256="0" * 64)


def test_missing_and_undeclared_assets_are_rejected(tmp_path: Path) -> None:
    output, assets, evidence = _submission(tmp_path)
    (assets / "reproduce.py").unlink()
    with pytest.raises(ContractError, match="missing"):
        _capture(ContractService(), output, assets, evidence)

    output, assets, evidence = _submission(tmp_path / "extra")
    (assets / "undeclared.txt").write_text("hidden", encoding="utf-8")
    with pytest.raises(ContractError, match="Undeclared"):
        _capture(ContractService(), output, assets, evidence)


def test_changed_asset_hash_is_rejected_before_and_after_capture(tmp_path: Path) -> None:
    output, assets, evidence = _submission(tmp_path)
    (assets / "reproduce.py").write_bytes(b"tampered")
    with pytest.raises(ContractError, match="hash mismatch"):
        _capture(ContractService(), output, assets, evidence)

    output, assets, evidence = _submission(tmp_path / "after")
    service = ContractService()
    validated = _capture(service, output, assets, evidence)
    approved = evidence / "investigation" / "reproduction-assets" / "reproduce.py"
    approved.write_bytes(b"changed after validation")
    with pytest.raises(ContractError, match="hash mismatch"):
        service.validate_approved_assets(validated.contract, approved.parent)


def test_symlink_asset_is_rejected(tmp_path: Path) -> None:
    output, assets, evidence = _submission(tmp_path)
    (assets / "reproduce.py").unlink()
    target = tmp_path / "outside.py"
    target.write_bytes(b"reproduce")
    try:
        (assets / "reproduce.py").symlink_to(target)
    except OSError:
        pytest.skip("symlink creation is not available")
    with pytest.raises(ContractError, match="links or reparse"):
        _capture(ContractService(), output, assets, evidence)


def test_hardlinked_asset_is_rejected(tmp_path: Path) -> None:
    output, assets, evidence = _submission(tmp_path)
    try:
        os.link(assets / "reproduce.py", tmp_path / "second-link.py")
    except OSError:
        pytest.skip("hard links are not available")
    with pytest.raises(ContractError, match="single-link"):
        _capture(ContractService(), output, assets, evidence)


def test_asset_and_contract_limits_fail_closed(tmp_path: Path) -> None:
    output, assets, evidence = _submission(tmp_path, asset_content=b"12345")
    service = ContractService(
        ContractLimits(
            maximum_contract_bytes=1024 * 1024,
            maximum_assets=1,
            maximum_asset_bytes=4,
            maximum_total_asset_bytes=4,
            maximum_timeout_seconds=10.0,
        )
    )
    with pytest.raises(ContractError):
        _capture(service, output, assets, evidence)


def test_disallowed_environment_and_repository_configuration_are_rejected(
    tmp_path: Path,
) -> None:
    contract = _contract()
    oracle = contract["oracle"]
    assert isinstance(oracle, dict)
    oracle["environment"] = {"TOKEN": "value"}
    output, assets, evidence = _submission(tmp_path, contract)
    with pytest.raises(ContractError, match="disallowed environment"):
        _capture(ContractService(), output, assets, evidence)

    contract = _contract()
    oracle = contract["oracle"]
    assert isinstance(oracle, dict)
    oracle["argv"] = ["git", "config", "user.name", "attacker"]
    output, assets, evidence = _submission(tmp_path / "config", contract)
    with pytest.raises(ContractError, match="repository configuration"):
        _capture(ContractService(), output, assets, evidence)


def test_evidence_and_investigator_output_references_are_rejected(tmp_path: Path) -> None:
    contract = _contract()
    contract["notes"] = str(tmp_path / "evidence")
    output, assets, evidence = _submission(tmp_path, contract)
    with pytest.raises(ContractError, match="protected evidence"):
        _capture(ContractService(), output, assets, evidence)

    contract = _contract()
    oracle = contract["oracle"]
    assert isinstance(oracle, dict)
    oracle["argv"] = ["python", "/proofpatch/out/fabricated.py"]
    output, assets, evidence = _submission(tmp_path / "out-ref", contract)
    with pytest.raises(ContractError, match="investigator output"):
        _capture(ContractService(), output, assets, evidence)


def test_issue_summary_and_transition_are_controller_bound(tmp_path: Path) -> None:
    contract = _contract()
    contract["issue_summary"] = "Different issue"
    output, assets, evidence = _submission(tmp_path, contract)
    with pytest.raises(ContractError, match="reported issue"):
        _capture(ContractService(), output, assets, evidence)

    contract = _contract()
    oracle = contract["oracle"]
    assert isinstance(oracle, dict)
    oracle["fixed_expectation"] = oracle["baseline_expectation"]
    with pytest.raises(ValidationError, match="demonstrate a transition"):
        FailureContract.model_validate(contract)


def test_duplicate_json_keys_are_rejected(tmp_path: Path) -> None:
    output, assets, evidence = _submission(tmp_path)
    (output / "failure-contract.json").write_text(
        '{"schema_version":1,"schema_version":1}',
        encoding="utf-8",
    )
    with pytest.raises(ContractError, match="JSON or schema"):
        _capture(ContractService(), output, assets, evidence)


def test_contract_limit_and_setup_models_reject_unbounded_inputs() -> None:
    with pytest.raises(ValueError, match="positive"):
        ContractLimits(maximum_assets=0)
    with pytest.raises(ValueError, match="cannot exceed"):
        ContractLimits(maximum_asset_bytes=2, maximum_total_asset_bytes=1)
    with pytest.raises(ValueError, match="ID"):
        SetupCommand("bad id!", ("python",), 1.0)
    with pytest.raises(ValueError, match="argv"):
        SetupCommand("setup", (), 1.0)
    with pytest.raises(ValueError, match="timeout"):
        SetupCommand("setup", ("python",), 0.0)


@pytest.mark.parametrize(
    "value",
    [
        {"schema_version": 1, "explanation": "x", "commands_attempted": [[]]},
        {"schema_version": 1, "explanation": "x", "commands_attempted": [["bad\0arg"]]},
        {
            "schema_version": 1,
            "explanation": "x",
            "commands_attempted": [["x"] * 257],
        },
        {"schema_version": 1, "explanation": "bad\0explanation", "commands_attempted": []},
    ],
)
def test_not_reproduced_outcome_is_bounded_and_structured(value: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        NotReproducedOutcome.model_validate(value)


def test_investigation_plan_rejects_environment_and_command_policy() -> None:
    image = ResolvedImage(
        requested_reference="example:latest",
        immutable_reference="example@sha256:" + "a" * 64,
        digest="sha256:" + "a" * 64,
        image_id="sha256:" + "b" * 64,
        architecture="amd64",
    )
    limits = ResourceLimits(
        timeout_seconds=1.0,
        memory_mb=64,
        cpus=1.0,
        pids=16,
        output_bytes=1024,
    )
    common: dict[str, Any] = {
        "investigator_image": image,
        "verifier_image": image,
        "investigation_resources": limits,
        "baseline_resources": limits,
        "investigator_environment_allowlist": (),
    }
    with pytest.raises(ValueError, match="argv"):
        InvestigationPlan(investigator_argv=(), investigator_environment={}, **common)
    with pytest.raises(ValueError, match="non-allowlisted"):
        InvestigationPlan(
            investigator_argv=("agent",),
            investigator_environment={"TOKEN": "value"},
            **common,
        )
    with pytest.raises(ValueError, match="reserved"):
        InvestigationPlan(
            investigator_argv=("agent",),
            investigator_environment={"PROOFPATCH_ISSUE": "override"},
            investigator_environment_allowlist=("PROOFPATCH_ISSUE",),
            investigator_image=image,
            verifier_image=image,
            investigation_resources=limits,
            baseline_resources=limits,
        )
    duplicate = SetupCommand("setup", ("python",), 1.0)
    with pytest.raises(ValueError, match="unique"):
        InvestigationPlan(
            investigator_argv=("agent",),
            investigator_environment={},
            setup_commands=(duplicate, duplicate),
            **common,
        )


def test_contract_string_command_and_environment_limits_are_enforced() -> None:
    invalid_contracts: list[dict[str, object]] = []

    value = _contract()
    signature = value["observed_failure_signature"]
    assert isinstance(signature, dict)
    signature["value"] = "bad\0signature"
    invalid_contracts.append(value)

    for argv in (["bad\0argument"],):
        value = _contract()
        oracle = value["oracle"]
        assert isinstance(oracle, dict)
        oracle["argv"] = argv
        invalid_contracts.append(value)

    for cwd in ("C:\\host", "/outside"):
        value = _contract()
        oracle = value["oracle"]
        assert isinstance(oracle, dict)
        oracle["cwd"] = cwd
        invalid_contracts.append(value)

    environments = (
        {f"KEY_{index}": "x" for index in range(129)},
        {"INVALID-NAME": "x"},
        {"TOKEN": "bad\0value"},
        {"TOKEN": "x" * (256 * 1024 + 1)},
    )
    for environment in environments:
        value = _contract()
        oracle = value["oracle"]
        assert isinstance(oracle, dict)
        oracle["environment"] = environment
        invalid_contracts.append(value)

    value = _contract()
    value["notes"] = "bad\0notes"
    invalid_contracts.append(value)

    value = _contract()
    assets = value["reproduction_assets"]
    assert isinstance(assets, list)
    assets.append(deepcopy(assets[0]))
    invalid_contracts.append(value)

    for invalid in invalid_contracts:
        with pytest.raises(ValidationError):
            FailureContract.model_validate(invalid)

    with pytest.raises(ValidationError, match="encoded size"):
        NotReproducedOutcome(
            explanation="x",
            commands_attempted=(("x" * (256 * 1024 + 1),),),
        )
