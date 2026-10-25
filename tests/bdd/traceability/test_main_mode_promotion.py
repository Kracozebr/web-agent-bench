"""Post-sync checks for promoting BEF into the synchronized main harness."""

from pathlib import Path

import hashlib
import json

import pytest

from tests.bdd.adapters import build_registry
from tools.generate_bdd_mirrors import (
    ContractError,
    _gate_metadata,
    expected_outputs,
    parse_specs,
)
from tools.harness_contracts import load_manifest
from tools.run_bdd_acceptance import _selected_gate_metadata


ROOT = Path(__file__).resolve().parents[3]
BASELINE_IDS = {
    *(f"WB-SC-{number:03d}" for number in range(1, 5)),
    *(f"PV-SC-{number:03d}" for number in range(1, 5)),
}
BEF_IDS = {f"BEF-SC-{number:03d}" for number in range(1, 13)}
BASELINE_CONTRACTS_SHA256 = "af2675b9d5fa3788061708b91cbf3e7643a28b4f9ef3642ea523a9d49393886f"


def test_main_mode_preserves_baseline_and_promotes_mixed_gate_inventory() -> None:
    scenarios = parse_specs(ROOT)
    expected_ids = BASELINE_IDS | BEF_IDS
    assert {scenario.scenario_id for scenario in scenarios} == expected_ids
    assert len(scenarios) == 20

    manifest, contracts = load_manifest(ROOT)
    assert set(contracts) == expected_ids
    assert set(manifest["protected_scenarios"]) == expected_ids
    assert set(build_registry().inventory()) == expected_ids
    baseline_semantics = {
        scenario_id: {
            key: value
            for key, value in manifest["protected_scenarios"][scenario_id].items()
            if key not in {"gate", "mandatory"}
        }
        for scenario_id in sorted(BASELINE_IDS)
    }
    baseline_digest = hashlib.sha256(
        json.dumps(baseline_semantics, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    assert baseline_digest == BASELINE_CONTRACTS_SHA256

    gate = _selected_gate_metadata(ROOT, scenarios, None)
    assert gate["class"] == "per_scenario"
    scenario_classes = gate["scenario_classes"]
    assert all(scenario_classes[item] == {"class": "local", "mandatory": True} for item in BASELINE_IDS)
    assert all(scenario_classes[item] == {"class": "environment", "mandatory": True} for item in BEF_IDS)
    assert gate["mandatory"] is True


def test_main_generated_mirrors_only_reference_synchronized_specs(tmp_path: Path) -> None:
    scenarios = parse_specs(ROOT)
    outputs = expected_outputs(ROOT, scenarios, acceptance_evidence_path=tmp_path / "no-evidence.json")
    assert outputs
    for content in outputs.values():
        assert "openspec/changes/" not in content
    feature = outputs[ROOT / "tests" / "bdd" / "features" / "benchmark_environment_feasibility.feature"]
    assert "# Normative source(s): openspec/specs/benchmark-environment-feasibility/spec.md" in feature
    assert "@gate_environment @mandatory" in feature
    scenario_map = outputs[ROOT / "tests" / "bdd" / "scenario-map.md"]
    assert "**Normative source:** `openspec/specs/*/spec.md`" in scenario_map


def test_main_gate_metadata_rejects_invalid_class() -> None:
    scenario = next(item for item in parse_specs(ROOT) if item.scenario_id == "BEF-SC-001")
    metadata = {
        "protected_scenarios": {
            scenario.scenario_id: {"gate": "environment gate", "mandatory": True}
        }
    }
    with pytest.raises(ContractError, match="invalid gate metadata"):
        _gate_metadata(scenario, metadata)


def test_main_environment_gate_metadata_is_required() -> None:
    scenario = next(item for item in parse_specs(ROOT) if item.scenario_id == "BEF-SC-001")
    metadata = {
        "protected_scenarios": {
            scenario.scenario_id: {"boundary": "environment", "mandatory": True}
        }
    }
    with pytest.raises(ContractError, match="missing gate metadata"):
        _gate_metadata(scenario, metadata)
