from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from tests.bdd.adapters import build_registry
from tests.bdd.conftest import pytest_collection_modifyitems
from tools.generate_bdd_mirrors import (
    expected_outputs,
    parse_specs,
    render_feature,
    render_mapper,
    render_scenario_map,
    validate_generated_inventory,
)
from tools.harness_contracts import (
    active_delta_source_paths,
    current_spec_snapshot,
    harness_source_paths,
    load_manifest,
    load_proposal,
    manifest_path,
    proposal_path,
    sha256_files,
    scenario_map_path,
    validate_proposal_inventory,
    validate_spec_snapshot,
)
from tools.run_bdd_acceptance import (
    _pytest_command,
    _pytest_targets,
    _record_source_integrity,
    _scenario_results_from_junit,
    _selected_gate_metadata,
)


CHANGE = "demo-change"
SCENARIO_ID = "DEMO-SC-001"
REQUIREMENT_ID = "DEMO-REQ-001"
TITLE = "The selected delta remains isolated"


def _write_spec(root: Path, source: str, *, title: str, scenario_id: str, requirement_id: str) -> None:
    path = root / source
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        f"# Capability\n\n"
        f"### Requirement: {requirement_id} Stable selection\n"
        f"The harness SHALL bind the selected source.\n\n"
        f"#### Scenario: {scenario_id} {title}\n"
        f"- **WHEN** the selected source runs\n"
        f"- **THEN** only its scenario is included\n",
        encoding="utf-8",
    )


def _row(title: str = TITLE) -> dict[str, object]:
    return {
        "requirement_id": REQUIREMENT_ID,
        "title": title,
        "gate": "environment",
        "mandatory": True,
        "named_mapper": "test_demo_sc_001",
        "adapter": "demo_adapter",
        "boundary": "environment",
        "boundary_detail": "actual_test_boundary",
        "required_observations": ["actual_observation"],
        "negative_variants": ["missing_observation"],
        "durable_effects": ["durable_record"],
        "evidence_mode": "actual_http_store_observation",
        "allowed_private_calls": [],
    }


def _make_active_root(root: Path, *, write_manifest: bool = True) -> tuple[dict, list]:
    _write_spec(
        root,
        "openspec/changes/demo-change/specs/demo-capability/spec.md",
        title=TITLE,
        scenario_id=SCENARIO_ID,
        requirement_id=REQUIREMENT_ID,
    )
    proposal = {
        "proposal_schema": "bdd-harness-contract-proposal/v1",
        "review_status": "approved",
        "runtime_manifest": "tests/bdd/changes/demo-change/harness-contracts.json",
        "normative_delta": "specs/demo-capability/spec.md",
        "protected_scenarios": {SCENARIO_ID: _row()},
    }
    proposal_file = proposal_path(root, CHANGE)
    proposal_file.parent.mkdir(parents=True, exist_ok=True)
    proposal_file.write_text(json.dumps(proposal), encoding="utf-8")
    scenarios = parse_specs(root, CHANGE)
    if write_manifest:
        row = proposal["protected_scenarios"][SCENARIO_ID]
        contract = {
            field: row[field]
            for field in (
                "boundary",
                "required_observations",
                "negative_variants",
                "durable_effects",
                "evidence_mode",
                "allowed_private_calls",
            )
        }
        manifest = {
            "schema_version": 1,
            "spec_snapshot": current_spec_snapshot(root, scenarios, CHANGE),
            "coverage_policy": {
                "status": "complete",
                "required_protected_scenarios": [SCENARIO_ID],
            },
            "protected_scenarios": {SCENARIO_ID: contract},
        }
        runtime_file = manifest_path(root, CHANGE)
        runtime_file.parent.mkdir(parents=True, exist_ok=True)
        runtime_file.write_text(json.dumps(manifest), encoding="utf-8")
    return proposal, scenarios


def test_change_selection_reads_only_the_requested_delta(tmp_path: Path) -> None:
    _write_spec(
        tmp_path,
        "openspec/specs/main-capability/spec.md",
        title="Main source scenario",
        scenario_id="BASE-SC-001",
        requirement_id="BASE-REQ-001",
    )
    _make_active_root(tmp_path)

    assert [scenario.scenario_id for scenario in parse_specs(tmp_path)] == ["BASE-SC-001"]
    selected = parse_specs(tmp_path, CHANGE)
    assert [scenario.scenario_id for scenario in selected] == [SCENARIO_ID]
    assert selected[0].source_relative_path.as_posix().startswith("openspec/changes/demo-change/")


def test_approved_proposal_and_runtime_snapshot_must_match(tmp_path: Path) -> None:
    proposal, scenarios = _make_active_root(tmp_path)
    manifest, contracts = load_manifest(tmp_path, CHANGE)
    validate_spec_snapshot(tmp_path, scenarios, manifest, CHANGE)
    validate_proposal_inventory(proposal, scenarios, contracts)

    proposal["protected_scenarios"][SCENARIO_ID]["title"] = "A stale planned title"
    with pytest.raises(ValueError, match="proposal drift"):
        validate_proposal_inventory(proposal, scenarios, contracts)

    manifest["spec_snapshot"]["scenarios"] += 1
    with pytest.raises(ValueError, match="snapshot is stale"):
        validate_spec_snapshot(tmp_path, scenarios, manifest, CHANGE)


def test_active_delta_digest_covers_approval_and_selected_runtime_contract(tmp_path: Path) -> None:
    _make_active_root(tmp_path)
    approval = tmp_path / "openspec/changes/demo-change/approval.md"
    approval.write_text("approved", encoding="utf-8")
    paths = active_delta_source_paths(tmp_path, CHANGE)
    assert Path("openspec/changes/demo-change/specs/demo-capability/spec.md") in paths
    assert Path("openspec/changes/demo-change/bdd-harness-proposal.json") in paths
    assert Path("openspec/changes/demo-change/approval.md") in paths
    assert Path("tests/bdd/changes/demo-change/harness-contracts.json") in paths

    before = sha256_files(tmp_path, paths)
    approval.write_text("approval revised", encoding="utf-8")
    assert sha256_files(tmp_path, active_delta_source_paths(tmp_path, CHANGE)) != before


def test_result_status_map_changes_do_not_change_harness_source_digest(tmp_path: Path) -> None:
    proposal, scenarios = _make_active_root(tmp_path)
    _manifest, contracts = load_manifest(tmp_path, CHANGE)
    active_map = scenario_map_path(tmp_path, CHANGE)
    baseline_map = scenario_map_path(tmp_path)
    baseline_map.parent.mkdir(parents=True, exist_ok=True)
    active_map.parent.mkdir(parents=True, exist_ok=True)
    baseline_map.write_text("| BASE-SC-001 | not_run |\\n", encoding="utf-8")
    active_map.write_text(
        render_scenario_map(scenarios, {SCENARIO_ID: "not_run"}, contracts, CHANGE, proposal),
        encoding="utf-8",
    )

    paths = harness_source_paths(tmp_path, CHANGE)
    assert baseline_map.relative_to(tmp_path) not in paths
    assert active_map.relative_to(tmp_path) not in paths
    before = sha256_files(tmp_path, paths)

    baseline_map.write_text("| BASE-SC-001 | passed |\\n", encoding="utf-8")
    active_map.write_text(
        render_scenario_map(scenarios, {SCENARIO_ID: "passed"}, contracts, CHANGE, proposal),
        encoding="utf-8",
    )

    assert sha256_files(tmp_path, harness_source_paths(tmp_path, CHANGE)) == before


@pytest.mark.parametrize(
    "relative",
    [
        Path("tests/bdd/adapters/demo_adapter.py"),
        Path("tests/bdd/features/demo_capability.feature"),
        Path("tests/bdd/changes/demo-change/harness-contracts.json"),
    ],
)
def test_harness_source_digest_changes_with_adapter_feature_or_contract(
    tmp_path: Path, relative: Path
) -> None:
    _make_active_root(tmp_path)
    source = tmp_path / relative
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_text("before\\n", encoding="utf-8")
    before = sha256_files(tmp_path, harness_source_paths(tmp_path, CHANGE))

    source.write_text("after\\n", encoding="utf-8")

    assert sha256_files(tmp_path, harness_source_paths(tmp_path, CHANGE)) != before


def test_main_runtime_contract_is_in_harness_source_digest(tmp_path: Path) -> None:
    _write_spec(
        tmp_path,
        "openspec/specs/main-capability/spec.md",
        title="Main source scenario",
        scenario_id="BASE-SC-001",
        requirement_id="BASE-REQ-001",
    )
    contract = manifest_path(tmp_path)
    contract.parent.mkdir(parents=True, exist_ok=True)
    contract.write_text("before\\n", encoding="utf-8")
    before = sha256_files(tmp_path, harness_source_paths(tmp_path))

    contract.write_text("after\\n", encoding="utf-8")

    assert sha256_files(tmp_path, harness_source_paths(tmp_path)) != before


@pytest.mark.parametrize(
    "relative",
    [
        Path("tools/replay_bef_evidence.py"),
        Path("tools/run_bef_sc011_trials.py"),
        Path("tools/bef_resource_sampler.py"),
    ],
)
def test_main_harness_source_digest_covers_bef_verifier_helpers(
    tmp_path: Path, relative: Path
) -> None:
    _write_spec(
        tmp_path,
        "openspec/specs/main-capability/spec.md",
        title="Main source scenario",
        scenario_id="BASE-SC-001",
        requirement_id="BASE-REQ-001",
    )
    assert relative not in harness_source_paths(tmp_path)

    source = tmp_path / relative
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_text("before\n", encoding="utf-8")
    paths = harness_source_paths(tmp_path)
    assert relative in paths
    before = sha256_files(tmp_path, paths)

    source.write_text("after\n", encoding="utf-8")

    assert sha256_files(tmp_path, harness_source_paths(tmp_path)) != before


def test_source_change_during_acceptance_marks_evidence_failed(tmp_path: Path) -> None:
    _make_active_root(tmp_path)
    adapter = tmp_path / "tests/bdd/adapters/demo_adapter.py"
    adapter.parent.mkdir(parents=True, exist_ok=True)
    adapter.write_text("before\\n", encoding="utf-8")
    expected = sha256_files(tmp_path, harness_source_paths(tmp_path, CHANGE))
    evidence: dict[str, object] = {
        "acceptance_state": "complete",
        "harness_sources_sha256": expected,
    }

    adapter.write_text("changed during run\\n", encoding="utf-8")

    assert not _record_source_integrity(tmp_path, CHANGE, evidence)
    assert evidence["acceptance_state"] == "failed"
    assert evidence["harness_sources_sha256"] == expected
    assert evidence["harness_sources_sha256_after"] != expected
    assert evidence["source_unchanged"] is False
    assert evidence["error"] == "harness_sources_changed_during_acceptance"


def test_acceptance_gate_metadata_preserves_local_baseline_and_environment_delta(
    tmp_path: Path,
) -> None:
    _write_spec(
        tmp_path,
        "openspec/specs/main-capability/spec.md",
        title="Main source scenario",
        scenario_id="BASE-SC-001",
        requirement_id="BASE-REQ-001",
    )
    _make_active_root(tmp_path)

    main_manifest = manifest_path(tmp_path)
    main_manifest.parent.mkdir(parents=True, exist_ok=True)
    local_contract = {
        key: value
        for key, value in _row().items()
        if key
        in {
            "boundary",
            "required_observations",
            "negative_variants",
            "durable_effects",
            "evidence_mode",
            "allowed_private_calls",
        }
    }
    local_contract["boundary"] = "reference_model"
    main_scenarios = parse_specs(tmp_path)
    main_manifest.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "spec_snapshot": current_spec_snapshot(tmp_path, main_scenarios),
                "coverage_policy": {
                    "status": "complete",
                    "required_protected_scenarios": [SCENARIO_ID],
                },
                "protected_scenarios": {SCENARIO_ID: local_contract},
            }
        ),
        encoding="utf-8",
    )

    assert _selected_gate_metadata(tmp_path, main_scenarios, None) == {
        "class": "local",
        "mandatory": True,
    }
    assert _selected_gate_metadata(tmp_path, parse_specs(tmp_path, CHANGE), CHANGE) == {
        "class": "environment",
        "mandatory": True,
    }


def test_approved_inventory_does_not_substitute_for_runtime_manifest(tmp_path: Path) -> None:
    _make_active_root(tmp_path, write_manifest=False)

    with pytest.raises(ValueError, match="proposal inventory is not a runtime contract"):
        load_manifest(tmp_path, CHANGE)


def test_generated_active_mirrors_leave_main_inventory_independent(tmp_path: Path) -> None:
    _write_spec(
        tmp_path,
        "openspec/specs/main-capability/spec.md",
        title="Main source scenario",
        scenario_id="BASE-SC-001",
        requirement_id="BASE-REQ-001",
    )
    _make_active_root(tmp_path)
    active_scenarios = parse_specs(tmp_path, CHANGE)
    active_outputs = expected_outputs(tmp_path, active_scenarios, change_name=CHANGE)
    for path, content in active_outputs.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    active_feature = active_outputs[
        tmp_path / "tests/bdd/features/demo_capability.feature"
    ]
    active_map = active_outputs[
        tmp_path / "tests/bdd/changes/demo-change/scenario-map.md"
    ]
    assert "@gate_environment @mandatory" in active_feature
    assert 'Given the approved environment setup for "DEMO-SC-001"' in active_feature
    assert "| `environment` | yes |" in active_map

    baseline_scenario = parse_specs(tmp_path)[0]
    baseline_feature = tmp_path / "tests/bdd/features/main_capability.feature"
    baseline_mapper = tmp_path / "tests/bdd/mappers/test_main_capability_bdd.py"
    baseline_feature.parent.mkdir(parents=True, exist_ok=True)
    baseline_mapper.parent.mkdir(parents=True, exist_ok=True)
    baseline_feature.write_text(
        render_feature(baseline_scenario.capability, [baseline_scenario]), encoding="utf-8"
    )
    baseline_mapper.write_text(
        render_mapper(baseline_scenario.capability, [baseline_scenario]), encoding="utf-8"
    )
    assert "@gate_local @mandatory" in baseline_feature.read_text(encoding="utf-8")
    assert 'Given the approved local setup for "BASE-SC-001"' in baseline_feature.read_text(
        encoding="utf-8"
    )

    assert validate_generated_inventory(tmp_path, active_outputs, CHANGE) == []
    baseline_outputs = {
        baseline_feature: baseline_feature.read_text(encoding="utf-8"),
        baseline_mapper: baseline_mapper.read_text(encoding="utf-8"),
    }
    assert validate_generated_inventory(tmp_path, baseline_outputs) == []


def test_acceptance_runner_targets_one_source_and_maps_blocked_separately(tmp_path: Path) -> None:
    _write_spec(
        tmp_path,
        "openspec/specs/main-capability/spec.md",
        title="Main source scenario",
        scenario_id="BASE-SC-001",
        requirement_id="BASE-REQ-001",
    )
    _make_active_root(tmp_path)
    active = parse_specs(tmp_path, CHANGE)
    baseline = parse_specs(tmp_path)

    assert _pytest_targets(active, CHANGE) == [
        "tests/bdd/mappers/test_demo_capability_bdd.py"
    ]
    assert _pytest_targets(baseline, None) == [
        "tests/bdd/mappers/test_main_capability_bdd.py",
        "tests/bdd/traceability",
    ]
    command = _pytest_command("python", active, "results.xml", CHANGE)
    assert "--change" in command
    assert command[command.index("--change") + 1] == CHANGE
    assert "tests/bdd" not in _pytest_targets(active, CHANGE)

    junit = tmp_path / "results.xml"
    junit.write_text(
        '<testsuite>'
        '<testcase name="test_demo_sc_001"><skipped message="BLOCKED: service unavailable" />'
        '</testcase>'
        '<testcase name="test_demo_sc_002"><skipped message="optional probe disabled" />'
        '</testcase>'
        '</testsuite>',
        encoding="utf-8",
    )
    minimal = [
        SimpleNamespace(scenario_id=SCENARIO_ID, mapper_name="test_demo_sc_001"),
        SimpleNamespace(scenario_id="DEMO-SC-002", mapper_name="test_demo_sc_002"),
    ]
    assert _scenario_results_from_junit(junit, minimal) == {
        SCENARIO_ID: "blocked",
        "DEMO-SC-002": "skipped",
    }


BASELINE_SCENARIO_IDS = {
    *(f"WB-SC-{number:03d}" for number in range(1, 5)),
    *(f"PV-SC-{number:03d}" for number in range(1, 5)),
}
BEF_SCENARIO_IDS = {f"BEF-SC-{number:03d}" for number in range(1, 13)}


def _bef_adapter_profiles() -> dict[str, str]:
    return {
        **{
            f"BEF-SC-{number:03d}": "benchmark_environment_http_evm_adapter"
            for number in range(1, 11)
        },
        "BEF-SC-011": "benchmark_environment_resource_adapter",
        "BEF-SC-012": "benchmark_source_rpc_evidence_adapter",
    }


def test_default_registry_keeps_twenty_main_scenarios_and_baseline_profiles() -> None:
    root = Path(__file__).resolve().parents[2]
    scenarios = parse_specs(root)
    registry = build_registry()
    expected_ids = BASELINE_SCENARIO_IDS | BEF_SCENARIO_IDS
    profiles = registry.adapter_profiles()

    assert len(scenarios) == 20
    assert {scenario.scenario_id for scenario in scenarios} == expected_ids
    assert registry.inventory() == expected_ids
    assert set(profiles) == expected_ids
    assert {scenario_id for scenario_id, profile in profiles.items() if profile is None} == (
        BASELINE_SCENARIO_IDS
    )
    assert {scenario_id: profiles[scenario_id] for scenario_id in BEF_SCENARIO_IDS} == (
        _bef_adapter_profiles()
    )


def test_collection_selection_preserves_unrelated_items_and_filters_only_mappers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = Path(__file__).resolve().parents[2]
    main_scenarios = parse_specs(root)
    active_scenarios = [
        scenario for scenario in main_scenarios if scenario.scenario_id in BEF_SCENARIO_IDS
    ]
    assert len(active_scenarios) == 12
    assert {scenario.scenario_id for scenario in active_scenarios} == BEF_SCENARIO_IDS

    # Archived changes no longer have a live delta path. Stub only source selection so this
    # test can keep exercising --change collection filtering after the promotion is archived.
    def select_scenarios(_root: Path, change_name: str | None = None) -> list:
        return active_scenarios if change_name else main_scenarios

    monkeypatch.setattr("tests.bdd.conftest.parse_specs", select_scenarios)
    main_mappers = {
        f"tests/bdd/mappers/test_{scenario.capability.slug}_bdd.py"
        for scenario in main_scenarios
    }
    active_mappers = {
        f"tests/bdd/mappers/test_{scenario.capability.slug}_bdd.py"
        for scenario in active_scenarios
    }
    baseline_mappers = {
        f"tests/bdd/mappers/test_{scenario.capability.slug}_bdd.py"
        for scenario in main_scenarios
        if scenario.scenario_id in BASELINE_SCENARIO_IDS
    }
    assert main_mappers == baseline_mappers | active_mappers
    assert active_mappers.isdisjoint(baseline_mappers)
    unrelated_unit = root / "tests/tools/test_active_delta_bdd_selection.py"
    traceability_test = root / "tests/bdd/traceability/test_traceability.py"

    active_items = [
        *(SimpleNamespace(path=root / mapper) for mapper in sorted(main_mappers)),
        SimpleNamespace(path=unrelated_unit),
        SimpleNamespace(path=traceability_test),
    ]
    pytest_collection_modifyitems(
        SimpleNamespace(getoption=lambda _: "benchmark-environment-feasibility"),
        active_items,
    )
    assert [item.path for item in active_items] == [
        *(root / mapper for mapper in sorted(active_mappers)),
        unrelated_unit,
        traceability_test,
    ]

    main_items = [
        *(SimpleNamespace(path=root / mapper) for mapper in sorted(main_mappers)),
        SimpleNamespace(path=unrelated_unit),
        SimpleNamespace(path=traceability_test),
    ]
    pytest_collection_modifyitems(SimpleNamespace(getoption=lambda _: None), main_items)
    assert [item.path for item in main_items] == [
        *(root / mapper for mapper in sorted(main_mappers)),
        unrelated_unit,
        traceability_test,
    ]
