"""Contract inventory and adapter coverage checks."""

from pathlib import Path

from tests.bdd.adapters import build_registry
from tools.generate_bdd_mirrors import parse_specs
from tools.harness_contracts import load_manifest, validate_spec_snapshot


ROOT = Path(__file__).resolve().parents[3]


def test_every_normative_scenario_has_a_protected_adapter() -> None:
    scenarios = parse_specs(ROOT)
    manifest, contracts = load_manifest(ROOT)
    validate_spec_snapshot(ROOT, scenarios, manifest)
    assert set(contracts) == {scenario.scenario_id for scenario in scenarios}
    assert set(build_registry().inventory()) == set(contracts)

