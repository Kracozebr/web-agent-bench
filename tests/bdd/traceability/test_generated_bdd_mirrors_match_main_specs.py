"""Traceability checks for generated BDD mirrors."""

from pathlib import Path

from tools.generate_bdd_mirrors import expected_outputs, parse_specs, validate_generated_inventory
from tools.harness_contracts import load_manifest, validate_spec_snapshot


ROOT = Path(__file__).resolve().parents[3]


def test_generated_mirrors_match_main_specs() -> None:
    scenarios = parse_specs(ROOT)
    manifest, _contracts = load_manifest(ROOT)
    validate_spec_snapshot(ROOT, scenarios, manifest)
    outputs = expected_outputs(ROOT, scenarios)
    assert not validate_generated_inventory(ROOT, outputs)

