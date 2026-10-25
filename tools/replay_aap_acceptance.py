#!/usr/bin/env python3
"""Verify stored AAP artifacts without browser, network, database or mutations."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tests.bdd.adapters.agent_access_and_permissions import (
    PARTIAL_CARD_SCENARIOS, PASSABLE_FACTS, SCENARIO_IDS, _derive_partial_facts, _load_run,
)

CARD_FACT_NAMES = frozenset({
    "owner_card_persisted",
    "declared_metadata_labelled",
    "foreign_owner_denied",
    "caller_visibility_change_cannot_publish",
    "profile_edit_correlated_to_postgres",
    "initial_policy_all_false",
    "policy_edit_committed",
})


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenario", nargs="?", default="all", choices=["all", *SCENARIO_IDS])
    parser.add_argument("--require-passed", action="store_true")
    args = parser.parse_args()
    results = []
    for scenario_id in SCENARIO_IDS if args.scenario == "all" else [args.scenario]:
        loaded = _load_run(scenario_id)
        if loaded is None:
            raise AssertionError(f"No capture for {scenario_id}")
        manifest, artifacts = loaded
        provenance = artifacts["provenance.json"]
        if provenance.get("sourceStableDuringRun") is not True or not provenance.get("inputHashesBefore") or provenance.get("inputHashesBefore") != provenance.get("inputHashesAfter"):
            raise AssertionError(f"{scenario_id} source inputs changed during capture")
        facts = _derive_partial_facts(scenario_id, artifacts)
        if scenario_id in PARTIAL_CARD_SCENARIOS and (
            not facts or any(facts.get(name) is not True for name in CARD_FACT_NAMES)
        ):
            raise AssertionError(f"{scenario_id} partial card facts do not follow from raw artifacts")
        if manifest["status"] == "passed":
            if scenario_id not in PASSABLE_FACTS:
                raise AssertionError(f"{scenario_id} has a full passed status without an implemented acceptance boundary")
            required_observations, required_negatives = PASSABLE_FACTS[scenario_id]
            if any(facts.get(name) is not True for name in (*required_observations, *required_negatives)):
                raise AssertionError(f"{scenario_id} facts do not derive all approved observations and negatives")
            for name in required_observations:
                if manifest.get("observations", {}).get(name, {}).get("status") != "observed":
                    raise AssertionError(f"{scenario_id} observation is not marked observed: {name}")
            for name in required_negatives:
                if manifest.get("negativeVariants", {}).get(name, {}).get("status") != "observed":
                    raise AssertionError(f"{scenario_id} negative is not marked observed: {name}")
        results.append({"scenarioId": scenario_id, "runId": manifest["runId"], "status": manifest["status"],
                        "integrity": "verified", "artifactCount": len(artifacts), "partialFacts": facts})
    blocked = args.require_passed and any(item["status"] != "passed" for item in results)
    print(json.dumps({"schemaVersion": "agent-access-evidence-replay/v1", "status": "blocked" if blocked else "verified",
                      "replayMode": "filesystem-only; no network, browser, or database access", "scenarios": results}, indent=2))
    return 1 if blocked else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AssertionError, ValueError, OSError) as error:
        print(json.dumps({"status": "failed", "reason": str(error)}), file=sys.stderr)
        raise SystemExit(1)
