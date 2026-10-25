#!/usr/bin/env python3
"""Verify stored TBB browser/API/PostgreSQL evidence without network or mutations."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tests.bdd.adapters.tester_bonus_billing import (
    PASSABLE_SCENARIOS,
    SCENARIO_IDS,
    _load_run,
    derive_tbb_facts,
)


def _scenario_result(scenario_id: str) -> dict[str, Any]:
    loaded = _load_run(scenario_id)
    if loaded is None:
        return {
            "scenarioId": scenario_id,
            "status": "not_run",
            "integrity": "not_available",
            "reasonCode": "no_durable_acceptance_run",
        }
    manifest, artifacts = loaded
    facts, negative_variants = derive_tbb_facts(scenario_id, artifacts)
    if manifest["status"] == "passed":
        contract_observations = manifest["observations"]
        contract_negatives = manifest["negativeVariants"]
        missing_observations = [name for name, row in contract_observations.items()
                                if row.get("status") != "observed" or facts.get(name) is not True]
        missing_negatives = [name for name, row in contract_negatives.items()
                             if row.get("status") != "observed" or negative_variants.get(name) is not True]
        if missing_observations or missing_negatives:
            raise AssertionError(
                f"{scenario_id} passed manifest does not derive from raw evidence; "
                f"observations={missing_observations}, negatives={missing_negatives}"
            )
    return {
        "scenarioId": scenario_id,
        "runId": manifest["runId"],
        "status": manifest["status"],
        "integrity": "verified",
        "artifactCount": len(artifacts),
        "facts": facts,
        "negativeVariants": negative_variants,
        **({"blockedReasonCode": manifest["blockedReasonCode"]} if manifest.get("blockedReasonCode") else {}),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenario", nargs="?", default="all", choices=["all", *SCENARIO_IDS])
    parser.add_argument(
        "--require-passed",
        action="store_true",
        help="return nonzero unless every selected scenario is passed",
    )
    args = parser.parse_args()
    selected = SCENARIO_IDS if args.scenario == "all" else (args.scenario,)
    results = [_scenario_result(scenario_id) for scenario_id in selected]
    failed = [row for row in results if row["status"] == "failed"]
    incomplete = [row for row in results if row["status"] != "passed"]
    status = "failed" if failed else "blocked" if incomplete else "verified"
    print(json.dumps({
        "schemaVersion": "tester-bonus-billing-evidence-replay/v1",
        "status": status,
        "replayMode": "filesystem-only; no network, browser, database, or product mutations",
        "passableScenarios": sorted(PASSABLE_SCENARIOS),
        "scenarios": results,
    }, indent=2))
    return 1 if failed or (args.require_passed and incomplete) else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AssertionError, OSError, ValueError, json.JSONDecodeError) as error:
        print(json.dumps({"schemaVersion": "tester-bonus-billing-evidence-replay/v1",
                          "status": "failed", "reason": str(error)}), file=sys.stderr)
        raise SystemExit(1)
