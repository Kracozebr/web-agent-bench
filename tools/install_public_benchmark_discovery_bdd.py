"""Install the already approved PBD active-delta BDD contract and mirrors.

This only installs reviewed traceability. It never creates runtime acceptance evidence.
"""

import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from tools.generate_bdd_mirrors import generate, parse_specs
from tools.harness_contracts import current_spec_snapshot


CHANGE = "public-benchmark-discovery"
proposal_path = ROOT / "openspec" / "changes" / CHANGE / "bdd-harness-proposal.json"
proposal = json.loads(proposal_path.read_text(encoding="utf-8"))
rows = proposal.get("protected_scenarios", proposal.get("scenarios"))
if not isinstance(rows, dict) or len(rows) != 6:
    raise SystemExit("PBD approved scenario inventory is missing or has changed")

proposal.update(
    proposal_schema="bdd-harness-contract-proposal/v1",
    review_status="approved",
    runtime_manifest=f"tests/bdd/changes/{CHANGE}/harness-contracts.json",
    normative_delta=f"specs/{CHANGE}/spec.md",
    protected_scenarios=rows,
    status="approved",
)
proposal.pop("scenarios", None)
scenarios = parse_specs(ROOT, CHANGE)
for scenario in scenarios:
    if scenario.scenario_id not in rows:
        raise SystemExit(f"PBD approved inventory is missing {scenario.scenario_id}")
    rows[scenario.scenario_id]["title"] = scenario.title
    rows[scenario.scenario_id]["named_mapper"] = scenario.mapper_name
proposal_path.write_text(json.dumps(proposal, indent=2) + "\n", encoding="utf-8")

contract_fields = (
    "boundary",
    "required_observations",
    "negative_variants",
    "durable_effects",
    "evidence_mode",
    "allowed_private_calls",
)
manifest = {
    "schema_version": 1,
    "spec_snapshot": current_spec_snapshot(ROOT, scenarios, CHANGE),
    "coverage_policy": {
        "status": "complete",
        "required_protected_scenarios": list(rows),
    },
    "protected_scenarios": {
        scenario_id: {key: row[key] for key in contract_fields}
        for scenario_id, row in rows.items()
    },
}
runtime_root = ROOT / "tests" / "bdd" / "changes" / CHANGE
runtime_root.mkdir(parents=True, exist_ok=True)
(runtime_root / "harness-contracts.json").write_text(
    json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
)
raise SystemExit(generate(ROOT, False, change_name=CHANGE))
