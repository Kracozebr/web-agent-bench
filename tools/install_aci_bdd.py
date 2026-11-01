"""Install the approved ACI mirror contract; never manufacture runtime evidence."""
import json
from pathlib import Path
from tools.harness_contracts import current_spec_snapshot
from tools.generate_bdd_mirrors import parse_specs, generate

root = Path(__file__).resolve().parents[1]
name = 'agent-client-installer'
proposal_path = root / 'openspec/changes' / name / 'bdd-harness-proposal.json'
proposal = json.loads(proposal_path.read_text(encoding='utf-8'))
rows = proposal.get('scenarios', proposal.get('protected_scenarios'))
proposal.update(proposal_schema='bdd-harness-contract-proposal/v1', review_status='approved',
    runtime_manifest=f'tests/bdd/changes/{name}/harness-contracts.json',
    normative_delta=f'specs/{name}/spec.md', protected_scenarios=rows,
    approval='renewed_remote_scope_2026-10-31', status='approved')
proposal.pop('scenarios', None)
proposal_path.write_text(json.dumps(proposal, indent=2) + '\n', encoding='utf-8')
scenarios = parse_specs(root, name)
for scenario in scenarios:
    rows[scenario.scenario_id]['title'] = scenario.title
proposal_path.write_text(json.dumps(proposal, indent=2) + '\n', encoding='utf-8')
runtime = root / 'tests/bdd/changes' / name
runtime.mkdir(parents=True, exist_ok=True)
fields = ('boundary', 'required_observations', 'negative_variants', 'durable_effects', 'evidence_mode', 'allowed_private_calls')
manifest = dict(schema_version=1, spec_snapshot=current_spec_snapshot(root, scenarios, name),
    coverage_policy=dict(status='complete', required_protected_scenarios=list(rows)),
    protected_scenarios={sid: {key: row[key] for key in fields} for sid, row in rows.items()})
(runtime / 'harness-contracts.json').write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
raise SystemExit(generate(root, False, change_name=name))
