// AICODE-NOTE: These exact lifecycle/output files may be updated after capture.
// Excluding them prevents selectors and the official result writer from hashing
// their own outputs. The scenario map is regenerated from pinned normative and
// executable inputs; it is not an alternate source of gate expectations.
const outputs=new Set([
  'tests/bdd/changes/mcp-call-diagnostics/runtime-inputs.json',
  'tests/bdd/changes/mcp-call-diagnostics/acceptance-evidence.json',
  'tests/bdd/changes/mcp-call-diagnostics/scenario-map.md',
  'openspec/changes/mcp-call-diagnostics/tasks.md',
  'openspec/changes/mcp-call-diagnostics/approval.md',
]);
export function selectMcdSourceInputs(inputs){return inputs.filter(row=>!outputs.has(row.path));}
