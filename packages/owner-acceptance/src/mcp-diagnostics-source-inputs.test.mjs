import assert from 'node:assert/strict';
import test from 'node:test';
import {createHash} from 'node:crypto';
import {mkdtemp,mkdir,readFile,writeFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,dirname} from 'node:path';
import {selectMcdSourceInputs} from './mcp-diagnostics-source-inputs.mjs';

test('MCD selector/lifecycle edits preserve source identity while code/spec/contract edits invalidate it',async()=>{
  const directory=await mkdtemp(join(tmpdir(),'mcd-source-policy-'));
  const metadata=['tests/bdd/changes/mcp-call-diagnostics/runtime-inputs.json','tests/bdd/changes/mcp-call-diagnostics/acceptance-evidence.json','tests/bdd/changes/mcp-call-diagnostics/scenario-map.md','openspec/changes/mcp-call-diagnostics/tasks.md','openspec/changes/mcp-call-diagnostics/approval.md'];
  const subjects=['packages/owner-identity/src/mcp-diagnostics-service.ts','packages/owner-web/components/diagnostics-panel.tsx',
    'openspec/changes/mcp-call-diagnostics/specs/mcp-call-diagnostics/spec.md','openspec/changes/mcp-call-diagnostics/design.md','openspec/changes/mcp-call-diagnostics/bdd-harness-proposal.json',
    'tests/bdd/changes/mcp-call-diagnostics/harness-contracts.json','tests/bdd/features/mcp_call_diagnostics.feature','tests/bdd/adapters/mcp_call_diagnostics.py','tests/bdd/adapters/mcd_physical_replay.py','tests/bdd/mappers/test_mcp_call_diagnostics_bdd.py',
    'tools/run_bdd_acceptance.py','tools/generate_bdd_mirrors.py','tools/check_bdd_harness.py','tools/harness_contracts.py','packages/owner-acceptance/src/mcp-diagnostics-source-inputs.mjs','packages/owner-acceptance/src/mcd-native-source-inputs.mjs',
    'openspec/changes/unrelated/approval.md','tests/bdd/changes/unrelated/acceptance-evidence.json','tests/bdd/changes/unrelated/scenario-map.md',
    'tests/bdd/changes/mcp-call-diagnostics/other-result.json','tools/scenario-map.md'];
  const paths=[...metadata,...subjects];
  async function snapshot(){const rows=[];for(const path of paths){const content=await readFile(join(directory,path));rows.push({path,sha256:createHash('sha256').update(content).digest('hex'),bytes:content.length});}return selectMcdSourceInputs(rows);}
  try{
    for(const path of paths){await mkdir(dirname(join(directory,path)),{recursive:true});await writeFile(join(directory,path),'original');}
    const before=await snapshot();assert.deepEqual(before.map(r=>r.path),subjects);
    for(const path of metadata)await writeFile(join(directory,path),'new selector or lifecycle output');
    assert.deepEqual(await snapshot(),before);
    for(const path of subjects){await writeFile(join(directory,path),'changed test subject');const changed=await snapshot();assert.notDeepEqual(changed,before);assert.notEqual(changed.find(r=>r.path===path).sha256,before.find(r=>r.path===path).sha256);await writeFile(join(directory,path),'original');}
  }finally{await rm(directory,{recursive:true,force:true});}
});
