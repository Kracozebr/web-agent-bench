import {spawnSync} from 'node:child_process';
import {createHash,randomUUID} from 'node:crypto';
import {mkdtemp,readFile,unlink,rmdir} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {benchmarkBddCaptureDecision,saveBenchmarkBddEvidence} from './bdd-evidence.mjs';

const repositoryRoot=resolve(fileURLToPath(new URL('../../..',import.meta.url)));
const sourcePaths=[
 'openspec/changes/benchmark-run-lifecycle/approval.md',
 'openspec/changes/benchmark-run-lifecycle/specs/benchmark-run-lifecycle/spec.md',
 'openspec/changes/benchmark-run-lifecycle/bdd-harness-proposal.json',
 'tests/bdd/changes/benchmark-run-lifecycle/harness-contracts.json',
 'tests/bdd/features/benchmark_run_lifecycle.feature',
 'tests/bdd/mappers/test_benchmark_run_lifecycle_bdd.py',
 'tests/bdd/adapters/benchmark_run_lifecycle.py',
 'tests/bdd/adapters/benchmark_run_lifecycle_verifier.py',
 'tests/bdd/adapters/test_benchmark_run_lifecycle_verifier.py',
 'packages/owner-identity/src/task-feedback.ts',
 'packages/owner-identity/src/task-issuance.ts',
 'packages/owner-identity/src/run-routes.ts',
 'packages/owner-identity/src/task-run-completion.test-fixture.ts',
 'packages/owner-identity/src/task-feedback-release.pg.test.ts',
 'packages/owner-acceptance/src/bdd-evidence.mjs',
 'packages/owner-acceptance/src/run-brl-sc016.mjs',
];
const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
async function sourceInventory(){
 const rows=[];
 for(const path of sourcePaths)rows.push({path,sha256:hash(await readFile(resolve(repositoryRoot,path)))});
 return rows;
}

if(!process.env.OID_DATABASE_URL||!process.env.OID_OBSERVER_DATABASE_URL){
 throw new Error('Docker runtime must provide the owner and read-only observer URLs.');
}
const inputHashesBefore=await sourceInventory();
const captureDirectory=await mkdtemp(join(tmpdir(),'brl-sc016-'));
const capturePath=join(captureDirectory,'runtime-evidence.json');
try{
 const result=spawnSync('pnpm',['--filter','@web-agent-bench/owner-identity','exec','node','--import','tsx','--test','src/task-feedback-release.pg.test.ts'],{
  cwd:repositoryRoot,
  env:{...process.env,OID_BRL_SC016_PG_TEST:'1',OID_BRL_SC016_CAPTURE_DIR:captureDirectory},
  encoding:'utf8',
 });
 if(result.stdout)process.stdout.write(result.stdout);
 if(result.stderr)process.stderr.write(result.stderr);
 if(result.status!==0)throw new Error(`BRL-SC-016 PostgreSQL/MCP integration test failed (exit ${result.status??'unknown'}).`);
 const capture=JSON.parse(await readFile(capturePath,'utf8'));
 const inputHashesAfter=await sourceInventory();
 const sourceStableDuringRun=JSON.stringify(inputHashesBefore)===JSON.stringify(inputHashesAfter);
 const decision=benchmarkBddCaptureDecision(capture,sourceStableDuringRun);
 const evidence=await saveBenchmarkBddEvidence({repositoryRoot,changeName:'benchmark-run-lifecycle',
  scenarioId:'BRL-SC-016',capture,provenance:{runId:randomUUID(),boundary:'isolated_postgresql_and_actual_mcp_json_rpc_handler',
   databaseIsolation:{createdFromTemplate:'template0',droppedAfterCapture:true},inputHashesBefore,inputHashesAfter,sourceStableDuringRun},
  status:decision.status,reasonCode:decision.reasonCode});
 process.stdout.write(JSON.stringify({...evidence,sourceStableDuringRun,observerRole:'oid_observer',observerReadOnly:true})+'\n');
 if(decision.status!=='passed')process.exitCode=2;
}finally{
 await unlink(capturePath).catch(()=>{});
 await rmdir(captureDirectory).catch(()=>{});
}
