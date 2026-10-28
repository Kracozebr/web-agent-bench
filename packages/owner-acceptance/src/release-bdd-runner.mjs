/** Real retained local-fork release validation in a fresh database; no agent actions. */
import {randomUUID} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {readFile, readdir, stat} from 'node:fs/promises';
import {resolve, relative, sep} from 'node:path';
import {fileURLToPath} from 'node:url';
import pg from 'pg';
import {validateAndActivatePinnedRelease} from './genuine-s1-cases.mjs';
import {benchmarkBddCaptureDecision, saveBenchmarkBddEvidence} from './bdd-evidence.mjs';
import {sha256} from './evidence.mjs';
const repositoryRoot = fileURLToPath(new URL('../../../', import.meta.url));
async function sourceHashes() {
  const paths = [];
  async function visit(path) {
    const entry = await stat(path);
    if (entry.isDirectory()) {
      for (const child of await readdir(path, {withFileTypes:true})) {
        if (!['node_modules','dist','.next','.local','__pycache__'].includes(child.name)) await visit(resolve(path,child.name));
      }
    } else if (/\.(?:js|mjs|ts|tsx|py|json|feature|md|yaml|yml|sql|sh)$/.test(path)
      && !path.endsWith('acceptance-evidence.json') && !path.endsWith('scenario-map.md')) paths.push(path);
  }
  for (const path of ['packages/owner-identity','packages/owner-acceptance','tests/bdd/adapters',
    'packages/owner-identity/dist','packages/benchmark-environment','tests/bdd/changes/benchmark-task-suite',
    'openspec/changes/benchmark-task-suite','infrastructure/owner-identity','package.json','pnpm-lock.yaml','pnpm-workspace.yaml']) await visit(resolve(repositoryRoot,path));
  return Object.fromEntries(await Promise.all(paths.sort().map(async path =>
    [relative(repositoryRoot,path).split(sep).join('/'),sha256(await readFile(path))])));
}
async function main() {
  if(process.argv.length!==2) throw new Error('release_bdd_runner_takes_no_arguments');
  const owner = new URL(process.env.OID_DATABASE_URL), observer = new URL(process.env.OID_OBSERVER_DATABASE_URL);
  if(owner.hostname!=='postgres'||observer.hostname!=='postgres'||owner.username!=='oid_owner'||observer.username!=='oid_observer'
    ||owner.pathname!=='/owner_identity'||observer.pathname!=='/owner_identity') throw new Error('release_bdd_requires_local_fixture_database');
  const before=await sourceHashes();
  const captureId=randomUUID(), databaseName='oid_acceptance_'+captureId.replaceAll('-','');
  const admin=new pg.Client({connectionString:owner.href}); await admin.connect();
  try{await admin.query('CREATE DATABASE "'+databaseName+'" TEMPLATE template0');}finally{await admin.end();}
  owner.pathname='/'+databaseName; observer.pathname='/'+databaseName;
  const setup=new pg.Client({connectionString:owner.href}); await setup.connect();
  try{
    await setup.query('GRANT CONNECT ON DATABASE "'+databaseName+'" TO oid_observer');
    await setup.query('GRANT USAGE ON SCHEMA public TO oid_observer');
    await setup.query('ALTER DEFAULT PRIVILEGES FOR ROLE oid_owner IN SCHEMA public GRANT SELECT ON TABLES TO oid_observer');
  }finally{await setup.end();}
  console.log(JSON.stringify({event:'local_release_bdd_database_created',captureId,databaseName}));
  const migration=spawnSync(process.execPath,['packages/owner-identity/dist/migrate.js'],{cwd:repositoryRoot,
    env:{...process.env,OID_DATABASE_URL:owner.href},encoding:'utf8',timeout:120000,maxBuffer:2*1024*1024});
  if(migration.status!==0) throw new Error('release_bdd_isolated_migration_failed');
  const context={};
  console.log(JSON.stringify({event:'local_release_bdd_started',captureId,databaseName}));
  const release=await validateAndActivatePinnedRelease({repositoryRoot,databaseUrl:owner.href,
    observerDatabaseUrl:observer.href,bddContext:context});
  const after=await sourceHashes(), sourceStableDuringRun=JSON.stringify(before)===JSON.stringify(after);
  const provenance={runId:captureId,inputHashesBefore:before,inputHashesAfter:after,sourceStableDuringRun,
    databaseIsolation:{databaseName,createdForCapture:true,retainedForInspection:true},
    runtimeBoundary:{profile:'retained_local_bef_fork_release_validation_no_agent_execution'}};
  const evidence=[];
  for(const scenarioId of ['BTS-SC-001','BTS-SC-002']) evidence.push(await saveBenchmarkBddEvidence({repositoryRoot,
    changeName:'benchmark-task-suite',scenarioId,capture:context.releaseProbe,provenance,
    ...benchmarkBddCaptureDecision(context.releaseProbe,sourceStableDuringRun)}));
  console.log(JSON.stringify({captureId,databaseName,releaseIdentity:release.releaseIdentity,
    rawStatus:context.releaseProbe.status,coverage:context.releaseProbe.coverage,sourceStableDuringRun,evidence},null,2));
  if(context.releaseProbe.status!=='verified'||!sourceStableDuringRun) process.exitCode=2;
}
main().catch(error=>{console.error(JSON.stringify({status:'failed',reasonCode:/^[A-Za-z0-9_]{1,96}$/.test(error.message)?error.message:'release_bdd_failed'}));process.exitCode=1;});