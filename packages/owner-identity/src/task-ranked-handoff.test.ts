import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import test from 'node:test';
import postgres from 'postgres';
import {drizzle} from 'drizzle-orm/postgres-js';
import type {OwnerDatabase} from './db.js';
import {addFixture} from './task-run-completion.test-fixture.js';
import {captureRankedVersionSnapshot,publishRankedHandoff} from './task-ranked-handoff.js';
import {aggregateVerifiedRankedOutcomes} from './task-ranked-aggregate.js';
import {TASK_IDS,PUBLIC_TASK_CATALOG} from './task-catalog.js';
import {canonicalTaskJson,sha256CanonicalTaskJson,type TaskReleaseManifest} from './task-release.js';
import type {TaskEvaluationResult} from './task-evaluator.js';
const hash=(label:string)=>sha256CanonicalTaskJson({label});

test('ranked persistence binds original version, publishes once, and rejects corrupt replay without repair',
 {skip:process.env.OID_RANKED_HANDOFF_PG_TEST!=='1'},async()=>{
 const source=process.env.OID_DATABASE_URL!;const url=new URL(source);assert.equal(url.hostname,'postgres');assert.equal(url.pathname,'/owner_identity');
 const name='oid_acceptance_'+randomUUID().replaceAll('-','');const targetUrl=new URL(source);targetUrl.pathname='/'+name;
 const admin=postgres(source,{max:1}),client=postgres(targetUrl.toString(),{max:8});const db=drizzle(client) as unknown as OwnerDatabase;
 try{
  await admin.unsafe(`CREATE DATABASE ${name}`);
  const migration=spawnSync(process.execPath,['--import','./packages/owner-identity/node_modules/tsx/dist/loader.mjs','packages/owner-identity/src/migrate.ts'],
   {cwd:'/workspace',env:{...process.env,OID_DATABASE_URL:targetUrl.toString()},encoding:'utf8'});
  assert.equal(migration.status,0,'isolated ranked database migration: '+migration.stderr);
  const fixture=await addFixture(client,{includeEvaluation:false});const ids={runId:fixture.runId,ownerId:fixture.ownerId,agentId:fixture.agentId};
  const cases=TASK_IDS.map((taskId,index)=>({taskId,mode:'ranked',taskWeight:PUBLIC_TASK_CATALOG[index]!.weight,caseHash:hash('case-'+taskId),rubricHash:hash('rubric-'+taskId)}));
  const release={...fixture.record.manifest,benchmarkVersion:fixture.record.benchmarkVersion,benchmarkHash:fixture.record.benchmarkHash,policyHash:fixture.record.policyHash,cases:{ranked:cases}} as unknown as TaskReleaseManifest;
  const proofs=cases.map((c,taskIndex)=>{const result:TaskEvaluationResult={taskId:c.taskId,status:'known',outcome:'passed',credit:{numerator:'1',denominator:'1'},mandatoryViolation:null,unknownReasons:[],operatingExpenseUsdcUnits:null};
   return{taskIndex,taskId:c.taskId,caseHash:c.caseHash,rubricHash:c.rubricHash,inputHash:hash('input-'+taskIndex),resultHash:sha256CanonicalTaskJson(result),fenceEvidenceHash:hash('fence-'+taskIndex),result};});
  const aggregate=aggregateVerifiedRankedOutcomes(release,proofs);const admittedAt=new Date(Date.now()-2000).toISOString(),startedAt=new Date(Date.now()-1000).toISOString(),finishedAt=new Date().toISOString();
  await client`UPDATE oid_benchmark_run SET mode='ranked',task_ids=${TASK_IDS},status='queued',started_at=NULL WHERE id=${ids.runId}`;
  const snapshot=await db.transaction(tx=>captureRankedVersionSnapshot(tx,ids,admittedAt));
  await client`UPDATE oid_agent SET name='Changed after admission',declared_version='v2',revision=revision+1 WHERE id=${ids.agentId}`;
  const retained=await db.transaction(tx=>captureRankedVersionSnapshot(tx,ids,finishedAt));assert.deepEqual(retained,snapshot);assert.equal(retained.createdAt,admittedAt);
  await assert.rejects(client`UPDATE oid_ranked_run_version_snapshot SET snapshot_hash=${hash('rewrite')} WHERE run_id=${ids.runId}`,/immutable/);
  await client`UPDATE oid_benchmark_run SET status='completed',started_at=${startedAt},finished_at=${finishedAt} WHERE id=${ids.runId}`;
  const payload={runId:ids.runId,mode:'ranked',tasks:proofs.map(p=>({taskIndex:p.taskIndex,taskId:p.taskId,inputHash:p.inputHash,resultHash:p.resultHash,fenceEvidenceHash:p.fenceEvidenceHash}))};
  const completionEventHash=sha256CanonicalTaskJson(payload);
  await client`INSERT INTO oid_run_event(id,run_id,sequence,source,event_type,payload_hash,payload_json) VALUES(${randomUUID()},${ids.runId},3,'coordinator','run.completed',${completionEventHash},${canonicalTaskJson(payload)}::jsonb)`;
  const input={...ids,aggregate,completionEventHash,finishedAt,replayed:false};
  const published=await db.transaction(tx=>publishRankedHandoff(tx,input));
  const repeated=await Promise.all([1,2].map(()=>db.transaction(tx=>publishRankedHandoff(tx,{...input,replayed:true}))));
  assert.ok(repeated.every(r=>r.handoffHash===published.handoffHash));
  const counts=await client`SELECT (SELECT count(*)::int FROM oid_ranked_run_handoff) AS handoffs,(SELECT count(*)::int FROM oid_ranked_verified_result) AS results,
   (SELECT count(*)::int FROM oid_agent_first_public_action) AS markers,(SELECT count(*)::int FROM oid_run_event WHERE event_type='run.ranked_eligible') AS events`;
  assert.deepEqual({...counts[0]},{handoffs:1,results:1,markers:1,events:1});
  const result=await client`SELECT version_snapshot_json FROM oid_ranked_verified_result WHERE run_id=${ids.runId}`;
  assert.equal(result[0]!.version_snapshot_json.name,'Synthetic completion agent');
  await client`DELETE FROM oid_ranked_best_result WHERE agent_id=${ids.agentId}`;
  await assert.rejects(db.transaction(tx=>publishRankedHandoff(tx,{...input,replayed:true})),(e:unknown)=>(e as {code:string}).code==='RANKED_BEST_REPLAY_CONFLICT');
  const absent=await client`SELECT count(*)::int AS count FROM oid_ranked_best_result WHERE agent_id=${ids.agentId}`;assert.equal(absent[0]!.count,0);
  await assert.rejects(client`DELETE FROM oid_ranked_verified_result WHERE run_id=${ids.runId}`,/immutable/);
 }finally{await client.end();await admin.end();}
});