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
  const proofs=cases.map((c,taskIndex)=>{const result:TaskEvaluationResult={taskId:c.taskId,status:'known',outcome:taskIndex===0?'partial':'passed',credit:{numerator:'1',denominator:taskIndex===0?'2':'1'},mandatoryViolation:null,unknownReasons:[],operatingExpenseUsdcUnits:null};
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
  const nextRun=randomUUID(),nextIntent=randomUUID(),nextManifest=hash('different-manifest'),nextBenchmark=hash('different-benchmark');
  await client`INSERT INTO oid_run_launch_intent SELECT (jsonb_populate_record(NULL::oid_run_launch_intent,
    to_jsonb(i)||jsonb_build_object('id',${nextIntent}::text,'operation_id',${'different_'+nextIntent}::text,'manifest_hash',${nextManifest}::text,'benchmark_hash',${nextBenchmark}::text))).*
    FROM oid_run_launch_intent i WHERE id=(SELECT intent_id FROM oid_benchmark_run WHERE id=${ids.runId})`;
  await client`INSERT INTO oid_benchmark_run SELECT (jsonb_populate_record(NULL::oid_benchmark_run,
    to_jsonb(r)||jsonb_build_object('id',${nextRun}::text,'intent_id',${nextIntent}::text,'manifest_hash',${nextManifest}::text,'benchmark_hash',${nextBenchmark}::text,
      'status','queued','started_at',NULL,'finished_at',NULL))).* FROM oid_benchmark_run r WHERE id=${ids.runId}`;
  const nextIds={...ids,runId:nextRun};await db.transaction(tx=>captureRankedVersionSnapshot(tx,nextIds,admittedAt));
  await client`UPDATE oid_benchmark_run SET status='completed',started_at=${startedAt},finished_at=${finishedAt} WHERE id=${nextRun}`;
  const nextProofs=proofs.map(p=>{const result:TaskEvaluationResult={...p.result,outcome:'passed',credit:{numerator:'1',denominator:'1'}};return{...p,result,resultHash:sha256CanonicalTaskJson(result)};});
  const nextAggregate=aggregateVerifiedRankedOutcomes({...release,manifestHash:nextManifest,benchmarkHash:nextBenchmark},nextProofs);
  assert.equal(nextAggregate.overall.numerator,'100');assert.equal(nextAggregate.overall.denominator,'1');
  assert.notDeepEqual(nextAggregate.overall,aggregate.overall);
  const nextPayload={...payload,runId:nextRun,tasks:nextProofs.map(p=>({taskIndex:p.taskIndex,taskId:p.taskId,inputHash:p.inputHash,resultHash:p.resultHash,fenceEvidenceHash:p.fenceEvidenceHash}))},nextEventHash=sha256CanonicalTaskJson(nextPayload);
  const nextInput={...nextIds,aggregate:nextAggregate,completionEventHash:nextEventHash,finishedAt,replayed:false};
  await assert.rejects(db.transaction(tx=>publishRankedHandoff(tx,nextInput)),(e:unknown)=>(e as {code:string}).code==='RANKED_COMPLETION_EVENT_MISMATCH');
  await client`INSERT INTO oid_run_event(id,run_id,sequence,source,event_type,payload_hash,payload_json) VALUES(${randomUUID()},${nextRun},3,'coordinator','run.completed',${nextEventHash},${canonicalTaskJson(nextPayload)}::jsonb)`;
  await assert.rejects(db.transaction(tx=>publishRankedHandoff(tx,{...nextInput,aggregate:{...nextAggregate,aggregateHash:hash('corrupt')}})),
    (e:unknown)=>(e as {code:string}).code==='RANKED_AGGREGATE_INVALID');
  await assert.rejects(db.transaction(tx=>publishRankedHandoff(tx,{...nextInput,aggregate:{...nextAggregate,taskProofs:nextAggregate.taskProofs.slice(1)}})),
    (e:unknown)=>(e as {code:string}).code==='RANKED_AGGREGATE_INVALID');
  // Seed malformed immutable historical proofs in this disposable database; never rewrite a retained proof.
  for(const invalid of [[],{...aggregate,aggregateHash:hash('corrupt-prior')}]){
    const invalidFixture=await addFixture(client,{includeEvaluation:false});
    await client`INSERT INTO oid_ranked_run_handoff SELECT (jsonb_populate_record(NULL::oid_ranked_run_handoff,
      to_jsonb(h)||jsonb_build_object('run_id',${invalidFixture.runId}::text))).* FROM oid_ranked_run_handoff h WHERE run_id=${ids.runId}`;
    await client`INSERT INTO oid_ranked_verified_result SELECT (jsonb_populate_record(NULL::oid_ranked_verified_result,
      to_jsonb(v)||jsonb_build_object('run_id',${invalidFixture.runId}::text,'aggregate_json',${canonicalTaskJson(invalid)}::jsonb))).*
      FROM oid_ranked_verified_result v WHERE run_id=${ids.runId}`;
    await client`UPDATE oid_ranked_best_result SET run_id=${invalidFixture.runId} WHERE agent_id=${ids.agentId}`;
    await assert.rejects(db.transaction(tx=>publishRankedHandoff(tx,nextInput)),(e:unknown)=>(e as {code:string}).code==='RANKED_BEST_CONFLICT');
    await assert.rejects(db.transaction(tx=>publishRankedHandoff(tx,{...input,replayed:true})),(e:unknown)=>(e as {code:string}).code==='RANKED_BEST_REPLAY_CONFLICT');
    await client`UPDATE oid_ranked_best_result SET run_id=${ids.runId} WHERE agent_id=${ids.agentId}`;
  }
  const nextPublished=await db.transaction(tx=>publishRankedHandoff(tx,nextInput));
  const nextReplayed=await Promise.all([1,2].map(()=>db.transaction(tx=>publishRankedHandoff(tx,{...nextInput,replayed:true}))));
  assert.ok(nextReplayed.every(r=>r.handoffHash===nextPublished.handoffHash));
  const stillBest=await client`SELECT run_id FROM oid_ranked_best_result WHERE agent_id=${ids.agentId}`;
  assert.equal(stillBest.length,1);assert.equal(stillBest[0]!.run_id,ids.runId);
  const actualRunIds=[ids.runId,nextRun];
  const afterDifferentManifest=await client`SELECT (SELECT count(*)::int FROM oid_ranked_run_handoff WHERE run_id=ANY(${actualRunIds}::uuid[])) handoffs,
    (SELECT count(*)::int FROM oid_ranked_verified_result WHERE run_id=ANY(${actualRunIds}::uuid[])) results,(SELECT count(*)::int FROM oid_agent_first_public_action) markers,
    (SELECT count(*)::int FROM oid_run_event WHERE event_type='run.ranked_eligible') events`;
  assert.deepEqual({...afterDifferentManifest[0]},{handoffs:2,results:2,markers:1,events:2});
  await client`DELETE FROM oid_ranked_best_result WHERE agent_id=${ids.agentId}`;
  await assert.rejects(db.transaction(tx=>publishRankedHandoff(tx,{...input,replayed:true})),(e:unknown)=>(e as {code:string}).code==='RANKED_BEST_REPLAY_CONFLICT');
  const absent=await client`SELECT count(*)::int AS count FROM oid_ranked_best_result WHERE agent_id=${ids.agentId}`;assert.equal(absent[0]!.count,0);
  await assert.rejects(client`DELETE FROM oid_ranked_verified_result WHERE run_id=${ids.runId}`,/immutable/);
 }finally{await client.end();await admin.end();}
});
