import assert from 'node:assert/strict';
import test from 'node:test';
import { randomUUID,createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { mkdtemp,writeFile,readFile,rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import postgres from 'postgres';
import { drizzle } from 'drizzle-orm/postgres-js';
import type { OwnerDatabase } from './db.js';
import type { SafeTaskActionEvidence } from './bef-task-executor.js';
import { addFixture,hash } from './task-run-completion.test-fixture.js';
import { sha256CanonicalTaskJson } from './task-release.js';
import { finalizeFencedTaskActionReceipts } from './task-action-fence-finalization.js';
import { createTaskPreparationCancellationExecutor } from './task-preparation.js';
import { requestRunCancellation,requestRunCancellationFromCoordinator,consumeRunCancellationOutbox } from './run-service.js';

const enabled=process.env.OID_TASK_ACTION_FENCE_PG_TEST==='1';
async function seedActions(client:ReturnType<typeof postgres>,fixture:Awaited<ReturnType<typeof addFixture>>){
 const grant=randomUUID(),closure=randomUUID(),ids=[randomUUID(),randomUUID(),randomUUID(),randomUUID()];
 await client`INSERT INTO oid_agent_access_grant(id,owner_id,agent_id,operation_id,resource,role,access_generation,expires_at)
  VALUES(${grant},${fixture.ownerId},${fixture.agentId},${'grant_'+randomUUID().replaceAll('-','')},'https://example.invalid/api/agent','agent',1,clock_timestamp()+interval '1 day')`;
 for(let index=0;index<ids.length;index++){
  const command={kind:'inspect_catalog'},payload=sha256CanonicalTaskJson({runId:fixture.runId,taskIndex:0,command});
  await client`INSERT INTO oid_run_task_action(id,run_id,task_index,owner_id,agent_id,access_generation,grant_id,task_id,
   environment_id,action_sequence,operation_id,payload_hash,action_kind,command_json)
   VALUES(${ids[index]!},${fixture.runId},0,${fixture.ownerId},${fixture.agentId},1,${grant},'S1',${fixture.environmentId},
    ${index+1},${'fence_'+randomUUID().replaceAll('-','')},${payload},'inspect_catalog',${JSON.stringify(command)}::jsonb)`;
  await client`INSERT INTO oid_run_task_action_outbox(action_id,status,delivered_at)
   VALUES(${ids[index]!},${index===0?'pending':'delivered'},${index===0?null:new Date().toISOString()})`;
  if(index<2)await client`INSERT INTO oid_run_task_action_receipt(action_id) VALUES(${ids[index]!})`;
  else await client`INSERT INTO oid_run_task_action_receipt(action_id,receipt_revision,receipt_status,evidence_hash,transaction_hash)
   VALUES(${ids[index]!},1,${index===2?'observed':'unknown'},${hash('original:'+ids[index])},${index===3?'0x'+'a'.repeat(64):null})`;
 }
 await client`UPDATE oid_run_task SET accepted_action_sequence=4 WHERE run_id=${fixture.runId} AND task_index=0`;
 await client`INSERT INTO oid_run_task_closure(id,run_id,task_index,payload_hash,reason,action_cutoff_sequence,actor_kind,owner_id,agent_id)
  VALUES(${closure},${fixture.runId},0,${hash('closure:'+fixture.runId)},'agent_finish',4,'coordinator',${fixture.ownerId},${fixture.agentId})`;
 await client`UPDATE oid_run_task SET closure_id=${closure},closure_status='closing',action_cutoff_sequence=4,
  closure_reason='agent_finish',closure_payload_hash=${hash('closure:'+fixture.runId)} WHERE run_id=${fixture.runId} AND task_index=0`;
 return ids;
}

test('isolated PostgreSQL exact-fence cancellation resolves receipts once without dispatch or refund', {skip:!enabled},async()=>{
 const sourceValue=process.env.OID_DATABASE_URL;assert.ok(sourceValue);
 const source=new URL(sourceValue);assert.equal(source.hostname,'postgres');assert.equal(source.username,'oid_owner');assert.equal(source.pathname,'/owner_identity');
 const databaseName='oid_postfence_'+randomUUID().replaceAll('-','');assert.match(databaseName,/^oid_postfence_[0-9a-f]{32}$/);
 const url=new URL(sourceValue);url.pathname='/'+databaseName;
 const admin=postgres(sourceValue,{max:1,connect_timeout:10}),client=postgres(url.href,{max:8,connect_timeout:10});
 const root=await mkdtemp(join(tmpdir(),'oid-postfence-evidence-'));let created=false;
 try{
  await admin.unsafe(`CREATE DATABASE ${databaseName}`);created=true;
  const migration=spawnSync('pnpm',['--filter','@web-agent-bench/owner-identity','migrate'],{
   cwd:'/workspace',env:{...process.env,OID_DATABASE_URL:url.href},encoding:'utf8'});
  assert.equal(migration.status,0,'isolated post-fence database migration');
  const db=drizzle(client) as unknown as OwnerDatabase;
  const fixtures:Array<Awaited<ReturnType<typeof addFixture>>&{
   kind:'owner_cancel'|'agent_revoke'|'session_lost'|'unproven_fence';ids:string[]}> =[];
  for(const kind of ['owner_cancel','agent_revoke','session_lost','unproven_fence'] as const){
   const fixture=await addFixture(client,{actionOpen:true,includeEvaluation:false,...(kind==='unproven_fence'?{fence:false}:{})});
   const ids=await seedActions(client,fixture);fixtures.push({...fixture,kind,ids});
  }
  const releaseSource={async getActiveAdmissionRelease(){return null;},async getValidatedReleaseRecord(identity:string,manifest:string){
   return fixtures.find(f=>f.record.releaseIdentity===identity&&f.record.manifestHash===manifest)?.record as never??null;}};
  const evidence:SafeTaskActionEvidence[]=[];
  const evidenceSink={async write(value:SafeTaskActionEvidence){
   const bytes=Buffer.from(JSON.stringify(value)+'\n'),digest=createHash('sha256').update(bytes).digest('hex');
   const name=value.actionId+'.json';await writeFile(join(root,name),bytes,{flag:'wx'});evidence.push(value);
   return {path:'synthetic-postfence/'+name,sha256:digest};
  }};
  for(const fixture of fixtures){
   if(fixture.kind==='agent_revoke'){
    // Simulates the already committed revoke snapshot: finalization must use original action/grant generation.
    await client`UPDATE oid_agent SET access_revoked_at=clock_timestamp(),access_generation=2 WHERE id=${fixture.agentId}`;
    await client`UPDATE oid_agent_access_grant SET revoked_at=clock_timestamp() WHERE agent_id=${fixture.agentId}`;
   }
   if(fixture.kind==='session_lost')await requestRunCancellationFromCoordinator(db,{runId:fixture.runId,reason:'coordinator_executor_session_lost'});
   else await requestRunCancellation(db,{ownerId:fixture.ownerId,runId:fixture.runId,
    operationId:'cancel_'+randomUUID().replaceAll('-',''),reason:'owner_voluntary'});
   let unbinds=0;
   const executor=createTaskPreparationCancellationExecutor({db,releaseSource,
    environmentSelector:{async selectEnvironment(){throw Error('must not prepare');}},
    preparationAdapter:{async prepare(){throw Error('must not prepare');},async reconcile(){throw Error('must not reconcile');},
     async fence(){throw Error('only stored independently confirmed fence is allowed');},clearCredentials(){}},
   },{unbindSession(){unbinds++;}},{actionEvidenceSink:evidenceSink});
   const before=await client`SELECT receipt_status,receipt_revision,evidence_hash,transaction_hash FROM oid_run_task_action_receipt
    WHERE action_id IN (${fixture.ids[2]!},${fixture.ids[3]!}) ORDER BY action_id`;
   await consumeRunCancellationOutbox(db,executor,100);
   const receipts=await client`SELECT a.id,r.receipt_status,r.receipt_revision,o.status AS outbox_status,r.transaction_hash
    FROM oid_run_task_action a JOIN oid_run_task_action_receipt r ON r.action_id=a.id
    JOIN oid_run_task_action_outbox o ON o.action_id=a.id WHERE a.run_id=${fixture.runId} ORDER BY a.action_sequence`;
   const state=await client`SELECT status,(SELECT count(*)::int FROM oid_run_task_action_reconciliation q
     JOIN oid_run_task_action a ON a.id=q.action_id WHERE a.run_id=r.id) AS reconciliations,
    (SELECT count(*)::int FROM oid_ledger_entry l WHERE l.owner_id=r.owner_id AND l.entry_type='refund') AS refunds,
    (SELECT count(*)::int FROM oid_run_task_evaluation e WHERE e.run_id=r.id) AS evaluations,
    (SELECT count(*)::int FROM oid_run_execution_slot s WHERE s.run_id=r.id) AS slots FROM oid_benchmark_run r WHERE id=${fixture.runId}`;
   if(fixture.kind==='unproven_fence'){
    assert.equal(state[0]?.status,'cancellation_requested');assert.equal(state[0]?.reconciliations,0);
    assert.equal(receipts[0]?.receipt_status,'pending');assert.equal(receipts[1]?.receipt_status,'pending');assert.equal(unbinds,0);
    continue;
   }
   assert.equal(state[0]?.status,'cancelled');assert.equal(state[0]?.reconciliations,2);
   assert.equal(state[0]?.refunds,0);assert.equal(state[0]?.evaluations,0);assert.equal(state[0]?.slots,0);
   assert.equal(receipts[0]?.receipt_status,'rejected_before_execution');assert.equal(receipts[0]?.outbox_status,'pending');
   assert.equal(receipts[1]?.receipt_status,'unknown');assert.equal(receipts[1]?.outbox_status,'delivered');
   assert.equal(receipts[3]?.transaction_hash,'0x'+'a'.repeat(64));assert.equal(unbinds,1);
   const after=await client`SELECT receipt_status,receipt_revision,evidence_hash,transaction_hash FROM oid_run_task_action_receipt
    WHERE action_id IN (${fixture.ids[2]!},${fixture.ids[3]!}) ORDER BY action_id`;
   assert.deepEqual(after,before,'observed and preexisting unknown receipts remain immutable');
   const lease=await client`SELECT fence_evidence FROM oid_task_environment_lease WHERE lease_id=${fixture.leaseId}`;
   const digest=lease[0]!.fence_evidence.evidence.sha256;
   // Repeated callback/restart finds terminal receipts and performs no evidence/business write.
   assert.deepEqual(await finalizeFencedTaskActionReceipts({db,evidenceSink},{runId:fixture.runId,agentId:fixture.agentId,
    taskIndex:0,preparationId:fixture.preparationId,generationId:fixture.generationId,fenceEvidenceHash:digest}),{rejected:0,unknown:0});
   await assert.rejects(finalizeFencedTaskActionReceipts({db,evidenceSink},{runId:fixture.runId,agentId:fixture.agentId,
    taskIndex:0,preparationId:fixture.preparationId,generationId:randomUUID(),fenceEvidenceHash:digest}),/fence\/action scope/);
   for(const action of evidence.filter(item=>item.runId===fixture.runId)){
    const bytes=await readFile(join(root,action.actionId+'.json'));assert.deepEqual(JSON.parse(bytes.toString()),action);
    assert.equal(JSON.stringify(action).includes('payerPrivateKey'),false);
   }
  }
  assert.equal(evidence.length,6);
 }finally{
  await client.end();if(created)await admin.unsafe(`DROP DATABASE ${databaseName}`);await admin.end();await rm(root,{recursive:true,force:true});
 }
});
