import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import postgres from 'postgres';
import { drizzle } from 'drizzle-orm/postgres-js';
import type { OwnerDatabase } from './db.js';
import type { ReportClosureStateStore } from './report-closure-state.js';
import { addFixture } from './task-run-completion.test-fixture.js';
import { diagnosticOAuthPgProbes } from './mcp-diagnostics-oauth.pg-probes.js';
import { admitTaskAction } from './task-action-service.js';
import { BefTaskExecutor } from './bef-task-executor.js';
import { setDiagnosticActionSink,withDiagnosticRequest,type DiagnosticBoundary } from './mcp-diagnostics-boundary.js';
import { diagnosticHash,DIAGNOSTIC_LIMITS,type DiagnosticEnvelope } from './mcp-diagnostics-contract.js';
import { appendDiagnosticBatch,cleanupDiagnosticRetention,diagnosticBackupInventory,diagnosticReceipt,getDiagnosticCase,importDiagnosticBatch,recordServerDiagnostic,registerDiagnosticCase } from './mcp-diagnostics-service.js';

// AICODE-NOTE: These are isolated actual-PostgreSQL contract probes, not native
// model/browser/chain acceptance. They never connect to the preserved Google DB.
test('diagnostic canonical cases, privacy, receipts and shared quotas survive actual PostgreSQL',
 {skip:process.env.OID_MCP_DIAGNOSTICS_PG_TEST!=='1'},async t=>{
 const source=process.env.OID_DATABASE_URL;assert.ok(source);const sourceUrl=new URL(source);
 assert.equal(sourceUrl.hostname,'postgres');assert.equal(sourceUrl.username,'oid_owner');assert.equal(sourceUrl.pathname,'/owner_identity');
 const name='oid_diagnostics_'+randomUUID().replaceAll('-','');assert.match(name,/^oid_diagnostics_[a-f0-9]{32}$/);
 const uri=new URL(source);uri.pathname='/'+name;const admin=postgres(source,{max:1,connect_timeout:10});
 const client=postgres(uri.href,{max:5,connect_timeout:10});const db=drizzle(client) as unknown as OwnerDatabase;let created=false;
 let externalClosure:string|null=null;
 const reportClosureState:ReportClosureStateStore={async readAuthoritativeClosure(){return {betaEndedAt:externalClosure,sourceEvidenceSha256:'a'.repeat(64)};},async persistAuthoritativeClosure(){throw new Error('read-only fixture closure');}};
 const deps={db,reportClosureState};
 function event(overrides:Partial<DiagnosticEnvelope>={}):DiagnosticEnvelope{return {eventId:randomUUID(),source:'client',stage:'client_validation',tool:'runs.task_action',outcome:'error',errorCode:'INVALID_ARGUMENTS',startedAt:'2026-11-02T11:00:00.000Z',completedAt:'2026-11-02T11:00:00.012Z',durationMs:12,fieldPaths:['operationId'],...overrides};}
 function batch(segmentId:string,batchSequence:number,events:DiagnosticEnvelope[],completion:'open'|'complete'|'partial'){
  const value={segmentId,batchSequence,events,completion};return {...value,payloadHash:diagnosticHash(value)};
 }
 async function business(){return JSON.stringify(await client`SELECT
  (SELECT md5(COALESCE(string_agg(to_jsonb(r)::text,'' ORDER BY id),'')) FROM oid_benchmark_run r) AS runs,
  (SELECT md5(COALESCE(string_agg(to_jsonb(r)::text,'' ORDER BY run_id,task_index),'')) FROM oid_run_task r) AS tasks,
  (SELECT md5(COALESCE(string_agg(to_jsonb(r)::text,'' ORDER BY id),'')) FROM oid_run_task_action r) AS actions,
  (SELECT md5(COALESCE(string_agg(to_jsonb(r)::text,'' ORDER BY id),'')) FROM oid_ledger_entry r) AS ledger`);}
 try{
  await admin.unsafe('CREATE DATABASE '+name);created=true;
  const migrated=spawnSync('pnpm',['--filter','@web-agent-bench/owner-identity','migrate'],{cwd:'/workspace',env:{PATH:process.env.PATH,HOME:process.env.HOME,NODE_ENV:'test',OID_DATABASE_URL:uri.href,OID_AUTH_SECRET:'synthetic-diagnostics-test-secret-not-live-123456789',OID_PUBLIC_ORIGIN:'http://127.0.0.1:3400'},encoding:'utf8'});
  const migrationFailure=(migrated.stderr??'').split('\n').filter(line=>/migration failed|Error:|PostgresError:|code:|constraint:|table:|column:|detail:/.test(line)).map(line=>line.replace(/postgres(?:ql)?:\/\/[^\s'"\]]+/gi,'[database-url]').replace(/(?:token|secret|password)\s*[:=]\s*[^\s,]+/gi,'credential=[redacted]')).slice(0,8).join('\n');
  assert.equal(migrated.status,0,`isolated full schema migration must succeed (${migrated.error?.name??'process'}): ${migrationFailure}`);
  const f=await addFixture(client,{includeEvaluation:false,fence:false,overallDeadlineSecondsFromNow:600});
  const intentId=(await client`SELECT intent_id FROM oid_benchmark_run WHERE id=${f.runId}`)[0]!.intent_id as string;
  const connectionId=randomUUID(),sessionId=randomUUID(),principal={ownerId:f.ownerId,agentId:f.agentId,connectionId};
  await client`INSERT INTO oid_agent_access_grant(id,owner_id,agent_id,operation_id,source,resource,access_generation,expires_at)
   VALUES (${connectionId},${f.ownerId},${f.agentId},${'diag_grant_'+randomUUID().replaceAll('-','')},'oauth','https://bench.example/api/agent/mcp',1,clock_timestamp()+interval '1 day')`;
  await client`INSERT INTO oid_audit(id,event_type,operation_id,actor_owner_id,metadata) VALUES (${randomUUID()},'agent.connection.intent_bound',${'connection-intent:'+intentId},${f.ownerId},${JSON.stringify({connectionId,agentId:f.agentId})}::jsonb)`;
  const originalBusiness=await business();
  const registered=await registerDiagnosticCase(deps,principal,{diagnosticSessionId:sessionId,intentId});
  const caseId=registered.caseId,segment=randomUUID();let reportId:string|null=null;

  await t.test('same intent canonicalizes caller sessions and cross-actor retries to one report',async()=>{
   const second=await registerDiagnosticCase(deps,principal,{diagnosticSessionId:randomUUID(),intentId});assert.equal(second.caseId,caseId);
   const open=batch(segment,0,[event({stage:'client_runtime',errorCode:'CLIENT_RUNTIME_ERROR',clientRunStatus:'running',clientRunObservedAt:'2026-11-02T10:59:59.000Z'})],'open');assert.equal((await appendDiagnosticBatch(deps,principal,caseId,open)).reportCreated,false,'do not consume active task time creating reports for open capture');
   const close=batch(segment,1,[],'partial');const results=await Promise.all([
    appendDiagnosticBatch(deps,principal,caseId,close),
    importDiagnosticBatch(deps,f.ownerId,{diagnosticSessionId:sessionId,intentId,caseId,binding:{agentId:f.agentId,connectionId},batch:close})
   ]);
   assert.equal(results[0]!.reportId,results[1]!.reportId);assert.ok(results[0]!.reportId);reportId=results[0]!.reportId;
   assert.equal(results[0]!.highestContiguousSequence,1);assert.equal(results[0]!.highestContiguousHash,close.payloadHash);assert.equal(results[0]!.diagnosticsSynced,true);
   assert.equal(Number((await client`SELECT count(*) AS n FROM oid_support_report WHERE id=${reportId}`)[0]!.n),1);
   assert.equal(Number((await client`SELECT count(*) AS n FROM oid_support_report_audit WHERE report_id=${reportId} AND event_type='created'`)[0]!.n),1);
   const snapshot=(await getDiagnosticCase(deps,f.ownerId,caseId)).events.find(e=>e.clientRunStatus!==undefined);assert.equal(snapshot?.clientRunStatus,'running');assert.equal(snapshot?.clientRunObservedAt,'2026-11-02T10:59:59.000Z');assert.equal(snapshot?.responsibility,'unknown');
   const linked=(await client`SELECT e.envelope->>'clientRunStatus' AS status,e.envelope->>'clientRunObservedAt' AS observed FROM oid_mcp_diagnostic_event e JOIN oid_mcp_diagnostic_case c ON c.id=e.case_id JOIN oid_support_report r ON r.id=c.report_id WHERE r.id=${reportId} AND e.envelope ? 'clientRunStatus'`)[0]!;assert.equal(linked.status,'running');assert.equal(linked.observed,'2026-11-02T10:59:59.000Z');
   assert.equal(await business(),originalBusiness,'report creation may not change running run, task or funding');
  });
  await t.test('an unrelated generic report cannot preempt the canonical diagnostic report',async()=>{
   const registered=await registerDiagnosticCase(deps,principal,{diagnosticSessionId:randomUUID()});
   const unrelated=randomUUID(),predictable='mcd_'+registered.caseId.replaceAll('-','');
   await client`INSERT INTO oid_support_report(id,owner_id,agent_id,source,reporter_kind,reporter_id,operation_id,payload_hash,title,body,safe_context)
    VALUES (${unrelated},${f.ownerId},${f.agentId},'agent','agent',${f.agentId},${predictable},${'a'.repeat(64)},'Synthetic unrelated report','Explicit generic-report namespace collision fixture','{}'::jsonb)`;
   const final=batch(randomUUID(),0,[event()],'complete');
   const receipt=await appendDiagnosticBatch(deps,principal,registered.caseId,final);
   assert.ok(receipt.reportId);assert.notEqual(receipt.reportId,unrelated);
   assert.equal((await appendDiagnosticBatch(deps,principal,registered.caseId,final)).reportId,receipt.reportId);
   assert.equal(Number((await client`SELECT count(*) AS n FROM oid_mcp_diagnostic_case WHERE report_id=${receipt.reportId}`)[0]!.n),1);
   assert.equal(await business(),originalBusiness);
  });
  await t.test('late segments update diagnostic projection without changing report submission',async()=>{
   const before=JSON.stringify(await client`SELECT to_jsonb(r) FROM oid_support_report r WHERE id=${reportId}`);
   const late=batch(randomUUID(),0,[event({stage:'transport',errorCode:'CONNECTION_LOST'})],'complete');
   const receipt=await appendDiagnosticBatch(deps,principal,caseId,late);assert.equal(receipt.reportId,reportId);
   const view=await getDiagnosticCase(deps,f.ownerId,caseId);assert.equal(view.case.errorCount,2);assert.equal(view.case.runId,f.runId);assert.equal(view.case.sourceTrust,'client_observed_unverified');
   assert.ok(view.events.every(e=>e.responsibility==='unknown'));assert.equal(JSON.stringify(await client`SELECT to_jsonb(r) FROM oid_support_report r WHERE id=${reportId}`),before);
   assert.equal(await business(),originalBusiness);
  });
  await t.test('same batch/event identity cannot be rewritten and missing sequences cannot be acknowledged',async()=>{
   const changed=batch(segment,1,[event()],'partial');await assert.rejects(appendDiagnosticBatch(deps,principal,caseId,changed),{code:'IDEMPOTENCY_CONFLICT'});
   const gap=batch(randomUUID(),1,[],'complete');await assert.rejects(appendDiagnosticBatch(deps,principal,caseId,gap),{code:'DIAGNOSTICS_SEQUENCE_GAP'});
   const receipt=await diagnosticReceipt(deps,principal,caseId,segment);assert.equal(receipt.highestContiguousSequence,1);assert.equal(receipt.reportId,reportId);
   await assert.rejects(client`UPDATE oid_mcp_diagnostic_event SET error_code='INTERNAL_ERROR' WHERE case_id=${caseId}`,/append_only/);
  });
  await t.test('foreign links, client attribution claims and raw canaries are rejected before durable event writes',async()=>{
   const before=Number((await client`SELECT count(*) AS n FROM oid_mcp_diagnostic_event`)[0]!.n);
   await assert.rejects(getDiagnosticCase(deps,randomUUID(),caseId),{code:'DIAGNOSTICS_CASE_NOT_FOUND'});
   await assert.rejects(appendDiagnosticBatch(deps,{...principal,connectionId:randomUUID()},caseId,batch(randomUUID(),0,[],'partial')),{code:'DIAGNOSTICS_CASE_NOT_FOUND'});
   const canary={...event(),rawMessage:'sk_CANARY_HIDDEN_RANKED'};
   for(const invalid of [{...event(),clientRunStatus:'running'},{...event(),clientRunObservedAt:'2026-11-02T10:59:59.000Z'},{...event(),source:'server',stage:'client_runtime',clientRunStatus:'running',clientRunObservedAt:'2026-11-02T10:59:59.000Z'},{...event(),stage:'client_runtime',clientRunStatus:'not_a_status',clientRunObservedAt:'2026-11-02T10:59:59.000Z'}])await assert.rejects(appendDiagnosticBatch(deps,principal,caseId,batch(randomUUID(),0,[invalid as DiagnosticEnvelope],'partial')),{code:'INVALID_DIAGNOSTICS'});
   await assert.rejects(appendDiagnosticBatch(deps,principal,caseId,{segmentId:randomUUID(),batchSequence:0,payloadHash:'a'.repeat(64),events:[canary],completion:'complete'}),{code:'INVALID_DIAGNOSTICS'});
   await assert.rejects(appendDiagnosticBatch(deps,principal,caseId,batch(randomUUID(),0,[event({actionId:randomUUID()})],'complete')),{code:'DIAGNOSTICS_LINK_NOT_FOUND'});
   assert.equal(Number((await client`SELECT count(*) AS n FROM oid_mcp_diagnostic_event`)[0]!.n),before);assert.equal(await business(),originalBusiness);
  });
  await t.test('complete error-free capture produces no diagnostic report; partial capture does',async()=>{
   const clean=await registerDiagnosticCase(deps,principal,{diagnosticSessionId:randomUUID()});
   const cleanReceipt=await appendDiagnosticBatch(deps,principal,clean.caseId,batch(randomUUID(),0,[event({outcome:'success',errorCode:undefined})],'complete'));
   assert.equal(cleanReceipt.reportCreated,false);assert.equal(cleanReceipt.diagnosticsSynced,true);
   await recordServerDiagnostic(deps,{principal,caseId:clean.caseId,event:event({source:'server',stage:'handler',errorCode:'INTERNAL_ERROR'})});
   assert.ok((await getDiagnosticCase(deps,f.ownerId,clean.caseId)).case.reportId,'late server error must replace the completed all-clear with a diagnostic report');
   const partial=await registerDiagnosticCase(deps,principal,{diagnosticSessionId:randomUUID()});
   assert.equal((await appendDiagnosticBatch(deps,principal,partial.caseId,batch(randomUUID(),0,[],'partial'))).reportCreated,true);
  });
  await t.test('owner quota exhaustion is durable and cannot be reset by rotating session identities',async()=>{
   const saved=(await client`SELECT * FROM oid_mcp_diagnostic_quota WHERE scope=${'owner:'+f.ownerId}`)[0]!;
   await client`UPDATE oid_mcp_diagnostic_quota SET bytes=${DIAGNOSTIC_LIMITS.ownerBytes-512} WHERE scope=${'owner:'+f.ownerId}`;
   await registerDiagnosticCase(deps,principal,{diagnosticSessionId:randomUUID()});
   const casesBefore=Number((await client`SELECT count(*) AS n FROM oid_mcp_diagnostic_case`)[0]!.n);
   for(let i=0;i<3;i++)await assert.rejects(registerDiagnosticCase(deps,principal,{diagnosticSessionId:randomUUID()}),{code:'DIAGNOSTICS_QUOTA_EXCEEDED'});
   assert.equal(Number((await client`SELECT count(*) AS n FROM oid_mcp_diagnostic_case`)[0]!.n),casesBefore);
   assert.equal(Number((await client`SELECT bytes FROM oid_mcp_diagnostic_quota WHERE scope=${'owner:'+f.ownerId}`)[0]!.bytes),DIAGNOSTIC_LIMITS.ownerBytes);
   await client`UPDATE oid_mcp_diagnostic_quota SET bytes=${(BigInt(saved.bytes)+512n).toString()}::bigint,rows=${saved.rows},cases=${Number(saved.cases)+1} WHERE scope=${'owner:'+f.ownerId}`;
  });
  await t.test('batch quota rejection commits only the partial marker and returns an explicit 429 without acknowledgement',async()=>{
   const c=await registerDiagnosticCase(deps,principal,{diagnosticSessionId:randomUUID()}),s=randomUUID();
   const saved=(await client`SELECT rows FROM oid_mcp_diagnostic_quota WHERE scope=${'owner:'+f.ownerId}`)[0]!.rows;
   await client`UPDATE oid_mcp_diagnostic_quota SET rows=${DIAGNOSTIC_LIMITS.ownerRows} WHERE scope=${'owner:'+f.ownerId}`;
   try{await assert.rejects(appendDiagnosticBatch(deps,principal,c.caseId,batch(s,0,[event()],'complete')),{status:429,code:'DIAGNOSTICS_QUOTA_EXCEEDED'});
    const receipt=await diagnosticReceipt(deps,principal,c.caseId,s);assert.equal(receipt.highestContiguousSequence,-1);assert.equal(receipt.diagnosticsSynced,false);
    assert.equal(receipt.reportCreated,true,'quota control report must not wait for an impossible final detailed batch');
    const reportId=receipt.reportId;
    for(let i=0;i<12;i++)await assert.rejects(appendDiagnosticBatch(deps,principal,c.caseId,batch(s,0,[event()],'complete')),{status:429,code:'DIAGNOSTICS_QUOTA_EXCEEDED'});
    assert.equal((await diagnosticReceipt(deps,principal,c.caseId,s)).reportId,reportId);
    assert.equal(Number((await client`SELECT count(*) AS n FROM oid_support_report WHERE id=${reportId}`)[0]!.n),1);
    assert.equal((await getDiagnosticCase(deps,f.ownerId,c.caseId)).case.captureState,'partial_quota');
    assert.equal(Number((await client`SELECT count(*) AS n FROM oid_mcp_diagnostic_event WHERE case_id=${c.caseId}`)[0]!.n),0);
   }finally{await client`UPDATE oid_mcp_diagnostic_quota SET rows=${saved} WHERE scope=${'owner:'+f.ownerId}`;}
  });
  await t.test('report throttling preserves acknowledged evidence and same-batch retry creates exactly one pending report',async()=>{
   const key=`principal:agent:${f.agentId}:minute`;
   const saved=(await client`SELECT * FROM oid_support_report_rate WHERE key=${key}`)[0]!;
   await client`UPDATE oid_support_report_rate SET window_start=floor(extract(epoch FROM clock_timestamp())/60)::bigint*60,request_count=5 WHERE key=${key}`;
   const c=await registerDiagnosticCase(deps,principal,{diagnosticSessionId:randomUUID()});
   const b=batch(randomUUID(),0,[event()],'complete');
   const pending=await appendDiagnosticBatch(deps,principal,c.caseId,b);
   assert.equal(pending.highestContiguousSequence,0);assert.equal(pending.reportCreated,false);assert.equal(pending.diagnosticsSynced,false);
   assert.equal(Number((await client`SELECT count(*) AS n FROM oid_mcp_diagnostic_event WHERE case_id=${c.caseId}`)[0]!.n),1);
   // Controlled rate-window rollover only: earlier scenarios may legitimately
   // have consumed the full minute. The retained diagnostic batch is retried
   // once the original quota window has expired, not given an increased limit.
   await client`UPDATE oid_support_report_rate SET window_start=${Number(saved.window_start)-60},request_count=${saved.request_count} WHERE key=${key}`;
   const retry=await appendDiagnosticBatch(deps,principal,c.caseId,b);assert.equal(retry.reportCreated,true);assert.equal(retry.diagnosticsSynced,true);
   assert.equal((await appendDiagnosticBatch(deps,principal,c.caseId,b)).reportId,retry.reportId);
  });
  await t.test('server backup inventory is deterministic and explicitly excludes remote native client files',async()=>{
   const a=await diagnosticBackupInventory(deps),b=await diagnosticBackupInventory(deps);assert.deepEqual(a,b);
   assert.equal(a.nativeClientFilesIncluded,false);assert.equal(a.remoteClientCoverage,'not_backed_up');assert.equal(Object.keys(a.tables).length,7);
   for(const v of Object.values(a.tables)){assert.match(v.sha256,/^[a-f0-9]{64}$/);assert.ok(v.count>=0);}
  });
  await t.test('anonymous overflow uses fixed aggregate buckets rather than new rows per caller/event',async()=>{
   await client`UPDATE oid_mcp_diagnostic_quota SET rows=${DIAGNOSTIC_LIMITS.anonymousRows} WHERE scope='anonymous'`;
   const before=Number((await client`SELECT count(*) AS n FROM oid_mcp_diagnostic_event WHERE case_id IS NULL`)[0]!.n);
   for(let i=0;i<20;i++){const result=await recordServerDiagnostic(deps,{event:event({source:'server',stage:'authentication',tool:'unknown',errorCode:'UNAUTHORIZED'})});assert.equal(result.recorded,false);}
   assert.equal(Number((await client`SELECT count(*) AS n FROM oid_mcp_diagnostic_event WHERE case_id IS NULL`)[0]!.n),before);
   assert.equal(Number((await client`SELECT count(*) AS n FROM oid_mcp_diagnostic_aggregate`)[0]!.n),128);
   assert.ok(Number((await client`SELECT sum(dropped_count) AS n FROM oid_mcp_diagnostic_aggregate`)[0]!.n)>=20);
  });
  await t.test('authoritative external beta closure defeats a restored null database retention row',async()=>{
   externalClosure=new Date(Date.now()-31*24*60*60*1000).toISOString();
   await assert.rejects(getDiagnosticCase(deps,f.ownerId,caseId),{code:'REPORT_RETENTION_EXPIRED'});
   await assert.rejects(appendDiagnosticBatch(deps,principal,caseId,batch(randomUUID(),0,[],'partial')),{code:'REPORT_RETENTION_EXPIRED'});
   assert.equal(await business(),originalBusiness);
   const cleaned=await cleanupDiagnosticRetention(deps);assert.equal(cleaned.expired,true);assert.ok(cleaned.removedCases>0);assert.ok(cleaned.removedEvents>0);
   const repeated=await cleanupDiagnosticRetention(deps);assert.equal(repeated.removedCases,0);assert.equal(repeated.removedEvents,0);
   assert.equal(Number((await client`SELECT count(*) AS n FROM oid_mcp_diagnostic_retention_receipt`)[0]!.n),1);
   assert.equal(await business(),originalBusiness,'retention cleanup cannot alter benchmark or funding records');
  });
  await t.test('helper OAuth PKCE, scope isolation, refresh and external rollback leave native authorization independent',async()=>{
   await diagnosticOAuthPgProbes(db,client,principal);assert.equal(await business(),originalBusiness);
  });
  await t.test('real admission, executor dispatch and durable rejection receipt emit only post-commit diagnostic hooks',async()=>{
   const fixture=await addFixture(client,{actionOpen:true,includeEvaluation:false,fence:false,overallDeadlineSecondsFromNow:600});
   const grantId=randomUUID(),resource='https://bench.example/api/agent/mcp';
   await client`INSERT INTO oid_agent_access_grant(id,owner_id,agent_id,operation_id,source,resource,access_generation,expires_at)
    VALUES(${grantId},${fixture.ownerId},${fixture.agentId},${randomUUID()},'oauth',${resource},1,clock_timestamp()+interval '1 day')`;
   const actor={ownerId:fixture.ownerId,agentId:fixture.agentId,grantId,credentialId:grantId,resource,role:'agent',accessGeneration:1,accessRevision:1,policyRevision:1,permissions:{training:true,ranked:false,forumMessages:false,customTopics:false}};
   const seen:DiagnosticBoundary[]=[];
   setDiagnosticActionSink(db,async event=>{
    assert.ok(event.actionId);
    if(event.stage==='dispatch')assert.equal((await client`SELECT status FROM oid_run_task_action_outbox WHERE action_id=${event.actionId}`)[0]!.status,'delivered');
    if(event.stage==='receipt')assert.equal((await client`SELECT receipt_status FROM oid_run_task_action_receipt WHERE action_id=${event.actionId}`)[0]!.receipt_status,'rejected_before_execution');
    seen.push(event);throw new Error('synthetic post-commit diagnostic outage');
   });
   try{
    const operationId='diagnostic_actual_admission';
    const input={runId:fixture.runId,taskIndex:0,operationId,command:{kind:'inspect_catalog'}};
    const admitted=await withDiagnosticRequest(async event=>{
     assert.ok(event.actionId);
     assert.equal(Number((await client`SELECT count(*) AS n FROM oid_run_task_action WHERE id=${event.actionId}`)[0]!.n),1,'independent connection must see committed action');
     seen.push(event);throw new Error('synthetic request diagnostic outage');
    },()=>admitTaskAction({db},actor,input));
    assert.equal(admitted.admitted,true);if(!admitted.admitted)return;
    const pin=(await client`SELECT * FROM oid_task_execution_binding WHERE run_id=${fixture.runId} AND task_index=0`)[0]!;
    const executor=new BefTaskExecutor({db,taskReleaseSource:{async getValidatedReleaseRecord(){return fixture.record;}} as never,participantApiByEnvironment:{[fixture.environmentId]:'http://127.0.0.1:19999'},
     evidenceSink:{async write(value){return {path:'synthetic-diagnostics/rejection.json',sha256:diagnosticHash(value)};}},
     async fetch(url){assert.equal(new URL(String(url)).pathname,'/healthz','revoked action must not reach participant execution');return new Response(JSON.stringify({status:'ready',boundary:'benchmark-environment-api',manifestSha256:pin.manifest_hash,applicationSourceSha256:pin.application_source_hash,environments:[{envId:fixture.environmentId}]}));}});
    await executor.attachStartedSession({runId:fixture.runId,taskIndex:0,envId:fixture.environmentId,generationId:fixture.generationId,manifestHash:pin.manifest_hash,applicationSourceHash:pin.application_source_hash,runToken:'synthetic-test-run-token-only-12345678901234567890',participantId:pin.participant_id,payerAddress:pin.payer_address});
    await client`UPDATE oid_agent_access_grant SET revoked_at=clock_timestamp() WHERE id=${grantId}`;
    const executed=await executor.executeNext(fixture.runId,0);assert.equal(executed.status,'recorded');
    assert.equal((await executor.executeNext(fixture.runId,0)).status,'idle','diagnostic rejection must never cause action redispatch');
    assert.deepEqual(seen.map(e=>e.stage),['admission','dispatch','receipt']);
    assert.equal(Number((await client`SELECT count(*) AS n FROM oid_run_task_action WHERE run_id=${fixture.runId}`)[0]!.n),1);
   }finally{setDiagnosticActionSink(db,undefined);}
  });
 }finally{await client.end();if(created)await admin.unsafe('DROP DATABASE '+name+' WITH (FORCE)');await admin.end();}
});

