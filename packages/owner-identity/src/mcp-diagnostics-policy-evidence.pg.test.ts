import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import test from 'node:test';
import postgres from 'postgres';
import {drizzle} from 'drizzle-orm/postgres-js';
import type {OwnerDatabase} from './db.js';
import type {AgentPrincipal} from './agents.js';
import type {ReportClosureStateStore} from './report-closure-state.js';
import {addFixture} from './task-run-completion.test-fixture.js';
import {admitTaskAction} from './task-action-service.js';
import {deriveDiagnosticPolicyEvidence} from './mcp-diagnostics-policy-evidence.js';
import {classifyDiagnosticResponsibility} from './mcp-diagnostics-contract.js';
import {recordServerDiagnostic,registerDiagnosticCase} from './mcp-diagnostics-service.js';

// Actual service denials and independently retained SQL evidence in a disposable
// full schema. This is not a native/HTTP/chain acceptance substitute.
test('normal policy diagnostics qualify only actual owned denials with matching retained SQL predicates',
 {skip:process.env.OID_MCP_DIAGNOSTICS_PG_TEST!=='1'},async t=>{
 const source=process.env.OID_DATABASE_URL;assert.ok(source);const original=new URL(source);assert.equal(original.hostname,'postgres');assert.equal(original.username,'oid_owner');assert.equal(original.pathname,'/owner_identity');
 const name='oid_diagnostics_policy_'+randomUUID().replaceAll('-','');assert.match(name,/^oid_diagnostics_policy_[a-f0-9]{32}$/);
 const target=new URL(original);target.pathname='/'+name;const admin=postgres(source,{max:1}),client=postgres(target.href,{max:4});
 const db=drizzle(client) as unknown as OwnerDatabase;let created=false;
 const closure:ReportClosureStateStore={async readAuthoritativeClosure(){return {betaEndedAt:null,sourceEvidenceSha256:'a'.repeat(64)};},async persistAuthoritativeClosure(){throw Error('read-only closure fixture');}};
 const deps={db,reportClosureState:closure};
 async function binding(f:Awaited<ReturnType<typeof addFixture>>){
  const connectionId=randomUUID(),intentId=(await client`SELECT intent_id FROM oid_benchmark_run WHERE id=${f.runId}`)[0]!.intent_id as string;
  await client`INSERT INTO oid_agent_access_grant(id,owner_id,agent_id,operation_id,source,resource,access_generation,expires_at) VALUES(${connectionId},${f.ownerId},${f.agentId},${randomUUID()},'oauth','https://bench.example/api/agent/mcp',1,clock_timestamp()+interval '1 day')`;
  await client`INSERT INTO oid_audit(id,event_type,operation_id,actor_owner_id,metadata) VALUES(${randomUUID()},'agent.connection.intent_bound',${'connection-intent:'+intentId},${f.ownerId},${JSON.stringify({connectionId,agentId:f.agentId})}::jsonb)`;
  const principal={ownerId:f.ownerId,agentId:f.agentId,connectionId},registered=await registerDiagnosticCase(deps,principal,{diagnosticSessionId:randomUUID(),intentId});
  const actor:AgentPrincipal={ownerId:f.ownerId,agentId:f.agentId,grantId:connectionId,credentialId:connectionId,resource:'https://bench.example/api/agent/mcp',role:'agent',accessGeneration:1,accessRevision:1,policyRevision:1,permissions:{training:true,ranked:false,forumMessages:false,customTopics:false}};
  return {principal,actor,caseId:registered.caseId};
 }
 async function unchanged(){return JSON.stringify(await client`SELECT
  (SELECT md5(COALESCE(string_agg(to_jsonb(r)::text,'' ORDER BY id),'')) FROM oid_benchmark_run r) AS runs,
  (SELECT md5(COALESCE(string_agg(to_jsonb(r)::text,'' ORDER BY run_id,task_index),'')) FROM oid_run_task r) AS tasks,
  (SELECT md5(COALESCE(string_agg(to_jsonb(r)::text,'' ORDER BY id),'')) FROM oid_run_task_action r) AS actions,
  (SELECT md5(COALESCE(string_agg(to_jsonb(r)::text,'' ORDER BY id),'')) FROM oid_ledger_entry r) AS ledger`);}
 try{
  await admin.unsafe('CREATE DATABASE '+name);created=true;
  const migration=spawnSync('pnpm',['--filter','@web-agent-bench/owner-identity','migrate'],{cwd:'/workspace',env:{PATH:process.env.PATH,HOME:process.env.HOME,NODE_ENV:'test',OID_DATABASE_URL:target.href,OID_AUTH_SECRET:'synthetic-policy-evidence-test-secret-12345678',OID_PUBLIC_ORIGIN:'http://127.0.0.1:3400'},encoding:'utf8'});
  assert.equal(migration.status,0,'synthetic full schema migration must succeed; secret-bearing stderr is not emitted');
  const f=await addFixture(client,{actionOpen:true,includeEvaluation:false,fence:false,overallDeadlineSecondsFromNow:600}),b=await binding(f);
  const args={runId:f.runId,taskIndex:0,operationId:'policy_evidence_original_action',command:{kind:'approve',amountUnits:'1',gasLimit:'50000'}};
  const admitted=await admitTaskAction({db},b.actor,args);assert.equal(admitted.admitted,true);if(!admitted.admitted)return;
  const conflict={...args,command:{...args.command,amountUnits:'2'}};
  await assert.rejects(admitTaskAction({db},b.actor,conflict),{code:'IDEMPOTENCY_CONFLICT'});
  const input={principal:b.principal,caseId:b.caseId,tool:'runs.task_action',errorCode:'IDEMPOTENCY_CONFLICT',arguments:conflict};
  await t.test('retained owned prior action proves the exact conflicting normalized payload',async()=>{
   const before=await unchanged(),proof=await deriveDiagnosticPolicyEvidence({db},input);
   assert.equal(classifyDiagnosticResponsibility(proof).responsibility,'expected_policy_denial');assert.ok(proof?.evidenceIds?.includes(admitted.actionId));
   assert.ok(proof);
   const differentTask={...args,taskIndex:1};await assert.rejects(admitTaskAction({db},b.actor,differentTask),{code:'IDEMPOTENCY_CONFLICT'});
   assert.equal(classifyDiagnosticResponsibility(await deriveDiagnosticPolicyEvidence({db},{...input,arguments:differentTask})).responsibility,'expected_policy_denial');
   const eventId=randomUUID(),stamp=new Date().toISOString();await recordServerDiagnostic(deps,{principal:b.principal,caseId:b.caseId,evidence:proof,event:{eventId,source:'server',stage:'handler',tool:'runs.task_action',outcome:'error',errorCode:'IDEMPOTENCY_CONFLICT',startedAt:stamp,completedAt:stamp,durationMs:0}});
   const persisted=(await client`SELECT responsibility,evidence_ids FROM oid_mcp_diagnostic_event WHERE event_id=${eventId}`)[0]!;
   assert.equal(persisted.responsibility,'expected_policy_denial');assert.deepEqual(persisted.evidence_ids,proof?.evidenceIds);assert.equal(await unchanged(),before);
  });
  await t.test('same normalized command, missing prior identity, malformed input and foreign binding remain unknown',async()=>{
   for(const variant of [
    {...input,arguments:{...args,command:{...args.command,tokenAssetId:'WETH'}}},
    {...input,arguments:{...conflict,operationId:'policy_evidence_no_prior_action'}},
    {...input,arguments:{...conflict,command:{kind:'unsupported'}}},
    {...input,principal:{...b.principal,ownerId:randomUUID()}},
    {...input,principal:{...b.principal,connectionId:randomUUID()}},
    {...input,arguments:{...conflict,runId:randomUUID()}},
    {principal:input.principal,tool:input.tool,errorCode:input.errorCode,arguments:input.arguments},{...input,tool:'runs.finish_task'},{...input,errorCode:'INTERNAL_ERROR'}
   ])assert.equal(classifyDiagnosticResponsibility(await deriveDiagnosticPolicyEvidence({db},variant)).responsibility,'unknown');
   await client`INSERT INTO oid_run_mode_cancellation_outbox(event_id,owner_id,agent_id,mode,policy_revision) VALUES(${randomUUID()},${f.ownerId},${f.agentId},'training',2)`;
   await assert.rejects(admitTaskAction({db},b.actor,conflict),{code:'RUN_MODE_FENCED'});
   assert.equal(await deriveDiagnosticPolicyEvidence({db},input),undefined,'a mode fence contradicts a later conflict cause');
  });
  await t.test('mode denial needs real current owned policy and does not mutate it',async()=>{
   const mode={...input,errorCode:'MODE_NOT_ALLOWED',arguments:{runId:f.runId}};
   assert.equal(await deriveDiagnosticPolicyEvidence({db},mode),undefined);
   await client`UPDATE oid_agent_policy SET training=false,revision=revision+1 WHERE agent_id=${f.agentId}`;
   await assert.rejects(admitTaskAction({db},b.actor,{...args,operationId:'policy_evidence_disabled_mode'}),{code:'MODE_NOT_ALLOWED'});
   const before=await unchanged();assert.equal(classifyDiagnosticResponsibility(await deriveDiagnosticPolicyEvidence({db},mode)).responsibility,'expected_policy_denial');assert.equal(await unchanged(),before);
   assert.equal(await deriveDiagnosticPolicyEvidence({db},input),undefined,'disabled mode contradicts a later-stage conflict cause');
  });
  await t.test('actual task closure UUID and immutable cutoff prove task closed but not an invented deadline',async()=>{
   const closed=await addFixture(client,{includeEvaluation:false,fence:false,overallDeadlineSecondsFromNow:600}),owned=await binding(closed),arguments_={runId:closed.runId,taskIndex:0,operationId:'policy_evidence_closed_task',command:{kind:'inspect_catalog'}};
   await assert.rejects(admitTaskAction({db},owned.actor,arguments_),{code:'TASK_CLOSED'});
   const request={principal:owned.principal,caseId:owned.caseId,tool:'runs.task_action',errorCode:'TASK_CLOSED',arguments:arguments_};
   const before=await unchanged(),proof=await deriveDiagnosticPolicyEvidence({db},request);assert.equal(classifyDiagnosticResponsibility(proof).responsibility,'expected_policy_denial');assert.ok(proof?.evidenceIds?.includes(closed.closureId));
   assert.equal(await deriveDiagnosticPolicyEvidence({db},{...request,errorCode:'TASK_DEADLINE'}),undefined);assert.equal(await unchanged(),before);
   assert.equal(await deriveDiagnosticPolicyEvidence({db},{...request,arguments:{...arguments_,taskIndex:11}}),undefined);
  });
  await t.test('actual elapsed database deadline with committed cutoff is policy evidence; an open task is not',async()=>{
   const expired=await addFixture(client,{actionOpen:true,includeEvaluation:false,fence:false,overallDeadlinePast:true}),owned=await binding(expired),arguments_={runId:expired.runId,taskIndex:0,operationId:'policy_evidence_actual_deadline',command:{kind:'inspect_catalog'}};
   const request={principal:owned.principal,caseId:owned.caseId,tool:'runs.task_action',errorCode:'TASK_DEADLINE',arguments:arguments_};
   assert.equal(await deriveDiagnosticPolicyEvidence({db},request),undefined);
   const response=await admitTaskAction({db},owned.actor,arguments_);assert.equal(response.admitted,false);
   const before=await unchanged();assert.equal(classifyDiagnosticResponsibility(await deriveDiagnosticPolicyEvidence({db},request)).responsibility,'expected_policy_denial');assert.equal(await unchanged(),before);
  });
 }finally{await client.end();if(created)await admin.unsafe('DROP DATABASE '+name+' WITH (FORCE)');await admin.end();}
});
