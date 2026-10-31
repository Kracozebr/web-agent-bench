import assert from 'node:assert/strict';
import test from 'node:test';
import {randomUUID} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import postgres from 'postgres';
import {drizzle} from 'drizzle-orm/postgres-js';
import type {OwnerDatabase} from './db.js';
import type {AgentPrincipal} from './agents.js';
import type {TaskReleaseQuerySource} from './task-release.js';
import {getCurrentAgentTask} from './task-issuance.js';
import {addFixture} from './task-run-completion.test-fixture.js';

// AICODE-NOTE: Synthetic isolated PostgreSQL projection/auth tests, not physical
// execution evidence. Real browser/MCP/worker qualification is recorded separately.
test('current_task exposes authoritative run progress without disclosing a queued/closed case or changing business rows',
  {skip:process.env.OID_TASK_ISSUANCE_PG_TEST!=='1'}, async t=>{
    const source=process.env.OID_DATABASE_URL;assert.ok(source);
    const sourceUrl=new URL(source);assert.equal(sourceUrl.hostname,'postgres');assert.equal(sourceUrl.username,'oid_owner');assert.equal(sourceUrl.pathname,'/owner_identity');
    const name='oid_issuance_'+randomUUID().replaceAll('-','');assert.match(name,/^oid_issuance_[a-f0-9]{32}$/);
    const url=new URL(source);url.pathname='/'+name;
    const admin=postgres(source,{max:1,connect_timeout:10});
    const client=postgres(url.href,{max:3,connect_timeout:10});const db=drizzle(client) as unknown as OwnerDatabase;
    let created=false;
    try{
      await admin.unsafe('CREATE DATABASE '+name);created=true;
      const migration=spawnSync('pnpm',['--filter','@web-agent-bench/owner-identity','migrate'],{cwd:'/workspace',env:{...process.env,OID_DATABASE_URL:url.href},encoding:'utf8'});
      assert.equal(migration.status,0,'isolated projection test schema migration');
      async function fixture(options:Parameters<typeof addFixture>[1]={}){
        const f=await addFixture(client,{includeEvaluation:false,fence:false,overallDeadlineSecondsFromNow:600,...options});
        const grantId=randomUUID(),resource='https://bench.example/api/agent/mcp';
        await client`INSERT INTO oid_agent_access_grant(id,owner_id,agent_id,operation_id,resource,role,access_generation,expires_at)
          VALUES(${grantId},${f.ownerId},${f.agentId},${randomUUID()},${resource},'agent',1,clock_timestamp()+interval '1 hour')`;
        const principal:AgentPrincipal={ownerId:f.ownerId,agentId:f.agentId,grantId,credentialId:randomUUID(),resource,role:'agent',accessGeneration:1,accessRevision:1,policyRevision:1,
          permissions:{training:true,ranked:false,forumMessages:false,customTopics:false}};
        const record={...f.record,manifest:{...f.record.manifest,
          executionIdentity:{...f.record.manifest.executionIdentity,localChainId:31337,localNetwork:'synthetic',assets:[],contracts:[]},
          cases:{...f.record.manifest.cases,training:f.record.manifest.cases.training.map(row=>({...row,mandatoryRules:[]}))}}};
        const source:TaskReleaseQuerySource={async getActiveAdmissionRelease(){return null;},async getValidatedReleaseRecord(){return record as never;}};
        return {...f,principal,source};
      }
      const tables=['oid_owner','oid_agent','oid_agent_access_grant','oid_agent_policy','oid_benchmark_run','oid_run_task','oid_run_task_evaluation','oid_run_task_closure','oid_run_task_action','oid_run_task_action_receipt','oid_run_task_action_outbox','oid_ledger_entry','oid_ledger_operation','oid_run_reservation','oid_run_event'];
      async function fingerprint(){const rows=[];for(const table of tables){assert.match(table,/^oid_[a-z_]+$/);rows.push((await client.unsafe(`SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text),'[]'::jsonb) AS rows FROM ${table} t`))[0]!.rows);}return JSON.stringify(rows);}
      async function readUnchanged(f:Awaited<ReturnType<typeof fixture>>){const before=await fingerprint();const response=await getCurrentAgentTask({db,taskReleaseSource:f.source},f.principal,f.runId);assert.equal(await fingerprint(),before,'a progress read must not dispatch, grade, refund or rewrite task history');return response;}
      await t.test('null during grading is nonterminal; the same case stays hidden until a real terminal run',async()=>{
        const f=await fixture({multiTask:true});
        let value=await readUnchanged(f);assert.equal(value.task,null);assert.equal(value.state,'evaluating_task');assert.equal(value.run.status,'running');assert.equal(value.run.terminal,false);assert.equal(value.retryAfterMs,1000);
        assert.equal(JSON.stringify(value).includes('caseHash'),false);assert.equal(JSON.stringify(value).includes('conditions'),false);
        await client`UPDATE oid_benchmark_run SET status='cancelled',terminal_reason='coordinator_evaluation_unknown',cancellation_reason='coordinator_evaluation_unknown',finished_at=clock_timestamp() WHERE id=${f.runId}`;
        value=await readUnchanged(f);assert.equal(value.state,'terminal');assert.equal(value.run.terminal,true);assert.equal(value.run.status,'cancelled');assert.equal(value.run.terminalReason,'coordinator_evaluation_unknown');assert.equal(value.run.cancellationReason,'coordinator_evaluation_unknown');assert.equal(value.retryAfterMs,null);assert.equal(value.task,null);
      });
      await t.test('queue, initial preparation and cancellation waits expose no task and keep a bounded poll hint',async()=>{
        const f=await fixture();for(const [status,state]of [['queued','waiting_queue'],['preparing','preparing_task'],['cancellation_requested','cancelling_run']] as const){
          await client`UPDATE oid_benchmark_run SET status=${status} WHERE id=${f.runId}`;const value=await readUnchanged(f);assert.equal(value.state,state);assert.equal(value.run.status,status);assert.equal(value.run.terminal,false);assert.equal(value.task,null);assert.equal(value.retryAfterMs,1000);
        }
      });
      await t.test('a closing cutoff and expired open task are reconciliation waits, not terminal or issuable tasks',async()=>{
        const closing=await fixture({openCutoff:true});assert.equal((await readUnchanged(closing)).state,'reconciling_actions');
        const expired=await fixture({actionOpen:true});await client`UPDATE oid_run_task SET deadline_at=clock_timestamp()-interval '1 second' WHERE run_id=${expired.runId}`;
        const value=await readUnchanged(expired);assert.equal(value.state,'reconciling_actions');assert.equal(value.run.terminal,false);assert.equal(value.task,null);
      });
      await t.test('known evaluation before successor activation is a preparation wait; no remaining task means finalization wait',async()=>{
        const next=await fixture({multiTask:true,includeEvaluation:true});assert.equal((await readUnchanged(next)).state,'preparing_next_task');
        const final=await fixture({includeEvaluation:true});assert.equal((await readUnchanged(final)).state,'finalizing_run');
      });
      await t.test('overall deadline does not fabricate a committed terminal status',async()=>{
        const f=await fixture({overallDeadlinePast:true});const value=await readUnchanged(f);assert.equal(value.state,'awaiting_terminal');assert.equal(value.run.status,'running');assert.equal(value.run.terminal,false);assert.equal(value.task,null);
      });
      await t.test('every existing terminal status stops polling without exposing the last or a future case',async()=>{
        const f=await fixture();for(const status of ['completed','cancelled','failed','expired','unknown','disqualified']){
          await client`UPDATE oid_benchmark_run SET status=${status},finished_at=clock_timestamp() WHERE id=${f.runId}`;const value=await readUnchanged(f);assert.equal(value.state,'terminal');assert.equal(value.run.terminal,true);assert.equal(value.task,null);assert.equal(value.retryAfterMs,null);
        }
      });
      await t.test('only one live/open bound case is issued with additive run metadata',async()=>{
        const f=await fixture({actionOpen:true});const value=await readUnchanged(f);assert.equal(value.state,'task_ready');assert.equal(value.run.status,'running');assert.equal(value.run.terminal,false);assert.equal(value.task?.taskId,'S1');assert.equal(value.task?.runId,f.runId);assert.equal(value.retryAfterMs,null);assert.equal(JSON.stringify(value).includes('referencePath'),false);
      });
      await t.test('grant expiry during release validation denies task and run metadata before disclosure',async()=>{
        const f=await fixture({actionOpen:true});
        await client`UPDATE oid_agent_access_grant SET expires_at=clock_timestamp()+interval '500 milliseconds' WHERE id=${f.principal.grantId}`;
        const original=f.source.getValidatedReleaseRecord;f.source={...f.source,async getValidatedReleaseRecord(...args){await new Promise(resolve=>setTimeout(resolve,750));return original(...args);}};
        await assert.rejects(readUnchanged(f),{code:'AGENT_ACCESS_REVOKED'});
      });
      await t.test('task expiry during release validation returns a reconciliation wait without a stale case',async()=>{
        const f=await fixture({actionOpen:true});
        await client`UPDATE oid_run_task SET deadline_at=clock_timestamp()+interval '500 milliseconds' WHERE run_id=${f.runId}`;
        const original=f.source.getValidatedReleaseRecord;f.source={...f.source,async getValidatedReleaseRecord(...args){await new Promise(resolve=>setTimeout(resolve,750));return original(...args);}};
        const value=await readUnchanged(f);assert.equal(value.task,null);assert.equal(value.run.terminal,false);assert.equal(value.state,'reconciling_actions');assert.equal(value.retryAfterMs,1000);
      });
      await t.test('foreign run/agent, stale generation, revoked/expired grant and disabled mode deny before any run projection',async()=>{
        const f=await fixture(),foreign=await fixture();const dependencies={db,taskReleaseSource:f.source};
        await assert.rejects(getCurrentAgentTask(dependencies,f.principal,foreign.runId),{code:'RUN_NOT_FOUND'});
        await assert.rejects(getCurrentAgentTask(dependencies,{...f.principal,agentId:foreign.agentId},f.runId),{code:'AGENT_ACCESS_REVOKED'});
        await assert.rejects(getCurrentAgentTask(dependencies,{...f.principal,accessGeneration:2},f.runId),{code:'AGENT_ACCESS_REVOKED'});
        await client`UPDATE oid_agent_access_grant SET revoked_at=clock_timestamp() WHERE id=${f.principal.grantId}`;
        await assert.rejects(getCurrentAgentTask(dependencies,f.principal,f.runId),{code:'AGENT_ACCESS_REVOKED'});
        await client`UPDATE oid_agent_access_grant SET revoked_at=NULL,expires_at=clock_timestamp()-interval '1 second' WHERE id=${f.principal.grantId}`;
        await assert.rejects(getCurrentAgentTask(dependencies,f.principal,f.runId),{code:'AGENT_ACCESS_REVOKED'});
        await client`UPDATE oid_agent_access_grant SET expires_at=clock_timestamp()+interval '1 hour' WHERE id=${f.principal.grantId}`;
        await client`UPDATE oid_agent_policy SET training=false WHERE agent_id=${f.agentId}`;
        await assert.rejects(getCurrentAgentTask(dependencies,f.principal,f.runId),{code:'MODE_NOT_ALLOWED'});
      });
    }finally{await client.end({timeout:5});if(created)await admin.unsafe('DROP DATABASE '+name+' WITH (FORCE)');await admin.end({timeout:5});}
  });
