import assert from 'node:assert/strict';
import test from 'node:test';
import { getTaskExecutionContext,assertTaskExecutionBinding } from './task-execution-binding.js';

const runId='21234567-89ab-4cde-8fab-0123456789ab',generationId='31234567-89ab-4cde-8fab-0123456789ab';
const actionId='71234567-89ab-4cde-8fab-0123456789ab',envId='admitted-drain-env';
const claimId='61234567-89ab-4cde-8fab-0123456789ab';
const input={runId,taskIndex:0,envId,generationId,manifestHash:'d'.repeat(64),applicationSourceHash:'e'.repeat(64)};
function context(patch:Record<string,unknown>={}) {
 return {run_id:runId,run_status:'running',mode:'training',task_ids:['H1'],release_identity:'drain-release',
  run_manifest_hash:'a'.repeat(64),run_live:true,task_index:0,task_id:'H1',task_status:'active',
  closure_status:'open',task_live:true,active_task_count:1,
  preparation_id:'41234567-89ab-4cde-8fab-0123456789ab',lease_id:'51234567-89ab-4cde-8fab-0123456789ab',
  preparation_claim_id:claimId,preparation_environment_id:envId,preparation_release_identity:'drain-release',
  preparation_manifest_hash:'a'.repeat(64),preparation_task_id:'H1',case_id:'drain-case',case_hash:'b'.repeat(64),
  initial_state_sha256:'c'.repeat(64),execution_identity_hash:'f'.repeat(64),
  environment_manifest_sha256:input.manifestHash,application_source_hash:input.applicationSourceHash,
  lease_state:'leased',observation_status:'ready',observation_generation_id:generationId,
  baseline_state_sha256:'c'.repeat(64),fixture_evidence:{},baseline_evidence:{},
  observation_participant_id:null,observation_payer_address:null,registered_generation_id:generationId,
  generation_environment_id:envId,binding_environment_id:envId,binding_generation_id:generationId,
  binding_manifest_hash:input.manifestHash,binding_application_source_hash:input.applicationSourceHash,
  binding_participant_id:null,binding_payer_address:null,run_claim_id:claimId,claim_status:'claimed',
  slot_claim_id:claimId,slot_state:'running',admitted_action_valid:true,...patch};
}
function reader(row:ReturnType<typeof context>) {return {async execute(){return [row];}};}

test('admitted H1 drain keeps its exact execution binding after cutoff without reopening admission',async()=>{
 const row=context({run_live:false,task_live:false,closure_status:'closing'});
 assert.equal(await getTaskExecutionContext(reader(row),{runId,taskIndex:0}),null);
 const drained=await getTaskExecutionContext(reader(row),{runId,taskIndex:0},{admittedActionId:actionId});
 assert.equal(drained?.generationId,generationId);
 assert.equal(drained?.closureStatus,'closing');
 const binding={run_id:runId,task_index:0,env_id:envId,generation_id:generationId,
  manifest_hash:input.manifestHash,application_source_hash:input.applicationSourceHash,
  participant_id:null,payer_address:null,created_at:new Date('2026-10-30T00:00:00Z')};
 const queue=[binding,row];
 const actual=await assertTaskExecutionBinding({async execute(){return [queue.shift()];}},input,{admittedActionId:actionId});
 assert.equal(actual.generationId,generationId);
});

test('admitted drain never substitutes for valid original action, leased generation or owner run authority',async()=>{
 for(const patch of [{admitted_action_valid:false},{closure_status:'closed'},{closure_status:'unknown'},
  {run_status:'cancelled'},{task_status:'completed'},{lease_state:'fenced'},{observation_status:'fenced'},
  {active_task_count:2},{claim_status:'released'},{slot_state:'preparing'},
  {slot_claim_id:'81234567-89ab-4cde-8fab-0123456789ab'},
  {binding_generation_id:'81234567-89ab-4cde-8fab-0123456789ab'}]) {
  assert.equal(await getTaskExecutionContext(reader(context({task_live:false,closure_status:'closing',...patch})),
   {runId,taskIndex:0},{admittedActionId:actionId}),null);
 }
 await assert.rejects(getTaskExecutionContext(reader(context()),{runId,taskIndex:0},{admittedActionId:'foreign-not-uuid'}),/action UUID/);
 await assert.rejects(getTaskExecutionContext(reader(context()),{runId,taskIndex:0},{requireActive:false,admittedActionId:actionId}),/active task/);
});
