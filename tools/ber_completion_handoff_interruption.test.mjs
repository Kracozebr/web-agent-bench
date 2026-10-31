import assert from 'node:assert/strict';
import test from 'node:test';
import {createHash} from 'node:crypto';
import {armBerCompletionHandoffInterruption,isBerUncommittedRankedHandoff} from './ber_completion_handoff_interruption.mjs';
const hash=v=>createHash('sha256').update(JSON.stringify(Object.fromEntries(Object.entries(v).sort(([a],[b])=>a.localeCompare(b))))).digest('hex');
function admission(){
 const run={id:'11111111-1111-4111-8111-111111111111',owner_id:'22222222-2222-4222-8222-222222222222',agent_id:'33333333-3333-4333-8333-333333333333',mode:'ranked',started_at:'2026-10-31T08:00:01.000Z'};
 const snapshot={schemaVersion:'ranked-agent-version-snapshot/v1',runId:run.id,ownerId:run.owner_id,agentId:run.agent_id,profileRevision:1,name:'fixture',declaredVersion:null};
 return{rows:{run:[run],versions:[{run_id:run.id,owner_id:run.owner_id,agent_id:run.agent_id,snapshot_hash:hash(snapshot),snapshot_json:snapshot,created_at:'2026-10-31T08:00:00.000Z'}],handoffs:[],results:[]}};
}
test('first owed handoff preserves the single snapshot committed at admission',()=>{
 const state=admission(),runId=state.rows.run[0].id,original=structuredClone(state.rows.versions);
 assert.equal(isBerUncommittedRankedHandoff(state,runId,original),true);
 for(const versions of [[],[...original,...original]])assert.equal(isBerUncommittedRankedHandoff({...state,rows:{...state.rows,versions}},runId,original),false);
});
test('first owed handoff rejects changed or foreign admission snapshots even with recomputed hash',()=>{
 const state=admission(),runId=state.rows.run[0].id,original=structuredClone(state.rows.versions);
 for(const change of ['foreign_binding','changed_version','late_origin','committed_handoff']){
  const copy=structuredClone(state),v=copy.rows.versions[0];
  if(change==='foreign_binding'){v.snapshot_json.agentId='44444444-4444-4444-8444-444444444444';v.snapshot_hash=hash(v.snapshot_json);}
  if(change==='changed_version'){v.snapshot_json.profileRevision=2;v.snapshot_hash=hash(v.snapshot_json);}
  if(change==='late_origin')v.created_at='2026-10-31T08:00:02.000Z';
  if(change==='committed_handoff')copy.rows.handoffs=[{run_id:runId}];
  assert.equal(isBerUncommittedRankedHandoff(copy,runId,original),false,change);
 }
});
test('first handoff gate cannot lock or stop a retained Google database',async()=>{
 let calls=0;const forbidden=async()=>{calls++;throw Error('must_not_run');};
 await assert.rejects(armBerCompletionHandoffInterruption({runId:'11111111-1111-4111-8111-111111111111',commonCapture:{
  databaseUrl:'postgres://oid_owner@postgres/oid_google_local_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
  observerDatabaseUrl:'postgres://oid_observer@postgres/oid_google_local_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
  repoRoot:'/must-not-touch-original',stopApi:forbidden,restartApi:forbidden}}),e=>e?.code==='ERR_ASSERTION');
 assert.equal(calls,0);
});
test('first handoff gate requires matching isolated owner and read-only observer identities',async()=>{
 await assert.rejects(armBerCompletionHandoffInterruption({runId:'11111111-1111-4111-8111-111111111111',commonCapture:{
  databaseUrl:'postgres://oid_owner@postgres/oid_acceptance_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
  observerDatabaseUrl:'postgres://oid_observer@postgres/oid_acceptance_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'}}),e=>e?.code==='ERR_ASSERTION');
});
