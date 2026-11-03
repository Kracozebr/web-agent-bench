import assert from 'node:assert/strict';
import test from 'node:test';
import {createHash} from 'node:crypto';
import {runBerCompletedCallbacks,selectCompletedReceiptReplay,verifyCompletedReceiptReplay} from './ber_completed_callbacks.mjs';

const valid={databaseUrl:'postgres://oid_owner@postgres/oid_acceptance_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
 observerDatabaseUrl:'postgres://oid_observer@postgres/oid_acceptance_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
 repoRoot:'/must-not-read-original-data',runId:'11111111-1111-4111-8111-111111111111',
 ownerId:'22222222-2222-4222-8222-222222222222',agentId:'33333333-3333-4333-8333-333333333333'};

for(const[name,patch]of[
 ['original Google database',{databaseUrl:'postgres://oid_owner@postgres/oid_google_local_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',observerDatabaseUrl:'postgres://oid_observer@postgres/oid_google_local_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'}],
 ['unrelated owner database',{databaseUrl:'postgres://oid_owner@postgres/owner_identity',observerDatabaseUrl:'postgres://oid_observer@postgres/owner_identity'}],
 ['observer bound to another database',{observerDatabaseUrl:'postgres://oid_observer@postgres/oid_acceptance_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'}],
 ['unexpected write role',{databaseUrl:'postgres://superuser@postgres/oid_acceptance_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'}],
 ['unexpected network host',{databaseUrl:'postgres://oid_owner@example.com/oid_acceptance_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'}],
])test('callback probes reject '+name+' before filesystem or database access',async()=>{
 await assert.rejects(runBerCompletedCallbacks({...valid,...patch}),error=>error?.code==='ERR_ASSERTION');
});

function fixture(){
 const action={id:'44444444-4444-4444-8444-444444444444',run_id:valid.runId,owner_id:valid.ownerId,agent_id:valid.agentId,task_index:0,action_sequence:'1'};
 const receipt={action_id:action.id,receipt_revision:2,receipt_status:'observed',evidence_hash:'a'.repeat(64),evidence_path:'artifacts/runs/original.json',transaction_hash:'0x'+'b'.repeat(64),tool_response_json:{status:'observed'},tool_response_hash:createHash('sha256').update('{"status":"observed"}').digest('hex')};
 return{actions:[action],receipts:[receipt],reconciliations:[{...receipt,revision:2}],tasks:[{run_id:valid.runId,task_index:0,closure_status:'closed',action_cutoff_sequence:'1',reconciled_action_sequence:'1'}]};
}
test('duplicate reconciliation preserves all original receipt fields and original revision',()=>{
 const rows=fixture(),original=structuredClone(rows),proof=selectCompletedReceiptReplay(rows,valid);
 assert.deepEqual(proof.request,{actionId:rows.actions[0].id,status:'observed',evidenceHash:'a'.repeat(64),evidencePath:'artifacts/runs/original.json',transactionHash:'0x'+'b'.repeat(64),toolResponse:{status:'observed'}});
 verifyCompletedReceiptReplay({...proof.expected},null,proof.expected);assert.equal(proof.expected.receiptRevision,2);assert.deepEqual(rows,original);
 proof.request.toolResponse.status='changed';assert.deepEqual(rows,original);
});
test('original absent optional fields remain omitted, not invented',()=>{
 const rows=fixture();for(const key of ['evidence_path','transaction_hash','tool_response_json','tool_response_hash']){rows.receipts[0][key]=null;rows.reconciliations[0][key]=null;}
 assert.deepEqual(Object.keys(selectCompletedReceiptReplay(rows,valid).request),['actionId','status','evidenceHash']);
});
for(const[name,mutate]of[
 ['foreign action',r=>r.actions[0].agent_id=valid.ownerId],
 ['conflicting latest history',r=>r.reconciliations[0].transaction_hash='0x'+'c'.repeat(64)],
 ['missing history',r=>r.reconciliations=[]],
 ['response hash corruption',r=>r.receipts[0].tool_response_json.status='changed'],
 ['beyond original cutoff',r=>r.tasks[0].action_cutoff_sequence='0'],
 ['unclosed task',r=>r.tasks[0].closure_status='closing'],
])test('original receipt selector rejects '+name,()=>{const rows=fixture();mutate(rows);assert.throws(()=>selectCompletedReceiptReplay(rows,valid));});
for(const[name,patch]of[['new revision',{receiptRevision:3}],['non replay',{replayed:false}],['changed status',{receiptStatus:'unknown'}],['changed action',{actionId:valid.runId}]])
 test('receipt replay verifier rejects '+name,()=>{const {expected}=selectCompletedReceiptReplay(fixture(),valid);assert.throws(()=>verifyCompletedReceiptReplay({...expected,...patch},null,expected));});
