import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {runBerMatrixOwnerCase} from './ber-matrix-cases.mjs';
function input(){return {mode:'training',berAdmittedMatrixProfile:'A',berAdmittedMatrixIsolated:true,automaticWorkerEvaluation:true,berMatrixCampaignId:randomUUID(),observerDatabaseUrl:'postgres://oid_observer:PRIVATE_TEST_CREDENTIAL@localhost/oid_acceptance_'+'a'.repeat(32)};}
test('wrapper preserves known failed task grade as completed run and leaves independent matrix acceptance incomplete',async()=>{
 const runId=randomUUID(),agentId=randomUUID();let selected;
 const result=await runBerMatrixOwnerCase(input(),{async runGenuineTrainingSequenceOwnerCase(options){selected=options;await options.onGenuineRunCompleted({runId,agentId,mode:'training',taskIds:options.taskIds,agentBearer:'NEVER_STORE_BEARER'});return {runId,runCompletion:{status:'verified'},status:'captured_training_run',taskEvaluations:[{taskId:'S1',result:{status:'known',outcome:'failed',credit:{numerator:'0',denominator:'1'}}}]};},async observeTerminal({runId,record}){record({body:{run:{runId,status:'completed',terminal:true}}});return {runId,status:'completed',terminal:true};}});
 assert.deepEqual(selected.taskIds,['S1','M1','H1']);assert.equal(result.status,'captured_training_run');assert.equal(result.taskEvaluations[0].result.outcome,'failed');assert.equal(result.berMatrixQualification.mainMatrixAcceptance,'incomplete');assert.equal(result.berMatrixQualification.independentProof.status,'not_run');assert(!JSON.stringify(result).includes('NEVER_STORE_BEARER'));assert(!JSON.stringify(result).includes('PRIVATE_TEST_CREDENTIAL'));
});
test('wrapper refuses subset, arbitrary profile, real database or unconfirmed terminal instead of a fake matrix pass',async()=>{
 for(const edit of [i=>{i.taskIds=['S1'];},i=>{i.berAdmittedMatrixProfile='custom';},i=>{i.observerDatabaseUrl='postgres://oid_observer:secret@localhost/original_google';},i=>{i.bddProbes=true;}]){const i=input();edit(i);await assert.rejects(runBerMatrixOwnerCase(i,{}));}
 const runId=randomUUID(),agentId=randomUUID(),result=await runBerMatrixOwnerCase(input(),{async runGenuineTrainingSequenceOwnerCase(i){await i.onGenuineRunCompleted({runId,agentId,mode:'training',taskIds:i.taskIds});return {runId,runCompletion:{status:'verified'}};},async observeTerminal(){return {runId,status:'running',terminal:false};}});assert.equal(result.status,'blocked');assert.equal(result.blocker.reasonCode,'ber_matrix_terminal_not_confirmed');
});

test('restored-history selector enters only full Ranked owner worker and leaves independent gates unclaimed',async()=>{
 const i={...input(),mode:'ranked',berAdmittedMatrixProfile:'S4_RESTORED_ALLOWANCE_HISTORY'},runId=randomUUID(),agentId=randomUUID();let selected;
 const result=await runBerMatrixOwnerCase(i,{async runGenuineRankedOwnerCase(options){selected=options;await options.onGenuineRunCompleted({runId,agentId,mode:'ranked',taskIds:options.taskIds});return {runId,runCompletion:{status:'verified'}};},async observeTerminal(){return {runId,status:'completed',terminal:true};}});
 assert.deepEqual(selected.taskIds,['S1','S2','S3','S4','M1','M2','M3','M4','H1','H2','H3','U1']);assert.equal(selected.berAdmittedMatrixProfile,'S4_RESTORED_ALLOWANCE_HISTORY');assert.equal(result.berMatrixQualification.independentProof.status,'not_run');
 await assert.rejects(runBerMatrixOwnerCase({...i,mode:'training'},{}));await assert.rejects(runBerMatrixOwnerCase({...i,taskIds:['S4']},{}));
});

test('finite negative and composite wrappers preserve complete task lists and explicitly assign no positive135 coverage credit',async()=>{
 for(const [profile,mode]of [['NOOP_REVERT_D','training'],['NOOP_REVERT_D','ranked'],['COMPOSITE_MIXED','ranked'],['NON_EOA_REJECTION','training'],['MCP_GUARDS','training']]){
  const i={...input(),mode,berAdmittedMatrixProfile:profile},runId=randomUUID(),agentId=randomUUID();let selected;
  const run=async options=>{selected=options;await options.onGenuineRunCompleted({runId,agentId,mode,taskIds:options.taskIds});return{runId,runCompletion:{status:'verified'}};};
  const result=await runBerMatrixOwnerCase(i,{runGenuineRankedOwnerCase:run,runGenuineTrainingSequenceOwnerCase:run,async observeTerminal(){return{runId,status:'completed',terminal:true};}});
  assert.equal(selected.taskIds.length,mode==='training'?3:12);assert.equal(result.berMatrixQualification.positiveCoverageCredit,false);assert.equal(result.berMatrixQualification.independentProof.status,'not_run');assert.equal(result.berMatrixQualification.mainMatrixAcceptance,'incomplete');
 }
 await assert.rejects(runBerMatrixOwnerCase({...input(),berAdmittedMatrixProfile:'NOOP_REVERT_D',taskIds:['S1']},{}));
 await assert.rejects(runBerMatrixOwnerCase({...input(),berAdmittedMatrixProfile:'COMPOSITE_MIXED'},{}));
 await assert.rejects(runBerMatrixOwnerCase({...input(),mode:'ranked',berAdmittedMatrixProfile:'NON_EOA_REJECTION'},{}));
 await assert.rejects(runBerMatrixOwnerCase({...input(),mode:'ranked',berAdmittedMatrixProfile:'MCP_GUARDS'},{}));
});
