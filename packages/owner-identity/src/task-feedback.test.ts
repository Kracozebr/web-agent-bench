import assert from 'node:assert/strict';
import test from 'node:test';
import { projectStoredTaskFeedback, getOwnerRunFeedback, type TaskFeedbackRow } from './task-feedback.js';
import { sha256CanonicalTaskJson } from './task-release.js';
import { TASK_IDS } from './task-catalog.js';
import type { EvaluateTaskInput } from './task-evaluator.js';
import type { OwnerDatabase } from './db.js';

function row(taskId: (typeof TASK_IDS)[number], evaluated: boolean): TaskFeedbackRow {
  const result={taskId,status:'known',outcome:'failed',credit:{numerator:'0',denominator:'1'},mandatoryViolation:null,unknownReasons:[],operatingExpenseUsdcUnits:null};
  return { task_index:TASK_IDS.indexOf(taskId),task_id:taskId,task_status:evaluated?'failed':'queued',
    closure_id:evaluated?'00000000-0000-4000-8000-000000000101':null,closure_reason:evaluated?'agent_finish':null,
    accepted_action_sequence:'0',reconciled_action_sequence:'0',result_json:evaluated?result:null,
    result_hash:evaluated?sha256CanonicalTaskJson(result):null };
}

function retainedS2Input() {
  const binding={ownerId:'00000000-0000-4000-8000-000000000001',agentId:'00000000-0000-4000-8000-000000000002',
    runId:'00000000-0000-4000-8000-000000000003',environmentId:'bef-test',releaseIdentity:'release-test',
    manifestHash:'a'.repeat(64),caseId:'s2-case',caseHash:'b'.repeat(64),rubricHash:'c'.repeat(64),taskId:'S2' as const};
  const capture={path:'artifacts/runs/owner-identity-bef-task-coordinator/observation/s2-answer.json',sha256:'d'.repeat(64),
    boundary:'actual_tool_http_x402_local_evm_application_store' as const};
  const answer={amountUnits:'100000',network:'eip155:8453',assetId:'USDC',authFields:[{name:'scheme',value:'exact'}]};
  const run={...binding,acceptedActionCutoffSequence:2,reconciledThroughActionSequence:2,observationCutoffSequence:2,
    cutoffStatus:'authoritative' as const,cutoffEvidence:capture};
  const input={taskCase:{taskId:'S2',caseId:binding.caseId,caseHash:binding.caseHash,rubricHash:binding.rubricHash} as never,
    release:{releaseIdentity:binding.releaseIdentity,manifestHash:binding.manifestHash,executionIdentity:{},
      costPolicy:{usdcAssetId:'USDC',ethValuation:{numerator:'1',denominator:'1'}}},run,
    observations:{schemaVersion:'bts-task-observations/v1',binding,coveredThroughSequence:2,captureEvidence:capture,coverage:{answers:'complete'},
      transfers:[],payments:[],stateMutations:[],finalStates:[],allowanceChanges:[],allowanceUses:[],
      answers:[{kind:'final_answer',observationId:'answer-old',sequence:1,actionSequence:1,source:'persisted_observer',binding,
        evidence:capture,answer:{offerId:'old'}} ,
      {kind:'final_answer',observationId:'answer-final',sequence:2,actionSequence:2,source:'persisted_observer',binding,
        evidence:capture,answer}],selections:[],deliveries:[],trades:[],conversions:[],expenses:[]}} as unknown as EvaluateTaskInput;
  return {input,answer,binding,closureId:'00000000-0000-4000-8000-000000000101'};
}

function responseDb(responses: unknown[][]): OwnerDatabase {
  let index=0;
  return {execute:async()=>responses[index++] ?? []} as unknown as OwnerDatabase;
}

function terminalS2Responses(input: EvaluateTaskInput, result: unknown, resultHash: string, inputHash: string | null) {
  return [[{mode:'ranked',status:'completed'}],
    [{task_index:TASK_IDS.indexOf('S2'),task_id:'S2',task_status:'completed',closure_id:'00000000-0000-4000-8000-000000000101',
      closure_reason:'agent_finish',accepted_action_sequence:'2',reconciled_action_sequence:'2',result_json:result,result_hash:resultHash}],
    ...(inputHash===null?[]:[[{closure_id:'00000000-0000-4000-8000-000000000101',input_hash:inputHash,input_json:input}]])];
}

test('eight grades plus four absent grades retain all task identities without inventing zeros',()=>{
  const tasks=TASK_IDS.map((id,i)=>projectStoredTaskFeedback(row(id,i<8)));
  assert.equal(tasks.filter(t=>t.diagnostic?.evaluationState==='evaluated').length,8);
  assert.equal(tasks.filter(t=>t.diagnostic?.evaluationState==='not_evaluated').length,4);
  for(const t of tasks.slice(8)){assert.equal(t.reason,'not_issued');assert.equal(t.outcome,'unknown');assert.equal(t.credit,null);assert.equal(t.diagnostic?.attribution,'unknown');}
  for(const t of tasks.slice(0,8)){assert.equal(t.outcome,'failed');assert.deepEqual(t.credit,{numerator:'0',denominator:'1'});assert.equal(t.diagnostic?.attribution,'unknown');}
});

test('ungraded active/closed task is not failed, and durable deadline does not attribute fault',()=>{
  const missing={...row('H1',false),task_status:'active',closure_reason:'task_deadline'};
  const ungraded=projectStoredTaskFeedback(missing);assert.equal(ungraded.reason,'not_evaluated');assert.equal(ungraded.credit,null);
  const expired=projectStoredTaskFeedback({...row('S2',true),closure_reason:'task_deadline'});
  assert.equal(expired.reason,'time_exhausted');assert.equal(expired.diagnostic?.attribution,'unknown');
  assert.doesNotMatch(JSON.stringify(expired),/caseHash|initialState|referencePath|expectedAnswer|observationId/);
});

test('corrupt grade hash remains rejected rather than regraded or disguised as an absent grade',()=>{
  assert.throws(()=>projectStoredTaskFeedback({...row('S2',true),result_hash:'0'.repeat(64)}),/hash mismatch/);
});

test('active Ranked remains withheld and foreign owner remains not found',async()=>{
  const active={execute:async()=>[{mode:'ranked',status:'running'}]} as unknown as OwnerDatabase;
  assert.deepEqual(await getOwnerRunFeedback(active,'owner','run'),{status:'withheld_until_run_termination',tasks:[]});
  const foreign={execute:async()=>[]} as unknown as OwnerDatabase;
  await assert.rejects(getOwnerRunFeedback(foreign,'owner','run'),/does not exist/);
});

test('terminal owner feedback exposes only the final S2 answer from the hash-verified retained input',async()=>{
  const {input,answer}=retainedS2Input();
  const result={taskId:'S2',status:'known',outcome:'partial',credit:{numerator:'2',denominator:'5'},
    mandatoryViolation:null,unknownReasons:[],operatingExpenseUsdcUnits:'0'};
  const responses=terminalS2Responses(input,result,sha256CanonicalTaskJson(result),sha256CanonicalTaskJson(input));
  const feedback=await getOwnerRunFeedback(responseDb(responses),'00000000-0000-4000-8000-000000000001',input.run.runId);
  assert.equal(feedback.status,'available');
  assert.deepEqual(feedback.tasks[0]!.submittedAnswer,answer);
  assert.equal(Object.hasOwn(feedback.tasks[0]!,'taskCase'),false);
  assert.equal(Object.hasOwn(feedback.tasks[0]!,'observations'),false);
  assert.equal(Object.hasOwn(feedback.tasks[0]!,'referenceAnswer'),false);
});

test('an unrelated malformed evidence domain does not hide the hash-verified submitted S2 answer',async()=>{
  const {input,answer}=retainedS2Input();
  (input.observations as unknown as {transfers: unknown[]}).transfers=[{kind:'transfer',evidence:{invalid:true}}];
  const result={taskId:'S2',status:'unknown',outcome:'unknown',credit:null,
    mandatoryViolation:null,unknownReasons:['invalid_or_foreign_transfers_evidence'],operatingExpenseUsdcUnits:null};
  const responses=terminalS2Responses(input,result,sha256CanonicalTaskJson(result),sha256CanonicalTaskJson(input));
  const feedback=await getOwnerRunFeedback(responseDb(responses),'00000000-0000-4000-8000-000000000001',input.run.runId);
  assert.equal(feedback.tasks[0]!.status,'unknown');
  assert.deepEqual(feedback.tasks[0]!.submittedAnswer,answer);
});

test('missing, corrupt, or differently closed evaluation input never leaks an S2 answer',async()=>{
  const {input}=retainedS2Input();
  const result={taskId:'S2',status:'known',outcome:'partial',credit:{numerator:'2',denominator:'5'},
    mandatoryViolation:null,unknownReasons:[],operatingExpenseUsdcUnits:'0'};
  for(const inputHash of [null,'0'.repeat(64)]){
    const feedback=await getOwnerRunFeedback(responseDb(terminalS2Responses(input,result,sha256CanonicalTaskJson(result),inputHash)),
      '00000000-0000-4000-8000-000000000001',input.run.runId);
    assert.equal(Object.hasOwn(feedback.tasks[0]!,'submittedAnswer'),false);
  }
  const mismatchedClosure=terminalS2Responses(input,result,sha256CanonicalTaskJson(result),sha256CanonicalTaskJson(input));
  (mismatchedClosure[2]![0] as { closure_id: string }).closure_id='00000000-0000-4000-8000-000000000102';
  const feedback=await getOwnerRunFeedback(responseDb(mismatchedClosure),
    '00000000-0000-4000-8000-000000000001',input.run.runId);
  assert.equal(Object.hasOwn(feedback.tasks[0]!,'submittedAnswer'),false);
});
