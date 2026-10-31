import assert from 'node:assert/strict';
import test from 'node:test';
import { projectStoredTaskFeedback, getOwnerRunFeedback, type TaskFeedbackRow } from './task-feedback.js';
import { sha256CanonicalTaskJson } from './task-release.js';
import { TASK_IDS } from './task-catalog.js';
import type { OwnerDatabase } from './db.js';

function row(taskId: (typeof TASK_IDS)[number], evaluated: boolean): TaskFeedbackRow {
  const result={taskId,status:'known',outcome:'failed',credit:{numerator:'0',denominator:'1'},mandatoryViolation:null,unknownReasons:[],operatingExpenseUsdcUnits:null};
  return { task_id:taskId,task_status:evaluated?'failed':'queued',closure_reason:evaluated?'agent_finish':null,
    accepted_action_sequence:'0',reconciled_action_sequence:'0',result_json:evaluated?result:null,
    result_hash:evaluated?sha256CanonicalTaskJson(result):null };
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
