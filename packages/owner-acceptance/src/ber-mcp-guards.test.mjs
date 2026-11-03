import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {executeMcpGuardTask,repeatMcpGuardFinish,FLAG,PROFILE} from './ber-mcp-guards.mjs';
const task=()=>({runId:randomUUID(),taskIndex:0,taskId:'S1',mode:'training'});
test('guard module has one finite training flag and rejects arbitrary selection/run before any transport',async()=>{
 assert.equal(FLAG,'--ber-mcp-guards-training');assert.equal(PROFILE,'MCP_GUARDS');
 for(const edit of [i=>{i.taskIds=['S1'];},i=>{i.task.mode='ranked';},i=>{i.state.runId=randomUUID();},i=>{i.task.taskId='M1';}]){
  let calls=0;const input={taskIds:['S1','M1','H1'],task:task(),state:{},proof:{},callExpected:async()=>{calls++;},admitAndObserve:async()=>{calls++;}};edit(input);await assert.rejects(executeMcpGuardTask(input));assert.equal(calls,0);
 }
});
test('foreign-task guard requires actual prior same-run IDs, never seeds references or admits a replacement payment',async()=>{
 for(const state of [{},{s1:{runId:randomUUID(),offerReadActionId:randomUUID(),payActionId:randomUUID()}},{s1:{offerReadActionId:'not-a-uuid',payActionId:randomUUID()}}]){
  let calls=0;const t={...task(),taskIndex:1,taskId:'M1'};await assert.rejects(executeMcpGuardTask({taskIds:['S1','M1','H1'],task:t,state,proof:{},callExpected:async()=>{calls++;},admitAndObserve:async()=>{calls++;}}),/BER_GUARDS_PRIOR_REAL_REFS_REQUIRED/);assert.equal(calls,0);
 }
});
test('finish replay preserves original arguments and refuses changed closure, scope, nonreplay and accidental postclosure admission',async()=>{
 for(const variant of ['positive','foreign_closure','foreign_run','not_replayed','postclosure_admitted']){
  const t=task(),operationId=randomUUID(),closureId=randomUUID(),args={runId:t.runId,taskIndex:0,operationId},calls=[],proof={repeats:[],denials:[]};
  const promise=repeatMcpGuardFinish({taskIds:['S1','M1','H1'],task:t,state:{},proof,finishArgs:args,finished:{closureId,reason:'agent_finish'},callIndex:()=>calls.length-1,
   async call(tool,a){calls.push({tool,args:a});return{runId:variant==='foreign_run'?randomUUID():t.runId,taskIndex:0,reason:'agent_finish',closureId:variant==='foreign_closure'?randomUUID():closureId,replayed:variant!=='not_replayed'};},
   async callExpected(tool,a){calls.push({tool,args:a});return variant==='postclosure_admitted'?{admitted:true,actionId:randomUUID()}:{error:{code:'TASK_CLOSED'}};}});
  if(variant==='positive'){await promise;assert.deepEqual(calls[0].args,args);assert.equal(proof.repeats[0].arguments.operationId,operationId);assert.equal(proof.denials[0].variant,'after_closure_new_action_not_deadline_test');assert.equal(proof.denials[0].callIndex,1);}
  else await assert.rejects(promise,/BER_GUARDS_(FINISH_REPLAY_CHANGED|POSTCLOSURE_ADMITTED)/);
  assert.equal(calls.filter(c=>c.tool==='runs.finish_task').length,1);
 }
});
