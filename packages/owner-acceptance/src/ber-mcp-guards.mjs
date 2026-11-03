/** Finite reference-SDK guard controls. Denial records are not independent no-effect proof. */
import {randomUUID,createHash} from 'node:crypto';
export const FLAG='--ber-mcp-guards-training';
export const PROFILE='MCP_GUARDS';
const TASKS=['S1','M1','H1'];
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;
const need=(value,code)=>{if(!value)throw Object.assign(new Error(code),{code});};
const digest=value=>createHash('sha256').update(JSON.stringify(value)).digest('hex');
function scope(taskIds,task,state){
 need(JSON.stringify(taskIds)===JSON.stringify(TASKS)&&task?.mode==='training'&&TASKS[task.taskIndex]===task.taskId&&UUID.test(task.runId??''),'BER_GUARDS_EXACT_TRAINING_REQUIRED');
 need(!state.runId||state.runId===task.runId,'BER_GUARDS_RUN_CHANGED');state.runId=task.runId;
}
export async function executeMcpGuardTask({taskIds,task,state,callExpected,call,admitAndObserve,selectOffer,verifyOffer,verifyRetrieval,proof,callIndex}){
 scope(taskIds,task,state);need(!state.tasks?.includes(task.taskIndex),'BER_GUARDS_TASK_REPLAY_FORBIDDEN');state.tasks??=[];state.tasks.push(task.taskIndex);
 proof.schemaVersion='ber-controlled-mcp-guards-task/v1';proof.denials=[];proof.repeats=[];proof.positiveCoverageCredit=false;
 const deny=async(variant,command,expectedCode)=>{
  const args={runId:task.runId,taskIndex:task.taskIndex,operationId:randomUUID(),command};
  const body=await callExpected('runs.task_action',args,{expectedCode});
  need(body?.error?.code===expectedCode&&!body.admitted&&!body.actionId,'BER_GUARDS_DENIAL_MISMATCH');
  proof.denials.push({variant,tool:'runs.task_action',arguments:args,expectedCode,actualCode:body.error.code,bodySha256:digest(body),callIndex:callIndex()});
 };
 if(task.taskId==='M1'){
  need(state.s1?.runId===task.runId&&UUID.test(state.s1.offerReadActionId)&&UUID.test(state.s1.payActionId),'BER_GUARDS_PRIOR_REAL_REFS_REQUIRED');
  proof.foreignTaskRefs={...state.s1};
  await deny('foreign_task_offer_read',{kind:'pay',resourceId:state.s1.resourceId,offerId:state.s1.offerId,offerReadActionId:state.s1.offerReadActionId},'TASK_PAYMENT_REFERENCE_UNAVAILABLE');
  await deny('foreign_task_payment',{kind:'retrieve',payActionId:state.s1.payActionId},'TASK_PAYMENT_REFERENCE_UNAVAILABLE');
 }
 const catalog=await admitAndObserve({kind:'inspect_catalog'}),offer=selectOffer(catalog.toolResponse);
 if(task.taskId==='S1'){
  await deny('protocol_disabled_purchase',{kind:'purchase',resourceId:offer.resourceId,offerId:offer.offerId},'COMBINED_PURCHASE_UNAVAILABLE');
  await deny('fabricated_offer_read',{kind:'pay',resourceId:offer.resourceId,offerId:offer.offerId,offerReadActionId:randomUUID()},'TASK_PAYMENT_REFERENCE_UNAVAILABLE');
  await deny('fabricated_payment',{kind:'retrieve',payActionId:randomUUID()},'TASK_PAYMENT_REFERENCE_UNAVAILABLE');
 }
 const inspected=await admitAndObserve({kind:'inspect_offer',resourceId:offer.resourceId,offerId:offer.offerId});verifyOffer(offer,inspected.toolResponse);
 const paid=await admitAndObserve({kind:'pay',resourceId:offer.resourceId,offerId:offer.offerId,offerReadActionId:inspected.actionId});
 need(paid.status==='observed'&&paid.toolResponse?.status==='payment_confirmed'&&paid.toolResponse.payment?.receiptStatus==='success'&&/^0x[a-f0-9]{64}$/i.test(paid.transactionHash??''),'BER_GUARDS_PAYMENT_NOT_OBSERVED');
 proof.originalRefs={runId:task.runId,offerReadActionId:inspected.actionId,payActionId:paid.actionId,resourceId:offer.resourceId,offerId:offer.offerId};
 if(task.taskId==='S1')state.s1={...proof.originalRefs};
 const repeatArgs={runId:task.runId,actionId:paid.actionId},repeat=await call('runs.task_action_status',repeatArgs);
 for(const key of ['actionId','runId','status','transactionHash','receiptRevision','evidencePath','evidenceHash'])need(repeat[key]===paid[key],'BER_GUARDS_STATUS_IDENTITY_CHANGED');
 proof.repeats.push({variant:'same_original_payment_status',tool:'runs.task_action_status',arguments:repeatArgs,bodySha256:digest(repeat),callIndex:callIndex()});
 const delivered=await admitAndObserve({kind:'retrieve',payActionId:paid.actionId});proof.retrieval=verifyRetrieval(offer,delivered.toolResponse);
 proof.selection={resourceId:offer.resourceId,offerId:offer.offerId,resourceSha256:offer.resourceSha256,payment:offer.payment};
}
export async function repeatMcpGuardFinish({taskIds,task,state,proof,finishArgs,finished,call,callExpected,callIndex}){
 scope(taskIds,task,state);need(finishArgs.runId===task.runId&&finishArgs.taskIndex===task.taskIndex&&UUID.test(finishArgs.operationId??'')&&UUID.test(finished.closureId??'')&&finished.reason==='agent_finish','BER_GUARDS_FINISH_IDENTITY_INVALID');
 const replay=await call('runs.finish_task',finishArgs,{afterCutoff:true});
 need(replay.closureId===finished.closureId&&replay.runId===task.runId&&replay.taskIndex===task.taskIndex&&replay.reason==='agent_finish'&&replay.replayed===true,'BER_GUARDS_FINISH_REPLAY_CHANGED');
 proof.repeats.push({variant:'same_original_finish',tool:'runs.finish_task',arguments:structuredClone(finishArgs),bodySha256:digest(replay),closureId:replay.closureId,callIndex:callIndex()});
 const args={runId:task.runId,taskIndex:task.taskIndex,operationId:randomUUID(),command:{kind:'inspect_catalog'}};
 const denied=await callExpected('runs.task_action',args,{expectedCode:'TASK_CLOSED',afterCutoff:true});
 need(denied?.error?.code==='TASK_CLOSED'&&!denied.admitted&&!denied.actionId,'BER_GUARDS_POSTCLOSURE_ADMITTED');
 proof.denials.push({variant:'after_closure_new_action_not_deadline_test',tool:'runs.task_action',arguments:args,expectedCode:'TASK_CLOSED',actualCode:denied.error.code,bodySha256:digest(denied),callIndex:callIndex()});
}
