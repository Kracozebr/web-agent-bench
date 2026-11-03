/** Controlled fixed reference-SDK matrix actor; never native acceptance or authoritative effect proof. */
import {createHash,randomUUID} from 'node:crypto';
import {createRequire} from 'node:module';
import {pathToFileURL} from 'node:url';
import {resolve} from 'node:path';
import {FLAG as S4_HISTORY_FLAG,PROFILE as S4_HISTORY_PROFILE,fixedHistoryTaskPlan,executeFixedS4RestoredHistory} from './ber-s4-restored-history.mjs';
import {FLAGS as NEGATIVE_FLAGS,PROFILE as NEGATIVE_PROFILE,executeFixedNoopRevert} from './ber-noop-revert.mjs';
import {FLAG as COMPOSITE_FLAG,PROFILE as COMPOSITE_PROFILE,fixedCompositeTaskPlan,executeFixedCompositeMixed} from './ber-composite-mixed.mjs';

import {FLAG as CONTRACT_REJECTION_FLAG,PROFILE as CONTRACT_REJECTION_PROFILE,contractRecipientTaskPlan,executeContractRecipientRejection,validateContractRecipientReceipt} from './ber-contract-recipient-rejection.mjs';
import {FLAG as GUARDS_FLAG,PROFILE as GUARDS_PROFILE,executeMcpGuardTask,repeatMcpGuardFinish} from './ber-mcp-guards.mjs';

export const TRAINING=Object.freeze(['S1','M1','H1']);
export const RANKED=Object.freeze(['S1','S2','S3','S4','M1','M2','M3','M4','H1','H2','H3','U1']);
export const MATRIX_PROFILES=Object.freeze({A:['inspect_catalog','inspect_offer','pay','retrieve'],B:['wrap','approve','swap','unwrap'],C:['inspect_catalog','wrap','approve','swap','transfer']});
const MATRIX_FLAGS=Object.freeze(Object.fromEntries(['training','ranked'].flatMap(mode=>['A','B','C'].map(profile=>[`--ber-admitted-matrix-${mode}-${profile.toLowerCase()}`,{mode,profile,taskIds:mode==='training'?TRAINING:RANKED}]))));
export function parseBerMatrixFlag(argumentsList){
 const candidates=argumentsList.filter(argument=>argument.startsWith('--ber-admitted-matrix-')||argument.startsWith('--ber-s4-restored-')||argument.startsWith('--ber-noop-revert-')||argument.startsWith('--ber-composite-mixed')||argument.startsWith('--ber-contract-recipient-rejection')||argument.startsWith('--ber-mcp-guards'));
 need(candidates.length<=1&&candidates.every(flag=>(Object.hasOwn(MATRIX_FLAGS,flag)||flag===S4_HISTORY_FLAG||Object.hasOwn(NEGATIVE_FLAGS,flag)||flag===COMPOSITE_FLAG||flag===CONTRACT_REJECTION_FLAG||flag===GUARDS_FLAG)),'ber_matrix_cli_profile_invalid');
 if(candidates[0]===GUARDS_FLAG)return {mode:'training',profile:GUARDS_PROFILE,taskIds:[...TRAINING]};
 if(candidates[0]===CONTRACT_REJECTION_FLAG)return {mode:'training',profile:CONTRACT_REJECTION_PROFILE,taskIds:[...TRAINING]};
 if(candidates[0]===COMPOSITE_FLAG)return {mode:'ranked',profile:COMPOSITE_PROFILE,taskIds:[...RANKED]};
 if(Object.hasOwn(NEGATIVE_FLAGS,candidates[0])){const mode=NEGATIVE_FLAGS[candidates[0]];return {mode,profile:NEGATIVE_PROFILE,taskIds:[...(mode==='training'?TRAINING:RANKED)]};}
 if(candidates[0]===S4_HISTORY_FLAG)return {mode:'ranked',profile:S4_HISTORY_PROFILE,taskIds:[...RANKED]};
 return candidates.length?{...MATRIX_FLAGS[candidates[0]],taskIds:[...MATRIX_FLAGS[candidates[0]].taskIds]}:null;
}

export const isAllowedBerMatrixProfile=(profile,mode)=>Object.hasOwn(MATRIX_PROFILES,profile)||([CONTRACT_REJECTION_PROFILE,GUARDS_PROFILE].includes(profile)&&mode==='training')||([S4_HISTORY_PROFILE,COMPOSITE_PROFILE].includes(profile)&&mode==='ranked')||(profile===NEGATIVE_PROFILE&&['training','ranked'].includes(mode));
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i,ADDRESS=/^0x[a-f0-9]{40}$/i,SHA=/^[a-f0-9]{64}$/i,UINT=/^(0|[1-9][0-9]*)$/;
const W=1000000000000n,MIN_DISPATCH_MS=12000,PACE_MS=2100,MAX_CALLS_PER_TASK=24;
const digest=v=>createHash('sha256').update(JSON.stringify(v)).digest('hex');
const need=(value,code)=>{if(!value)throw Object.assign(new Error(code),{code});};
const uint=value=>{need(typeof value==='string'&&UINT.test(value),'ber_matrix_public_units_invalid');return BigInt(value);};
const pause=ms=>new Promise(done=>setTimeout(done,ms));
const paymentKeys=['scheme','network','asset','amount','payTo','transferMethod','name','version','paymentFlow'];
const statuses=new Set(['queued','preparing','running','cancellation_requested','cancelled','expired','completed','failed','unknown','disqualified']);
function safeFaultReference(value){if(!value||typeof value!=='object'||typeof value.path!=='string'||value.path.length>512||! /^(?:\.local\/|artifacts\/runs\/)[A-Za-z0-9._/-]+$/.test(value.path)||value.path.split('/').some(part=>!part||part==='.'||part==='..')||!SHA.test(value.sha256??''))return;return{path:value.path,sha256:value.sha256.toLowerCase()};}

/** Select only actual published terms. No task goal, reference answer or raw platform source is used. */
export function selectMatrixOffer(body){
 need(body?.freeInspection===true&&body.deliveryState==='not_delivered'&&body.readHandle?.kind==='catalog'&&UUID.test(body.operationId??'')&&body.readHandle.operationId===body.operationId&&Array.isArray(body.catalog),'ber_matrix_catalog_shape_invalid');
 for(const resource of body.catalog){const offer=resource?.offers?.[0],p=offer?.payment;
  if(typeof resource?.resourceId!=='string'||!SHA.test(resource.resourceSha256??'')||typeof resource.contentType!=='string'||typeof offer?.id!=='string'||!p||!paymentKeys.slice(0,6).every(k=>typeof p[k]==='string')||!ADDRESS.test(p.asset)||!ADDRESS.test(p.payTo)||/^0x0{40}$/i.test(p.payTo)||!UINT.test(p.amount)||BigInt(p.amount)<=0n)continue;
  need(paymentKeys.slice(6).every(k=>p[k]===undefined||typeof p[k]==='string'),'ber_matrix_public_payment_identity_invalid');
  return {resourceId:resource.resourceId,resourceSha256:resource.resourceSha256,contentType:resource.contentType,offerId:offer.id,payment:Object.fromEntries(paymentKeys.filter(k=>p[k]!==undefined).map(k=>[k,p[k]]))};
 }throw Object.assign(new Error('ber_matrix_no_published_canonical_offer'),{code:'ber_matrix_no_published_canonical_offer'});
}
export function verifyMatrixOffer(selection,body){
 need(body?.freeInspection===true&&body.deliveryState==='not_delivered'&&body.resourceId===selection.resourceId&&body.resourceSha256===selection.resourceSha256&&body.contentType===selection.contentType&&body.readHandle?.kind==='offer'&&UUID.test(body.operationId??'')&&body.readHandle.operationId===body.operationId&&Array.isArray(body.offers)&&body.offers[0]?.id===selection.offerId&&body.offers.filter(o=>o.id===selection.offerId).length===1,'ber_matrix_offer_identity_invalid');
 for(const key of paymentKeys)need(body.payment?.[key]===selection.payment[key]&&body.offers[0].payment?.[key]===selection.payment[key],'ber_matrix_offer_terms_changed');
}

const MAX_RESOURCE_BYTES=4*1024*1024;
function decodePublicResourceBytes(value){
 need(typeof value==='string'&&value.length>0&&value.length<=Math.ceil(MAX_RESOURCE_BYTES/3)*4&&/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value),'ber_matrix_retrieval_base64_invalid');
 const bytes=Buffer.from(value,'base64');need(bytes.length>0&&bytes.length<=MAX_RESOURCE_BYTES&&bytes.toString('base64')===value,'ber_matrix_retrieval_base64_invalid');return bytes;
}
export function verifyMatrixRetrieval(selection,body){
 need(body?.resourceId===selection.resourceId&&body?.contentType===selection.contentType&&body?.contentHash===selection.resourceSha256,'ber_matrix_retrieval_resource_changed');
 const bytes=decodePublicResourceBytes(body.contentBytes),sha256=createHash('sha256').update(bytes).digest('hex');need(sha256===body.contentHash,'ber_matrix_retrieval_content_hash_mismatch');return {resourceId:body.resourceId,contentType:body.contentType,sha256,byteCount:bytes.length};
}
/** Explicitly empty S2/S3 answer is a reviewed learning strategy, never an inferred answer. */
export function matrixFinishAnswer(task){
 const contract=task.answerContract;
 if(task.taskId==='S2'||task.taskId==='S3'){
  need(contract?.acceptsStructuredAnswer===true&&contract.answerOptional===true&&contract.schema?.type==='object'&&(!Object.hasOwn(contract.schema,'required')||Array.isArray(contract.schema.required)&&contract.schema.required.length===0),'ber_matrix_public_answer_contract_unavailable');return {};
 }
 need(contract?.acceptsStructuredAnswer===false&&contract.answerOptional===true,'ber_matrix_public_answer_contract_unavailable');return undefined;
}

/** Calls retain identities/statuses/hashes only; no raw tool errors, resource bodies or Ranked answers. */
export function projectMatrixBody(body){
 const out={};for(const key of ['actionId','runId','taskId','taskIndex','operationId','closureId','actionSequence','receiptRevision','admitted','status','reason','transactionHash','evidencePath','evidenceHash','replayed','state','retryAfterMs'])if(body?.[key]!==undefined)out[key]=body[key];
 if(body?.error)out.error={code:typeof body.error.code==='string'&&/^[A-Z][A-Z0-9_]{0,95}$/.test(body.error.code)?body.error.code:'UNKNOWN_ERROR'};
 if(body?.task)out.task={runId:body.task.runId,taskIndex:body.task.taskIndex,taskId:body.task.taskId,caseHash:body.task.caseHash,conditionsSha256:digest(body.task.conditions),executionSha256:digest(body.task.execution),deadlineAt:body.task.deadlineAt,overallDeadline:body.task.overallDeadline};
 else if(body&&Object.hasOwn(body,'task'))out.task=null;
 if(body?.run){need(UUID.test(body.run.runId??'')&&statuses.has(body.run.status)&&typeof body.run.terminal==='boolean','ber_matrix_run_state_invalid');out.run={runId:body.run.runId,status:body.run.status,terminal:body.run.terminal,terminalReason:body.run.terminalReason??null,cancellationReason:body.run.cancellationReason??null};}
 if(body?.toolResponse){const r=body.toolResponse;out.toolResponse={sha256:digest(r)};for(const key of ['outcome','operationId','status','resourceId','resourceSha256','contentSha256','contentHash','byteCount','contentType'])if(r[key]!==undefined)out.toolResponse[key]=r[key];if(typeof r.contentBytes==='string'&&SHA.test(r.contentHash??'')){try{const bytes=decodePublicResourceBytes(r.contentBytes),sha256=createHash('sha256').update(bytes).digest('hex');if(sha256===r.contentHash)out.toolResponse.decodedContent={byteCount:bytes.length,sha256};}catch{}}}
 if(body?.rejectionProof){const p=body.rejectionProof;if(p.schemaVersion==='bef-selected-recipient-code-guard/v1'&&p.reasonCode==='selected_recipient_must_be_eoa'&&UUID.test(p.operationId??'')&&SHA.test(p.requestSha256??''))out.rejectionProof={schemaVersion:p.schemaVersion,reasonCode:p.reasonCode,operationId:p.operationId,requestSha256:p.requestSha256};}
 if(body?.allowed!==undefined)out.allowed=body.allowed;
 return out;
}
/** ARC tracing receives actual bodies in RAM; persist only the same strict safe projection. */
export function projectMatrixHttpRecord(record){
 const out={};for(const key of ['method','path','status','startedAt','headersObservedAt','contentType','bodyCaptureStatus','finishedAt'])if(record[key]!==undefined)out[key]=record[key];
 if(record.body!==undefined){out.bodySha256=digest(record.body);const wire=record.body;if(wire&&typeof wire==='object'){
  const id=wire.id;out.jsonrpc={version:wire.jsonrpc=== '2.0'?'2.0':'unknown',...(Number.isSafeInteger(id)?{id}:{idSha256:digest(id??null)})};
  if(wire.error)out.error={code:Number.isSafeInteger(wire.error.code)?wire.error.code:null};
  const result=wire.result;let body=result?.structuredContent;
  if(!body&&typeof result?.content?.find(item=>item.type==='text')?.text==='string'){try{body=JSON.parse(result.content.find(item=>item.type==='text').text);}catch{}}
  if(body&&typeof body==='object')out.body=projectMatrixBody(body);
 }}return out;
}

function taskIdentity(task,context){need(task?.runId===context.runId&&task?.taskId===context.taskId&&task?.taskIndex===context.taskIndex&&task?.mode===context.mode&&SHA.test(task.caseHash??'')&&task.participantToolProtocol==='separate_payment_delivery_v2','ber_matrix_issued_identity_invalid');}
export function validateMatrixBoundary(context,task){
 const {input,output,mode,runId,taskIndex,taskId}=context,profile=input.berAdmittedMatrixProfile,expected=mode==='training'?TRAINING:mode==='ranked'?RANKED:null;
 need(input.berAdmittedMatrixIsolated===true&&input.automaticWorkerEvaluation===true&&isAllowedBerMatrixProfile(profile,context.mode)&&UUID.test(input.berMatrixCampaignId??'')&&expected&&JSON.stringify(output.taskIds)===JSON.stringify(expected)&&expected[taskIndex]===taskId&&UUID.test(runId??'')&&UUID.test(output.agent?.agentId??''),'ber_matrix_exact_isolated_profile_required');
 const db=new URL(input.observerDatabaseUrl);need(db.username==='oid_observer'&&/^\/oid_acceptance_[a-f0-9]{32}$/.test(db.pathname),'ber_matrix_disposable_observer_required');taskIdentity(task,context);return profile;
}

/** Unit seam only supplies a transport, clock and sleeper; the action vectors remain fixed. */
export async function executeFixedMatrixTask(context,task,{callTool,now=Date.now,sleep=pause,provenance='unit_fixture_not_runtime_acceptance',runState={preflightDone:false},transportPaces=false}={}){
 const profile=validateMatrixBoundary(context,task);need(typeof callTool==='function','ber_matrix_transport_missing');
 const global=context.output.berMatrix??={schemaVersion:'ber-controlled-matrix-actor/v1',campaignId:context.input.berMatrixCampaignId,profile,mode:context.mode,nativeAgent:false,fullScenarioAcceptance:false,calls:[],http:[],tasks:[]};
 need(global.profile===profile&&global.campaignId===context.input.berMatrixCampaignId,'ber_matrix_campaign_identity_changed');
 const proof={runId:context.runId,taskIndex:context.taskIndex,taskId:context.taskId,profile,caseHash:task.caseHash,issuedTaskSha256:digest(task),executionSha256:digest(task.execution),conditionsSha256:digest(task.conditions),provenance,actions:[],timing:{startedAt:new Date(now()).toISOString(),deadlineAt:task.deadlineAt,overallDeadline:task.overallDeadline},coverage:{status:'not_independently_verified',kinds:[]}};global.tasks.push(proof);
 let lastAt=-Infinity,calls=0,activeDeadline=Math.min(Date.parse(task.deadlineAt),Date.parse(task.overallDeadline));need(Number.isFinite(activeDeadline),'ber_matrix_deadline_invalid');
 const remaining=()=>activeDeadline-now();
 const call=async(tool,args,{afterCutoff=false,expectedCode}={})=>{need(calls++<MAX_CALLS_PER_TASK,'ber_matrix_call_budget_exhausted');const delay=transportPaces?0:Math.max(0,PACE_MS-(now()-lastAt));need(afterCutoff||remaining()>delay+500,'ber_matrix_actual_deadline_exhausted');await sleep(delay);lastAt=now();const startedAt=new Date(now()).toISOString();let result;
  try{result=await callTool(tool,args);}catch{global.calls.push({tool,args:structuredClone(args),startedAt,completedAt:new Date(now()).toISOString(),outcome:'transport_unknown',provenance});throw Object.assign(new Error('ber_matrix_transport_unknown_original_ids_retained'),{code:'ber_matrix_transport_unknown_original_ids_retained'});}
  const body=result.structuredContent??(typeof result.content?.find(x=>x.type==='text')?.text==='string'?JSON.parse(result.content.find(x=>x.type==='text').text):null);need(body&&typeof body==='object','ber_matrix_mcp_body_missing');
  const event={tool,args:structuredClone(args),startedAt,completedAt:new Date(now()).toISOString(),isError:result.isError===true,body:projectMatrixBody(body),bodySha256:digest(body),provenance};global.calls.push(event);if(expectedCode!==undefined){need(profile===GUARDS_PROFILE&&result.isError===true&&body.error?.code===expectedCode,'ber_matrix_expected_guard_denial_missing');}else need(!result.isError&&!body.error,'ber_matrix_mcp_error');return body;};
 const callExpected=(tool,args,options)=>{need(profile===GUARDS_PROFILE&&tool==='runs.task_action'&&['COMBINED_PURCHASE_UNAVAILABLE','TASK_PAYMENT_REFERENCE_UNAVAILABLE','TASK_CLOSED'].includes(options?.expectedCode),'ber_matrix_guard_expected_code_invalid');return call(tool,args,options);};
 const action=async(command,{expectedTerminal='observed'}={})=>{need(expectedTerminal==='observed'||expectedTerminal==='rejected_before_execution'&&profile===CONTRACT_REJECTION_PROFILE&&context.taskId==='S1'&&context.taskIndex===0&&command.kind==='swap','ber_matrix_expected_terminal_scope_invalid');need(remaining()>MIN_DISPATCH_MS,'ber_matrix_insufficient_dispatch_headroom');const operationId=randomUUID(),fact={operationId,command:structuredClone(command),kind:command.kind,admissionStatus:'unknown',receiptStatus:'unknown',provenance};proof.actions.push(fact);
  const admitted=await call('runs.task_action',{runId:context.runId,taskIndex:context.taskIndex,operationId,command});need(admitted.admitted===true&&UUID.test(admitted.actionId??''),'ber_matrix_action_not_admitted');fact.actionId=admitted.actionId;fact.admissionStatus='admitted';
  context.output.participantActions??=[];context.output.participantActions.push({taskId:context.taskId,taskIndex:context.taskIndex,kind:command.kind,operationId,command:structuredClone(command),actionId:admitted.actionId,httpStatus:200,transport:'actual_mcp_reference_sdk'});
  const readUntil=Math.min(Date.parse(task.overallDeadline)+30000,now()+90000);for(;;){need(now()<readUntil,'ber_matrix_receipt_pending_read_budget_original_identity_retained');const receipt=await call('runs.task_action_status',{runId:context.runId,actionId:admitted.actionId},{afterCutoff:true});need(receipt.actionId===admitted.actionId&&receipt.runId===context.runId,'ber_matrix_receipt_identity_invalid');fact.receiptStatus=receipt.status;if(receipt.transactionHash){need(/^0x[a-f0-9]{64}$/i.test(receipt.transactionHash)&&(!fact.transactionHash||fact.transactionHash.toLowerCase()===receipt.transactionHash.toLowerCase()),'ber_matrix_original_transaction_identity_changed');fact.transactionHash=receipt.transactionHash;}fact.evidence=receipt.evidencePath&&receipt.evidenceHash?{path:receipt.evidencePath,sha256:receipt.evidenceHash}:null;
   if(expectedTerminal==='rejected_before_execution'&&receipt.status==='rejected_before_execution'){need(!fact.transactionHash,'ber_matrix_rejection_conflicts_original_transaction');validateContractRecipientReceipt(receipt,{task,actionId:admitted.actionId});return receipt;}
   need(expectedTerminal==='observed'||receipt.status!=='observed','ber_matrix_expected_rejection_not_observed');
   if(receipt.status==='observed'){need(!['approve','transfer','wrap','unwrap','swap','pay'].includes(command.kind)||/^0x[a-f0-9]{64}$/i.test(receipt.transactionHash??''),'ber_matrix_observed_tx_missing');if(![NEGATIVE_PROFILE,COMPOSITE_PROFILE,CONTRACT_REJECTION_PROFILE,GUARDS_PROFILE].includes(profile))proof.coverage.kinds.push(command.kind);return receipt;}
   need(receipt.status==='pending'||receipt.status==='unknown','ber_matrix_action_unresolved_no_economic_retry');
  }
 };
 let primaryFailure,matchedFault,matchedBoundaryKind;
 try{
  if(!runState.preflightDone){const preflight=await call('identity.preflight',{agentId:context.output.agent.agentId,operationId:randomUUID()});need(preflight.allowed===true||preflight.status==='allowed','ber_matrix_preflight_denied');runState.preflightDone=true;}
  const current=await call('runs.current_task',{runId:context.runId});need(current.run?.runId===context.runId&&current.run.terminal===false,'ber_matrix_current_run_identity_invalid');taskIdentity(current.task,context);need(current.task.caseHash===task.caseHash&&digest(current.task.execution)===digest(task.execution)&&digest(current.task.conditions)===digest(task.conditions)&&digest(current.task.answerContract)===digest(task.answerContract),'ber_matrix_actual_disclosure_changed');activeDeadline=Math.min(activeDeadline,Date.parse(current.task.deadlineAt),Date.parse(current.task.overallDeadline));
  const boundaries=[['genericFault',context.input.berGenericSealFault],['s4PreparationFault',context.input.berS4PreparationFault],['chainBoundaryObserver',context.input.berChainObserver],['sourceObservationFault',context.input.berSourceObservationFault]].filter(([,value])=>value);need(boundaries.length<=1,'ber_matrix_boundary_profiles_mutually_exclusive');
  if(boundaries.length){const [kind,fault]=boundaries[0];need(['matchesTarget','beforeFinish','afterFinish','close'].every(key=>typeof fault[key]==='function'),'ber_matrix_fault_handle_invalid');if(fault.matchesTarget({taskId:context.taskId,taskIndex:context.taskIndex})){const allowed=kind==='genericFault'?(profile==='B'&&context.mode==='training'&&context.taskId==='S1'&&context.taskIndex===0||profile===COMPOSITE_PROFILE&&context.mode==='ranked'&&context.taskId==='U1'&&context.taskIndex===11):kind==='sourceObservationFault'?(profile==='B'&&context.mode==='training'&&context.taskId==='S1'&&context.taskIndex===0):kind==='s4PreparationFault'?(profile===S4_HISTORY_PROFILE&&context.mode==='ranked'&&context.taskId==='S4'&&context.taskIndex===3):(['B','C',NEGATIVE_PROFILE].includes(profile)||profile===COMPOSITE_PROFILE&&['H3','U1'].includes(context.taskId));need(allowed,'ber_matrix_fault_exact_target_required');matchedFault=fault;matchedBoundaryKind=kind;}}
  const taskPlan=profile===S4_HISTORY_PROFILE?fixedHistoryTaskPlan(context.output.taskIds,current.task):profile===COMPOSITE_PROFILE?fixedCompositeTaskPlan(context.output.taskIds,current.task):profile===CONTRACT_REJECTION_PROFILE?contractRecipientTaskPlan(context.output.taskIds,current.task):profile;
  if([S4_HISTORY_PROFILE,COMPOSITE_PROFILE,CONTRACT_REJECTION_PROFILE].includes(profile))proof.strategyProfile=taskPlan;
  if(profile===COMPOSITE_PROFILE){proof.coverage.status='composite_coexistence_not_positive_matrix';proof.positiveCoverageCredit=false;}
  if(profile===CONTRACT_REJECTION_PROFILE){proof.coverage.status='negative_control_not_positive_matrix';proof.positiveCoverageCredit=false;}
  if(taskPlan===GUARDS_PROFILE){
   proof.coverage.status='guard_negative_control_not_positive_matrix';proof.positiveCoverageCredit=false;proof.mcpGuards={};runState.guardState??={};
   await executeMcpGuardTask({taskIds:context.output.taskIds,task:current.task,state:runState.guardState,callExpected,call,admitAndObserve:action,selectOffer:selectMatrixOffer,verifyOffer:verifyMatrixOffer,verifyRetrieval:verifyMatrixRetrieval,proof:proof.mcpGuards,callIndex:()=>global.calls.length-1});
  }else if(taskPlan===CONTRACT_REJECTION_PROFILE){
   proof.contractRecipientRejection=await executeContractRecipientRejection({taskIds:context.output.taskIds,task:current.task,now,admitAndObserve:async command=>{const receipt=await action(command,{expectedTerminal:'rejected_before_execution'}),fact=proof.actions.at(-1);return {admission:{operationId:fact.operationId,actionId:fact.actionId,runId:context.runId,taskIndex:context.taskIndex,command:fact.command},receipt};}});
  }else if(taskPlan===COMPOSITE_PROFILE){
   proof.compositeMixed=await executeFixedCompositeMixed({taskIds:context.output.taskIds,task:current.task,now,admitAndObserve:async command=>{const receipt=await action(command),fact=proof.actions.at(-1);return {admission:{operationId:fact.operationId,actionId:fact.actionId,runId:context.runId,taskIndex:context.taskIndex,command:fact.command},receipt};}});
  }else if(taskPlan===NEGATIVE_PROFILE){
   proof.coverage.status='negative_control_not_positive_matrix';proof.positiveCoverageCredit=false;
   proof.noopRevert=await executeFixedNoopRevert({taskIds:context.output.taskIds,task:current.task,now,admitAndObserve:async command=>{const receipt=await action(command),fact=proof.actions.at(-1);return {admission:{operationId:fact.operationId,actionId:fact.actionId,runId:context.runId,taskIndex:context.taskIndex,command:fact.command},receipt};}});
  }else if(taskPlan===S4_HISTORY_PROFILE){
   proof.s4RestoredHistory=await executeFixedS4RestoredHistory({taskIds:context.output.taskIds,task:current.task,now,admitAndObserve:async command=>{const receipt=await action(command),fact=proof.actions.at(-1);return {admission:{operationId:fact.operationId,actionId:fact.actionId,runId:context.runId,taskIndex:context.taskIndex,command:fact.command},receipt};}});
  }else if(taskPlan==='A'){
   const catalog=await action({kind:'inspect_catalog'}),offer=selectMatrixOffer(catalog.toolResponse),inspected=await action({kind:'inspect_offer',resourceId:offer.resourceId,offerId:offer.offerId});verifyMatrixOffer(offer,inspected.toolResponse);
   const paid=await action({kind:'pay',resourceId:offer.resourceId,offerId:offer.offerId,offerReadActionId:inspected.actionId});need(paid.toolResponse?.status==='payment_confirmed'&&paid.toolResponse?.payment?.receiptStatus==='success','ber_matrix_payment_not_confirmed');
   const delivered=await action({kind:'retrieve',payActionId:paid.actionId});proof.retrieval=verifyMatrixRetrieval(offer,delivered.toolResponse);proof.selection={resourceId:offer.resourceId,offerId:offer.offerId,resourceSha256:offer.resourceSha256,payment:offer.payment};
  }else if(taskPlan==='B'){
   const wrapped=await action({kind:'wrap',amountWei:String(2n*W),gasLimit:'100000'}),participant=wrapped.toolResponse?.transaction?.from;need(ADDRESS.test(participant??'')&&wrapped.toolResponse?.outcome==='success','ber_matrix_wrap_not_confirmed');
   need(uint(wrapped.toolResponse.after?.payerWethUnits)-uint(wrapped.toolResponse.before?.payerWethUnits)===2n*W,'ber_matrix_own_wrapped_amount_unverified');
   await action({kind:'approve',tokenAssetId:'WETH',amountUnits:String(W),gasLimit:'100000'});
   await action({kind:'swap',inputAssetId:'WETH',outputAssetId:'USDC',feeTier:500,amountInUnits:String(W),amountOutMinimumUnits:'1',recipient:participant,gasLimit:'300000'});
   await action({kind:'unwrap',amountWei:String(W),gasLimit:'100000'});
  }else{
   const catalog=await action({kind:'inspect_catalog'}),offer=selectMatrixOffer(catalog.toolResponse);
   // AICODE-NOTE: Predeclared uniform bootstrap, never conditional funding or goal repair.
   const wrapped=await action({kind:'wrap',amountWei:String(2n*W),gasLimit:'100000'}),participant=wrapped.toolResponse?.transaction?.from;need(ADDRESS.test(participant??'')&&wrapped.toolResponse?.outcome==='success'&&uint(wrapped.toolResponse.after?.payerWethUnits)-uint(wrapped.toolResponse.before?.payerWethUnits)===2n*W,'ber_matrix_wrap_not_confirmed');
   await action({kind:'approve',tokenAssetId:'WETH',amountUnits:String(W),gasLimit:'100000'});
   const swapped=await action({kind:'swap',inputAssetId:'WETH',outputAssetId:'USDC',feeTier:500,amountInUnits:String(W),amountOutMinimumUnits:'1',recipient:participant,gasLimit:'300000'}),beforeUsdc=uint(swapped.toolResponse?.before?.payerUsdcUnits),afterUsdc=uint(swapped.toolResponse?.after?.payerUsdcUnits);
   need(swapped.toolResponse?.outcome==='success'&&swapped.toolResponse?.receipt?.status==='success'&&swapped.toolResponse.receipt.transactionHash===swapped.transactionHash&&swapped.toolResponse?.selectedAction?.kind==='swap'&&swapped.toolResponse.selectedAction.recipient?.toLowerCase()===participant.toLowerCase()&&swapped.toolResponse.selectedAction.inputAssetId==='WETH'&&swapped.toolResponse.selectedAction.outputAssetId==='USDC'&&swapped.toolResponse.selectedAction.amountInUnits===String(W)&&afterUsdc-beforeUsdc>=1n,'ber_matrix_declared_swap_supply_unconfirmed');proof.bootstrapSupply={beforeUsdcUnits:beforeUsdc.toString(),afterUsdcUnits:afterUsdc.toString(),deltaUsdcUnits:(afterUsdc-beforeUsdc).toString()};
   await action({kind:'transfer',amountUnits:'1',recipient:offer.payment.payTo,gasLimit:'100000'});proof.selection={resourceId:offer.resourceId,offerId:offer.offerId,payTo:offer.payment.payTo};
  }
  await matchedFault?.beforeFinish({runId:context.runId,taskId:context.taskId,taskIndex:context.taskIndex});
  const operationId=randomUUID(),answer=matrixFinishAnswer(task),finishArgs={runId:context.runId,taskIndex:context.taskIndex,operationId,...(answer!==undefined?{answer}:{})},finished=await call('runs.finish_task',finishArgs);need(UUID.test(finished.closureId??''),'ber_matrix_finish_identity_invalid');proof.finish={operationId,closureId:finished.closureId,body:projectMatrixBody(finished),provenance};
  const boundaryRef=safeFaultReference(await matchedFault?.afterFinish({runId:context.runId,taskId:context.taskId,taskIndex:context.taskIndex,operationId,closureId:finished.closureId}));if(boundaryRef)proof[matchedBoundaryKind+'Reference']=boundaryRef;
  if(profile===GUARDS_PROFILE)await repeatMcpGuardFinish({taskIds:context.output.taskIds,task:current.task,state:runState.guardState,proof:proof.mcpGuards,finishArgs,finished,call,callExpected,callIndex:()=>global.calls.length-1});
  const next=await call('runs.current_task',{runId:context.runId},{afterCutoff:true});proof.afterFinish=projectMatrixBody(next);proof.timing.finishedAt=new Date(now()).toISOString();proof.timing.remainingMs=remaining();
  return {answer,berMcpFinishFact:{taskId:context.taskId,taskIndex:context.taskIndex,kind:'finish',operationId,httpStatus:200,closureId:finished.closureId,transport:'actual_mcp_reference_sdk'}};
 }catch(error){primaryFailure=error;if(error?.s4HistoryProof)proof.s4RestoredHistory=error.s4HistoryProof;if(error?.negativeControlProof)proof.noopRevert=error.negativeControlProof;if(error?.compositeMixedProof)proof.compositeMixed=error.compositeMixedProof;const failureRef=safeFaultReference(error?.s4PreparationFaultCapture??error?.sourceObservationFaultCapture??error?.berGenericFaultCapture??error?.primaryFailureRef),cleanupRef=safeFaultReference(error?.cleanupRef),kind=matchedBoundaryKind??'genericFault';if(failureRef)proof[kind+'FailureReference']=failureRef;if(cleanupRef)proof[kind+'CleanupReference']=cleanupRef;proof.blocker={code:/^(?:ber_matrix_[a-z0-9_]+|S4_HISTORY_[A-Z_]+|BER_GUARDS_[A-Z_]+|BER_D_[A-Z_]+|BER_CONTRACT_REJECTION_[A-Z_]+|BER_COMPOSITE_[A-Z_]+|BER_FAULT_[A-Z_]+|BER_GENERIC_SEAL_FAULT_[A-Z_]+|BER_S4_PREP_FAULT_[A-Z_]+|BER_SOURCE_FAULT_[A-Z_]+)$/.test(error?.code??'')?error.code:'ber_matrix_unclassified_failure',phase:'fixed_actor',originalIdentitiesRetained:true};throw Object.assign(new Error(proof.blocker.code),{code:proof.blocker.code});}
 finally{if(matchedFault)try{await matchedFault.close();}catch(cleanup){proof.faultCleanupUnavailable=true;const ref=safeFaultReference(cleanup?.cleanupRef);if(ref)proof[(matchedBoundaryKind??'genericFault')+'CleanupReference']=ref;if(!primaryFailure)throw Object.assign(new Error('ber_matrix_fault_cleanup_failed'),{code:'ber_matrix_fault_cleanup_failed',...(ref?{cleanupRef:ref}:{})});}}
}

/** One serialized HTTP-start timeline, including SDK initialization/notifications. Never reset per task. */
export function createMatrixRunPacer({now=Date.now,sleep=pause}={}){
 let chain=Promise.resolve(),lastAt=-Infinity,count=0;
 return {wait(){const next=chain.then(async()=>{need(count<400,'ber_matrix_run_http_budget_exhausted');count++;await sleep(Math.max(0,PACE_MS-(now()-lastAt)));lastAt=now();return lastAt;});chain=next.catch(()=>{});return next;},snapshot(){return {requestCount:count,lastStartedAt:Number.isFinite(lastAt)?new Date(lastAt).toISOString():null,intervalMs:PACE_MS};}};
}
function identityPin(context){need(typeof context.bearer==='string'&&context.bearer.length>0,'ber_matrix_scoped_bearer_missing');return digest({runId:context.runId,agentId:context.output.agent.agentId,campaignId:context.input.berMatrixCampaignId,profile:context.input.berAdmittedMatrixProfile,mode:context.mode,origin:new URL(context.input.publicOrigin).origin,bearerSha256:createHash('sha256').update(context.bearer).digest('hex')});}
function actorOutput(context){return context.output.berMatrix??={schemaVersion:'ber-controlled-matrix-actor/v1',campaignId:context.input.berMatrixCampaignId,profile:context.input.berAdmittedMatrixProfile,mode:context.mode,nativeAgent:false,fullScenarioAcceptance:false,calls:[],http:[],tasks:[]};}
/** RAM-only bounded registry. Unit opener injection is not a runtime qualification seam. */
export function createMatrixSessionRegistry({open,now=Date.now,sleep=pause}){
 const sessions=new Map(),closed=new Set();
 const get=async(context,existingOnly=false)=>{
  const pin=identityPin(context);let entry=sessions.get(context.runId);
  if(entry){need(entry.pin===pin&&entry.output===context.output,'ber_matrix_run_session_identity_changed');return entry.ready;}
  need(!existingOnly&&!closed.has(context.runId)&&sessions.size<2&&closed.size<32,'ber_matrix_run_session_closed_or_capacity');
  entry={pin,output:context.output,inFlight:false,state:{preflightDone:false},pacer:createMatrixRunPacer({now,sleep})};sessions.set(context.runId,entry);
  actorOutput(context);entry.ready=Promise.resolve().then(()=>open(context,entry.pacer)).then(resource=>{entry.resource=resource;return entry;});
  try{return await entry.ready;}catch{actorOutput(context).setupBlocker={code:'ber_matrix_sdk_connection_failed',runId:context.runId};throw Object.assign(new Error('ber_matrix_sdk_connection_failed'),{code:'ber_matrix_sdk_connection_failed'});}
 };
 return {
  async perform(context,task){const entry=await get(context);need(!entry.inFlight,'ber_matrix_parallel_task_actor_forbidden');entry.inFlight=true;
   try{return await executeFixedMatrixTask(context,task,{callTool:(name,args)=>entry.resource.callTool(name,args),now,sleep,runState:entry.state,transportPaces:true,provenance:entry.resource.provenance});}
   finally{entry.inFlight=false;actorOutput(context).sessionPacing=entry.pacer.snapshot();}
  },
  async monitor(context,options){const entry=await get(context,true);need(!entry.inFlight,'ber_matrix_parallel_task_actor_forbidden');return monitorMatrixTerminal({...options,runId:context.runId,callTool:(name,args)=>entry.resource.callTool(name,args),now,sleep});},
  async monitorExisting({runId,agentId,...options}){const entry=sessions.get(runId);need(entry&&entry.output.agent?.agentId===agentId&&!entry.inFlight,'ber_matrix_existing_session_identity_required');await entry.ready;return monitorMatrixTerminal({...options,runId,callTool:(name,args)=>entry.resource.callTool(name,args),now,sleep});},
  async close(runId){const entry=sessions.get(runId);if(!entry)return;need(!entry.inFlight,'ber_matrix_cannot_close_active_actor');try{await entry.ready;await entry.resource.close();}catch{}finally{sessions.delete(runId);closed.add(runId);}},
  state(){return {liveCount:sessions.size,closedCount:closed.size};}
 };
}
async function openSdkSession(context,pacer){
 const origin=new URL(context.input.publicOrigin);need(['127.0.0.1','localhost','host.docker.internal'].includes(origin.hostname)&&!origin.username&&!origin.password,'ber_matrix_disposable_origin_required');const require=createRequire(resolve(context.input.repoRoot,'packages/owner-acceptance/package.json'));
 const {Client,StreamableHTTPClientTransport}=await import(pathToFileURL(require.resolve('@modelcontextprotocol/client')).href);
 const {createArcTracingFetch}=await import(pathToFileURL(resolve(context.input.repoRoot,'packages/owner-acceptance/src/arc-http-trace.mjs')).href);
 const client=new Client({name:'ber-admitted-matrix-reference-sdk',version:'2.4.0'},{versionNegotiation:{mode:{pin:'2026-07-28'}}}),trace=actorOutput(context).http,slots=new WeakMap();
 const tracing=createArcTracingFetch({onRecord:row=>{let index=slots.get(row);if(index===undefined){index=trace.length;slots.set(row,index);}trace[index]=projectMatrixHttpRecord(row);}});
 const pacedFetch=async(url,init)=>{await pacer.wait();return tracing.fetch(url,init);};
 const transport=new StreamableHTTPClientTransport(new URL('/api/agent/mcp',origin),{requestInit:{headers:{authorization:'Bearer '+context.bearer,origin:origin.origin}},fetch:pacedFetch,onInsufficientScope:'throw'});
 try{await client.connect(transport);}catch{await client.close().catch(()=>{});await tracing.settle();throw new Error('ber_matrix_sdk_connection_failed');}
 return {provenance:'actual_participant_mcp_reference_sdk_not_native_model',callTool:(name,args)=>client.callTool({name,arguments:args}),async close(){await client.close().catch(()=>{});await tracing.settle();}};
}
const actualSessions=createMatrixSessionRegistry({open:openSdkSession});
/** Only the disposable harness scoped bearer; no native OAuth caches, helpers or grants. */
export async function performBerMatrixActions(context,task){validateMatrixBoundary(context,task);return actualSessions.perform(context,task);}
export async function monitorBerMatrixRun(context,options){return actualSessions.monitor(context,options);}
export async function observeBerMatrixRunTerminal(options){return actualSessions.monitorExisting(options);}
/** Mandatory runner finally hook, after terminal observation or preserved blocker. Idempotent. */
export async function closeBerMatrixRunSession(runId){return actualSessions.close(runId);}

/** Whole-run follow-up: explicit server terminal state; respects retryAfterMs, never admits actions. */
export async function monitorMatrixTerminal({runId,callTool,record,deadlineMs,now=Date.now,sleep=pause}){
 need(UUID.test(runId??'')&&typeof record==='function'&&Number.isFinite(deadlineMs),'ber_matrix_monitor_identity_invalid');
 while(now()<deadlineMs){const r=await callTool('runs.current_task',{runId}),body=r.structuredContent;need(!r.isError&&body?.run?.runId===runId,'ber_matrix_monitor_response_invalid');record({observedAt:new Date(now()).toISOString(),body:projectMatrixBody(body)});if(body.run.terminal===true)return {runId,status:body.run.status,terminal:true,terminalReason:body.run.terminalReason??null};const wait=Number.isSafeInteger(body.retryAfterMs)&&body.retryAfterMs>=1000?body.retryAfterMs:2100;await sleep(Math.min(Math.max(2100,wait),Math.max(0,deadlineMs-now())));}
 return {runId,status:'unconfirmed',terminal:false,reason:'monitor_deadline_reached_without_server_terminal'};
}
