/** Controlled composite vector only; effect proofs and grades require independent retained-source replay. */
import {createHash} from 'node:crypto';
export const FLAG='--ber-composite-mixed-ranked';
export const PROFILE='COMPOSITE_MIXED';
export const RANKED=Object.freeze(['S1','S2','S3','S4','M1','M2','M3','M4','H1','H2','H3','U1']);
export const MINIMUM_TASK_MCP_CALLS=19;
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i,ADDRESS=/^0x[a-f0-9]{40}$/i,SHA=/^[a-f0-9]{64}$/i,HASH=/^0x[a-f0-9]{64}$/i,UINT=/^(0|[1-9][0-9]*)$/;
const W=1000000000000n,paymentKeys=['scheme','network','asset','amount','payTo','transferMethod','name','version','paymentFlow'];
const need=(value,code)=>{if(!value)throw Object.assign(new Error(code),{code});};
const canonical=v=>JSON.stringify(v,(_,x)=>x&&typeof x==='object'&&!Array.isArray(x)?Object.fromEntries(Object.keys(x).sort().map(k=>[k,x[k]])):x);
const sha=v=>createHash('sha256').update(canonical(v)).digest('hex');
const uint=v=>{need(typeof v==='string'&&UINT.test(v),'BER_COMPOSITE_UNITS_INVALID');return BigInt(v);};
export function fixedCompositeTaskPlan(taskIds,task){need(JSON.stringify(taskIds)===JSON.stringify(RANKED)&&task?.mode==='ranked'&&RANKED[task.taskIndex]===task.taskId&&UUID.test(task.runId??''),'BER_COMPOSITE_FULL_RANKED_REQUIRED');return ['H3','U1'].includes(task.taskId)?PROFILE:'A';}
function selectMatrixOffer(body){
 need(body?.freeInspection===true&&body.deliveryState==='not_delivered'&&body.readHandle?.kind==='catalog'&&UUID.test(body.operationId??'')&&body.readHandle.operationId===body.operationId&&Array.isArray(body.catalog),'ber_matrix_catalog_shape_invalid');
 for(const resource of body.catalog){const offer=resource?.offers?.[0],p=offer?.payment;
  if(typeof resource?.resourceId!=='string'||!SHA.test(resource.resourceSha256??'')||typeof resource.contentType!=='string'||typeof offer?.id!=='string'||!p||!paymentKeys.slice(0,6).every(k=>typeof p[k]==='string')||!ADDRESS.test(p.asset)||!ADDRESS.test(p.payTo)||/^0x0{40}$/i.test(p.payTo)||!UINT.test(p.amount)||BigInt(p.amount)<=0n)continue;
  need(paymentKeys.slice(6).every(k=>p[k]===undefined||typeof p[k]==='string'),'ber_matrix_public_payment_identity_invalid');
  return {resourceId:resource.resourceId,resourceSha256:resource.resourceSha256,contentType:resource.contentType,offerId:offer.id,payment:Object.fromEntries(paymentKeys.filter(k=>p[k]!==undefined).map(k=>[k,p[k]]))};
 }throw Object.assign(new Error('ber_matrix_no_published_canonical_offer'),{code:'ber_matrix_no_published_canonical_offer'});
}
function verifyMatrixOffer(selection,body){
 need(body?.freeInspection===true&&body.deliveryState==='not_delivered'&&body.resourceId===selection.resourceId&&body.resourceSha256===selection.resourceSha256&&body.contentType===selection.contentType&&body.readHandle?.kind==='offer'&&UUID.test(body.operationId??'')&&body.readHandle.operationId===body.operationId&&Array.isArray(body.offers)&&body.offers[0]?.id===selection.offerId&&body.offers.filter(o=>o.id===selection.offerId).length===1,'ber_matrix_offer_identity_invalid');
 for(const key of paymentKeys)need(body.payment?.[key]===selection.payment[key]&&body.offers[0].payment?.[key]===selection.payment[key],'ber_matrix_offer_terms_changed');
}

const MAX_RESOURCE_BYTES=4*1024*1024;
function decodePublicResourceBytes(value){
 need(typeof value==='string'&&value.length>0&&value.length<=Math.ceil(MAX_RESOURCE_BYTES/3)*4&&/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value),'ber_matrix_retrieval_base64_invalid');
 const bytes=Buffer.from(value,'base64');need(bytes.length>0&&bytes.length<=MAX_RESOURCE_BYTES&&bytes.toString('base64')===value,'ber_matrix_retrieval_base64_invalid');return bytes;
}
function verifyMatrixRetrieval(selection,body){
 need(body?.resourceId===selection.resourceId&&body?.contentType===selection.contentType&&body?.contentHash===selection.resourceSha256,'ber_matrix_retrieval_resource_changed');
 const bytes=decodePublicResourceBytes(body.contentBytes),sha256=createHash('sha256').update(bytes).digest('hex');need(sha256===body.contentHash,'ber_matrix_retrieval_content_hash_mismatch');return {resourceId:body.resourceId,contentType:body.contentType,sha256,byteCount:bytes.length};
}

/** The callback supplies actual admission/status evidence; this helper never retries an action or finishes a task. */
export async function executeFixedCompositeMixed({taskIds,task,admitAndObserve,now=Date.now}){
 need(fixedCompositeTaskPlan(taskIds,task)===PROFILE&&task.participantToolProtocol==='separate_payment_delivery_v2'&&typeof admitAndObserve==='function','BER_COMPOSITE_EXACT_TASK_REQUIRED');
 const deadline=Math.min(Date.parse(task.deadlineAt),Date.parse(task.overallDeadline));need(Number.isFinite(deadline),'BER_COMPOSITE_DEADLINE_INVALID');
 const proof={schemaVersion:'ber-composite-mixed-actor/v1',profile:PROFILE,classification:'controlled_fixed_vector_NOT_independent_effect_or_grade',nativeAgent:false,fullScenarioAcceptance:false,independentProof:'not_run',runId:task.runId,taskId:task.taskId,taskIndex:task.taskIndex,issuedTaskSha256:sha(task),minimumTaskMcpCalls:MINIMUM_TASK_MCP_CALLS,steps:[]};
 const actions=new Set(),operations=new Set(),transactions=new Set(),economic=[];
 const action=async command=>{
  need(deadline-now()>12000,'BER_COMPOSITE_DISPATCH_HEADROOM_EXHAUSTED');const record={command:structuredClone(command)};proof.steps.push(record);let observed;
  try{observed=await admitAndObserve(command);}catch{throw Object.assign(new Error('BER_COMPOSITE_ORIGINAL_ACTION_UNRESOLVED'),{code:'BER_COMPOSITE_ORIGINAL_ACTION_UNRESOLVED'});}
  const a=observed?.admission,r=observed?.receipt;record.receivedIdentities={...(UUID.test(a?.actionId??'')?{actionId:a.actionId}:{}),...(UUID.test(a?.operationId??'')?{operationId:a.operationId}:{}),...(UUID.test(r?.actionId??'')?{receiptActionId:r.actionId}:{}),...(HASH.test(r?.transactionHash??'')?{transactionHash:r.transactionHash}:{})};
  need(a&&UUID.test(a.operationId??'')&&UUID.test(a.actionId??'')&&a.runId===task.runId&&a.taskIndex===task.taskIndex&&canonical(a.command)===canonical(command),'BER_COMPOSITE_ADMISSION_IDENTITY_CHANGED');
  need(r?.actionId===a.actionId&&r.runId===task.runId&&r.taskIndex===task.taskIndex&&r.taskId===task.taskId&&r.status==='observed'&&Number.isSafeInteger(r.receiptRevision)&&r.receiptRevision>0&&String(r.actionSequence)===String(proof.steps.length),'BER_COMPOSITE_RECEIPT_IDENTITY_CHANGED');
  need(!actions.has(a.actionId)&&!operations.has(a.operationId),'BER_COMPOSITE_DUPLICATE_ACTION');actions.add(a.actionId);operations.add(a.operationId);
  need(typeof r.evidencePath==='string'&&/^artifacts\/runs\/[A-Za-z0-9._/-]+$/.test(r.evidencePath)&&r.evidencePath.length<=512&&!r.evidencePath.split('/').some(p=>!p||p==='.'||p==='..')&&SHA.test(r.evidenceHash??''),'BER_COMPOSITE_EVIDENCE_MISSING');
  record.original={operationId:a.operationId,actionId:a.actionId,actionSequence:r.actionSequence,receiptRevision:r.receiptRevision,evidence:{path:r.evidencePath,sha256:r.evidenceHash}};
  if(['pay','wrap','approve','swap','unwrap'].includes(command.kind)){need(HASH.test(r.transactionHash??'')&&!transactions.has(r.transactionHash.toLowerCase()),'BER_COMPOSITE_TRANSACTION_IDENTITY_CHANGED');transactions.add(r.transactionHash.toLowerCase());record.original.transactionHash=r.transactionHash;economic.push({actionId:a.actionId,kind:command.kind,transactionHash:r.transactionHash.toLowerCase(),evidence:record.original.evidence});}
  else need(r.transactionHash===null||r.transactionHash===undefined,'BER_COMPOSITE_READ_HAS_TRANSACTION');
  record.responseSha256=sha(r.toolResponse);if(['wrap','approve','swap','unwrap'].includes(command.kind))for(const [commandKey,value]of Object.entries(command)){const key=command.kind==='swap'&&commandKey==='feeTier'?'fee':commandKey;need(typeof value==='string'&&ADDRESS.test(value)?r.toolResponse?.selectedAction?.[key]?.toLowerCase()===value.toLowerCase():r.toolResponse?.selectedAction?.[key]===value,'BER_COMPOSITE_SELECTED_ACTION_CHANGED');}return r;
 };
 try{
  const catalog=await action({kind:'inspect_catalog'}),offer=selectMatrixOffer(catalog.toolResponse),inspected=await action({kind:'inspect_offer',resourceId:offer.resourceId,offerId:offer.offerId});verifyMatrixOffer(offer,inspected.toolResponse);
  const paid=await action({kind:'pay',resourceId:offer.resourceId,offerId:offer.offerId,offerReadActionId:inspected.actionId});need(paid.toolResponse?.status==='payment_confirmed'&&paid.toolResponse?.payment?.receiptStatus==='success','BER_COMPOSITE_PAYMENT_UNCONFIRMED');
  const delivered=await action({kind:'retrieve',payActionId:paid.actionId});proof.delivery={payActionId:paid.actionId,retrievalActionId:delivered.actionId,...verifyMatrixRetrieval(offer,delivered.toolResponse)};
  const wrap=await action({kind:'wrap',amountWei:String(2n*W),gasLimit:'100000'}),participant=wrap.toolResponse?.transaction?.from;
  need(ADDRESS.test(participant??'')&&wrap.toolResponse?.outcome==='success'&&wrap.toolResponse?.receipt?.status==='success'&&wrap.toolResponse.receipt.transactionHash===wrap.transactionHash&&uint(wrap.toolResponse.after?.payerWethUnits)-uint(wrap.toolResponse.before?.payerWethUnits)===2n*W,'BER_COMPOSITE_WRAP_UNCONFIRMED');
  const chainSuccess=r=>need(r.toolResponse?.outcome==='success'&&r.toolResponse?.receipt?.status==='success'&&r.toolResponse.receipt.transactionHash===r.transactionHash&&r.toolResponse?.transaction?.hash===r.transactionHash&&r.toolResponse?.transaction?.from?.toLowerCase()===participant.toLowerCase(),'BER_COMPOSITE_CHAIN_NOT_SUCCESS');
  chainSuccess(wrap);
  const approve=await action({kind:'approve',tokenAssetId:'WETH',amountUnits:String(W),gasLimit:'100000'});chainSuccess(approve);
  const swap=await action({kind:'swap',inputAssetId:'WETH',outputAssetId:'USDC',feeTier:500,amountInUnits:String(W),amountOutMinimumUnits:'1',recipient:participant,gasLimit:'300000'});chainSuccess(swap);
  const unwrap=await action({kind:'unwrap',amountWei:String(W),gasLimit:'100000'});
  chainSuccess(unwrap);
  const selected=swap.toolResponse.selectedAction;need(selected?.kind==='swap'&&selected.inputAssetId==='WETH'&&selected.outputAssetId==='USDC'&&selected.amountInUnits===String(W)&&selected.amountOutMinimumUnits==='1'&&selected.recipient?.toLowerCase()===participant.toLowerCase(),'BER_COMPOSITE_SELECTED_SWAP_CHANGED');
  proof.economicUnion={classification:'original_identity_union_NOT_independent_effect_totals',transactions:economic,paymentActionIds:[paid.actionId],chainActionIds:proof.steps.slice(4).map(s=>s.original.actionId),principalEffects:'requires_independent_receipt_and_state_replay',gas:'one_source_transaction_identity_per_entry_no_summed_or_duplicated_cost',deliveryActionIds:[delivered.actionId]};
  need(economic.length===5,'BER_COMPOSITE_TRANSACTION_UNION_INCOMPLETE');return proof;
 }catch(error){proof.blocker={code:/^(?:BER_COMPOSITE_[A-Z_]+|ber_matrix_[a-z0-9_]+)$/.test(error?.code??'')?error.code:'BER_COMPOSITE_UNVERIFIED',originalIdentitiesRetained:true};throw Object.assign(new Error(proof.blocker.code),{code:proof.blocker.code,compositeMixedProof:proof});}
}
