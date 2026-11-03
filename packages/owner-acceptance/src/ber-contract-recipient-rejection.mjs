/** Finite admitted contract-recipient denial control. Provisional receipt marker is not raw no-effect proof. */
import{createHash}from'node:crypto';
export const FLAG='--ber-contract-recipient-rejection-training',PROFILE='NON_EOA_REJECTION';
const TASKS=['S1','M1','H1'],UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i,SHA=/^[a-f0-9]{64}$/i,ADDRESS=/^0x[a-f0-9]{40}$/i;
const need=(v,code)=>{if(!v)throw Object.assign(new Error(code),{code});},canonical=v=>JSON.stringify(v,(_,x)=>x&&typeof x==='object'&&!Array.isArray(x)?Object.fromEntries(Object.keys(x).sort().map(k=>[k,x[k]])):x),hash=v=>createHash('sha256').update(canonical(v)).digest('hex');
export function contractRecipientTaskPlan(taskIds,task){need(canonical(taskIds)===canonical(TASKS)&&task?.mode==='training'&&TASKS[task.taskIndex]===task.taskId,'BER_CONTRACT_REJECTION_FULL_TRAINING_REQUIRED');return task.taskId==='S1'?PROFILE:'A';}
export function contractRecipientCommand(task){
 need(task?.mode==='training'&&task.taskId==='S1'&&task.taskIndex===0&&UUID.test(task.runId??''),'BER_CONTRACT_REJECTION_S1_REQUIRED');
 const assets=task.execution?.assets;need(Array.isArray(assets),'BER_CONTRACT_REJECTION_PUBLIC_ASSETS_REQUIRED');const usdc=assets.filter(a=>a.assetId==='USDC'&&a.kind==='erc20');need(usdc.length===1&&ADDRESS.test(usdc[0].address??'')&&!/^0x0{40}$/i.test(usdc[0].address),'BER_CONTRACT_REJECTION_PUBLIC_USDC_REQUIRED');
 return{kind:'swap',inputAssetId:'WETH',outputAssetId:'USDC',feeTier:500,amountInUnits:'1000000000000',amountOutMinimumUnits:'1',recipient:usdc[0].address.toLowerCase(),gasLimit:'300000'};
}
export function validateContractRecipientReceipt(receipt,{task,actionId}){
 need(receipt?.status==='rejected_before_execution'&&receipt.runId===task.runId&&receipt.taskIndex===0&&receipt.taskId==='S1'&&receipt.actionId===actionId&&String(receipt.actionSequence)==='1'&&Number.isSafeInteger(receipt.receiptRevision)&&receipt.receiptRevision>0&&receipt.transactionHash===null&&receipt.toolResponse===null,'BER_CONTRACT_REJECTION_VERIFIED_RECEIPT_REQUIRED');
 const p=receipt.rejectionProof;need(p&&Object.keys(p).sort().join(',')===['schemaVersion','reasonCode','operationId','requestSha256'].sort().join(',')&&p.schemaVersion==='bef-selected-recipient-code-guard/v1'&&p.reasonCode==='selected_recipient_must_be_eoa'&&UUID.test(p.operationId??'')&&SHA.test(p.requestSha256??''),'BER_CONTRACT_REJECTION_STRUCTURED_MARKER_REQUIRED');
 need(typeof receipt.evidencePath==='string'&&receipt.evidencePath.length<=512&&/^artifacts\/runs\/[A-Za-z0-9._/-]+$/.test(receipt.evidencePath)&&!receipt.evidencePath.split('/').some(x=>!x||x==='.'||x==='..')&&SHA.test(receipt.evidenceHash??''),'BER_CONTRACT_REJECTION_EVIDENCE_REQUIRED');return structuredClone(p);
}
export async function executeContractRecipientRejection({taskIds,task,admitAndObserve,now=Date.now}){
 need(contractRecipientTaskPlan(taskIds,task)===PROFILE&&typeof admitAndObserve==='function','BER_CONTRACT_REJECTION_SCOPE_REQUIRED');need(Math.min(Date.parse(task.deadlineAt),Date.parse(task.overallDeadline))-now()>12000,'BER_CONTRACT_REJECTION_HEADROOM');
 const command=contractRecipientCommand(task),proof={schemaVersion:'ber-contract-recipient-rejection-actor/v1',profile:PROFILE,runId:task.runId,taskIndex:0,taskId:'S1',issuedExecutionSha256:hash(task.execution),command,nativeAgent:false,negativeControlOnly:true,positiveCoverageCredit:false,independentProof:'not_run'};
 const{admission:a,receipt:r}=await admitAndObserve(command);need(a?.runId===task.runId&&a.taskIndex===0&&UUID.test(a.operationId??'')&&UUID.test(a.actionId??'')&&canonical(a.command)===canonical(command),'BER_CONTRACT_REJECTION_ADMISSION_IDENTITY');const marker=validateContractRecipientReceipt(r,{task,actionId:a.actionId});
 proof.original={operationId:a.operationId,actionId:a.actionId,befOperationId:marker.operationId,requestSha256:marker.requestSha256,actionSequence:r.actionSequence,receiptRevision:r.receiptRevision};proof.rejectionProof=marker;proof.evidence={path:r.evidencePath,sha256:r.evidenceHash};proof.receiptStatus=r.status;proof.transactionHash=null;return proof;
}
