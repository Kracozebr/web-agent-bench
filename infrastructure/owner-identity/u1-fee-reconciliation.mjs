/** Qualification only: compare independently verified raw fee effects, never change a runtime grade. */
import {loadV2ReferenceContext,verifyTaskReferenceEvidenceV2} from '../../packages/owner-identity/src/task-reference-evidence-v2.ts';
import {canonicalTaskJson,sha256CanonicalTaskJson,taskCaseHash} from '../../packages/owner-identity/src/task-release.ts';
const same=(a,b)=>canonicalTaskJson(a)===canonicalTaskJson(b);
const need=(v,code)=>{if(!v)throw new Error(code)};
const HASH=/^0x[0-9a-f]{64}$/i;
const NATIVE=new Set(['transfer','approve','swap','unwrap','wrap','revoke']);
function integer(v){need(typeof v==='string'&&/^(?:0x[0-9a-f]+|0|[1-9][0-9]*)$/i.test(v),'u1_fee_integer_invalid');return BigInt(v);}
function normalize(v,payer){if(typeof v==='string'&&v.toLowerCase()===payer.toLowerCase())return 'participant';if(Array.isArray(v))return v.map(x=>normalize(x,payer));if(v&&typeof v==='object')return Object.fromEntries(Object.entries(v).map(([k,x])=>[k,normalize(x,payer)]));return v;}
function deriveParticipantGas(context, fixedCount){
 const seen=new Set(),receipts=[],selections=[],blocks=[];let gas=0n;
 for(const action of context.actions){
  if(!NATIVE.has(action.kind)){
   if(fixedCount===undefined){const body=context.action(action);need(['inspect_catalog','inspect_offer','pay','retrieve'].includes(action.kind)&&!body.transaction&&!body.receipt,'native_fee_unrecognized_transaction_action');}
   continue;
  }
  const body=context.action(action),hash=body.transaction?.hash??body.receipt?.transactionHash;
  need(body.outcome==='success'&&typeof hash==='string'&&HASH.test(hash)&&!seen.has(hash.toLowerCase()),'u1_fee_native_action_unverified');seen.add(hash.toLowerCase());
  const receipt=context.receipt(hash),transaction=context.transaction(hash);
  need(receipt&&transaction&&String(receipt.transactionHash).toLowerCase()===hash.toLowerCase()&&String(transaction.hash).toLowerCase()===hash.toLowerCase()
   &&String(receipt.status).toLowerCase()==='0x1'&&String(receipt.from).toLowerCase()===context.generation.payerAddress.toLowerCase()
   &&String(transaction.from).toLowerCase()===context.generation.payerAddress.toLowerCase()
   &&String(transaction.blockHash).toLowerCase()===String(receipt.blockHash).toLowerCase()
   &&integer(transaction.blockNumber)===integer(receipt.blockNumber),'u1_fee_rpc_receipt_binding_invalid');
  const units=integer(receipt.gasUsed),price=integer(receipt.effectiveGasPrice);
  need(units>0n&&price>0n&&body.selectedAction&&typeof body.selectedAction==='object','u1_fee_receipt_or_selection_missing');
  gas+=units*price;receipts.push(hash.toLowerCase());blocks.push(integer(receipt.blockNumber));selections.push({kind:action.kind,selected:normalize(body.selectedAction,context.generation.payerAddress)});
 }
 need(fixedCount===undefined?receipts.length>0:receipts.length===fixedCount,'u1_fee_exact_native_receipt_set_required');
 if(fixedCount===undefined){
  need(typeof context.rpc==='function','native_fee_raw_receipt_census_missing');
  const first=blocks.reduce((a,b)=>a<b?a:b),last=blocks.reduce((a,b)=>a>b?a:b),observed=new Set();
  for(const doc of context.rpc('eth_getTransactionReceipt')){const r=doc.result;if(!r||String(r.from).toLowerCase()!==context.generation.payerAddress.toLowerCase())continue;
   const number=integer(r.blockNumber);if(number<first||number>last)continue;
   need(typeof r.transactionHash==='string'&&seen.has(r.transactionHash.toLowerCase()),'native_fee_extra_participant_receipt');observed.add(r.transactionHash.toLowerCase());
  }
  need(observed.size===seen.size,'native_fee_raw_receipt_census_incomplete');
 }
 return {gasWei:gas.toString(),receipts,selections};
}
export const deriveU1ParticipantGas=context=>deriveParticipantGas(context,5);
export const deriveVerifiedParticipantGas=context=>deriveParticipantGas(context);
export function reconcileU1FinalStates(oldState,newState,oldGas,newGas){
 const clean=(state)=>{const copy=structuredClone(state),rows=copy.balances.filter(r=>r.account==='participant'&&r.assetId==='ETH');need(rows.length===1,'u1_fee_native_balance_scope_invalid');const native=integer(rows[0].amountUnits);rows[0].amountUnits='0';return {state:copy,native}};
 const before=clean(oldState),after=clean(newState);
 need(same(before.state,after.state),'u1_fee_non_native_final_state_changed');
 need(before.native+integer(oldGas)===after.native+integer(newGas),'u1_fee_native_delta_unexplained');
 return {oldNativeWei:before.native.toString(),newNativeWei:after.native.toString(),oldParticipantGasWei:oldGas,newParticipantGasWei:newGas};
}
export function assertU1FeeSemanticCore(candidate,approved,strictAssert){
 need(candidate.taskId==='U1'&&candidate.mode==='ranked'&&approved.taskId==='U1'&&approved.mode==='ranked','u1_fee_case_scope_invalid');
 const adjusted=structuredClone(candidate);adjusted.referencePath.finalStateSha256=approved.referencePath.finalStateSha256;const {caseHash,...core}=adjusted;adjusted.caseHash=taskCaseHash(core);strictAssert(adjusted,approved);
}
async function assertFeeReconciliation({root,candidate,approved,context,strictAssert,profilePolicy},generic){
 if(generic)assertNativeFeeSemanticCore(candidate,approved,strictAssert);else assertU1FeeSemanticCore(candidate,approved,strictAssert);
 const oldInput={repositoryRoot:root,identity:context.baseline.executionIdentity,executionIdentityHash:context.baseline.executionIdentityHash,taskCase:approved,evidence:approved.referencePath.evidence,profilePolicy};
 const newInput={repositoryRoot:root,identity:context.identity,executionIdentityHash:context.identityHash,taskCase:candidate,evidence:candidate.referencePath.evidence,profilePolicy};
 for(const input of [oldInput,newInput]){const proof=await verifyTaskReferenceEvidenceV2(input);need(proof.status==='verified','u1_fee_independent_reference_not_verified');}
 const old=await loadV2ReferenceContext(oldInput),fresh=await loadV2ReferenceContext(newInput);
 need(same(old.actions.map(a=>a.kind),fresh.actions.map(a=>a.kind)),'u1_fee_action_sequence_changed');
 need(same(old.envelope.initialState,fresh.envelope.initialState),'u1_fee_initial_state_changed');
 const derive=generic?deriveVerifiedParticipantGas:deriveU1ParticipantGas;
 const oldGas=derive(old),newGas=derive(fresh);
 need(oldGas.receipts.length===newGas.receipts.length,'native_fee_receipt_count_changed');
 need(same(oldGas.selections,newGas.selections),'u1_fee_native_economic_action_changed');
 const cutoff=c=>{const v=structuredClone(c.probe.capture.finalCutoff);delete v.blockNumber;delete v.blockHash;delete v.payerNativeWei;return v};
 if(!generic||candidate.taskId==='U1'||old.probe.capture.finalCutoff!==undefined||fresh.probe.capture.finalCutoff!==undefined){
  need(old.probe.capture.finalCutoff&&fresh.probe.capture.finalCutoff,'native_fee_cutoff_scope_changed');
  need(same(cutoff(old),cutoff(fresh)),'u1_fee_other_economic_effect_changed');
 }
 need(sha256CanonicalTaskJson(old.envelope.finalState)===approved.referencePath.finalStateSha256&&sha256CanonicalTaskJson(fresh.envelope.finalState)===candidate.referencePath.finalStateSha256,'u1_fee_final_state_hash_substituted');
 return { ...reconcileU1FinalStates(old.envelope.finalState,fresh.envelope.finalState,oldGas.gasWei,newGas.gasWei),oldReference:approved.referencePath.evidence,newReference:candidate.referencePath.evidence,oldReceipts:oldGas.receipts,newReceipts:newGas.receipts};
}

const FINITE_KEYS=new Set(['S1:ranked','S2:ranked','S3:ranked','S4:ranked','M1:ranked','M2:ranked','M3:ranked','M4:ranked','H1:ranked','H2:ranked','H3:ranked','U1:ranked','S1:training','M1:training','H1:training']);
export function assertNativeFeeSemanticCore(candidate,approved,strictAssert){
 need(FINITE_KEYS.has(`${candidate.taskId}:${candidate.mode}`)&&candidate.taskId===approved.taskId&&candidate.mode===approved.mode,'native_fee_case_scope_invalid');
 const adjusted=structuredClone(candidate);adjusted.referencePath.finalStateSha256=approved.referencePath.finalStateSha256;
 const {caseHash,...core}=adjusted;adjusted.caseHash=taskCaseHash(core);strictAssert(adjusted,approved);
}
export const assertU1FeeReconciliation=input=>assertFeeReconciliation(input,false);
export const assertNativeFeeReconciliation=input=>assertFeeReconciliation(input,true);
