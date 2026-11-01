import test from 'node:test';
import assert from 'node:assert/strict';
import {deriveU1ParticipantGas,deriveVerifiedParticipantGas,reconcileU1FinalStates,assertNativeFeeSemanticCore} from './u1-fee-reconciliation.mjs';
const payer='0x'+'1'.repeat(40),other='0x'+'2'.repeat(40),block='0x'+'b'.repeat(64);
function context(){const hashes=Array.from({length:5},(_,i)=>'0x'+String(i+1).repeat(64));return {generation:{payerAddress:payer},actions:['transfer','transfer','approve','swap','unwrap'].map((kind,i)=>({kind,operationId:String(i)})),action(a){return {outcome:'success',transaction:{hash:hashes[Number(a.operationId)]},selectedAction:{kind:a.kind,recipient:payer}}},receipt(h){return {transactionHash:h,status:'0x1',from:payer,blockHash:block,blockNumber:'123',gasUsed:'2',effectiveGasPrice:'3'}},transaction(h){return {hash:h,from:payer,blockHash:block,blockNumber:'123'}},rpc(){return this.actions.map(a=>({result:this.receipt(this.action(a).transaction.hash)}))}};}
const state=n=>({balances:[{account:'participant',assetId:'ETH',amountUnits:String(n)},{account:'participant',assetId:'USDC',amountUnits:'90'}],allowances:[{owner:'participant',tokenAssetId:'USDC',spender:other,amountUnits:'0'}],deliveredComponentIds:['resource'],fulfilledObligationIds:['payout']});
test('gas comes from all five bound RPC receipts and exact native equation has no tolerance',()=>{
 assert.equal(deriveU1ParticipantGas(context()).gasWei,'30');
 assert.deepEqual(reconcileU1FinalStates(state(100),state(105),'30','25'),{oldNativeWei:'100',newNativeWei:'105',oldParticipantGasWei:'30',newParticipantGasWei:'25'});
 assert.throws(()=>reconcileU1FinalStates(state(100),state(106),'30','25'),/unexplained/);
});
test('missing, duplicate, wrong-sender or forged gas observations cannot qualify',()=>{
 for(const modify of [c=>{c.actions.pop()},c=>{c.action=()=>({outcome:'success',transaction:{hash:'0x'+'1'.repeat(64)},selectedAction:{}})},
 c=>{c.receipt=()=>undefined},c=>{const old=c.receipt;c.receipt=h=>({...old(h),from:other})},
 c=>{const old=c.receipt;c.receipt=h=>({...old(h),status:'0x0'})},c=>{const old=c.receipt;c.receipt=h=>({...old(h),effectiveGasPrice:undefined})},
 c=>{const old=c.transaction;c.transaction=h=>({...old(h),hash:'0x'+'f'.repeat(64)})}]){const c=context();modify(c);assert.throws(()=>deriveU1ParticipantGas(c));}
});
test('token, payout, allowance, scope and delivery changes are never explained by gas',()=>{
 for(const mutate of [s=>{s.balances[1].amountUnits='89'},s=>{s.allowances[0].amountUnits='1'},s=>{s.deliveredComponentIds=[]},s=>{s.fulfilledObligationIds=[]},s=>{s.balances.push({...s.balances[0]})}]){const fresh=state(105);mutate(fresh);assert.throws(()=>reconcileU1FinalStates(state(100),fresh,'30','25'));}
 for(const unknown of [undefined,'','unknown','-1'])assert.throws(()=>reconcileU1FinalStates(state(100),state(105),unknown,'25'));
});
test('generic native reconciliation requires a positive complete set while legacy U1 still requires five',()=>{
 const m3=context();m3.actions=m3.actions.slice(2);
 assert.equal(deriveVerifiedParticipantGas(m3).gasWei,'18');
 assert.throws(()=>deriveU1ParticipantGas(m3));
 const empty=context();empty.actions=[];assert.throws(()=>deriveVerifiedParticipantGas(empty));
 const paid=context();paid.actions=paid.actions.map(a=>({...a,kind:'pay'}));assert.throws(()=>deriveVerifiedParticipantGas(paid));
});
test('generic scope does not include future tasks or unsupported training types',()=>{
 for(const task of [{taskId:'FUTURE',mode:'ranked'},{taskId:'S2',mode:'training'},{taskId:'U1',mode:'training'}])assert.throws(()=>assertNativeFeeSemanticCore(task,task,()=>{}),/case_scope/);
});
test('generic receipt census covers sets of one, three, five and six without accepting extra or unknown actions',()=>{
 for(const count of [1,3,5,6]){const c=context();if(count===6)c.actions.push({kind:'transfer',operationId:'5'});else c.actions=c.actions.slice(0,count);
  if(count===6){const read=c.action;c.action=a=>a.operationId==='5'?{outcome:'success',transaction:{hash:'0x'+'6'.repeat(64)},selectedAction:{kind:'transfer',recipient:payer}}:read(a)}
  assert.equal(deriveVerifiedParticipantGas(c).receipts.length,count);
 }
 const revoke=context();revoke.actions=[{kind:'revoke',operationId:'0'}];assert.equal(deriveVerifiedParticipantGas(revoke).receipts.length,1);
 const extra=context(),rpc=extra.rpc;extra.rpc=function(){return [...rpc.call(this),{result:{...this.receipt('0x'+'a'.repeat(64))}}]};assert.throws(()=>deriveVerifiedParticipantGas(extra),/extra_participant/);
 const missing=context();missing.rpc=()=>[];assert.throws(()=>deriveVerifiedParticipantGas(missing),/incomplete/);
 const unknown=context();unknown.actions[0].kind='future_native';assert.throws(()=>deriveVerifiedParticipantGas(unknown),/unrecognized/);
});
