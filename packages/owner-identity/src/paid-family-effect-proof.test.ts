import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';
import { validPaidDataCapturePacket } from './task-paid-data-capture-packet.fixture.js';
import { sha256CanonicalTaskJson } from './task-release.js';
import { verifyPaidFamilyEffectsAgainstChain } from './paid-family-effect-proof.js';
import type { ChainCapturePacket } from './task-chain-capture-packet.js';
import type { AdmittedActionCensus } from './bef-admitted-action-census.js';

// Pure join fixture only: common-census and full RPC/manifest parsers have separate
// adversarial tests. No generated transaction or observer row is runtime evidence.
function fixture(){
  const paid=validPaidDataCapturePacket();paid.schemaVersion='bts-paid-family-observation-capture/v1';
  const censusRows=paid.bef.after as Record<string,any>;
  const participant='0x'+'1'.repeat(40),token='0x'+'2'.repeat(40),recipient='0x'+'3'.repeat(40);
  const transactions:any[]=[],balanceHistory:any[]=[];
  for(let i=0;i<censusRows.payments.length;i++){
    const payment=censusRows.payments[i],effect=paid.rpc.paymentEffects[i]!,action=paid.ownerActions.find(row=>row.actionKind==='pay'&&row.befOperationId===payment.operation_id)!;
    const amount=BigInt(payment.amount_units),payerBefore=900000n-BigInt(i)*amount,payeeBefore=BigInt(i)*amount;
    Object.assign(payment,{payer_balance_before:String(payerBefore),payer_balance_after:String(payerBefore-amount),
      facilitator_balance_before:String(payeeBefore),facilitator_balance_after:String(payeeBefore+amount)});
    const blockNumber=String(102+i),blockHash='0x'+(i?'e':'c').repeat(64),transactionHash=String(payment.transaction_hash);
    const log={address:token,topics:['0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef',
      '0x'+participant.slice(2).padStart(64,'0'),'0x'+recipient.slice(2).padStart(64,'0')],
      data:'0x'+amount.toString(16).padStart(64,'0'),blockNumber,blockHash,transactionHash,
      transactionIndex:'0',logIndex:'0',removed:false};
    const tx={hash:transactionHash,from:recipient,to:token,nonce:String(i+1),valueWei:'0',gasLimit:'100000',blockNumber,blockHash,
      transactionIndex:'0',chainId:'8453',status:'success',gasUsed:'50000',effectiveGasPriceWei:'1000000000',
      gasCostWei:'50000000000000',input:null,inputSha256:'a'.repeat(64),receiptLogsSha256:'b'.repeat(64),logs:[log]};
    transactions.push(tx);
    Object.assign(effect,{paymentId:payment.payment_id,sourceOwnerActionIds:[action.actionId],verification:'observed',
      transaction:{hash:transactionHash,from:tx.from,to:tx.to,nonce:tx.nonce,value:'0',blockNumber,blockHash,inputSha256:tx.inputSha256},
      receipt:{transactionHash,transactionIndex:'0',blockNumber,blockHash,status:'success',gasUsed:tx.gasUsed,
        effectiveGasPriceWei:tx.effectiveGasPriceWei,logsSha256:tx.receiptLogsSha256},
      decodedTransfers:[{assetId:'USDC',tokenAddress:token,transactionHash,blockNumber,blockHash,logIndex:'0',
        from:participant,to:recipient,amountUnits:String(amount)}]});
    Object.assign(censusRows.costs[i],{receipt_block_number:blockNumber,receipt_block_hash:blockHash});
    balanceHistory.push({family:'payment',actionId:action.actionId,actionSequence:action.actionSequence,transactionHash,blockNumber,blockHash,
      balances:[{account:'participant',assetId:'USDC',beforeValue:String(payerBefore),afterValue:String(payerBefore-amount)},
        {account:recipient,assetId:'USDC',beforeValue:String(payeeBefore),afterValue:String(payeeBefore+amount)}]});
  }
  paid.bef.before=structuredClone(paid.bef.after);paid.bef.censusSha256=sha256CanonicalTaskJson(paid.bef.after);
  const chain={schemaVersion:'bts-chain-family-observation-capture/v1',binding:paid.binding,execution:paid.execution,
    closure:{closureId:paid.closure.closureId,actionCutoffSequence:5,reconciledActionSequence:5},
    rpc:{localChainId:'8453',participant,assets:[{assetId:'USDC',kind:'erc20',address:token,codeHash:'f'.repeat(64)}],transactions,balanceHistory}} as unknown as ChainCapturePacket;
  const census={binding:paid.binding,execution:paid.execution,closure:paid.closure,entries:paid.ownerActions.map(action=>({
    actionId:action.actionId,actionKind:action.actionKind,transactionHash:action.transactionHash,
    actionSequence:action.actionSequence,actionEvidence:action.actionEvidence}))} as unknown as AdmittedActionCensus;
  return {paid,chain,census};
}

test('paid facts join actual receipt/log/cost/history values without taking observed labels as evidence',()=>{
  const value=fixture();assert.doesNotThrow(()=>verifyPaidFamilyEffectsAgainstChain(value.paid,value.chain,value.census));
});

for(const [name,alter] of Object.entries({
  missing_receipt:(v:ReturnType<typeof fixture>)=>{delete v.paid.rpc.paymentEffects[0]!.receipt;},
  forged_transfer:(v:ReturnType<typeof fixture>)=>{(v.paid.rpc.paymentEffects[0]!.decodedTransfers as any[])[0].amountUnits='1';},
  missing_history:(v:ReturnType<typeof fixture>)=>{v.chain.rpc.balanceHistory=[];},
  invented_balance:(v:ReturnType<typeof fixture>)=>{(v.paid.bef.after as any).payments[0].payer_balance_before='999999';v.paid.bef.before=structuredClone(v.paid.bef.after);v.paid.bef.censusSha256=sha256CanonicalTaskJson(v.paid.bef.after);},
  wrong_recipient:(v:ReturnType<typeof fixture>)=>{v.paid.ownerActions[0]!.paymentProtocol!.paymentRecipient='0x'+'4'.repeat(40);},
  altered_gas:(v:ReturnType<typeof fixture>)=>{v.chain.rpc.transactions[0]!.gasUsed='50001';},
  mutable_census:(v:ReturnType<typeof fixture>)=>{(v.paid.bef.before as any).payments.pop();},
  hidden_owner_payment:(v:ReturnType<typeof fixture>)=>{v.census.entries.splice(0,1);},
  wrong_operation_key:(v:ReturnType<typeof fixture>)=>{(v.paid.bef.after as any).operations[0].idempotency_key_sha256=createHash('sha256').update('another-operation').digest('hex');v.paid.bef.before=structuredClone(v.paid.bef.after);v.paid.bef.censusSha256=sha256CanonicalTaskJson(v.paid.bef.after);},
  wrong_role:(v:ReturnType<typeof fixture>)=>{v.paid.bef.session.transactionReadOnly='off';},
  unknown_effect:(v:ReturnType<typeof fixture>)=>{v.paid.rpc.paymentEffects[0]!.verification='unknown';},
})){test('paid effect proof rejects '+name+' despite retained observed coverage',()=>{
  const value=fixture();alter(value);assert.throws(()=>verifyPaidFamilyEffectsAgainstChain(value.paid,value.chain,value.census));
});}
