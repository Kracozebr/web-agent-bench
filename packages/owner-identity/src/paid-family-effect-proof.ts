import { createHash } from 'node:crypto';
import { capturePaymentRecipient } from './capture-payment-recipient.js';
import { canonicalTaskJson, sha256CanonicalTaskJson } from './task-release.js';
import { validatePaidFamilyCapturePacket, type PaidDataCapturePacket } from './task-paid-data-capture-packet.js';
import type { ChainCapturePacket } from './task-chain-capture-packet.js';
import type { AdmittedActionCensus } from './bef-admitted-action-census.js';

type Json = Record<string, unknown>;
const TRANSFER='0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef';
const ADDRESS=/^0x[0-9a-f]{40}$/i, HASH=/^0x[0-9a-f]{64}$/i, UINT=/^(0|[1-9][0-9]*)$/;
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
type ProofPhase='paid_scope_or_snapshot_mismatch'|'paid_observer_role_invalid'|'paid_generation_binding_mismatch'|
  'paid_action_census_mismatch'|'paid_payment_binding_mismatch'|'paid_transaction_receipt_mismatch'|
  'paid_transfer_log_mismatch'|'paid_balance_history_mismatch'|'paid_cost_receipt_mismatch'|'paid_delivery_observation_mismatch';
export class PaidFamilyEffectProofUnavailable extends Error {
  constructor(readonly reasonCode:ProofPhase){super('PAID_FAMILY_EFFECTS_UNVERIFIED');}
}
function fail():never { throw new Error('PAID_FAMILY_EFFECTS_UNVERIFIED'); }
function object(value:unknown):value is Json { return !!value&&typeof value==='object'&&!Array.isArray(value); }
function rows(value:unknown):Json[] { if(!Array.isArray(value)||!value.every(object))fail();return value; }
function address(value:unknown):string { if(typeof value!=='string'||!ADDRESS.test(value))fail();return value.toLowerCase(); }
function hash(value:unknown):string { if(typeof value!=='string'||!HASH.test(value))fail();return value.toLowerCase(); }
function units(value:unknown):bigint { if(typeof value!=='string'||!UINT.test(value))fail();return BigInt(value); }
function one<T>(values:T[]):T { if(values.length!==1)fail();return values[0]!; }
const same=(a:unknown,b:unknown)=>canonicalTaskJson(a)===canonicalTaskJson(b);
function decodeTransfer(log:Json,tx:ChainCapturePacket['rpc']['transactions'][number],assets:ChainCapturePacket['rpc']['assets']) {
  if(!Array.isArray(log.topics)||log.topics[0]!==TRANSFER)return null;
  if(log.topics.length!==3||typeof log.data!=='string'||!/^0x[0-9a-f]{64}$/i.test(log.data)||
    !/^0x0{24}[0-9a-f]{40}$/i.test(String(log.topics[1]))||!/^0x0{24}[0-9a-f]{40}$/i.test(String(log.topics[2]))||
    log.removed!==false||hash(log.transactionHash)!==tx.hash||String(log.blockNumber)!==tx.blockNumber||
    hash(log.blockHash)!==tx.blockHash||String(log.transactionIndex)!==tx.transactionIndex)fail();
  const token=address(log.address),asset=one(assets.filter(item=>item.kind==='erc20'&&item.address?.toLowerCase()===token));
  return {assetId:asset.assetId,tokenAddress:token,transactionHash:tx.hash,blockNumber:tx.blockNumber,
    blockHash:tx.blockHash,logIndex:String(log.logIndex),from:'0x'+String(log.topics[1]).slice(-40).toLowerCase(),
    to:'0x'+String(log.topics[2]).slice(-40).toLowerCase(),amountUnits:BigInt(log.data).toString()};
}

/**
 * AICODE-NOTE: Call only after the chain-family parser has independently verified its
 * RPC interval, code identities, receipt/log normalization and per-transaction history.
 * This join checks actual raw facts; an "observed" label never supplies missing evidence.
 */
export function verifyPaidFamilyEffectsAgainstChain(paidValue:unknown,chain:ChainCapturePacket,census:AdmittedActionCensus):void {
  let phase:ProofPhase='paid_scope_or_snapshot_mismatch';
  try {
  const paid:PaidDataCapturePacket=validatePaidFamilyCapturePacket(paidValue);
  if(chain.schemaVersion!=='bts-chain-family-observation-capture/v1'||!same(paid.binding,chain.binding)||
    !same(paid.execution,chain.execution)||paid.closure.closureId!==chain.closure.closureId||
    paid.closure.actionCutoffSequence!==chain.closure.actionCutoffSequence||
    paid.closure.reconciledActionSequence!==chain.closure.reconciledActionSequence||!same(census.binding,paid.binding)||
    !same(census.execution,paid.execution)||!same(census.closure,paid.closure)||
    !same(paid.bef.before,paid.bef.after)||sha256CanonicalTaskJson(paid.bef.after)!==paid.bef.censusSha256)fail();
  const session=paid.bef.session;
  phase='paid_observer_role_invalid';
  if(session.currentUser!=='bef_observer'||session.sessionUser!=='bef_observer'||session.transactionReadOnly!=='on'||
    session.transactionIsolation!=='repeatable read'||session.superuser!==false||session.bypassRls!==false)fail();
  if(paid.coverage.status!=='observed')fail();
  phase='paid_generation_binding_mismatch';
  const before=paid.bef.before,generation=before.generation;
  if(!object(generation)||generation.env_id!==paid.execution.environmentId||generation.generation_id!==paid.execution.generationId||
    generation.status!=='active'||address(generation.payer_address)!==address(chain.rpc.participant)||
    String(generation.manifest_sha256)!==paid.execution.environmentManifestHash||
    String(generation.environment_manifest_sha256)!==paid.execution.environmentManifestHash||
    String(generation.chain_id)!==chain.rpc.localChainId||paid.rpc.localChainId!==chain.rpc.localChainId)fail();
  const payments=rows(before.payments),operations=rows(before.operations),costs=rows(before.costs),deliveries=rows(before.deliveries);
  phase='paid_action_census_mismatch';
  const payActions=paid.ownerActions.filter(action=>['pay','purchase'].includes(action.actionKind)&&action.receiptStatus==='observed');
  if(payments.length!==payActions.length||paid.rpc.paymentEffects.length!==payActions.length||
    new Set(payments.map(row=>row.payment_id)).size!==payments.length||
    new Set(payActions.map(action=>action.befOperationId)).size!==payActions.length)fail();
  const participant=address(chain.rpc.participant);
  for(const action of payActions){
    phase='paid_payment_binding_mismatch';
    const entry=one(census.entries.filter(item=>item.actionId===action.actionId));
    if(entry.actionKind!==action.actionKind||entry.transactionHash!==action.transactionHash||
      entry.actionSequence!==action.actionSequence||!same(entry.actionEvidence,action.actionEvidence))fail();
    const payment=one(payments.filter(row=>row.operation_id===action.befOperationId));
    const operation=one(operations.filter(row=>row.operation_id===action.befOperationId));
    const effect=one(paid.rpc.paymentEffects.filter(row=>row.operationId===action.befOperationId));
    const tx=one(chain.rpc.transactions.filter(row=>row.hash===hash(payment.transaction_hash)));
    if(!action.paymentProtocol||!object(action.paymentProtocol.acceptedTerms))fail();
    const recipient=address(capturePaymentRecipient(action.paymentProtocol,payment));
    const token=address(payment.asset_address),asset=one(chain.rpc.assets.filter(row=>row.kind==='erc20'&&row.address?.toLowerCase()===token));
    const amount=units(payment.amount_units),cost=one(costs.filter(row=>row.operation_id===action.befOperationId));
    if(effect.verification!=='observed'||!UUID.test(String(payment.payment_id))||!UUID.test(String(action.befOperationId))||
      effect.paymentId!==payment.payment_id||!same(effect.sourceOwnerActionIds,[action.actionId])||
      payment.env_id!==paid.execution.environmentId||payment.generation_id!==paid.execution.generationId||
      address(payment.payer_address)!==participant||payment.receipt_status!=='success'||units(payment.token_delta_units)!==amount||
      payment.network!=='eip155:'+chain.rpc.localChainId||recipient!==address(action.paymentProtocol.acceptedTerms.payTo)||
      units(action.paymentProtocol.amountUnits)!==amount||address(action.paymentProtocol.asset)!==token||
      action.transactionHash!==tx.hash||operation.transaction_hash!==tx.hash||operation.receipt_status!=='success'||
      operation.env_id!==paid.execution.environmentId||operation.generation_id!==paid.execution.generationId||
      operation.participant_id!==generation.participant_id||operation.operation_kind!=='purchase'||
      !['settled','delivered'].includes(String(operation.status))||operation.payment_response_mode!=='deferred_delivery'||
      String(operation.idempotency_key_sha256)!==createOperationKey(action.actionId))fail();
    const sender=address(payment.facilitator_address);
    phase='paid_transaction_receipt_mismatch';
    if(tx.status!=='success'||tx.from!==sender||tx.to!==token||units(tx.valueWei)!==0n||tx.chainId!==chain.rpc.localChainId||
      tx.input!==null||!object(effect.transaction)||!object(effect.receipt)||effect.transactionHash!==tx.hash||
      effect.transaction.hash!==tx.hash||effect.transaction.from!==tx.from||effect.transaction.to!==tx.to||
      effect.transaction.value!==tx.valueWei||effect.transaction.nonce!==tx.nonce||effect.transaction.blockNumber!==tx.blockNumber||
      effect.transaction.blockHash!==tx.blockHash||effect.transaction.inputSha256!==tx.inputSha256||
      effect.receipt.transactionHash!==tx.hash||effect.receipt.blockNumber!==tx.blockNumber||
      effect.receipt.blockHash!==tx.blockHash||effect.receipt.transactionIndex!==tx.transactionIndex||
      effect.receipt.status!==tx.status||effect.receipt.gasUsed!==tx.gasUsed||
      effect.receipt.effectiveGasPriceWei!==tx.effectiveGasPriceWei||effect.receipt.logsSha256!==tx.receiptLogsSha256)fail();
    phase='paid_transfer_log_mismatch';
    const transfers=tx.logs.map(log=>decodeTransfer(log,tx,chain.rpc.assets)).filter(value=>value!==null)
      .filter(value=>value.from===participant||value.to===participant);
    if(!same(transfers,effect.decodedTransfers)||
      transfers.filter(value=>value.assetId===asset.assetId&&value.from===participant&&value.to===recipient&&units(value.amountUnits)===amount).length!==1)fail();
    phase='paid_balance_history_mismatch';
    const history=one((chain.rpc.balanceHistory??[]).filter(row=>row.actionId===action.actionId&&row.transactionHash===tx.hash));
    const balances=rows(history.balances),payer=one(balances.filter(row=>row.account==='participant'&&row.assetId===asset.assetId)),
      payee=one(balances.filter(row=>address(row.account==='participant'?participant:row.account)===recipient&&row.assetId===asset.assetId));
    if(history.family!=='payment'||history.actionSequence!==action.actionSequence||history.blockNumber!==tx.blockNumber||history.blockHash!==tx.blockHash||
      units(payer.beforeValue)!==units(payment.payer_balance_before)||units(payer.afterValue)!==units(payment.payer_balance_after)||
      units(payee.beforeValue)!==units(payment.facilitator_balance_before)||units(payee.afterValue)!==units(payment.facilitator_balance_after)||
      units(payer.beforeValue)-units(payer.afterValue)!==amount||units(payee.afterValue)-units(payee.beforeValue)!==amount)fail();
    const gas=units(tx.gasUsed)*units(tx.effectiveGasPriceWei);
    phase='paid_cost_receipt_mismatch';
    if(cost.env_id!==paid.execution.environmentId||cost.generation_id!==paid.execution.generationId||cost.payer_role!=='facilitator'||
      address(cost.payer_address)!==sender||address(cost.transaction_from)!==sender||address(cost.receipt_from)!==sender||
      cost.receipt_status!=='success'||cost.transaction_hash!==tx.hash||String(cost.receipt_block_number)!==tx.blockNumber||
      cost.receipt_block_hash!==tx.blockHash||String(cost.gas_used)!==tx.gasUsed||String(cost.effective_gas_price_wei)!==tx.effectiveGasPriceWei||
      units(cost.gas_cost_wei)!==gas||units(tx.gasCostWei)!==gas||cost.manifest_sha256!==paid.execution.environmentManifestHash)fail();
    units(cost.modeled_gas_fee_usdc_units);
  }
  phase='paid_delivery_observation_mismatch';
  for(const delivery of deliveries){
    const retrievals=paid.ownerActions.filter(action=>action.actionKind==='retrieve'&&action.receiptStatus==='observed'&&action.befOperationId===delivery.operation_id);
    if(retrievals.length<1||retrievals.some(action=>!action.retrievedContent||action.retrievedContent.resourceId!==delivery.resource_id||
      action.retrievedContent.contentSha256!==delivery.content_sha256||String(action.retrievedContent.byteCount)!==String(delivery.byte_count))||
      delivery.env_id!==paid.execution.environmentId||delivery.generation_id!==paid.execution.generationId)fail();
  }
  } catch {
    // AICODE-NOTE: Persist a finite proof phase; never propagate raw values or provider errors.
    throw new PaidFamilyEffectProofUnavailable(phase);
  }
}

function createOperationKey(actionId:string):string { return createHash('sha256').update('task-action-'+actionId).digest('hex'); }
