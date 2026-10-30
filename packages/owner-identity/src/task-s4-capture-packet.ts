import { createHash } from 'node:crypto';
import { canonicalTaskJson } from './task-release.js';
import type { EvidenceReference } from './task-release.js';

const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const TASK_OPERATION_ID=/^[A-Za-z0-9_-]{12,128}$/;
const HASH=/^[0-9a-f]{64}$/i;
const TX=/^0x[0-9a-f]{64}$/i;
const ADDRESS=/^0x[0-9a-f]{40}$/i;
const UINT=/^(?:0|[1-9][0-9]{0,77})$/;
const DECIMAL=/^(?:0|[1-9][0-9]*)$/;
const BOUNDARY='actual_tool_http_x402_local_evm_application_store' as const;
const ROOT='artifacts/runs/owner-identity-bef-task-coordinator/';
const PREPARATION_PREFIX=`${ROOT}preparation/`;
const ACTION_PREFIX=`${ROOT}action/`;
const CAPTURE_PREFIX=`${ROOT}observation/`;
const MAX_PACKET_BYTES=8*1024*1024;
const MAX_ACTIONS=256;
const MAX_ROWS=2048;
const OBSERVATION_DOMAINS=['transfers','payments','stateMutations','finalStates','allowanceChanges','allowanceUses',
  'answers','selections','deliveries','trades','conversions','expenses'] as const;
const COVERAGE_DOMAINS=['transfers','payments','stateMutations','balances','allowances','answers','selections','deliveries',
  'trades','conversions','expenses'] as const;

type JsonRecord=Record<string,unknown>;
export type S4CaptureBundleView={
  binding:Record<string,unknown>;
  closure:Record<string,unknown>;
  execution:Record<string,unknown>;
  observations:Record<string,unknown>;
};

export class S4CapturePacketError extends Error {
  constructor(readonly code:'packet_invalid'|'binding_mismatch'|'child_reference_invalid'|'observation_mismatch'|'packet_too_large') {
    super(`S4 capture packet ${code}`);
    this.name='S4CapturePacketError';
  }
}

function fail(code:S4CapturePacketError['code']):never { throw new S4CapturePacketError(code); }
function isRecord(value:unknown):value is JsonRecord {
  return Boolean(value&&typeof value==='object'&&!Array.isArray(value)&&
    (Object.getPrototypeOf(value)===Object.prototype||Object.getPrototypeOf(value)===null));
}
function exactKeys(value:JsonRecord,keys:readonly string[]):boolean {
  return Object.keys(value).sort().join(',')===[...keys].sort().join(',');
}
function uint(value:unknown):value is string { return typeof value==='string'&&UINT.test(value); }
function safeSequence(value:unknown):number|null {
  if(typeof value!=='number'&&!uint(value))return null;
  try { const n=BigInt(value);return n>=0n&&n<=BigInt(Number.MAX_SAFE_INTEGER)?Number(n):null; } catch { return null; }
}
function validHash(value:unknown):value is string { return typeof value==='string'&&HASH.test(value); }
function validTx(value:unknown):value is string { return typeof value==='string'&&TX.test(value); }
function validAddress(value:unknown):value is string { return typeof value==='string'&&ADDRESS.test(value); }
function same(left:unknown,right:unknown):boolean { return canonicalTaskJson(left)===canonicalTaskJson(right); }
function canonicalDigest(value:unknown):string { return createHash('sha256').update(canonicalTaskJson(value)).digest('hex'); }
function validEvidence(value:unknown,prefix:string):value is EvidenceReference {
  return isRecord(value)&&exactKeys(value,['path','sha256','boundary'])&&value.boundary===BOUNDARY&&
    typeof value.path==='string'&&value.path.startsWith(prefix)&&value.path.length<=512&&
    /^(?![A-Za-z]:)(?!\/)(?!.*(?:^|\/)\.\.(?:\/|$))[A-Za-z0-9._/-]{1,512}$/.test(value.path)&&
    !value.path.includes('\\')&&!value.path.includes('\0')&&value.path.split('/').every((part)=>part!==''&&part!=='.'&&part!=='..')&&validHash(value.sha256);
}
function requireRecord(value:unknown,keys:readonly string[],code:S4CapturePacketError['code']='packet_invalid'):JsonRecord {
  if(!isRecord(value)||!exactKeys(value,keys))fail(code);
  return value;
}
function addressEquals(left:unknown,right:unknown):boolean {
  return typeof left==='string'&&typeof right==='string'&&left.toLowerCase()===right.toLowerCase();
}

const BINDING_KEYS=['ownerId','agentId','runId','environmentId','releaseIdentity','manifestHash','caseId','caseHash','rubricHash','taskId'] as const;
const OBSERVATIONS_KEYS=['schemaVersion','binding','coveredThroughSequence','captureEvidence','coverage',...OBSERVATION_DOMAINS] as const;
const PACKET_KEYS=['schemaVersion','classification','binding','closure','execution','preparation','ownerActions','bef','rpc'] as const;

function validateBinding(binding:JsonRecord):void {
  if(!exactKeys(binding,BINDING_KEYS)||!UUID.test(String(binding.ownerId))||!UUID.test(String(binding.agentId))||
      !UUID.test(String(binding.runId))||typeof binding.environmentId!=='string'||binding.environmentId.length<1||binding.environmentId.length>128||
      typeof binding.releaseIdentity!=='string'||binding.releaseIdentity.length<1||binding.releaseIdentity.length>128||
      !validHash(binding.manifestHash)||typeof binding.caseId!=='string'||binding.caseId.length<1||binding.caseId.length>128||
      !validHash(binding.caseHash)||!validHash(binding.rubricHash)||binding.taskId!=='S4')fail('binding_mismatch');
}

function validateBundle(bundle:S4CaptureBundleView):{cutoff:number;reconciled:number} {
  const binding=requireRecord(bundle.binding,BINDING_KEYS,'binding_mismatch');
  validateBinding(binding);
  const closure=requireRecord(bundle.closure,['closureId','operationId','payloadHash','reason','actionCutoffSequence','reconciledActionSequence'],'binding_mismatch');
  const cutoff=safeSequence(closure.actionCutoffSequence),reconciled=safeSequence(closure.reconciledActionSequence);
  if(!UUID.test(String(closure.closureId))||(closure.operationId!==null&&
      (typeof closure.operationId!=='string'||!TASK_OPERATION_ID.test(closure.operationId)))||!validHash(closure.payloadHash)||
      !['agent_finish','task_deadline','run_deadline'].includes(String(closure.reason))||cutoff===null||reconciled===null||cutoff>MAX_ACTIONS||reconciled<cutoff)fail('binding_mismatch');
  const execution=requireRecord(bundle.execution,['preparationId','leaseId','generationId','environmentManifestHash','applicationSourceHash','executionIdentityHash','initialStateSha256'],'binding_mismatch');
  if(!UUID.test(String(execution.preparationId))||!UUID.test(String(execution.leaseId))||!UUID.test(String(execution.generationId))||
      !validHash(execution.environmentManifestHash)||!validHash(execution.applicationSourceHash)||!validHash(execution.executionIdentityHash)||!validHash(execution.initialStateSha256))fail('binding_mismatch');
  const observations=requireRecord(bundle.observations,OBSERVATIONS_KEYS,'observation_mismatch');
  if(observations.schemaVersion!=='bts-task-observations/v1'||!same(observations.binding,binding)||
      safeSequence(observations.coveredThroughSequence)===null||!isRecord(observations.coverage)||
      Object.entries(observations.coverage).some(([domain,status])=>!COVERAGE_DOMAINS.includes(domain as typeof COVERAGE_DOMAINS[number])||
        !['complete','incomplete','contradictory'].includes(String(status)))||
      !OBSERVATION_DOMAINS.every((domain)=>Array.isArray(observations[domain])))fail('observation_mismatch');
  return {cutoff,reconciled};
}

function validateCheckpoint(value:unknown):JsonRecord {
  const checkpoint=requireRecord(value,['blockNumber','blockHash','parentHash','balances','allowances','participantTransactionCount']);
  if(!DECIMAL.test(String(checkpoint.blockNumber))||!validTx(checkpoint.blockHash)||!validTx(checkpoint.parentHash)||
      !DECIMAL.test(String(checkpoint.participantTransactionCount))||!Array.isArray(checkpoint.balances)||checkpoint.balances.length>256||
      !Array.isArray(checkpoint.allowances)||checkpoint.allowances.length>256)fail('packet_invalid');
  for(const item of checkpoint.balances){
    const balance=requireRecord(item,['account','assetId','amountUnits']);
    if(typeof balance.account!=='string'||typeof balance.assetId!=='string'||!uint(balance.amountUnits))fail('packet_invalid');
  }
  for(const item of checkpoint.allowances){
    const allowance=requireRecord(item,['owner','tokenAssetId','spender','amountUnits']);
    if(typeof allowance.owner!=='string'||typeof allowance.tokenAssetId!=='string'||typeof allowance.spender!=='string'||!validAddress(allowance.spender)||!uint(allowance.amountUnits))fail('packet_invalid');
  }
  return checkpoint;
}

function validateReceipt(value:unknown):JsonRecord {
  const receipt=requireRecord(value,['transactionHash','from','to','blockNumber','blockHash','transactionIndex','status','gasUsed','effectiveGasPriceWei','gasCostWei','logsSha256']);
  if(!validTx(receipt.transactionHash)||!validAddress(receipt.from)||(receipt.to!==null&&!validAddress(receipt.to))||!DECIMAL.test(String(receipt.blockNumber))||
      !validTx(receipt.blockHash)||!DECIMAL.test(String(receipt.transactionIndex))||!['success','reverted'].includes(String(receipt.status))||
      !uint(receipt.gasUsed)||!uint(receipt.effectiveGasPriceWei)||!uint(receipt.gasCostWei)||!validHash(receipt.logsSha256))fail('packet_invalid');
  if(BigInt(receipt.gasUsed as string)*BigInt(receipt.effectiveGasPriceWei as string)!==BigInt(receipt.gasCostWei as string))fail('packet_invalid');
  return receipt;
}

function validateTransaction(value:unknown):JsonRecord {
  const tx=requireRecord(value,['hash','from','to','nonce','input','valueWei','gasLimit','blockNumber','blockHash','transactionIndex','chainId']);
  if(!validTx(tx.hash)||!validAddress(tx.from)||(tx.to!==null&&!validAddress(tx.to))||!uint(tx.nonce)||
      typeof tx.input!=='string'||!/^0x(?:[0-9a-f]{2})*$/i.test(tx.input)||!uint(tx.valueWei)||!uint(tx.gasLimit)||
      !DECIMAL.test(String(tx.blockNumber))||!validTx(tx.blockHash)||!DECIMAL.test(String(tx.transactionIndex))||!DECIMAL.test(String(tx.chainId)))fail('packet_invalid');
  return tx;
}

function validateLog(value:unknown,kind:'approval'|'transfer'):JsonRecord {
  const keys=kind==='approval'?['tokenAddress','owner','spender','amountUnits','transactionHash','blockNumber','blockHash','transactionIndex','logIndex']:
    ['tokenAddress','from','to','amountUnits','transactionHash','blockNumber','blockHash','transactionIndex','logIndex'];
  const log=requireRecord(value,keys);
  if(!validAddress(log.tokenAddress)||!validAddress(kind==='approval'?log.owner:log.from)||
      !validAddress(kind==='approval'?log.spender:log.to)||!uint(log.amountUnits)||!validTx(log.transactionHash)||
      !DECIMAL.test(String(log.blockNumber))||!validTx(log.blockHash)||!DECIMAL.test(String(log.transactionIndex))||!DECIMAL.test(String(log.logIndex)))fail('packet_invalid');
  return log;
}

function validatePacketShape(packet:JsonRecord):{
  preparation:JsonRecord;actions:JsonRecord[];bef:JsonRecord;rpc:JsonRecord;fixtureEvidence:EvidenceReference;baselineEvidence:EvidenceReference;
  receipts:Map<string,JsonRecord>;operations:Map<string,JsonRecord>;selectedByOperation:Map<string,JsonRecord>;
  approvals:JsonRecord[];transfers:JsonRecord[];payer:string;generationId:string;environmentId:string;
} {
  requireRecord(packet,PACKET_KEYS);
  if(packet.schemaVersion!=='bts-s4-run-observation-capture/v1'||packet.classification!=='run_bound_observations_candidate_not_grade')fail('packet_invalid');
  const binding=requireRecord(packet.binding,BINDING_KEYS);validateBinding(binding);
  const closure=requireRecord(packet.closure,['closureId','actionCutoffSequence','reconciledActionSequence']);
  const execution=requireRecord(packet.execution,['preparationId','leaseId','generationId','environmentId','environmentManifestHash','applicationSourceHash','executionIdentityHash','initialStateSha256']);
  const preparation=requireRecord(packet.preparation,['fixtureEvidence','baselineEvidence','baselineBlockNumber','baselineBlockHash','fixtureOperationId',
    'fixtureTransactionHash','fixtureBlockNumber','fixtureBlockHash','fixtureProofSha256']);
  const actions=packet.ownerActions;
  const bef=requireRecord(packet.bef,['session','before','after','censusSha256']);
  const rpc=requireRecord(packet.rpc,['localChainId','baseline','final','intervalBlocks','approvals','transfers','receipts','responseHashes']);
  if(!Array.isArray(actions)||actions.length>MAX_ACTIONS||!validHash(bef.censusSha256)||
      execution.environmentId!==binding.environmentId||
      !UUID.test(String(execution.preparationId))||!UUID.test(String(execution.leaseId))||!UUID.test(String(execution.generationId))||
      !validHash(execution.applicationSourceHash)||!validHash(execution.executionIdentityHash)||!validHash(execution.initialStateSha256))fail('packet_invalid');
  const fixtureEvidence=preparation.fixtureEvidence,baselineEvidence=preparation.baselineEvidence;
  if(!validEvidence(fixtureEvidence,PREPARATION_PREFIX)||!validEvidence(baselineEvidence,PREPARATION_PREFIX)||
      fixtureEvidence.path===baselineEvidence.path||
      !DECIMAL.test(String(preparation.baselineBlockNumber))||!validTx(preparation.baselineBlockHash)||
      !UUID.test(String(preparation.fixtureOperationId))||!validTx(preparation.fixtureTransactionHash)||
      !DECIMAL.test(String(preparation.fixtureBlockNumber))||!validTx(preparation.fixtureBlockHash)||!validHash(preparation.fixtureProofSha256)||
      BigInt(preparation.fixtureBlockNumber as string)>BigInt(preparation.baselineBlockNumber as string)||
      (preparation.fixtureBlockNumber===preparation.baselineBlockNumber&&preparation.fixtureBlockHash.toLowerCase()!==preparation.baselineBlockHash.toLowerCase()))fail('child_reference_invalid');
  const packetCutoff=safeSequence(closure.actionCutoffSequence),packetReconciled=safeSequence(closure.reconciledActionSequence);
  if(!exactKeys(closure,['closureId','actionCutoffSequence','reconciledActionSequence'])||!UUID.test(String(closure.closureId))||
      packetCutoff===null||packetReconciled===null||packetCutoff>MAX_ACTIONS||packetReconciled<packetCutoff||
      !exactKeys(execution,['preparationId','leaseId','generationId','environmentId','environmentManifestHash','applicationSourceHash','executionIdentityHash','initialStateSha256'])||
      !validHash(execution.environmentManifestHash))fail('binding_mismatch');
  const session=requireRecord(bef.session,['currentUser','sessionUser','transactionReadOnly','transactionIsolation','superuser','bypassRls']);
  if(session.currentUser!=='bef_observer'||session.sessionUser!=='bef_observer'||session.transactionReadOnly!=='on'||
      session.transactionIsolation!=='repeatable read'||session.superuser!==false||session.bypassRls!==false||
      !isRecord(bef.before)||!isRecord(bef.after)||!same(bef.before,bef.after)||canonicalDigest(bef.before).toLowerCase()!==String(bef.censusSha256).toLowerCase())fail('packet_invalid');
  const census=requireRecord(bef.before,['generation','operations','selectedExecutions','selectedEvents','costs','paymentsCount','deliveriesCount','counts']);
  const generation=requireRecord(census.generation,['generation_id','env_id','participant_id','payer_address','manifest_sha256','status','chain_id','environment_manifest_sha256']);
  if(generation.generation_id!==execution.generationId||generation.env_id!==binding.environmentId||generation.status!=='active'||
      !UUID.test(String(generation.participant_id))||!validAddress(generation.payer_address)||
      generation.manifest_sha256!==execution.environmentManifestHash||generation.environment_manifest_sha256!==execution.environmentManifestHash||
      !DECIMAL.test(String(generation.chain_id))||!Array.isArray(census.operations)||!Array.isArray(census.selectedExecutions)||
      !Array.isArray(census.selectedEvents)||!Array.isArray(census.costs)||census.operations.length>MAX_ROWS||census.selectedExecutions.length>MAX_ROWS||
      census.selectedEvents.length>MAX_ROWS||census.costs.length>MAX_ROWS||census.paymentsCount!=='0'||census.deliveriesCount!=='0')fail('packet_invalid');
  const counts=requireRecord(census.counts,['operations','selectedExecutions','selectedEvents','costs']);
  if(counts.operations!==String(census.operations.length)||counts.selectedExecutions!==String(census.selectedExecutions.length)||
      counts.selectedEvents!==String(census.selectedEvents.length)||counts.costs!==String(census.costs.length))fail('packet_invalid');
  const operations=new Map<string,JsonRecord>();
  for(const value of census.operations){
    const op=requireRecord(value,['operation_id','env_id','generation_id','participant_id','idempotency_key_sha256','request_sha256','operation_kind','status',
      'receipt_status','transaction_hash','response_sha256','started_at','completed_at']);
    const readKind=['catalog','offer'].includes(String(op.operation_kind));
    if(!UUID.test(String(op.operation_id))||operations.has(String(op.operation_id))||op.env_id!==binding.environmentId||op.generation_id!==execution.generationId||
        op.participant_id!==generation.participant_id||!validHash(op.idempotency_key_sha256)||!validHash(op.request_sha256)||
        (!['approve','transfer','catalog','offer'].includes(String(op.operation_kind)))||
        (readKind?(op.status!=='accepted'||op.receipt_status!=='not_submitted'||op.transaction_hash!==null||
            typeof op.response_sha256!=='string'||!validHash(op.response_sha256)):
          (!['settled','reverted'].includes(String(op.status))||!['success','reverted'].includes(String(op.receipt_status))||!validTx(op.transaction_hash)))||
        (op.response_sha256!==null&&!validHash(op.response_sha256))||typeof op.started_at!=='string'||typeof op.completed_at!=='string')fail('packet_invalid');
    operations.set(String(op.operation_id),op);
  }
  const selectedByOperation=new Map<string,JsonRecord>();
  for(const value of census.selectedExecutions){
    const selected=requireRecord(value,['operation_id','env_id','generation_id','action_kind','selected_action','prestate','transaction_intent','measurement',
      'transaction_hash','outcome','reason_code','completed_at']);
    if(!UUID.test(String(selected.operation_id))||selectedByOperation.has(String(selected.operation_id))||selected.env_id!==binding.environmentId||
        selected.generation_id!==execution.generationId||!['approve','transfer'].includes(String(selected.action_kind))||
        !isRecord(selected.selected_action)||!isRecord(selected.prestate)||!isRecord(selected.transaction_intent)||!isRecord(selected.measurement)||
        !validTx(selected.transaction_hash)||!['success','reverted'].includes(String(selected.outcome))||
        (selected.reason_code!==null&&typeof selected.reason_code!=='string')||typeof selected.completed_at!=='string')fail('packet_invalid');
    selectedByOperation.set(String(selected.operation_id),selected);
  }
  const mutableOperationIds=new Set([...operations].filter(([,op])=>['approve','transfer'].includes(String(op.operation_kind))).map(([id])=>id));
  if(selectedByOperation.size!==mutableOperationIds.size||[...mutableOperationIds].some((id)=>!selectedByOperation.has(id))||
      [...operations].some(([id,op])=>['catalog','offer'].includes(String(op.operation_kind))&&selectedByOperation.has(id)))fail('packet_invalid');
  const eventKinds=new Map<string,string[]>();
  const eventsByOperation=new Map<string,JsonRecord[]>();
  const eventIds=new Set<string>();
  const eventSequences=new Set<string>();
  for(const value of census.selectedEvents){
    const event=requireRecord(value,['eventId','eventSequence','operationId','eventKind','transactionHash','eventJsonSha256','eventPayload']);
    const id=String(event.operationId),kind=String(event.eventKind),op=operations.get(id);
    if(!op||!['approve','transfer'].includes(String(op.operation_kind))||!UUID.test(String(event.eventId))||eventIds.has(String(event.eventId))||!DECIMAL.test(String(event.eventSequence))||
        eventSequences.has(String(event.eventSequence))||!['selected_action_bound','prestate_observed','original_tx_hash_bound','receipt_finalized'].includes(kind)||
        (event.transactionHash!==null&&!validTx(event.transactionHash))||!validHash(event.eventJsonSha256)||!isRecord(event.eventPayload))fail('packet_invalid');
    eventIds.add(String(event.eventId));eventSequences.add(String(event.eventSequence));
    const kinds=eventKinds.get(id)??[];kinds.push(kind);eventKinds.set(id,kinds);
    const owned=eventsByOperation.get(id)??[];owned.push(event);eventsByOperation.set(id,owned);
  }
  for(const id of operations.keys()){
    if(!mutableOperationIds.has(id))continue;
    const owned=eventsByOperation.get(id)??[];
    owned.sort((left,right)=>BigInt(String(left.eventSequence))<BigInt(String(right.eventSequence))?-1:
      BigInt(String(left.eventSequence))>BigInt(String(right.eventSequence))?1:0);
    if(owned.length!==4||eventKinds.get(id)?.length!==4||
        owned.map((event)=>event.eventKind).join(',')!=='selected_action_bound,prestate_observed,original_tx_hash_bound,receipt_finalized')fail('packet_invalid');
    const op=operations.get(id)!,selected=selectedByOperation.get(id)!;
    const [selectedEvent,prestateEvent,intentEvent,receiptEvent]=owned;
    const selectedPayload=selectedEvent!.eventPayload as JsonRecord;
    const prestatePayload=prestateEvent!.eventPayload as JsonRecord;
    const intentPayload=intentEvent!.eventPayload as JsonRecord;
    const receiptPayload=receiptEvent!.eventPayload as JsonRecord;
    const measurement=selected.measurement as JsonRecord;
    if(!exactKeys(selectedPayload,['actionKind','requestSha256','selectedAction'])||selectedPayload.actionKind!==op.operation_kind||
        selectedPayload.requestSha256!==op.request_sha256||!same(selectedPayload.selectedAction,selected.selected_action)||
        !exactKeys(prestatePayload,Object.keys(prestatePayload).includes('idempotentReplay')?['prestate','idempotentReplay']:['prestate'])||
        (prestatePayload.idempotentReplay!==undefined&&prestatePayload.idempotentReplay!==true)||!same(prestatePayload.prestate,selected.prestate)||
        !exactKeys(intentPayload,['requestSha256','transactionHash','transactionIntent'])||intentPayload.requestSha256!==op.request_sha256||
        String(intentPayload.transactionHash).toLowerCase()!==String(op.transaction_hash).toLowerCase()||
        !same(intentPayload.transactionIntent,selected.transaction_intent)||
        !exactKeys(receiptPayload,['outcome','measurementSha256'])||receiptPayload.outcome!==selected.outcome||
        !validHash(measurement.measurementSha256)||receiptPayload.measurementSha256!==measurement.measurementSha256||
        selectedEvent!.transactionHash!==null||prestateEvent!.transactionHash!==null||
        String(intentEvent!.transactionHash).toLowerCase()!==String(op.transaction_hash).toLowerCase()||
        String(receiptEvent!.transactionHash).toLowerCase()!==String(op.transaction_hash).toLowerCase())fail('packet_invalid');
  }
  const costs=new Map<string,JsonRecord>();
  const costKeys=['operation_id','env_id','generation_id','transaction_hash','payer_address','payer_role','receipt_status','transaction_from','receipt_from',
    'receipt_block_number','receipt_block_hash','receipt_block_parent_hash','gas_used','effective_gas_price_wei','gas_cost_wei','modeled_gas_fee_usdc_units',
    'manifest_sha256','selected_principal_asset','selected_principal_units','observed_principal_units','created_at'] as const;
  for(const value of census.costs){
    const cost=requireRecord(value,costKeys),opId=String(cost.operation_id);
    if(!operations.has(opId)||!mutableOperationIds.has(opId)||costs.has(opId)||cost.env_id!==binding.environmentId||cost.generation_id!==execution.generationId||
        !validTx(cost.transaction_hash)||!validAddress(cost.payer_address)||!['participant','facilitator'].includes(String(cost.payer_role))||
        !['success','reverted'].includes(String(cost.receipt_status))||!validAddress(cost.transaction_from)||!validAddress(cost.receipt_from)||
        !DECIMAL.test(String(cost.receipt_block_number))||!validTx(cost.receipt_block_hash)||!validTx(cost.receipt_block_parent_hash)||
        !uint(cost.gas_used)||!uint(cost.effective_gas_price_wei)||!uint(cost.gas_cost_wei)||!validHash(cost.manifest_sha256)||typeof cost.created_at!=='string')fail('packet_invalid');
    costs.set(opId,cost);
  }
  if(costs.size!==mutableOperationIds.size)fail('packet_invalid');
  for(const [id,op] of operations){
    if(!mutableOperationIds.has(id))continue;
    const selected=selectedByOperation.get(id)!;
    const cost=costs.get(id)!;
    if(selected.transaction_hash!==op.transaction_hash||selected.action_kind!==op.operation_kind||
        selected.outcome!==(op.receipt_status==='success'?'success':'reverted')||
        cost.transaction_hash!==op.transaction_hash||cost.receipt_status!==op.receipt_status||
        BigInt(cost.gas_used as string)*BigInt(cost.effective_gas_price_wei as string)!==BigInt(cost.gas_cost_wei as string))fail('packet_invalid');
  }
  const fixtureOperationId=String(preparation.fixtureOperationId);
  const fixtureOperation=operations.get(fixtureOperationId);
  const fixtureSelected=selectedByOperation.get(fixtureOperationId);
  const fixtureCost=costs.get(fixtureOperationId);
  if(!fixtureOperation||!fixtureSelected||!fixtureCost||String(fixtureOperation.transaction_hash).toLowerCase()!==String(preparation.fixtureTransactionHash).toLowerCase()||
      fixtureOperation.operation_kind!=='approve'||fixtureOperation.status!=='settled'||fixtureOperation.receipt_status!=='success'||
      fixtureSelected.action_kind!=='approve'||fixtureSelected.outcome!=='success'||
      String((fixtureSelected.selected_action as JsonRecord).tokenAssetId)!=='USDC'||
      fixtureCost.receipt_block_number!==preparation.fixtureBlockNumber||
      String(fixtureCost.receipt_block_hash).toLowerCase()!==String(preparation.fixtureBlockHash).toLowerCase())fail('packet_invalid');
  const baseline=validateCheckpoint(rpc.baseline),final=validateCheckpoint(rpc.final);
  if(String(rpc.localChainId)!==String(generation.chain_id)||baseline.blockNumber!==preparation.baselineBlockNumber||
      String(baseline.blockHash).toLowerCase()!==String(preparation.baselineBlockHash).toLowerCase()||
      BigInt(final.blockNumber as string)<BigInt(baseline.blockNumber as string)||!Array.isArray(rpc.intervalBlocks)||rpc.intervalBlocks.length>256||
      !Array.isArray(rpc.approvals)||rpc.approvals.length>MAX_ROWS||!Array.isArray(rpc.transfers)||rpc.transfers.length>MAX_ROWS||
      !Array.isArray(rpc.receipts)||rpc.receipts.length>MAX_ROWS||!Array.isArray(rpc.responseHashes)||rpc.responseHashes.length>4096)fail('packet_invalid');
  const receipts=new Map<string,JsonRecord>();
  for(const value of rpc.receipts){const receipt=validateReceipt(value);const hash=String(receipt.transactionHash).toLowerCase();
    if(receipts.has(hash))fail('packet_invalid');receipts.set(hash,receipt);}
  const approvals=rpc.approvals.map((item)=>validateLog(item,'approval'));
  const transfers=rpc.transfers.map((item)=>validateLog(item,'transfer'));
  for(const value of rpc.intervalBlocks){
    const block=requireRecord(value,['number','hash','parentHash','transactionCount','participantTransactions']);
    if(!DECIMAL.test(String(block.number))||!validTx(block.hash)||!validTx(block.parentHash)||!Number.isSafeInteger(block.transactionCount)||
        (block.transactionCount as number)<0||!Array.isArray(block.participantTransactions)||block.participantTransactions.length>MAX_ACTIONS||
        block.participantTransactions.length>(block.transactionCount as number))fail('packet_invalid');
    for(const item of block.participantTransactions){
      const tx=validateTransaction(item);
      const receipt=receipts.get(String(tx.hash).toLowerCase());
      if(tx.blockNumber!==block.number||String(tx.blockHash).toLowerCase()!==String(block.hash).toLowerCase()||
          !addressEquals(tx.from,generation.payer_address)||!receipt||receipt.blockNumber!==tx.blockNumber||
          String(receipt.blockHash).toLowerCase()!==String(tx.blockHash).toLowerCase()||receipt.transactionIndex!==tx.transactionIndex||
          !addressEquals(receipt.from,tx.from)||!addressEquals(receipt.to,tx.to))fail('packet_invalid');
    }
  }
  const receiptSet=new Set<string>();let intervalTxCount=0;
  for(const value of rpc.intervalBlocks as JsonRecord[]){for(const item of value.participantTransactions as unknown[]){const tx=item as JsonRecord;
    const hash=String(tx.hash).toLowerCase();intervalTxCount++;if(receiptSet.has(hash)||String(tx.chainId)!==String(rpc.localChainId))fail('packet_invalid');receiptSet.add(hash);
  }}
  if(receiptSet.size!==receipts.size||[...receipts.keys()].some((hash)=>!receiptSet.has(hash)))fail('packet_invalid');
  const fixtureHash=String(preparation.fixtureTransactionHash).toLowerCase();
  if(receipts.has(fixtureHash)||mutableOperationIds.size!==receipts.size+1||intervalTxCount!==receipts.size)fail('packet_invalid');
  for(const [id,op] of operations){
    if(id===String(preparation.fixtureOperationId)||!mutableOperationIds.has(id))continue;
    const receipt=receipts.get(String(op.transaction_hash).toLowerCase());
    const selected=selectedByOperation.get(id)!;
    if(!receipt||receipt.status!==op.receipt_status||selected.outcome!==receipt.status||
        String(op.status)!==(receipt.status==='success'?'settled':'reverted'))fail('packet_invalid');
  }
  for(const log of [...approvals,...transfers]){
    const receipt=receipts.get(String(log.transactionHash).toLowerCase());
    if(!receipt||receipt.blockNumber!==log.blockNumber||String(receipt.blockHash).toLowerCase()!==String(log.blockHash).toLowerCase()||
        receipt.transactionIndex!==log.transactionIndex)fail('packet_invalid');
  }
  for(const value of rpc.responseHashes){
    const row=requireRecord(value,['method','paramsSha256','resultSha256']);
    if(typeof row.method!=='string'||row.method.length<1||row.method.length>80||!validHash(row.paramsSha256)||!validHash(row.resultSha256))fail('packet_invalid');
  }
  const intervals=rpc.intervalBlocks as JsonRecord[];
  let previousNumber=BigInt(String(baseline.blockNumber)),previousHash=String(baseline.blockHash).toLowerCase();
  for(const block of intervals){
    const number=BigInt(String(block.number));
    if(number!==previousNumber+1n||String(block.parentHash).toLowerCase()!==previousHash)fail('packet_invalid');
    previousNumber=number;previousHash=String(block.hash).toLowerCase();
  }
  if(String(final.blockNumber)!==previousNumber.toString()||String(final.blockHash).toLowerCase()!==previousHash)fail('packet_invalid');
  return {preparation,actions:actions as JsonRecord[],bef,rpc,fixtureEvidence:fixtureEvidence as EvidenceReference,
    baselineEvidence:baselineEvidence as EvidenceReference,receipts,operations,selectedByOperation,
    approvals,transfers,payer:String(generation.payer_address),generationId:String(execution.generationId),environmentId:String(binding.environmentId)};
}

/**
 * Validates the S4 capture packet's own immutable topology and returns its private child refs.
 * It does not hash child files or re-evaluate RPC/BEF semantics; the caller must verify bytes for
 * every returned reference and the independent collector remains the source of semantic proof.
 * `fixtureProofSha256` is retained as packet metadata only; this helper does not claim that the
 * fixture or baseline child contents prove that digest without reading those child bytes.
 */
export function verifyS4CapturePacketChildren(bytes:Buffer,bundle:S4CaptureBundleView):EvidenceReference[] {
  if(bytes.byteLength>MAX_PACKET_BYTES)fail('packet_too_large');
  let packet:unknown;
  try{packet=JSON.parse(bytes.toString('utf8')) as unknown;}catch{fail('packet_invalid');}
  if(!isRecord(packet))fail('packet_invalid');
  const {cutoff,reconciled}=validateBundle(bundle);
  const pBinding=requireRecord(packet.binding,BINDING_KEYS,'binding_mismatch');validateBinding(pBinding);
  if(packet.schemaVersion!=='bts-s4-run-observation-capture/v1'||packet.classification!=='run_bound_observations_candidate_not_grade'||
      !same(pBinding,bundle.binding))fail('binding_mismatch');
  const closure=requireRecord(packet.closure,['closureId','actionCutoffSequence','reconciledActionSequence'],'binding_mismatch');
  if(closure.closureId!==bundle.closure.closureId||safeSequence(closure.actionCutoffSequence)!==cutoff||
      safeSequence(closure.reconciledActionSequence)!==reconciled)fail('binding_mismatch');
  const shape=validatePacketShape(packet);
  if(shape.actions.length!==cutoff||shape.actions.length>MAX_ACTIONS)fail('binding_mismatch');
  const execution=requireRecord(packet.execution,['preparationId','leaseId','generationId','environmentId','environmentManifestHash',
    'applicationSourceHash','executionIdentityHash','initialStateSha256'],'binding_mismatch');
  if(execution.preparationId!==bundle.execution.preparationId||execution.leaseId!==bundle.execution.leaseId||
      execution.generationId!==bundle.execution.generationId||execution.environmentId!==bundle.binding.environmentId||
      execution.environmentManifestHash!==bundle.execution.environmentManifestHash||execution.applicationSourceHash!==bundle.execution.applicationSourceHash||
      execution.executionIdentityHash!==bundle.execution.executionIdentityHash||execution.initialStateSha256!==bundle.execution.initialStateSha256)fail('binding_mismatch');
  if(!validHash(execution.initialStateSha256)||execution.initialStateSha256!==bundle.execution.initialStateSha256)fail('binding_mismatch');
  const capture= bundle.observations.captureEvidence;
  if(!validEvidence(capture,CAPTURE_PREFIX)||capture.sha256.toLowerCase()!==createHash('sha256').update(bytes).digest('hex'))fail('child_reference_invalid');
  const children:EvidenceReference[]=[shape.fixtureEvidence,shape.baselineEvidence];
  const paths=new Map<string,string>(children.map((item)=>[item.path,item.sha256.toLowerCase()]));
  const actionIds=new Set<string>(),ownerOperations=new Set<string>(),befOperations=new Set<string>();
  for(const action of shape.actions){
    const readAction=['inspect_catalog','inspect_offer'].includes(String(action.actionKind));
    const allowed=['actionId','actionSequence','ownerOperationId','actionKind','commandSha256','actionEvidence','befOperationId','transactionHash'];
    if(!isRecord(action)||!exactKeys(action,allowed)||!UUID.test(String(action.actionId))||!Number.isSafeInteger(action.actionSequence)||
        (action.actionSequence as number)<1||(action.actionSequence as number)>cutoff||!['approve','transfer','inspect_catalog','inspect_offer'].includes(String(action.actionKind))||
        typeof action.ownerOperationId!=='string'||!TASK_OPERATION_ID.test(action.ownerOperationId)||
        !validHash(action.commandSha256)||!UUID.test(String(action.befOperationId))||
        (readAction?action.transactionHash!==null:!validTx(action.transactionHash))||
        !validEvidence(action.actionEvidence,ACTION_PREFIX))fail('child_reference_invalid');
    if(actionIds.has(String(action.actionId))||ownerOperations.has(String(action.ownerOperationId))||befOperations.has(String(action.befOperationId))||
        String(action.befOperationId)===String(shape.preparation.fixtureOperationId))fail('child_reference_invalid');
    actionIds.add(String(action.actionId));ownerOperations.add(String(action.ownerOperationId));befOperations.add(String(action.befOperationId));
    const op=shape.operations.get(String(action.befOperationId));
    const selected=shape.selectedByOperation.get(String(action.befOperationId));
    if(!op||op.idempotency_key_sha256!==createHash('sha256').update(`task-action-${String(action.actionId)}`).digest('hex'))fail('child_reference_invalid');
    if(readAction){
      const expectedKind=action.actionKind==='inspect_catalog'?'catalog':'offer';
      if(selected||op.operation_kind!==expectedKind||op.status!=='accepted'||op.receipt_status!=='not_submitted'||op.transaction_hash!==null||
          !validHash(op.response_sha256)||
          (action.actionKind==='inspect_catalog'&&String(op.request_sha256).toLowerCase()!==createHash('sha256').update(JSON.stringify({method:'GET',path:'/catalog'})).digest('hex')))
        fail('child_reference_invalid');
    }else if(!selected||op.operation_kind!==action.actionKind||selected.action_kind!==action.actionKind||
        String(op.transaction_hash).toLowerCase()!==String(action.transactionHash).toLowerCase()||
        String(selected.transaction_hash).toLowerCase()!==String(action.transactionHash).toLowerCase())fail('child_reference_invalid');
    const ref=action.actionEvidence as EvidenceReference;
    const existing=paths.get(ref.path);if(existing&&existing!==ref.sha256.toLowerCase())fail('child_reference_invalid');
    if(existing)fail('child_reference_invalid');paths.set(ref.path,ref.sha256.toLowerCase());children.push(ref);
  }
  const taskOperationIds=[...shape.operations.keys()].filter((id)=>id!==String(shape.preparation.fixtureOperationId));
  if(befOperations.size!==taskOperationIds.length||taskOperationIds.some((id)=>!befOperations.has(id)))fail('child_reference_invalid');
  const sequenceList=shape.actions.map((item)=>item.actionSequence as number).sort((a,b)=>a-b);
  if(sequenceList.some((item,index)=>item!==index+1)||children.length>MAX_ACTIONS+2)fail('child_reference_invalid');
  validateS4Observations(bundle.observations,packet,shape,capture,cutoff);
  return children;
}

function validateS4Observations(observations:JsonRecord,packet:JsonRecord,shape:ReturnType<typeof validatePacketShape>,
  capture:EvidenceReference,cutoff:number):void {
  const metaKeys=['observationId','sequence','actionSequence','source','binding','evidence'];
  const arrays=new Map<string,JsonRecord[]>();
  for(const domain of OBSERVATION_DOMAINS){
    const entries=observations[domain] as unknown[];
    if(!['transfers','finalStates','allowanceChanges','expenses'].includes(domain)&&entries.length!==0)fail('observation_mismatch');
    arrays.set(domain,entries.map((entry)=>{
      if(!isRecord(entry))fail('observation_mismatch');
      const kind=String(entry.kind);
      const keys=kind==='final_state'?[...metaKeys,'kind','balances','allowances']:
        kind==='allowance_change'?[...metaKeys,'kind','owner','tokenAssetId','spender','amountBeforeUnits','amountAfterUnits','transactionHash']:
        kind==='transfer'?[...metaKeys,'kind','from','to','assetId','amountUnits','receiptStatus','transactionHash','operation']:
        kind==='expense'?[...metaKeys,'kind','component','sourceEffectId','gasUsed','effectiveGasPriceWei','receiptStatus','transactionHash']:[];
      return requireRecord(entry,keys,'observation_mismatch');
    }));
  }
  const actionBySequence=new Map<number,JsonRecord>();
  const operationByHash=new Map<string,JsonRecord>();
  for(const action of shape.actions){
    const seq=action.actionSequence as number;
    if(actionBySequence.has(seq))fail('observation_mismatch');actionBySequence.set(seq,action);
  }
  for(const [id,op] of shape.operations){
    if(['catalog','offer'].includes(String(op.operation_kind)))continue;
    const tx=String(op.transaction_hash).toLowerCase();if(operationByHash.has(tx))fail('packet_invalid');operationByHash.set(tx,op);
    const selected=shape.selectedByOperation.get(id)!;
    const events=(shape.bef.before as JsonRecord).selectedEvents as JsonRecord[];
    const owned=events.filter((event)=>event.operationId===id).sort((a,b)=>Number(a.eventSequence)-Number(b.eventSequence));
    if(owned.length!==4||owned.map((event)=>event.eventKind).join(',')!=='selected_action_bound,prestate_observed,original_tx_hash_bound,receipt_finalized')fail('packet_invalid');
    const txReceipt=shape.receipts.get(tx);
    const fixture=packet.preparation as JsonRecord;
    if(id===fixture.fixtureOperationId){
      if(tx!==fixture.fixtureTransactionHash||txReceipt||op.operation_kind!=='approve'||op.status!=='settled'||op.receipt_status!=='success'||
          String((shape.selectedByOperation.get(id)?.selected_action as JsonRecord).tokenAssetId)!=='USDC')fail('packet_invalid');
      const cost=[...((shape.bef.before as JsonRecord).costs as JsonRecord[])].find((item)=>item.operation_id===id);
      if(!cost||String(cost.transaction_hash)!==fixture.fixtureTransactionHash||String(cost.receipt_block_number)!==fixture.fixtureBlockNumber||
          String(cost.receipt_block_hash).toLowerCase()!==String(fixture.fixtureBlockHash).toLowerCase())fail('packet_invalid');
      continue;
    }
    if(!txReceipt||String(op.receipt_status)!==txReceipt.status||String(op.status)!==(txReceipt.status==='success'?'settled':'reverted')||
        selected.transaction_hash!==tx||selected.outcome!==txReceipt.status)fail('packet_invalid');
    const cost=[...((shape.bef.before as JsonRecord).costs as JsonRecord[])].find((item)=>item.operation_id===id);
    if(!cost||cost.transaction_hash!==tx||cost.receipt_status!==txReceipt.status||String(cost.gas_used)!==String(txReceipt.gasUsed)||
        String(cost.effective_gas_price_wei)!==String(txReceipt.effectiveGasPriceWei)||String(cost.gas_cost_wei)!==String(txReceipt.gasCostWei))fail('packet_invalid');
  }
  if(operationByHash.size!==shape.receipts.size+1)fail('packet_invalid');
  const validateMeta=(entry:JsonRecord,kind:string):number=>{
    const coveredThrough=safeSequence(observations.coveredThroughSequence);
    if(entry.kind!==kind||!exactKeys(entry,kind==='final_state'?[...metaKeys,'kind','balances','allowances']:
      kind==='allowance_change'?[...metaKeys,'kind','owner','tokenAssetId','spender','amountBeforeUnits','amountAfterUnits','transactionHash']:
      kind==='transfer'?[...metaKeys,'kind','from','to','assetId','amountUnits','receiptStatus','transactionHash','operation']:
      [...metaKeys,'kind','component','sourceEffectId','gasUsed','effectiveGasPriceWei','receiptStatus','transactionHash'])||
        typeof entry.observationId!=='string'||entry.observationId.length<1||entry.observationId.length>192||
        !Number.isSafeInteger(entry.sequence)||(entry.sequence as number)<0||coveredThrough===null||(entry.sequence as number)>coveredThrough||
        !Number.isSafeInteger(entry.actionSequence)||
        (entry.actionSequence as number)<0||(entry.actionSequence as number)>cutoff||entry.source!=='persisted_observer'||
        !same(entry.binding,packet.binding)||!same(entry.evidence,capture))fail('observation_mismatch');
    return entry.actionSequence as number;
  };
  const receipts=shape.receipts;
  const transferObs=arrays.get('transfers')!;
  const allowanceObs=arrays.get('allowanceChanges')!;
  const expenseObs=arrays.get('expenses')!;
  const finalStates=arrays.get('finalStates')!;
  if(finalStates.length!==1)fail('observation_mismatch');
  const finalState=finalStates[0]!;
  const finalActionSequence=validateMeta(finalState,'final_state');
  const finalAllowances=finalState.allowances as unknown[];
  const finalAllowanceKeys=new Set<string>();
  if(finalActionSequence!==cutoff||safeSequence(finalState.sequence)!==safeSequence(observations.coveredThroughSequence)||
      !same(finalState.balances,(packet.rpc as JsonRecord).final&&((packet.rpc as JsonRecord).final as JsonRecord).balances)||
      !Array.isArray(finalAllowances)||finalAllowances.length>256)fail('observation_mismatch');
  for(const value of finalAllowances){
    const allowance=requireRecord(value,['owner','tokenAssetId','spender','amountUnits'],'observation_mismatch');
    const key=`${String(allowance.owner).toLowerCase()}|${String(allowance.tokenAssetId)}|${String(allowance.spender).toLowerCase()}`;
    if(typeof allowance.owner!=='string'||typeof allowance.tokenAssetId!=='string'||!validAddress(allowance.spender)||!uint(allowance.amountUnits)||
        finalAllowanceKeys.has(key))fail('observation_mismatch');
    finalAllowanceKeys.add(key);
  }
  for(const domain of ['transfers','finalStates','allowanceChanges','expenses'] as const){
    const ids=new Set<string>();
    for(const item of arrays.get(domain)!){
      if(ids.has(String(item.observationId)))fail('observation_mismatch');
      ids.add(String(item.observationId));
    }
  }
  for(const row of [...transferObs,...allowanceObs,...expenseObs]){
    const kind=String(row.kind);const actionSeq=validateMeta(row,kind);
    const hashValue=typeof row.transactionHash==='string'?row.transactionHash.toLowerCase():row.transactionHash;
    if(!validTx(hashValue)||!receipts.has(hashValue))fail('observation_mismatch');
    const receipt=receipts.get(hashValue)!;
    const op=operationByHash.get(hashValue);
    if(!op)fail('observation_mismatch');
    if(actionSeq>0){
      const action=actionBySequence.get(actionSeq);
      if(!action||action.transactionHash!==hashValue||action.befOperationId!==op.operation_id)fail('observation_mismatch');
    }
    if(kind==='expense'){
      if(row.component!=='participant_gas'||row.sourceEffectId!==`bef-operation:${String(op.operation_id)}`||
          String(row.gasUsed)!==String(receipt.gasUsed)||String(row.effectiveGasPriceWei)!==String(receipt.effectiveGasPriceWei)||
          row.receiptStatus!==receipt.status)fail('observation_mismatch');
    }else if(kind==='allowance_change'){
      const selected=shape.selectedByOperation.get(String(op.operation_id))?.selected_action as JsonRecord|undefined;
      const log=shape.approvals.find((item)=>item.transactionHash===hashValue&&item.owner===shape.payer&&
        item.spender===String(row.spender).toLowerCase()&&String(item.amountUnits)===String(row.amountAfterUnits));
      if(!selected||selected.kind!=='approve'||selected.tokenAssetId!==row.tokenAssetId||String(selected.amountUnits)!==String(row.amountAfterUnits)||
          !addressEquals(selected.spender,row.spender)||!log||row.owner!=='participant'||row.receiptStatus!==undefined||
          !uint(row.amountBeforeUnits)||!uint(row.amountAfterUnits)||!validAddress(row.spender))fail('observation_mismatch');
      if(actionSeq>0&&actionBySequence.get(actionSeq)!.actionKind!=='approve')fail('observation_mismatch');
    }else{
      const selected=shape.selectedByOperation.get(String(op.operation_id))?.selected_action as JsonRecord|undefined;
      const log=shape.transfers.find((item)=>item.transactionHash===hashValue&&item.from===shape.payer&&
        addressEquals(item.to,row.to)&&String(item.amountUnits)===String(row.amountUnits));
      if(!selected||selected.kind!=='transfer'||String(selected.amountUnits)!==String(row.amountUnits)||!addressEquals(selected.recipient,row.to)||
          !log||row.from!=='participant'||row.operation!=='principal'||row.receiptStatus!==receipt.status||
          selected.tokenAssetId!==row.assetId||!addressEquals(selected.tokenAddress,log.tokenAddress)||!validAddress(row.to)||!uint(row.amountUnits))fail('observation_mismatch');
      if(actionSeq>0&&actionBySequence.get(actionSeq)!.actionKind!=='transfer')fail('observation_mismatch');
    }
  }
  const expenseByTx=new Map(expenseObs.map((item)=>[String(item.transactionHash),item]));
  if(expenseByTx.size!==expenseObs.length||expenseByTx.size!==receipts.size||[...receipts.keys()].some((hashValue)=>!expenseByTx.has(hashValue)))fail('observation_mismatch');
  for(const action of shape.actions){
    if(['inspect_catalog','inspect_offer'].includes(String(action.actionKind))){
      const op=shape.operations.get(String(action.befOperationId));
      if(!op||op.idempotency_key_sha256!==createHash('sha256').update(`task-action-${action.actionId}`).digest('hex')||
          op.operation_kind!==(action.actionKind==='inspect_catalog'?'catalog':'offer')||op.status!=='accepted'||
          op.receipt_status!=='not_submitted'||op.transaction_hash!==null)fail('observation_mismatch');
      continue;
    }
    const actionSeq=action.actionSequence as number,hashValue=String(action.transactionHash).toLowerCase(),op=operationByHash.get(hashValue);
    if(!op||op.operation_id!==action.befOperationId||op.idempotency_key_sha256!==createHash('sha256').update(`task-action-${action.actionId}`).digest('hex'))fail('observation_mismatch');
    const matchingAllowance=allowanceObs.filter((item)=>item.actionSequence===actionSeq&&item.transactionHash===hashValue);
    const matchingTransfers=transferObs.filter((item)=>item.actionSequence===actionSeq&&item.transactionHash===hashValue);
    const receipt=receipts.get(hashValue)!;
    if(op.operation_kind==='approve'&&receipt.status==='success'&&matchingAllowance.length!==1)fail('observation_mismatch');
    if(op.operation_kind==='approve'&&receipt.status==='reverted'&&matchingAllowance.length!==0)fail('observation_mismatch');
    if(op.operation_kind==='transfer'&&receipt.status==='success'&&matchingTransfers.length===0)fail('observation_mismatch');
    if(op.operation_kind==='transfer'&&receipt.status==='reverted'&&matchingTransfers.length!==0)fail('observation_mismatch');
  }
}
