import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';
import { canonicalTaskJson, type EvidenceReference } from './task-release.js';
import { S4CapturePacketError, verifyS4CapturePacketChildren, type S4CaptureBundleView } from './task-s4-capture-packet.js';

const hash=(value:string)=>createHash('sha256').update(value).digest('hex');
const HASH_A='a'.repeat(64), HASH_B='b'.repeat(64), HASH_C='c'.repeat(64), HASH_D='d'.repeat(64);
const OWNER='10000000-0000-4000-8000-000000000001';
const AGENT='10000000-0000-4000-8000-000000000002';
const RUN='10000000-0000-4000-8000-000000000003';
const CLOSURE='10000000-0000-4000-8000-000000000004';
const PREPARATION='10000000-0000-4000-8000-000000000005';
const LEASE='10000000-0000-4000-8000-000000000006';
const GENERATION='10000000-0000-4000-8000-000000000007';
const PARTICIPANT='10000000-0000-4000-8000-000000000008';
const ACTION='10000000-0000-4000-8000-000000000009';
const OWNER_OPERATION='10000000-0000-4000-8000-000000000010';
const FIXTURE_OPERATION='10000000-0000-4000-8000-000000000011';
const ACTION_OPERATION='10000000-0000-4000-8000-000000000012';
const ENVIRONMENT='bef-env-a';
const PAYER='0x00000000000000000000000000000000000000a1';
const TOKEN='0x00000000000000000000000000000000000000b2';
const ROUTER='0x00000000000000000000000000000000000000c3';
const RECIPIENT='0x00000000000000000000000000000000000000d4';
const FIXTURE_TX=`0x${'1'.repeat(64)}`;
const ACTION_TX=`0x${'2'.repeat(64)}`;
const FIXTURE_BLOCK=`0x${'3'.repeat(64)}`;
const BASELINE_BLOCK=`0x${'4'.repeat(64)}`;
const ACTION_BLOCK=`0x${'5'.repeat(64)}`;
const FIXTURE_PARENT=`0x${'6'.repeat(64)}`;
const ZERO='0';
const BOUNDARY='actual_tool_http_x402_local_evm_application_store' as const;
const CAPTURE_ROOT='artifacts/runs/owner-identity-bef-task-coordinator/observation/';

function evidence(path:string,digest=HASH_A):EvidenceReference {
  return {path,sha256:digest,boundary:BOUNDARY};
}

function snapshot() {
  return {blockNumber:'9',payerNativeWei:'1000000',payerWethUnits:'0',payerUsdcUnits:'1000',recipientWethUnits:'0',
    recipientUsdcUnits:'0',wethRouterAllowance:'0',usdcRouterAllowance:'0',poolWethUnits:'0',poolUsdcUnits:'0',
    poolLiquidity:'0',poolSqrtPriceX96:'0'};
}

function transactionIntent(txHash:string,blockHash:string|null,blockNumber:string|null,transactionIndex:string|null) {
  return {hash:txHash,type:'eip1559',chainId:8453,blockHash,blockNumber,transactionIndex,from:PAYER,to:TOKEN,nonce:'4',
    input:'0x095ea7b3',valueWei:'0',gasLimit:'100000',maxFeePerGasWei:'3',maxPriorityFeePerGasWei:'1'};
}

function operationRows(withAction:boolean) {
  const actionSelected={kind:'approve',tokenAssetId:'USDC',tokenAddress:TOKEN,spender:ROUTER,amountUnits:'50',gasLimit:'100000'};
  const fixtureSelected={kind:'approve',tokenAssetId:'USDC',tokenAddress:TOKEN,spender:ROUTER,amountUnits:'25',gasLimit:'100000'};
  const fixtureIntent=transactionIntent(FIXTURE_TX,FIXTURE_BLOCK,'9','0');
  const actionIntent=transactionIntent(ACTION_TX,ACTION_BLOCK,'11','0');
  const fixtureOperation={operation_id:FIXTURE_OPERATION,env_id:ENVIRONMENT,generation_id:GENERATION,participant_id:PARTICIPANT,
    idempotency_key_sha256:HASH_B,request_sha256:HASH_C,operation_kind:'approve',status:'settled',receipt_status:'success',
    transaction_hash:FIXTURE_TX,response_sha256:null,started_at:'2026-10-28T00:00:00.000Z',completed_at:'2026-10-28T00:00:01.000Z'};
  const fixtureExecution={operation_id:FIXTURE_OPERATION,env_id:ENVIRONMENT,generation_id:GENERATION,action_kind:'approve',
    selected_action:fixtureSelected,prestate:snapshot(),transaction_intent:fixtureIntent,measurement:{measurementSha256:HASH_D},
    transaction_hash:FIXTURE_TX,outcome:'success',reason_code:null,completed_at:'2026-10-28T00:00:01.000Z'};
  const operations=[fixtureOperation],selectedExecutions=[fixtureExecution];
  if(withAction){
    operations.push({operation_id:ACTION_OPERATION,env_id:ENVIRONMENT,generation_id:GENERATION,participant_id:PARTICIPANT,
      idempotency_key_sha256:hash(`task-action-${ACTION}`),request_sha256:HASH_A,operation_kind:'approve',status:'settled',receipt_status:'success',
      transaction_hash:ACTION_TX,response_sha256:null,started_at:'2026-10-28T00:00:02.000Z',completed_at:'2026-10-28T00:00:03.000Z'});
    selectedExecutions.push({operation_id:ACTION_OPERATION,env_id:ENVIRONMENT,generation_id:GENERATION,action_kind:'approve',
      selected_action:actionSelected,prestate:snapshot(),transaction_intent:actionIntent,measurement:{measurementSha256:HASH_D},
      transaction_hash:ACTION_TX,outcome:'success',reason_code:null,completed_at:'2026-10-28T00:00:03.000Z'});
  }
  const selectedEvents:Record<string,unknown>[]=[];
  const addEvents=(operationId:string,txHash:string,requestHash:string,selectedAction:Record<string,unknown>,intent:Record<string,unknown>,start:number)=>{
    const selectedMeasurement={measurementSha256:HASH_D};
    const eventData=[
      ['selected_action_bound',null,{actionKind:'approve',requestSha256:requestHash,selectedAction}],
      ['prestate_observed',null,{prestate:snapshot()}],
      ['original_tx_hash_bound',txHash,{requestSha256:requestHash,transactionHash:txHash,transactionIntent:intent}],
      ['receipt_finalized',txHash,{outcome:'success',measurementSha256:selectedMeasurement.measurementSha256}],
    ] as const;
    for(let index=0;index<eventData.length;index++){
      const [eventKind,transactionHash,eventPayload]=eventData[index]!;
      selectedEvents.push({eventId:`10000000-0000-4000-8000-0000000000${String(start+index+1).padStart(2,'0')}`,
        eventSequence:String(start+index+1),operationId,eventKind,transactionHash,eventJsonSha256:HASH_C,eventPayload});
    }
  };
  addEvents(FIXTURE_OPERATION,FIXTURE_TX,HASH_C,fixtureSelected,fixtureIntent,0);
  if(withAction)addEvents(ACTION_OPERATION,ACTION_TX,HASH_A,actionSelected,actionIntent,4);
  const fixtureCost={operation_id:FIXTURE_OPERATION,env_id:ENVIRONMENT,generation_id:GENERATION,transaction_hash:FIXTURE_TX,
    payer_address:PAYER,payer_role:'participant',receipt_status:'success',transaction_from:PAYER,receipt_from:PAYER,receipt_block_number:'9',
    receipt_block_hash:FIXTURE_BLOCK,receipt_block_parent_hash:FIXTURE_PARENT,gas_used:'10',effective_gas_price_wei:'2',gas_cost_wei:'20',
    modeled_gas_fee_usdc_units:'0',manifest_sha256:HASH_B,selected_principal_asset:null,selected_principal_units:null,
    observed_principal_units:null,created_at:'2026-10-28T00:00:01.000Z'};
  const costs=[fixtureCost];
  if(withAction)costs.push({...fixtureCost,operation_id:ACTION_OPERATION,transaction_hash:ACTION_TX,receipt_block_number:'11',
    receipt_block_hash:ACTION_BLOCK,receipt_block_parent_hash:BASELINE_BLOCK,effective_gas_price_wei:'3',gas_cost_wei:'30',
    created_at:'2026-10-28T00:00:03.000Z'});
  return {operations,selectedExecutions,selectedEvents,costs};
}

function makeCase(withAction:boolean) {
  const binding={ownerId:OWNER,agentId:AGENT,runId:RUN,environmentId:ENVIRONMENT,releaseIdentity:'release-s4',manifestHash:HASH_B,
    caseId:'s4-case',caseHash:HASH_C,rubricHash:HASH_D,taskId:'S4'};
  const closure={closureId:CLOSURE,operationId:null,payloadHash:HASH_A,reason:'agent_finish',actionCutoffSequence:withAction?1:0,
    reconciledActionSequence:withAction?1:0};
  const execution={preparationId:PREPARATION,leaseId:LEASE,generationId:GENERATION,environmentManifestHash:HASH_B,
    applicationSourceHash:HASH_C,executionIdentityHash:HASH_D,initialStateSha256:HASH_A};
  const preparation={fixtureEvidence:evidence('artifacts/runs/owner-identity-bef-task-coordinator/preparation/fixture.json',HASH_A),
    baselineEvidence:evidence('artifacts/runs/owner-identity-bef-task-coordinator/preparation/baseline.json',HASH_B),
    baselineBlockNumber:'10',baselineBlockHash:BASELINE_BLOCK,fixtureOperationId:FIXTURE_OPERATION,fixtureTransactionHash:FIXTURE_TX,
    fixtureBlockNumber:'9',fixtureBlockHash:FIXTURE_BLOCK,fixtureProofSha256:HASH_C};
  const rows=operationRows(withAction);
  const generation={generation_id:GENERATION,env_id:ENVIRONMENT,participant_id:PARTICIPANT,payer_address:PAYER,manifest_sha256:HASH_B,
    status:'active',chain_id:'8453',environment_manifest_sha256:HASH_B};
  const census={generation,operations:rows.operations,selectedExecutions:rows.selectedExecutions,selectedEvents:rows.selectedEvents,costs:rows.costs,
    paymentsCount:'0',deliveriesCount:'0',counts:{operations:String(rows.operations.length),selectedExecutions:String(rows.selectedExecutions.length),
      selectedEvents:String(rows.selectedEvents.length),costs:String(rows.costs.length)}};
  const bef={session:{currentUser:'bef_observer',sessionUser:'bef_observer',transactionReadOnly:'on',transactionIsolation:'repeatable read',
      superuser:false,bypassRls:false},before:census,after:structuredClone(census),censusSha256:hash(canonicalTaskJson(census))};
  const baseBalances=[{account:'participant',assetId:'ETH',amountUnits:'1000000'},{account:'participant',assetId:'USDC',amountUnits:'1000'}];
  const finalBalances=withAction?[{account:'participant',assetId:'ETH',amountUnits:'999970'},{account:'participant',assetId:'USDC',amountUnits:'1000'}]:baseBalances;
  const baselineAllowances=[{owner:'participant',tokenAssetId:'USDC',spender:ROUTER,amountUnits:'0'}];
  const finalAllowances=withAction?[{owner:'participant',tokenAssetId:'USDC',spender:ROUTER,amountUnits:'50'}]:baselineAllowances;
  const baseline={blockNumber:'10',blockHash:BASELINE_BLOCK,parentHash:FIXTURE_PARENT,balances:baseBalances,allowances:baselineAllowances,
    participantTransactionCount:'7'};
  const final=withAction?{blockNumber:'11',blockHash:ACTION_BLOCK,parentHash:BASELINE_BLOCK,balances:finalBalances,allowances:finalAllowances,
    participantTransactionCount:'8'}:structuredClone(baseline);
  const receipt={transactionHash:ACTION_TX,from:PAYER,to:TOKEN,blockNumber:'11',blockHash:ACTION_BLOCK,transactionIndex:'0',status:'success',
    gasUsed:'10',effectiveGasPriceWei:'3',gasCostWei:'30',logsSha256:HASH_D};
  const transaction={hash:ACTION_TX,from:PAYER,to:TOKEN,nonce:'7',input:'0x095ea7b3',valueWei:'0',gasLimit:'100000',blockNumber:'11',
    blockHash:ACTION_BLOCK,transactionIndex:'0',chainId:'8453'};
  const rpc={localChainId:'8453',baseline,final,intervalBlocks:withAction?[{number:'11',hash:ACTION_BLOCK,parentHash:BASELINE_BLOCK,
      transactionCount:1,participantTransactions:[transaction]}]:[],approvals:withAction?[{tokenAddress:TOKEN,owner:PAYER,spender:ROUTER,
      amountUnits:'50',transactionHash:ACTION_TX,blockNumber:'11',blockHash:ACTION_BLOCK,transactionIndex:'0',logIndex:'0'}]:[],transfers:[],
    receipts:withAction?[receipt]:[],responseHashes:[]};
  const packet={schemaVersion:'bts-s4-run-observation-capture/v1',classification:'run_bound_observations_candidate_not_grade',binding,
    closure:{closureId:CLOSURE,actionCutoffSequence:withAction?1:0,reconciledActionSequence:withAction?1:0},
    execution:{...execution,environmentId:ENVIRONMENT},preparation,
    ownerActions:withAction?[{actionId:ACTION,actionSequence:1,ownerOperationId:OWNER_OPERATION,actionKind:'approve',commandSha256:HASH_A,
      actionEvidence:evidence('artifacts/runs/owner-identity-bef-task-coordinator/action/approve.json',HASH_D),befOperationId:ACTION_OPERATION,
      transactionHash:ACTION_TX}]:[],bef,rpc};
  const bytes=Buffer.from(canonicalTaskJson(packet));
  const captureEvidence=evidence(`${CAPTURE_ROOT}s4-packet.json`,createHash('sha256').update(bytes).digest('hex'));
  const meta=(sequence:number,actionSequence:number,observationId:string)=>({observationId,sequence,actionSequence,source:'persisted_observer',binding,evidence:captureEvidence});
  const observations={schemaVersion:'bts-task-observations/v1',binding,coveredThroughSequence:withAction?3:0,captureEvidence,
    coverage:{transfers:'complete',balances:'complete',allowances:'complete'},
    transfers:[],payments:[],stateMutations:[],finalStates:[{kind:'final_state',...meta(withAction?3:0,withAction?1:0,'final-s4'),
      balances:finalBalances,allowances:finalAllowances}],allowanceChanges:withAction?[{kind:'allowance_change',...meta(1,1,'allow-s4'),
      owner:'participant',tokenAssetId:'USDC',spender:ROUTER,amountBeforeUnits:'0',amountAfterUnits:'50',transactionHash:ACTION_TX}]:[],
    allowanceUses:[],answers:[],selections:[],deliveries:[],trades:[],conversions:[],expenses:withAction?[{kind:'expense',...meta(2,1,'gas-s4'),
      component:'participant_gas',sourceEffectId:`bef-operation:${ACTION_OPERATION}`,gasUsed:'10',effectiveGasPriceWei:'3',receiptStatus:'success',
      transactionHash:ACTION_TX}]:[]};
  const bundle:S4CaptureBundleView={binding,closure,execution,observations};
  return {packet,bundle,bytes};
}

function resealPacket(packet:Record<string,unknown>,bundle:S4CaptureBundleView) {
  const bytes=Buffer.from(canonicalTaskJson(packet));
  const captureEvidence=evidence(`${CAPTURE_ROOT}s4-packet.json`,createHash('sha256').update(bytes).digest('hex'));
  const observations={...bundle.observations,captureEvidence} as Record<string,unknown>;
  for(const name of ['transfers','payments','stateMutations','finalStates','allowanceChanges','allowanceUses','answers','selections',
    'deliveries','trades','conversions','expenses']){
    const entries=observations[name];
    if(Array.isArray(entries))for(const entry of entries)if(entry&&typeof entry==='object'&&!Array.isArray(entry)){
      (entry as Record<string,unknown>).evidence=captureEvidence;
    }
  }
  return {bytes,bundle:{...bundle,observations}};
}

function addInspectionPrefix(item:ReturnType<typeof makeCase>) {
  const packet=structuredClone(item.packet) as Record<string,unknown>;
  const bef=packet.bef as Record<string,unknown>,census=bef.before as Record<string,unknown>;
  const operations=census.operations as Array<Record<string,unknown>>;
  const catalogOperation='10000000-0000-4000-8000-000000000013';
  const offerOperation='10000000-0000-4000-8000-000000000014';
  const catalogAction='10000000-0000-4000-8000-000000000015';
  const offerAction='10000000-0000-4000-8000-000000000016';
  const readOperations=[
    {operation_id:catalogOperation,env_id:ENVIRONMENT,generation_id:GENERATION,participant_id:PARTICIPANT,
      idempotency_key_sha256:hash(`task-action-${catalogAction}`),request_sha256:hash(JSON.stringify({method:'GET',path:'/catalog'})),
      operation_kind:'catalog',status:'accepted',receipt_status:'not_submitted',transaction_hash:null,response_sha256:HASH_C,
      started_at:'2026-10-28T00:00:01.000Z',completed_at:'2026-10-28T00:00:01.000Z'},
    {operation_id:offerOperation,env_id:ENVIRONMENT,generation_id:GENERATION,participant_id:PARTICIPANT,
      idempotency_key_sha256:hash(`task-action-${offerAction}`),request_sha256:hash(JSON.stringify({method:'GET',path:'/offer',resourceId:'s4-resource'})),
      operation_kind:'offer',status:'accepted',receipt_status:'not_submitted',transaction_hash:null,response_sha256:HASH_D,
      started_at:'2026-10-28T00:00:01.500Z',completed_at:'2026-10-28T00:00:01.500Z'},
  ];
  operations.splice(1,0,...readOperations);
  (census.counts as Record<string,unknown>).operations=String(operations.length);
  const actions=packet.ownerActions as Array<Record<string,unknown>>;
  actions[0]!.actionSequence=3;
  packet.ownerActions=[
    {actionId:catalogAction,actionSequence:1,ownerOperationId:'10000000-0000-4000-8000-000000000017',actionKind:'inspect_catalog',commandSha256:HASH_A,
      actionEvidence:evidence('artifacts/runs/owner-identity-bef-task-coordinator/action/catalog.json',HASH_B),befOperationId:catalogOperation,transactionHash:null},
    {actionId:offerAction,actionSequence:2,ownerOperationId:'10000000-0000-4000-8000-000000000018',actionKind:'inspect_offer',commandSha256:HASH_C,
      actionEvidence:evidence('artifacts/runs/owner-identity-bef-task-coordinator/action/offer.json',HASH_D),befOperationId:offerOperation,transactionHash:null},
    ...actions,
  ];
  bef.after=structuredClone(census);
  bef.censusSha256=hash(canonicalTaskJson(census));
  (packet.closure as Record<string,unknown>).actionCutoffSequence=3;
  (packet.closure as Record<string,unknown>).reconciledActionSequence=3;
  const observations=structuredClone(item.bundle.observations) as Record<string,unknown>;
  for(const name of ['finalStates','allowanceChanges','expenses']){
    for(const entry of observations[name] as Array<Record<string,unknown>>) entry.actionSequence=3;
  }
  const bundle:S4CaptureBundleView={...item.bundle,closure:{...item.bundle.closure,actionCutoffSequence:3,reconciledActionSequence:3},observations};
  return resealPacket(packet,bundle);
}

function assertPacketError(action:()=>unknown,code?:S4CapturePacketError['code']) {
  assert.throws(action,(error:unknown)=>error instanceof S4CapturePacketError&&(code===undefined||error.code===code));
}

test('S4 packet returns hash references and crosslinks one action to its observed BEF operation',()=>{
  const item=makeCase(true);
  const refs=verifyS4CapturePacketChildren(item.bytes,item.bundle);
  assert.deepEqual(refs.map((ref)=>ref.path),[
    'artifacts/runs/owner-identity-bef-task-coordinator/preparation/fixture.json',
    'artifacts/runs/owner-identity-bef-task-coordinator/preparation/baseline.json',
    'artifacts/runs/owner-identity-bef-task-coordinator/action/approve.json',
  ]);
});

test('S4 packet accepts owner operation IDs in the task-action service format',()=>{
  for(const ownerOperationId of ['owner-op-1234','x'.repeat(128)]){
    const item=makeCase(true);
    const packet=structuredClone(item.packet) as Record<string,unknown>;
    const actions=packet.ownerActions as Array<Record<string,unknown>>;
    actions[0]!.ownerOperationId=ownerOperationId;
    const resealed=resealPacket(packet,item.bundle);
    assert.equal(verifyS4CapturePacketChildren(resealed.bytes,resealed.bundle).length,3);
  }
});

test('S4 packet accepts the task-action service format for a non-null finish operation ID',()=>{
  for(const operationId of ['finish-op-123','x'.repeat(128)]){
    const item=makeCase(true);
    const bundle={...item.bundle,closure:{...item.bundle.closure,operationId}};
    assert.equal(verifyS4CapturePacketChildren(item.bytes,bundle).length,3);
  }
});

test('S4 packet rejects malformed non-null finish operation IDs',()=>{
  for(const operationId of ['short','finish.operation.id','x'.repeat(129)]){
    const item=makeCase(true);
    const bundle={...item.bundle,closure:{...item.bundle.closure,operationId}};
    assertPacketError(()=>verifyS4CapturePacketChildren(item.bytes,bundle),'binding_mismatch');
  }
});

test('S4 packet rejects malformed and duplicate owner operation IDs',()=>{
  for(const ownerOperationId of ['too-short','owner.operation.1','x'.repeat(129)]){
    const item=makeCase(true);
    const packet=structuredClone(item.packet) as Record<string,unknown>;
    const actions=packet.ownerActions as Array<Record<string,unknown>>;
    actions[0]!.ownerOperationId=ownerOperationId;
    const resealed=resealPacket(packet,item.bundle);
    assertPacketError(()=>verifyS4CapturePacketChildren(resealed.bytes,resealed.bundle),'child_reference_invalid');
  }

  const item=addInspectionPrefix(makeCase(true));
  const packet=JSON.parse(item.bytes.toString('utf8')) as Record<string,unknown>;
  const actions=packet.ownerActions as Array<Record<string,unknown>>;
  actions[1]!.ownerOperationId=actions[0]!.ownerOperationId;
  const resealed=resealPacket(packet,item.bundle);
  assertPacketError(()=>verifyS4CapturePacketChildren(resealed.bytes,resealed.bundle),'child_reference_invalid');
});

test('S4 packet keeps BEF operation idempotency bound to the durable action ID',()=>{
  const item=makeCase(true);
  const packet=structuredClone(item.packet) as Record<string,unknown>;
  const bef=packet.bef as Record<string,unknown>;
  const census=bef.before as Record<string,unknown>;
  const operations=census.operations as Array<Record<string,unknown>>;
  operations.find((operation)=>operation.operation_id===ACTION_OPERATION)!.idempotency_key_sha256=HASH_B;
  bef.after=structuredClone(census);
  bef.censusSha256=hash(canonicalTaskJson(census));
  const resealed=resealPacket(packet,item.bundle);
  assertPacketError(()=>verifyS4CapturePacketChildren(resealed.bytes,resealed.bundle),'child_reference_invalid');
});

test('S4 packet retains both neutral inspection actions before a mutable transaction',()=>{
  const item=addInspectionPrefix(makeCase(true));
  const refs=verifyS4CapturePacketChildren(item.bytes,item.bundle);
  assert.deepEqual(refs.map((ref)=>ref.path),[
    'artifacts/runs/owner-identity-bef-task-coordinator/preparation/fixture.json',
    'artifacts/runs/owner-identity-bef-task-coordinator/preparation/baseline.json',
    'artifacts/runs/owner-identity-bef-task-coordinator/action/catalog.json',
    'artifacts/runs/owner-identity-bef-task-coordinator/action/offer.json',
    'artifacts/runs/owner-identity-bef-task-coordinator/action/approve.json',
  ]);

  const packet=JSON.parse(item.bytes.toString('utf8')) as Record<string,unknown>;
  const actions=packet.ownerActions as Array<Record<string,unknown>>;
  actions[0]!.transactionHash=ACTION_TX;
  const resealed=resealPacket(packet,item.bundle);
  assertPacketError(()=>verifyS4CapturePacketChildren(resealed.bytes,resealed.bundle));
});

test('S4 packet preserves a cutoff-zero final snapshot without inventing an action',()=>{
  const item=makeCase(false);
  assert.equal(verifyS4CapturePacketChildren(item.bytes,item.bundle).length,2);
});

test('S4 packet rejects an observation action sequence with no matching admitted owner action',()=>{
  const item=makeCase(true);
  const observations=structuredClone(item.bundle.observations) as Record<string,unknown>;
  const allowanceChanges=observations.allowanceChanges as Array<Record<string,unknown>>;
  allowanceChanges[0]!.actionSequence=0;
  assertPacketError(()=>verifyS4CapturePacketChildren(item.bytes,{...item.bundle,observations}), 'observation_mismatch');
});

test('S4 packet rejects event payload tampering even when its capture hash is recomputed',()=>{
  const item=makeCase(true);
  const packet=structuredClone(item.packet) as Record<string,unknown>;
  const bef=packet.bef as Record<string,unknown>;
  const census=bef.before as Record<string,unknown>;
  const events=census.selectedEvents as Array<Record<string,unknown>>;
  const event=events.find((entry)=>entry.operationId===ACTION_OPERATION&&entry.eventKind==='selected_action_bound')!;
  (event.eventPayload as Record<string,unknown>).requestSha256=HASH_D;
  bef.censusSha256=hash(canonicalTaskJson(census));
  const resealed=resealPacket(packet,item.bundle);
  assertPacketError(()=>verifyS4CapturePacketChildren(resealed.bytes,resealed.bundle),'packet_invalid');
});

test('S4 packet requires the bounded preparation and action child reference graph',()=>{
  const item=makeCase(true);
  const packet=structuredClone(item.packet) as Record<string,unknown>;
  const actions=packet.ownerActions as Array<Record<string,unknown>>;
  delete actions[0]!.actionEvidence;
  const resealed=resealPacket(packet,item.bundle);
  assertPacketError(()=>verifyS4CapturePacketChildren(resealed.bytes,resealed.bundle));
});

test('S4 packet binds the task execution identity to the sealed bundle',()=>{
  const item=makeCase(true);
  const packet=structuredClone(item.packet) as Record<string,unknown>;
  (packet.execution as Record<string,unknown>).generationId='10000000-0000-4000-8000-000000000099';
  const resealed=resealPacket(packet,item.bundle);
  assertPacketError(()=>verifyS4CapturePacketChildren(resealed.bytes,resealed.bundle),'packet_invalid');
});
