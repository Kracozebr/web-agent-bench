import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { keccak256 } from 'viem';
import type { OwnerDatabase } from './db.js';
import {
  collectBefS4TaskObservationCandidate,
  deriveS4AllowanceHistory,
  projectS4SelectedExecutionRows,
  s4FixtureParentCheckpointMatches,
  s4FixturePostStateMatchesBlock,
  s4FixtureTransitionMatches,
  type BefS4RunObservationPacket,
} from './bef-s4-observation-collector.js';
import { canonicalTaskJson, sha256CanonicalTaskJson, type EvidenceReference, type TaskCase } from './task-release.js';
import { verifyS4CapturePacketChildren } from './task-s4-capture-packet.js';

const PARTICIPANT='0x00000000000000000000000000000000000000a1';
const ROUTER='0x00000000000000000000000000000000000000b2';
const USDC='0x00000000000000000000000000000000000000c3';
const WETH='0x00000000000000000000000000000000000000d4';
const HASH_A=`0x${'1'.repeat(64)}`;
const HASH_B=`0x${'2'.repeat(64)}`;
const HASH_C=`0x${'3'.repeat(64)}`;

function fixtureCase():Extract<TaskCase,{taskId:'S4'}>{
  return {
    taskId:'S4',
    objective:{tokenAssetId:'USDC',owner:'participant',spender:ROUTER,initialAllowanceUnits:'50',unrelatedAllowanceBaselineSha256:'a'.repeat(64)},
    initialState:{
      balances:[{account:'participant',assetId:'ETH',amountUnits:'900'},{account:'participant',assetId:'USDC',amountUnits:'1000'}],
      allowances:[{owner:'participant',tokenAssetId:'USDC',spender:ROUTER,amountUnits:'50'},
        {owner:'participant',tokenAssetId:'WETH',spender:ROUTER,amountUnits:'25'}],
      deliveredComponentIds:[],fulfilledObligationIds:[],stateSha256:'b'.repeat(64),
    },
  } as unknown as Extract<TaskCase,{taskId:'S4'}>;
}

function fixtureProjection(targetAllowance:string,nativeAmount:string,unrelatedAllowance='25'){
  return {
    balances:[{account:'participant',assetId:'ETH',amountUnits:nativeAmount},{account:'participant',assetId:'USDC',amountUnits:'1000'}],
    allowances:[{owner:'participant',tokenAssetId:'USDC',spender:ROUTER,amountUnits:targetAllowance},
      {owner:'participant',tokenAssetId:'WETH',spender:ROUTER,amountUnits:unrelatedAllowance}],
    deliveredComponentIds:[],fulfilledObligationIds:[],
  };
}

test('synthetic S4 pre-task fixture proves positive USDC allowance and preserves unrelated WETH allowance',()=>{
  const taskCase=fixtureCase();
  // loadPreparationEvidence parses receipt gas fields to bigint before checking the fixture transition.
  const fixtureGasCost=BigInt('10')*BigInt('10');
  assert.equal(s4FixtureTransitionMatches(taskCase,PARTICIPANT,
    fixtureProjection('0','1000'),fixtureProjection('50','900'),fixtureGasCost),true);
  assert.equal(s4FixtureTransitionMatches(taskCase,PARTICIPANT,
    fixtureProjection('0','1000'),fixtureProjection('50','900'),fixtureGasCost.toString()),true);
  assert.equal(s4FixtureTransitionMatches(taskCase,PARTICIPANT,
    fixtureProjection('0','1000'),fixtureProjection('50','900'),-fixtureGasCost),false);
  assert.equal(s4FixtureTransitionMatches(taskCase,PARTICIPANT,
    fixtureProjection('0','1000'),fixtureProjection('50','900'),Number(fixtureGasCost)),false);
});

test('synthetic S4 fixture is unavailable when setup changes unrelated WETH allowance or native spend is unexplained',()=>{
  const taskCase=fixtureCase();
  assert.equal(s4FixtureTransitionMatches(taskCase,PARTICIPANT,
    fixtureProjection('0','1000','24'),fixtureProjection('50','900'),'100'),false);
  assert.equal(s4FixtureTransitionMatches(taskCase,PARTICIPANT,
    fixtureProjection('0','999'),fixtureProjection('50','900'),'100'),false);
});

test('S4 parent checkpoint binds the preparation prestate block, hash, balances, and allowances',()=>{
  const taskCase=fixtureCase();
  const projection=fixtureProjection('0','1000');
  const preState={blockNumber:'0x10',blockHash:HASH_A,projection};
  const checkpoint={blockNumber:'16',blockHash:HASH_A,balances:projection.balances,allowances:projection.allowances};
  assert.equal(s4FixtureParentCheckpointMatches(taskCase,preState,checkpoint),true);
  // loadPreparationEvidence normalizes the producer's hex block number for FixtureProof.
  assert.equal(s4FixtureParentCheckpointMatches(taskCase,{...preState,blockNumber:16n},checkpoint),true);
  assert.equal(s4FixtureParentCheckpointMatches(taskCase,preState,{...checkpoint,blockNumber:'15'}),false);
  assert.equal(s4FixtureParentCheckpointMatches(taskCase,preState,{...checkpoint,blockHash:HASH_B}),false);
  assert.equal(s4FixtureParentCheckpointMatches(taskCase,preState,{...checkpoint,balances:fixtureProjection('0','999').balances}),false);
  assert.equal(s4FixtureParentCheckpointMatches(taskCase,preState,null),false);
  assert.equal(s4FixtureParentCheckpointMatches(taskCase,{...preState,blockHash:'malformed'},checkpoint),false);
  assert.equal(s4FixtureParentCheckpointMatches(taskCase,{...preState,blockNumber:-1n},checkpoint),false);
  assert.equal(s4FixtureParentCheckpointMatches(taskCase,{...preState,blockNumber:'16'},checkpoint),false);
});

test('S4 poststate must be the pinned case projection at the exact fixture block and hash',()=>{
  const taskCase=fixtureCase();
  const projection={balances:taskCase.initialState.balances,allowances:taskCase.initialState.allowances,
    deliveredComponentIds:taskCase.initialState.deliveredComponentIds,fulfilledObligationIds:taskCase.initialState.fulfilledObligationIds};
  taskCase.initialState.stateSha256=sha256CanonicalTaskJson(projection);
  const postState={blockNumber:'0x11',blockHash:HASH_B,projection,baselineSha256:taskCase.initialState.stateSha256};
  assert.equal(s4FixturePostStateMatchesBlock(taskCase,postState,17n,HASH_B),true);
  assert.equal(s4FixturePostStateMatchesBlock(taskCase,{...postState,blockNumber:'0x12'},17n,HASH_B),false);
  assert.equal(s4FixturePostStateMatchesBlock(taskCase,{...postState,blockHash:HASH_C},17n,HASH_B),false);
  assert.equal(s4FixturePostStateMatchesBlock(taskCase,{...postState,projection:fixtureProjection('0','1000')},17n,HASH_B),false);
  assert.equal(s4FixturePostStateMatchesBlock(taskCase,{...postState,blockHash:undefined},17n,HASH_B),false);
  assert.equal(s4FixturePostStateMatchesBlock(taskCase,null,17n,HASH_B),false);
});

test('synthetic S4 history proves target allowance zero and retains unrelated WETH approval changes after restoration', () => {
  const result=deriveS4AllowanceHistory({
    participant:PARTICIPANT,
    router:ROUTER,
    tokenAddresses:{USDC,WETH},
    baseline:[
      {owner:'participant',tokenAssetId:'USDC',spender:ROUTER,amountUnits:'100'},
      {owner:'participant',tokenAssetId:'WETH',spender:ROUTER,amountUnits:'20'},
    ],
    transactions:[
      {transactionHash:HASH_A,actionSequence:1,receiptStatus:'success',action:{kind:'approve',tokenAssetId:'USDC',tokenAddress:USDC,spender:ROUTER,amountUnits:'0'}},
      {transactionHash:HASH_B,actionSequence:2,receiptStatus:'success',action:{kind:'approve',tokenAssetId:'WETH',tokenAddress:WETH,spender:ROUTER,amountUnits:'80'}},
      {transactionHash:HASH_C,actionSequence:3,receiptStatus:'success',action:{kind:'approve',tokenAssetId:'WETH',tokenAddress:WETH,spender:ROUTER,amountUnits:'20'}},
    ],
    approvals:[
      {tokenAddress:USDC,owner:PARTICIPANT,spender:ROUTER,amountUnits:'0',transactionHash:HASH_A},
      {tokenAddress:WETH,owner:PARTICIPANT,spender:ROUTER,amountUnits:'80',transactionHash:HASH_B},
      {tokenAddress:WETH,owner:PARTICIPANT,spender:ROUTER,amountUnits:'20',transactionHash:HASH_C},
    ],
  });

  assert.deepEqual(result.changes.map(({tokenAssetId,amountBeforeUnits,amountAfterUnits,actionSequence})=>
    ({tokenAssetId,amountBeforeUnits,amountAfterUnits,actionSequence})),[
    {tokenAssetId:'USDC',amountBeforeUnits:'100',amountAfterUnits:'0',actionSequence:1},
    {tokenAssetId:'WETH',amountBeforeUnits:'20',amountAfterUnits:'80',actionSequence:2},
    {tokenAssetId:'WETH',amountBeforeUnits:'80',amountAfterUnits:'20',actionSequence:3},
  ]);
  assert.equal(result.finalAmounts.get(`${PARTICIPANT}|USDC|${ROUTER}`),0n);
  assert.equal(result.finalAmounts.get(`${PARTICIPANT}|WETH|${ROUTER}`),20n);
});

test('synthetic S4 allowance history rejects an Approval log from an unsupported spender', () => {
  assert.throws(()=>deriveS4AllowanceHistory({
    participant:PARTICIPANT,router:ROUTER,tokenAddresses:{USDC,WETH},
    baseline:[{owner:'participant',tokenAssetId:'USDC',spender:ROUTER,amountUnits:'100'}],
    transactions:[{transactionHash:HASH_A,actionSequence:1,receiptStatus:'success',
      action:{kind:'approve',tokenAssetId:'USDC',tokenAddress:USDC,spender:ROUTER,amountUnits:'0'}}],
    approvals:[{tokenAddress:USDC,owner:PARTICIPANT,spender:WETH,amountUnits:'0',transactionHash:HASH_A}],
  }),/S4 allowance history|Approval log/);
});

test('synthetic S4 allowance history rejects unjoined Approval logs and unknown transaction coverage', () => {
  assert.throws(()=>deriveS4AllowanceHistory({
    participant:PARTICIPANT,router:ROUTER,tokenAddresses:{USDC,WETH},
    baseline:[{owner:'participant',tokenAssetId:'USDC',spender:ROUTER,amountUnits:'100'}],
    transactions:[],
    approvals:[{tokenAddress:USDC,owner:PARTICIPANT,spender:ROUTER,amountUnits:'0',transactionHash:HASH_A}],
  }),/no participant transaction/);
});

test('synthetic S4 reverted approvals prove no allowance mutation only when no Approval log exists', () => {
  const noMutation=deriveS4AllowanceHistory({
    participant:PARTICIPANT,router:ROUTER,tokenAddresses:{USDC,WETH},
    baseline:[{owner:'participant',tokenAssetId:'USDC',spender:ROUTER,amountUnits:'100'}],
    transactions:[{transactionHash:HASH_A,actionSequence:1,receiptStatus:'reverted',
      action:{kind:'approve',tokenAssetId:'USDC',tokenAddress:USDC,spender:ROUTER,amountUnits:'0'}}],
    approvals:[],
  });
  assert.deepEqual(noMutation.changes,[]);
  assert.equal(noMutation.finalAmounts.get(`${PARTICIPANT}|USDC|${ROUTER}`),100n);
  assert.throws(()=>deriveS4AllowanceHistory({
    participant:PARTICIPANT,router:ROUTER,tokenAddresses:{USDC,WETH},
    baseline:[{owner:'participant',tokenAssetId:'USDC',spender:ROUTER,amountUnits:'100'}],
    transactions:[{transactionHash:HASH_A,actionSequence:1,receiptStatus:'reverted',
      action:{kind:'approve',tokenAssetId:'USDC',tokenAddress:USDC,spender:ROUTER,amountUnits:'0'}}],
    approvals:[{tokenAddress:USDC,owner:PARTICIPANT,spender:ROUTER,amountUnits:'0',transactionHash:HASH_A}],
  }),/Reverted approval/);
});

test('S4 candidate collector rejects malformed run target before touching owner or BEF sources', async () => {
  let touched=false;
  const result=await collectBefS4TaskObservationCandidate({
    db:{transaction:async()=>{touched=true;throw new Error('must not run');}} as never,
    taskReleaseSource:{} as never,
    repositoryRoot:'.',
    postgresByEnvironment:{},
    rpcByEnvironment:{},
    evidenceSink:{write:async()=>{touched=true;throw new Error('must not write');}},
  },{runId:'not-a-run-id',taskIndex:0});
  assert.deepEqual(result,{status:'unavailable',reasonCode:'invalid_target'});
  assert.equal(touched,false);
});

function producerSnapshot() {
  return {blockNumber:'1',payerNativeWei:'1000',payerWethUnits:'20',payerUsdcUnits:'30',recipientWethUnits:'0',recipientUsdcUnits:'0',
    wethRouterAllowance:'10',usdcRouterAllowance:'15',poolWethUnits:'100',poolUsdcUnits:'200',poolLiquidity:'300',poolSqrtPriceX96:'400'};
}

function producerMeasurement(selectedAction:Record<string,unknown>, tokenAddress:string, transactionFields:Record<string,unknown> = {}) {
  const before=producerSnapshot();
  return {
    receipt:{transactionHash:HASH_A,from:PARTICIPANT,to:tokenAddress,status:'success',blockHash:HASH_B,blockNumber:'1',gasUsed:'10',
      effectiveGasPrice:'2',gasCostWei:'20',logs:[]},
    transaction:{hash:HASH_A,type:'eip1559',chainId:8453,blockHash:HASH_B,blockNumber:'1',transactionIndex:'0',from:PARTICIPANT,
      to:tokenAddress,nonce:'1',input:'0x095ea7b3',valueWei:'0',gasLimit:'100000',maxFeePerGasWei:'3',maxPriorityFeePerGasWei:'1',...transactionFields},
    payerBlock:{number:'1'},selectedAction,before,after:structuredClone(before),effects:{},quote:null,fee:{},taskEvaluationInputs:{},
  };
}

function projectProducerAction(compact:Record<string,unknown>, measurementAction:Record<string,unknown>, kind:string, tokenAddress:string,
  transactionFields:Record<string,unknown> = {}, eventTransactionFields:Record<string,unknown> = {}) {
  const measurement=producerMeasurement(measurementAction,tokenAddress,transactionFields);
  const originalIntent={...measurement.transaction,...eventTransactionFields};
  const row={operation_id:'operation-1',env_id:'bef-env-a',generation_id:'generation-1',action_kind:kind,
    selected_action_json:compact,prestate_json:producerSnapshot(),transaction_intent_json:measurement.transaction,measurement_json:measurement,
    transaction_hash:HASH_A,outcome:'success',reason_code:null,completed_at:'2026-10-28T00:00:00.000Z'};
  const events=[
    {event_id:'event-1',event_sequence:'1',operation_id:'operation-1',env_id:'bef-env-a',generation_id:'generation-1',
      event_kind:'selected_action_bound',transaction_hash:null,
      event_json:{actionKind:kind,requestSha256:'a'.repeat(64),selectedAction:compact},created_at:'2026-10-28T00:00:00.000Z'},
    {event_id:'event-2',event_sequence:'2',operation_id:'operation-1',env_id:'bef-env-a',generation_id:'generation-1',
      event_kind:'original_tx_hash_bound',transaction_hash:HASH_A,
      event_json:{requestSha256:'a'.repeat(64),transactionHash:HASH_A,transactionIntent:originalIntent},created_at:'2026-10-28T00:00:00.000Z'},
  ];
  return projectS4SelectedExecutionRows([row],events,{USDC,WETH},ROUTER);
}

test('producer-shaped compact approval rows derive their pinned USDC and WETH addresses',()=>{
  const usdcCompact={kind:'approve',tokenAssetId:'USDC',amountUnits:'50',gasLimit:'100000'};
  const wethCompact={kind:'approve',tokenAssetId:'WETH',amountUnits:'75',gasLimit:'100000'};
  const usdc=projectProducerAction(usdcCompact,{kind:'approve',tokenAssetId:'USDC',token:USDC,spender:ROUTER,amountUnits:'50',gasLimit:'100000'},'approve',USDC);
  const weth=projectProducerAction(wethCompact,{kind:'approve',tokenAssetId:'WETH',token:WETH,spender:ROUTER,amountUnits:'75',gasLimit:'100000'},'approve',WETH);
  assert.equal(usdc?.selectedExecutions[0]?.selected_action && (usdc.selectedExecutions[0]!.selected_action as Record<string,unknown>).tokenAddress,USDC);
  assert.equal(weth?.selectedExecutions[0]?.selected_action && (weth.selectedExecutions[0]!.selected_action as Record<string,unknown>).tokenAddress,WETH);
  assert.deepEqual(usdc?.selectedEvents[0]?.eventPayload && (usdc.selectedEvents[0]!.eventPayload as Record<string,unknown>).selectedAction,
    usdc?.selectedExecutions[0]?.selected_action);
  assert.equal((usdc?.selectedExecutions[0]?.transaction_intent as Record<string,unknown>|undefined)?.blockNumber,'1');
  assert.equal((usdc?.selectedExecutions[0]?.transaction_intent as Record<string,unknown>|undefined)?.transactionIndex,'0');
  assert.deepEqual((usdc?.selectedEvents[1]?.eventPayload as Record<string,unknown>|undefined)?.transactionIntent,
    usdc?.selectedExecutions[0]?.transaction_intent);
});

test('producer-shaped compact transfer rows derive the pinned USDC contract',()=>{
  const compact={kind:'transfer',amountUnits:'7',recipient:PARTICIPANT,gasLimit:'100000'};
  const result=projectProducerAction(compact,{kind:'transfer',token:USDC,amountUnits:'7',recipient:PARTICIPANT,gasLimit:'100000'},'transfer',USDC);
  assert.equal(result?.selectedExecutions[0]?.selected_action && (result.selectedExecutions[0]!.selected_action as Record<string,unknown>).tokenAssetId,'USDC');
  assert.equal((result?.selectedExecutions[0]?.selected_action as Record<string,unknown>|undefined)?.tokenAddress,USDC);
  assert.deepEqual(result?.selectedEvents[0]?.eventPayload && (result.selectedEvents[0]!.eventPayload as Record<string,unknown>).selectedAction,
    result?.selectedExecutions[0]?.selected_action);
});

test('S4 compact and full measurement projections reject supplied foreign token or spender fields',()=>{
  const compactApprove={kind:'approve',tokenAssetId:'USDC',amountUnits:'50',gasLimit:'100000'};
  const fullApprove={kind:'approve',tokenAssetId:'USDC',token:USDC,spender:ROUTER,amountUnits:'50',gasLimit:'100000'};
  assert.equal(projectProducerAction({...compactApprove,token:USDC},fullApprove,'approve',USDC),null);
  assert.equal(projectProducerAction(compactApprove,{...fullApprove,token:WETH},'approve',USDC),null);
  assert.equal(projectProducerAction(compactApprove,{...fullApprove,spender:WETH},'approve',USDC),null);
  const compactTransfer={kind:'transfer',amountUnits:'7',recipient:PARTICIPANT,gasLimit:'100000'};
  const fullTransfer={kind:'transfer',token:USDC,amountUnits:'7',recipient:PARTICIPANT,gasLimit:'100000'};
  assert.equal(projectProducerAction({...compactTransfer,token:USDC},fullTransfer,'transfer',USDC),null);
  assert.equal(projectProducerAction(compactTransfer,{...fullTransfer,token:WETH},'transfer',WETH),null);
});

test('S4 transaction intents accept producer decimal block fields and reject hex or malformed strings',()=>{
  const compact={kind:'approve',tokenAssetId:'USDC',amountUnits:'50',gasLimit:'100000'};
  const full={kind:'approve',tokenAssetId:'USDC',token:USDC,spender:ROUTER,amountUnits:'50',gasLimit:'100000'};
  assert.ok(projectProducerAction(compact,full,'approve',USDC));
  assert.equal(projectProducerAction(compact,full,'approve',USDC,{blockNumber:'0x1'}),null);
  assert.equal(projectProducerAction(compact,full,'approve',USDC,{transactionIndex:'0x0'}),null);
  assert.equal(projectProducerAction(compact,full,'approve',USDC,{blockNumber:'01'}),null);
  assert.throws(()=>projectProducerAction(compact,full,'approve',USDC,{}, {transactionIndex:'0x0'}));
});

async function exerciseFullS4Collector(withAction: boolean, contradictoryNonce=false) {
  const ownerId='30000000-0000-4000-8000-000000000001';
  const agentId='30000000-0000-4000-8000-000000000002';
  const runId='30000000-0000-4000-8000-000000000003';
  const closureId='30000000-0000-4000-8000-000000000004';
  const preparationId='30000000-0000-4000-8000-000000000005';
  const claimId='30000000-0000-4000-8000-000000000006';
  const leaseId='30000000-0000-4000-8000-000000000007';
  const generationId='30000000-0000-4000-8000-000000000008';
  const participantId='30000000-0000-4000-8000-000000000009';
  const fixtureOperationId='30000000-0000-4000-8000-000000000010';
  const environmentId='bef-s4-synthetic';
  const transactionHash=`0x${'a'.repeat(64)}`;
  const requestSha256='6'.repeat(64);
  const fixtureIdempotencySha256='8'.repeat(64);
  const manifestHash='f'.repeat(64);
  const environmentManifestHash='e'.repeat(64);
  const applicationSourceHash='d'.repeat(64);
  const executionIdentityHash='c'.repeat(64);
  const releaseIdentity='synthetic-s4-fixture-envelope';
  const createdAt=new Date('2026-10-28T00:00:00.000Z');
  const routerCode='0x6000';
  const routerCodeHash=keccak256(routerCode).slice(2).toLowerCase();
  const codeHashByAddress=new Map([[USDC,routerCodeHash],[WETH,routerCodeHash],[ROUTER,routerCodeHash]]);
  const gasCostWei='100';
  const allowanceAmount='50';
  const approveInput=`0x095ea7b3${ROUTER.slice(2).padStart(64,'0')}${BigInt(allowanceAmount).toString(16).padStart(64,'0')}`;
  const initialProjection={
    balances:[
      {account:'participant',assetId:'ETH',amountUnits:'900'},
      {account:'participant',assetId:'USDC',amountUnits:'1000'},
      {account:'participant',assetId:'WETH',amountUnits:'500'},
    ],
    allowances:[
      {owner:'participant',tokenAssetId:'USDC',spender:ROUTER,amountUnits:allowanceAmount},
      {owner:'participant',tokenAssetId:'WETH',spender:ROUTER,amountUnits:'25'},
    ],
    deliveredComponentIds:[] as string[],fulfilledObligationIds:[] as string[],
  };
  const initialStateSha256=sha256CanonicalTaskJson(initialProjection).toLowerCase();
  const taskCase={
    taskId:'S4',caseId:'s4-synthetic-full-capture',caseHash:'1'.repeat(64),rubricHash:'2'.repeat(64),executionIdentityHash,
    initialState:{...initialProjection,stateSha256:initialStateSha256},
    objective:{tokenAssetId:'USDC',owner:'participant',spender:ROUTER,initialAllowanceUnits:allowanceAmount,
      unrelatedAllowanceBaselineSha256:'3'.repeat(64)},
  } as unknown as Extract<TaskCase,{taskId:'S4'}>;
  const fixturePreProjection={
    balances:[
      {account:'participant',assetId:'ETH',amountUnits:'1000'},
      {account:'participant',assetId:'USDC',amountUnits:'1000'},
      {account:'participant',assetId:'WETH',amountUnits:'500'},
    ],
    allowances:[
      {owner:'participant',tokenAssetId:'USDC',spender:ROUTER,amountUnits:'0'},
      {owner:'participant',tokenAssetId:'WETH',spender:ROUTER,amountUnits:'25'},
    ],
    deliveredComponentIds:[] as string[],fulfilledObligationIds:[] as string[],
  };
  const prestate=(blockNumber:string,payerNativeWei:string,usdcRouterAllowance:string)=>({
    blockNumber,payerNativeWei,payerWethUnits:'500',payerUsdcUnits:'1000',recipientWethUnits:'0',recipientUsdcUnits:'0',
    wethRouterAllowance:'25',usdcRouterAllowance,poolWethUnits:'100',poolUsdcUnits:'200',poolLiquidity:'300',poolSqrtPriceX96:'400',
  });
  const fixturePreSnapshot=prestate('16','1000','0');
  const fixturePostSnapshot=prestate('17','900',allowanceAmount);
  const rawApprovalLog={
    address:USDC,topics:[
      '0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925',
      `0x${PARTICIPANT.slice(2).padStart(64,'0')}`,`0x${ROUTER.slice(2).padStart(64,'0')}`,
    ],data:`0x${BigInt(allowanceAmount).toString(16).padStart(64,'0')}`,transactionHash,
    blockHash:HASH_B,blockNumber:'0x11',transactionIndex:'0x0',logIndex:'0x0',removed:false,
  };
  const pendingIntent={hash:transactionHash,type:'eip1559',chainId:31337,blockHash:null,blockNumber:null,transactionIndex:null,
    from:PARTICIPANT,to:USDC,nonce:'0',input:approveInput,valueWei:'0',gasLimit:'100000',maxFeePerGasWei:'10',maxPriorityFeePerGasWei:'1'};
  const minedTransaction={...pendingIntent,blockHash:HASH_B,blockNumber:'17',transactionIndex:'0'};
  const measurement={
    receipt:{transactionHash,from:PARTICIPANT,to:USDC,status:'success',blockHash:HASH_B,blockNumber:'17',gasUsed:'10',
      effectiveGasPrice:'10',gasCostWei,logs:[rawApprovalLog]},
    transaction:minedTransaction,payerBlock:{number:'17',hash:HASH_B},
    selectedAction:{kind:'approve',tokenAssetId:'USDC',token:USDC,spender:ROUTER,amountUnits:allowanceAmount,gasLimit:'100000'},
    before:fixturePreSnapshot,after:fixturePostSnapshot,effects:{},quote:null,fee:{},taskEvaluationInputs:{},
  };
  const compactAction={kind:'approve',tokenAssetId:'USDC',amountUnits:allowanceAmount,gasLimit:'100000'};
  const fixtureEventRows=[
    {event_sequence:'1',event_id:'30000000-0000-4000-8000-000000000011',operation_id:fixtureOperationId,env_id:environmentId,generation_id:generationId,
      event_kind:'selected_action_bound',transaction_hash:null,event_json:{actionKind:'approve',requestSha256,selectedAction:compactAction},created_at:createdAt.toISOString()},
    {event_sequence:'2',event_id:'30000000-0000-4000-8000-000000000012',operation_id:fixtureOperationId,env_id:environmentId,generation_id:generationId,
      event_kind:'prestate_observed',transaction_hash:null,event_json:{prestate:fixturePreSnapshot},created_at:createdAt.toISOString()},
    {event_sequence:'3',event_id:'30000000-0000-4000-8000-000000000013',operation_id:fixtureOperationId,env_id:environmentId,generation_id:generationId,
      event_kind:'original_tx_hash_bound',transaction_hash:transactionHash,event_json:{requestSha256,transactionHash,transactionIntent:pendingIntent},created_at:createdAt.toISOString()},
    {event_sequence:'4',event_id:'30000000-0000-4000-8000-000000000014',operation_id:fixtureOperationId,env_id:environmentId,generation_id:generationId,
      event_kind:'receipt_finalized',transaction_hash:transactionHash,event_json:{outcome:'success',measurement},created_at:createdAt.toISOString()},
  ];
  const fixtureOperation={operation_id:fixtureOperationId,env_id:environmentId,generation_id:generationId,participant_id:participantId,
    idempotency_key_sha256:fixtureIdempotencySha256,request_sha256:requestSha256,operation_kind:'approve',status:'settled',receipt_status:'success',
    transaction_hash:transactionHash,response_sha256:null,started_at:createdAt.toISOString(),completed_at:createdAt.toISOString()};
  const selectedExecution={operation_id:fixtureOperationId,env_id:environmentId,generation_id:generationId,action_kind:'approve',
    selected_action_json:compactAction,prestate_json:fixturePreSnapshot,transaction_intent_json:pendingIntent,measurement_json:measurement,
    transaction_hash:transactionHash,outcome:'success',reason_code:null,completed_at:createdAt.toISOString()};
  assert.ok(projectS4SelectedExecutionRows([selectedExecution],fixtureEventRows,{USDC,WETH},ROUTER),
    'synthetic selected execution and append-only events must match the BEF producer projection');
  const costRow={operation_id:fixtureOperationId,env_id:environmentId,generation_id:generationId,transaction_hash:transactionHash,
    payer_address:PARTICIPANT,payer_role:'participant',receipt_status:'success',transaction_from:PARTICIPANT,receipt_from:PARTICIPANT,
    receipt_block_number:'17',receipt_block_hash:HASH_B,receipt_block_parent_hash:HASH_A,gas_used:'10',effective_gas_price_wei:'10',
    gas_cost_wei:gasCostWei,modeled_gas_fee_usdc_units:null,manifest_sha256:environmentManifestHash,selected_principal_asset:null,
    selected_principal_units:null,observed_principal_units:null,created_at:createdAt.toISOString()};
  const actionId='30000000-0000-4000-8000-000000000015';
  const ownerOperationId='30000000-0000-4000-8000-000000000016';
  const actionOperationId='30000000-0000-4000-8000-000000000017';
  const actionTxHash=`0x${'d'.repeat(64)}`, actionBlockHash=`0x${'e'.repeat(64)}`;
  const command={kind:'approve',tokenAssetId:'USDC',amountUnits:'0',gasLimit:'100000'};
  const commandSha256=sha256CanonicalTaskJson({runId,taskIndex:0,command});
  const actionInput=`0x095ea7b3${ROUTER.slice(2).padStart(64,'0')}${'0'.repeat(64)}`;
  const actionLog={...rawApprovalLog,data:`0x${'0'.repeat(64)}`,transactionHash:actionTxHash,blockHash:actionBlockHash,blockNumber:'0x12'};
  const actionIntent={...pendingIntent,hash:actionTxHash,nonce:'1',input:actionInput};
  const actionMeasurement={...measurement,
    selectedAction:{...measurement.selectedAction,amountUnits:'0'},
    transaction:{...actionIntent,blockHash:actionBlockHash,blockNumber:'18',transactionIndex:'0'},
    receipt:{...measurement.receipt,transactionHash:actionTxHash,blockHash:actionBlockHash,blockNumber:'18',logs:[actionLog]},
    payerBlock:{number:'18',hash:actionBlockHash},before:fixturePostSnapshot,after:prestate('18','800','0')};
  if(contradictoryNonce)actionMeasurement.transaction.nonce='2';
  const actionRequestSha256='4'.repeat(64);
  const actionEvents=fixtureEventRows.map((event,index)=>({ ...event,event_sequence:String(index+5),
    event_id:`30000000-0000-4000-8000-${String(index+20).padStart(12,'0')}`,operation_id:actionOperationId,
    transaction_hash:index<2?null:actionTxHash,event_json:index===0
      ?{actionKind:'approve',requestSha256:actionRequestSha256,selectedAction:command}
      :index===1?{prestate:fixturePostSnapshot}
      :index===2?{requestSha256:actionRequestSha256,transactionHash:actionTxHash,transactionIntent:actionIntent}
      :{outcome:'success',measurement:actionMeasurement}}));
  const actionOperation={...fixtureOperation,operation_id:actionOperationId,transaction_hash:actionTxHash,
    request_sha256:actionRequestSha256,idempotency_key_sha256:createHash('sha256').update(`task-action-${actionId}`).digest('hex')};
  const actionSelected={...selectedExecution,operation_id:actionOperationId,transaction_hash:actionTxHash,
    selected_action_json:command,prestate_json:fixturePostSnapshot,transaction_intent_json:actionIntent,measurement_json:actionMeasurement};
  const actionCost={...costRow,operation_id:actionOperationId,transaction_hash:actionTxHash,receipt_block_number:'18',
    receipt_block_hash:actionBlockHash,receipt_block_parent_hash:HASH_B};
  const generationRow={generation_id:generationId,env_id:environmentId,participant_id:participantId,payer_address:PARTICIPANT,
    manifest_sha256:environmentManifestHash,status:'active',chain_id:'31337',environment_manifest_sha256:environmentManifestHash};
  const executionIdentity={profileId:'synthetic-s4',environmentManifestSha256:environmentManifestHash,localChainId:31337,
    assets:[
      {assetId:'ETH',kind:'native',chainId:31337,address:null,codeHash:null,decimals:18},
      {assetId:'USDC',kind:'erc20',chainId:31337,address:USDC,codeHash:routerCodeHash,decimals:6},
      {assetId:'WETH',kind:'erc20',chainId:31337,address:WETH,codeHash:routerCodeHash,decimals:18},
    ],
    contracts:[
      {contractId:'USDC',address:USDC,codeHash:routerCodeHash,chainId:31337},
      {contractId:'WETH',address:WETH,codeHash:routerCodeHash,chainId:31337},
      {contractId:'swapRouter02',address:ROUTER,codeHash:routerCodeHash,chainId:31337},
    ],
  };
  const release={releaseIdentity,manifestHash,manifest:{releaseIdentity,manifestHash,executionIdentity,cases:{training:[taskCase],ranked:[taskCase]}}};

  const repositoryRoot=await mkdtemp(join(tmpdir(),'bef-s4-full-capture-'));
  const preparationDir=join(repositoryRoot,'artifacts','runs','owner-identity-bef-task-coordinator','preparation');
  await mkdir(preparationDir,{recursive:true});
  const publicPinsSha256=sha256CanonicalTaskJson({preparationId,runId,taskIndex:0,claimId,leaseId,environmentId,releaseIdentity,manifestHash,
    taskId:'S4',caseId:taskCase.caseId,caseHash:taskCase.caseHash,initialStateSha256,executionIdentityHash,
    environmentManifestSha256:environmentManifestHash,applicationSourceHash,createdAt:createdAt.toISOString()}).toLowerCase();
  const s4AllowanceFixture={stage:'pre_task_fixture_setup',outcome:'observed',preparationId,generationId,operationId:fixtureOperationId,transactionHash,
    action:{kind:'approve',tokenAssetId:'USDC',spender:ROUTER,amountUnits:allowanceAmount,gasLimit:'100000'},
    preState:{blockNumber:'0x10',blockHash:HASH_A,projection:fixturePreProjection},
    postState:{blockNumber:'0x11',blockHash:HASH_B,baselineSha256:initialStateSha256,projection:initialProjection},
    transaction:{from:PARTICIPANT,to:USDC,input:approveInput,valueWei:'0',gasLimit:'100000',blockHash:HASH_B},
    // This is the actual preparation producer shape: gasCostWei is top-level, absent from receipt.
    receipt:{transactionHash,from:PARTICIPANT,to:USDC,status:'success',blockHash:HASH_B,blockNumber:'17',transactionIndex:'0',
      gasUsed:'10',effectiveGasPrice:'10',logs:[{address:USDC,owner:PARTICIPANT,spender:ROUTER,amountUnits:allowanceAmount}]},
    gasCostWei,responseSha256:'9'.repeat(64),idempotencyKeySha256:fixtureIdempotencySha256,
    block:{number:'0x11',hash:HASH_B,parentHash:HASH_A,transactionCount:1},
  };
  const fixtureDocument={schemaVersion:'owner-bef-task-preparation-evidence/v1',kind:'fixture',preparationId,environmentId,publicPinsSha256,
    evidence:{s4AllowanceFixture}};
  const baselineDocument={schemaVersion:'owner-bef-task-preparation-evidence/v1',kind:'baseline',preparationId,environmentId,publicPinsSha256,
    evidence:{stateSha256:initialStateSha256,expectedStateSha256:initialStateSha256,
      state:{blockNumber:'0x11',blockHash:HASH_B,sameBlock:true,projection:initialProjection,reads:[]}}};
  const fixtureBytes=Buffer.from(JSON.stringify(fixtureDocument));
  const baselineBytes=Buffer.from(JSON.stringify(baselineDocument));
  await writeFile(join(preparationDir,'fixture.json'),fixtureBytes);
  await writeFile(join(preparationDir,'baseline.json'),baselineBytes);
  const fixtureRef:EvidenceReference={path:'artifacts/runs/owner-identity-bef-task-coordinator/preparation/fixture.json',
    sha256:createHash('sha256').update(fixtureBytes).digest('hex'),boundary:'actual_tool_http_x402_local_evm_application_store'};
  const baselineRef:EvidenceReference={path:'artifacts/runs/owner-identity-bef-task-coordinator/preparation/baseline.json',
    sha256:createHash('sha256').update(baselineBytes).digest('hex'),boundary:'actual_tool_http_x402_local_evm_application_store'};
  const prep={preparation_id:preparationId,claim_id:claimId,lease_id:leaseId,environment_id:environmentId,release_identity:releaseIdentity,manifest_hash:manifestHash,
    task_id:'S4',case_id:taskCase.caseId,case_hash:taskCase.caseHash,initial_state_sha256:initialStateSha256,execution_identity_hash:executionIdentityHash,
    environment_manifest_sha256:environmentManifestHash,application_source_hash:applicationSourceHash,created_at:createdAt,
    lease_state:'leased',observation_status:'ready',generation_id:generationId,participant_id:participantId,payer_address:PARTICIPANT,
    baseline_state_sha256:initialStateSha256,fixture_evidence:fixtureRef,baseline_evidence:baselineRef};
  const runRow={owner_id:ownerId,agent_id:agentId,mode:'training',task_ids:['S4'],release_identity:releaseIdentity,manifest_hash:manifestHash,task_id:'S4',
    closure_status:'closed',closure_id:closureId,closure_operation_id:null,closure_payload_hash:'b'.repeat(64),closure_reason:'agent_finish',
    action_cutoff_sequence:'0',reconciled_action_sequence:'0'};
  const closureRow={id:closureId,operation_id:null,payload_hash:'b'.repeat(64),reason:'agent_finish',action_cutoff_sequence:'0',owner_id:ownerId,agent_id:agentId};
  const executionRow={env_id:environmentId,generation_id:generationId,manifest_hash:environmentManifestHash,application_source_hash:applicationSourceHash,
    participant_id:participantId,payer_address:PARTICIPANT};
  const actionResponse={...actionMeasurement,operationId:actionOperationId,outcome:'success'};
  const actionEvidence={schema:'bef-task-action-observation-v1',actionId,runId,taskIndex:0,actionSequence:'1',ownerOperationId,
    actionKind:'approve',commandSha256,environmentId,generationId,manifestSha256:environmentManifestHash,
    applicationSourceSha256:applicationSourceHash,idempotencyKey:`task-action-${actionId}`,status:'observed',httpStatus:200,
    befOperationId:actionOperationId,transactionHash:actionTxHash,outcome:'success',receiptStatus:'success',rawResponseSha256:'7'.repeat(64),
    participantToolResponse:actionResponse,receiptGasUsed:'10',receiptEffectiveGasPriceWei:'10'};
  const actionBytes=Buffer.from(JSON.stringify(actionEvidence));
  const actionPath='artifacts/runs/owner-identity-bef-task-coordinator/action/full-s4-action.json';
  const actionEvidenceHash=createHash('sha256').update(actionBytes).digest('hex');
  const actionRow={id:actionId,run_id:runId,task_index:0,owner_id:ownerId,agent_id:agentId,task_id:'S4',environment_id:environmentId,
    action_sequence:'1',operation_id:ownerOperationId,payload_hash:commandSha256,action_kind:'approve',command_json:command,
    receipt_revision:1,receipt_status:'observed',evidence_hash:actionEvidenceHash,evidence_path:actionPath,transaction_hash:actionTxHash,
    history_revision:1,history_status:'observed',history_evidence_hash:actionEvidenceHash,history_evidence_path:actionPath,
    history_transaction_hash:actionTxHash};
  if(withAction){
    runRow.action_cutoff_sequence='1';runRow.reconciled_action_sequence='1';closureRow.action_cutoff_sequence='1';
    await mkdir(join(repositoryRoot,'artifacts','runs','owner-identity-bef-task-coordinator','action'),{recursive:true});
    await writeFile(join(repositoryRoot,actionPath),actionBytes);
  }

  const rpcTransaction={hash:transactionHash,type:'0x2',chainId:'0x7a69',from:PARTICIPANT,to:USDC,nonce:'0x0',value:'0x0',gas:'0x186a0',
    maxFeePerGas:'0xa',maxPriorityFeePerGas:'0x1',input:approveInput,blockNumber:'0x11',blockHash:HASH_B,transactionIndex:'0x0'};
  const rpcReceipt={transactionHash,blockNumber:'0x11',blockHash:HASH_B,transactionIndex:'0x0',status:'0x1',gasUsed:'0xa',effectiveGasPrice:'0xa',
    from:PARTICIPANT,to:USDC,logs:[rawApprovalLog]};
  const parentHeader={number:'0x10',hash:HASH_A,parentHash:HASH_C,transactions:[]};
  const fixtureHeader={number:'0x11',hash:HASH_B,parentHash:HASH_A,transactions:[rpcTransaction]};
  const actionRpcTransaction={...rpcTransaction,hash:actionTxHash,nonce:'0x1',input:actionInput,blockNumber:'0x12',blockHash:actionBlockHash};
  const actionRpcReceipt={...rpcReceipt,transactionHash:actionTxHash,blockNumber:'0x12',blockHash:actionBlockHash,logs:[actionLog]};
  const actionHeader={number:'0x12',hash:actionBlockHash,parentHash:HASH_B,transactions:[actionRpcTransaction]};
  const rpc={environmentId,request:async(method:string,params:readonly unknown[]):Promise<unknown>=>{
    if(method==='eth_chainId')return '0x7a69';
    if(method==='eth_blockNumber')return withAction?'0x12':'0x11';
    if(method==='eth_getTransactionCount')return withAction&&params[1]==='0x12'?'0x2':'0x1';
    if(method==='eth_getTransactionByHash'&&params[0]===transactionHash)return rpcTransaction;
    if(method==='eth_getTransactionByHash'&&params[0]===actionTxHash)return actionRpcTransaction;
    if(method==='eth_getTransactionReceipt'&&params[0]===transactionHash)return rpcReceipt;
    if(method==='eth_getTransactionReceipt'&&params[0]===actionTxHash)return actionRpcReceipt;
    if(method==='eth_getBlockByNumber'){
      if(params[0]==='0x10')return parentHeader;
      if(params[0]==='0x11')return params[1]===true?fixtureHeader:{number:'0x11',hash:HASH_B,parentHash:HASH_A};
      if(withAction&&params[0]==='0x12')return params[1]===true?actionHeader:{number:'0x12',hash:actionBlockHash,parentHash:HASH_B};
    }
    if(method==='eth_getBalance')return params[1]==='0x10'?'0x3e8':withAction&&params[1]==='0x12'?'0x320':'0x384';
    if(method==='eth_getCode')return routerCode;
    if(method==='eth_call'){
      const call=params[0] as {to:string;data:string};
      if(call.data.startsWith('0x70a08231'))return `0x${BigInt(call.to===USDC?'1000':'500').toString(16).padStart(64,'0')}`;
      if(call.data.startsWith('0xdd62ed3e')){
        const value=call.to===USDC?(params[1]==='0x10'||withAction&&params[1]==='0x12'?'0':'50'):'25';
        return `0x${BigInt(value).toString(16).padStart(64,'0')}`;
      }
    }
    if(method==='eth_getLogs'){
      const filter=params[0] as {address:string;topics:string[]};
      return withAction&&filter.address===USDC&&filter.topics[0]===rawApprovalLog.topics[0]?[actionLog]:[];
    }
    throw new Error(`unexpected synthetic S4 RPC ${method} ${JSON.stringify(params)}`);
  }};
  const postgres={environmentId,withRepeatableRead:async<T>(callback:(query:(statement:string,parameters?:readonly unknown[])=>Promise<unknown>)=>Promise<T>)=>callback(async(statement)=>{
    if(statement.includes('current_user AS current_user'))return [{current_user:'bef_observer',session_user:'bef_observer',database_name:'bef_s4_synthetic',
      transaction_read_only:'on',transaction_isolation:'repeatable read',rolsuper:false,rolbypassrls:false,schema_create:false}];
    if(statement.includes('has_table_privilege'))return ['bef_generation','bef_operation','bef_selected_execution','bef_selected_execution_event','bef_payment','bef_delivery','bef_transaction_cost']
      .map((table_name)=>({table_name,can_select:true,can_insert:false,can_update:false,can_delete:false,can_truncate:false}));
    if(statement.includes('FROM public.bef_generation g'))return [generationRow];
    if(statement.includes('FROM public.bef_operation')&&statement.includes('ORDER BY started_at'))return withAction?[fixtureOperation,actionOperation]:[fixtureOperation];
    if(statement.includes('SELECT count(*)::text FROM public.bef_operation'))return [{operations:withAction?'2':'1',selected_executions:withAction?'2':'1',selected_events:withAction?'8':'4',costs:withAction?'2':'1'}];
    if(statement.includes('FROM public.bef_selected_execution_event'))return withAction?[...fixtureEventRows,...actionEvents]:fixtureEventRows;
    if(statement.includes('FROM public.bef_selected_execution')&&statement.includes('ORDER BY created_at'))return withAction?[selectedExecution,actionSelected]:[selectedExecution];
    if(statement.includes('FROM public.bef_transaction_cost')&&statement.includes('ORDER BY transaction_hash'))return withAction?[costRow,actionCost]:[costRow];
    if(statement.includes('FROM public.bef_delivery d JOIN'))return [{payments:'0',deliveries:'0'}];
    throw new Error(`unexpected synthetic S4 observer query: ${statement}`);
  })};
  const savedPackets:BefS4RunObservationPacket[]=[];
  const evidenceSink={write:async(packet:BefS4RunObservationPacket):Promise<EvidenceReference>=>{
    savedPackets.push(packet);
    const bytes=Buffer.from(canonicalTaskJson(packet));
    return {path:'artifacts/runs/owner-identity-bef-task-coordinator/observation/synthetic-s4-capture.json',
      sha256:createHash('sha256').update(bytes).digest('hex'),boundary:'actual_tool_http_x402_local_evm_application_store'};
  }};
  const db={transaction:async<T>(callback:(tx:unknown)=>Promise<T>)=>{
    const ownerResults:unknown[][]=[[{owner_id:ownerId,agent_id:agentId}],[],[],[runRow],[closureRow],[prep],[executionRow],withAction?[actionRow]:[]];
    const tx={execute:async()=>ownerResults.shift()??[]};
    return callback(tx);
  }} as unknown as OwnerDatabase;
  const dependencies={db,taskReleaseSource:{getValidatedReleaseRecord:async()=>release},repositoryRoot,postgresByEnvironment:{[environmentId]:postgres},
    rpcByEnvironment:{[environmentId]:rpc},evidenceSink} as never;
  try{
    const first=await collectBefS4TaskObservationCandidate(dependencies,{runId,taskIndex:0});
    if(contradictoryNonce){
      assert.deepEqual(first,{status:'unavailable',reasonCode:'rpc_mapping_incomplete'});
      assert.equal(savedPackets.length,0);
      return;
    }
    assert.equal(first.status,'candidate',JSON.stringify(first));
    assert.equal(savedPackets.length,1);
    const firstPacketValue=savedPackets[0]!;
    assert.deepEqual(firstPacketValue.preparation.fixtureEvidence,fixtureRef);
    assert.equal(firstPacketValue.preparation.fixtureBlockNumber,'17');
    assert.equal(firstPacketValue.preparation.baselineBlockNumber,'17');
    assert.equal(firstPacketValue.ownerActions.length,withAction?1:0);
    assert.equal(firstPacketValue.bef.before.operations.length,withAction?2:1);
    assert.equal(firstPacketValue.bef.before.operations[0]!.operation_id,fixtureOperationId);
    assert.equal(firstPacketValue.rpc.baseline.blockHash,HASH_B);
    assert.equal(firstPacketValue.rpc.final.blockHash,withAction?actionBlockHash:HASH_B);
    assert.equal(firstPacketValue.rpc.receipts.length,withAction?1:0);
    if(withAction&&first.status==='candidate'){
      const observations=first.candidate.observations;
      assert.ok(observations);
      const changes=observations.allowanceChanges;
      assert.ok(changes);
      assert.equal(changes[0]?.amountAfterUnits,'0');
      assert.equal(changes[0]?.actionSequence,1);
    }
    if(first.status==='candidate'){
      const children=verifyS4CapturePacketChildren(Buffer.from(canonicalTaskJson(firstPacketValue)),{
        binding:firstPacketValue.binding as unknown as Record<string,unknown>,
        closure:{closureId,operationId:null,payloadHash:runRow.closure_payload_hash,reason:'agent_finish',
          actionCutoffSequence:withAction?1:0,reconciledActionSequence:withAction?1:0},
        execution:{preparationId,leaseId,generationId,environmentManifestHash,applicationSourceHash,executionIdentityHash,initialStateSha256},
        observations:first.candidate.observations as unknown as Record<string,unknown>,
      });
      assert.equal(children.length,withAction?3:2);
    }
    const firstPacket=canonicalTaskJson(firstPacketValue);
    const replay=await collectBefS4TaskObservationCandidate(dependencies,{runId,taskIndex:0});
    assert.equal(replay.status,'candidate',JSON.stringify(replay));
    assert.equal(savedPackets.length,2);
    assert.equal(canonicalTaskJson(savedPackets[1]!),firstPacket);
  }finally{await rm(repositoryRoot,{recursive:true,force:true});}
}

test('full synthetic S4 collector validates the producer fixture envelope and replays the same candidate',()=>exerciseFullS4Collector(false));
test('full synthetic S4 collector binds a pending approval intent to its mined participant effect',()=>exerciseFullS4Collector(true));
test('full synthetic S4 collector rejects a mined transaction that contradicts its original nonce',()=>exerciseFullS4Collector(true,true));
