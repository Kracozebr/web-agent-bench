import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';
import { canonicalTaskJson } from './task-release.js';
import type { OwnerDatabase } from './db.js';
import {
  collectBefM1TaskObservationCandidate,
  m1PreparationHealthMatches,
  parseM1PreparationEvidence,
  decodeM1TransferLog,
  validateM1OperationCensus,
  type BefM1ObservationCollectorDependencies,
} from './bef-m1-observation-collector.js';

const RUN_ID = '10000000-0000-4000-8000-000000000001';
const OWNER_ID = '10000000-0000-4000-8000-000000000002';
const AGENT_ID = '10000000-0000-4000-8000-000000000003';

test('M1 receipt transfer decoder preserves the original JSON-RPC block quantity', () => {
  const token=`0x${'1'.repeat(40)}`,payer=`0x${'2'.repeat(40)}`,recipient=`0x${'3'.repeat(40)}`;
  const raw={address:token,transactionHash:`0x${'4'.repeat(64)}`,blockHash:`0x${'5'.repeat(64)}`,blockNumber:'0x123',logIndex:'0x0',
    topics:['0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef',`0x${'0'.repeat(24)}${payer.slice(2)}`,`0x${'0'.repeat(24)}${recipient.slice(2)}`],
    data:`0x${'0'.repeat(63)}1`,removed:false};
  assert.deepEqual(decodeM1TransferLog(raw,token,'USDC',payer),{assetId:'USDC',tokenAddress:token,transactionHash:raw.transactionHash,
    blockNumber:'291',blockHash:raw.blockHash,logIndex:'0',from:payer,to:recipient,amountUnits:'1'});
  assert.throws(()=>decodeM1TransferLog({...raw,blockNumber:291n},token,'USDC',payer));
});

test('M1 baseline permits only exact public balance and allowance reads without weakening signed-data checks', () => {
  const to=`0x${'1'.repeat(40)}`,account=`${'0'.repeat(24)}${'2'.repeat(40)}`,spender=`${'0'.repeat(24)}${'3'.repeat(40)}`;
  const baseline={evidence:{state:{blockNumber:'0x123',reads:[
    {method:'eth_call',params:[{to,data:`0x70a08231${account}`},'0x123'],result:'0x0'},
    {method:'eth_call',params:[{to,data:`0xdd62ed3e${account}${spender}`},'0x123'],result:'0x0'},
  ]}}};
  const parse=(value:unknown)=>parseM1PreparationEvidence(Buffer.from(JSON.stringify(value)),'baseline');
  assert.deepEqual(parse(baseline),baseline);
  const wrongSelector=structuredClone(baseline);wrongSelector.evidence.state.reads[0]!.params[0]={to,data:`0xa9059cbb${account}${spender}`};
  assert.throws(()=>parse(wrongSelector));
  const wrongBlock=structuredClone(baseline);wrongBlock.evidence.state.reads[0]!.params[1]='latest';assert.throws(()=>parse(wrongBlock));
  assert.throws(()=>parse({...baseline,input:'signed-transaction-material'}));
  assert.throws(()=>parse({...baseline,evidence:{...baseline.evidence,signature:'not-retained'}}));
  assert.throws(()=>parseM1PreparationEvidence(Buffer.from(JSON.stringify(baseline)),'fixture'));
});

test('M1 preparation accepts the API writer boundary while rejecting foreign identities and fork labels', () => {
  const pins = { environmentId:'bef-env-a', preparationId:RUN_ID, generationId:AGENT_ID,
    environmentManifestHash:'a'.repeat(64), applicationSourceHash:'b'.repeat(64) };
  const health = { boundary:'benchmark-environment-api', environmentId:pins.environmentId,
    environmentManifestSha256:pins.environmentManifestHash, applicationSourceSha256:pins.applicationSourceHash,
    localNetwork:'eip155:8453', localChainId:8453 };
  const status = { schemaVersion:'bef-preparation-status/v1', envId:pins.environmentId,
    preparationId:pins.preparationId, generationId:pins.generationId, status:'ready' };
  assert.equal(m1PreparationHealthMatches(health,status,pins),true);
  assert.equal(m1PreparationHealthMatches({...health,boundary:'private_fork'},status,pins),false);
  assert.equal(m1PreparationHealthMatches({...health,environmentId:'bef-env-b'},status,pins),false);
  assert.equal(m1PreparationHealthMatches(health,{...status,generationId:OWNER_ID},pins),false);
  assert.equal(m1PreparationHealthMatches({...health,applicationSourceSha256:'c'.repeat(64)},status,pins),false);
  assert.equal(m1PreparationHealthMatches(health,{...status,schemaVersion:'bef-public-preparation-status/v1'},pins),false);
});

function dependencies(results: unknown[][], calls: { transactions: number; observer: number; evidence: number }): BefM1ObservationCollectorDependencies {
  const tx = { execute: async () => results.shift() ?? [] };
  const db = { transaction: async (callback: (tx: unknown) => Promise<unknown>) => {
    calls.transactions += 1;
    return callback(tx);
  } } as unknown as OwnerDatabase;
  return {
    db,
    taskReleaseSource: { getValidatedReleaseRecord: async () => { throw new Error('must not load release'); } },
    repositoryRoot: 'unused-before-cutoff',
    postgresByEnvironment: { 'bef-env-a': { environmentId: 'bef-env-a', withRepeatableRead: async () => {
      calls.observer += 1; throw new Error('must not query observer');
    } } },
    rpcByEnvironment: {},
    evidenceSink: { write: async () => { calls.evidence += 1; throw new Error('must not write evidence'); } },
  } as unknown as BefM1ObservationCollectorDependencies;
}

test('M1 collector rejects malformed targets before opening the owner transaction', async () => {
  const calls = { transactions: 0, observer: 0, evidence: 0 };
  const result = await collectBefM1TaskObservationCandidate(dependencies([], calls), { runId: 'not-a-uuid', taskIndex: 0 });
  assert.deepEqual(result, { status: 'unavailable', reasonCode: 'invalid_target' });
  assert.deepEqual(calls, { transactions: 0, observer: 0, evidence: 0 });
});

test('M1 collector leaves a closed action cutoff pending until every action receipt is reconciled', async () => {
  const calls = { transactions: 0, observer: 0, evidence: 0 };
  const run = {
    owner_id: OWNER_ID, agent_id: AGENT_ID, mode: 'training', task_ids: ['M1'], release_identity: 'release', manifest_hash: 'a'.repeat(64),
    status: 'running', cancellation_reason: null, task_id: 'M1', task_status: 'active', started_at: '2026-10-28T00:00:00.000Z',
    closure_status: 'closed', closure_id: '10000000-0000-4000-8000-000000000004',
    closure_operation_id: 'finish-operation', closure_payload_hash: 'b'.repeat(64), closure_reason: 'agent_finish',
    action_cutoff_sequence: '1', reconciled_action_sequence: '0',
  };
  const deps = dependencies([
    [{ owner_id: OWNER_ID, agent_id: AGENT_ID }], // owner/run identity
    [], // owner lock
    [], // agent lock
    [run], // the exact M1 task/run snapshot
  ], calls);
  const result = await collectBefM1TaskObservationCandidate(deps, { runId: RUN_ID, taskIndex: 0 });
  assert.deepEqual(result, { status: 'unavailable', reasonCode: 'reconciliation_pending' });
  assert.deepEqual(calls, { transactions: 1, observer: 0, evidence: 0 });
});

test('M1 collector refuses ranked, cancelled, or mismatched task targets before reading BEF state', async (t) => {
  for (const change of [
    { mode: 'ranked' },
    { cancellation_reason: 'owner_cancelled' },
    { task_id: 'S1' },
    { task_ids: ['S1'] },
  ]) {
    await t.test(JSON.stringify(change), async () => {
      const calls = { transactions: 0, observer: 0, evidence: 0 };
      const run = {
        owner_id: OWNER_ID, agent_id: AGENT_ID, mode: 'training', task_ids: ['M1'], release_identity: 'release', manifest_hash: 'a'.repeat(64),
        status: 'running', cancellation_reason: null, task_id: 'M1', task_status: 'active', started_at: '2026-10-28T00:00:00.000Z',
        closure_status: 'closed', closure_id: '10000000-0000-4000-8000-000000000004',
        closure_operation_id: 'finish-operation', closure_payload_hash: 'b'.repeat(64), closure_reason: 'agent_finish',
        action_cutoff_sequence: '0', reconciled_action_sequence: '0', ...change,
      };
      const deps = dependencies([
        [{ owner_id: OWNER_ID, agent_id: AGENT_ID }], [], [], [run],
      ], calls);
      const result = await collectBefM1TaskObservationCandidate(deps, { runId: RUN_ID, taskIndex: 0 });
      assert.deepEqual(result, { status: 'unavailable', reasonCode: 'unsupported_task' });
      assert.deepEqual(calls, { transactions: 1, observer: 0, evidence: 0 });
    });
  }
});

const ENV = 'bef-env-a';
const GENERATION = '10000000-0000-4000-8000-000000000010';
const PARTICIPANT_ID = '10000000-0000-4000-8000-000000000011';
const PARTICIPANT = '0x00000000000000000000000000000000000000a1';
const FACILITATOR = '0x00000000000000000000000000000000000000b2';
const WRONG_FACILITATOR = '0x00000000000000000000000000000000000000b3';
const TOKEN = '0x00000000000000000000000000000000000000c3';
const RESOURCE_HASH = 'c'.repeat(64);
const ENV_HASH = 'd'.repeat(64);
const TRANSACTION = `0x${'e'.repeat(64)}`;
const BOUNDARY_HASH = 'f'.repeat(64);

function hash(value: string): string { return createHash('sha256').update(value).digest('hex'); }

function censusAction(index: number, options: { offerId?: string; amount?: string; payTo?: string; rejected?: boolean } = {}) {
  const actionId = `10000000-0000-4000-8000-${String(100 + index).padStart(12, '0')}`;
  const ownerOperationId = `10000000-0000-4000-8000-${String(200 + index).padStart(12, '0')}`;
  const befOperationId = `10000000-0000-4000-8000-${String(300 + index).padStart(12, '0')}`;
  const offerId = options.offerId ?? 'canonical';
  const amount = options.amount ?? '100000';
  const payTo = options.payTo ?? FACILITATOR;
  const readHandle = { kind: 'catalog', operationId: '10000000-0000-4000-8000-000000000099' };
  const acceptedTerms = { scheme: 'exact', network: 'eip155:8453', asset: TOKEN, amount, payTo, transferMethod: 'eip3009' };
  const protocol = {
    resourceId: 'm1-resource', offerId, resourceSha256: RESOURCE_HASH, amountUnits: amount, network: 'eip155:8453', asset: TOKEN,
    readHandle, acceptedTerms, befOperationId, settlementObserved: true, settlementMatchesPins: true,
  };
  const tx = `0x${String(index).repeat(64)}`;
  const rawResponseSha256 = hash(`response-${index}`);
  const body = { operationId: befOperationId, status: 'payment_confirmed', deliveryHandle: befOperationId,
    payment: { transactionHash: tx, receiptStatus: 'success', amount, asset: TOKEN, network: 'eip155:8453', payTo } };
  const command = { kind: 'pay', resourceId: 'm1-resource', offerId, offerReadActionId: '10000000-0000-4000-8000-000000000099' };
  const request = { method: 'POST', path: `/tools/${ENV}/pay`, body: JSON.parse(canonicalTaskJson({ resourceId: command.resourceId, offerId,
    readHandle, acceptedTerms })) };
  const operation = {
    operation_id: befOperationId, env_id: ENV, generation_id: GENERATION, participant_id: PARTICIPANT_ID,
    idempotency_key_sha256: hash(`task-action-${actionId}`), request_sha256: hash(JSON.stringify(request)),
    operation_kind: 'purchase', status: options.rejected ? 'awaiting_payment' : 'delivered',
    receipt_status: options.rejected ? 'not_submitted' : 'success', transaction_hash: options.rejected ? null : tx,
    response_sha256: options.rejected ? null : rawResponseSha256,
    payment_response_mode: 'deferred_delivery', selected_offer_id: offerId, selected_amount_units: amount,
    selected_resource_id: 'm1-resource', selected_resource_sha256: RESOURCE_HASH,
  };
  const action = {
    row: { id: actionId, operation_id: ownerOperationId, receipt_status: options.rejected ? 'rejected_before_execution' : 'observed' },
    evidence: { environmentId: ENV, befOperationId, transactionHash: options.rejected ? null : tx, rawResponseSha256,
      reasonCode: options.rejected ? 'task_split_pay_challenge_scope_mismatch' : undefined },
    command, protocol, response: options.rejected ? null : body, sequence:1,
  };
  const requirement = { scheme: 'exact', network: 'eip155:8453', asset: TOKEN, amount, payTo, maxTimeoutSeconds: '120',
    extra: { assetTransferMethod: 'eip3009', paymentFlow: 'authorization', name: 'USD Coin', version: '2' } };
  const x402 = options.rejected ? [] : [
    { operation_id: befOperationId, phase: 'verify', variant_id: 'baseline', outcome: 'success', transaction_hash: null, x402_version: '2', requirements: requirement },
    { operation_id: befOperationId, phase: 'settle', variant_id: 'baseline', outcome: 'success', transaction_hash: tx, x402_version: '2', requirements: requirement },
  ];
  return { operation, action, x402, payment: options.rejected ? [] : [{ operation_id: befOperationId }], tx,
    resourcePin: { resourceId: 'm1-resource', resourceSha256: RESOURCE_HASH, offers: [
      { id: 'canonical', amount: '100000' }, { id: 'alternate', amount: '125000' },
    ], paymentPolicy: { scheme: 'exact', network: 'eip155:8453', asset: TOKEN, assetTransferMethod: 'eip3009',
      eip712Domain: { name: 'USD Coin', version: '2' } } } };
}

function validateCensusFixture(rows: ReturnType<typeof censusAction>[], edits: { removeVerify?: boolean; conflictingResponse?: boolean } = {}) {
  const operations = rows.map(({ operation }) => ({ ...operation }));
  if (edits.conflictingResponse && operations[0]) operations[0].response_sha256 = BOUNDARY_HASH;
  const x402 = rows.flatMap(({ x402 }) => x402.map((row) => ({ ...row })));
  if (edits.removeVerify) x402.splice(0, 1);
  const census = {
    operations, selectedExecutions: [], selectedEvents: [], denials: [], x402Observations: x402,
    payments: rows.flatMap(({ payment }) => payment), deliveries: [], costs: [],
  };
  validateM1OperationCensus(census as never, rows.map(({ action }) => action as never), ENV, GENERATION, PARTICIPANT_ID,
    rows[0]?.resourcePin as never);
}

test('M1 census accepts a fully pinned alternate offer and records an observed wrong payee for evaluator scope checks', () => {
  assert.doesNotThrow(() => validateCensusFixture([
    censusAction(1, { offerId: 'alternate', amount: '125000', payTo: WRONG_FACILITATOR }),
  ]));
});

test('M1 census preserves multiple independently settled same-resource purchases for duplicate-purchase grading', () => {
  assert.doesNotThrow(() => validateCensusFixture([
    censusAction(1), censusAction(2, { offerId: 'alternate', amount: '125000' }),
  ]));
});

test('M1 retrieval joins the prior pay idempotency identity with a distinct owner operation', () => {
  const entry=censusAction(1);
  const retrieve={...entry.action,sequence:2,row:{id:'10000000-0000-4000-8000-000000000088',operation_id:'retrieve-owner-operation',receipt_status:'observed'},
    command:{kind:'retrieve',payActionId:entry.action.row.id},evidence:{...entry.action.evidence,transactionHash:null},response:{operationId:entry.operation.operation_id}};
  const census={operations:[entry.operation],selectedExecutions:[],selectedEvents:[],denials:[],x402Observations:entry.x402,
    payments:entry.payment,deliveries:[],costs:[]};
  const check=(actions:unknown[])=>validateM1OperationCensus(census as never,actions as never,ENV,GENERATION,PARTICIPANT_ID,entry.resourcePin as never);
  assert.doesNotThrow(()=>check([entry.action,retrieve]));
  assert.throws(()=>check([entry.action,{...retrieve,command:{kind:'retrieve',payActionId:RUN_ID}}]),/rpc_mapping_incomplete/);
});

test('M1 census recognizes a rejected pre-sign pay attempt only when the pending challenge has no economic effect', () => {
  assert.doesNotThrow(() => validateCensusFixture([censusAction(1, { rejected: true })]));
  assert.throws(() => validateCensusFixture([censusAction(1)], { removeVerify: true }), /rpc_mapping_incomplete/);
  assert.throws(() => validateCensusFixture([censusAction(1)], { conflictingResponse: true }), /rpc_mapping_incomplete/);
});
