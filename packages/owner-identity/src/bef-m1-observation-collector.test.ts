import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';
import type { OwnerDatabase } from './db.js';
import {
  collectBefM1TaskObservationCandidate,
  validateM1OperationCensus,
  type BefM1ObservationCollectorDependencies,
} from './bef-m1-observation-collector.js';

const RUN_ID = '10000000-0000-4000-8000-000000000001';
const OWNER_ID = '10000000-0000-4000-8000-000000000002';
const AGENT_ID = '10000000-0000-4000-8000-000000000003';

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
    status: 'running', cancellation_reason: null, task_id: 'M1', task_status: 'running', started_at: '2026-10-28T00:00:00.000Z',
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
        status: 'running', cancellation_reason: null, task_id: 'M1', task_status: 'running', started_at: '2026-10-28T00:00:00.000Z',
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
  const request = { method: 'POST', path: `/tools/${ENV}/pay`, body: { resourceId: command.resourceId, offerId,
    readHandle, acceptedTerms } };
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
    command, protocol, response: options.rejected ? null : body,
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

test('M1 census recognizes a rejected pre-sign pay attempt only when the pending challenge has no economic effect', () => {
  assert.doesNotThrow(() => validateCensusFixture([censusAction(1, { rejected: true })]));
  assert.throws(() => validateCensusFixture([censusAction(1)], { removeVerify: true }), /rpc_mapping_incomplete/);
  assert.throws(() => validateCensusFixture([censusAction(1)], { conflictingResponse: true }), /rpc_mapping_incomplete/);
});
