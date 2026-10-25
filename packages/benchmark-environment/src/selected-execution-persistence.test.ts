import assert from 'node:assert/strict';
import test from 'node:test';
import type { PoolClient } from 'pg';
import type { ExecutionMeasurement, ExecutionTransactionObservation, SelectedAction } from './selected-execution.js';
import { PostgresExecutionPersistence } from './selected-execution-persistence.js';
import { parsePersistedAction } from './selected-execution-persistence.js';
import { principalAccountingForMeasurement } from './selected-execution.js';

const OPERATION_ID = '31b0b927-79f7-4e07-87e3-f5ed2f9c97e6';
const TRANSACTION_HASH = `0x${'ab'.repeat(32)}` as `0x${string}`;
const BLOCK_HASH = `0x${'cd'.repeat(32)}` as `0x${string}`;
const PARENT_HASH = `0x${'ef'.repeat(32)}` as `0x${string}`;
const PAYER = '0xb441c27dA3476936d1bDc965dC0788f3e5b12DBB';
const WETH = '0x4200000000000000000000000000000000000006';
const ROUTER = '0x2626664c2603336E57B271c5C0b26F421741e481';
const USDC = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913';
const SWAP_RECIPIENT = '0x5555555555555555555555555555555555555555';

function addressWord(value: string): string { return value.slice(2).toLowerCase().padStart(64, '0'); }
function uintWord(value: bigint): string { return value.toString(16).padStart(64, '0'); }

function measurementFixture(kind: 'approve' | 'swap'): { action: SelectedAction; intent: ExecutionTransactionObservation; measurement: ExecutionMeasurement } {
  const amountUnits = '777';
  const amountInWei = '123456';
  const amountOutMinimumUsdcUnits = '234';
  const action: SelectedAction = kind === 'approve'
    ? { kind, amountUnits, gasLimit: '100000' }
    : {
      kind, amountInWei, amountOutMinimumUsdcUnits, recipient: SWAP_RECIPIENT as `0x${string}`,
      gasLimit: '300000',
    };
  const selectedAction = kind === 'approve'
    ? { kind, token: WETH, spender: ROUTER, amountUnits, gasLimit: '100000' }
    : {
      kind, route: 'uniswap-v3-exactInputSingle', router: ROUTER, tokenIn: WETH, tokenOut: USDC, fee: 500,
      amountInWei, amountOutMinimumUsdcUnits,
      recipient: SWAP_RECIPIENT as `0x${string}`, gasLimit: '300000',
    };
  const input = kind === 'approve'
    ? `0x095ea7b3${addressWord(ROUTER)}${uintWord(BigInt(amountUnits))}`
    : `0x04e45aaf${addressWord(WETH)}${addressWord(USDC)}${uintWord(500n)}${addressWord(SWAP_RECIPIENT)}${uintWord(BigInt(amountInWei))}${uintWord(BigInt(amountOutMinimumUsdcUnits))}${uintWord(0n)}`;
  const to = kind === 'approve' ? WETH : ROUTER;
  const intent: ExecutionTransactionObservation = {
    hash: TRANSACTION_HASH, type: 'eip1559', chainId: 8453, blockHash: null, blockNumber: null, transactionIndex: null,
    from: PAYER as `0x${string}`, to: to as `0x${string}`, nonce: '0', input: input as `0x${string}`, valueWei: '0', gasLimit: action.gasLimit,
    maxFeePerGasWei: '10', maxPriorityFeePerGasWei: '2',
  };
  const afterAllowance = kind === 'approve' ? '777' : '100';
  const before = {
    blockNumber: '52982198', payerNativeWei: '1000000', payerWethUnits: '1000', payerUsdcUnits: '0',
    recipientUsdcUnits: '0', wethRouterAllowance: kind === 'approve' ? '0' : '100', poolWethUnits: '10000',
    poolUsdcUnits: '20000', poolLiquidity: '5000', poolSqrtPriceX96: '6000',
  };
  const after = { ...before, blockNumber: '52982199', wethRouterAllowance: afterAllowance };
  const approvalTopic = '0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925';
  const logs: ExecutionMeasurement['receipt']['logs'] = kind === 'approve' ? [{
    address: WETH as `0x${string}`,
    topics: [approvalTopic, `0x${addressWord(PAYER)}`, `0x${addressWord(ROUTER)}`] as `0x${string}`[],
    data: `0x${uintWord(BigInt(amountUnits))}` as `0x${string}`,
    logIndex: '0', transactionHash: TRANSACTION_HASH, transactionIndex: '0', blockHash: BLOCK_HASH,
    blockNumber: '52982199', removed: false,
  }] : [];
  const measuredTransaction = {
    ...intent, from: PAYER.toLowerCase() as `0x${string}`, to: to.toLowerCase() as `0x${string}`,
    blockHash: BLOCK_HASH, blockNumber: '52982199', transactionIndex: '0',
  };
  const measurement: ExecutionMeasurement = {
    receipt: {
      transactionHash: TRANSACTION_HASH, from: PAYER.toLowerCase() as `0x${string}`, to: to.toLowerCase() as `0x${string}`,
      status: 'success', blockHash: BLOCK_HASH, blockNumber: '52982199', gasUsed: '50000', effectiveGasPrice: '3',
      gasCostWei: '150000', logs,
    },
    transaction: measuredTransaction,
    payerBlock: {
      hash: BLOCK_HASH, number: '52982199', parentHash: PARENT_HASH, baseFeePerGasWei: '8',
      transactions: [{ hash: TRANSACTION_HASH, from: PAYER.toLowerCase() as `0x${string}` }],
    },
    selectedAction,
    before,
    after,
    effects: { payerNativeWei: '-150000', payerWethUnits: '0', payerUsdcUnits: '0', recipientUsdcUnits: '0', wethRouterAllowance: kind === 'approve' ? '777' : '0' },
    quote: null,
    fee: {
      modeledGasFeeUsdcUnits: '1', baseL1Fee: 'unmodelled', principalAsset: kind === 'approve' ? null : 'WETH',
      selectedPrincipalUnits: kind === 'approve' ? '0' : amountInWei, principalUnits: kind === 'approve' ? '0' : amountInWei,
    },
    taskEvaluationInputs: {
      expenseBudgetUsdcUnits: '1000000', recipient: kind === 'approve' ? null : SWAP_RECIPIENT as `0x${string}`,
      allowanceAfterUnits: afterAllowance, nativeEthReserveWei: '100000', allowanceCleanupExpected: true,
      selectedMinimumOutputUnits: kind === 'approve' ? null : amountOutMinimumUsdcUnits,
    },
  };
  return { action, intent, measurement };
}

class MemoryExecutionClient {
  operationStatus = 'settling';
  receiptStatus = 'unknown';
  outcome = 'settling';
  storedMeasurement: unknown = null;
  terminalWrites = 0;
  readonly eventKinds: string[] = [];
  constructor(readonly action: SelectedAction, readonly intent: ExecutionTransactionObservation) {}

  async query(text: string, values: unknown[] = []): Promise<{ rows: Array<Record<string, unknown>>; rowCount: number | null }> {
    if (text.includes('SELECT action_kind,selected_action_json,transaction_intent_json,transaction_hash')) {
      return { rows: [{ action_kind: this.action.kind, selected_action_json: this.action, transaction_intent_json: this.intent, transaction_hash: TRANSACTION_HASH }], rowCount: 1 };
    }
    if (text.includes('UPDATE bef_operation SET status=$3')) {
      this.operationStatus = String(values[2]);
      this.receiptStatus = String(values[3]);
      this.terminalWrites += 1;
      return { rows: [{
        operation_id: OPERATION_ID, env_id: 'bef-a', generation_id: '11111111-1111-4111-8111-111111111111',
        participant_id: '22222222-2222-4222-8222-222222222222', operation_kind: this.action.kind,
        status: this.operationStatus, request_sha256: 'f'.repeat(64), transaction_hash: TRANSACTION_HASH,
        receipt_status: this.receiptStatus,
      }], rowCount: 1 };
    }
    if (text.includes('UPDATE bef_selected_execution') && text.includes('SET outcome=$4')) {
      this.outcome = String(values[3]);
      this.storedMeasurement = JSON.parse(String(values[4])) as unknown;
      this.terminalWrites += 1;
      return { rows: [{ operation_id: OPERATION_ID }], rowCount: 1 };
    }
    if (text.includes('INSERT INTO bef_selected_execution_event')) {
      this.eventKinds.push(String(values[4]));
      return { rows: [], rowCount: 1 };
    }
    if (text.includes('FROM bef_selected_execution e JOIN bef_operation o')) {
      return { rows: [{
        operation_id: OPERATION_ID, env_id: 'bef-a', generation_id: '11111111-1111-4111-8111-111111111111',
        action_kind: this.action.kind, selected_action_json: this.action, prestate_json: {},
        transaction_intent_json: this.intent, transaction_hash: TRANSACTION_HASH, outcome: this.outcome,
        reason_code: null, measurement_json: this.storedMeasurement, status: this.operationStatus,
        receipt_status: this.receiptStatus,
      }], rowCount: 1 };
    }
    throw new Error(`unexpected persistence query: ${text.slice(0, 80)}`);
  }
}

function asPoolClient(client: MemoryExecutionClient): PoolClient { return client as unknown as PoolClient; }

test('stored selected actions round-trip through the strict participant schemas', () => {
  const cases = [
    {
      kind: 'approve',
      value: { kind: 'approve', amountUnits: '999999999', gasLimit: '100000' },
    },
    {
      kind: 'wrap',
      value: { kind: 'wrap', amountWei: '9500000000000000000', gasLimit: '100000' },
    },
    {
      kind: 'unwrap',
      value: { kind: 'unwrap', amountWei: '1230000000000000000', gasLimit: '100000' },
    },
    {
      kind: 'swap',
      value: {
        kind: 'swap',
        amountInWei: '10000000000000000',
        amountOutMinimumUsdcUnits: '1',
        recipient: '0x1111111111111111111111111111111111111111',
        gasLimit: '300000',
      },
    },
  ] as const;

  for (const entry of cases) {
    assert.deepEqual(parsePersistedAction(entry.value, entry.kind), entry.value);
  }
});

test('stored selected actions reject unexpected database fields', () => {
  assert.throws(() => parsePersistedAction({
    kind: 'approve',
    amountUnits: '1',
    gasLimit: '100000',
    unexpectedField: 'rejected',
  }));
});

test('reverted selected executions retain intent but record zero observed principal', () => {
  const wrap = parsePersistedAction({ kind: 'wrap', amountWei: '9500000000000000000', gasLimit: '100000' });
  assert.deepEqual(principalAccountingForMeasurement(wrap, 'success'), {
    selectedPrincipalUnits: '9500000000000000000', principalUnits: '9500000000000000000',
  });
  assert.deepEqual(principalAccountingForMeasurement(wrap, 'reverted'), {
    selectedPrincipalUnits: '9500000000000000000', principalUnits: '0',
  });

  const swap = parsePersistedAction({
    kind: 'swap', amountInWei: '10000000000000000', amountOutMinimumUsdcUnits: '50000',
    recipient: '0x1111111111111111111111111111111111111111', gasLimit: '300000',
  });
  assert.deepEqual(principalAccountingForMeasurement(swap, 'reverted'), {
    selectedPrincipalUnits: '10000000000000000', principalUnits: '0',
  });
});

test('finish and readCompleted round-trip approve and swap measurements against stored inputs and intent', async () => {
  const persistence = new PostgresExecutionPersistence();
  for (const kind of ['approve', 'swap'] as const) {
    const fixture = measurementFixture(kind);
    const client = new MemoryExecutionClient(fixture.action, fixture.intent);
    await persistence.finish(asPoolClient(client), OPERATION_ID, TRANSACTION_HASH, 'success', fixture.measurement);
    const completed = await persistence.readCompleted(asPoolClient(client), OPERATION_ID);
    assert.equal(completed?.outcome, 'success');
    assert.equal(completed?.transactionHash, TRANSACTION_HASH);
    assert.deepEqual(completed?.measurement.selectedAction, fixture.measurement.selectedAction);
    assert.deepEqual(client.eventKinds, ['receipt_finalized']);
  }
});

test('finish rejects changed derived approve and swap metadata before terminal writes', async () => {
  const persistence = new PostgresExecutionPersistence();
  const mutations: Array<{ kind: 'approve' | 'swap'; field: string; value: unknown }> = [
    { kind: 'approve', field: 'token', value: USDC },
    { kind: 'approve', field: 'spender', value: PAYER },
    { kind: 'swap', field: 'router', value: WETH },
    { kind: 'swap', field: 'tokenIn', value: USDC },
    { kind: 'swap', field: 'fee', value: 3000 },
  ];
  for (const mutation of mutations) {
    const fixture = measurementFixture(mutation.kind);
    (fixture.measurement.selectedAction as Record<string, unknown>)[mutation.field] = mutation.value;
    const client = new MemoryExecutionClient(fixture.action, fixture.intent);
    await assert.rejects(
      persistence.finish(asPoolClient(client), OPERATION_ID, TRANSACTION_HASH, 'success', fixture.measurement),
      /execution_persistence_measurement_action/,
    );
    assert.equal(client.terminalWrites, 0, `${mutation.kind}.${mutation.field} must fail before terminal updates`);
  }
});
