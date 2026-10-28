import assert from 'node:assert/strict';
import test from 'node:test';
import type { PoolClient } from 'pg';
import type { ExecutionMeasurement, ExecutionTransactionObservation, SelectedAction } from './selected-execution.js';
import { PostgresExecutionPersistence } from './selected-execution-persistence.js';
import { parsePersistedAction } from './selected-execution-persistence.js';
import { parseSelectedAction, principalAccountingForMeasurement } from './selected-execution.js';

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

function measurementFixture(kind: 'approve' | 'swap', direction: 'weth-usdc' | 'usdc-weth' = 'weth-usdc'): { action: SelectedAction; intent: ExecutionTransactionObservation; measurement: ExecutionMeasurement } {
  const amountUnits = '777';
  const amountInUnits = '500';
  const amountOutMinimumUnits = '234';
  const inputAssetId = direction === 'weth-usdc' ? 'WETH' : 'USDC';
  const outputAssetId = direction === 'weth-usdc' ? 'USDC' : 'WETH';
  const tokenIn = inputAssetId === 'WETH' ? WETH : USDC;
  const tokenOut = outputAssetId === 'WETH' ? WETH : USDC;
  const action: SelectedAction = kind === 'approve'
    ? { kind, tokenAssetId: 'WETH', amountUnits, gasLimit: '100000' }
    : {
      kind, inputAssetId, outputAssetId, feeTier: 500, amountInUnits, amountOutMinimumUnits, recipient: SWAP_RECIPIENT as `0x${string}`,
      gasLimit: '300000',
    };
  const selectedAction = kind === 'approve'
    ? { kind, tokenAssetId: 'WETH', token: WETH, spender: ROUTER, amountUnits, gasLimit: '100000' }
    : {
      kind, route: 'uniswap-v3-exactInputSingle', router: ROUTER, inputAssetId, outputAssetId, tokenIn, tokenOut, fee: 500,
      amountInUnits, amountOutMinimumUnits,
      recipient: SWAP_RECIPIENT as `0x${string}`, gasLimit: '300000',
    };
  const input = kind === 'approve'
    ? `0x095ea7b3${addressWord(ROUTER)}${uintWord(BigInt(amountUnits))}`
    : `0x04e45aaf${addressWord(tokenIn)}${addressWord(tokenOut)}${uintWord(500n)}${addressWord(SWAP_RECIPIENT)}${uintWord(BigInt(amountInUnits))}${uintWord(BigInt(amountOutMinimumUnits))}${uintWord(0n)}`;
  const to = kind === 'approve' ? WETH : ROUTER;
  const intent: ExecutionTransactionObservation = {
    hash: TRANSACTION_HASH, type: 'eip1559', chainId: 8453, blockHash: null, blockNumber: null, transactionIndex: null,
    from: PAYER as `0x${string}`, to: to as `0x${string}`, nonce: '0', input: input as `0x${string}`, valueWei: '0', gasLimit: action.gasLimit,
    maxFeePerGasWei: '10', maxPriorityFeePerGasWei: '2',
  };
  const afterAllowance = kind === 'approve' ? '777' : '500';
  const before = {
    blockNumber: '52982198', payerNativeWei: '1000000', payerWethUnits: '1000', payerUsdcUnits: '1000',
    recipientWethUnits: '0', recipientUsdcUnits: '0', wethRouterAllowance: kind === 'approve' ? '0' : direction === 'weth-usdc' ? '1000' : '0',
    usdcRouterAllowance: kind === 'approve' ? '0' : direction === 'usdc-weth' ? '1000' : '0', poolWethUnits: '10000',
    poolUsdcUnits: '20000', poolLiquidity: '5000', poolSqrtPriceX96: '6000',
  };
  const after = {
    ...before, blockNumber: '52982199',
    wethRouterAllowance: kind === 'approve' || direction === 'weth-usdc' ? afterAllowance : before.wethRouterAllowance,
    usdcRouterAllowance: kind === 'swap' && direction === 'usdc-weth' ? afterAllowance : before.usdcRouterAllowance,
  };
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
      modeledGasFeeUsdcUnits: '1', baseL1Fee: 'unmodelled', principalAsset: kind === 'approve' ? null : inputAssetId,
      selectedPrincipalUnits: kind === 'approve' ? '0' : amountInUnits, principalUnits: kind === 'approve' ? '0' : amountInUnits,
    },
    taskEvaluationInputs: {
      expenseBudgetUsdcUnits: '1000000', recipient: kind === 'approve' ? null : SWAP_RECIPIENT as `0x${string}`,
      allowanceAssetId: kind === 'swap' ? inputAssetId : 'WETH',
      allowanceAfterUnits: afterAllowance, nativeEthReserveWei: '100000', allowanceCleanupExpected: true,
      selectedMinimumOutputUnits: kind === 'approve' ? null : amountOutMinimumUnits,
    },
  };
  return { action, intent, measurement };
}

function transferMeasurementFixture(): { action: SelectedAction; intent: ExecutionTransactionObservation; measurement: ExecutionMeasurement } {
  const amountUnits = '777';
  const gasLimit = '100000';
  const action: SelectedAction = { kind: 'transfer', amountUnits, recipient: SWAP_RECIPIENT as `0x${string}`, gasLimit };
  const input = `0xa9059cbb${addressWord(SWAP_RECIPIENT)}${uintWord(BigInt(amountUnits))}` as `0x${string}`;
  const intent: ExecutionTransactionObservation = {
    hash: TRANSACTION_HASH, type: 'eip1559', chainId: 8453, blockHash: null, blockNumber: null, transactionIndex: null,
    from: PAYER as `0x${string}`, to: USDC as `0x${string}`, nonce: '0', input, valueWei: '0', gasLimit,
    maxFeePerGasWei: '10', maxPriorityFeePerGasWei: '2',
  };
  const before = {
    blockNumber: '52982198', payerNativeWei: '1000000', payerWethUnits: '1000', payerUsdcUnits: '5000',
    recipientWethUnits: '0', recipientUsdcUnits: '100', wethRouterAllowance: '0', usdcRouterAllowance: '0', poolWethUnits: '10000',
    poolUsdcUnits: '20000', poolLiquidity: '5000', poolSqrtPriceX96: '6000',
  };
  const after = { ...before, blockNumber: '52982199', payerNativeWei: '850000', payerUsdcUnits: '4223', recipientUsdcUnits: '877' };
  const transferTopic = '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef';
  const logs: ExecutionMeasurement['receipt']['logs'] = [{
    address: USDC as `0x${string}`,
    topics: [transferTopic, `0x${addressWord(PAYER)}`, `0x${addressWord(SWAP_RECIPIENT)}`] as `0x${string}`[],
    data: `0x${uintWord(BigInt(amountUnits))}` as `0x${string}`,
    logIndex: '0', transactionHash: TRANSACTION_HASH, transactionIndex: '0', blockHash: BLOCK_HASH,
    blockNumber: '52982199', removed: false,
  }];
  const measuredTransaction = {
    ...intent, from: PAYER.toLowerCase() as `0x${string}`, to: USDC.toLowerCase() as `0x${string}`,
    blockHash: BLOCK_HASH, blockNumber: '52982199', transactionIndex: '0',
  };
  const measurement: ExecutionMeasurement = {
    receipt: {
      transactionHash: TRANSACTION_HASH, from: PAYER.toLowerCase() as `0x${string}`, to: USDC.toLowerCase() as `0x${string}`,
      status: 'success', blockHash: BLOCK_HASH, blockNumber: '52982199', gasUsed: '50000', effectiveGasPrice: '3',
      gasCostWei: '150000', logs,
    },
    transaction: measuredTransaction,
    payerBlock: {
      hash: BLOCK_HASH, number: '52982199', parentHash: PARENT_HASH, baseFeePerGasWei: '8',
      transactions: [{ hash: TRANSACTION_HASH, from: PAYER.toLowerCase() as `0x${string}` }],
    },
    selectedAction: { kind: 'transfer', token: USDC, amountUnits, recipient: SWAP_RECIPIENT, gasLimit },
    before,
    after,
    effects: {
      payerNativeWei: '-150000', payerWethUnits: '0', payerUsdcUnits: '-777', recipientWethUnits: '0', recipientUsdcUnits: '777',
      wethRouterAllowance: '0', usdcRouterAllowance: '0', poolWethUnits: '0', poolUsdcUnits: '0',
    },
    quote: null,
    fee: {
      modeledGasFeeUsdcUnits: '1', baseL1Fee: 'unmodelled', principalAsset: 'USDC',
      selectedPrincipalUnits: amountUnits, principalUnits: amountUnits,
    },
    taskEvaluationInputs: {
      expenseBudgetUsdcUnits: '1000000', recipient: SWAP_RECIPIENT as `0x${string}`,
      allowanceAssetId: 'WETH', allowanceAfterUnits: '0', nativeEthReserveWei: '100000', allowanceCleanupExpected: false,
      selectedMinimumOutputUnits: null,
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
    const parsed = parsePersistedAction(entry.value, entry.kind);
    if (entry.kind === 'approve') assert.deepEqual(parsed, { ...entry.value, tokenAssetId: 'WETH' });
    else if (entry.kind === 'swap') assert.deepEqual(parsed, {
      kind: 'swap', feeTier: 500, inputAssetId: 'WETH', outputAssetId: 'USDC', amountInUnits: entry.value.amountInWei,
      amountOutMinimumUnits: entry.value.amountOutMinimumUsdcUnits, recipient: entry.value.recipient, gasLimit: entry.value.gasLimit,
    });
    else assert.deepEqual(parsed, entry.value);
  }

  const transfer = { kind: 'transfer', amountUnits: '777', recipient: SWAP_RECIPIENT, gasLimit: '100000' };
  const transferPayload = { amountUnits: transfer.amountUnits, recipient: transfer.recipient, gasLimit: transfer.gasLimit };
  assert.deepEqual(parseSelectedAction('transfer', transferPayload), transfer);
  assert.deepEqual(parsePersistedAction(transfer, 'transfer'), transfer);
  assert.equal(parseSelectedAction('transfer', { ...transferPayload, unexpected: true }), null);
  assert.equal(parseSelectedAction('transfer', { ...transferPayload, recipient: 'not-an-address' }), null);
  assert.deepEqual(parseSelectedAction('approve', { tokenAssetId: 'USDC', amountUnits: '5', gasLimit: '100000' }), {
    kind: 'approve', tokenAssetId: 'USDC', amountUnits: '5', gasLimit: '100000',
  });
  assert.deepEqual(parseSelectedAction('swap', {
    inputAssetId: 'USDC', outputAssetId: 'WETH', amountInUnits: '9', amountOutMinimumUnits: '4',
    recipient: SWAP_RECIPIENT, gasLimit: '300000',
  }), {
    kind: 'swap', feeTier: 500, inputAssetId: 'USDC', outputAssetId: 'WETH', amountInUnits: '9', amountOutMinimumUnits: '4',
    recipient: SWAP_RECIPIENT.toLowerCase(), gasLimit: '300000',
  });
  const fee3000Action = parseSelectedAction('swap', {
    inputAssetId: 'USDC', outputAssetId: 'WETH', feeTier: 3000, amountInUnits: '9', amountOutMinimumUnits: '4',
    recipient: SWAP_RECIPIENT, gasLimit: '300000',
  });
  assert.deepEqual(fee3000Action, {
    kind: 'swap', feeTier: 3000, inputAssetId: 'USDC', outputAssetId: 'WETH', amountInUnits: '9', amountOutMinimumUnits: '4',
    recipient: SWAP_RECIPIENT.toLowerCase(), gasLimit: '300000',
  });
  assert.deepEqual(parsePersistedAction(fee3000Action, 'swap'), fee3000Action);
  assert.equal(parseSelectedAction('swap', {
    inputAssetId: 'USDC', outputAssetId: 'WETH', feeTier: 10000, amountInUnits: '9', amountOutMinimumUnits: '4',
    recipient: SWAP_RECIPIENT, gasLimit: '300000',
  }), null);
  assert.equal(parseSelectedAction('swap', {
    inputAssetId: 'WETH', outputAssetId: 'WETH', amountInUnits: '9', amountOutMinimumUnits: '4',
    recipient: SWAP_RECIPIENT, gasLimit: '300000',
  }), null);
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
  const reverseSwap = parsePersistedAction({
    kind: 'swap', inputAssetId: 'USDC', outputAssetId: 'WETH', amountInUnits: '777', amountOutMinimumUnits: '500',
    recipient: SWAP_RECIPIENT, gasLimit: '300000',
  });
  assert.equal(reverseSwap.kind, 'swap');
  if (reverseSwap.kind === 'swap') assert.equal(reverseSwap.inputAssetId, 'USDC');
  assert.deepEqual(principalAccountingForMeasurement(reverseSwap, 'reverted'), {
    selectedPrincipalUnits: '777', principalUnits: '0',
  });

  const transfer = parsePersistedAction({
    kind: 'transfer', amountUnits: '777', recipient: SWAP_RECIPIENT, gasLimit: '100000',
  });
  assert.deepEqual(principalAccountingForMeasurement(transfer, 'success'), {
    selectedPrincipalUnits: '777', principalUnits: '777',
  });
  assert.deepEqual(principalAccountingForMeasurement(transfer, 'reverted'), {
    selectedPrincipalUnits: '777', principalUnits: '0',
  });
});

test('finish and readCompleted round-trip approve and both pinned swap directions against stored inputs and intent', async () => {
  const persistence = new PostgresExecutionPersistence();
  for (const fixture of [measurementFixture('approve'), measurementFixture('swap'), measurementFixture('swap', 'usdc-weth')]) {
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
    { kind: 'swap', field: 'inputAssetId', value: 'USDC' },
    { kind: 'swap', field: 'fee', value: 3000 },
  ];
  for (const mutation of mutations) {
    const fixture = measurementFixture(mutation.kind);
    (fixture.measurement.selectedAction as Record<string, unknown>)[mutation.field] = mutation.value;
    const client = new MemoryExecutionClient(fixture.action, fixture.intent);
    await assert.rejects(
      persistence.finish(asPoolClient(client), OPERATION_ID, TRANSACTION_HASH, 'success', fixture.measurement),
      /execution_persistence_measurement_(?:action|invalid)/,
    );
    assert.equal(client.terminalWrites, 0, `${mutation.kind}.${mutation.field} must fail before terminal updates`);
  }
});

test('finish and readCompleted preserve a receipt-bound USDC transfer and its separate principal', async () => {
  const persistence = new PostgresExecutionPersistence();
  const fixture = transferMeasurementFixture();
  const client = new MemoryExecutionClient(fixture.action, fixture.intent);
  await persistence.finish(asPoolClient(client), OPERATION_ID, TRANSACTION_HASH, 'success', fixture.measurement);
  const completed = await persistence.readCompleted(asPoolClient(client), OPERATION_ID);
  assert.equal(completed?.outcome, 'success');
  assert.deepEqual(completed?.measurement.selectedAction, fixture.measurement.selectedAction);
  assert.equal(completed?.measurement.fee.principalAsset, 'USDC');
  assert.equal(completed?.measurement.fee.selectedPrincipalUnits, '777');
  assert.equal(completed?.measurement.fee.principalUnits, '777');
  assert.equal(completed?.measurement.fee.modeledGasFeeUsdcUnits, '1');
  assert.deepEqual(client.eventKinds, ['receipt_finalized']);
});

test('transfer persistence rejects mismatched calldata, principal asset, and missing or duplicate receipt logs', async () => {
  const persistence = new PostgresExecutionPersistence();
  const cases = [
    (measurement: ExecutionMeasurement) => { measurement.transaction.input = `0xa9059cbb${addressWord(PAYER)}${uintWord(777n)}` as `0x${string}`; },
    (measurement: ExecutionMeasurement) => { measurement.fee.principalAsset = 'ETH'; },
    (measurement: ExecutionMeasurement) => { measurement.receipt.logs = []; },
    (measurement: ExecutionMeasurement) => { measurement.receipt.logs.push(structuredClone(measurement.receipt.logs[0]!)); },
  ];
  for (const mutate of cases) {
    const fixture = transferMeasurementFixture();
    mutate(fixture.measurement);
    const client = new MemoryExecutionClient(fixture.action, fixture.intent);
    await assert.rejects(
      persistence.finish(asPoolClient(client), OPERATION_ID, TRANSACTION_HASH, 'success', fixture.measurement),
      /execution_persistence_measurement_(?:action|invalid)/,
    );
    assert.equal(client.terminalWrites, 0);
  }
});
