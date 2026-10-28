/**
 * Narrow local-fork capture for the selected USDC transfer primitive.
 *
 * This is executor evidence only. It is not a BTS task case, release, rubric
 * evaluation, or product acceptance result.
 */
import { createHash, randomUUID } from 'node:crypto';
import pg from 'pg';
import { decodeEventLog, encodeFunctionData, parseAbi } from 'viem';
import type { ProbeContext } from './runner.js';
import type { SelectedExecutionTransactionEvidence } from './rpc.js';
import { transferEvents } from './rpc.js';
import { apiPath, newParticipantId } from './environment.js';
import { createEphemeralSigner } from './x402.js';

const { Pool } = pg;
const ERC20_ABI = [{
  type: 'function', name: 'balanceOf', stateMutability: 'view',
  inputs: [{ name: 'account', type: 'address' }], outputs: [{ name: '', type: 'uint256' }],
}] as const;
const TRANSFER_ABI = [{
  type: 'function', name: 'transfer', stateMutability: 'nonpayable',
  inputs: [{ name: 'to', type: 'address' }, { name: 'amount', type: 'uint256' }], outputs: [{ name: '', type: 'bool' }],
}] as const;
const APPROVE_ABI = [{
  type: 'function', name: 'approve', stateMutability: 'nonpayable',
  inputs: [{ name: 'spender', type: 'address' }, { name: 'amount', type: 'uint256' }], outputs: [{ name: '', type: 'bool' }],
}] as const;
const SWAP_ROUTER_ABI = [{
  type: 'function', name: 'exactInputSingle', stateMutability: 'payable',
  inputs: [{ name: 'params', type: 'tuple', components: [
    { name: 'tokenIn', type: 'address' }, { name: 'tokenOut', type: 'address' }, { name: 'fee', type: 'uint24' },
    { name: 'recipient', type: 'address' }, { name: 'amountIn', type: 'uint256' },
    { name: 'amountOutMinimum', type: 'uint256' }, { name: 'sqrtPriceLimitX96', type: 'uint160' },
  ] }], outputs: [{ name: 'amountOut', type: 'uint256' }],
}] as const;
const POOL_SWAP_ABI = parseAbi([
  'event Swap(address indexed sender,address indexed recipient,int256 amount0,int256 amount1,uint160 sqrtPriceX96,uint128 liquidity,int24 tick)',
]);
const ADDRESS = /^0x[0-9a-f]{40}$/i;
const HASH = /^0x[0-9a-f]{64}$/i;
const UINT = /^(?:0|[1-9][0-9]*)$/;
const VARIANT_ID = 'task_s1_transfer_capture';

type TransferSnapshot = {
  blockNumber: string;
  blockHash: string;
  payerAddress: string;
  recipientAddress: string;
  payerNativeWei: string;
  payerUsdcUnits: string;
  recipientWethUnits: string;
  recipientUsdcUnits: string;
  payerWethUnits: string;
  poolUsdcUnits: string;
  poolWethUnits: string;
  wethRouterAllowanceUnits: string;
  usdcRouterAllowanceUnits: string;
};

type SelectedExecutionRows = {
  databaseRole: string;
  transactionReadOnly: string;
  operation: Record<string, unknown> | null;
  selectedExecution: Record<string, unknown> | null;
  transactionCost: Record<string, unknown> | null;
  events: Array<Record<string, unknown>>;
};

function objectRecord(value: unknown): Record<string, unknown> | null {
  return value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : null;
}

function requireString(value: unknown, label: string): string {
  if (typeof value !== 'string' || value.length === 0) throw new Error(`task_transfer_${label}_missing`);
  return value;
}

function uint(value: unknown, label: string): bigint {
  if (typeof value === 'bigint' && value >= 0n) return value;
  if (typeof value === 'number' && Number.isSafeInteger(value) && value >= 0) return BigInt(value);
  if (typeof value === 'string' && /^0x[0-9a-f]+$/i.test(value)) return BigInt(value);
  if (typeof value === 'string' && UINT.test(value)) return BigInt(value);
  throw new Error(`task_transfer_${label}_invalid`);
}

function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>).sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0);
    return `{${entries.map(([key, child]) => `${JSON.stringify(key)}:${canonicalJson(child)}`).join(',')}}`;
  }
  return JSON.stringify(value) ?? 'null';
}

async function readRpc<T>(ctx: ProbeContext, input: {
  method: string;
  params: unknown[];
  requestedBlock?: string;
  operationId: string | null;
  label: string;
  variantId?: string;
}): Promise<T> {
  const { result } = await ctx.rpc.call<T>({
    url: ctx.env.localRpcUrl,
    endpointBoundary: 'local-chain-readonly-proxy',
    environmentId: ctx.env.envId,
    method: input.method,
    params: input.params,
    ...(input.requestedBlock === undefined ? {} : { requestedBlock: input.requestedBlock }),
    operationId: input.operationId,
    variantId: input.variantId ?? VARIANT_ID,
    label: input.label,
  });
  return result;
}

async function readTokenBalance(ctx: ProbeContext, token: string, owner: string, blockTag: string, operationId: string | null, label: string, variantId = VARIANT_ID): Promise<string> {
  const result = await readRpc<string>(ctx, {
    method: 'eth_call',
    params: [{ to: token, data: encodeFunctionData({ abi: ERC20_ABI, functionName: 'balanceOf', args: [owner as `0x${string}`] }) }, blockTag],
    requestedBlock: blockTag, operationId, label, variantId,
  });
  return uint(result, 'token_balance').toString();
}

async function readSnapshot(ctx: ProbeContext, payer: string, recipient: string, operationId: string | null, label: string, blockTag?: string, variantId = VARIANT_ID, selectedPoolAddress?: string): Promise<TransferSnapshot> {
  const observedTag = blockTag ?? await readRpc<string>(ctx, {
    method: 'eth_blockNumber', params: [], operationId, label: `${label}-height`, variantId,
  });
  if (typeof observedTag !== 'string' || !/^0x[0-9a-f]+$/i.test(observedTag)) throw new Error('task_transfer_block_height_invalid');
  const normalizedTag = `0x${BigInt(observedTag).toString(16)}`;
  const block = await readRpc<Record<string, unknown> | null>(ctx, {
    method: 'eth_getBlockByNumber', params: [normalizedTag, false], requestedBlock: normalizedTag, operationId, label: `${label}-block`, variantId,
  });
  if (!block || typeof block.number !== 'string' || typeof block.hash !== 'string' || !HASH.test(block.hash)) {
    throw new Error('task_transfer_block_identity_invalid');
  }
  const manifest = ctx.runtime.manifest;
  const poolAddress = selectedPoolAddress ?? manifest.contracts.pool.address;
  const [payerNative, payerUsdc, recipientWeth, recipientUsdc, payerWeth, poolUsdc, poolWeth, wethAllowance, usdcAllowance] = await Promise.all([
    readRpc<string>(ctx, { method: 'eth_getBalance', params: [payer, normalizedTag], requestedBlock: normalizedTag, operationId, label: `${label}-payer-native`, variantId }),
    readTokenBalance(ctx, manifest.contracts.usdc.address, payer, normalizedTag, operationId, `${label}-payer-usdc`, variantId),
    readTokenBalance(ctx, manifest.contracts.weth.address, recipient, normalizedTag, operationId, `${label}-recipient-weth`, variantId),
    readTokenBalance(ctx, manifest.contracts.usdc.address, recipient, normalizedTag, operationId, `${label}-recipient-usdc`, variantId),
    readTokenBalance(ctx, manifest.contracts.weth.address, payer, normalizedTag, operationId, `${label}-payer-weth`, variantId),
    readTokenBalance(ctx, manifest.contracts.usdc.address, poolAddress, normalizedTag, operationId, `${label}-pool-usdc`, variantId),
    readTokenBalance(ctx, manifest.contracts.weth.address, poolAddress, normalizedTag, operationId, `${label}-pool-weth`, variantId),
    readRpc<string>(ctx, {
      method: 'eth_call',
      params: [{
        to: manifest.contracts.weth.address,
        data: encodeFunctionData({
          abi: [{ type: 'function', name: 'allowance', stateMutability: 'view', inputs: [{ name: 'owner', type: 'address' }, { name: 'spender', type: 'address' }], outputs: [{ name: '', type: 'uint256' }] }] as const,
          functionName: 'allowance',
          args: [payer as `0x${string}`, manifest.contracts.swapRouter02.address as `0x${string}`],
        }),
      }, normalizedTag],
      requestedBlock: normalizedTag, operationId, label: `${label}-weth-router-allowance`, variantId,
    }),
    readRpc<string>(ctx, {
      method: 'eth_call',
      params: [{
        to: manifest.contracts.usdc.address,
        data: encodeFunctionData({
          abi: [{ type: 'function', name: 'allowance', stateMutability: 'view', inputs: [{ name: 'owner', type: 'address' }, { name: 'spender', type: 'address' }], outputs: [{ name: '', type: 'uint256' }] }] as const,
          functionName: 'allowance',
          args: [payer as `0x${string}`, manifest.contracts.swapRouter02.address as `0x${string}`],
        }),
      }, normalizedTag],
      requestedBlock: normalizedTag, operationId, label: `${label}-usdc-router-allowance`, variantId,
    }),
  ]);
  return {
    blockNumber: BigInt(block.number).toString(), blockHash: block.hash.toLowerCase(),
    payerAddress: payer.toLowerCase(), recipientAddress: recipient.toLowerCase(),
    payerNativeWei: uint(payerNative, 'native_balance').toString(),
    payerUsdcUnits: payerUsdc, recipientWethUnits: recipientWeth, recipientUsdcUnits: recipientUsdc,
    payerWethUnits: payerWeth, poolUsdcUnits: poolUsdc, poolWethUnits: poolWeth,
    wethRouterAllowanceUnits: uint(wethAllowance, 'allowance').toString(),
    usdcRouterAllowanceUnits: uint(usdcAllowance, 'allowance').toString(),
  };
}

async function readSelectedRows(ctx: ProbeContext, session: { envId: string; generationId: string }, operationId: string, variantId = VARIANT_ID): Promise<SelectedExecutionRows> {
  const pool = new Pool({
    connectionString: ctx.env.databaseObserverUrl, max: 1, connectionTimeoutMillis: 5_000,
    idleTimeoutMillis: 5_000, statement_timeout: 5_000, query_timeout: 8_000,
    application_name: 'web-agent-bench-bef-task-transfer-readonly',
  });
  const client = await pool.connect();
  let failedAt = 'begin';
  try {
    await client.query('BEGIN READ ONLY');
    failedAt = 'role';
    const role = await client.query<{ role_name: string }>('SELECT current_user AS role_name');
    failedAt = 'mode';
    const mode = await client.query<{ transaction_read_only: string }>('SHOW transaction_read_only');
    failedAt = 'operation';
    const operation = await client.query(`SELECT operation_id::text, env_id, generation_id::text, participant_id, idempotency_key_sha256,
                           operation_kind, status, transaction_hash, receipt_status, request_sha256
                      FROM bef_operation WHERE env_id=$1 AND generation_id=$2::uuid AND operation_id=$3::uuid`,
      [session.envId, session.generationId, operationId]);
    failedAt = 'selected_execution';
    const selected = await client.query(`SELECT operation_id::text, action_kind, selected_action_json, transaction_intent_json,
                           transaction_hash, outcome, measurement_json
                      FROM bef_selected_execution WHERE env_id=$1 AND generation_id=$2::uuid AND operation_id=$3::uuid`,
      [session.envId, session.generationId, operationId]);
    failedAt = 'transaction_cost';
    const transactionCost = await client.query(`SELECT * FROM bef_transaction_cost WHERE env_id=$1 AND generation_id=$2::uuid AND operation_id=$3::uuid`,
      [session.envId, session.generationId, operationId]);
    failedAt = 'events';
    const events = await client.query(`SELECT event_sequence::text, event_kind, transaction_hash, event_json
                      FROM bef_selected_execution_event WHERE env_id=$1 AND generation_id=$2::uuid AND operation_id=$3::uuid
                     ORDER BY event_sequence`, [session.envId, session.generationId, operationId]);
    const databaseRole = role.rows[0]?.role_name ?? '';
    const transactionReadOnly = mode.rows[0]?.transaction_read_only ?? '';
    if (databaseRole !== ctx.database.databaseRole || transactionReadOnly !== 'on') throw new Error('task_transfer_database_not_readonly');
    const result: SelectedExecutionRows = {
      databaseRole, transactionReadOnly,
      operation: operation.rows[0] as Record<string, unknown> | undefined ?? null,
      selectedExecution: selected.rows[0] as Record<string, unknown> | undefined ?? null,
      transactionCost: transactionCost.rows[0] as Record<string, unknown> | undefined ?? null,
      events: events.rows as Record<string, unknown>[],
    };
    failedAt = 'evidence';
    await ctx.evidence.writeObservation(`db/task-transfer-${operationId}.json`, `task-transfer-selected-execution-${operationId}`, {
      schemaVersion: 'bef-db-observation/v1', boundary: 'readonly-database', operationId, variantId,
      envId: session.envId, generationId: session.generationId, queryName: 'task-transfer-operation-selected-execution-and-events',
      readOnly: true, databaseRole, transactionReadOnly,
      rows: { operation: result.operation, selectedExecution: result.selectedExecution, transactionCost: result.transactionCost, events: result.events },
    });
    await client.query('ROLLBACK');
    return result;
  } catch (error) {
    await client.query('ROLLBACK').catch(() => undefined);
    if (error instanceof Error && error.message === 'task_transfer_database_not_readonly') throw error;
    const sqlState = objectRecord(error)?.code;
    if (typeof sqlState === 'string' && /^[0-9A-Z]{5}$/.test(sqlState)) {
      throw new Error(`task_transfer_database_${failedAt}_failed_${sqlState.toLowerCase()}`);
    }
    if (error instanceof Error && error.message.startsWith('task_transfer_database_')) throw error;
    throw new Error(`task_transfer_database_${failedAt}_failed`);
  } finally {
    client.release();
    await pool.end();
  }
}

/** Reset the isolated environment and capture one actual participant USDC transfer. */
export async function captureSelectedUsdcTransfer(
  ctx: ProbeContext,
  requestedAmountUnits = '100000',
): Promise<Record<string, unknown>> {
  if (!UINT.test(requestedAmountUnits) || BigInt(requestedAmountUnits) <= 0n ||
      BigInt(requestedAmountUnits) > BigInt(ctx.runtime.manifest.funding.maxUsdcUnitsPerGeneration)) {
    throw new Error('task_transfer_amount_outside_fixture_bounds');
  }
  const resetRoute = ctx.capability.reset?.route?.replace(/^POST\s+/i, '').replace('{envId}', ctx.env.envId);
  if (!resetRoute || !resetRoute.startsWith('/internal/admin/environments/')) throw new Error('task_transfer_reset_route_unavailable');
  const reset = await ctx.transport.request({
    boundary: 'private-admin-http', observationId: 'task-transfer-reset', method: 'POST',
    url: apiPath(ctx.env.apiBaseUrl, resetRoute),
    headers: { 'X-BEF-Admin-Key': ctx.env.adminKey, 'content-type': 'application/json' },
    body: {}, operationId: null, variantId: VARIANT_ID,
  });
  if (reset.status < 200 || reset.status >= 300) throw new Error(`task_transfer_reset_failed_${reset.status}`);

  const signer = createEphemeralSigner();
  const recipientSigner = createEphemeralSigner();
  ctx.secretValues.push(signer.privateKey, recipientSigner.privateKey);
  const participantId = newParticipantId(ctx.scenarioId);
  const generation = await ctx.transport.request({
    boundary: 'private-admin-http', observationId: 'task-transfer-generation', method: 'POST',
    url: apiPath(ctx.env.apiBaseUrl, `/internal/admin/environments/${ctx.env.envId}/generations`),
    headers: { 'X-BEF-Admin-Key': ctx.env.adminKey, 'content-type': 'application/json' },
    body: { participantId, payerAddress: signer.payerAddress, payerPrivateKey: signer.privateKey, resourceVariant: 'canonical' },
    operationId: null, variantId: VARIANT_ID,
  });
  if (generation.status < 200 || generation.status >= 300) throw new Error(`task_transfer_generation_failed_${generation.status}`);
  const generationBody = objectRecord(generation.body);
  const session = {
    envId: requireString(generationBody?.envId, 'generation_env_id'),
    generationId: requireString(generationBody?.generationId, 'generation_id'),
    participantId,
    payerAddress: signer.payerAddress,
    runToken: requireString(generationBody?.runToken ?? objectRecord(generationBody?.participant)?.runToken, 'run_token'),
    signer,
  };
  if (session.envId !== ctx.env.envId || requireString(generationBody?.payerAddress, 'generation_payer').toLowerCase() !== signer.payerAddress.toLowerCase()) {
    throw new Error('task_transfer_generation_identity_mismatch');
  }
  ctx.secretValues.push(session.runToken);
  ctx.primaryGeneration = { envId: session.envId, generationId: session.generationId, participantId, payerAddress: signer.payerAddress };
  ctx.primarySession = session;
  await ctx.database.snapshot({ envId: session.envId, generationId: session.generationId, variantId: VARIANT_ID, label: 'task-transfer-generation-row' });

  const recipient = recipientSigner.payerAddress;
  if (recipient.toLowerCase() === signer.payerAddress.toLowerCase()) throw new Error('task_transfer_recipient_collides_with_payer');
  const before = await readSnapshot(ctx, signer.payerAddress, recipient, null, 'task-transfer-before');
  const amount = BigInt(requestedAmountUnits);
  if (BigInt(before.payerUsdcUnits) < amount) throw new Error('task_transfer_fixture_balance_insufficient');
  const gasLimit = 100_000n;
  if (gasLimit > BigInt(ctx.runtime.manifest.swap.maxTransactionGas) || gasLimit < 70_000n) {
    throw new Error('task_transfer_probe_gas_limit_outside_manifest_bound');
  }
  const action = { amountUnits: requestedAmountUnits, recipient, gasLimit: gasLimit.toString() };
  const inputData = encodeFunctionData({ abi: TRANSFER_ABI, functionName: 'transfer', args: [recipient, amount] });
  const idempotencyKey = randomUUID();
  const response = await ctx.transport.request({
    boundary: 'actual-tool-http', observationId: 'task-transfer-execute', method: 'POST',
    url: apiPath(ctx.env.apiBaseUrl, `/tools/${session.envId}/transfer`),
    headers: {
      authorization: `Bearer ${session.runToken}`,
      'X-BEF-Generation': session.generationId,
      'Idempotency-Key': idempotencyKey,
      'content-type': 'application/json',
    },
    body: action, operationId: null, variantId: VARIANT_ID,
    resolveOperationId: async (_status, body) => {
      const direct = objectRecord(body)?.operationId;
      if (typeof direct === 'string') return direct;
      const rows = await ctx.database.snapshot({
        envId: session.envId, generationId: session.generationId, idempotencyKey, variantId: VARIANT_ID,
        label: 'task-transfer-operation-lookup',
      });
      const operationId = rows.operations[0]?.operation_id;
      return typeof operationId === 'string' ? operationId : null;
    },
  });
  const responseBody = objectRecord(response.body);
  const operationId = response.operationId ?? (typeof responseBody?.operationId === 'string' ? responseBody.operationId : null);
  if (!operationId) throw new Error('task_transfer_operation_id_missing');
  const hashIdempotencyKey = createHash('sha256').update(idempotencyKey).digest('hex');
  const bodyReceipt = objectRecord(responseBody?.receipt);
  const bodyTransaction = objectRecord(responseBody?.transaction);
  const transactionHash = requireString(bodyReceipt?.transactionHash ?? bodyTransaction?.hash, 'transaction_hash');
  if (!HASH.test(transactionHash)) throw new Error('task_transfer_transaction_hash_invalid');
  ctx.operations.set(operationId, {
    operationId, kind: 'transfer', idempotencyKeyHash: hashIdempotencyKey,
    observedStatus: 'unknown', transactionHash, receiptStatus: 'unknown',
  });
  await ctx.database.snapshot({ envId: session.envId, generationId: session.generationId, operationId, variantId: VARIANT_ID, label: 'task-transfer-operation-snapshot' });

  const expectedInput = inputData.toLowerCase();
  const measurement = objectRecord(responseBody);
  const selectedAction = objectRecord(measurement?.selectedAction);
  const txIntent = objectRecord(measurement?.transaction);
  const measuredReceipt = objectRecord(measurement?.receipt);
  if (!txIntent) throw new Error('task_transfer_http_measurement_binding_invalid');
  if (response.status < 200 || response.status >= 300 || responseBody?.outcome !== 'success' ||
      selectedAction?.kind !== 'transfer' || selectedAction.amountUnits !== requestedAmountUnits ||
      typeof selectedAction.token !== 'string' || selectedAction.token.toLowerCase() !== ctx.runtime.manifest.contracts.usdc.address.toLowerCase() ||
      typeof selectedAction.recipient !== 'string' || selectedAction.recipient.toLowerCase() !== recipient.toLowerCase() ||
      typeof txIntent.hash !== 'string' || txIntent.hash.toLowerCase() !== transactionHash.toLowerCase() ||
      typeof txIntent.input !== 'string' || txIntent.input.toLowerCase() !== expectedInput ||
      typeof txIntent.from !== 'string' || txIntent.from.toLowerCase() !== signer.payerAddress.toLowerCase() ||
      typeof txIntent.to !== 'string' || txIntent.to.toLowerCase() !== ctx.runtime.manifest.contracts.usdc.address.toLowerCase() ||
      txIntent.valueWei !== '0' || measuredReceipt?.status !== 'success') {
    throw new Error('task_transfer_http_measurement_binding_invalid');
  }
  const selectedEvidence: SelectedExecutionTransactionEvidence = {
    environmentId: session.envId,
    operationId,
    variantId: VARIANT_ID,
    kind: 'transfer',
    transactionHash,
    expectedFrom: signer.payerAddress,
    expectedTo: ctx.runtime.manifest.contracts.usdc.address,
    expectedValueWei: '0',
    expectedChainId: String(ctx.runtime.manifest.local.chainId),
    expectedNonce: uint(txIntent.nonce, 'nonce').toString(),
    expectedGas: uint(txIntent.gasLimit, 'gas_limit').toString(),
    expectedInput,
  };
  const transaction = await ctx.rpc.call<Record<string, unknown>>({
    url: ctx.env.localRpcUrl, endpointBoundary: 'local-chain-readonly-proxy', environmentId: session.envId,
    method: 'eth_getTransactionByHash', params: [transactionHash], operationId, variantId: VARIANT_ID,
    label: 'task-transfer-selected-calldata', selectedExecutionTransaction: selectedEvidence,
  });
  if (typeof transaction.result.hash !== 'string' || transaction.result.hash.toLowerCase() !== transactionHash.toLowerCase() ||
      typeof transaction.result.input !== 'string' || transaction.result.input.toLowerCase() !== expectedInput ||
      typeof transaction.result.from !== 'string' || transaction.result.from.toLowerCase() !== signer.payerAddress.toLowerCase() ||
      typeof transaction.result.to !== 'string' || transaction.result.to.toLowerCase() !== ctx.runtime.manifest.contracts.usdc.address.toLowerCase() ||
      uint(transaction.result.value, 'onchain_value') !== 0n ||
      uint(transaction.result.chainId, 'onchain_chain_id') !== BigInt(ctx.runtime.manifest.local.chainId) ||
      uint(transaction.result.gas, 'onchain_gas_limit') !== gasLimit ||
      uint(transaction.result.nonce, 'onchain_nonce') !== uint(txIntent.nonce, 'nonce')) {
    throw new Error('task_transfer_onchain_transaction_binding_invalid');
  }
  const receipt = await ctx.rpc.receipt({
    url: ctx.env.localRpcUrl, boundary: 'local-chain-readonly-proxy', transactionHash,
    operationId, variantId: VARIANT_ID, label: 'task-transfer-receipt',
  });
  if (receipt.status !== '0x1' && receipt.status !== '1') throw new Error('task_transfer_receipt_not_success');
  if (receipt.from.toLowerCase() !== signer.payerAddress.toLowerCase() ||
      receipt.to?.toLowerCase() !== ctx.runtime.manifest.contracts.usdc.address.toLowerCase()) {
    throw new Error('task_transfer_receipt_identity_mismatch');
  }
  const receiptGasUsed = uint(receipt.gasUsed, 'onchain_gas_used');
  const receiptEffectiveGasPrice = uint(receipt.effectiveGasPrice, 'onchain_effective_gas_price');
  if (uint(measuredReceipt?.gasUsed, 'measured_gas_used') !== receiptGasUsed ||
      uint(measuredReceipt?.effectiveGasPrice, 'measured_effective_gas_price') !== receiptEffectiveGasPrice) {
    throw new Error('task_transfer_receipt_cost_measurement_mismatch');
  }
  const matchingTransfers = transferEvents(receipt, ctx.runtime.manifest.contracts.usdc.address).filter((event) =>
    event.from.toLowerCase() === signer.payerAddress.toLowerCase() &&
    event.to.toLowerCase() === recipient.toLowerCase() && event.amount === amount);
  if (matchingTransfers.length !== 1) throw new Error('task_transfer_receipt_event_mismatch');

  const receiptBlockTag = `0x${BigInt(receipt.blockNumber).toString(16)}`;
  const after = await readSnapshot(ctx, signer.payerAddress, recipient, operationId, 'task-transfer-after', receiptBlockTag);
  const gasCostWei = (receiptGasUsed * receiptEffectiveGasPrice).toString();
  if (BigInt(before.blockNumber) >= BigInt(after.blockNumber) ||
      after.blockHash.toLowerCase() !== receipt.blockHash.toLowerCase() ||
      BigInt(before.payerUsdcUnits) - BigInt(after.payerUsdcUnits) !== amount ||
      BigInt(after.recipientUsdcUnits) - BigInt(before.recipientUsdcUnits) !== amount ||
      BigInt(before.payerNativeWei) - BigInt(after.payerNativeWei) !== BigInt(gasCostWei) ||
      before.payerWethUnits !== after.payerWethUnits || before.poolUsdcUnits !== after.poolUsdcUnits ||
      before.poolWethUnits !== after.poolWethUnits || before.wethRouterAllowanceUnits !== after.wethRouterAllowanceUnits) {
    throw new Error('task_transfer_effect_delta_mismatch');
  }

  const persisted = await readSelectedRows(ctx, session, operationId);
  const operation = persisted.operation;
  const selected = persisted.selectedExecution;
  const persistedAction = objectRecord(selected?.selected_action_json);
  const transactionIntent = objectRecord(selected?.transaction_intent_json);
  const persistedMeasurement = objectRecord(selected?.measurement_json);
  const persistedMeasurementTransaction = objectRecord(persistedMeasurement?.transaction);
  const persistedMeasurementReceipt = objectRecord(persistedMeasurement?.receipt);
  const persistedMeasurementAction = objectRecord(persistedMeasurement?.selectedAction);
  const persistedMeasurementFee = objectRecord(persistedMeasurement?.fee);
  if (!transactionIntent || !persistedMeasurement || !persistedMeasurementTransaction ||
      !persistedMeasurementReceipt || !persistedMeasurementAction || !persistedMeasurementFee) {
    throw new Error('task_transfer_persisted_operation_binding_invalid_stored_json_missing');
  }
  const eventKinds = persisted.events.map((event) => event.event_kind);
  const requiredEventKinds = ['selected_action_bound', 'prestate_observed', 'original_tx_hash_bound', 'receipt_finalized'];
  const eventCounts = new Map(requiredEventKinds.map((kind) => [kind, eventKinds.filter((seen) => seen === kind).length]));
  const expectedRequestSha256 = createHash('sha256').update(canonicalJson({
    method: 'POST',
    path: '/tools/transfer',
    action: {
      kind: 'transfer',
      token: ctx.runtime.manifest.contracts.usdc.address,
      amountUnits: requestedAmountUnits,
      recipient: recipient.toLowerCase(),
      gasLimit: gasLimit.toString(),
    },
  })).digest('hex');
  const expectedStoredAction = {
    kind: 'transfer', amountUnits: requestedAmountUnits, recipient: recipient.toLowerCase(), gasLimit: gasLimit.toString(),
  };
  const bindingChecks: Array<[string, boolean]> = [
    ['operation_identity', operation !== null && operation.operation_id === operationId && operation.env_id === session.envId &&
      operation.generation_id === session.generationId && operation.participant_id === participantId],
    ['operation_state', operation !== null && operation.operation_kind === 'transfer' && operation.status === 'settled' && operation.receipt_status === 'success'],
    ['operation_idempotency', operation !== null && typeof operation.idempotency_key_sha256 === 'string' && operation.idempotency_key_sha256.toLowerCase() === hashIdempotencyKey],
    ['operation_request', operation !== null && typeof operation.request_sha256 === 'string' && operation.request_sha256.toLowerCase() === expectedRequestSha256],
    ['operation_transaction_hash', operation !== null && typeof operation.transaction_hash === 'string' && operation.transaction_hash.toLowerCase() === transactionHash.toLowerCase()],
    ['selected_execution_identity', selected !== null && selected.operation_id === operationId && selected.action_kind === 'transfer' && selected.outcome === 'success'],
    ['selected_execution_transaction_hash', selected !== null && typeof selected.transaction_hash === 'string' && selected.transaction_hash.toLowerCase() === transactionHash.toLowerCase()],
    ['selected_action', persistedAction !== null && canonicalJson(persistedAction) === canonicalJson(expectedStoredAction)],
    ['transaction_intent', typeof transactionIntent.hash === 'string' && transactionIntent.hash.toLowerCase() === transactionHash.toLowerCase() &&
      transactionIntent.type === 'eip1559' && transactionIntent.chainId === ctx.runtime.manifest.local.chainId &&
      transactionIntent.blockHash === null && transactionIntent.blockNumber === null && transactionIntent.transactionIndex === null &&
      typeof transactionIntent.from === 'string' && transactionIntent.from.toLowerCase() === signer.payerAddress.toLowerCase() &&
      typeof transactionIntent.to === 'string' && transactionIntent.to.toLowerCase() === ctx.runtime.manifest.contracts.usdc.address.toLowerCase() &&
      transactionIntent.valueWei === '0' && transactionIntent.nonce === uint(txIntent.nonce, 'nonce').toString() &&
      transactionIntent.gasLimit === gasLimit.toString() && typeof transactionIntent.input === 'string' && transactionIntent.input.toLowerCase() === expectedInput],
    ['measurement_transaction', typeof persistedMeasurementTransaction.hash === 'string' && persistedMeasurementTransaction.hash.toLowerCase() === transactionHash.toLowerCase() &&
      typeof persistedMeasurementTransaction.from === 'string' && persistedMeasurementTransaction.from.toLowerCase() === signer.payerAddress.toLowerCase() &&
      typeof persistedMeasurementTransaction.to === 'string' && persistedMeasurementTransaction.to.toLowerCase() === ctx.runtime.manifest.contracts.usdc.address.toLowerCase() &&
      typeof persistedMeasurementTransaction.input === 'string' && persistedMeasurementTransaction.input.toLowerCase() === expectedInput],
    ['measurement_receipt', persistedMeasurementReceipt.status === 'success' && typeof persistedMeasurementReceipt.transactionHash === 'string' &&
      persistedMeasurementReceipt.transactionHash.toLowerCase() === transactionHash.toLowerCase() &&
      typeof persistedMeasurementReceipt.blockHash === 'string' && persistedMeasurementReceipt.blockHash.toLowerCase() === receipt.blockHash.toLowerCase() &&
      uint(persistedMeasurementReceipt.gasUsed, 'persisted_gas_used') === receiptGasUsed &&
      uint(persistedMeasurementReceipt.effectiveGasPrice, 'persisted_effective_gas_price') === receiptEffectiveGasPrice],
    ['measurement_action', persistedMeasurementAction.kind === 'transfer' && persistedMeasurementAction.amountUnits === requestedAmountUnits &&
      typeof persistedMeasurementAction.token === 'string' && persistedMeasurementAction.token.toLowerCase() === ctx.runtime.manifest.contracts.usdc.address.toLowerCase() &&
      typeof persistedMeasurementAction.recipient === 'string' && persistedMeasurementAction.recipient.toLowerCase() === recipient.toLowerCase()],
    ['principal_accounting', persistedMeasurementFee.principalAsset === 'USDC' &&
      persistedMeasurementFee.selectedPrincipalUnits === requestedAmountUnits && persistedMeasurementFee.principalUnits === requestedAmountUnits],
    ['event_sequence', eventCounts.get('selected_action_bound') === 1 && eventCounts.get('prestate_observed') === 1 &&
      eventCounts.get('original_tx_hash_bound') === 1 && eventCounts.get('receipt_finalized') === 1 &&
      !persisted.events.some((event) => ['original_tx_hash_bound', 'receipt_finalized'].includes(String(event.event_kind)) &&
        (typeof event.transaction_hash !== 'string' || event.transaction_hash.toLowerCase() !== transactionHash.toLowerCase()))],
  ];
  const failedBindingChecks = bindingChecks.filter(([, passed]) => !passed).map(([name]) => name);
  if (failedBindingChecks.length) {
    throw new Error(`task_transfer_persisted_operation_binding_invalid_${failedBindingChecks.join('_')}`);
  }
  if (!operation) throw new Error('task_transfer_persisted_operation_binding_invalid_missing_operation');
  ctx.operations.set(operationId, {
    operationId, kind: 'transfer', idempotencyKeyHash: hashIdempotencyKey,
    observedStatus: String(operation.status), transactionHash,
    receiptStatus: 'success',
  });
  const fees = objectRecord(measurement?.fee);
  if (!fees || fees.principalAsset !== 'USDC' || fees.selectedPrincipalUnits !== requestedAmountUnits || fees.principalUnits !== requestedAmountUnits) {
    throw new Error('task_transfer_principal_accounting_invalid');
  }

  const result = {
    schemaVersion: 'bts-transfer-probe/v1',
    classification: 'selected_executor_primitive_capture_not_bts_acceptance',
    status: 'captured',
    environment: { envId: session.envId, generationId: session.generationId, participantId, payerAddress: signer.payerAddress },
    operation: { operationId, transactionHash, status: operation.status, receiptStatus: operation.receipt_status },
    action: { token: ctx.runtime.manifest.contracts.usdc.address, amountUnits: requestedAmountUnits, recipient },
    transaction: { from: txIntent.from, to: txIntent.to, chainId: txIntent.chainId, nonce: txIntent.nonce, gasLimit: txIntent.gasLimit, input: expectedInput },
    receipt: {
      blockNumber: BigInt(receipt.blockNumber).toString(), blockHash: receipt.blockHash, status: receipt.status,
      gasUsed: receiptGasUsed.toString(), effectiveGasPrice: receiptEffectiveGasPrice.toString(), gasCostWei,
    },
    before, after,
    verifiedDeltas: {
      payerUsdcUnits: (BigInt(after.payerUsdcUnits) - BigInt(before.payerUsdcUnits)).toString(),
      recipientUsdcUnits: (BigInt(after.recipientUsdcUnits) - BigInt(before.recipientUsdcUnits)).toString(),
      payerNativeWei: (BigInt(after.payerNativeWei) - BigInt(before.payerNativeWei)).toString(),
      payerWethUnits: (BigInt(after.payerWethUnits) - BigInt(before.payerWethUnits)).toString(),
      poolUsdcUnits: (BigInt(after.poolUsdcUnits) - BigInt(before.poolUsdcUnits)).toString(),
      poolWethUnits: (BigInt(after.poolWethUnits) - BigInt(before.poolWethUnits)).toString(),
      wethRouterAllowanceUnits: (BigInt(after.wethRouterAllowanceUnits) - BigInt(before.wethRouterAllowanceUnits)).toString(),
    },
    principalAndExpense: { principalAsset: fees.principalAsset, principalUnits: fees.principalUnits, gasCostWei, modeledGasFeeUsdcUnits: fees.modeledGasFeeUsdcUnits },
  };
  const { schemaVersion: captureSchemaVersion, ...captureResult } = result;
  await ctx.evidence.writeObservation(`task-transfer/${operationId}-summary.json`, `task-transfer-summary-${operationId}`, {
    ...captureResult,
    schemaVersion: 'bef-resource-observation/v1', captureSchemaVersion,
    boundary: 'actual-tool-http', operationId, variantId: VARIANT_ID,
    envId: session.envId, generationId: session.generationId,
  });
  return result;
}

/** Capture the full USDC approval -> USDC/WETH exact-input path on the pinned local fork. */
export async function captureSelectedUsdcToWethSwap(
  ctx: ProbeContext,
  requestedAmountUnits = '100000',
  feeTier: 500 | 3000 = 500,
): Promise<Record<string, unknown>> {
  const variantId = feeTier === 3000 ? 'task_m3_reverse_swap_fee3000_capture' : 'task_m3_reverse_swap_capture';
  const manifest = ctx.runtime.manifest;
  const routePool = feeTier === 500 ? manifest.contracts.pool : feeTier === 3000 ? manifest.contracts.pool3000 : undefined;
  if (!routePool || routePool.fee !== feeTier || routePool.token0.toLowerCase() !== manifest.contracts.weth.address.toLowerCase() ||
      routePool.token1.toLowerCase() !== manifest.contracts.usdc.address.toLowerCase() ||
      feeTier === 3000 && (!/^[0-9a-f]{64}$/i.test(routePool.codeHash.replace(/^0x/i, '')) || routePool.address.toLowerCase() === manifest.contracts.pool.address.toLowerCase())) {
    throw new Error('task_reverse_swap_pinned_route_unavailable');
  }
  const amount = BigInt(requestedAmountUnits);
  if (!UINT.test(requestedAmountUnits) || amount <= 0n ||
      amount > BigInt(manifest.funding.maxUsdcUnitsPerGeneration)) {
    throw new Error('task_reverse_swap_amount_outside_fixture_bounds');
  }
  const resetRoute = ctx.capability.reset?.route?.replace(/^POST\s+/i, '').replace('{envId}', ctx.env.envId);
  if (!resetRoute || !resetRoute.startsWith('/internal/admin/environments/')) throw new Error('task_reverse_swap_reset_route_unavailable');
  const reset = await ctx.transport.request({
    boundary: 'private-admin-http', observationId: 'task-reverse-swap-reset', method: 'POST',
    url: apiPath(ctx.env.apiBaseUrl, resetRoute),
    headers: { 'X-BEF-Admin-Key': ctx.env.adminKey, 'content-type': 'application/json' },
    body: {}, operationId: null, variantId,
  });
  if (reset.status < 200 || reset.status >= 300) throw new Error(`task_reverse_swap_reset_failed_${reset.status}`);

  const signer = createEphemeralSigner();
  const recipientSigner = createEphemeralSigner();
  ctx.secretValues.push(signer.privateKey, recipientSigner.privateKey);
  const participantId = newParticipantId(ctx.scenarioId);
  const generation = await ctx.transport.request({
    boundary: 'private-admin-http', observationId: 'task-reverse-swap-generation', method: 'POST',
    url: apiPath(ctx.env.apiBaseUrl, `/internal/admin/environments/${ctx.env.envId}/generations`),
    headers: { 'X-BEF-Admin-Key': ctx.env.adminKey, 'content-type': 'application/json' },
    body: { participantId, payerAddress: signer.payerAddress, payerPrivateKey: signer.privateKey, resourceVariant: 'canonical' },
    operationId: null, variantId,
  });
  if (generation.status < 200 || generation.status >= 300) throw new Error(`task_reverse_swap_generation_failed_${generation.status}`);
  const generationBody = objectRecord(generation.body);
  const session = {
    envId: requireString(generationBody?.envId, 'generation_env_id'),
    generationId: requireString(generationBody?.generationId, 'generation_id'),
    participantId,
    payerAddress: signer.payerAddress,
    runToken: requireString(generationBody?.runToken ?? objectRecord(generationBody?.participant)?.runToken, 'run_token'),
  };
  if (session.envId !== ctx.env.envId || requireString(generationBody?.payerAddress, 'generation_payer').toLowerCase() !== signer.payerAddress.toLowerCase()) {
    throw new Error('task_reverse_swap_generation_identity_mismatch');
  }
  ctx.secretValues.push(session.runToken);
  ctx.primaryGeneration = { envId: session.envId, generationId: session.generationId, participantId, payerAddress: signer.payerAddress };
  await ctx.database.snapshot({ envId: session.envId, generationId: session.generationId, variantId, label: 'task-reverse-swap-generation-row' });

  const recipient = recipientSigner.payerAddress;
  if (recipient.toLowerCase() === signer.payerAddress.toLowerCase()) throw new Error('task_reverse_swap_recipient_collides_with_payer');
  const beforeApproval = await readSnapshot(ctx, signer.payerAddress, recipient, null, 'task-reverse-swap-before-approval', undefined, variantId, routePool.address);
  if (BigInt(beforeApproval.payerUsdcUnits) < amount) throw new Error('task_reverse_swap_fixture_balance_insufficient');
  const approvalGasLimit = 100_000n;
  const swapGasLimit = 400_000n;
  if (approvalGasLimit > BigInt(manifest.swap.maxTransactionGas) || swapGasLimit > BigInt(manifest.swap.maxTransactionGas)) {
    throw new Error('task_reverse_swap_gas_limit_outside_manifest_bound');
  }
  const requestHeaders = (key: string) => ({
    authorization: `Bearer ${session.runToken}`,
    'X-BEF-Generation': session.generationId,
    'Idempotency-Key': key,
    'content-type': 'application/json',
  });
  const postAction = async (kind: 'approve' | 'swap', body: Record<string, unknown>, label: string) => {
    const idempotencyKey = randomUUID();
    const response = await ctx.transport.request({
      boundary: 'actual-tool-http', observationId: `task-reverse-swap-${label}`, method: 'POST',
      url: apiPath(ctx.env.apiBaseUrl, `/tools/${session.envId}/${kind}`),
      headers: requestHeaders(idempotencyKey), body, operationId: null, variantId,
      resolveOperationId: async (_status, responseBody) => {
        const operationId = objectRecord(responseBody)?.operationId;
        return typeof operationId === 'string' ? operationId : null;
      },
    });
    const payload = objectRecord(response.body);
    const operationId = response.operationId ?? (typeof payload?.operationId === 'string' ? payload.operationId : null);
    if (!operationId || response.status < 200 || response.status >= 300 || payload?.outcome !== 'success') {
      throw new Error(`task_reverse_swap_${label}_tool_action_failed_${response.status}`);
    }
    const tx = objectRecord(payload.transaction);
    const receipt = objectRecord(payload.receipt);
    const transactionHash = requireString(receipt?.transactionHash ?? tx?.hash, `${label}_transaction_hash`);
    if (!HASH.test(transactionHash)) throw new Error(`task_reverse_swap_${label}_transaction_hash_invalid`);
    ctx.operations.set(operationId, {
      operationId, kind, idempotencyKeyHash: createHash('sha256').update(idempotencyKey).digest('hex'),
      observedStatus: 'unknown', transactionHash, receiptStatus: 'unknown',
    });
    await ctx.database.snapshot({ envId: session.envId, generationId: session.generationId, operationId, variantId, label: `task-reverse-swap-${label}-operation-snapshot` });
    return { payload, operationId, transactionHash, idempotencyKey };
  };
  const approveAmount = amount.toString();
  const approvalBody = { tokenAssetId: 'USDC', amountUnits: approveAmount, gasLimit: approvalGasLimit.toString() };
  const approval = await postAction('approve', approvalBody, 'approve-usdc');
  const approvalInput = encodeFunctionData({ abi: APPROVE_ABI, functionName: 'approve', args: [manifest.contracts.swapRouter02.address as `0x${string}`, amount] });
  const approvalMeasurement = objectRecord(approval.payload);
  const approvalTransaction = objectRecord(approvalMeasurement?.transaction);
  const approvalReceiptMeasurement = objectRecord(approvalMeasurement?.receipt);
  const approvalFee = objectRecord(approvalMeasurement?.fee);
  if (!approvalTransaction || !approvalReceiptMeasurement ||
      approvalTransaction.to?.toString().toLowerCase() !== manifest.contracts.usdc.address.toLowerCase() ||
      approvalTransaction.input?.toString().toLowerCase() !== approvalInput.toLowerCase() ||
      !approvalFee || approvalFee.principalAsset !== null || approvalFee.selectedPrincipalUnits !== '0' || approvalFee.principalUnits !== '0') {
    throw new Error('task_reverse_swap_approval_http_measurement_binding_invalid');
  }
  const approvalReceipt = await ctx.rpc.receipt({
    url: ctx.env.localRpcUrl, boundary: 'local-chain-readonly-proxy', transactionHash: approval.transactionHash,
    operationId: approval.operationId, variantId, label: 'task-reverse-swap-approve-usdc-receipt',
  });
  if (approvalReceipt.status.toLowerCase() !== '0x1' ||
      approvalReceipt.to?.toLowerCase() !== manifest.contracts.usdc.address.toLowerCase()) {
    throw new Error('task_reverse_swap_approval_receipt_invalid');
  }
  const approvalEvents = approvalReceipt.logs.filter((log) => log.address.toLowerCase() === manifest.contracts.usdc.address.toLowerCase()).flatMap((log) => {
    try {
      const decoded = decodeEventLog({
        abi: parseAbi(['event Approval(address indexed owner,address indexed spender,uint256 value)']),
        eventName: 'Approval', topics: log.topics as [`0x${string}`, ...`0x${string}`[]], data: log.data as `0x${string}`,
      });
      const args = decoded.args as { owner: `0x${string}`; spender: `0x${string}`; value: bigint };
      return args.owner.toLowerCase() === signer.payerAddress.toLowerCase() &&
        args.spender.toLowerCase() === manifest.contracts.swapRouter02.address.toLowerCase() && args.value === amount ? [args] : [];
    } catch { return []; }
  });
  if (approvalEvents.length !== 1) throw new Error('task_reverse_swap_approval_event_mismatch');
  const afterApproval = await readSnapshot(ctx, signer.payerAddress, recipient, approval.operationId, 'task-reverse-swap-after-approval', `0x${BigInt(approvalReceipt.blockNumber).toString(16)}`, variantId, routePool.address);
  const approvalGasUsed = uint(approvalReceipt.gasUsed, 'approval_gas_used');
  const approvalEffectiveGasPrice = uint(approvalReceipt.effectiveGasPrice, 'approval_effective_gas_price');
  if (afterApproval.blockHash.toLowerCase() !== approvalReceipt.blockHash.toLowerCase() ||
      BigInt(afterApproval.usdcRouterAllowanceUnits) !== BigInt(beforeApproval.usdcRouterAllowanceUnits) + amount ||
      afterApproval.wethRouterAllowanceUnits !== beforeApproval.wethRouterAllowanceUnits ||
      afterApproval.payerUsdcUnits !== beforeApproval.payerUsdcUnits || afterApproval.payerWethUnits !== beforeApproval.payerWethUnits ||
      BigInt(beforeApproval.payerNativeWei) - BigInt(afterApproval.payerNativeWei) !== approvalGasUsed * approvalEffectiveGasPrice) {
    throw new Error('task_reverse_swap_approval_effect_delta_mismatch');
  }

  const minimumOutputUnits = '1';
  const swapBody = {
    inputAssetId: 'USDC', outputAssetId: 'WETH', feeTier, amountInUnits: approveAmount,
    amountOutMinimumUnits: minimumOutputUnits, recipient, gasLimit: swapGasLimit.toString(),
  };
  const swap = await postAction('swap', swapBody, 'usdc-to-weth');
  const swapInput = encodeFunctionData({
    abi: SWAP_ROUTER_ABI, functionName: 'exactInputSingle',
    args: [{
      tokenIn: manifest.contracts.usdc.address as `0x${string}`,
      tokenOut: manifest.contracts.weth.address as `0x${string}`,
      fee: routePool.fee,
      recipient: recipient as `0x${string}`,
      amountIn: amount,
      amountOutMinimum: BigInt(minimumOutputUnits),
      sqrtPriceLimitX96: 0n,
    }],
  });
  const swapMeasurement = objectRecord(swap.payload);
  if (!swapMeasurement) throw new Error('task_reverse_swap_http_measurement_binding_invalid');
  const swapTransaction = objectRecord(swapMeasurement?.transaction);
  const swapReceiptMeasurement = objectRecord(swapMeasurement?.receipt);
  const swapSelectedAction = objectRecord(swapMeasurement?.selectedAction);
  if (!swapTransaction || !swapReceiptMeasurement ||
      swapTransaction.to?.toString().toLowerCase() !== manifest.contracts.swapRouter02.address.toLowerCase() ||
      swapTransaction.input?.toString().toLowerCase() !== swapInput.toLowerCase() ||
      swapSelectedAction?.inputAssetId !== 'USDC' || swapSelectedAction?.outputAssetId !== 'WETH' ||
      swapSelectedAction.fee !== feeTier ||
      (feeTier === 3000 && (typeof swapSelectedAction.poolAddress !== 'string' ||
        swapSelectedAction.poolAddress.toLowerCase() !== routePool.address.toLowerCase() ||
        typeof swapSelectedAction.poolCodeHash !== 'string' ||
        swapSelectedAction.poolCodeHash.toLowerCase() !== routePool.codeHash.toLowerCase()))) {
    throw new Error('task_reverse_swap_http_measurement_binding_invalid');
  }
  const swapReceipt = await ctx.rpc.receipt({
    url: ctx.env.localRpcUrl, boundary: 'local-chain-readonly-proxy', transactionHash: swap.transactionHash,
    operationId: swap.operationId, variantId, label: 'task-reverse-swap-usdc-to-weth-receipt',
  });
  if (swapReceipt.status.toLowerCase() !== '0x1' || swapReceipt.to?.toLowerCase() !== manifest.contracts.swapRouter02.address.toLowerCase()) {
    throw new Error('task_reverse_swap_receipt_invalid');
  }
  const swapIntent = objectRecord(swapMeasurement.transaction)!;
  const onchainTransaction = await ctx.rpc.call<Record<string, unknown>>({
    url: ctx.env.localRpcUrl, endpointBoundary: 'local-chain-readonly-proxy', environmentId: session.envId,
    method: 'eth_getTransactionByHash', params: [swap.transactionHash], operationId: swap.operationId, variantId,
    label: 'task-reverse-swap-usdc-to-weth-transaction',
    selectedExecutionTransaction: {
      environmentId: session.envId, operationId: swap.operationId, variantId, kind: 'swap', transactionHash: swap.transactionHash,
      expectedFrom: signer.payerAddress, expectedTo: manifest.contracts.swapRouter02.address,
      expectedValueWei: '0', expectedChainId: String(manifest.local.chainId), expectedNonce: uint(swapIntent.nonce, 'swap_nonce').toString(),
      expectedGas: swapGasLimit.toString(), expectedInput: swapInput,
    } satisfies SelectedExecutionTransactionEvidence,
  });
  const txProjection = objectRecord(onchainTransaction.result);
  if (!txProjection || typeof txProjection.input !== 'string' || txProjection.input.toLowerCase() !== swapInput.toLowerCase()) {
    throw new Error('task_reverse_swap_onchain_transaction_binding_invalid');
  }
  const poolSwapLogs = swapReceipt.logs.filter((log) => log.address.toLowerCase() === routePool.address.toLowerCase());
  if (poolSwapLogs.length !== 1) throw new Error('task_reverse_swap_pool_event_count_invalid');
  let inputUnitsFromPool = 0n;
  let outputUnitsFromPool = 0n;
  try {
    const decoded = decodeEventLog({ abi: POOL_SWAP_ABI, eventName: 'Swap', topics: poolSwapLogs[0]!.topics as [`0x${string}`, ...`0x${string}`[]], data: poolSwapLogs[0]!.data as `0x${string}` });
    const args = decoded.args as { sender: `0x${string}`; recipient: `0x${string}`; amount0: bigint; amount1: bigint };
    if (args.sender.toLowerCase() !== manifest.contracts.swapRouter02.address.toLowerCase() ||
        args.recipient.toLowerCase() !== recipient.toLowerCase() || args.amount0 >= 0n || args.amount1 <= 0n) {
      throw new Error('task_reverse_swap_pool_event_direction_invalid');
    }
    outputUnitsFromPool = -args.amount0;
    inputUnitsFromPool = args.amount1;
  } catch (error) {
    if (error instanceof Error && error.message.startsWith('task_reverse_swap_')) throw error;
    throw new Error('task_reverse_swap_pool_event_invalid');
  }
  const usdcInputEvents = transferEvents(swapReceipt, manifest.contracts.usdc.address).filter((event) =>
    event.from.toLowerCase() === signer.payerAddress.toLowerCase() &&
    event.to.toLowerCase() === routePool.address.toLowerCase() && event.amount === amount);
  const wethOutputEvents = transferEvents(swapReceipt, manifest.contracts.weth.address).filter((event) =>
    event.from.toLowerCase() === routePool.address.toLowerCase() &&
    event.to.toLowerCase() === recipient.toLowerCase() && event.amount === outputUnitsFromPool);
  if (inputUnitsFromPool !== amount || outputUnitsFromPool < BigInt(minimumOutputUnits) ||
      usdcInputEvents.length !== 1 || wethOutputEvents.length !== 1) {
    throw new Error('task_reverse_swap_receipt_events_mismatch');
  }
  const afterSwap = await readSnapshot(ctx, signer.payerAddress, recipient, swap.operationId, 'task-reverse-swap-after-swap', `0x${BigInt(swapReceipt.blockNumber).toString(16)}`, variantId, routePool.address);
  const swapGasUsed = uint(swapReceipt.gasUsed, 'swap_gas_used');
  const swapEffectiveGasPrice = uint(swapReceipt.effectiveGasPrice, 'swap_effective_gas_price');
  const swapGasCost = swapGasUsed * swapEffectiveGasPrice;
  if (afterSwap.blockHash.toLowerCase() !== swapReceipt.blockHash.toLowerCase() ||
      BigInt(afterApproval.payerUsdcUnits) - BigInt(afterSwap.payerUsdcUnits) !== amount ||
      BigInt(afterSwap.recipientWethUnits) - BigInt(afterApproval.recipientWethUnits) !== outputUnitsFromPool ||
      afterSwap.payerWethUnits !== afterApproval.payerWethUnits ||
      afterSwap.recipientUsdcUnits !== afterApproval.recipientUsdcUnits ||
      BigInt(afterSwap.poolUsdcUnits) - BigInt(afterApproval.poolUsdcUnits) !== amount ||
      BigInt(afterApproval.poolWethUnits) - BigInt(afterSwap.poolWethUnits) !== outputUnitsFromPool ||
      BigInt(afterApproval.usdcRouterAllowanceUnits) - BigInt(afterSwap.usdcRouterAllowanceUnits) !== amount ||
      afterSwap.wethRouterAllowanceUnits !== afterApproval.wethRouterAllowanceUnits ||
      BigInt(afterApproval.payerNativeWei) - BigInt(afterSwap.payerNativeWei) !== swapGasCost) {
    throw new Error('task_reverse_swap_effect_delta_mismatch');
  }
  const swapFee = objectRecord(swapMeasurement.fee);
  if (!swapFee || swapFee.principalAsset !== 'USDC' || swapFee.selectedPrincipalUnits !== approveAmount ||
      swapFee.principalUnits !== approveAmount || uint(swapReceiptMeasurement.gasCostWei, 'measured_gas_cost') !== swapGasCost) {
    throw new Error('task_reverse_swap_principal_cost_accounting_invalid');
  }
  const transactionCost = async (operationId: string, expectedAsset: string | null, expectedPrincipal: string) => {
    const persisted = await readSelectedRows(ctx, session, operationId, variantId);
    const operation = persisted.operation;
    const selected = persisted.selectedExecution;
    const cost = persisted.transactionCost;
    const expectedAction = operationId === swap.operationId
      ? { kind: 'swap', inputAssetId: 'USDC', outputAssetId: 'WETH', amountInUnits: approveAmount,
        feeTier, amountOutMinimumUnits: minimumOutputUnits, recipient: recipient.toLowerCase(), gasLimit: swapGasLimit.toString() }
      : { kind: 'approve', tokenAssetId: 'USDC', amountUnits: approveAmount, gasLimit: approvalGasLimit.toString() };
    let storedAction = objectRecord(selected?.selected_action_json);
    if (!storedAction && typeof selected?.selected_action_json === 'string') {
      try { storedAction = objectRecord(JSON.parse(selected.selected_action_json)); } catch { storedAction = null; }
    }
    if (!operation || !selected || !cost || operation.status !== 'settled' || operation.receipt_status !== 'success' ||
        selected.outcome !== 'success' || canonicalJson(storedAction) !== canonicalJson(expectedAction) ||
        cost.receipt_status !== 'success' || cost.selected_principal_asset !== expectedAsset ||
        String(cost.selected_principal_units) !== expectedPrincipal || String(cost.observed_principal_units) !== expectedPrincipal ||
        typeof cost.gas_cost_wei !== 'string' || !UINT.test(cost.gas_cost_wei) ||
        typeof cost.modeled_gas_fee_usdc_units !== 'string' || !UINT.test(cost.modeled_gas_fee_usdc_units)) {
      throw new Error('task_reverse_swap_database_cost_or_action_binding_invalid');
    }
    if (operationId === swap.operationId) {
      const storedMeasurement = objectRecord(selected.measurement_json);
      const storedMeasurementAction = objectRecord(storedMeasurement?.selectedAction);
      if (!storedMeasurementAction || storedMeasurementAction.fee !== feeTier ||
          (feeTier === 3000 && (typeof storedMeasurementAction.poolAddress !== 'string' ||
            storedMeasurementAction.poolAddress.toLowerCase() !== routePool.address.toLowerCase() ||
            typeof storedMeasurementAction.poolCodeHash !== 'string' ||
            storedMeasurementAction.poolCodeHash.toLowerCase() !== routePool.codeHash.toLowerCase()))) {
        throw new Error('task_reverse_swap_database_route_binding_invalid');
      }
    }
    const kinds = persisted.events.map((event) => event.event_kind);
    for (const required of ['selected_action_bound', 'prestate_observed', 'original_tx_hash_bound', 'receipt_finalized']) {
      if (kinds.filter((kind) => kind === required).length !== 1) throw new Error('task_reverse_swap_database_event_sequence_invalid');
    }
    return { operation, selected, cost, events: persisted.events };
  };
  const approvalPersisted = await transactionCost(approval.operationId, null, '0');
  const swapPersisted = await transactionCost(swap.operationId, 'USDC', approveAmount);
  if (String(swapPersisted.cost.gas_cost_wei) !== swapGasCost.toString() ||
      String(approvalPersisted.cost.gas_cost_wei) !== (approvalGasUsed * approvalEffectiveGasPrice).toString()) {
    throw new Error('task_reverse_swap_persisted_cost_receipt_mismatch');
  }
  const result = {
    schemaVersion: 'bts-reverse-swap-probe/v1',
    classification: 'selected_executor_reverse_swap_capture_not_bts_acceptance',
    status: 'captured',
    environment: { envId: session.envId, generationId: session.generationId, participantId, payerAddress: signer.payerAddress },
    approval: {
      operationId: approval.operationId, transactionHash: approval.transactionHash, status: 'success',
      tokenAssetId: 'USDC', amountUnits: approveAmount,
      gasUsed: approvalGasUsed.toString(), effectiveGasPriceWei: approvalEffectiveGasPrice.toString(),
      gasCostWei: (approvalGasUsed * approvalEffectiveGasPrice).toString(),
      persistedCost: approvalPersisted.cost,
    },
    swap: {
      operationId: swap.operationId, transactionHash: swap.transactionHash, status: 'success',
      feeTier, poolAddress: routePool.address, poolCodeHash: routePool.codeHash,
      inputAssetId: 'USDC', outputAssetId: 'WETH', amountInUnits: approveAmount,
      amountOutMinimumUnits: minimumOutputUnits, observedOutputUnits: outputUnitsFromPool.toString(), recipient,
      gasUsed: swapGasUsed.toString(), effectiveGasPriceWei: swapEffectiveGasPrice.toString(), gasCostWei: swapGasCost.toString(),
      persistedCost: swapPersisted.cost,
    },
    snapshots: { beforeApproval, afterApproval, afterSwap },
    verifiedDeltas: {
      payerUsdcUnits: (BigInt(afterSwap.payerUsdcUnits) - BigInt(beforeApproval.payerUsdcUnits)).toString(),
      recipientWethUnits: (BigInt(afterSwap.recipientWethUnits) - BigInt(beforeApproval.recipientWethUnits)).toString(),
      poolUsdcUnits: (BigInt(afterSwap.poolUsdcUnits) - BigInt(beforeApproval.poolUsdcUnits)).toString(),
      poolWethUnits: (BigInt(afterSwap.poolWethUnits) - BigInt(beforeApproval.poolWethUnits)).toString(),
      usdcRouterAllowanceUnits: (BigInt(afterSwap.usdcRouterAllowanceUnits) - BigInt(beforeApproval.usdcRouterAllowanceUnits)).toString(),
      payerNativeWei: (BigInt(afterSwap.payerNativeWei) - BigInt(beforeApproval.payerNativeWei)).toString(),
    },
    principalAndExpense: {
      principalAsset: swapFee.principalAsset, principalUnits: swapFee.principalUnits,
      swapGasCostWei: swapGasCost.toString(), swapModeledGasFeeUsdcUnits: swapFee.modeledGasFeeUsdcUnits,
      approvalGasCostWei: approvalPersisted.cost.gas_cost_wei,
      approvalModeledGasFeeUsdcUnits: approvalPersisted.cost.modeled_gas_fee_usdc_units,
      principalExcludedFromExpense: true,
    },
  };
  await ctx.evidence.writeObservation(`task-reverse-swap/${swap.operationId}-summary.json`, `task-reverse-swap-summary-${swap.operationId}`, {
    ...result, boundary: 'actual-tool-http', operationId: swap.operationId, variantId,
    envId: session.envId, generationId: session.generationId,
  });
  return result;
}
