/**
 * SC009/010 candidate workload. This file is in the ignored validation copy;
 * the frozen central CLI/adapter are not changed by it.
 *
 * The workload reuses the extracted canonical x402 purchase flow and sends
 * selected wrap/approve/swap requests through the same public tool routes as
 * SC007. Snapshots below are only hash-bound indexes to raw RPC/DB artifacts.
 */
import { createHash, randomUUID } from 'node:crypto';
import pg from 'pg';
import { encodeFunctionData, parseAbi, type Address, type Hex } from 'viem';
import { apiPath } from './environment.js';
import type { ProbeContext, GenerationSession, ScenarioExecution } from './runner.js';
import type { SelectedExecutionTransactionEvidence } from './rpc.js';

const { Pool } = pg;
const GAS_LIMIT = '1200000';
const SWAP_AMOUNT_WEI = '100000000000000000';
const ROUTE_ALLOWANCE_WEI = '200000000000000000';
const APPROVE_ABI = parseAbi(['function approve(address spender,uint256 amount) returns (bool)']);
const WETH_ACTION_ABI = parseAbi(['function deposit() payable']);
const SWAP_ROUTER_ABI = parseAbi([
  'function exactInputSingle((address tokenIn,address tokenOut,uint24 fee,address recipient,uint256 amountIn,uint256 amountOutMinimum,uint160 sqrtPriceLimitX96) params) payable returns (uint256 amountOut)',
]);
const CHAIN_KEYS = [
  'chainId', 'head', 'payerNative', 'payerNonce', 'facilitatorNative', 'facilitatorNonce',
  'donorNative', 'donorNonce', 'donorUsdc', 'payerWeth', 'payerUsdc', 'facilitatorUsdc',
  'recipientUsdc', 'poolWeth', 'poolUsdc', 'wethRouterAllowance', 'usdcRouterAllowance',
  'usdcCode', 'usdcImplementationCode', 'wethCode', 'factoryCode', 'routerCode',
  'quoterCode', 'poolCode', 'poolLiquidity', 'poolSlot0',
] as const;
const SERVICE_QUERIES = [
  'generation-by-id', 'operations-by-generation', 'payments-by-operation', 'deliveries-by-operation',
  'denials-by-generation', 'x402-observations-by-operation', 'selected-execution-by-generation',
  'selected-execution-events-by-generation',
] as const;

type ScenarioId = 'BEF-SC-009' | 'BEF-SC-010';
type SnapshotPhase009 = 'baseline' | 'mutated' | 'reset' | 'after_reset';
type SnapshotPhase010 = 'baseline' | 'trial' | 'reset' | 'after_stale' | 'fresh_trial';
type Checkpoint = {
  phase: string;
  environmentId: string;
  generationId: string;
  chainSnapshot: { path: string; sha256: string };
  serviceSnapshot: { path: string; sha256: string };
  resetRequest?: { path: string; sha256: string };
};
type SelectedAction = 'wrap' | 'approve' | 'swap';

function record(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : null;
}

function stableJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(',')}]`;
  const object = record(value);
  if (object) return `{${Object.keys(object).sort().map((key) => `${JSON.stringify(key)}:${stableJson(object[key])}`).join(',')}}`;
  return JSON.stringify(value) ?? 'null';
}

function expectedSelectedTransaction(ctx: ProbeContext, session: GenerationSession, kind: SelectedAction,
                                     body: Record<string, string>): { to: Address; valueWei: string; input: Hex } {
  const manifest = ctx.runtime.manifest;
  if (kind === 'wrap') return {
    to: manifest.contracts.weth.address as Address,
    valueWei: body.amountWei!,
    input: encodeFunctionData({ abi: WETH_ACTION_ABI, functionName: 'deposit' }),
  };
  if (kind === 'approve') return {
    to: manifest.contracts.weth.address as Address,
    valueWei: '0',
    input: encodeFunctionData({
      abi: APPROVE_ABI, functionName: 'approve',
      args: [manifest.contracts.swapRouter02.address as Address, BigInt(body.amountUnits!)],
    }),
  };
  return {
    to: manifest.contracts.swapRouter02.address as Address,
    valueWei: '0',
    input: encodeFunctionData({
      abi: SWAP_ROUTER_ABI, functionName: 'exactInputSingle',
      args: [{
        tokenIn: manifest.swap.tokenIn as Address,
        tokenOut: manifest.swap.tokenOut as Address,
        fee: manifest.swap.fee,
        recipient: session.payerAddress as Address,
        amountIn: BigInt(body.amountInWei!),
        amountOutMinimum: BigInt(body.amountOutMinimumUsdcUnits!),
        sqrtPriceLimitX96: 0n,
      }],
    }),
  };
}

async function readSelectedExecution(ctx: ProbeContext, session: GenerationSession, operationId: string,
                                     variantId: string): Promise<Record<string, unknown>> {
  const pool = new Pool({ connectionString: ctx.env.databaseObserverUrl, max: 1, connectionTimeoutMillis: 5_000, statement_timeout: 5_000 });
  const client = await pool.connect();
  try {
    await client.query('BEGIN READ ONLY');
    const role = await client.query<{ role_name: string }>('SELECT current_user AS role_name');
    const readOnly = await client.query<{ transaction_read_only: string }>('SHOW transaction_read_only');
    if (role.rows[0]?.role_name !== ctx.database.databaseRole || readOnly.rows[0]?.transaction_read_only !== 'on') {
      throw new Error('probe_sc009010_selected_db_not_readonly');
    }
    const result = await client.query(
      `SELECT operation_id::text, env_id, generation_id::text, action_kind, selected_action_json,
              transaction_intent_json, transaction_hash, outcome, reason_code, completed_at
         FROM bef_selected_execution
        WHERE env_id=$1 AND generation_id=$2::uuid AND operation_id=$3::uuid`,
      [session.envId, session.generationId, operationId],
    );
    await client.query('COMMIT');
    if (result.rows.length !== 1) throw new Error('probe_sc009010_selected_execution_row_missing');
    await ctx.evidence.writeObservation(`db/${session.envId}-${operationId}-selected-execution.json`,
      `${session.envId}-${operationId}-selected-execution`, {
        schemaVersion: 'bef-db-observation/v1', boundary: 'readonly-database', operationId, variantId,
        readOnly: true, transactionReadOnly: 'on', databaseRole: ctx.database.databaseRole,
        queryName: 'selected-execution-by-operation', observationScope: 'operation',
        envId: session.envId, generationId: session.generationId, rows: result.rows,
      });
    return result.rows[0] as Record<string, unknown>;
  } catch (error) {
    await client.query('ROLLBACK').catch(() => undefined);
    if (error instanceof Error && error.message.startsWith('probe_sc009010_selected_')) throw error;
    throw new Error('probe_sc009010_selected_db_snapshot_failed');
  } finally {
    client.release();
    await pool.end();
  }
}

function requiredString(value: unknown, label: string): string {
  if (typeof value !== 'string' || !value) throw new Error(`probe_sc009010_${label}_missing`);
  return value;
}

function address(value: unknown, label: string): `0x${string}` {
  if (typeof value !== 'string' || !/^0x[0-9a-f]{40}$/i.test(value)) throw new Error(`probe_sc009010_${label}_invalid`);
  return value.toLowerCase() as `0x${string}`;
}

function refForPath(ctx: ProbeContext, path: string): { path: string; sha256: string } {
  const matches = ctx.evidence.artifacts.filter((artifact) => artifact.path === path);
  if (matches.length !== 1) throw new Error('probe_sc009010_raw_artifact_reference_missing');
  return { path, sha256: matches[0]!.sha256 };
}

async function rpcRead(ctx: ProbeContext, label: string, method: string, params: unknown[]): Promise<{ value: unknown; ref: { path: string; sha256: string } }> {
  const before = ctx.evidence.artifacts.length;
  const result = await ctx.rpc.call({
    url: ctx.env.localRpcUrl,
    endpointBoundary: 'local-chain-readonly-proxy',
    environmentId: ctx.env.envId,
    method,
    params,
    operationId: null,
    variantId: null,
    label,
  });
  const added = ctx.evidence.artifacts.slice(before).filter((artifact) => artifact.boundary === 'local-chain-readonly-proxy');
  if (added.length !== 1) throw new Error('probe_sc009010_rpc_artifact_cardinality_invalid');
  return { value: result.result, ref: { path: added[0]!.path, sha256: added[0]!.sha256 } };
}

function word(addressValue: string): string {
  return addressValue.toLowerCase().replace(/^0x/, '').padStart(64, '0');
}

async function captureChainSnapshot(ctx: ProbeContext, session: GenerationSession, scenarioId: ScenarioId, phase: string): Promise<{ path: string; sha256: string }> {
  const manifest = ctx.runtime.manifest;
  const contracts = manifest.contracts;
  const services = record(ctx.capability.services);
  const facilitatorServices = record(services?.facilitator);
  const addresses = {
    payer: address(session.payerAddress, 'payer'),
    facilitator: address(facilitatorServices?.address, 'facilitator'),
    donor: address(manifest.funding.donor, 'donor'),
    recipient: address(session.payerAddress, 'recipient'),
    weth: address(contracts.weth.address, 'weth'),
    usdc: address(contracts.usdc.address, 'usdc'),
    usdcImplementation: address(contracts.usdc.implementation, 'usdc_implementation'),
    factory: address(contracts.factory.address, 'factory'),
    router: address(contracts.swapRouter02.address, 'router'),
    quoter: address(contracts.quoterV2.address, 'quoter'),
    pool: address(contracts.pool.address, 'pool'),
  };
  const reads = {} as Record<typeof CHAIN_KEYS[number], { path: string; sha256: string }>;
  const label = (key: string) => `${scenarioId.toLowerCase()}-${ctx.env.envId}-${phase}-${key}`;
  const read = async (key: typeof CHAIN_KEYS[number], method: string, params: unknown[]) => {
    reads[key] = (await rpcRead(ctx, label(key), method, params)).ref;
  };
  await read('chainId', 'eth_chainId', []);
  await read('head', 'eth_getBlockByNumber', ['latest', false]);
  for (const role of ['payer', 'facilitator', 'donor'] as const) {
    await read(`${role}Native`, 'eth_getBalance', [addresses[role], 'latest']);
    await read(`${role}Nonce`, 'eth_getTransactionCount', [addresses[role], 'latest']);
  }
  const balanceOf = async (key: typeof CHAIN_KEYS[number], token: string, account: string) =>
    read(key, 'eth_call', [{ to: token, data: `0x70a08231${word(account)}` }, 'latest']);
  await balanceOf('donorUsdc', addresses.usdc, addresses.donor);
  await balanceOf('payerWeth', addresses.weth, addresses.payer);
  await balanceOf('payerUsdc', addresses.usdc, addresses.payer);
  await balanceOf('facilitatorUsdc', addresses.usdc, addresses.facilitator);
  await balanceOf('recipientUsdc', addresses.usdc, addresses.recipient);
  await balanceOf('poolWeth', addresses.weth, addresses.pool);
  await balanceOf('poolUsdc', addresses.usdc, addresses.pool);
  await read('wethRouterAllowance', 'eth_call', [{ to: addresses.weth, data: `0xdd62ed3e${word(addresses.payer)}${word(addresses.router)}` }, 'latest']);
  await read('usdcRouterAllowance', 'eth_call', [{ to: addresses.usdc, data: `0xdd62ed3e${word(addresses.payer)}${word(addresses.router)}` }, 'latest']);
  for (const [key, target] of [
    ['usdcCode', addresses.usdc], ['usdcImplementationCode', addresses.usdcImplementation],
    ['wethCode', addresses.weth], ['factoryCode', addresses.factory], ['routerCode', addresses.router],
    ['quoterCode', addresses.quoter], ['poolCode', addresses.pool],
  ] as const) await read(key, 'eth_getCode', [target, 'latest']);
  await read('poolLiquidity', 'eth_call', [{ to: addresses.pool, data: '0x1a686502' }, 'latest']);
  await read('poolSlot0', 'eth_call', [{ to: addresses.pool, data: '0x3850c7bd' }, 'latest']);
  if (Object.keys(reads).length !== CHAIN_KEYS.length || CHAIN_KEYS.some((key) => !reads[key])) {
    throw new Error('probe_sc009010_chain_read_set_incomplete');
  }
  const path = `state/${scenarioId.toLowerCase()}-${ctx.env.envId}-${phase}-chain.json`;
  await ctx.evidence.writeObservation(path, `${scenarioId.toLowerCase()}-${ctx.env.envId}-${phase}-chain-snapshot`, {
    schemaVersion: 'bef-sc009010-chain-snapshot/v1',
    boundary: 'local-chain-readonly-proxy',
    operationId: null,
    variantId: null,
    scenarioId,
    environmentId: ctx.env.envId,
    generationId: session.generationId,
    phase,
    addresses,
    reads,
  });
  return refForPath(ctx, path);
}

async function selectedRows(ctx: ProbeContext, session: GenerationSession, phase: string): Promise<void> {
  const pool = new Pool({ connectionString: ctx.env.databaseObserverUrl, max: 1, connectionTimeoutMillis: 5_000, statement_timeout: 5_000 });
  const client = await pool.connect();
  try {
    await client.query('BEGIN READ ONLY');
    const role = await client.query<{ role_name: string }>('SELECT current_user AS role_name');
    const readOnly = await client.query<{ transaction_read_only: string }>('SHOW transaction_read_only');
    if (role.rows[0]?.role_name !== ctx.database.databaseRole || readOnly.rows[0]?.transaction_read_only !== 'on') {
      throw new Error('probe_sc009010_selected_db_not_readonly');
    }
    const executions = await client.query(
      `SELECT operation_id::text, env_id, generation_id::text, action_kind, selected_action_json,
              prestate_json, transaction_intent_json, transaction_hash, outcome, reason_code,
              measurement_json, created_at, updated_at, completed_at
         FROM bef_selected_execution WHERE env_id=$1 AND generation_id=$2::uuid ORDER BY operation_id`,
      [session.envId, session.generationId],
    );
    const events = await client.query(
      `SELECT event_sequence::text, event_id::text, operation_id::text, env_id, generation_id::text,
              event_kind, transaction_hash, event_json, created_at
         FROM bef_selected_execution_event WHERE env_id=$1 AND generation_id=$2::uuid
        ORDER BY operation_id,event_sequence`,
      [session.envId, session.generationId],
    );
    await client.query('COMMIT');
    for (const [queryName, rows] of [
      ['selected-execution-by-generation', executions.rows],
      ['selected-execution-events-by-generation', events.rows],
    ] as const) {
      await ctx.evidence.writeObservation(`db/${session.envId}-${phase}-${queryName}.json`, `${session.envId}-${phase}-${queryName}`, {
        schemaVersion: 'bef-db-observation/v1', boundary: 'readonly-database', operationId: null, variantId: null,
        readOnly: true, transactionReadOnly: 'on', databaseRole: ctx.database.databaseRole, queryName, observationScope: 'generation',
        envId: session.envId, generationId: session.generationId, rows,
      });
    }
  } catch {
    await client.query('ROLLBACK').catch(() => undefined);
    throw new Error('probe_sc009010_selected_db_snapshot_failed');
  } finally {
    client.release();
    await pool.end();
  }
}

async function captureServiceSnapshot(ctx: ProbeContext, session: GenerationSession, scenarioId: ScenarioId, phase: string): Promise<{ path: string; sha256: string }> {
  const label = `${scenarioId.toLowerCase()}-${session.envId}-${phase}`;
  await ctx.database.snapshot({
    envId: session.envId, generationId: session.generationId, variantId: null, label,
    observationScope: 'generation',
  });
  await selectedRows(ctx, session, label);
  const tables = {} as Record<typeof SERVICE_QUERIES[number], { path: string; sha256: string }>;
  const suffix: Record<typeof SERVICE_QUERIES[number], string> = {
    'generation-by-id': 'generation-by-id',
    'operations-by-generation': 'operations-by-generation',
    'payments-by-operation': 'payments-by-operation',
    'deliveries-by-operation': 'deliveries-by-operation',
    'denials-by-generation': 'denials-by-generation',
    'x402-observations-by-operation': 'x402-observations-by-operation',
    'selected-execution-by-generation': 'selected-execution-by-generation',
    'selected-execution-events-by-generation': 'selected-execution-events-by-generation',
  };
  for (const queryName of SERVICE_QUERIES) {
    const path = queryName.startsWith('selected-execution')
      ? `db/${session.envId}-${label}-${queryName}.json`
      : `db/${label}-${suffix[queryName]}.json`;
    tables[queryName] = refForPath(ctx, path);
  }
  const path = `state/${scenarioId.toLowerCase()}-${session.envId}-${phase}-service.json`;
  await ctx.evidence.writeObservation(path, `${scenarioId.toLowerCase()}-${session.envId}-${phase}-service-snapshot`, {
    schemaVersion: 'bef-sc009010-service-snapshot/v1', boundary: 'readonly-database',
    operationId: null, variantId: null, scenarioId, environmentId: session.envId,
    generationId: session.generationId, phase, tables,
  });
  return refForPath(ctx, path);
}

async function checkpoint(ctx: ProbeContext, session: GenerationSession, scenarioId: ScenarioId, phase: string): Promise<Checkpoint> {
  const [chainSnapshot, serviceSnapshot] = await Promise.all([
    captureChainSnapshot(ctx, session, scenarioId, phase),
    captureServiceSnapshot(ctx, session, scenarioId, phase),
  ]);
  return { phase, environmentId: session.envId, generationId: session.generationId, chainSnapshot, serviceSnapshot };
}

function resetRequestSince(ctx: ProbeContext, artifactOffset: number): { path: string; sha256: string } {
  // startCanonicalGeneration emits the reset request before its generation-create request.
  // Preserve the first raw private-admin HTTP artifact from that exact call window;
  // the evidence predicate verifies its method, route, body, response and ordering.
  const calls = ctx.evidence.artifacts.slice(artifactOffset).filter((artifact) =>
    artifact.boundary === 'private-admin-http' && artifact.path.startsWith('http/'));
  if (calls.length !== 2 || !calls[0]?.path || !calls[0]?.sha256) {
    throw new Error('probe_sc009010_reset_request_reference_missing');
  }
  return { path: calls[0].path, sha256: calls[0].sha256 };
}

function writeCheckpointIndex(ctx: ProbeContext, scenarioId: ScenarioId, checkpoints: Checkpoint[],
                              extra: Record<string, unknown> = {}): Promise<string> {
  const path = `scenario/${scenarioId.toLowerCase()}-checkpoint-index.json`;
  return ctx.evidence.writeObservation(path, `${scenarioId.toLowerCase()}-checkpoint-index`, {
    schemaVersion: 'bef-sc009010-checkpoint-index/v1', boundary: 'scenario-report',
    operationId: null, variantId: null, scenarioId, checkpoints, ...extra,
  });
}

function participantHeaders(session: GenerationSession, key: string): Record<string, string> {
  return {
    authorization: `Bearer ${session.runToken}`, 'X-BEF-Generation': session.generationId,
    'Idempotency-Key': key, 'content-type': 'application/json',
  };
}

async function deniedRequest(ctx: ProbeContext, session: GenerationSession, scenarioId: ScenarioId, variantId: string,
                            method: string, path: string, body?: unknown, extraHeaders: Record<string, string> = {},
                            idempotencyKey?: string) {
  const key = idempotencyKey ?? `${scenarioId.toLowerCase()}-${variantId}-${randomUUID()}`;
  return ctx.transport.request({
    boundary: 'actual-tool-http', observationId: `${scenarioId.toLowerCase()}-${session.envId}-${variantId}`,
    method, url: apiPath(ctx.env.apiBaseUrl, path), headers: { ...participantHeaders(session, key), ...extraHeaders },
    ...(body === undefined ? {} : { body }), operationId: null, variantId,
    resolveOperationId: async (_status, responseBody) => {
      const result = record(responseBody)?.operationId;
      return typeof result === 'string' ? result : null;
    },
  });
}

async function selectedAction(ctx: ProbeContext, session: GenerationSession, scenarioId: ScenarioId,
                              kind: SelectedAction, body: Record<string, string>, variantId: string): Promise<string> {
  const key = `${scenarioId.toLowerCase()}-${session.envId}-${session.generationId}-${kind}-${randomUUID()}`;
  const response = await ctx.transport.request({
    boundary: 'actual-tool-http', observationId: `${scenarioId.toLowerCase()}-${session.envId}-${session.generationId}-selected-${kind}`,
    method: 'POST', url: apiPath(ctx.env.apiBaseUrl, `/tools/${session.envId}/${kind}`),
    headers: participantHeaders(session, key), body, operationId: null, variantId,
    resolveOperationId: async (_status, responseBody) => {
      const result = record(responseBody)?.operationId;
      return typeof result === 'string' ? result : null;
    },
  });
  if (response.status !== 200) throw new Error(`probe_sc009010_selected_${kind}_failed_${response.status}`);
  const payload = record(response.body);
  const operationId = response.operationId ?? (typeof payload?.operationId === 'string' ? payload.operationId : null);
  const tx = record(payload?.transaction);
  const transactionHash = tx?.hash ?? record(payload?.receipt)?.transactionHash;
  if (!operationId || typeof transactionHash !== 'string' || !/^0x[0-9a-f]{64}$/i.test(transactionHash)) {
    throw new Error(`probe_sc009010_selected_${kind}_identity_missing`);
  }
  const expectedTx = expectedSelectedTransaction(ctx, session, kind, body);
  if (!tx || tx.hash !== transactionHash || String(tx.from).toLowerCase() !== session.payerAddress.toLowerCase()
      || typeof tx.to !== 'string' || tx.to.toLowerCase() !== expectedTx.to.toLowerCase()
      || typeof tx.input !== 'string' || tx.input.toLowerCase() !== expectedTx.input.toLowerCase()
      || tx.valueWei !== expectedTx.valueWei || tx.chainId !== ctx.runtime.manifest.local.chainId
      || typeof tx.nonce !== 'string' || !/^(?:0|[1-9][0-9]*)$/.test(tx.nonce)
      || typeof tx.gasLimit !== 'string' || !/^(?:0|[1-9][0-9]*)$/.test(tx.gasLimit)) {
    throw new Error(`probe_sc009010_selected_${kind}_transaction_intent_invalid`);
  }
  const rows = await ctx.database.snapshot({ envId: session.envId, generationId: session.generationId,
    operationId, variantId, label: `${scenarioId.toLowerCase()}-${session.envId}-${session.generationId}-${kind}-${operationId}-operation` });
  const operation = rows.operations.find((row) => String(row.operation_id) === operationId);
  if (!operation || String(operation.transaction_hash).toLowerCase() !== transactionHash.toLowerCase()
      || String(operation.status) !== 'settled' || String(operation.receipt_status) !== 'success') {
    throw new Error(`probe_sc009010_selected_${kind}_database_binding_invalid`);
  }
  const execution = await readSelectedExecution(ctx, session, operationId, variantId);
  let storedAction = record(execution.selected_action_json);
  if (!storedAction && typeof execution.selected_action_json === 'string') {
    try { storedAction = record(JSON.parse(execution.selected_action_json)); } catch { storedAction = null; }
  }
  const expectedStoredAction: Record<string, unknown> = kind === 'approve'
    ? { kind, tokenAssetId: 'WETH', ...body }
    : kind === 'swap'
      ? {
        kind, inputAssetId: 'WETH', outputAssetId: 'USDC', amountInUnits: body.amountInWei,
        amountOutMinimumUnits: body.amountOutMinimumUsdcUnits, recipient: session.payerAddress.toLowerCase(), gasLimit: body.gasLimit,
      }
      : { kind, ...body };
  let storedIntent = record(execution.transaction_intent_json);
  if (!storedIntent && typeof execution.transaction_intent_json === 'string') {
    try { storedIntent = record(JSON.parse(execution.transaction_intent_json)); } catch { storedIntent = null; }
  }
  if (execution.operation_id !== operationId || execution.env_id !== session.envId
      || execution.generation_id !== session.generationId || execution.action_kind !== kind
      || execution.transaction_hash !== transactionHash || execution.outcome !== 'success'
      || !storedAction || stableJson(storedAction) !== stableJson(expectedStoredAction)
      || !storedIntent || String(storedIntent.hash).toLowerCase() !== transactionHash.toLowerCase()
      || String(storedIntent.from).toLowerCase() !== session.payerAddress.toLowerCase()
      || String(storedIntent.to).toLowerCase() !== expectedTx.to.toLowerCase()
      || String(storedIntent.input).toLowerCase() !== expectedTx.input.toLowerCase()
      || String(storedIntent.valueWei) !== expectedTx.valueWei
      || String(storedIntent.chainId) !== String(ctx.runtime.manifest.local.chainId)
      || String(storedIntent.nonce) !== tx.nonce || String(storedIntent.gasLimit) !== tx.gasLimit) {
    throw new Error(`probe_sc009010_selected_${kind}_stored_intent_binding_invalid`);
  }
  const receipt = await ctx.rpc.receipt({ url: ctx.env.localRpcUrl, boundary: 'local-chain-readonly-proxy',
    transactionHash, operationId, variantId,
    label: `${scenarioId.toLowerCase()}-${session.envId}-${session.generationId}-${operationId}-${kind}-receipt` });
  if (receipt.status.toLowerCase() !== '0x1' || receipt.from.toLowerCase() !== session.payerAddress.toLowerCase()) {
    throw new Error(`probe_sc009010_selected_${kind}_receipt_invalid`);
  }
  const onchain = record((await ctx.rpc.call({
    url: ctx.env.localRpcUrl, endpointBoundary: 'local-chain-readonly-proxy', environmentId: session.envId,
    method: 'eth_getTransactionByHash', params: [transactionHash], operationId, variantId,
    label: `${scenarioId.toLowerCase()}-${session.envId}-${session.generationId}-${operationId}-${kind}-transaction-by-hash`,
    selectedExecutionTransaction: {
      environmentId: session.envId, operationId, variantId, kind, transactionHash,
      expectedFrom: session.payerAddress, expectedTo: expectedTx.to, expectedValueWei: expectedTx.valueWei,
      expectedChainId: String(ctx.runtime.manifest.local.chainId), expectedNonce: tx.nonce,
      expectedGas: tx.gasLimit, expectedInput: expectedTx.input,
    } satisfies SelectedExecutionTransactionEvidence,
  })).result);
  if (!onchain || String(onchain.hash).toLowerCase() !== transactionHash.toLowerCase()
      || String(onchain.from).toLowerCase() !== session.payerAddress.toLowerCase()
      || String(onchain.to).toLowerCase() !== expectedTx.to.toLowerCase()
      || typeof onchain.input !== 'string' || onchain.input.toLowerCase() !== expectedTx.input.toLowerCase()) {
    throw new Error(`probe_sc009010_selected_${kind}_onchain_intent_invalid`);
  }
  ctx.operations.set(operationId, {
    operationId, kind, idempotencyKeyHash: createHash('sha256').update(key).digest('hex'),
    observedStatus: String(operation.status), transactionHash,
    receiptStatus: 'success',
  });
  return operationId;
}

async function quote(ctx: ProbeContext, session: GenerationSession, scenarioId: ScenarioId): Promise<void> {
  const key = `${scenarioId.toLowerCase()}-${session.envId}-${session.generationId}-quote-${randomUUID()}`;
  const response = await ctx.transport.request({
    boundary: 'actual-tool-http', observationId: `${scenarioId.toLowerCase()}-${session.envId}-${session.generationId}-selected-quote`,
    method: 'GET', url: `${apiPath(ctx.env.apiBaseUrl, `/tools/${session.envId}/quote`)}?amountInWei=${SWAP_AMOUNT_WEI}`,
    headers: participantHeaders(session, key), operationId: null, variantId: null,
  });
  if (response.status !== 200 || !record(response.body)?.quote) throw new Error('probe_sc009010_selected_quote_invalid');
}

async function selectedRouteSequence(ctx: ProbeContext, session: GenerationSession, scenarioId: ScenarioId, actionVariant: string): Promise<void> {
  const manifest = ctx.runtime.manifest;
  await selectedAction(ctx, session, scenarioId, 'wrap', { amountWei: SWAP_AMOUNT_WEI, gasLimit: GAS_LIMIT }, actionVariant);
  await selectedAction(ctx, session, scenarioId, 'approve', { amountUnits: ROUTE_ALLOWANCE_WEI, gasLimit: GAS_LIMIT }, actionVariant);
  await quote(ctx, session, scenarioId);
  await selectedAction(ctx, session, scenarioId, 'swap', {
    amountInWei: SWAP_AMOUNT_WEI,
    amountOutMinimumUsdcUnits: '0',
    recipient: session.payerAddress,
    gasLimit: GAS_LIMIT,
  }, actionVariant);
  if (BigInt(SWAP_AMOUNT_WEI) > BigInt(manifest.swap.maxAmountIn)
      || BigInt(GAS_LIMIT) > BigInt(manifest.swap.maxTransactionGas)) {
    throw new Error('probe_sc009010_selected_flow_outside_manifest_bounds');
  }
}

function assertContexts(ctxA: ProbeContext, ctxB?: ProbeContext): void {
  const envs = ctxA.runtime.manifest.local.environments.map((item) => item.id);
  if (envs.length !== 2 || envs[0] !== ctxA.env.envId || (ctxB && envs[1] !== ctxB.env.envId)) {
    throw new Error('probe_sc009010_environment_context_order_invalid');
  }
  if (ctxB && (ctxA.evidence !== ctxB.evidence || ctxA.runtime.manifestSha256 !== ctxB.runtime.manifestSha256
      || ctxA.database.databaseRole !== ctxB.database.databaseRole)) {
    throw new Error('probe_sc009010_contexts_not_shared_evidence_or_manifest');
  }
}

function mergeOperations(target: ProbeContext, source: ProbeContext): void {
  for (const [key, operation] of source.operations) {
    if (target.operations.has(key)) throw new Error('probe_sc009010_operation_identity_collision');
    target.operations.set(key, operation);
  }
}

export async function runScenario009(ctxA: ProbeContext, ctxB: ProbeContext): Promise<ScenarioExecution> {
  assertContexts(ctxA, ctxB);
  const scenarioId: ScenarioId = 'BEF-SC-009';
  const maxSeconds = ctxA.runtime.manifest.guardrails.maxSwapScenarioSeconds;
  if (!Number.isInteger(maxSeconds) || maxSeconds <= 0) throw new Error('probe_sc009010_deadline_pin_invalid');
  const deadlineAt = Date.now() + maxSeconds * 1_000;
  for (const ctx of [ctxA, ctxB]) {
    ctx.transport.setDeadlineAt(deadlineAt); ctx.rpc.setDeadlineAt(deadlineAt); ctx.database.setDeadlineAt(deadlineAt);
    await ctx.rpc.bindLocalEndpoint({ url: ctx.env.localRpcUrl, environmentId: ctx.env.envId,
      manifestSha256: ctx.runtime.manifestSha256, label: `sc009-${ctx.env.envId}-rpc-binding` });
  }
  const sessionA = await (await import('./runner.js')).startCanonicalGeneration(ctxA, 'sc009-a');
  const sessionB = await (await import('./runner.js')).startCanonicalGeneration(ctxB, 'sc009-b');
  const checkpoints: Checkpoint[] = [];
  checkpoints.push(await checkpoint(ctxA, sessionA, scenarioId, 'baseline'));
  checkpoints.push(await checkpoint(ctxB, sessionB, scenarioId, 'baseline'));
  const runner = await import('./runner.js');
  await Promise.all([
    runner.runCanonicalPurchaseInSession(ctxA, sessionA, 'sc009-a-canonical', {
      idempotencyKey: `sc009-${ctxA.env.envId}-purchase-${randomUUID()}`, variantId: 'concurrent_operations',
    }),
    runner.runCanonicalPurchaseInSession(ctxB, sessionB, 'sc009-b-canonical', {
      idempotencyKey: `sc009-${ctxB.env.envId}-purchase-${randomUUID()}`, variantId: 'concurrent_operations',
    }),
  ]);
  await Promise.all([
    selectedAction(ctxA, sessionA, scenarioId, 'wrap', { amountWei: SWAP_AMOUNT_WEI, gasLimit: GAS_LIMIT }, 'concurrent_operations'),
    selectedAction(ctxB, sessionB, scenarioId, 'wrap', { amountWei: SWAP_AMOUNT_WEI, gasLimit: GAS_LIMIT }, 'concurrent_operations'),
  ]);
  await Promise.all([
    selectedAction(ctxA, sessionA, scenarioId, 'approve', { amountUnits: ROUTE_ALLOWANCE_WEI, gasLimit: GAS_LIMIT }, 'concurrent_operations'),
    selectedAction(ctxB, sessionB, scenarioId, 'approve', { amountUnits: ROUTE_ALLOWANCE_WEI, gasLimit: GAS_LIMIT }, 'concurrent_operations'),
  ]);
  await Promise.all([quote(ctxA, sessionA, scenarioId), quote(ctxB, sessionB, scenarioId)]);
  await Promise.all([
    selectedAction(ctxA, sessionA, scenarioId, 'swap', { amountInWei: SWAP_AMOUNT_WEI, amountOutMinimumUsdcUnits: '0', recipient: sessionA.payerAddress, gasLimit: GAS_LIMIT }, 'concurrent_operations'),
    selectedAction(ctxB, sessionB, scenarioId, 'swap', { amountInWei: SWAP_AMOUNT_WEI, amountOutMinimumUsdcUnits: '0', recipient: sessionB.payerAddress, gasLimit: GAS_LIMIT }, 'concurrent_operations'),
  ]);
  await Promise.all([selectedRows(ctxA, sessionA, 'sc009-mutated'), selectedRows(ctxB, sessionB, 'sc009-mutated')]);
  checkpoints.push(await checkpoint(ctxA, sessionA, scenarioId, 'mutated'));
  checkpoints.push(await checkpoint(ctxB, sessionB, scenarioId, 'mutated'));

  const foreign = await deniedRequest(ctxA, sessionA, scenarioId, 'foreign_environment_reference', 'GET', `/tools/${sessionB.envId}/balances`);
  if (foreign.status < 400 || foreign.status >= 500 || foreign.operationId) throw new Error('probe_sc009_foreign_environment_not_denied');
  const resetOther = await deniedRequest(ctxA, sessionA, scenarioId, 'reset_other_instance', 'POST', `/internal/admin/environments/${sessionB.envId}/reset`, {});
  if (resetOther.status < 400 || resetOther.status >= 500 || resetOther.operationId) throw new Error('probe_sc009_foreign_reset_not_denied');

  const resetArtifactOffset = ctxA.evidence.artifacts.length;
  const resetSessionA = await (await import('./runner.js')).startCanonicalGeneration(ctxA, 'sc009-a-reset');
  const resetCheckpoint = await checkpoint(ctxA, resetSessionA, scenarioId, 'reset');
  resetCheckpoint.resetRequest = resetRequestSince(ctxA, resetArtifactOffset);
  checkpoints.push(resetCheckpoint);
  checkpoints.push(await checkpoint(ctxB, sessionB, scenarioId, 'after_reset'));
  mergeOperations(ctxA, ctxB);
  await writeCheckpointIndex(ctxA, scenarioId, checkpoints);
  if (!ctxA.primaryGeneration) throw new Error('probe_sc009_primary_generation_missing');
  return { environment: { envId: ctxA.primaryGeneration.envId, generation: {
    generationId: ctxA.primaryGeneration.generationId, participantId: ctxA.primaryGeneration.participantId,
    payerAddress: ctxA.primaryGeneration.payerAddress,
  } } };
}

export async function runScenario010(ctx: ProbeContext): Promise<ScenarioExecution> {
  const scenarioId: ScenarioId = 'BEF-SC-010';
  const maxSeconds = ctx.runtime.manifest.guardrails.maxSwapScenarioSeconds;
  if (!Number.isInteger(maxSeconds) || maxSeconds <= 0) throw new Error('probe_sc009010_deadline_pin_invalid');
  const deadlineAt = Date.now() + maxSeconds * 1_000;
  ctx.transport.setDeadlineAt(deadlineAt); ctx.rpc.setDeadlineAt(deadlineAt); ctx.database.setDeadlineAt(deadlineAt);
  await ctx.rpc.bindLocalEndpoint({ url: ctx.env.localRpcUrl, environmentId: ctx.env.envId,
    manifestSha256: ctx.runtime.manifestSha256, label: `sc010-${ctx.env.envId}-rpc-binding` });
  const oldSession = await (await import('./runner.js')).startCanonicalGeneration(ctx, 'sc010-first');
  const checkpoints: Checkpoint[] = [];
  checkpoints.push(await checkpoint(ctx, oldSession, scenarioId, 'baseline'));
  const runner = await import('./runner.js');
  const reusedIdempotencyKey = `sc010-reused-${randomUUID()}`;
  const oldPurchase = await runner.runCanonicalPurchaseInSession(ctx, oldSession, 'sc010-first-canonical', {
    idempotencyKey: reusedIdempotencyKey, variantId: 'reused_operation_namespace',
  });
  await selectedRouteSequence(ctx, oldSession, scenarioId, 'reused_operation_namespace');
  checkpoints.push(await checkpoint(ctx, oldSession, scenarioId, 'trial'));

  const resetArtifactOffset = ctx.evidence.artifacts.length;
  const newSession = await runner.startCanonicalGeneration(ctx, 'sc010-reset');
  const resetCheckpoint = await checkpoint(ctx, newSession, scenarioId, 'reset');
  resetCheckpoint.resetRequest = resetRequestSince(ctx, resetArtifactOffset);
  checkpoints.push(resetCheckpoint);

  const lateWorker = await deniedRequest(ctx, oldSession, scenarioId, 'late_worker', 'POST', `/tools/${oldSession.envId}/swap`, {
    amountInWei: SWAP_AMOUNT_WEI, amountOutMinimumUsdcUnits: '0', recipient: oldSession.payerAddress, gasLimit: GAS_LIMIT,
  });
  if (lateWorker.status < 400 || lateWorker.status >= 500 || lateWorker.operationId) throw new Error('probe_sc010_late_worker_not_denied');
  const previousNonce = await deniedRequest(ctx, oldSession, scenarioId, 'previous_payment_nonce', 'POST', `/tools/${oldSession.envId}/purchase`,
    { resourceId: ctx.runtime.manifest.x402.resourceId, offerId: 'canonical' }, oldPurchase.paymentHeaders, oldPurchase.idempotencyKey);
  if (previousNonce.status < 400 || previousNonce.status >= 500 || previousNonce.operationId) throw new Error('probe_sc010_previous_payment_not_denied');
  const staleDelivery = await deniedRequest(ctx, oldSession, scenarioId, 'stale_delivery_record', 'POST', `/tools/${oldSession.envId}/purchase`,
    { resourceId: ctx.runtime.manifest.x402.resourceId, offerId: 'canonical' }, {}, oldPurchase.idempotencyKey);
  if (staleDelivery.status < 400 || staleDelivery.status >= 500 || staleDelivery.operationId) throw new Error('probe_sc010_stale_delivery_not_denied');
  const oldGenerationAfterStale = await captureServiceSnapshot(ctx, oldSession, scenarioId, 'old_generation_after_stale');
  checkpoints.push(await checkpoint(ctx, newSession, scenarioId, 'after_stale'));

  const newPurchase = await runner.runCanonicalPurchaseInSession(ctx, newSession, 'sc010-fresh-canonical', {
    idempotencyKey: reusedIdempotencyKey, variantId: 'reused_operation_namespace',
  });
  if (newPurchase.operationId === oldPurchase.operationId || newPurchase.paymentId === oldPurchase.paymentId
      || newPurchase.deliveryId === oldPurchase.deliveryId || newPurchase.transactionHash === oldPurchase.transactionHash) {
    throw new Error('probe_sc010_new_trial_identity_reused');
  }
  await selectedRouteSequence(ctx, newSession, scenarioId, 'reused_operation_namespace');
  checkpoints.push(await checkpoint(ctx, newSession, scenarioId, 'fresh_trial'));
  await writeCheckpointIndex(ctx, scenarioId, checkpoints, {
    oldGenerationAfterStaleServiceSnapshot: oldGenerationAfterStale,
  });
  if (!ctx.primaryGeneration) throw new Error('probe_sc010_primary_generation_missing');
  return { environment: { envId: ctx.primaryGeneration.envId, generation: {
    generationId: ctx.primaryGeneration.generationId, participantId: ctx.primaryGeneration.participantId,
    payerAddress: ctx.primaryGeneration.payerAddress,
  } } };
}
