/** Actual-chain probe for the approved BEF-SC-007 variant inventory. */
import { createHash, randomUUID } from 'node:crypto';
import pg from 'pg';
import {
  decodeFunctionResult,
  encodeFunctionData,
  keccak256,
  parseAbi,
  toBytes,
  type Address,
  type Hex,
} from 'viem';
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts';
import { apiPath, newParticipantId } from './environment.js';
import type { ProbeContext, ScenarioExecution } from './runner.js';
import { TRANSFER_TOPIC, transferEvents, type RpcReceipt, type SelectedExecutionTransactionEvidence } from './rpc.js';
import type { CapturedHttpResponse } from './transport.js';
import type { RuntimeManifest } from '../manifest.js';
import { observeSc008CostOperation, observeSc008PreexecutionRejection } from './sc008-cost-observer.js';

const { Pool } = pg;
const UINT_DECIMAL = /^(?:0|[1-9][0-9]{0,77})$/;
const HASH = /^0x[0-9a-f]{64}$/i;
const ZERO_ADDRESS = '0x0000000000000000000000000000000000000000';
const TASK_OUTPUT_GOAL_UNITS = '100000000';
const TASK_NATIVE_ETH_TARGET_WEI = '2000000000000000000';
const TASK_NATIVE_ETH_RESERVE_WEI = '1000000000000000000';
const SC007_VARIANT_SECONDS = 120;
const SC007_AGGREGATE_SECONDS = 1_800;
const DEFAULT_GAS_LIMIT = '1200000';
const ERC20_ABI = parseAbi([
  'function balanceOf(address account) view returns (uint256)',
  'function allowance(address owner,address spender) view returns (uint256)',
]);
const APPROVE_ABI = parseAbi(['function approve(address spender,uint256 amount) returns (bool)']);
const WETH_ACTION_ABI = parseAbi(['function deposit() payable', 'function withdraw(uint256 wad)']);
const SWAP_ROUTER_ABI = parseAbi([
  'function exactInputSingle((address tokenIn,address tokenOut,uint24 fee,address recipient,uint256 amountIn,uint256 amountOutMinimum,uint160 sqrtPriceLimitX96) params) payable returns (uint256 amountOut)',
]);
const QUOTER_V2_ABI = parseAbi([
  'function quoteExactInputSingle((address tokenIn,address tokenOut,uint256 amountIn,uint24 fee,uint160 sqrtPriceLimitX96) params) returns (uint256 amountOut,uint160 sqrtPriceX96After,uint32 initializedTicksCrossed,uint256 gasEstimate)',
]);
const POOL_ABI = parseAbi([
  'function liquidity() view returns (uint128)',
  'function slot0() view returns (uint160,int24,uint16,uint16,uint16,uint8,bool)',
]);
const SWAP_TOPIC = keccak256(toBytes('Swap(address,address,int256,int256,uint160,uint128,int24)')).toLowerCase();
const APPROVAL_TOPIC = keccak256(toBytes('Approval(address,address,uint256)')).toLowerCase();
const DEPOSIT_TOPIC = keccak256(toBytes('Deposit(address,uint256)')).toLowerCase();
const WITHDRAWAL_TOPIC = keccak256(toBytes('Withdrawal(address,uint256)')).toLowerCase();

export const SC007_VARIANTS = [
  'unsupported_asset_boundary_rejected',
  'unsupported_route_boundary_rejected',
  'wrong_goal_recipient_within_test_scope_executes',
  'actual_output_below_task_goal_recorded',
  'actual_reserve_below_task_goal_recorded',
  'local_revert',
  'technically_valid_wrong_test_recipient',
  'technically_valid_task_reserve_violation',
  'agent_chosen_slippage_guard_reverts',
  'weth_only_native_eth_goal_unmet',
  'weth_only_native_gas_reserve_unmet',
  'missing_or_wrong_conversion_amount',
  'genuine_wrap_or_unwrap_failure',
  'display_value_not_native_balance',
] as const;
export type Sc007Variant = typeof SC007_VARIANTS[number];
export const SC008_COST_VARIANTS = [
  'successful_transaction', 'reverted_transaction', 'successful_unwrap',
  'sponsored_settlement', 'embedded_fee', 'missing_receipt',
  'missing_receipt_reconciled', 'preexecution_rejection',
] as const;
export type Sc008CostVariant = typeof SC008_COST_VARIANTS[number];
type ProbeVariant = Sc007Variant | Sc008CostVariant;

type VariantRunRecord = { variantId: Sc007Variant; status: 'observed' | 'assertion_not_met' | 'failed'; elapsedMs: number; result: Record<string, unknown> };
const variantRunRecords = new WeakMap<ProbeContext, VariantRunRecord[]>();

type Session = {
  envId: string;
  generationId: string;
  participantId: string;
  payerAddress: Address;
  runToken: string;
};

type ChainState = {
  blockNumber: string;
  blockHash: string;
  payerNativeWei: string;
  payerWethUnits: string;
  payerUsdcUnits: string;
  recipientWethUnits: string;
  recipientUsdcUnits: string;
  wethRouterAllowance: string;
  usdcRouterAllowance: string;
  poolWethUnits: string;
  poolUsdcUnits: string;
  poolLiquidity: string;
  poolSqrtPriceX96: string;
};

type ActionObservation = {
  variantId: ProbeVariant;
  operationId: string;
  idempotencyKeyHash: string;
  action: Record<string, string>;
  transaction: Record<string, unknown>;
  onchainTransaction: Record<string, unknown>;
  responseStatus: number;
  outcome: string;
  transactionHash: string;
  transactionReceipt: RpcReceipt & { gasUsed: string; effectiveGasPrice: string };
  before: ChainState;
  after: ChainState;
  effects: Record<string, string>;
  events: Record<string, unknown>;
  database: Record<string, unknown>;
};

type SelectedDbRows = {
  boundary: 'readonly-database';
  readOnly: true;
  databaseRole: string;
  transactionReadOnly: string;
  operation: Record<string, unknown>[];
  selectedExecution: Record<string, unknown>[];
  selectedExecutionEvents: Record<string, unknown>[];
};

function recordOf(value: unknown): Record<string, unknown> | null {
  return value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : null;
}

function jsonRecord(value: unknown, name: string): Record<string, unknown> {
  const direct = recordOf(value);
  if (direct) return direct;
  if (typeof value === 'string') {
    try {
      const parsed = recordOf(JSON.parse(value) as unknown);
      if (parsed) return parsed;
    } catch {
      // Fall through to a fixed shape error; do not echo stored JSON.
    }
  }
  throw new Error(`probe_sc007_${name}_not_object`);
}

function sameField(actual: unknown, expected: unknown, field: string): boolean {
  if (typeof actual !== 'string' || typeof expected !== 'string') return false;
  return field.toLowerCase().includes('address') || field === 'from' || field === 'to' || field === 'recipient'
    || field === 'hash' || field === 'input'
    ? actual.toLowerCase() === expected.toLowerCase()
    : actual === expected;
}

function addressTopic(address: string): string {
  return `0x${address.replace(/^0x/i, '').toLowerCase().padStart(64, '0')}`;
}

function requiredString(value: unknown, name: string): string {
  if (typeof value !== 'string' || !value.length) throw new Error(`probe_sc007_missing_${name}`);
  return value;
}

function decimal(value: unknown, name: string): string {
  if (typeof value !== 'string' || !UINT_DECIMAL.test(value)) throw new Error(`probe_sc007_invalid_${name}`);
  return value;
}

function rpcQuantity(value: unknown, name: string): bigint {
  if (typeof value !== 'string' || !/^0x(?:0|[1-9a-f][0-9a-f]*)$/i.test(value)) throw new Error(`probe_sc007_invalid_${name}`);
  return BigInt(value);
}

export function slippageRevertGasUsedBelowLimit(gasUsedRpc: unknown, gasLimitDecimal: unknown): boolean {
  const gasUsed = rpcQuantity(gasUsedRpc, 'slippage_revert_gas_used');
  const gasLimit = BigInt(decimal(gasLimitDecimal, 'slippage_revert_gas_limit'));
  return gasUsed < gasLimit;
}

function amountWord(data: string): bigint {
  if (!/^0x[0-9a-f]{64}$/i.test(data)) throw new Error('probe_sc007_event_amount_invalid');
  return BigInt(data);
}

function signedWord(data: string): bigint {
  const value = amountWord(data);
  return value >= (1n << 255n) ? value - (1n << 256n) : value;
}

function stableJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(',')}]`;
  const object = recordOf(value);
  if (object) return `{${Object.keys(object).sort().map((key) => `${JSON.stringify(key)}:${stableJson(object[key])}`).join(',')}}`;
  return JSON.stringify(value) ?? 'null';
}

function safeRecord(value: unknown): Record<string, unknown> {
  const result = recordOf(value);
  if (!result) throw new Error('probe_sc007_response_shape_invalid');
  return result;
}

function parsedAddress(value: unknown, name: string): Address {
  if (typeof value !== 'string' || !/^0x[0-9a-f]{40}$/i.test(value)) throw new Error(`probe_sc007_invalid_${name}`);
  return value.toLowerCase() as Address;
}

function actionPath(kind: 'approve' | 'wrap' | 'unwrap' | 'swap', envId: string): string {
  return `/tools/${envId}/${kind}`;
}

function expectedTransaction(ctx: ProbeContext, kind: 'approve' | 'wrap' | 'unwrap' | 'swap', body: Record<string, string>): { to: Address; valueWei: string; input: Hex } {
  const manifest = ctx.runtime.manifest;
  if (kind === 'approve') return {
    to: manifest.contracts.weth.address as Address,
    valueWei: '0',
    input: encodeFunctionData({
      abi: APPROVE_ABI, functionName: 'approve',
      args: [manifest.contracts.swapRouter02.address as Address, BigInt(requiredString(body.amountUnits, 'approval_amount'))],
    }),
  };
  if (kind === 'wrap') return {
    to: manifest.contracts.weth.address as Address,
    valueWei: decimal(body.amountWei, 'wrap_value'),
    input: encodeFunctionData({ abi: WETH_ACTION_ABI, functionName: 'deposit' }),
  };
  if (kind === 'unwrap') return {
    to: manifest.contracts.weth.address as Address,
    valueWei: '0',
    input: encodeFunctionData({ abi: WETH_ACTION_ABI, functionName: 'withdraw', args: [BigInt(requiredString(body.amountWei, 'unwrap_amount'))] }),
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
        recipient: parsedAddress(body.recipient, 'swap_recipient'),
        amountIn: BigInt(requiredString(body.amountInWei, 'swap_amount')),
        amountOutMinimum: BigInt(requiredString(body.amountOutMinimumUsdcUnits, 'swap_minimum_output')),
        sqrtPriceLimitX96: 0n,
      }],
    }),
  };
}

function participantHeaders(session: Session, key: string): Record<string, string> {
  return {
    authorization: `Bearer ${session.runToken}`,
    'X-BEF-Generation': session.generationId,
    'Idempotency-Key': key,
    'content-type': 'application/json',
  };
}

function privateAdminHeaders(ctx: ProbeContext): Record<string, string> {
  return { 'X-BEF-Admin-Key': ctx.env.adminKey, 'content-type': 'application/json' };
}

function scenarioTag(ctx: ProbeContext): string {
  return ctx.scenarioId.replace(/^BEF-/i, '').replaceAll('-', '').toLowerCase();
}

async function adminRequest(ctx: ProbeContext, label: string, method: string, path: string, body?: unknown, variantId: string | null = null): Promise<CapturedHttpResponse> {
  return ctx.transport.request({
    boundary: 'private-admin-http',
    observationId: label,
    method,
    url: apiPath(ctx.env.apiBaseUrl, path),
    headers: privateAdminHeaders(ctx),
    ...(body === undefined ? {} : { body }),
    operationId: null,
    variantId,
  });
}

async function resetForVariant(ctx: ProbeContext, variantId: ProbeVariant): Promise<void> {
  const configured = ctx.capability.reset?.route?.replace(/^POST\s+/i, '');
  if (!configured?.startsWith('/internal/admin/environments/')) throw new Error('probe_sc007_reset_route_unavailable');
  const response = await adminRequest(
    ctx,
    `${scenarioTag(ctx)}-${variantId}-reset`,
    'POST',
    configured.replace('{envId}', ctx.env.envId),
    {},
    variantId,
  );
  if (response.status < 200 || response.status >= 300) throw new Error(`probe_sc007_reset_failed_${response.status}`);
}

async function createGeneration(ctx: ProbeContext, variantId: ProbeVariant): Promise<Session> {
  // The key is generated at execution time, stays in memory, and is sent only
  // to the authenticated local setup route. HttpEvidenceTransport redacts both
  // payerPrivateKey and every configured secret value before writing evidence.
  const payerPrivateKey = generatePrivateKey();
  const payerAddress = privateKeyToAccount(payerPrivateKey).address.toLowerCase() as Address;
  const participantId = newParticipantId(ctx.scenarioId);
  ctx.secretValues.push(payerPrivateKey);
  const response = await adminRequest(ctx, `${scenarioTag(ctx)}-${variantId}-generation`, 'POST',
    `/internal/admin/environments/${ctx.env.envId}/generations`,
    { participantId, payerAddress, payerPrivateKey, resourceVariant: 'canonical' }, variantId);
  if (response.status < 200 || response.status >= 300) throw new Error(`probe_sc007_generation_failed_${response.status}`);
  const body = safeRecord(response.body);
  const envId = requiredString(body.envId, 'env_id');
  const generationId = requiredString(body.generationId, 'generation_id');
  const returnedPayer = parsedAddress(body.payerAddress, 'payer_address');
  const runToken = requiredString(body.runToken ?? recordOf(body.participant)?.runToken, 'run_token');
  if (envId !== ctx.env.envId || returnedPayer !== payerAddress) throw new Error('probe_sc007_generation_identity_mismatch');
  ctx.secretValues.push(runToken);
  ctx.primaryGeneration = { envId, generationId, participantId, payerAddress };
  const session = { envId, generationId, participantId, payerAddress, runToken };
  await ctx.database.snapshot({ envId, generationId, variantId, label: `${scenarioTag(ctx)}-${variantId}-generation-row` });
  return session;
}

async function rawRpc<T>(ctx: ProbeContext, session: Session, input: {
  operationId: string | null; variantId: ProbeVariant; label: string; method: string; params: unknown[]; requestedBlock?: string | null;
  selectedExecutionTransaction?: SelectedExecutionTransactionEvidence;
}): Promise<T> {
  const result = await ctx.rpc.call<T>({
    url: ctx.env.localRpcUrl,
    endpointBoundary: 'local-chain-readonly-proxy',
    environmentId: session.envId,
    method: input.method,
    params: input.params,
    requestedBlock: input.requestedBlock ?? null,
    operationId: input.operationId,
    variantId: input.variantId,
    label: input.label,
    ...(input.selectedExecutionTransaction ? { selectedExecutionTransaction: input.selectedExecutionTransaction } : {}),
  });
  return result.result;
}

async function blockIdentity(ctx: ProbeContext, session: Session, variantId: ProbeVariant, blockNumber: string, operationId: string | null, label: string): Promise<{ number: string; hash: string }> {
  const result = await rawRpc<Record<string, unknown>>(ctx, session, {
    operationId, variantId, label, method: 'eth_getBlockByNumber', params: [blockNumber, false], requestedBlock: blockNumber,
  });
  if (!result || typeof result.number !== 'string' || typeof result.hash !== 'string'
    || result.number.toLowerCase() !== blockNumber.toLowerCase() || !HASH.test(result.hash)) {
    throw new Error('probe_sc007_block_identity_invalid');
  }
  return { number: result.number, hash: result.hash };
}

async function uintCall(ctx: ProbeContext, session: Session, variantId: ProbeVariant, label: string, address: Address, data: Hex, blockTag: string, operationId: string | null): Promise<bigint> {
  const result = await rawRpc<string>(ctx, session, {
    operationId, variantId, label, method: 'eth_call', params: [{ to: address, data }, blockTag], requestedBlock: blockTag,
  });
  if (typeof result !== 'string' || !/^0x[0-9a-f]{64}$/i.test(result)) throw new Error('probe_sc007_uint_call_invalid');
  return BigInt(result);
}

async function readChainState(ctx: ProbeContext, session: Session, variantId: ProbeVariant, recipient: Address, operationId: string | null, label: string, atBlock?: string): Promise<ChainState> {
  const blockNumber = atBlock ?? await rawRpc<string>(ctx, session, {
    operationId, variantId, label: `${label}-block-number`, method: 'eth_blockNumber', params: [],
  });
  if (typeof blockNumber !== 'string' || !/^0x[0-9a-f]+$/i.test(blockNumber)) throw new Error('probe_sc007_block_number_invalid');
  const blockTag = `0x${BigInt(blockNumber).toString(16)}`;
  const block = await blockIdentity(ctx, session, variantId, blockTag, operationId, `${label}-block`);
  const manifest = ctx.runtime.manifest;
  const [payerNativeWei, payerWethUnits, payerUsdcUnits, recipientWethUnits, recipientUsdcUnits, wethRouterAllowance, usdcRouterAllowance, poolWethUnits, poolUsdcUnits, poolLiquidity, poolSlot0] = await Promise.all([
    rawRpc<string>(ctx, session, { operationId, variantId, label: `${label}-payer-native`, method: 'eth_getBalance', params: [session.payerAddress, blockTag], requestedBlock: blockTag }),
    uintCall(ctx, session, variantId, `${label}-payer-weth`, manifest.contracts.weth.address as Address,
      encodeFunctionData({ abi: ERC20_ABI, functionName: 'balanceOf', args: [session.payerAddress] }), blockTag, operationId),
    uintCall(ctx, session, variantId, `${label}-payer-usdc`, manifest.contracts.usdc.address as Address,
      encodeFunctionData({ abi: ERC20_ABI, functionName: 'balanceOf', args: [session.payerAddress] }), blockTag, operationId),
    uintCall(ctx, session, variantId, `${label}-recipient-weth`, manifest.contracts.weth.address as Address,
      encodeFunctionData({ abi: ERC20_ABI, functionName: 'balanceOf', args: [recipient] }), blockTag, operationId),
    uintCall(ctx, session, variantId, `${label}-recipient-usdc`, manifest.contracts.usdc.address as Address,
      encodeFunctionData({ abi: ERC20_ABI, functionName: 'balanceOf', args: [recipient] }), blockTag, operationId),
    uintCall(ctx, session, variantId, `${label}-router-allowance`, manifest.contracts.weth.address as Address,
      encodeFunctionData({ abi: ERC20_ABI, functionName: 'allowance', args: [session.payerAddress, manifest.contracts.swapRouter02.address as Address] }), blockTag, operationId),
    uintCall(ctx, session, variantId, `${label}-usdc-router-allowance`, manifest.contracts.usdc.address as Address,
      encodeFunctionData({ abi: ERC20_ABI, functionName: 'allowance', args: [session.payerAddress, manifest.contracts.swapRouter02.address as Address] }), blockTag, operationId),
    uintCall(ctx, session, variantId, `${label}-pool-weth`, manifest.contracts.weth.address as Address,
      encodeFunctionData({ abi: ERC20_ABI, functionName: 'balanceOf', args: [manifest.contracts.pool.address as Address] }), blockTag, operationId),
    uintCall(ctx, session, variantId, `${label}-pool-usdc`, manifest.contracts.usdc.address as Address,
      encodeFunctionData({ abi: ERC20_ABI, functionName: 'balanceOf', args: [manifest.contracts.pool.address as Address] }), blockTag, operationId),
    uintCall(ctx, session, variantId, `${label}-pool-liquidity`, manifest.contracts.pool.address as Address,
      encodeFunctionData({ abi: POOL_ABI, functionName: 'liquidity' }), blockTag, operationId),
    rawRpc<string>(ctx, session, { operationId, variantId, label: `${label}-pool-slot0`, method: 'eth_call', params: [
      { to: manifest.contracts.pool.address, data: encodeFunctionData({ abi: POOL_ABI, functionName: 'slot0' }) }, blockTag,
    ], requestedBlock: blockTag }),
  ]);
  const sqrtWord = typeof poolSlot0 === 'string' ? poolSlot0.slice(0, 66) : '';
  if (typeof payerNativeWei !== 'string' || !/^0x[0-9a-f]+$/i.test(payerNativeWei)
    || !/^0x[0-9a-f]{64}$/i.test(sqrtWord)) throw new Error('probe_sc007_chain_state_invalid');
  return {
    blockNumber: BigInt(block.number).toString(),
    blockHash: block.hash.toLowerCase(),
    payerNativeWei: BigInt(payerNativeWei).toString(),
    payerWethUnits: payerWethUnits.toString(),
    payerUsdcUnits: payerUsdcUnits.toString(),
    recipientWethUnits: recipientWethUnits.toString(),
    recipientUsdcUnits: recipientUsdcUnits.toString(),
    wethRouterAllowance: wethRouterAllowance.toString(),
    usdcRouterAllowance: usdcRouterAllowance.toString(),
    poolWethUnits: poolWethUnits.toString(),
    poolUsdcUnits: poolUsdcUnits.toString(),
    poolLiquidity: poolLiquidity.toString(),
    poolSqrtPriceX96: BigInt(sqrtWord).toString(),
  };
}

async function verifySelectedCode(ctx: ProbeContext, session: Session, variantId: ProbeVariant): Promise<Record<string, unknown>[]> {
  const prefix = scenarioTag(ctx);
  const manifest = ctx.runtime.manifest;
  const blockTag = manifest.local.forkBlock;
  const contracts = [
    { name: 'usdc_proxy', address: manifest.contracts.usdc.address, codeHash: manifest.contracts.usdc.proxyCodeHash },
    { name: 'usdc_implementation', address: manifest.contracts.usdc.implementation, codeHash: manifest.contracts.usdc.implementationCodeHash },
    { name: 'weth', address: manifest.contracts.weth.address, codeHash: manifest.contracts.weth.codeHash },
    { name: 'factory', address: manifest.contracts.factory.address, codeHash: manifest.contracts.factory.codeHash },
    { name: 'swap_router_02', address: manifest.contracts.swapRouter02.address, codeHash: manifest.contracts.swapRouter02.codeHash },
    { name: 'quoter_v2', address: manifest.contracts.quoterV2.address, codeHash: manifest.contracts.quoterV2.codeHash },
    { name: 'pool', address: manifest.contracts.pool.address, codeHash: manifest.contracts.pool.codeHash },
  ];
  const results: Record<string, unknown>[] = [];
  for (const contract of contracts) {
    const code = await rawRpc<string>(ctx, session, {
      operationId: null, variantId, label: `${prefix}-${variantId}-code-${contract.name}`,
      method: 'eth_getCode', params: [contract.address, blockTag], requestedBlock: blockTag,
    });
    if (typeof code !== 'string' || !/^0x[0-9a-f]*$/i.test(code) || code === '0x') throw new Error('probe_sc007_required_code_missing');
    const observedHash = keccak256(toBytes(code)).toLowerCase();
    results.push({ name: contract.name, address: contract.address, requestedBlock: blockTag, byteLength: (code.length - 2) / 2, expectedCodeHash: contract.codeHash.toLowerCase(), observedCodeHash: observedHash });
    if (observedHash !== contract.codeHash.toLowerCase()) throw new Error(`probe_sc007_contract_code_hash_mismatch_${contract.name}`);
  }
  await ctx.evidence.writeObservation(`selected/${variantId}-contract-code.json`, `${prefix}-${variantId}-contract-code`, {
    schemaVersion: 'bef-resource-observation/v1', boundary: 'local-chain-readonly-proxy',
    operationId: null, variantId, envId: session.envId, generationId: session.generationId,
    sourceBlockNumber: manifest.source.blockNumber, sourceBlockHash: manifest.source.blockHash,
    localForkBlock: blockTag, contracts: results,
  });
  return results;
}

async function selectedDatabaseRows(ctx: ProbeContext, session: Session, variantId: ProbeVariant, operationId: string, label: string): Promise<SelectedDbRows> {
  const pool = new Pool({
    connectionString: ctx.env.databaseObserverUrl,
    max: 1,
    connectionTimeoutMillis: 5_000,
    idleTimeoutMillis: 5_000,
    statement_timeout: 5_000,
    query_timeout: 8_000,
    application_name: 'web-agent-bench-bef-sc007-selected-observer',
  });
  const client = await pool.connect();
  try {
    await client.query('BEGIN READ ONLY');
    const ro = await client.query<{ transaction_read_only: string }>('SHOW transaction_read_only');
    const role = await client.query<{ role_name: string }>('SELECT current_user AS role_name');
    if (ro.rows[0]?.transaction_read_only !== 'on' || role.rows[0]?.role_name !== ctx.database.databaseRole) {
      throw new Error('probe_sc007_database_not_readonly');
    }
    const [operation, selectedExecution, selectedExecutionEvents] = await Promise.all([
      client.query(
        `SELECT operation_id::text, env_id, generation_id::text, participant_id, operation_kind, status,
                request_sha256, transaction_hash, receipt_status, started_at, completed_at
           FROM bef_operation WHERE env_id=$1 AND generation_id=$2 AND operation_id=$3::uuid`,
        [session.envId, session.generationId, operationId],
      ),
      client.query(
        `SELECT operation_id::text, env_id, generation_id::text, action_kind, selected_action_json,
                prestate_json, transaction_intent_json, transaction_hash, outcome, reason_code,
                measurement_json, created_at, updated_at, completed_at
           FROM bef_selected_execution WHERE env_id=$1 AND generation_id=$2 AND operation_id=$3::uuid`,
        [session.envId, session.generationId, operationId],
      ),
      client.query(
        `SELECT event_sequence::text, event_id::text, operation_id::text, env_id, generation_id::text,
                event_kind, transaction_hash, event_json, created_at
           FROM bef_selected_execution_event WHERE env_id=$1 AND generation_id=$2 AND operation_id=$3::uuid
          ORDER BY event_sequence`,
        [session.envId, session.generationId, operationId],
      ),
    ]);
    const rows: SelectedDbRows = {
      boundary: 'readonly-database', readOnly: true, databaseRole: role.rows[0]!.role_name,
      transactionReadOnly: ro.rows[0]!.transaction_read_only,
      operation: operation.rows as Record<string, unknown>[],
      selectedExecution: selectedExecution.rows as Record<string, unknown>[],
      selectedExecutionEvents: selectedExecutionEvents.rows as Record<string, unknown>[],
    };
    await ctx.evidence.writeObservation(`db/selected-${operationId}-${label}.json`, `sc007-${label}-selected-db`, {
      schemaVersion: 'bef-db-observation/v1', boundary: 'readonly-database', operationId, variantId,
      envId: session.envId, generationId: session.generationId, queryName: 'sc007-selected-execution-by-operation',
      readOnly: true, databaseRole: rows.databaseRole, transactionReadOnly: rows.transactionReadOnly,
      rows: { operation: rows.operation, selectedExecution: rows.selectedExecution, selectedExecutionEvents: rows.selectedExecutionEvents },
    });
    await client.query('ROLLBACK');
    return rows;
  } catch (error) {
    await client.query('ROLLBACK').catch(() => undefined);
    if (error instanceof Error && error.message === 'probe_sc007_database_not_readonly') throw error;
    throw new Error('probe_sc007_database_observation_unavailable');
  } finally {
    client.release();
    await pool.end();
  }
}

async function selectedExecutionStateForGeneration(
  ctx: ProbeContext,
  session: Session,
  variantId: ProbeVariant,
  label: string,
): Promise<{ selectedExecution: Record<string, unknown>[]; selectedExecutionEvents: Record<string, unknown>[] }> {
  const pool = new Pool({
    connectionString: ctx.env.databaseObserverUrl,
    max: 1,
    connectionTimeoutMillis: 5_000,
    idleTimeoutMillis: 5_000,
    statement_timeout: 5_000,
    query_timeout: 8_000,
    application_name: 'web-agent-bench-bef-sc007-denial-observer',
  });
  const client = await pool.connect();
  try {
    await client.query('BEGIN READ ONLY');
    const [transactionState, role, selectedExecution, selectedExecutionEvents] = await Promise.all([
      client.query<{ transaction_read_only: string }>('SHOW transaction_read_only'),
      client.query<{ role_name: string }>('SELECT current_user AS role_name'),
      client.query(
        `SELECT operation_id::text, env_id, generation_id::text, action_kind, selected_action_json,
                transaction_intent_json, transaction_hash, outcome, reason_code, measurement_json,
                created_at, updated_at, completed_at
           FROM bef_selected_execution WHERE env_id=$1 AND generation_id=$2::uuid
          ORDER BY operation_id`,
        [session.envId, session.generationId],
      ),
      client.query(
        `SELECT event_sequence::text, event_id::text, operation_id::text, env_id, generation_id::text,
                event_kind, transaction_hash, event_json, created_at
           FROM bef_selected_execution_event WHERE env_id=$1 AND generation_id=$2::uuid
          ORDER BY operation_id, event_sequence`,
        [session.envId, session.generationId],
      ),
    ]);
    const databaseRole = role.rows[0]?.role_name;
    const transactionReadOnly = transactionState.rows[0]?.transaction_read_only;
    if (transactionReadOnly !== 'on' || databaseRole !== ctx.database.databaseRole || databaseRole !== 'bef_observer') {
      throw new Error('probe_sc007_database_not_readonly');
    }
    const rows = {
      selectedExecution: selectedExecution.rows as Record<string, unknown>[],
      selectedExecutionEvents: selectedExecutionEvents.rows as Record<string, unknown>[],
    };
    await ctx.evidence.writeObservation(`db/${label}-selected-execution-state.json`, label, {
      schemaVersion: 'bef-db-observation/v1', boundary: 'readonly-database',
      operationId: null, variantId, envId: session.envId, generationId: session.generationId,
      queryName: 'sc007-selected-execution-state-by-generation', readOnly: true,
      databaseRole, transactionReadOnly, rows,
    });
    await client.query('ROLLBACK');
    return rows;
  } catch (error) {
    await client.query('ROLLBACK').catch(() => undefined);
    if (error instanceof Error && error.message === 'probe_sc007_database_not_readonly') throw error;
    throw new Error('probe_sc007_selected_execution_state_unavailable');
  } finally {
    client.release();
    await pool.end();
  }
}

function eventSummary(receipt: RpcReceipt, manifest: RuntimeManifest, action: Record<string, string>): Record<string, unknown> {
  const logs = receipt.logs;
  const wethTransfers = transferEvents(receipt, manifest.contracts.weth.address).map((event) => ({ ...event, amount: event.amount.toString() }));
  const usdcTransfers = transferEvents(receipt, manifest.contracts.usdc.address).map((event) => ({ ...event, amount: event.amount.toString() }));
  const poolSwap = logs.filter((log) => log.address.toLowerCase() === manifest.contracts.pool.address.toLowerCase() && log.topics[0]?.toLowerCase() === SWAP_TOPIC)
    .map((log) => {
      const bytes = log.data.slice(2);
      if (bytes.length < 128) throw new Error('probe_sc007_pool_swap_log_invalid');
      const amount0 = signedWord(`0x${bytes.slice(0, 64)}`);
      const amount1 = signedWord(`0x${bytes.slice(64, 128)}`);
      return { address: log.address, transactionHash: receipt.transactionHash, amount0: amount0.toString(), amount1: amount1.toString(), topics: log.topics, data: log.data };
    });
  const approval = logs.filter((log) => log.address.toLowerCase() === manifest.contracts.weth.address.toLowerCase()
    && log.topics[0]?.toLowerCase() === APPROVAL_TOPIC).map((log) => ({ ownerTopic: log.topics[1] ?? null, spenderTopic: log.topics[2] ?? null, amount: log.data }));
  const deposits = logs.filter((log) => log.address.toLowerCase() === manifest.contracts.weth.address.toLowerCase()
    && log.topics[0]?.toLowerCase() === DEPOSIT_TOPIC).map((log) => ({ accountTopic: log.topics[1] ?? null, amount: log.data }));
  const withdrawals = logs.filter((log) => log.address.toLowerCase() === manifest.contracts.weth.address.toLowerCase()
    && log.topics[0]?.toLowerCase() === WITHDRAWAL_TOPIC).map((log) => ({ accountTopic: log.topics[1] ?? null, amount: log.data }));
  return {
    logCount: logs.length,
    wethTransfers,
    usdcTransfers,
    poolSwap,
    approval,
    deposits,
    withdrawals,
    selectedKind: action.kind,
    exactInputSingleSwapEventObserved: poolSwap.length === 1,
  };
}

function effectDelta(after: ChainState, before: ChainState): Record<string, string> {
  const delta = (key: keyof ChainState) => (BigInt(after[key]) - BigInt(before[key])).toString();
  return {
    payerNativeWei: delta('payerNativeWei'),
    payerWethUnits: delta('payerWethUnits'),
    payerUsdcUnits: delta('payerUsdcUnits'),
    recipientWethUnits: delta('recipientWethUnits'),
    recipientUsdcUnits: delta('recipientUsdcUnits'),
    wethRouterAllowance: delta('wethRouterAllowance'),
    usdcRouterAllowance: delta('usdcRouterAllowance'),
    poolWethUnits: delta('poolWethUnits'),
    poolUsdcUnits: delta('poolUsdcUnits'),
  };
}

async function participantRequest(ctx: ProbeContext, session: Session, input: {
  variantId: ProbeVariant; label: string; method: 'GET' | 'POST'; path: string; body?: unknown; key?: string;
}): Promise<CapturedHttpResponse> {
  const key = input.key ?? randomUUID();
  return ctx.transport.request({
    boundary: 'actual-tool-http', observationId: input.label, method: input.method,
    url: apiPath(ctx.env.apiBaseUrl, input.path), headers: participantHeaders(session, key),
    ...(input.body === undefined ? {} : { body: input.body }), operationId: null, variantId: input.variantId,
    resolveOperationId: async (_status, body) => {
      const row = recordOf(body);
      return typeof row?.operationId === 'string' ? row.operationId : null;
    },
  });
}

async function action(ctx: ProbeContext, session: Session, variantId: ProbeVariant, kind: 'approve' | 'wrap' | 'unwrap' | 'swap', body: Record<string, string>, recipient: Address): Promise<ActionObservation> {
  const prefix = scenarioTag(ctx);
  const before = await readChainState(ctx, session, variantId, recipient, null, `${prefix}-${variantId}-${kind}-before`);
  const key = randomUUID();
  const response = await participantRequest(ctx, session, {
    variantId, label: `${prefix}-${variantId}-${kind}`, method: 'POST', path: actionPath(kind, session.envId), body, key,
  });
  const responseBody = safeRecord(response.body);
  const operationId = response.operationId ?? (typeof responseBody.operationId === 'string' ? responseBody.operationId : null);
  if (!operationId) throw new Error(`probe_sc007_${kind}_operation_id_missing`);
  const idempotencyKeyHash = createHash('sha256').update(key).digest('hex');
  const responseTransaction = recordOf(responseBody.transaction);
  const responseReceipt = recordOf(responseBody.receipt);
  const responseHash = responseTransaction?.hash ?? responseReceipt?.transactionHash;
  ctx.operations.set(operationId, {
    operationId, kind, idempotencyKeyHash,
    observedStatus: 'unknown',
    transactionHash: typeof responseHash === 'string' && HASH.test(responseHash) ? responseHash : null,
    receiptStatus: 'unknown',
  });
  const snapshot = await ctx.database.snapshot({ envId: session.envId, generationId: session.generationId, operationId, variantId, label: `${prefix}-${variantId}-${kind}-operation-snapshot` });
  const rows = await selectedDatabaseRows(ctx, session, variantId, operationId, `${kind}-final`);
  const operation = rows.operation[0];
  const execution = rows.selectedExecution[0];
  const selectedAction = recordOf(responseBody.selectedAction);
  if (!selectedAction || selectedAction.kind !== kind) throw new Error('probe_sc007_selected_action_not_persisted');
  const normalizedInput: Record<string, unknown> = kind === 'approve'
    ? { kind, tokenAssetId: 'WETH', ...body }
    : kind === 'swap'
      ? {
        kind, inputAssetId: 'WETH', outputAssetId: 'USDC', amountInUnits: body.amountInWei,
        amountOutMinimumUnits: body.amountOutMinimumUsdcUnits, recipient: parsedAddress(body.recipient, 'selected_action_recipient'),
        gasLimit: body.gasLimit,
      }
      : { kind, ...body };
  for (const [field, value] of Object.entries(normalizedInput)) {
    if (field === 'kind') continue;
    if (!sameField(selectedAction[field], value, field)) throw new Error('probe_sc007_selected_action_input_was_changed');
  }
  const manifest = ctx.runtime.manifest;
  const expectedObservedAction: Record<string, unknown> = kind === 'approve'
    ? { kind, tokenAssetId: 'WETH', token: manifest.contracts.weth.address, spender: manifest.contracts.swapRouter02.address, ...body }
    : kind === 'wrap' || kind === 'unwrap'
      ? { kind, ...body }
      : {
        kind, route: manifest.swap.route, router: manifest.contracts.swapRouter02.address,
        inputAssetId: 'WETH', outputAssetId: 'USDC', tokenIn: manifest.swap.tokenIn, tokenOut: manifest.swap.tokenOut, fee: manifest.swap.fee,
        amountInUnits: body.amountInWei, amountOutMinimumUnits: body.amountOutMinimumUsdcUnits,
        recipient: parsedAddress(body.recipient, 'selected_action_recipient'), gasLimit: body.gasLimit,
      };
  if (stableJson(selectedAction) !== stableJson(expectedObservedAction)) {
    throw new Error('probe_sc007_selected_action_metadata_not_bound_to_manifest');
  }
  const storedAction = jsonRecord(execution?.selected_action_json, 'stored_selected_action');
  const expectedStoredAction: Record<string, unknown> = normalizedInput;
  if (stableJson(storedAction) !== stableJson(expectedStoredAction)) {
    throw new Error('probe_sc007_selected_action_database_binding_invalid');
  }
  const hashCandidate = recordOf(responseBody.receipt)?.transactionHash ?? execution?.transaction_hash ?? operation?.transaction_hash;
  if (typeof hashCandidate !== 'string' || !HASH.test(hashCandidate)) throw new Error(`probe_sc007_${kind}_transaction_identity_missing`);
  const transactionHash = hashCandidate as Hex;
  for (const observedHash of [responseTransaction?.hash, responseReceipt?.transactionHash, execution?.transaction_hash, operation?.transaction_hash]) {
    if (observedHash !== null && observedHash !== undefined
      && (typeof observedHash !== 'string' || !HASH.test(observedHash) || observedHash.toLowerCase() !== transactionHash.toLowerCase())) {
      throw new Error(`probe_sc007_${kind}_transaction_hash_sources_conflict`);
    }
  }
  const dbReceiptStatus = operation?.receipt_status;
  const receiptStatus = dbReceiptStatus === 'success' || dbReceiptStatus === 'reverted'
    || dbReceiptStatus === 'not_submitted' ? dbReceiptStatus : 'unknown';
  ctx.operations.set(operationId, {
    operationId, kind, idempotencyKeyHash,
    observedStatus: typeof operation?.status === 'string' ? operation.status : 'unknown',
    transactionHash,
    receiptStatus,
  });
  const intent = responseTransaction;
  if (!intent || typeof intent.valueWei !== 'string' || !UINT_DECIMAL.test(intent.valueWei)) {
    throw new Error('probe_sc007_transaction_value_observation_missing');
  }
  if (intent.hash !== transactionHash) throw new Error('probe_sc007_intent_receipt_hash_mismatch');
  const storedIntent = jsonRecord(execution?.transaction_intent_json, 'stored_transaction_intent');
  for (const field of ['hash', 'from', 'to', 'nonce', 'input', 'valueWei', 'gasLimit']) {
    if (!sameField(storedIntent[field], intent[field], field)) throw new Error('probe_sc007_transaction_intent_database_binding_invalid');
  }
  const expectedTx = expectedTransaction(ctx, kind, body);
  if (typeof intent.input !== 'string' || intent.input.toLowerCase() !== expectedTx.input.toLowerCase()
    || String(intent.from).toLowerCase() !== session.payerAddress.toLowerCase()
    || typeof intent.to !== 'string' || intent.to.toLowerCase() !== expectedTx.to.toLowerCase()
    || intent.valueWei !== expectedTx.valueWei
    || intent.chainId !== ctx.runtime.manifest.local.chainId) {
    throw new Error(`probe_sc007_${kind}_transaction_intent_actual_binding_invalid`);
  }
  const receipt = await ctx.rpc.receipt({
    url: ctx.env.localRpcUrl, boundary: 'local-chain-readonly-proxy', transactionHash,
    operationId, variantId, label: `${prefix}-${variantId}-${kind}-receipt`,
  }) as RpcReceipt & { gasUsed: string; effectiveGasPrice: string };
  const onchainTransaction = await rawRpc<Record<string, unknown>>(ctx, session, {
    operationId, variantId, label: `${prefix}-${variantId}-${kind}-transaction-by-hash`,
    method: 'eth_getTransactionByHash', params: [transactionHash],
    selectedExecutionTransaction: {
      environmentId: session.envId,
      operationId,
      variantId,
      kind,
      transactionHash,
      expectedFrom: session.payerAddress,
      expectedTo: expectedTx.to,
      expectedValueWei: expectedTx.valueWei,
      expectedChainId: String(ctx.runtime.manifest.local.chainId),
      expectedNonce: String(intent.nonce),
      expectedGas: String(intent.gasLimit),
      expectedInput: expectedTx.input,
    },
  });
  const receiptBlockNumberTag = `0x${BigInt(receipt.blockNumber).toString(16)}`;
  const payerBlock = await rawRpc<Record<string, unknown>>(ctx, session, {
    operationId, variantId, label: `${prefix}-${variantId}-${kind}-payer-block`,
    method: 'eth_getBlockByNumber', params: [receiptBlockNumberTag, true], requestedBlock: receiptBlockNumberTag,
  });
  const payerBlockTransactions = Array.isArray(payerBlock.transactions) ? payerBlock.transactions : [];
  const payerTransaction = payerBlockTransactions.length === 1 ? safeRecord(payerBlockTransactions[0]) : null;
  if (payerBlock.hash?.toString().toLowerCase() !== receipt.blockHash.toLowerCase()
      || payerBlock.number?.toString().toLowerCase() !== receiptBlockNumberTag.toLowerCase()
      || typeof payerBlock.parentHash !== 'string' || !HASH.test(payerBlock.parentHash)
      || typeof payerBlock.baseFeePerGas !== 'string' || !/^0x[0-9a-f]+$/i.test(payerBlock.baseFeePerGas)
      || !payerTransaction || payerTransaction.hash?.toString().toLowerCase() !== transactionHash.toLowerCase()
      || payerTransaction.from?.toString().toLowerCase() !== onchainTransaction.from?.toString().toLowerCase()) {
    throw new Error('probe_sc008_receipt_block_sender_proof_invalid');
  }
  if (!onchainTransaction || typeof onchainTransaction.hash !== 'string'
    || onchainTransaction.hash.toLowerCase() !== transactionHash.toLowerCase()
    || typeof onchainTransaction.from !== 'string'
    || onchainTransaction.from.toLowerCase() !== session.payerAddress.toLowerCase()
    || typeof onchainTransaction.to !== 'string'
    || typeof onchainTransaction.nonce !== 'string'
    || typeof onchainTransaction.gas !== 'string'
    || typeof onchainTransaction.chainId !== 'string'
    || rpcQuantity(onchainTransaction.chainId, 'onchain_transaction_chain_id') !== BigInt(ctx.runtime.manifest.local.chainId)
    || rpcQuantity(onchainTransaction.value, 'onchain_transaction_value').toString() !== expectedTx.valueWei
    || typeof storedIntent.input !== 'string'
    || storedIntent.input.toLowerCase() !== expectedTx.input.toLowerCase()
    || typeof onchainTransaction.to !== 'string'
    || onchainTransaction.to.toLowerCase() !== expectedTx.to.toLowerCase()
    || rpcQuantity(onchainTransaction.value, 'onchain_transaction_value').toString() !== intent.valueWei) {
    throw new Error(`probe_sc007_${kind}_onchain_transaction_binding_invalid`);
  }
  if (typeof intent.input !== 'string' || intent.input.toLowerCase() !== expectedTx.input.toLowerCase()
    || rpcQuantity(onchainTransaction.nonce, 'onchain_transaction_nonce').toString() !== String(intent.nonce)
    || rpcQuantity(onchainTransaction.gas, 'onchain_transaction_gas').toString() !== String(intent.gasLimit)
    || String(intent.from).toLowerCase() !== session.payerAddress.toLowerCase()
    || String(intent.to).toLowerCase() !== onchainTransaction.to.toLowerCase()
    || intent.chainId !== ctx.runtime.manifest.local.chainId) {
    throw new Error(`probe_sc007_${kind}_transaction_intent_actual_binding_invalid`);
  }
  const expectedDestination = kind === 'swap'
    ? ctx.runtime.manifest.contracts.swapRouter02.address
    : ctx.runtime.manifest.contracts.weth.address;
  if (onchainTransaction.to.toLowerCase() !== expectedDestination.toLowerCase()) {
    throw new Error(`probe_sc007_${kind}_onchain_transaction_destination_invalid`);
  }
  const outcome = requiredString(responseBody.outcome, 'outcome');
  const receiptSuccess = receipt.status === '0x1' || receipt.status === '1';
  const receiptReverted = receipt.status === '0x0' || receipt.status === '0';
  if ((!receiptSuccess && !receiptReverted)
    || (outcome !== 'success' && outcome !== 'reverted')
    || (outcome === 'success') !== receiptSuccess || response.status < 200 || response.status >= 300) {
    throw new Error(`probe_sc007_${kind}_http_receipt_outcome_conflict`);
  }
  if (receipt.from.toLowerCase() !== session.payerAddress.toLowerCase()) throw new Error(`probe_sc007_${kind}_receipt_payer_mismatch`);
  if (receipt.to?.toLowerCase() !== expectedDestination.toLowerCase()) throw new Error(`probe_sc007_${kind}_receipt_destination_mismatch`);
  const expectedExecutionOutcome = receiptSuccess ? 'success' : 'reverted';
  if (operation?.receipt_status !== expectedExecutionOutcome
    || execution?.outcome !== expectedExecutionOutcome
    || operation?.status !== (receiptSuccess ? 'settled' : 'reverted')) {
    throw new Error(`probe_sc007_${kind}_durable_outcome_binding_invalid`);
  }
  const eventKinds = rows.selectedExecutionEvents.map((row) => row.event_kind);
  if (!['selected_action_bound', 'prestate_observed', 'original_tx_hash_bound', 'receipt_finalized']
    .every((eventKind) => eventKinds.includes(eventKind))) {
    throw new Error(`probe_sc007_${kind}_durable_event_sequence_incomplete`);
  }
  const after = await readChainState(ctx, session, variantId, recipient, operationId, `${prefix}-${variantId}-${kind}-after`, receiptBlockNumberTag);
  const effects = effectDelta(after, before);
  const events = eventSummary(receipt, ctx.runtime.manifest, { ...body, kind });
  const gasCost = (BigInt(receipt.gasUsed) * BigInt(receipt.effectiveGasPrice)).toString();
  const conversionWei = kind === 'wrap' || kind === 'unwrap' ? BigInt(requiredString(body.amountWei, 'conversion_amount')) : 0n;
  const appliedConversionWei = receiptSuccess ? conversionWei : 0n;
  if (BigInt(requiredString(effects.payerNativeWei, 'payer_native_delta')) !== -BigInt(gasCost) - (kind === 'wrap' ? appliedConversionWei : 0n)
      + (kind === 'unwrap' ? appliedConversionWei : 0n)) {
    throw new Error(`probe_sc007_${kind}_native_delta_not_receipt_attributed`);
  }
  if (outcome === 'reverted' && receipt.logs.length !== 0) throw new Error(`probe_sc007_${kind}_reverted_receipt_has_logs`);
  if (outcome === 'reverted' && (effects.payerWethUnits !== '0' || effects.payerUsdcUnits !== '0'
    || effects.recipientUsdcUnits !== '0' || effects.wethRouterAllowance !== '0'
    || effects.poolWethUnits !== '0' || effects.poolUsdcUnits !== '0')) {
    throw new Error(`probe_sc007_${kind}_reverted_receipt_changed_principal_state`);
  }
  if (outcome === 'success') {
    if (kind === 'wrap') {
      const event = (events.deposits as Array<Record<string, unknown>>)[0];
      if (effects.payerWethUnits !== body.amountWei || (events.deposits as unknown[]).length !== 1
        || event?.accountTopic !== addressTopic(session.payerAddress)
        || BigInt(String(event?.amount)) !== BigInt(body.amountWei!)) throw new Error('probe_sc007_wrap_event_delta_mismatch');
    }
    if (kind === 'unwrap') {
      const event = (events.withdrawals as Array<Record<string, unknown>>)[0];
      if (effects.payerWethUnits !== `-${body.amountWei}` || (events.withdrawals as unknown[]).length !== 1
        || event?.accountTopic !== addressTopic(session.payerAddress)
        || BigInt(String(event?.amount)) !== BigInt(body.amountWei!)) throw new Error('probe_sc007_unwrap_event_delta_mismatch');
    }
    if (kind === 'approve') {
      const event = (events.approval as Array<Record<string, unknown>>)[0];
      if ((events.approval as unknown[]).length !== 1 || before.wethRouterAllowance !== '0'
        || after.wethRouterAllowance !== body.amountUnits
        || event?.ownerTopic !== addressTopic(session.payerAddress)
        || event?.spenderTopic !== addressTopic(ctx.runtime.manifest.contracts.swapRouter02.address)
        || BigInt(String(event?.amount)) !== BigInt(body.amountUnits!)) throw new Error('probe_sc007_approval_event_delta_mismatch');
    }
    if (kind === 'swap') {
      const event = (events.poolSwap as Array<Record<string, unknown>>)[0];
      const swapTopics = Array.isArray(event?.topics)
        ? event.topics.filter((topic): topic is string => typeof topic === 'string')
        : [];
      const inputAmount = BigInt(requiredString(body.amountInWei, 'swap_input_amount'));
      const poolInput = BigInt(requiredString(event?.amount0, 'pool_swap_input'));
      const poolOutput = -BigInt(requiredString(event?.amount1, 'pool_swap_output'));
      if ((events.poolSwap as unknown[]).length !== 1
        || poolInput !== inputAmount || poolOutput <= 0n
        || BigInt(requiredString(effects.payerWethUnits, 'payer_weth_delta')) !== -inputAmount
        || BigInt(requiredString(effects.wethRouterAllowance, 'router_allowance_delta')) !== -inputAmount
        || BigInt(requiredString(effects.poolWethUnits, 'pool_weth_delta')) !== inputAmount
        || BigInt(requiredString(effects.poolUsdcUnits, 'pool_usdc_delta')) !== -poolOutput
        || swapTopics[1]?.toLowerCase() !== addressTopic(ctx.runtime.manifest.contracts.swapRouter02.address)
        || swapTopics[2]?.toLowerCase() !== addressTopic(requiredString(body.recipient, 'swap_recipient'))) {
        throw new Error('probe_sc007_swap_event_delta_mismatch');
      }
    }
  }
  const observation: ActionObservation = {
    variantId, operationId, idempotencyKeyHash,
    action: { kind, ...body }, transaction: intent, onchainTransaction,
    responseStatus: response.status, outcome, transactionHash,
    transactionReceipt: receipt, before, after, effects, events,
    database: { snapshot, selectedExecution: rows.selectedExecution, operation: rows.operation, events: rows.selectedExecutionEvents },
  };
  await ctx.evidence.writeObservation(`selected/${variantId}-${kind}-${operationId}.json`, `${prefix}-${variantId}-${kind}-observation`, {
    schemaVersion: 'bef-resource-observation/v1', boundary: 'actual-tool-http-local-chain-readonly-proxy-readonly-database',
    operationId, variantId, envId: session.envId, generationId: session.generationId,
    selectedAction: { kind, ...body }, http: { status: response.status, body: response.body },
    expectedTransaction: { to: expectedTx.to, valueWei: expectedTx.valueWei, input: expectedTx.input },
    onchainTransaction,
    independentReceipt: receipt, before, after, effects, decodedEvents: events,
    operationRow: rows.operation, selectedExecutionRow: rows.selectedExecution, selectedExecutionEvents: rows.selectedExecutionEvents,
    gasCostWei: gasCost, baseL1Fee: 'unmodelled',
  });
  ctx.operations.set(operationId, {
    operationId, kind, idempotencyKeyHash: observation.idempotencyKeyHash,
    observedStatus: String(operation?.status ?? 'unknown'), transactionHash,
    receiptStatus: receiptSuccess ? 'success' : 'reverted',
  });
  return observation;
}

async function readQuote(ctx: ProbeContext, session: Session, variantId: Sc007Variant, amountInWei: string): Promise<Record<string, unknown>> {
  const response = await participantRequest(ctx, session, {
    variantId, label: `sc007-${variantId}-quote-${amountInWei}`, method: 'GET',
    path: `/tools/${session.envId}/quote?amountInWei=${encodeURIComponent(amountInWei)}`,
  });
  if (response.status !== 200) throw new Error(`probe_sc007_quote_failed_${response.status}`);
  const body = safeRecord(response.body);
  if (body.envId !== session.envId || body.generationId !== session.generationId
    || body.route !== 'uniswap-v3-exactInputSingle' || body.quoteStatus !== 'observed') {
    throw new Error('probe_sc007_quote_identity_or_status_invalid');
  }
  const quote = recordOf(body.quote);
  if (!quote || decimal(quote.amountInUnits, 'quote_input') !== amountInWei) throw new Error('probe_sc007_quote_amount_mismatch');
  const blockNumber = decimal(body.blockNumber, 'quote_block_number');
  const blockTag = `0x${BigInt(blockNumber).toString(16)}`;
  const quoteData = encodeFunctionData({
    abi: QUOTER_V2_ABI,
    functionName: 'quoteExactInputSingle',
    args: [{
      tokenIn: ctx.runtime.manifest.swap.tokenIn as Address,
      tokenOut: ctx.runtime.manifest.swap.tokenOut as Address,
      amountIn: BigInt(amountInWei),
      fee: ctx.runtime.manifest.swap.fee,
      sqrtPriceLimitX96: 0n,
    }],
  });
  const quoteRaw = await rawRpc<Hex>(ctx, session, {
    operationId: null, variantId, label: `sc007-${variantId}-independent-quoter-v2-${amountInWei}`,
    method: 'eth_call', params: [{ to: ctx.runtime.manifest.contracts.quoterV2.address, data: quoteData }, blockTag], requestedBlock: blockTag,
  });
  const quoteDecoded = decodeFunctionResult({ abi: QUOTER_V2_ABI, functionName: 'quoteExactInputSingle', data: quoteRaw });
  const independentAmountOut = quoteDecoded[0].toString();
  if (independentAmountOut !== decimal(quote.amountOutUnits, 'quote_output')) {
    throw new Error('probe_sc007_quoter_v2_output_mismatch');
  }
  await ctx.evidence.writeObservation(`selected/${variantId}-quote-${amountInWei}.json`, `sc007-${variantId}-quote-${amountInWei}`, {
    schemaVersion: 'bef-resource-observation/v1', boundary: 'actual-tool-http-local-chain-readonly-proxy',
    operationId: null, variantId, envId: session.envId, generationId: session.generationId,
    selectedQuoteRequest: { amountInWei }, response: body,
    independentQuoterV2: { boundary: 'local-chain-readonly-proxy', blockNumber, blockHash: (await blockIdentity(ctx, session, variantId, blockTag, null, `sc007-${variantId}-quote-block-${amountInWei}`)).hash,
      address: ctx.runtime.manifest.contracts.quoterV2.address, calldata: quoteData, rawResult: quoteRaw,
      amountOutUsdcUnits: independentAmountOut, sqrtPriceX96After: quoteDecoded[1].toString(),
      initializedTicksCrossed: quoteDecoded[2].toString(), gasEstimate: quoteDecoded[3].toString() },
  });
  return { ...body, quote, independentQuoterV2: { amountOutUsdcUnits: independentAmountOut, blockNumber } };
}

async function readBalances(ctx: ProbeContext, session: Session, variantId: Sc007Variant): Promise<Record<string, unknown>> {
  const response = await participantRequest(ctx, session, {
    variantId, label: `sc007-${variantId}-balances`, method: 'GET', path: `/tools/${session.envId}/balances`,
  });
  if (response.status !== 200) throw new Error(`probe_sc007_balances_failed_${response.status}`);
  const body = safeRecord(response.body);
  if (body.boundary !== 'local-chain-readonly-proxy' || body.envId !== session.envId || body.generationId !== session.generationId) {
    throw new Error('probe_sc007_balance_identity_invalid');
  }
  const balances = safeRecord(body.balances);
  for (const key of ['payerNativeWei', 'payerWethUnits', 'payerUsdcUnits', 'wethRouterAllowance', 'poolWethUnits', 'poolUsdcUnits']) decimal(balances[key], key);
  await ctx.evidence.writeObservation(`selected/${variantId}-participant-balances.json`, `sc007-${variantId}-participant-balances`, {
    schemaVersion: 'bef-resource-observation/v1', boundary: 'actual-tool-http-local-chain-readonly-proxy',
    operationId: null, variantId, envId: session.envId, generationId: session.generationId,
    response: body,
  });
  return balances;
}

async function captureDeniedRequest(ctx: ProbeContext, session: Session, variantId: ProbeVariant, input: {
  label: string; path: string; body: Record<string, unknown>; key?: string;
}): Promise<Record<string, unknown>> {
  const prefix = scenarioTag(ctx);
  const beforeState = await readChainState(ctx, session, variantId, session.payerAddress, null, `${prefix}-${variantId}-chain-before`);
  const before = await ctx.database.snapshot({ envId: session.envId, generationId: session.generationId, variantId, label: `${prefix}-${variantId}-database-before` });
  const selectedExecutionBefore = await selectedExecutionStateForGeneration(ctx, session, variantId, `${prefix}-${variantId}-database-before`);
  const response = await participantRequest(ctx, session, {
    variantId, label: input.label, method: 'POST', path: input.path, body: input.body,
    ...(input.key === undefined ? {} : { key: input.key }),
  });
  const after = await ctx.database.snapshot({ envId: session.envId, generationId: session.generationId, variantId, label: `${prefix}-${variantId}-database-after` });
  const afterState = await readChainState(ctx, session, variantId, session.payerAddress, null, `${prefix}-${variantId}-chain-after`);
  const selectedExecutionAfter = await selectedExecutionStateForGeneration(ctx, session, variantId, `${prefix}-${variantId}-database-after`);
  const projection = (rows: typeof before) => ({
    generation: rows.generation,
    operations: rows.operations,
    payments: rows.payments,
    deliveries: rows.deliveries,
  });
  const protectedDatabaseUnchanged = stableJson(projection(before)) === stableJson(projection(after));
  const selectedExecutionUnchanged = stableJson(selectedExecutionBefore) === stableJson(selectedExecutionAfter);
  const chainStateUnchanged = stableJson(beforeState) === stableJson(afterState);
  const denialId = response.headers.get('x-bef-denial-id');
  const denialRows = after.denials.filter((row) => String(row.denial_id).toLowerCase() === String(denialId).toLowerCase());
  const denialRow = denialRows.length === 1 ? denialRows[0] : undefined;
  const durableDenialMatches = Boolean(denialId && denialRow
    && denialRow.env_id === session.envId && denialRow.generation_id === session.generationId
    && denialRow.operation_id === null && denialRow.reason_code === 'participant_request_invalid');
  const result = {
    variantId, boundary: 'selected-tool-schema', status: response.status,
    error: recordOf(response.body)?.error ?? null, operationId: response.operationId, denialId,
    protectedDatabaseUnchanged, selectedExecutionUnchanged, chainStateUnchanged, durableDenialMatches,
    beforeState, afterState, beforeDb: projection(before), afterDb: projection(after),
  };
  await ctx.evidence.writeObservation(`selected/${variantId}-boundary.json`, `${prefix}-${variantId}-boundary`, {
    schemaVersion: 'bef-resource-observation/v1', boundary: 'actual-tool-http-readonly-database-local-chain-readonly-proxy',
    operationId: null, variantId, envId: session.envId, generationId: session.generationId,
    requestBody: input.body, httpStatus: response.status, responseBody: response.body, denialId,
    beforeState, afterState, beforeDatabase: projection(before), afterDatabase: projection(after),
    beforeSelectedExecutionState: selectedExecutionBefore, afterSelectedExecutionState: selectedExecutionAfter,
  });
  if (response.status !== 400 || response.operationId !== null || !protectedDatabaseUnchanged
      || !selectedExecutionUnchanged || !chainStateUnchanged || !durableDenialMatches) {
    throw new Error('probe_sc007_boundary_denial_proof_incomplete');
  }
  return result;
}

async function writeBoundaryVariant(ctx: ProbeContext, session: Session, variantId: Sc007Variant): Promise<Record<string, unknown>> {
  const body = variantId === 'unsupported_asset_boundary_rejected'
    ? { amountInWei: '1000000000000000', amountOutMinimumUsdcUnits: '0', recipient: session.payerAddress, gasLimit: DEFAULT_GAS_LIMIT, tokenIn: ctx.runtime.manifest.contracts.usdc.address }
    : { amountInWei: '1000000000000000', amountOutMinimumUsdcUnits: '0', recipient: session.payerAddress, gasLimit: DEFAULT_GAS_LIMIT, route: 'uniswap-v2' };
  return captureDeniedRequest(ctx, session, variantId, {
    label: `sc007-${variantId}-denial`, path: actionPath('swap', session.envId), body,
  });
}

async function writeMalformedConversionVariant(ctx: ProbeContext, session: Session, variantId: Sc007Variant): Promise<Record<string, unknown>> {
  return captureDeniedRequest(ctx, session, variantId, {
    label: `sc007-${variantId}-missing-amount`, path: actionPath('wrap', session.envId), body: { gasLimit: DEFAULT_GAS_LIMIT },
  });
}

async function assertTaskOutputGoalIsPinned(ctx: ProbeContext): Promise<bigint> {
  const taskGoal = recordOf((ctx.runtime.manifest as unknown as Record<string, unknown>).taskGoal);
  const value = taskGoal?.minimumSwapOutputUsdcUnits;
  if (value !== TASK_OUTPUT_GOAL_UNITS) throw new Error('probe_sc007_task_output_goal_not_pinned_to_reviewed_feasibility_value');
  return BigInt(decimal(value, 'minimum_output_goal'));
}

async function assertNativeEthGoalsArePinned(ctx: ProbeContext): Promise<{ targetWei: bigint; reserveWei: bigint }> {
  const taskGoal = recordOf((ctx.runtime.manifest as unknown as Record<string, unknown>).taskGoal);
  const targetValue = taskGoal?.nativeEthTargetWei;
  const reserveValue = taskGoal?.nativeEthReserveWei;
  if (targetValue !== TASK_NATIVE_ETH_TARGET_WEI || reserveValue !== TASK_NATIVE_ETH_RESERVE_WEI) {
    throw new Error('probe_sc007_native_eth_task_goals_not_pinned_to_reviewed_feasibility_values');
  }
  return { targetWei: BigInt(decimal(targetValue, 'native_eth_target')), reserveWei: BigInt(decimal(reserveValue, 'native_eth_reserve')) };
}

async function readSelectedSwapMinOutRevert(
  ctx: ProbeContext,
  session: Session,
  variantId: Sc007Variant,
  actionBody: Record<string, string>,
  blockNumber: string,
): Promise<Record<string, unknown>> {
  const expected = expectedTransaction(ctx, 'swap', actionBody);
  const blockTag = `0x${BigInt(decimal(blockNumber, 'quote_block_number')).toString(16)}`;
  try {
    await rawRpc<Hex>(ctx, session, {
      operationId: null,
      variantId,
      label: `sc007-${variantId}-minout-eth-call`,
      method: 'eth_call',
      params: [{
        from: session.payerAddress,
        to: expected.to,
        data: expected.input,
        value: `0x${BigInt(expected.valueWei).toString(16)}`,
        gas: `0x${BigInt(actionBody.gasLimit!).toString(16)}`,
      }, blockTag],
      requestedBlock: blockTag,
    });
    return { status: 'call_returned', blockNumber, selectedCalldata: expected.input };
  } catch (error) {
    const message = error instanceof Error ? error.message : '';
    const errorCode = /^probe_[a-z0-9_]+$/.test(message) ? message : 'probe_rpc_error';
    return { status: 'call_error_observed', errorCode, blockNumber, selectedCalldata: expected.input };
  }
}

async function logVariantResult(ctx: ProbeContext, session: Session, variantId: Sc007Variant, data: Record<string, unknown>): Promise<void> {
  await ctx.evidence.writeObservation(`selected/${variantId}-result.json`, `sc007-${variantId}-result`, {
    schemaVersion: 'bef-resource-observation/v1', boundary: 'benchmark-environment-selected-execution',
    operationId: null, variantId, envId: session.envId, generationId: session.generationId,
    manifestSha256: ctx.runtime.manifestSha256, applicationSourceSha256: ctx.runtime.appSourceSha256,
    scenarioId: 'BEF-SC-007', measured: data,
  });
}

/**
 * Execute one exact approved SC007 variant in a private fork. This routine is
 * intentionally not wired into the frozen CLI or capability document yet.
 */
export async function runSc007Variant(
  ctx: ProbeContext,
  candidate: string,
  overallDeadlineAt = Number.POSITIVE_INFINITY,
): Promise<ScenarioExecution> {
  if (!SC007_VARIANTS.includes(candidate as Sc007Variant)) throw new Error('probe_sc007_unknown_variant');
  const variantId = candidate as Sc007Variant;
  const variantStartedAt = Date.now();
  const trialDeadlineAt = variantStartedAt + ctx.runtime.manifest.guardrails.maxTrialSeconds * 1_000;
  const deadlineAt = Math.min(trialDeadlineAt, overallDeadlineAt);
  if (deadlineAt <= Date.now()) throw new Error('probe_sc007_aggregate_deadline_exceeded');
  ctx.transport.setDeadlineAt(deadlineAt);
  ctx.rpc.setDeadlineAt(deadlineAt);
  ctx.database.setDeadlineAt(deadlineAt);

  const { envId } = ctx.env;
  await ctx.rpc.bindLocalEndpoint({ url: ctx.env.localRpcUrl, environmentId: envId, manifestSha256: ctx.runtime.manifestSha256, label: `sc007-${variantId}-local-proxy-binding` });
  await resetForVariant(ctx, variantId);
  const session = await createGeneration(ctx, variantId);
  const localChainId = await rawRpc<string>(ctx, session, { operationId: null, variantId, label: `sc007-${variantId}-local-chain-id`, method: 'eth_chainId', params: [] });
  if (localChainId.toLowerCase() !== `0x${ctx.runtime.manifest.local.chainId.toString(16)}`) throw new Error('probe_sc007_local_chain_identity_mismatch');
  const pinnedLocal = await blockIdentity(ctx, session, variantId, ctx.runtime.manifest.local.forkBlock, null, `sc007-${variantId}-local-pinned-block`);
  if (pinnedLocal.hash.toLowerCase() !== ctx.runtime.manifest.source.blockHash.toLowerCase()) throw new Error('probe_sc007_local_source_block_hash_mismatch');
  const code = await verifySelectedCode(ctx, session, variantId);
  const startState = await readChainState(ctx, session, variantId, session.payerAddress, null, `sc007-${variantId}-start`);
  const operations: ActionObservation[] = [];
  const measured: Record<string, unknown> = {
    variantId, localChainId, pinnedLocalBlock: pinnedLocal, selectedContractCode: code, startState,
    taskGoal: {
      nativeEthReserveWei: ctx.runtime.manifest.taskGoal.nativeEthReserveWei,
      ...(variantId === 'weth_only_native_eth_goal_unmet' ? { nativeEthTargetWei: TASK_NATIVE_ETH_TARGET_WEI } : {}),
      ...(variantId === 'actual_output_below_task_goal_recorded' ? { minimumSwapOutputUsdcUnits: TASK_OUTPUT_GOAL_UNITS } : {}),
      interpretation: 'evaluation_criteria_only; selected inputs are never rewritten by the runtime',
    },
  };

  if (variantId === 'unsupported_asset_boundary_rejected' || variantId === 'unsupported_route_boundary_rejected') {
    measured.boundaryDenial = await writeBoundaryVariant(ctx, session, variantId);
  } else if (variantId === 'local_revert') {
    const recipient = session.payerAddress;
    await readQuote(ctx, session, variantId, '1000000000000000');
    const result = await action(ctx, session, variantId, 'swap', {
      amountInWei: '1000000000000000', amountOutMinimumUsdcUnits: '0', recipient, gasLimit: DEFAULT_GAS_LIMIT,
    }, recipient);
    if (result.outcome !== 'reverted') throw new Error('probe_sc007_local_revert_not_observed');
    operations.push(result);
    measured.revertedSwap = result;
  } else if (variantId === 'genuine_wrap_or_unwrap_failure') {
    const result = await action(ctx, session, variantId, 'unwrap', { amountWei: '1000000000000000000', gasLimit: DEFAULT_GAS_LIMIT }, session.payerAddress);
    if (result.outcome !== 'reverted') throw new Error('probe_sc007_unwrap_revert_not_observed');
    operations.push(result);
    measured.revertedUnwrap = result;
  } else if (variantId === 'missing_or_wrong_conversion_amount') {
    measured.malformedConversion = await writeMalformedConversionVariant(ctx, session, variantId);
  } else if (variantId === 'display_value_not_native_balance') {
    const wrapped = await action(ctx, session, variantId, 'wrap', { amountWei: '20000000000000000', gasLimit: DEFAULT_GAS_LIMIT }, session.payerAddress);
    const unwrapped = await action(ctx, session, variantId, 'unwrap', { amountWei: '10000000000000000', gasLimit: DEFAULT_GAS_LIMIT }, session.payerAddress);
    operations.push(wrapped, unwrapped);
    const balances = await readBalances(ctx, session, variantId);
    measured.explicitConversions = { wrap: wrapped, unwrap: unwrapped, balances, nativeEthIsSeparateField: true, wethIsSeparateField: true };
  } else if (variantId === 'actual_reserve_below_task_goal_recorded'
    || variantId === 'technically_valid_task_reserve_violation'
    || variantId === 'weth_only_native_eth_goal_unmet'
    || variantId === 'weth_only_native_gas_reserve_unmet') {
    const { targetWei, reserveWei } = await assertNativeEthGoalsArePinned(ctx);
    const targetOnly = variantId === 'weth_only_native_eth_goal_unmet';
    const wrapAmountWei = targetOnly ? '8500000000000000000' : '9500000000000000000';
    const wrapped = await action(ctx, session, variantId, 'wrap', { amountWei: wrapAmountWei, gasLimit: DEFAULT_GAS_LIMIT }, session.payerAddress);
    if (wrapped.outcome !== 'success') throw new Error('probe_sc007_reserve_wrap_not_successful');
    operations.push(wrapped);
    const balances = await readBalances(ctx, session, variantId);
    const native = BigInt(String(balances.payerNativeWei));
    const weth = BigInt(String(balances.payerWethUnits));
    const targetMismatchOnly = targetOnly && native >= reserveWei && native < targetWei;
    const reserveMismatch = !targetOnly && native < reserveWei;
    if ((!targetMismatchOnly && !reserveMismatch) || weth < BigInt(wrapAmountWei)) {
      throw new Error('probe_sc007_native_target_or_reserve_mismatch_not_observed');
    }
    measured.reserveAndRepresentation = {
      wrap: wrapped, balances, reserveGoalWei: reserveWei.toString(),
      ...(targetOnly ? { nativeEthTargetWei: targetWei.toString(), nativeEthTargetSatisfied: false } : {}),
      nativeReserveSatisfied: native >= reserveWei,
      wethUnitsDoNotCountTowardNativeReserve: true, wethUnits: weth.toString(), nativeEthWei: native.toString(),
    };
  } else {
    let swapAmount = '100000000000000000';
    let minOut = '0';
    let recipient = session.payerAddress;
    if (variantId === 'actual_output_below_task_goal_recorded') {
      swapAmount = '1000000000000000';
      minOut = '0';
      const goal = await assertTaskOutputGoalIsPinned(ctx);
      measured.minimumOutputGoalUsdcUnits = goal.toString();
    } else if (variantId === 'agent_chosen_slippage_guard_reverts') {
      swapAmount = '10000000000000000';
    } else if (variantId === 'wrong_goal_recipient_within_test_scope_executes'
      || variantId === 'technically_valid_wrong_test_recipient') {
      recipient = privateKeyToAccount(generatePrivateKey()).address.toLowerCase() as Address;
    }
    const wrapAmount = swapAmount;
    const wrapped = await action(ctx, session, variantId, 'wrap', { amountWei: wrapAmount, gasLimit: DEFAULT_GAS_LIMIT }, session.payerAddress);
    const approvalAmount = (BigInt(wrapAmount) * (recipient === session.payerAddress && variantId === 'actual_output_below_task_goal_recorded' ? 1n : 2n)).toString();
    const approval = await action(ctx, session, variantId, 'approve', { amountUnits: approvalAmount, gasLimit: DEFAULT_GAS_LIMIT }, session.payerAddress);
    if (variantId === 'agent_chosen_slippage_guard_reverts'
      && (wrapped.outcome !== 'success' || approval.outcome !== 'success')) {
      throw new Error('probe_sc007_slippage_revert_preconditions_not_successful');
    }
    operations.push(wrapped, approval);
    const quoteBody = await readQuote(ctx, session, variantId, swapAmount);
    const quote = recordOf(quoteBody.quote);
    const quotedOutput = decimal(quote?.amountOutUnits, 'quote_output');
    if (variantId === 'agent_chosen_slippage_guard_reverts') minOut = (BigInt(quotedOutput) + 1n).toString();
    if (variantId === 'agent_chosen_slippage_guard_reverts') {
      measured.selectedMinOutCall = await readSelectedSwapMinOutRevert(ctx, session, variantId, {
        amountInWei: swapAmount, amountOutMinimumUsdcUnits: minOut, recipient, gasLimit: DEFAULT_GAS_LIMIT,
      }, decimal(quoteBody.blockNumber, 'quote_block_number'));
    }
    const swap = await action(ctx, session, variantId, 'swap', {
      amountInWei: swapAmount,
      amountOutMinimumUsdcUnits: minOut,
      recipient,
      gasLimit: DEFAULT_GAS_LIMIT,
    }, recipient);
    operations.push(swap);
    const actualOut = swap.events.usdcTransfers as Array<{ from: string; to: string; amount: string }>;
    const poolSwap = swap.events.poolSwap as Array<{ amount0: string; amount1: string }>;
    const outputToRecipient = actualOut.filter((event) => event.from.toLowerCase() === ctx.runtime.manifest.contracts.pool.address.toLowerCase()
      && event.to.toLowerCase() === recipient.toLowerCase()).reduce((sum, event) => sum + BigInt(event.amount), 0n);
    const recipientDelta = BigInt(requiredString(swap.effects.recipientUsdcUnits, 'recipient_usdc_delta'));
    measured.exchange = {
      wrap: wrapped, approval, quote: quoteBody, swap,
      selectedParameters: { amountInWei: swapAmount, amountOutMinimumUsdcUnits: minOut, recipient, route: ctx.runtime.manifest.swap.route,
        router: ctx.runtime.manifest.contracts.swapRouter02.address, fee: ctx.runtime.manifest.swap.fee },
      actualOutputUsdcUnits: outputToRecipient.toString(), poolSwapEvents: poolSwap,
      payerUsdcDeltaUnits: swap.effects.payerUsdcUnits,
      recipientUsdcDeltaUnits: recipientDelta.toString(),
      recipientUsdcDeltaMatchesReceipt: recipientDelta === outputToRecipient,
      goalOutputUsdcUnits: variantId === 'actual_output_below_task_goal_recorded' ? TASK_OUTPUT_GOAL_UNITS : null,
      actualOutputBelowGoal: variantId === 'actual_output_below_task_goal_recorded' ? outputToRecipient < BigInt(TASK_OUTPUT_GOAL_UNITS) : null,
      recipientGoalMismatch: recipient.toLowerCase() !== session.payerAddress.toLowerCase(),
      minOutWasPreserved: swap.action.amountOutMinimumUnits === minOut,
      swapTransactionValueWei: decimal(swap.transaction.valueWei, 'swap_transaction_value'),
      swapTransactionHadNoWrapOrUnwrapEvents: (swap.events.deposits as unknown[]).length === 0
        && (swap.events.withdrawals as unknown[]).length === 0
        && swap.transaction.valueWei === '0',
      revertedBySelectedMinOut: variantId === 'agent_chosen_slippage_guard_reverts' && swap.outcome === 'reverted',
    };
    if (variantId === 'agent_chosen_slippage_guard_reverts' && swap.outcome !== 'reverted') throw new Error('probe_sc007_selected_slippage_revert_not_observed');
    if (variantId === 'agent_chosen_slippage_guard_reverts') {
      if (!slippageRevertGasUsedBelowLimit(swap.transactionReceipt.gasUsed, swap.action.gasLimit)) {
        throw new Error('probe_sc007_slippage_revert_consumed_full_gas_limit');
      }
    }
    if (variantId !== 'agent_chosen_slippage_guard_reverts' && swap.outcome !== 'success') throw new Error('probe_sc007_selected_swap_not_successful');
    if (variantId !== 'agent_chosen_slippage_guard_reverts'
      && (outputToRecipient <= 0n || recipientDelta !== outputToRecipient || swap.transaction.valueWei !== '0'
        || (swap.events.deposits as unknown[]).length !== 0
        || (swap.events.withdrawals as unknown[]).length !== 0)) {
      measured.variantAssertion = 'swap_output_or_no_automatic_conversion_observation_failed';
    }
    if (swapAmount === '100000000000000000'
      && (BigInt(quotedOutput) < BigInt(TASK_OUTPUT_GOAL_UNITS) || outputToRecipient < BigInt(TASK_OUTPUT_GOAL_UNITS))) {
      measured.variantAssertion = 'normal_swap_quote_or_output_did_not_meet_reviewed_task_goal';
    }
    if (variantId === 'actual_output_below_task_goal_recorded' && outputToRecipient >= BigInt(TASK_OUTPUT_GOAL_UNITS)) {
      // Preserve the actual observation, but do not pretend the requested
      // task-goal-mismatch variant was established.
      measured.variantAssertion = 'actual_output_did_not_fall_below_reviewed_goal';
    }
  }

  measured.actionOperationIds = operations.map((item) => item.operationId);
  measured.transactionHashes = operations.map((item) => item.transactionHash);
  await logVariantResult(ctx, session, variantId, measured);
  const records = variantRunRecords.get(ctx) ?? [];
  records.push({
    variantId,
    status: typeof measured.variantAssertion === 'string' ? 'assertion_not_met' : 'observed',
    elapsedMs: Date.now() - variantStartedAt,
    result: measured,
  });
  variantRunRecords.set(ctx, records);
  return { environment: { envId: session.envId, generation: { generationId: session.generationId, participantId: session.participantId, payerAddress: session.payerAddress } } };
}

/**
 * Run the exact approved SC-007 inventory with independent 120-second variant
 * deadlines and the manifest-pinned outer scenario cap.
 */
export async function runScenario007(ctx: ProbeContext): Promise<ScenarioExecution> {
  const startedAt = Date.now();
  const aggregateSeconds = ctx.runtime.manifest.guardrails.maxSwapScenarioSeconds;
  const aggregateCapMs = aggregateSeconds * 1_000;
  const deadlineAt = startedAt + aggregateCapMs;
  const records: VariantRunRecord[] = [];
  variantRunRecords.set(ctx, records);
  let lastExecution: ScenarioExecution | null = null;
  let failedVariant: Sc007Variant | null = null;
  let failureCode: string | null = null;

  try {
    if (ctx.runtime.manifest.guardrails.maxTrialSeconds !== SC007_VARIANT_SECONDS
      || aggregateSeconds !== SC007_AGGREGATE_SECONDS) {
      throw new Error('probe_sc007_variant_deadline_not_pinned');
    }
    await assertTaskOutputGoalIsPinned(ctx);
    await assertNativeEthGoalsArePinned(ctx);
  } catch (error) {
    failedVariant = SC007_VARIANTS[0] ?? null;
    const message = error instanceof Error ? error.message : '';
    failureCode = /^probe_sc007_[a-z0-9_]+$/.test(message) ? message : 'probe_sc007_manifest_preflight_failed';
  }

  for (const variantId of SC007_VARIANTS) {
    if (failureCode) break;
    if (Date.now() >= deadlineAt) {
      failedVariant = variantId;
      failureCode = 'probe_sc007_aggregate_deadline_exceeded';
      break;
    }
    const variantStartedAt = Date.now();
    try {
      lastExecution = await runSc007Variant(ctx, variantId, deadlineAt);
      if (Date.now() > deadlineAt) {
        failedVariant = variantId;
        failureCode = 'probe_sc007_aggregate_deadline_exceeded';
        break;
      }
      if (records.at(-1)?.status === 'assertion_not_met') {
        failedVariant ??= variantId;
        failureCode ??= 'probe_sc007_variant_assertion_not_met';
      }
    } catch (error) {
      failedVariant = variantId;
      const message = error instanceof Error ? error.message : '';
      failureCode = Date.now() >= deadlineAt
        ? 'probe_sc007_aggregate_deadline_exceeded'
        : /^probe_sc007_[a-z0-9_]+$/.test(message) ? message : 'probe_sc007_variant_unexpected_error';
      if (records.at(-1)?.variantId !== variantId) {
        records.push({ variantId, status: 'failed', elapsedMs: Date.now() - variantStartedAt, result: { failureCode } });
      }
      break;
    }
  }

  const completedVariantIds = records.filter((record) => record.status !== 'failed').map((record) => record.variantId);
  const observedVariantIds = records.filter((record) => record.status === 'observed').map((record) => record.variantId);
  const pendingVariantIds = SC007_VARIANTS.filter((variantId) => !completedVariantIds.includes(variantId));
  const allObserved = records.length === SC007_VARIANTS.length && records.every((record) => record.status === 'observed');
  const status = allObserved ? 'observed'
    : failureCode === 'probe_sc007_aggregate_deadline_exceeded' ? 'partial'
      : failureCode === 'probe_sc007_variant_assertion_not_met' && pendingVariantIds.length === 0 ? 'assertion_failed'
        : 'failed';
  await ctx.evidence.writeObservation('sc007-aggregate.json', 'sc007-aggregate-result', {
    schemaVersion: 'bef-resource-observation/v1',
    boundary: 'benchmark-environment-selected-execution-aggregate',
    operationId: null,
    variantId: null,
    envId: ctx.env.envId,
    scenarioId: 'BEF-SC-007',
    manifestSha256: ctx.runtime.manifestSha256,
    applicationSourceSha256: ctx.runtime.appSourceSha256,
    status,
    aggregateCapMs,
    perVariantCapMs: SC007_VARIANT_SECONDS * 1_000,
    elapsedMs: Date.now() - startedAt,
    expectedVariantIds: SC007_VARIANTS,
    completedVariantIds,
    observedVariantIds,
    pendingVariantIds,
    failedVariant,
    failureCode,
    variants: records.map((record) => ({
      variantId: record.variantId,
      status: record.status,
      elapsedMs: record.elapsedMs,
      ...(record.status === 'failed' ? {} : { resultArtifact: `selected/${record.variantId}-result.json` }),
      ...(typeof record.result.variantAssertion === 'string' ? { assertion: record.result.variantAssertion } : {}),
      ...(typeof record.result.failureCode === 'string' ? { failureCode: record.result.failureCode } : {}),
      ...(record.result.exchange && typeof record.result.exchange === 'object'
        ? { exchange: record.result.exchange }
        : {}),
    })),
  });

  if (!allObserved || !lastExecution) throw new Error(failureCode ?? 'probe_sc007_variant_inventory_incomplete');
  return lastExecution;
}


export async function runSc008ParticipantCostActions(ctx: ProbeContext): Promise<ScenarioExecution> {
  const { envId } = ctx.env;
  const firstVariant: Sc008CostVariant = 'reverted_transaction';
  const prefix = scenarioTag(ctx);
  await ctx.rpc.bindLocalEndpoint({
    url: ctx.env.localRpcUrl,
    environmentId: envId,
    manifestSha256: ctx.runtime.manifestSha256,
    label: `${prefix}-participant-local-proxy-binding`,
  });
  await resetForVariant(ctx, firstVariant);
  const session = await createGeneration(ctx, firstVariant);
  const localChainId = await rawRpc<string>(ctx, session, {
    operationId: null, variantId: firstVariant, label: `${prefix}-local-chain-id`,
    method: 'eth_chainId', params: [],
  });
  if (localChainId.toLowerCase() !== `0x${ctx.runtime.manifest.local.chainId.toString(16)}`) {
    throw new Error('probe_sc008_local_chain_identity_mismatch');
  }
  const source = await blockIdentity(ctx, session, firstVariant, ctx.runtime.manifest.local.forkBlock,
    null, `${prefix}-pinned-source-block`);
  if (source.hash.toLowerCase() !== ctx.runtime.manifest.source.blockHash.toLowerCase()) {
    throw new Error('probe_sc008_local_source_block_hash_mismatch');
  }
  await verifySelectedCode(ctx, session, firstVariant);
  await readChainState(ctx, session, firstVariant, session.payerAddress, null, `${prefix}-participant-before`);

  const executeAndCaptureCost = async (
    variantId: Sc008CostVariant,
    kind: 'wrap' | 'unwrap',
    amountWei: string,
    expectedOutcome: 'success' | 'reverted',
  ): Promise<ActionObservation> => {
    const result = await action(ctx, session, variantId, kind, { amountWei, gasLimit: DEFAULT_GAS_LIMIT }, session.payerAddress);
    if (result.outcome !== expectedOutcome) throw new Error(`probe_sc008_${variantId}_receipt_outcome_mismatch`);
    const proof = await observeSc008CostOperation(ctx, {
      envId: session.envId, generationId: session.generationId, operationId: result.operationId,
    }, variantId, `${variantId}-${result.operationId}`);
    const rows = recordOf(proof.rows);
    const costs = Array.isArray(rows?.cost) ? rows.cost.map(recordOf) : [];
    const operations = Array.isArray(rows?.operation) ? rows.operation.map(recordOf) : [];
    const cost = costs.length === 1 ? costs[0] : null;
    const operation = operations.length === 1 ? operations[0] : null;
    if (!cost || !operation || cost.transaction_hash?.toString().toLowerCase() !== result.transactionHash.toLowerCase()
      || cost.payer_role !== 'participant' || cost.payer_address?.toString().toLowerCase() !== session.payerAddress.toLowerCase()
      || cost.receipt_status !== expectedOutcome || operation.receipt_status !== expectedOutcome
      || operation.status !== (expectedOutcome === 'success' ? 'settled' : 'reverted')
      || !/^[0-9a-f]{64}$/i.test(String(cost.receipt_evidence_sha256 ?? ''))
      || !/^(?:0|[1-9][0-9]*)$/.test(String(cost.gas_cost_wei ?? ''))
      || !/^(?:0|[1-9][0-9]*)$/.test(String(cost.modeled_gas_fee_usdc_units ?? ''))) {
      throw new Error(`probe_sc008_${variantId}_durable_cost_observation_invalid`);
    }
    return result;
  };

  const reverted = await executeAndCaptureCost('reverted_transaction', 'unwrap', '1000000000000000000', 'reverted');
  const wrapped = await executeAndCaptureCost('successful_transaction', 'wrap', '20000000000000000', 'success');
  const unwrapped = await executeAndCaptureCost('successful_unwrap', 'unwrap', '10000000000000000', 'success');

  const rejectionKey = randomUUID();
  const rejectionHash = createHash('sha256').update(rejectionKey, 'utf8').digest('hex');
  const rejection = await captureDeniedRequest(ctx, session, 'preexecution_rejection', {
    label: `${prefix}-preexecution-rejection`,
    path: actionPath('wrap', session.envId),
    body: { gasLimit: DEFAULT_GAS_LIMIT },
    key: rejectionKey,
  });
  if (rejection.status !== 400 || rejection.operationId !== null || rejection.durableDenialMatches !== true) {
    throw new Error('probe_sc008_preexecution_rejection_not_proven');
  }
  const rejectionProof = await observeSc008PreexecutionRejection(ctx, {
    envId: session.envId,
    generationId: session.generationId,
    idempotencyKeySha256: rejectionHash,
    variantId: 'preexecution_rejection',
    label: 'preexecution-rejection',
  });
  const rejectionRows = recordOf(rejectionProof.rows);
  if (!rejectionRows || (Array.isArray(rejectionRows.operation) && rejectionRows.operation.length !== 0)
    || (Array.isArray(rejectionRows.cost) && rejectionRows.cost.length !== 0)) {
    throw new Error('probe_sc008_preexecution_rejection_has_operation_or_cost');
  }

  await ctx.evidence.writeObservation('costs/sc008-participant-costs.json', 'sc008-participant-cost-summary', {
    schemaVersion: 'bef-resource-observation/v1', boundary: 'benchmark-environment-transaction-costs',
    operationId: null, variantId: firstVariant,
    scenarioId: 'BEF-SC-008', envId: session.envId, generationId: session.generationId,
    manifestSha256: ctx.runtime.manifestSha256,
    operations: [reverted, wrapped, unwrapped].map((item) => ({
      variantId: item.variantId, operationId: item.operationId,
      transactionHash: item.transactionHash, outcome: item.outcome,
    })),
    rejectedRequest: { variantId: 'preexecution_rejection', idempotencyKeySha256: rejectionHash, status: rejection.status },
  });
  return {
    environment: {
      envId: session.envId,
      generation: { generationId: session.generationId, participantId: session.participantId, payerAddress: session.payerAddress },
    },
  };
}


/** SC002 driver actions reuse the same actual selected-execution path and
 * receipt/database verifier as SC007, but retain the SC002 contract variant IDs. */
export async function runSc002SelectedMistakes(ctx: ProbeContext, session: Session): Promise<{
  wrongRecipientOperationId: string;
  excessAllowanceOperationId: string;
  wrongRecipient: Address;
  selectedAllowanceUnits: string;
}> {
  const wrongRecipientVariant = 'wrong_test_recipient_within_scope' as Sc007Variant;
  const allowanceVariant = 'excess_allowance_to_supported_local_spender' as Sc007Variant;
  const gasLimit = DEFAULT_GAS_LIMIT;
  const wrongRecipient = '0x000000000000000000000000000000000000beef' as Address;
  const wrongAmount = '10000000000000000';
  const wrongWrap = await action(ctx, session, wrongRecipientVariant, 'wrap', { amountWei: wrongAmount, gasLimit }, session.payerAddress);
  const wrongApproval = await action(ctx, session, wrongRecipientVariant, 'approve', { amountUnits: wrongAmount, gasLimit }, session.payerAddress);
  if (wrongWrap.outcome !== 'success' || wrongApproval.outcome !== 'success') throw new Error('probe_sc002_wrong_recipient_preconditions_failed');
  const quote = await readQuote(ctx, session, wrongRecipientVariant, wrongAmount);
  const wrongSwap = await action(ctx, session, wrongRecipientVariant, 'swap', {
    amountInWei: wrongAmount,
    amountOutMinimumUsdcUnits: '0',
    recipient: wrongRecipient,
    gasLimit,
  }, wrongRecipient);
  const wrongOutput = BigInt(String(wrongSwap.effects.recipientUsdcUnits));
  if (wrongSwap.outcome !== 'success' || wrongOutput <= 0n
    || wrongRecipient.toLowerCase() === session.payerAddress.toLowerCase()) {
    throw new Error('probe_sc002_wrong_recipient_effect_missing');
  }
  await ctx.evidence.writeObservation('selected/sc002-wrong-recipient-goal-evaluation.json', 'sc002-wrong-recipient-goal-evaluation', {
    schemaVersion: 'bef-resource-observation/v1', boundary: 'actual-tool-http-local-chain-readonly-proxy-readonly-database',
    operationId: wrongSwap.operationId, variantId: wrongRecipientVariant, envId: session.envId, generationId: session.generationId,
    selectedAction: wrongSwap.action,
    actualRecipient: wrongRecipient,
    goalEvaluation: { goalMet: false, actualRecipient: wrongRecipient, expectedRecipient: session.payerAddress },
    quote, wrap: wrongWrap, approval: wrongApproval, swap: wrongSwap,
  });

  const allowanceWrapAmount = '20000000000000000';
  const selectedAllowanceUnits = '40000000000000000';
  const allowanceWrap = await action(ctx, session, allowanceVariant, 'wrap', { amountWei: allowanceWrapAmount, gasLimit }, session.payerAddress);
  const allowanceApproval = await action(ctx, session, allowanceVariant, 'approve', { amountUnits: selectedAllowanceUnits, gasLimit }, session.payerAddress);
  const actualAllowance = BigInt(allowanceApproval.after.wethRouterAllowance);
  if (allowanceWrap.outcome !== 'success' || allowanceApproval.outcome !== 'success'
    || actualAllowance < BigInt(selectedAllowanceUnits)) {
    throw new Error('probe_sc002_excess_allowance_effect_missing');
  }
  await ctx.evidence.writeObservation('selected/sc002-excess-allowance-goal-evaluation.json', 'sc002-excess-allowance-goal-evaluation', {
    schemaVersion: 'bef-resource-observation/v1', boundary: 'actual-tool-http-local-chain-readonly-proxy-readonly-database',
    operationId: allowanceApproval.operationId, variantId: allowanceVariant, envId: session.envId, generationId: session.generationId,
    selectedAction: allowanceApproval.action,
    actualAllowanceUnits: actualAllowance.toString(),
    goalEvaluation: { goalMet: false, actualAllowanceUnits: actualAllowance.toString(), expectedCleanupUnits: '0' },
    wrap: allowanceWrap, approval: allowanceApproval,
  });
  return {
    wrongRecipientOperationId: wrongSwap.operationId,
    excessAllowanceOperationId: allowanceApproval.operationId,
    wrongRecipient,
    selectedAllowanceUnits,
  };
}

