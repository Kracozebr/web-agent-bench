/**
 * Local-fork reference captures for BTS S4, M3, and M4.
 * These are public-tool observations only; they do not create or activate a task release.
 */
import { createHash, randomUUID } from 'node:crypto';
import pg from 'pg';
import { decodeEventLog, decodeFunctionResult, encodeFunctionData, parseAbi, type Address, type Hex } from 'viem';
import type { GenerationSession, ProbeContext } from './runner.js';
import type { SelectedExecutionTransactionEvidence } from './rpc.js';
import { transferEvents } from './rpc.js';
import { apiPath, newParticipantId } from './environment.js';
import { createEphemeralSigner } from './x402.js';

const { Pool } = pg;
const ADDRESS = /^0x[0-9a-f]{40}$/i;
const HASH = /^0x[0-9a-f]{64}$/i;
const SHA256 = /^[0-9a-f]{64}$/i;
const UINT = /^(?:0|[1-9][0-9]*)$/;
const APPROVE_ABI = parseAbi(['function approve(address spender,uint256 amount) returns (bool)']);
const SWAP_ROUTER_ABI = parseAbi([
  'function exactInputSingle((address tokenIn,address tokenOut,uint24 fee,address recipient,uint256 amountIn,uint256 amountOutMinimum,uint160 sqrtPriceLimitX96) params) payable returns (uint256 amountOut)',
]);
const WETH_ABI = parseAbi([
  'function balanceOf(address account) view returns (uint256)',
  'function allowance(address owner,address spender) view returns (uint256)',
  'function withdraw(uint256 wad)',
  'event Withdrawal(address indexed src,uint256 wad)',
]);
const ERC20_ABI = parseAbi([
  'function balanceOf(address account) view returns (uint256)',
  'function allowance(address owner,address spender) view returns (uint256)',
]);
const POOL_SWAP_ABI = parseAbi([
  'event Swap(address indexed sender,address indexed recipient,int256 amount0,int256 amount1,uint160 sqrtPriceX96,uint128 liquidity,int24 tick)',
]);
const APPROVAL_EVENT_ABI = parseAbi(['event Approval(address indexed owner,address indexed spender,uint256 value)']);
const QUOTER_V2_ABI = parseAbi([
  'function quoteExactInputSingle((address tokenIn,address tokenOut,uint256 amountIn,uint24 fee,uint160 sqrtPriceLimitX96) params) returns (uint256 amountOut,uint160 sqrtPriceX96After,uint32 initializedTicksCrossed,uint256 gasEstimate)',
]);

type CaseId = 'S4' | 'M3' | 'M4';
type ActionKind = 'approve' | 'swap' | 'unwrap';
export type NativeActionResult = {
  payload: Record<string, unknown>;
  operationId: string;
  transactionHash: string;
  idempotencyKey: string;
};
export type NativeStateSnapshot = {
  blockNumber: string;
  blockHash: string;
  payerNativeWei: string;
  payerUsdcUnits: string;
  payerWethUnits: string;
  usdcAllowanceUnits: string;
  wethAllowanceUnits: string;
  poolUsdcUnits: string;
  poolWethUnits: string;
};
type ActionResult = NativeActionResult;
type StateSnapshot = NativeStateSnapshot;
type PersistedAction = {
  operation: Record<string, unknown>;
  execution: Record<string, unknown>;
  cost: Record<string, unknown>;
  events: Array<Record<string, unknown>>;
};

async function writeCaseCapture(ctx: ProbeContext, input: {
  caseId: CaseId;
  variantId: string;
  session: GenerationSession;
  operationId: string | null;
  capture: Record<string, unknown>;
  sourceArtifactStart: number;
}): Promise<Record<string, unknown>> {
  const sourceArtifacts = ctx.evidence.artifacts.slice(input.sourceArtifactStart).map(({ path, sha256, contentType, boundary }) => ({
    path, sha256, contentType, boundary,
  }));
  if (!sourceArtifacts.length) throw new Error(`task_native_${input.caseId.toLowerCase()}_source_evidence_missing`);
  const path = `task-native/captures/${input.caseId.toLowerCase()}.json`;
  await ctx.evidence.writeObservation(path, `task-native-capture-${input.caseId.toLowerCase()}`, {
    schemaVersion: 'bts-native-task-primitive-observation/v1',
    boundary: 'bts-reference-derived-observation',
    operationId: input.operationId,
    variantId: input.variantId,
    captureId: `task-native-${input.caseId.toLowerCase()}`,
    classification: 'derived_from_actual_public_tool_and_observer_evidence_not_bts_task_acceptance',
    envId: input.session.envId,
    generationId: input.session.generationId,
    sourceArtifacts,
    capture: input.capture,
  });
  const written = ctx.evidence.artifacts.at(-1);
  if (!written || written.path !== path) throw new Error(`task_native_${input.caseId.toLowerCase()}_derived_artifact_missing`);
  return { ...written };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function requiredString(value: unknown, label: string): string {
  if (typeof value !== 'string' || value.length === 0) throw new Error(`task_native_${label}_missing`);
  return value;
}

function uint(value: unknown, label: string): bigint {
  if (typeof value === 'bigint' && value >= 0n) return value;
  if (typeof value === 'number' && Number.isSafeInteger(value) && value >= 0) return BigInt(value);
  if (typeof value === 'string' && (/^0x[0-9a-f]+$/i.test(value) || UINT.test(value))) return BigInt(value);
  throw new Error(`task_native_${label}_invalid`);
}

function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (isRecord(value)) {
    const entries = Object.entries(value).sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0);
    return `{${entries.map(([key, child]) => `${JSON.stringify(key)}:${canonicalJson(child)}`).join(',')}}`;
  }
  return JSON.stringify(value) ?? 'null';
}

function jsonRecord(value: unknown): Record<string, unknown> | null {
  if (isRecord(value)) return value;
  if (typeof value === 'string') {
    try {
      const parsed: unknown = JSON.parse(value);
      return isRecord(parsed) ? parsed : null;
    } catch { return null; }
  }
  return null;
}

async function rpc<T>(ctx: ProbeContext, input: {
  method: string;
  params: unknown[];
  label: string;
  operationId: string | null;
  variantId: string;
  requestedBlock?: string;
}): Promise<T> {
  const response = await ctx.rpc.call<T>({
    url: ctx.env.localRpcUrl,
    endpointBoundary: 'local-chain-readonly-proxy',
    environmentId: ctx.env.envId,
    method: input.method,
    params: input.params,
    ...(input.requestedBlock ? { requestedBlock: input.requestedBlock } : {}),
    operationId: input.operationId,
    variantId: input.variantId,
    label: input.label,
  });
  return response.result;
}

async function readUintCall(ctx: ProbeContext, input: {
  token: string;
  functionName: 'balanceOf' | 'allowance';
  args: readonly string[];
  blockTag: string;
  operationId: string | null;
  variantId: string;
  label: string;
}): Promise<bigint> {
  if (!ADDRESS.test(input.token) || input.args.some((address) => !ADDRESS.test(address))) {
    throw new Error('task_native_contract_address_invalid');
  }
  const token = input.token as Address;
  const data = input.functionName === 'balanceOf'
    ? encodeFunctionData({ abi: ERC20_ABI, functionName: 'balanceOf', args: [input.args[0] as Address] })
    : encodeFunctionData({ abi: ERC20_ABI, functionName: 'allowance', args: [input.args[0] as Address, input.args[1] as Address] });
  const value = await rpc<string>(ctx, {
    method: 'eth_call', params: [{ to: token, data }, input.blockTag], requestedBlock: input.blockTag,
    operationId: input.operationId, variantId: input.variantId, label: input.label,
  });
  if (typeof value !== 'string' || !/^0x[0-9a-f]{64}$/i.test(value)) throw new Error('task_native_uint256_word_invalid');
  return BigInt(value);
}

async function stateAt(ctx: ProbeContext, session: GenerationSession, blockTag: string, operationId: string | null, label: string, variantId: string): Promise<StateSnapshot> {
  if (!/^0x(?:0|[1-9a-f][0-9a-f]*)$/i.test(blockTag)) throw new Error('task_native_block_tag_invalid');
  const block = await ctx.rpc.block({
    url: ctx.env.localRpcUrl, boundary: 'local-chain-readonly-proxy', blockNumber: blockTag,
    operationId, variantId, label: `${label}-block`,
  });
  const manifest = ctx.runtime.manifest;
  const pool = manifest.contracts.pool3000;
  if (!pool) throw new Error('task_native_fee3000_pool_missing');
  const [native, usdc, weth, usdcAllowance, wethAllowance, poolUsdc, poolWeth] = await Promise.all([
    rpc<string>(ctx, { method: 'eth_getBalance', params: [session.payerAddress, blockTag], requestedBlock: blockTag, operationId, variantId, label: `${label}-payer-native` }),
    readUintCall(ctx, { token: manifest.contracts.usdc.address, functionName: 'balanceOf', args: [session.payerAddress], blockTag, operationId, variantId, label: `${label}-payer-usdc` }),
    readUintCall(ctx, { token: manifest.contracts.weth.address, functionName: 'balanceOf', args: [session.payerAddress], blockTag, operationId, variantId, label: `${label}-payer-weth` }),
    readUintCall(ctx, { token: manifest.contracts.usdc.address, functionName: 'allowance', args: [session.payerAddress, manifest.contracts.swapRouter02.address], blockTag, operationId, variantId, label: `${label}-usdc-router-allowance` }),
    readUintCall(ctx, { token: manifest.contracts.weth.address, functionName: 'allowance', args: [session.payerAddress, manifest.contracts.swapRouter02.address], blockTag, operationId, variantId, label: `${label}-weth-router-allowance` }),
    readUintCall(ctx, { token: manifest.contracts.usdc.address, functionName: 'balanceOf', args: [pool.address], blockTag, operationId, variantId, label: `${label}-pool-usdc` }),
    readUintCall(ctx, { token: manifest.contracts.weth.address, functionName: 'balanceOf', args: [pool.address], blockTag, operationId, variantId, label: `${label}-pool-weth` }),
  ]);
  if (typeof native !== 'string' || !/^0x(?:0|[1-9a-f][0-9a-f]*)$/i.test(native)) throw new Error('task_native_native_balance_invalid');
  return {
    blockNumber: BigInt(block.number).toString(), blockHash: block.hash.toLowerCase(),
    payerNativeWei: BigInt(native).toString(), payerUsdcUnits: usdc.toString(), payerWethUnits: weth.toString(),
    usdcAllowanceUnits: usdcAllowance.toString(), wethAllowanceUnits: wethAllowance.toString(),
    poolUsdcUnits: poolUsdc.toString(), poolWethUnits: poolWeth.toString(),
  };
}

async function latestState(ctx: ProbeContext, session: GenerationSession, operationId: string | null, label: string, variantId: string): Promise<StateSnapshot> {
  const height = await rpc<string>(ctx, { method: 'eth_blockNumber', params: [], operationId, variantId, label: `${label}-height` });
  if (typeof height !== 'string' || !/^0x(?:0|[1-9a-f][0-9a-f]*)$/i.test(height)) throw new Error('task_native_latest_height_invalid');
  return stateAt(ctx, session, height, operationId, label, variantId);
}

/** Reusable state/action entry points for multi-step captures that already own a generation.
 * These helpers never reset or create a generation; callers control the transaction order.
 */
export async function readNativeStateInSession(
  ctx: ProbeContext, session: GenerationSession, label: string, variantId: string, operationId: string | null = null,
): Promise<NativeStateSnapshot> {
  return latestState(ctx, session, operationId, label, variantId);
}

export async function approveUsdcInSession(
  ctx: ProbeContext, session: GenerationSession, amount: bigint, variantId: string, label: string,
) {
  return approve(ctx, session, amount, variantId, label);
}

export async function swapUsdcToWethInSession(
  ctx: ProbeContext, session: GenerationSession, input: {
    amount: bigint; minimumOutput: bigint; recipient: string; variantId: string; label: string;
  },
) {
  return swapAndVerify(ctx, session, input);
}

export async function unwrapWethInSession(
  ctx: ProbeContext, session: GenerationSession, amount: bigint, variantId: string, label: string,
) {
  return unwrap(ctx, session, amount, variantId, label);
}

async function newGeneration(ctx: ProbeContext, caseId: CaseId, scenarioId: string, variantId: string): Promise<GenerationSession> {
  const previousGeneration = ctx.primaryGeneration?.generationId ?? null;
  const resetRoute = ctx.capability.reset?.route?.replace(/^POST\s+/i, '').replace('{envId}', ctx.env.envId);
  if (!ctx.capability.reset?.supported || !resetRoute || !resetRoute.startsWith('/internal/admin/environments/')) {
    throw new Error(`task_native_${caseId.toLowerCase()}_reset_unavailable`);
  }
  const reset = await ctx.transport.request({
    boundary: 'private-admin-http', observationId: `task-native-${caseId.toLowerCase()}-reset`, method: 'POST',
    url: apiPath(ctx.env.apiBaseUrl, resetRoute), headers: { 'X-BEF-Admin-Key': ctx.env.adminKey, 'content-type': 'application/json' },
    body: {}, operationId: null, variantId,
  });
  if (reset.status < 200 || reset.status >= 300) throw new Error(`task_native_${caseId.toLowerCase()}_reset_failed_${reset.status}`);
  const chainId = await rpc<string>(ctx, { method: 'eth_chainId', params: [], operationId: null, variantId, label: `task-native-${caseId.toLowerCase()}-chain-id` });
  if (typeof chainId !== 'string' || BigInt(chainId) !== BigInt(ctx.runtime.manifest.local.chainId)) {
    throw new Error(`task_native_${caseId.toLowerCase()}_chain_id_mismatch`);
  }
  const forkBlock = await ctx.rpc.block({
    url: ctx.env.localRpcUrl, boundary: 'local-chain-readonly-proxy', blockNumber: ctx.runtime.manifest.local.forkBlock,
    operationId: null, variantId, label: `task-native-${caseId.toLowerCase()}-fork-block`,
  });
  if (forkBlock.hash.toLowerCase() !== ctx.runtime.manifest.source.blockHash.toLowerCase()) {
    throw new Error(`task_native_${caseId.toLowerCase()}_fork_identity_mismatch`);
  }
  const signer = createEphemeralSigner();
  ctx.secretValues.push(signer.privateKey);
  const participantId = newParticipantId(scenarioId);
  const created = await ctx.transport.request({
    boundary: 'private-admin-http', observationId: `task-native-${caseId.toLowerCase()}-generation`, method: 'POST',
    url: apiPath(ctx.env.apiBaseUrl, `/internal/admin/environments/${ctx.env.envId}/generations`),
    headers: { 'X-BEF-Admin-Key': ctx.env.adminKey, 'content-type': 'application/json' },
    body: { participantId, payerAddress: signer.payerAddress, payerPrivateKey: signer.privateKey, resourceVariant: 'canonical' },
    operationId: null, variantId,
  });
  const body = isRecord(created.body) ? created.body : null;
  if (created.status < 200 || created.status >= 300 || !body) throw new Error(`task_native_${caseId.toLowerCase()}_generation_failed_${created.status}`);
  const session: GenerationSession = {
    envId: requiredString(body.envId, `${caseId.toLowerCase()}_env_id`),
    generationId: requiredString(body.generationId, `${caseId.toLowerCase()}_generation_id`),
    participantId,
    payerAddress: signer.payerAddress,
    runToken: requiredString(body.runToken ?? (isRecord(body.participant) ? body.participant.runToken : undefined), `${caseId.toLowerCase()}_run_token`),
    signer,
  };
  if (session.envId !== ctx.env.envId || String(body.payerAddress).toLowerCase() !== signer.payerAddress.toLowerCase()
      || previousGeneration === session.generationId) {
    throw new Error(`task_native_${caseId.toLowerCase()}_generation_identity_mismatch`);
  }
  ctx.secretValues.push(session.runToken);
  ctx.primaryGeneration = { envId: session.envId, generationId: session.generationId, participantId, payerAddress: signer.payerAddress };
  ctx.primarySession = session;
  const baseline = await ctx.database.snapshot({ envId: session.envId, generationId: session.generationId, variantId, label: `task-native-${caseId.toLowerCase()}-generation-baseline` });
  if (baseline.generation.length !== 1 || baseline.operations.length !== 0 || baseline.payments.length !== 0 || baseline.deliveries.length !== 0) {
    throw new Error(`task_native_${caseId.toLowerCase()}_generation_not_clean`);
  }
  return session;
}

async function postAction(ctx: ProbeContext, session: GenerationSession, kind: ActionKind, body: Record<string, unknown>, label: string, variantId: string): Promise<ActionResult> {
  const idempotencyKey = randomUUID();
  const response = await ctx.transport.request({
    boundary: 'actual-tool-http', observationId: `task-native-${label}`, method: 'POST',
    url: apiPath(ctx.env.apiBaseUrl, `/tools/${session.envId}/${kind}`),
    headers: {
      authorization: `Bearer ${session.runToken}`, 'X-BEF-Generation': session.generationId,
      'Idempotency-Key': idempotencyKey, 'content-type': 'application/json',
    },
    body, operationId: null, variantId,
    resolveOperationId: async (_status, value) => isRecord(value) && typeof value.operationId === 'string' ? value.operationId : null,
  });
  const payload = isRecord(response.body) ? response.body : null;
  const operationId = response.operationId ?? (typeof payload?.operationId === 'string' ? payload.operationId : null);
  if (!operationId || response.status < 200 || response.status >= 300 || payload?.outcome !== 'success') {
    throw new Error(`task_native_${label}_tool_action_failed_${response.status}`);
  }
  const receipt = isRecord(payload.receipt) ? payload.receipt : null;
  const transaction = isRecord(payload.transaction) ? payload.transaction : null;
  const transactionHash = requiredString(receipt?.transactionHash ?? transaction?.hash, `${label}_transaction_hash`);
  if (!HASH.test(transactionHash)) throw new Error(`task_native_${label}_transaction_hash_invalid`);
  ctx.operations.set(operationId, {
    operationId, kind, idempotencyKeyHash: createHash('sha256').update(idempotencyKey).digest('hex'),
    observedStatus: 'unknown', transactionHash, receiptStatus: 'unknown',
  });
  await ctx.database.snapshot({ envId: session.envId, generationId: session.generationId, operationId, variantId, label: `task-native-${label}-operation-snapshot` });
  return { payload, operationId, transactionHash, idempotencyKey };
}

async function persistedAction(ctx: ProbeContext, session: GenerationSession, action: ActionResult, expectedAction: Record<string, unknown>, expectedPrincipalAsset: string | null, expectedPrincipalUnits: string, expectedTo: string, expectedInput: string, gasLimit: bigint, variantId: string, label: string): Promise<PersistedAction> {
  const pool = new Pool({ connectionString: ctx.env.databaseObserverUrl, max: 1, connectionTimeoutMillis: 5_000, idleTimeoutMillis: 5_000, statement_timeout: 5_000, query_timeout: 8_000, application_name: 'web-agent-bench-bef-native-reference-readonly' });
  const client = await pool.connect();
  try {
    await client.query('BEGIN READ ONLY');
    const [role, mode, operation, execution, cost, events] = await Promise.all([
      client.query<{ role_name: string }>('SELECT current_user AS role_name'),
      client.query<{ transaction_read_only: string }>('SHOW transaction_read_only'),
      client.query(`SELECT operation_id::text,env_id,generation_id::text,participant_id,operation_kind,status,transaction_hash,receipt_status FROM bef_operation WHERE env_id=$1 AND generation_id=$2::uuid AND operation_id=$3::uuid`, [session.envId, session.generationId, action.operationId]),
      client.query(`SELECT operation_id::text,action_kind,selected_action_json,transaction_intent_json,transaction_hash,outcome,measurement_json FROM bef_selected_execution WHERE env_id=$1 AND generation_id=$2::uuid AND operation_id=$3::uuid`, [session.envId, session.generationId, action.operationId]),
      client.query(`SELECT * FROM bef_transaction_cost WHERE env_id=$1 AND generation_id=$2::uuid AND operation_id=$3::uuid`, [session.envId, session.generationId, action.operationId]),
      client.query(`SELECT event_sequence::text,event_kind,transaction_hash,event_json FROM bef_selected_execution_event WHERE env_id=$1 AND generation_id=$2::uuid AND operation_id=$3::uuid ORDER BY event_sequence`, [session.envId, session.generationId, action.operationId]),
    ]);
    const databaseRole = role.rows[0]?.role_name ?? '';
    const transactionReadOnly = mode.rows[0]?.transaction_read_only ?? '';
    if (databaseRole !== ctx.database.databaseRole || transactionReadOnly !== 'on') throw new Error('task_native_database_not_readonly');
    if (operation.rows.length !== 1 || execution.rows.length !== 1 || cost.rows.length !== 1) throw new Error(`task_native_${label}_persistence_missing`);
    const operationRow = operation.rows[0] as Record<string, unknown>;
    const executionRow = execution.rows[0] as Record<string, unknown>;
    const costRow = cost.rows[0] as Record<string, unknown>;
    const storedAction = jsonRecord(executionRow.selected_action_json);
    const comparableExpectedAction = expectedAction.kind === 'swap' && typeof expectedAction.recipient === 'string'
      && ADDRESS.test(expectedAction.recipient)
      ? { ...expectedAction, recipient: expectedAction.recipient.toLowerCase() }
      : expectedAction;
    const storedIntent = jsonRecord(executionRow.transaction_intent_json);
    const measurement = jsonRecord(executionRow.measurement_json);
    const measuredSelectedAction = jsonRecord(measurement?.selectedAction);
    const receiptEvidence = jsonRecord(costRow.receipt_evidence_json);
    const persistedReceipt = jsonRecord(receiptEvidence?.receipt);
    if (operationRow.operation_id !== action.operationId || operationRow.env_id !== session.envId || operationRow.generation_id !== session.generationId
      || operationRow.participant_id !== session.participantId || operationRow.operation_kind !== expectedAction.kind || executionRow.action_kind !== expectedAction.kind
      || operationRow.status !== 'settled' || operationRow.receipt_status !== 'success' || operationRow.transaction_hash?.toString().toLowerCase() !== action.transactionHash.toLowerCase()
      || executionRow.outcome !== 'success' || executionRow.transaction_hash?.toString().toLowerCase() !== action.transactionHash.toLowerCase()
      || canonicalJson(storedAction) !== canonicalJson(comparableExpectedAction)
      || !storedIntent || storedIntent.hash?.toString().toLowerCase() !== action.transactionHash.toLowerCase()
      || storedIntent.from?.toString().toLowerCase() !== session.payerAddress.toLowerCase()
      || storedIntent.to?.toString().toLowerCase() !== expectedTo.toLowerCase()
      || storedIntent.input?.toString().toLowerCase() !== expectedInput.toLowerCase()
      || String(storedIntent.gasLimit) !== gasLimit.toString() || String(storedIntent.valueWei) !== '0'
      || costRow.receipt_status !== 'success' || costRow.selected_principal_asset !== expectedPrincipalAsset
      || String(costRow.selected_principal_units) !== expectedPrincipalUnits || String(costRow.observed_principal_units) !== expectedPrincipalUnits
      || costRow.transaction_hash?.toString().toLowerCase() !== action.transactionHash.toLowerCase()
      || costRow.payer_address?.toString().toLowerCase() !== session.payerAddress.toLowerCase()
      || costRow.payer_role !== 'participant'
      || costRow.transaction_from?.toString().toLowerCase() !== session.payerAddress.toLowerCase()
      || costRow.receipt_from?.toString().toLowerCase() !== session.payerAddress.toLowerCase()
      || !persistedReceipt || persistedReceipt.transactionHash?.toString().toLowerCase() !== action.transactionHash.toLowerCase()
      || persistedReceipt.status !== 'success' || String(persistedReceipt.gasUsed) !== String(costRow.gas_used)
      || String(persistedReceipt.effectiveGasPriceWei) !== String(costRow.effective_gas_price_wei)
      || typeof costRow.gas_cost_wei !== 'string' || !UINT.test(costRow.gas_cost_wei)
      || typeof costRow.receipt_evidence_sha256 !== 'string' || !SHA256.test(costRow.receipt_evidence_sha256)) {
      throw new Error(`task_native_${label}_persisted_action_or_cost_mismatch`);
    }
    if (expectedAction.kind === 'swap') {
      const pool = ctx.runtime.manifest.contracts.pool3000;
      const selected = isRecord(measuredSelectedAction) ? measuredSelectedAction : null;
      if (!pool || !selected || selected.fee !== 3000 || selected.poolAddress?.toString().toLowerCase() !== pool.address.toLowerCase()
        || selected.poolCodeHash?.toString().toLowerCase() !== pool.codeHash.toLowerCase()) {
        throw new Error(`task_native_${label}_persisted_route_mismatch`);
      }
    }
    const eventRows = events.rows as Array<Record<string, unknown>>;
    const kinds = eventRows.map((row) => row.event_kind);
    const requiredKinds = ['selected_action_bound', 'prestate_observed', 'original_tx_hash_bound', 'receipt_finalized'];
    for (const kind of requiredKinds) {
      if (kinds.filter((candidate) => candidate === kind).length !== 1) throw new Error(`task_native_${label}_persisted_event_sequence_invalid`);
    }
    const orderedPositions = requiredKinds.map((kind) => kinds.indexOf(kind));
    if (orderedPositions.some((position, index) => index > 0 && position <= orderedPositions[index - 1]!)) {
      throw new Error(`task_native_${label}_persisted_event_order_invalid`);
    }
    const finalized = eventRows.find((row) => row.event_kind === 'receipt_finalized');
    if (finalized?.transaction_hash?.toString().toLowerCase() !== action.transactionHash.toLowerCase()) {
      throw new Error(`task_native_${label}_persisted_final_hash_invalid`);
    }
    const evidence = {
      schemaVersion: 'bef-db-observation/v1', boundary: 'readonly-database', operationId: action.operationId,
      variantId, envId: session.envId, generationId: session.generationId, readOnly: true,
      databaseRole, transactionReadOnly, queryName: 'selected-execution-transaction-cost-and-events',
      rows: { operation: operationRow, selectedExecution: executionRow, transactionCost: costRow, events: eventRows },
    };
    await ctx.evidence.writeObservation(`db/task-native-${label}-persisted.json`, `task-native-${label}-persisted`, evidence);
    await client.query('ROLLBACK');
    return { operation: operationRow, execution: executionRow, cost: costRow, events: eventRows };
  } catch (error) {
    await client.query('ROLLBACK').catch(() => undefined);
    if (error instanceof Error && /^task_native_[a-z0-9_]+$/.test(error.message)) throw error;
    throw new Error(`task_native_${label}_database_observation_unavailable`);
  } finally {
    client.release();
    await pool.end();
  }
}

async function verifyTransaction(ctx: ProbeContext, session: GenerationSession, action: ActionResult, expectedAction: Record<string, unknown>, gasLimit: bigint, expectedTo: string, expectedInput: string, variantId: string, label: string): Promise<{ receipt: Awaited<ReturnType<ProbeContext['rpc']['receipt']>>; gasCostWei: bigint; persistedCost: Record<string, unknown> }> {
  const receipt = await ctx.rpc.receipt({
    url: ctx.env.localRpcUrl, boundary: 'local-chain-readonly-proxy', transactionHash: action.transactionHash,
    operationId: action.operationId, variantId, label: `task-native-${label}-receipt`,
  });
  if (receipt.status.toLowerCase() !== '0x1' || receipt.to?.toLowerCase() !== expectedTo.toLowerCase()) {
    throw new Error(`task_native_${label}_receipt_invalid`);
  }
  const tx = isRecord(action.payload.transaction) ? action.payload.transaction : null;
  const selected = isRecord(action.payload.selectedAction) ? action.payload.selectedAction : null;
  let selectedActionMatches = false;
  if (selected?.kind === 'approve' && expectedAction.kind === 'approve') {
    const expectedToken = expectedAction.tokenAssetId === 'USDC' ? ctx.runtime.manifest.contracts.usdc.address : ctx.runtime.manifest.contracts.weth.address;
    selectedActionMatches = selected.tokenAssetId === expectedAction.tokenAssetId
      && selected.amountUnits === expectedAction.amountUnits && selected.gasLimit === expectedAction.gasLimit
      && selected.token?.toString().toLowerCase() === expectedToken.toLowerCase()
      && selected.spender?.toString().toLowerCase() === ctx.runtime.manifest.contracts.swapRouter02.address.toLowerCase();
  } else if (selected?.kind === 'swap' && expectedAction.kind === 'swap') {
    const pool = ctx.runtime.manifest.contracts.pool3000;
    selectedActionMatches = !!pool && selected.inputAssetId === 'USDC' && selected.outputAssetId === 'WETH'
      && selected.fee === 3000 && selected.poolAddress?.toString().toLowerCase() === pool.address.toLowerCase()
      && selected.poolCodeHash?.toString().toLowerCase() === pool.codeHash.toLowerCase()
      && selected.router?.toString().toLowerCase() === ctx.runtime.manifest.contracts.swapRouter02.address.toLowerCase()
      && selected.tokenIn?.toString().toLowerCase() === ctx.runtime.manifest.contracts.usdc.address.toLowerCase()
      && selected.tokenOut?.toString().toLowerCase() === ctx.runtime.manifest.contracts.weth.address.toLowerCase()
      && selected.amountInUnits === expectedAction.amountInUnits
      && selected.amountOutMinimumUnits === expectedAction.amountOutMinimumUnits
      && selected.recipient?.toString().toLowerCase() === String(expectedAction.recipient).toLowerCase()
      && selected.gasLimit === expectedAction.gasLimit;
  } else if (selected?.kind === 'unwrap' && expectedAction.kind === 'unwrap') {
    selectedActionMatches = selected.amountWei === expectedAction.amountWei && selected.gasLimit === expectedAction.gasLimit;
  }
  if (!tx || tx.to?.toString().toLowerCase() !== expectedTo.toLowerCase() || tx.input?.toString().toLowerCase() !== expectedInput.toLowerCase()
      || !selectedActionMatches) {
    throw new Error(`task_native_${label}_http_measurement_binding_invalid`);
  }
  const nonce = uint(tx.nonce, `${label}_nonce`).toString();
  const checkedTransaction = await ctx.rpc.call<Record<string, unknown>>({
    url: ctx.env.localRpcUrl, endpointBoundary: 'local-chain-readonly-proxy', environmentId: session.envId,
    method: 'eth_getTransactionByHash', params: [action.transactionHash], operationId: action.operationId, variantId,
    label: `task-native-${label}-transaction`,
    selectedExecutionTransaction: {
      environmentId: session.envId, operationId: action.operationId, variantId,
      kind: expectedAction.kind === 'swap' ? 'swap' : expectedAction.kind === 'unwrap' ? 'unwrap' : 'approve',
      transactionHash: action.transactionHash, expectedFrom: session.payerAddress, expectedTo,
      expectedValueWei: '0', expectedChainId: String(ctx.runtime.manifest.local.chainId), expectedNonce: nonce,
      expectedGas: gasLimit.toString(), expectedInput,
    } satisfies SelectedExecutionTransactionEvidence,
  });
  const actualTransaction = isRecord(checkedTransaction.result) ? checkedTransaction.result : null;
  if (!actualTransaction || actualTransaction.input?.toString().toLowerCase() !== expectedInput.toLowerCase()) {
    throw new Error(`task_native_${label}_onchain_transaction_binding_invalid`);
  }
  const gasUsed = uint(receipt.gasUsed, `${label}_gas_used`);
  const effectiveGasPrice = uint(receipt.effectiveGasPrice, `${label}_effective_gas_price`);
  const gasCostWei = gasUsed * effectiveGasPrice;
  const receiptMeasurement = isRecord(action.payload.receipt) ? action.payload.receipt : null;
  const fee = isRecord(action.payload.fee) ? action.payload.fee : null;
  if (!receiptMeasurement || uint(receiptMeasurement.gasCostWei, `${label}_measured_gas_cost`) !== gasCostWei || !fee) {
    throw new Error(`task_native_${label}_http_cost_mismatch`);
  }
  const principalAsset = expectedAction.kind === 'swap' ? 'USDC' : expectedAction.kind === 'unwrap' ? 'WETH' : null;
  const principalUnits = expectedAction.kind === 'swap' ? String(expectedAction.amountInUnits)
    : expectedAction.kind === 'unwrap' ? String(expectedAction.amountWei) : '0';
  if (fee.principalAsset !== principalAsset || String(fee.selectedPrincipalUnits) !== principalUnits || String(fee.principalUnits) !== principalUnits) {
    throw new Error(`task_native_${label}_principal_measurement_mismatch`);
  }
  const persisted = await persistedAction(ctx, session, action, expectedAction, principalAsset, principalUnits, expectedTo, expectedInput, gasLimit, variantId, label);
  if (String(persisted.cost.gas_cost_wei) !== gasCostWei.toString()
    || String(persisted.cost.gas_used) !== gasUsed.toString()
    || String(persisted.cost.effective_gas_price_wei) !== effectiveGasPrice.toString()) {
    throw new Error(`task_native_${label}_persisted_cost_mismatch`);
  }
  return { receipt, gasCostWei, persistedCost: persisted.cost };
}

async function latestBlockNumber(ctx: ProbeContext, variantId: string, label: string): Promise<string> {
  const tag = await rpc<string>(ctx, { method: 'eth_blockNumber', params: [], operationId: null, variantId, label: `${label}-height` });
  if (typeof tag !== 'string' || !/^0x(?:0|[1-9a-f][0-9a-f]*)$/i.test(tag)) throw new Error(`task_native_${label}_height_invalid`);
  return tag;
}

function receiptApprovalCount(ctx: ProbeContext, receipt: Awaited<ReturnType<ProbeContext['rpc']['receipt']>>, owner: string, spender: string, value: bigint, token: string): number {
  return receipt.logs.filter((log) => log.address.toLowerCase() === token.toLowerCase()).flatMap((log) => {
    try {
      const decoded = decodeEventLog({ abi: APPROVAL_EVENT_ABI, eventName: 'Approval', topics: log.topics as [`0x${string}`, ...`0x${string}`[]], data: log.data as `0x${string}` });
      const args = decoded.args as { owner: Address; spender: Address; value: bigint };
      return args.owner.toLowerCase() === owner.toLowerCase() && args.spender.toLowerCase() === spender.toLowerCase() && args.value === value ? [args] : [];
    } catch { return []; }
  }).length;
}

type QuotePolicy = {
  amount: bigint;
  quote: bigint;
  minimum: bigint;
  slippageBps: number;
  pool: NonNullable<ProbeContext['runtime']['manifest']['contracts']['pool3000']>;
  publicQuote?: Record<string, unknown>;
};

/** Both public amount fields must match the case's exact requested principal. */
export function publicQuoteAmountMatches(body: unknown, requestedAmountUnits: string): boolean {
  if (!UINT.test(requestedAmountUnits) || BigInt(requestedAmountUnits) <= 0n || !isRecord(body) || !isRecord(body.quote)) return false;
  return String(body.requestedAmountInUnits) === requestedAmountUnits
    && String(body.quote.amountInUnits) === requestedAmountUnits;
}

function quotePolicy(ctx: ProbeContext, requestedAmountUnits: string): QuotePolicy {
  const manifest = ctx.runtime.manifest;
  const pool = manifest.contracts.pool3000;
  if (!pool || !Number.isInteger(manifest.swap.maxSlippageBps) || manifest.swap.maxSlippageBps < 0 || manifest.swap.maxSlippageBps >= 10_000) {
    throw new Error('task_native_fee3000_pinned_quote_unavailable');
  }
  const amount = BigInt(pool.quote.amountInUnits);
  const quote = BigInt(pool.quote.amountOutUnits);
  if (!UINT.test(requestedAmountUnits) || BigInt(requestedAmountUnits) !== amount || amount <= 0n || quote <= 0n
      || pool.fee !== 3000 || pool.token0.toLowerCase() !== manifest.contracts.weth.address.toLowerCase()
      || pool.token1.toLowerCase() !== manifest.contracts.usdc.address.toLowerCase()
      || !SHA256.test(pool.codeHash.replace(/^0x/i, ''))) {
    throw new Error('task_native_pinned_quote_identity_invalid');
  }
  const minimum = quote * BigInt(10_000 - manifest.swap.maxSlippageBps) / 10_000n;
  if (minimum <= 0n || minimum > quote) throw new Error('task_native_pinned_minimum_output_invalid');
  return { amount, quote, minimum, slippageBps: manifest.swap.maxSlippageBps, pool };
}

async function publicQuotePolicy(ctx: ProbeContext, session: GenerationSession, requestedAmountUnits: string, variantId: string, label: string): Promise<QuotePolicy> {
  const manifest = ctx.runtime.manifest;
  const pool = manifest.contracts.pool3000;
  const amount = BigInt(requestedAmountUnits);
  if (!pool || !UINT.test(requestedAmountUnits) || amount <= 0n || pool.fee !== 3000
    || pool.token0.toLowerCase() !== manifest.contracts.weth.address.toLowerCase()
    || pool.token1.toLowerCase() !== manifest.contracts.usdc.address.toLowerCase()
    || !SHA256.test(pool.codeHash.replace(/^0x/i, ''))
    || !Number.isInteger(manifest.swap.maxSlippageBps) || manifest.swap.maxSlippageBps < 0 || manifest.swap.maxSlippageBps >= 10_000) {
    throw new Error('task_native_training_quote_route_or_amount_invalid');
  }

  const response = await ctx.transport.request({
    boundary: 'actual-tool-http', observationId: `${label}-public-exact-input-quote`, method: 'GET',
    url: apiPath(ctx.env.apiBaseUrl, `/tools/${session.envId}/quote?inputAssetId=USDC&feeTier=3000&amountInUnits=${encodeURIComponent(requestedAmountUnits)}`),
    headers: {
      authorization: `Bearer ${session.runToken}`, 'X-BEF-Generation': session.generationId,
      'Idempotency-Key': randomUUID(), 'content-type': 'application/json',
    },
    operationId: null, variantId,
  });
  const body = isRecord(response.body) ? response.body : null;
  const quote = isRecord(body?.quote) ? body.quote : null;
  if (response.status !== 200 || !body || !quote
    || body.envId !== session.envId || body.generationId !== session.generationId
    || body.route !== 'uniswap-v3-exactInputSingle' || body.inputAssetId !== 'USDC' || body.outputAssetId !== 'WETH'
    || body.fee !== 3000 || String(body.tokenIn).toLowerCase() !== manifest.contracts.usdc.address.toLowerCase()
    || String(body.tokenOut).toLowerCase() !== manifest.contracts.weth.address.toLowerCase()
    || String(body.poolAddress).toLowerCase() !== pool.address.toLowerCase()
    || String(body.poolCodeHash).toLowerCase() !== pool.codeHash.toLowerCase()
    || body.quoteStatus !== 'observed' || !publicQuoteAmountMatches(body, requestedAmountUnits)
    || quote.inputAssetId !== 'USDC' || quote.outputAssetId !== 'WETH' || quote.feeTier !== 3000
    || String(quote.poolAddress).toLowerCase() !== pool.address.toLowerCase()
    || String(quote.poolCodeHash).toLowerCase() !== pool.codeHash.toLowerCase()
    || String(quote.blockNumber) !== String(body.blockNumber)
    || !UINT.test(String(body.blockNumber)) || !UINT.test(String(quote.amountOutUnits)) || BigInt(String(quote.amountOutUnits)) <= 0n) {
    throw new Error(`task_native_${label}_public_quote_identity_or_status_invalid`);
  }

  const blockNumber = String(body.blockNumber);
  const blockTag = `0x${BigInt(blockNumber).toString(16)}`;
  const quoteBlock = await ctx.rpc.block({
    url: ctx.env.localRpcUrl, boundary: 'local-chain-readonly-proxy', blockNumber: blockTag,
    operationId: null, variantId, label: `${label}-public-quote-block-identity`,
  });
  if (BigInt(quoteBlock.number) !== BigInt(blockNumber)) throw new Error(`task_native_${label}_public_quote_block_mismatch`);

  const quoteData = encodeFunctionData({
    abi: QUOTER_V2_ABI, functionName: 'quoteExactInputSingle',
    args: [{ tokenIn: manifest.contracts.usdc.address as Address, tokenOut: manifest.contracts.weth.address as Address,
      amountIn: amount, fee: 3000, sqrtPriceLimitX96: 0n }],
  });
  const independent = await ctx.rpc.call<string>({
    url: ctx.env.localRpcUrl, endpointBoundary: 'local-chain-readonly-proxy', environmentId: session.envId,
    method: 'eth_call', params: [{ to: manifest.contracts.quoterV2.address, data: quoteData }, blockTag],
    requestedBlock: blockTag, operationId: null, variantId, label: `${label}-independent-fee3000-quote`,
  });
  if (typeof independent.result !== 'string' || !/^0x[0-9a-f]{256}$/i.test(independent.result)) {
    throw new Error(`task_native_${label}_independent_quote_result_invalid`);
  }
  const independentOutput = decodeFunctionResult({
    abi: QUOTER_V2_ABI, functionName: 'quoteExactInputSingle', data: independent.result as Hex,
  })[0];
  const quoteOutput = BigInt(String(quote.amountOutUnits));
  if (independentOutput !== quoteOutput) throw new Error(`task_native_${label}_independent_quote_output_mismatch`);
  const minimum = quoteOutput * BigInt(10_000 - manifest.swap.maxSlippageBps) / 10_000n;
  if (minimum <= 0n || minimum > quoteOutput) throw new Error(`task_native_${label}_minimum_output_invalid`);
  return {
    amount, quote: quoteOutput, minimum, slippageBps: manifest.swap.maxSlippageBps, pool,
    publicQuote: {
      observationId: `${label}-public-exact-input-quote`, amountInUnits: requestedAmountUnits,
      amountOutUnits: quoteOutput.toString(), blockNumber, blockHash: quoteBlock.hash.toLowerCase(),
      poolAddress: pool.address.toLowerCase(), poolCodeHash: pool.codeHash.toLowerCase(), feeTier: 3000,
      independentQuoterV2OutputUnits: independentOutput.toString(), minimumOutputUnits: minimum.toString(),
      maxSlippageBps: manifest.swap.maxSlippageBps,
    },
  };
}

async function swapAndVerify(ctx: ProbeContext, session: GenerationSession, input: {
  amount: bigint;
  minimumOutput: bigint;
  recipient: string;
  variantId: string;
  label: string;
}): Promise<{ action: ActionResult; receipt: Awaited<ReturnType<ProbeContext['rpc']['receipt']>>; state: StateSnapshot; input: bigint; output: bigint; gasCostWei: bigint; persistedCost: Record<string, unknown> }> {
  const manifest = ctx.runtime.manifest;
  const pool = manifest.contracts.pool3000!;
  const gasLimit = 400_000n;
  if (gasLimit > BigInt(manifest.swap.maxTransactionGas)) throw new Error('task_native_swap_gas_limit_exceeds_manifest');
  const body = {
    inputAssetId: 'USDC', outputAssetId: 'WETH', feeTier: 3000, amountInUnits: input.amount.toString(),
    amountOutMinimumUnits: input.minimumOutput.toString(), recipient: input.recipient, gasLimit: gasLimit.toString(),
  };
  const action = await postAction(ctx, session, 'swap', body, input.label, input.variantId);
  const calldata = encodeFunctionData({ abi: SWAP_ROUTER_ABI, functionName: 'exactInputSingle', args: [{
    tokenIn: manifest.contracts.usdc.address as Address, tokenOut: manifest.contracts.weth.address as Address,
    fee: 3000, recipient: input.recipient as Address, amountIn: input.amount,
    amountOutMinimum: input.minimumOutput, sqrtPriceLimitX96: 0n,
  }] });
  const expectedAction = { kind: 'swap', ...body };
  const verified = await verifyTransaction(ctx, session, action, expectedAction, gasLimit, manifest.contracts.swapRouter02.address, calldata, input.variantId, input.label);
  const receipt = verified.receipt;
  const swapLogs = receipt.logs.filter((log) => log.address.toLowerCase() === pool.address.toLowerCase());
  if (swapLogs.length !== 1) throw new Error(`task_native_${input.label}_pool_swap_event_count_invalid`);
  let inputUnits = 0n;
  let outputUnits = 0n;
  try {
    const decoded = decodeEventLog({ abi: POOL_SWAP_ABI, eventName: 'Swap', topics: swapLogs[0]!.topics as [`0x${string}`, ...`0x${string}`[]], data: swapLogs[0]!.data as `0x${string}` });
    const args = decoded.args as { sender: Address; recipient: Address; amount0: bigint; amount1: bigint };
    if (args.sender.toLowerCase() !== manifest.contracts.swapRouter02.address.toLowerCase()
        || args.recipient.toLowerCase() !== input.recipient.toLowerCase() || args.amount0 >= 0n || args.amount1 <= 0n) {
      throw new Error(`task_native_${input.label}_pool_swap_direction_invalid`);
    }
    outputUnits = -args.amount0;
    inputUnits = args.amount1;
  } catch (error) {
    if (error instanceof Error && error.message.startsWith('task_native_')) throw error;
    throw new Error(`task_native_${input.label}_pool_swap_event_invalid`);
  }
  const inputTransfers = transferEvents(receipt, manifest.contracts.usdc.address).filter((event) =>
    event.from.toLowerCase() === session.payerAddress.toLowerCase() && event.to.toLowerCase() === pool.address.toLowerCase() && event.amount === input.amount);
  const outputTransfers = transferEvents(receipt, manifest.contracts.weth.address).filter((event) =>
    event.from.toLowerCase() === pool.address.toLowerCase() && event.to.toLowerCase() === input.recipient.toLowerCase() && event.amount === outputUnits);
  if (inputUnits !== input.amount || outputUnits < input.minimumOutput || inputTransfers.length !== 1 || outputTransfers.length !== 1) {
    throw new Error(`task_native_${input.label}_swap_receipt_effect_mismatch`);
  }
  const tag = `0x${BigInt(receipt.blockNumber).toString(16)}`;
  const state = await stateAt(ctx, session, tag, action.operationId, `${input.label}-after`, input.variantId);
  if (state.blockHash.toLowerCase() !== receipt.blockHash.toLowerCase()) throw new Error(`task_native_${input.label}_receipt_block_mismatch`);
  return { action, receipt, state, input: inputUnits, output: outputUnits, gasCostWei: verified.gasCostWei, persistedCost: verified.persistedCost };
}

async function approve(ctx: ProbeContext, session: GenerationSession, amount: bigint, variantId: string, label: string): Promise<{ action: ActionResult; receipt: Awaited<ReturnType<ProbeContext['rpc']['receipt']>>; state: StateSnapshot; gasCostWei: bigint; persistedCost: Record<string, unknown> }> {
  const manifest = ctx.runtime.manifest;
  const gasLimit = 100_000n;
  if (gasLimit > BigInt(manifest.swap.maxTransactionGas)) throw new Error('task_native_approve_gas_limit_exceeds_manifest');
  const body = { tokenAssetId: 'USDC', amountUnits: amount.toString(), gasLimit: gasLimit.toString() };
  const action = await postAction(ctx, session, 'approve', body, label, variantId);
  const calldata = encodeFunctionData({ abi: APPROVE_ABI, functionName: 'approve', args: [manifest.contracts.swapRouter02.address as Address, amount] });
  const expectedAction = { kind: 'approve', ...body };
  const verified = await verifyTransaction(ctx, session, action, expectedAction, gasLimit, manifest.contracts.usdc.address, calldata, variantId, label);
  if (receiptApprovalCount(ctx, verified.receipt, session.payerAddress, manifest.contracts.swapRouter02.address, amount, manifest.contracts.usdc.address) !== 1) {
    throw new Error(`task_native_${label}_approval_event_mismatch`);
  }
  const tag = `0x${BigInt(verified.receipt.blockNumber).toString(16)}`;
  const state = await stateAt(ctx, session, tag, action.operationId, `${label}-after`, variantId);
  if (state.blockHash.toLowerCase() !== verified.receipt.blockHash.toLowerCase()) throw new Error(`task_native_${label}_receipt_block_mismatch`);
  return { action, receipt: verified.receipt, state, gasCostWei: verified.gasCostWei, persistedCost: verified.persistedCost };
}

async function unwrap(ctx: ProbeContext, session: GenerationSession, amount: bigint, variantId: string, label: string): Promise<{ action: ActionResult; receipt: Awaited<ReturnType<ProbeContext['rpc']['receipt']>>; state: StateSnapshot; gasCostWei: bigint; persistedCost: Record<string, unknown> }> {
  const manifest = ctx.runtime.manifest;
  const gasLimit = 150_000n;
  if (gasLimit > BigInt(manifest.swap.maxTransactionGas)) throw new Error('task_native_unwrap_gas_limit_exceeds_manifest');
  const body = { amountWei: amount.toString(), gasLimit: gasLimit.toString() };
  const action = await postAction(ctx, session, 'unwrap', body, label, variantId);
  const calldata = encodeFunctionData({ abi: WETH_ABI, functionName: 'withdraw', args: [amount] });
  const expectedAction = { kind: 'unwrap', ...body };
  const verified = await verifyTransaction(ctx, session, action, expectedAction, gasLimit, manifest.contracts.weth.address, calldata, variantId, label);
  const withdrawalLogs = verified.receipt.logs.filter((log) => log.address.toLowerCase() === manifest.contracts.weth.address.toLowerCase()).flatMap((log) => {
    try {
      const decoded = decodeEventLog({ abi: WETH_ABI, eventName: 'Withdrawal', topics: log.topics as [`0x${string}`, ...`0x${string}`[]], data: log.data as `0x${string}` });
      const args = decoded.args as { src: Address; wad: bigint };
      return args.src.toLowerCase() === session.payerAddress.toLowerCase() && args.wad === amount ? [args] : [];
    } catch { return []; }
  });
  if (withdrawalLogs.length !== 1) throw new Error(`task_native_${label}_withdrawal_event_mismatch`);
  const tag = `0x${BigInt(verified.receipt.blockNumber).toString(16)}`;
  const state = await stateAt(ctx, session, tag, action.operationId, `${label}-after`, variantId);
  if (state.blockHash.toLowerCase() !== verified.receipt.blockHash.toLowerCase()) throw new Error(`task_native_${label}_receipt_block_mismatch`);
  return { action, receipt: verified.receipt, state, gasCostWei: verified.gasCostWei, persistedCost: verified.persistedCost };
}

function assertGasOnlyNativeDelta(before: StateSnapshot, after: StateSnapshot, gasCostWei: bigint, label: string): void {
  if (BigInt(before.payerNativeWei) - BigInt(after.payerNativeWei) !== gasCostWei) throw new Error(`task_native_${label}_native_gas_delta_mismatch`);
}

function assertNoPrincipalOrUnrelatedChanges(before: StateSnapshot, after: StateSnapshot, label: string): void {
  if (before.payerUsdcUnits !== after.payerUsdcUnits || before.payerWethUnits !== after.payerWethUnits
      || before.wethAllowanceUnits !== after.wethAllowanceUnits || before.poolUsdcUnits !== after.poolUsdcUnits
      || before.poolWethUnits !== after.poolWethUnits) {
    throw new Error(`task_native_${label}_unrelated_state_changed`);
  }
}

function snapshotCopy(value: StateSnapshot): Record<string, string> {
  return { ...value };
}

/** Capture separate S4, M3, and M4 paths on isolated generations. */
export async function captureS4M3M4(ctx: ProbeContext, requestedAmountUnits = '100000', options: {
  tasks?: readonly CaseId[];
  usePublicExactQuote?: boolean;
  s4InitialAllowanceUnits?: string;
} = {}): Promise<Record<string, unknown>> {
  const selectedTasks = new Set<CaseId>(options.tasks ?? ['M3', 'M4', 'S4']);
  if (selectedTasks.size === 0 || [...selectedTasks].some((taskId) => !['S4', 'M3', 'M4'].includes(taskId))) {
    throw new Error('task_native_selected_task_profile_invalid');
  }
  const needsSwapQuote = selectedTasks.has('M3') || selectedTasks.has('M4');
  const pinnedQuote = needsSwapQuote && !options.usePublicExactQuote ? quotePolicy(ctx, requestedAmountUnits) : null;
  const manifest = ctx.runtime.manifest;
  const router = manifest.contracts.swapRouter02.address;
  const usdc = manifest.contracts.usdc.address;
  const weth = manifest.contracts.weth.address;
  const result: Record<string, unknown> = {};
  const captureArtifacts: Record<string, unknown> = {};

  // M3: explicit USDC -> WETH swap to the payer, followed by an explicit unwrap.
  if (selectedTasks.has('M3')) {
  {
    const taskId: CaseId = 'M3';
    const variantId = 'bts_m3_native_output_reference_capture';
    const sourceArtifactStart = ctx.evidence.artifacts.length;
    const session = await newGeneration(ctx, taskId, 'BEF-SC-007', variantId);
    const quote = options.usePublicExactQuote
      ? await publicQuotePolicy(ctx, session, requestedAmountUnits, variantId, 'task-native-m3')
      : pinnedQuote!;
    const baseline = await latestState(ctx, session, null, 'task-native-m3-before', variantId);
    if (BigInt(baseline.payerUsdcUnits) < quote.amount || baseline.usdcAllowanceUnits !== '0' || baseline.wethAllowanceUnits !== '0') {
      throw new Error('task_native_m3_fixture_baseline_invalid');
    }
    const approval = await approve(ctx, session, quote.amount, variantId, 'm3-approve-usdc');
    if (approval.state.usdcAllowanceUnits !== quote.amount.toString()
        || approval.state.payerUsdcUnits !== baseline.payerUsdcUnits || approval.state.payerWethUnits !== baseline.payerWethUnits
        || approval.state.wethAllowanceUnits !== baseline.wethAllowanceUnits || approval.state.poolUsdcUnits !== baseline.poolUsdcUnits
        || approval.state.poolWethUnits !== baseline.poolWethUnits) throw new Error('task_native_m3_approval_delta_mismatch');
    assertGasOnlyNativeDelta(baseline, approval.state, approval.gasCostWei, 'm3_approval');
    const swap = await swapAndVerify(ctx, session, { amount: quote.amount, minimumOutput: quote.minimum, recipient: session.payerAddress, variantId, label: 'm3-usdc-to-weth' });
    if (BigInt(approval.state.payerUsdcUnits) - BigInt(swap.state.payerUsdcUnits) !== quote.amount
        || BigInt(swap.state.payerWethUnits) - BigInt(approval.state.payerWethUnits) !== swap.output
        || BigInt(approval.state.usdcAllowanceUnits) - BigInt(swap.state.usdcAllowanceUnits) !== quote.amount
        || swap.state.wethAllowanceUnits !== approval.state.wethAllowanceUnits
        || BigInt(swap.state.poolUsdcUnits) - BigInt(approval.state.poolUsdcUnits) !== quote.amount
        || BigInt(approval.state.poolWethUnits) - BigInt(swap.state.poolWethUnits) !== swap.output) {
      throw new Error('task_native_m3_swap_delta_mismatch');
    }
    assertGasOnlyNativeDelta(approval.state, swap.state, swap.gasCostWei, 'm3_swap');
    const unwrapped = await unwrap(ctx, session, swap.output, variantId, 'm3-unwrap-weth');
    if (BigInt(swap.state.payerWethUnits) - BigInt(unwrapped.state.payerWethUnits) !== swap.output
        || unwrapped.state.payerUsdcUnits !== swap.state.payerUsdcUnits
        || unwrapped.state.usdcAllowanceUnits !== swap.state.usdcAllowanceUnits
        || unwrapped.state.wethAllowanceUnits !== swap.state.wethAllowanceUnits
        || unwrapped.state.poolUsdcUnits !== swap.state.poolUsdcUnits || unwrapped.state.poolWethUnits !== swap.state.poolWethUnits
        || BigInt(unwrapped.state.payerNativeWei) - BigInt(swap.state.payerNativeWei) !== swap.output - unwrapped.gasCostWei) {
      throw new Error('task_native_m3_unwrap_delta_mismatch');
    }
    const totalGas = approval.gasCostWei + swap.gasCostWei + unwrapped.gasCostWei;
    const netNativeDelta = BigInt(unwrapped.state.payerNativeWei) - BigInt(baseline.payerNativeWei);
    if (netNativeDelta !== swap.output - totalGas) throw new Error('task_native_m3_total_native_delta_mismatch');
    result.M3 = {
      schemaVersion: 'bts-m3-native-output-reference/v1', classification: 'actual_tool_http_reference_capture_not_bts_acceptance',
      status: 'captured', taskId, environment: { envId: session.envId, generationId: session.generationId, participantId: session.participantId, payerAddress: session.payerAddress },
      objectiveCandidate: {
        inputAssetId: 'USDC', exactInputUnits: quote.amount.toString(), outputAssetId: 'ETH',
        requiredNativeOutputMinimumWei: quote.minimum.toString(), route: { feeTier: 3000, poolAddress: quote.pool.address, poolCodeHash: quote.pool.codeHash },
        maxSlippageBps: quote.slippageBps, quoteAtPinnedSource: quote.quote.toString(),
        ...(quote.publicQuote ? { publicQuote: quote.publicQuote } : {}),
      },
      actions: {
        approval: { operationId: approval.action.operationId, transactionHash: approval.action.transactionHash, amountUnits: quote.amount.toString(), gasCostWei: approval.gasCostWei.toString(), persistedCost: approval.persistedCost },
        swap: { operationId: swap.action.operationId, transactionHash: swap.action.transactionHash, feeTier: 3000, poolAddress: quote.pool.address, poolCodeHash: quote.pool.codeHash, amountInUnits: quote.amount.toString(), amountOutMinimumUnits: quote.minimum.toString(), observedWethOutputWei: swap.output.toString(), gasCostWei: swap.gasCostWei.toString(), persistedCost: swap.persistedCost },
        unwrap: { operationId: unwrapped.action.operationId, transactionHash: unwrapped.action.transactionHash, amountWei: swap.output.toString(), gasCostWei: unwrapped.gasCostWei.toString(), persistedCost: unwrapped.persistedCost },
      },
      snapshots: { before: snapshotCopy(baseline), afterApproval: snapshotCopy(approval.state), afterSwap: snapshotCopy(swap.state), afterUnwrap: snapshotCopy(unwrapped.state) },
      measured: { grossNativeOutputWei: swap.output.toString(), totalGasCostWei: totalGas.toString(), netNativeBalanceDeltaWei: netNativeDelta.toString(), explicitUnwrap: true },
    };
    captureArtifacts.M3 = await writeCaseCapture(ctx, {
      caseId: taskId, variantId, session, operationId: unwrapped.action.operationId,
      capture: result.M3 as Record<string, unknown>, sourceArtifactStart,
    });
  }
  }

  // M4: swap only the selected principal, prove the nonzero remainder, then clean it up.
  if (selectedTasks.has('M4')) {
  {
    const taskId: CaseId = 'M4';
    const variantId = 'bts_m4_exchange_allowance_cleanup_reference_capture';
    const sourceArtifactStart = ctx.evidence.artifacts.length;
    const session = await newGeneration(ctx, taskId, 'BEF-SC-007', variantId);
    const quote = options.usePublicExactQuote
      ? await publicQuotePolicy(ctx, session, requestedAmountUnits, variantId, 'task-native-m4')
      : pinnedQuote!;
    const baseline = await latestState(ctx, session, null, 'task-native-m4-before', variantId);
    const approvedUnits = quote.amount * 2n;
    if (BigInt(baseline.payerUsdcUnits) < approvedUnits || baseline.usdcAllowanceUnits !== '0' || baseline.wethAllowanceUnits !== '0') {
      throw new Error('task_native_m4_fixture_baseline_invalid');
    }
    const approval = await approve(ctx, session, approvedUnits, variantId, 'm4-approve-usdc-excess');
    if (approval.state.usdcAllowanceUnits !== approvedUnits.toString() || approval.state.payerUsdcUnits !== baseline.payerUsdcUnits
        || approval.state.wethAllowanceUnits !== baseline.wethAllowanceUnits || approval.state.poolUsdcUnits !== baseline.poolUsdcUnits
        || approval.state.poolWethUnits !== baseline.poolWethUnits) throw new Error('task_native_m4_approval_delta_mismatch');
    assertGasOnlyNativeDelta(baseline, approval.state, approval.gasCostWei, 'm4_approval');
    const swap = await swapAndVerify(ctx, session, { amount: quote.amount, minimumOutput: quote.minimum, recipient: session.payerAddress, variantId, label: 'm4-usdc-to-weth' });
    if (BigInt(approval.state.payerUsdcUnits) - BigInt(swap.state.payerUsdcUnits) !== quote.amount
        || BigInt(swap.state.payerWethUnits) - BigInt(approval.state.payerWethUnits) !== swap.output
        || swap.state.usdcAllowanceUnits !== quote.amount.toString()
        || swap.state.wethAllowanceUnits !== approval.state.wethAllowanceUnits
        || BigInt(swap.state.poolUsdcUnits) - BigInt(approval.state.poolUsdcUnits) !== quote.amount
        || BigInt(approval.state.poolWethUnits) - BigInt(swap.state.poolWethUnits) !== swap.output) {
      throw new Error('task_native_m4_swap_residual_delta_mismatch');
    }
    assertGasOnlyNativeDelta(approval.state, swap.state, swap.gasCostWei, 'm4_swap');
    const cleanup = await approve(ctx, session, 0n, variantId, 'm4-cleanup-usdc-allowance');
    if (cleanup.state.usdcAllowanceUnits !== '0' || cleanup.state.payerUsdcUnits !== swap.state.payerUsdcUnits
        || cleanup.state.payerWethUnits !== swap.state.payerWethUnits || cleanup.state.wethAllowanceUnits !== swap.state.wethAllowanceUnits
        || cleanup.state.poolUsdcUnits !== swap.state.poolUsdcUnits || cleanup.state.poolWethUnits !== swap.state.poolWethUnits) {
      throw new Error('task_native_m4_cleanup_delta_mismatch');
    }
    assertGasOnlyNativeDelta(swap.state, cleanup.state, cleanup.gasCostWei, 'm4_cleanup');
    result.M4 = {
      schemaVersion: 'bts-m4-exchange-cleanup-reference/v1', classification: 'actual_tool_http_reference_capture_not_bts_acceptance',
      status: 'captured', taskId, environment: { envId: session.envId, generationId: session.generationId, participantId: session.participantId, payerAddress: session.payerAddress },
      objectiveCandidate: {
        inputAssetId: 'USDC', exactInputUnits: quote.amount.toString(), outputAssetId: 'WETH',
        minimumOutputUnits: quote.minimum.toString(), route: { feeTier: 3000, poolAddress: quote.pool.address, poolCodeHash: quote.pool.codeHash },
        maxSlippageBps: quote.slippageBps, quoteAtPinnedSource: quote.quote.toString(),
        ...(quote.publicQuote ? { publicQuote: quote.publicQuote } : {}),
        requiredTemporaryAllowance: { tokenAssetId: 'USDC', spender: router, initialUnits: '0', approvedUnits: approvedUnits.toString(), residualAfterSwapUnits: quote.amount.toString(), finalUnits: '0' },
      },
      actions: {
        approval: { operationId: approval.action.operationId, transactionHash: approval.action.transactionHash, amountUnits: approvedUnits.toString(), gasCostWei: approval.gasCostWei.toString(), persistedCost: approval.persistedCost },
        swap: { operationId: swap.action.operationId, transactionHash: swap.action.transactionHash, feeTier: 3000, poolAddress: quote.pool.address, poolCodeHash: quote.pool.codeHash, amountInUnits: quote.amount.toString(), amountOutMinimumUnits: quote.minimum.toString(), observedWethOutputUnits: swap.output.toString(), gasCostWei: swap.gasCostWei.toString(), persistedCost: swap.persistedCost },
        cleanup: { operationId: cleanup.action.operationId, transactionHash: cleanup.action.transactionHash, tokenAssetId: 'USDC', finalAllowanceUnits: '0', gasCostWei: cleanup.gasCostWei.toString(), persistedCost: cleanup.persistedCost },
      },
      snapshots: { before: snapshotCopy(baseline), afterApproval: snapshotCopy(approval.state), afterSwapResidual: snapshotCopy(swap.state), afterCleanup: snapshotCopy(cleanup.state) },
    };
    captureArtifacts.M4 = await writeCaseCapture(ctx, {
      caseId: taskId, variantId, session, operationId: cleanup.action.operationId,
      capture: result.M4 as Record<string, unknown>, sourceArtifactStart,
    });
  }
  }

  // S4: the positive allowance is an explicitly labelled fixture setup operation,
  // outside the task path. The measured task begins at the setup receipt block.
  if (selectedTasks.has('S4')) {
  {
    const taskId: CaseId = 'S4';
    const variantId = 'bts_s4_allowance_revocation_reference_capture';
    const sourceArtifactStart = ctx.evidence.artifacts.length;
    const session = await newGeneration(ctx, taskId, 'BEF-SC-002', variantId);
    const beforeSetup = await latestState(ctx, session, null, 'task-native-s4-before-setup', variantId);
    const setupAmountUnits = options.s4InitialAllowanceUnits ?? '10000';
    if (!UINT.test(setupAmountUnits) || BigInt(setupAmountUnits) <= 0n) throw new Error('task_native_s4_setup_amount_invalid');
    const setupAmount = BigInt(setupAmountUnits);
    if (beforeSetup.usdcAllowanceUnits !== '0' || beforeSetup.wethAllowanceUnits !== '0' || BigInt(beforeSetup.payerUsdcUnits) < setupAmount) {
      throw new Error('task_native_s4_fixture_baseline_invalid');
    }
    const setup = await approve(ctx, session, setupAmount, variantId, 's4-fixture-setup-approve');
    if (setup.state.usdcAllowanceUnits !== setupAmount.toString() || setup.state.payerUsdcUnits !== beforeSetup.payerUsdcUnits
        || setup.state.payerWethUnits !== beforeSetup.payerWethUnits || setup.state.wethAllowanceUnits !== beforeSetup.wethAllowanceUnits
        || setup.state.poolUsdcUnits !== beforeSetup.poolUsdcUnits || setup.state.poolWethUnits !== beforeSetup.poolWethUnits) {
      throw new Error('task_native_s4_fixture_setup_delta_mismatch');
    }
    assertGasOnlyNativeDelta(beforeSetup, setup.state, setup.gasCostWei, 's4_fixture_setup');
    const taskStart = setup.state;
    if (taskStart.usdcAllowanceUnits !== setupAmount.toString()) throw new Error('task_native_s4_positive_start_allowance_missing');
    await ctx.database.snapshot({
      envId: session.envId, generationId: session.generationId, variantId,
      label: 'task-native-s4-task-start-after-fixture-setup',
    });
    const revoke = await approve(ctx, session, 0n, variantId, 's4-task-revoke-allowance');
    if (revoke.state.usdcAllowanceUnits !== '0') throw new Error('task_native_s4_target_allowance_not_zero');
    assertNoPrincipalOrUnrelatedChanges(taskStart, revoke.state, 's4_revoke');
    assertGasOnlyNativeDelta(taskStart, revoke.state, revoke.gasCostWei, 's4_revoke');
    if (receiptApprovalCount(ctx, revoke.receipt, session.payerAddress, router, 0n, usdc) !== 1) throw new Error('task_native_s4_revoke_event_mismatch');
    result.S4 = {
      schemaVersion: 'bts-s4-allowance-revocation-reference/v1', classification: 'actual_tool_http_reference_capture_not_bts_acceptance',
      status: 'captured', taskId, environment: { envId: session.envId, generationId: session.generationId, participantId: session.participantId, payerAddress: session.payerAddress },
      fixtureSetup: {
        outsideTaskPath: true, action: 'public_approve', tokenAssetId: 'USDC', spender: router, initialAllowanceUnits: '0',
        positiveAllowanceUnits: setupAmount.toString(), operationId: setup.action.operationId, transactionHash: setup.action.transactionHash,
        gasCostWei: setup.gasCostWei.toString(), persistedCost: setup.persistedCost,
      },
      objectiveCandidate: { tokenAssetId: 'USDC', owner: session.payerAddress, spender: router, taskStartAllowanceUnits: setupAmount.toString(), requiredFinalAllowanceUnits: '0' },
      taskPath: { action: 'public_approve_zero', operationId: revoke.action.operationId, transactionHash: revoke.action.transactionHash, finalAllowanceUnits: revoke.state.usdcAllowanceUnits, gasCostWei: revoke.gasCostWei.toString(), persistedCost: revoke.persistedCost },
      snapshots: { beforeSetup: snapshotCopy(beforeSetup), taskStartAfterSetup: snapshotCopy(taskStart), finalAfterRevoke: snapshotCopy(revoke.state) },
    };
    captureArtifacts.S4 = await writeCaseCapture(ctx, {
      caseId: taskId, variantId, session, operationId: revoke.action.operationId,
      capture: result.S4 as Record<string, unknown>, sourceArtifactStart,
    });
  }
  }

  return {
    schemaVersion: 'bts-native-task-reference/v1',
    classification: 'local_fork_public_tool_evidence_not_release_manifest',
    status: 'captured',
    sourceBlock: { number: ctx.runtime.manifest.source.blockNumber, hash: ctx.runtime.manifest.source.blockHash },
    ...(pinnedQuote ? { pinnedFee3000Route: { poolAddress: pinnedQuote.pool.address, poolCodeHash: pinnedQuote.pool.codeHash, feeTier: 3000, quoteAmountInUnits: pinnedQuote.amount.toString(), quoteAmountOutUnits: pinnedQuote.quote.toString(), outputFloorUnits: pinnedQuote.minimum.toString(), maxSlippageBps: pinnedQuote.slippageBps } } : {}),
    captures: result,
    captureArtifacts,
  };
}
