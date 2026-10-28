/**
 * Draft selected-action runtime for BEF-SC-002/007/008.
 *
 * Participant-selected bounded local-chain actions. Private keys stay in the
 * process-scoped signer store; only exact selected inputs and observed effects
 * are persisted.
 */
import { createHash, randomUUID, timingSafeEqual } from 'node:crypto';
import { type FastifyInstance, type FastifyReply, type FastifyRequest } from 'fastify';
import {
  createPublicClient,
  decodeEventLog,
  encodeFunctionData,
  http,
  keccak256,
  MethodNotFoundRpcError,
  parseAbi,
  RpcRequestError,
  TransactionReceiptNotFoundError,
  type Address,
  type Hex,
  type TransactionReceipt,
  type TransactionSerializableEIP1559,
} from 'viem';
import { base } from 'viem/chains';
import { z } from 'zod';
import type { Pool, PoolClient } from 'pg';
import type { RuntimeManifest } from './manifest.js';
import type { RuntimeEnvironment } from './runtime.js';
import { EphemeralSignerStore } from './ephemeral-signer-store.js';

const MAX_UINT256 = (1n << 256n) - 1n;
const ZERO_ADDRESS = '0x0000000000000000000000000000000000000000' as Address;
const UINT_DECIMAL = /^(?:0|[1-9][0-9]{0,77})$/;
const ADDRESS = /^0x[0-9a-f]{40}$/i;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

const ERC20_ABI = parseAbi([
  'function approve(address spender,uint256 amount) returns (bool)',
  'function transfer(address to,uint256 amount) returns (bool)',
  'function allowance(address owner,address spender) view returns (uint256)',
  'function balanceOf(address account) view returns (uint256)',
  'event Approval(address indexed owner,address indexed spender,uint256 value)',
  'event Transfer(address indexed from,address indexed to,uint256 value)',
] as const);
const WETH_ABI = parseAbi([
  'function deposit() payable',
  'function withdraw(uint256 wad)',
  'function balanceOf(address account) view returns (uint256)',
  'event Deposit(address indexed dst,uint256 wad)',
  'event Withdrawal(address indexed src,uint256 wad)',
] as const);
const QUOTER_V2_ABI = parseAbi([
  'function quoteExactInputSingle((address tokenIn,address tokenOut,uint256 amountIn,uint24 fee,uint160 sqrtPriceLimitX96) params) returns (uint256 amountOut,uint160 sqrtPriceX96After,uint32 initializedTicksCrossed,uint256 gasEstimate)',
] as const);
const SWAP_ROUTER_ABI = parseAbi([
  'function exactInputSingle((address tokenIn,address tokenOut,uint24 fee,address recipient,uint256 amountIn,uint256 amountOutMinimum,uint160 sqrtPriceLimitX96) params) payable returns (uint256 amountOut)',
] as const);
const V3_POOL_ABI = parseAbi([
  'function token0() view returns (address)',
  'function token1() view returns (address)',
  'function fee() view returns (uint24)',
  'function slot0() view returns (uint160 sqrtPriceX96,int24 tick,uint16 observationIndex,uint16 observationCardinality,uint16 observationCardinalityNext,uint8 feeProtocol,bool unlocked)',
  'function liquidity() view returns (uint128)',
  'event Swap(address indexed sender,address indexed recipient,int256 amount0,int256 amount1,uint160 sqrtPriceX96,uint128 liquidity,int24 tick)',
] as const);

export type PinnedV3FeeTier = 500 | 3000;

export type SelectedExecutionAction =
  | { kind: 'approve'; tokenAssetId: 'WETH' | 'USDC'; amountUnits: string; gasLimit: string }
  | { kind: 'transfer'; amountUnits: string; recipient: Address; gasLimit: string }
  | { kind: 'wrap'; amountWei: string; gasLimit: string }
  | { kind: 'unwrap'; amountWei: string; gasLimit: string }
  | {
    kind: 'swap'; inputAssetId: 'WETH' | 'USDC'; outputAssetId: 'WETH' | 'USDC';
    amountInUnits: string; amountOutMinimumUnits: string; recipient: Address; gasLimit: string; feeTier?: PinnedV3FeeTier;
  };
export type SelectedAction = SelectedExecutionAction;

export type ParticipantAuth = {
  env: RuntimeEnvironment;
  envId: string;
  generationId: string;
  participantId: string;
  payer: Address;
  idempotencyKey: string;
};

export type OperationRecord = {
  operationId: string;
  requestHash: string;
  status: string;
  transactionHash: Hex | null;
  isNew: boolean;
};

export type ExecutionSnapshot = {
  blockNumber: string;
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

export type ExecutionTransactionObservation = {
  hash: Hex;
  type: string | null;
  chainId: number | null;
  blockHash: Hex | null;
  blockNumber: string | null;
  transactionIndex: string | null;
  from: Address;
  to: Address | null;
  nonce: string;
  input: Hex;
  valueWei: string;
  gasLimit: string;
  maxFeePerGasWei: string | null;
  maxPriorityFeePerGasWei: string | null;
};

export type ExecutionPayerBlockObservation = {
  hash: Hex;
  number: string;
  parentHash: Hex;
  baseFeePerGasWei: string;
  transactions: Array<{ hash: Hex; from: Address }>;
};

export type ExecutionMeasurement = {
  receipt: {
    transactionHash: Hex;
    from: Address;
    to: Address | null;
    status: 'success' | 'reverted';
    blockHash: Hex;
    blockNumber: string;
    gasUsed: string;
    effectiveGasPrice: string;
    gasCostWei: string;
    logs: Array<{
      address: Address;
      topics: readonly Hex[];
      data: Hex;
      logIndex: string | null;
      transactionHash: Hex | null;
      transactionIndex: string | null;
      blockHash: Hex | null;
      blockNumber: string | null;
      removed: boolean;
    }>;
  };
  transaction: ExecutionTransactionObservation;
  payerBlock: ExecutionPayerBlockObservation;
  selectedAction: Record<string, unknown>;
  before: ExecutionSnapshot;
  after: ExecutionSnapshot;
  effects: Record<string, string>;
  quote: Record<string, string> | null;
  fee: {
    modeledGasFeeUsdcUnits: string;
    baseL1Fee: 'unmodelled';
    principalAsset: 'ETH' | 'WETH' | 'USDC' | null;
    selectedPrincipalUnits: string;
    principalUnits: string;
  };
  taskEvaluationInputs: {
    expenseBudgetUsdcUnits: string;
    recipient: Address | null;
    allowanceAssetId: 'WETH' | 'USDC';
    allowanceAfterUnits: string;
    nativeEthReserveWei: string;
    allowanceCleanupExpected: boolean;
    selectedMinimumOutputUnits: string | null;
  };
};

/** The adapter binds the original hash before RPC and stores only the selected
 * action, prestate, unsigned transaction intent, and measured receipt. It never
 * persists keys or signed transaction bytes. */
export interface ExecutionPersistence {
  createOrGet(client: PoolClient, auth: ParticipantAuth, kind: SelectedAction['kind'], requestHash: string, action: SelectedAction): Promise<OperationRecord>;
  saveSelectedInputAndPrestate(client: PoolClient, operationId: string, action: SelectedAction, before: ExecutionSnapshot): Promise<void>;
  bindHashBeforeBroadcast(client: PoolClient, operationId: string, transactionHash: Hex, requestHash: string, intent: ExecutionTransactionObservation): Promise<void>;
  readPending(client: PoolClient, operationId: string): Promise<{ action: SelectedAction; before: ExecutionSnapshot; intent: ExecutionTransactionObservation | null } | null>;
  readCompleted(client: PoolClient, operationId: string): Promise<{ outcome: 'success' | 'reverted'; transactionHash: Hex; measurement: ExecutionMeasurement } | null>;
  rejectBeforeBroadcast(client: PoolClient, operationId: string, reasonCode: string): Promise<void>;
  markUnknown(client: PoolClient, operationId: string, transactionHash: Hex, measurement?: ExecutionMeasurement | null): Promise<void>;
  finish(client: PoolClient, operationId: string, transactionHash: Hex, outcome: 'success' | 'reverted', measurement: ExecutionMeasurement | null): Promise<void>;
}

export type SelectedExecutionDependencies = {
  signerStore: EphemeralSignerStore;
  persistence: ExecutionPersistence;
  /** Fixed server config per environment; never read from a participant request. */
  transactionRpcUrls: ReadonlyMap<string, string>;
};

export type SelectedExecutionRuntime = {
  manifest: RuntimeManifest;
  pool: Pool;
  envs: Map<string, RuntimeEnvironment>;
};

const actionSchemas = {
  approve: z.object({
    tokenAssetId: z.enum(['WETH', 'USDC']).optional(),
    amountUnits: z.string().regex(UINT_DECIMAL),
    gasLimit: z.string().regex(UINT_DECIMAL),
  }).strict(),
  transfer: z.object({ amountUnits: z.string().regex(UINT_DECIMAL), recipient: z.string().regex(ADDRESS), gasLimit: z.string().regex(UINT_DECIMAL) }).strict(),
  wrap: z.object({ amountWei: z.string().regex(UINT_DECIMAL), gasLimit: z.string().regex(UINT_DECIMAL) }).strict(),
  unwrap: z.object({ amountWei: z.string().regex(UINT_DECIMAL), gasLimit: z.string().regex(UINT_DECIMAL) }).strict(),
  swap: z.union([
    z.object({
      inputAssetId: z.enum(['WETH', 'USDC']),
      outputAssetId: z.enum(['WETH', 'USDC']),
      feeTier: z.union([z.literal(500), z.literal(3000)]).optional(),
      amountInUnits: z.string().regex(UINT_DECIMAL),
      amountOutMinimumUnits: z.string().regex(UINT_DECIMAL),
      recipient: z.string().regex(ADDRESS),
      gasLimit: z.string().regex(UINT_DECIMAL),
    }).strict(),
    // Preserve the original WETH->USDC tool input for already deployed probe
    // drivers. New callers select both assets and use denomination-neutral units.
    z.object({
      feeTier: z.union([z.literal(500), z.literal(3000)]).optional(),
      amountInWei: z.string().regex(UINT_DECIMAL),
      amountOutMinimumUsdcUnits: z.string().regex(UINT_DECIMAL),
      recipient: z.string().regex(ADDRESS),
      gasLimit: z.string().regex(UINT_DECIMAL),
    }).strict(),
  ]),
} as const;
const balancesQuerySchema = z.object({}).strict();
const quoteFeeTierQuerySchema = z.preprocess((value) => {
  if (value === '500') return 500;
  if (value === '3000') return 3000;
  return value;
}, z.union([z.literal(500), z.literal(3000)]));
const quoteQuerySchema = z.union([
  z.object({ inputAssetId: z.enum(['WETH', 'USDC']), feeTier: quoteFeeTierQuerySchema.optional(), amountInUnits: z.string().regex(UINT_DECIMAL) }).strict(),
  z.object({ feeTier: quoteFeeTierQuerySchema.optional(), amountInWei: z.string().regex(UINT_DECIMAL) }).strict(),
]);

function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0);
    return `{${entries.map(([key, item]) => `${JSON.stringify(key)}:${canonicalJson(item)}`).join(',')}}`;
  }
  return JSON.stringify(value) ?? 'null';
}

function constantTimeEqual(leftValue: string, rightValue: string): boolean {
  const left = Buffer.from(leftValue);
  const right = Buffer.from(rightValue);
  return left.length === right.length && timingSafeEqual(left, right);
}

function hasReadRequestBody(request: FastifyRequest): boolean {
  const contentLength = request.headers['content-length'];
  if (typeof contentLength === 'string' && /^\d+$/.test(contentLength) && BigInt(contentLength) > 0n) return true;
  if (request.headers['transfer-encoding'] !== undefined || request.body !== undefined) return true;
  return false;
}

function runTokenDigest(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

function decimalValue(value: string): bigint {
  if (!UINT_DECIMAL.test(value)) throw new Error('invalid_decimal');
  const parsed = BigInt(value);
  if (parsed > MAX_UINT256) throw new Error('uint256_out_of_range');
  return parsed;
}

function assetAddress(manifest: RuntimeManifest, assetId: 'WETH' | 'USDC'): Address {
  return assetId === 'WETH' ? manifest.contracts.weth.address as Address : manifest.contracts.usdc.address as Address;
}

export function swapRouteAddresses(
  manifest: RuntimeManifest,
  inputAssetId: 'WETH' | 'USDC',
  outputAssetId: 'WETH' | 'USDC',
  feeTier: PinnedV3FeeTier = 500,
): { tokenIn: Address; tokenOut: Address; fee: PinnedV3FeeTier; poolAddress: Address; poolCodeHash: string } {
  if (inputAssetId === outputAssetId) throw new Error('selected_swap_route_not_permitted');
  const tokenIn = assetAddress(manifest, inputAssetId);
  const tokenOut = assetAddress(manifest, outputAssetId);
  const pinnedPair = new Set([manifest.swap.tokenIn.toLowerCase(), manifest.swap.tokenOut.toLowerCase()]);
  if (!pinnedPair.has(tokenIn.toLowerCase()) || !pinnedPair.has(tokenOut.toLowerCase()) || tokenIn.toLowerCase() === tokenOut.toLowerCase()) {
    throw new Error('selected_swap_route_not_permitted');
  }
  const pool = feeTier === 500 ? manifest.contracts.pool
    : feeTier === 3000 ? manifest.contracts.pool3000 : undefined;
  if (!pool || pool.fee !== feeTier || pool.token0.toLowerCase() !== manifest.contracts.weth.address.toLowerCase() ||
      pool.token1.toLowerCase() !== manifest.contracts.usdc.address.toLowerCase()) {
    throw new Error('selected_swap_route_not_permitted');
  }
  return { tokenIn, tokenOut, fee: feeTier, poolAddress: pool.address as Address, poolCodeHash: pool.codeHash };
}

function maximumSwapInput(manifest: RuntimeManifest, inputAssetId: 'WETH' | 'USDC'): bigint {
  return inputAssetId === 'WETH'
    ? BigInt(manifest.swap.maxAmountIn)
    : BigInt(manifest.funding.maxUsdcUnitsPerGeneration);
}

function validateHardBounds(action: SelectedAction, manifest: RuntimeManifest): void {
  const maxGas = BigInt(manifest.swap.maxTransactionGas);
  const gasLimit = decimalValue(action.gasLimit);
  if (gasLimit === 0n || gasLimit > maxGas) throw new Error('gas_limit_outside_manifest_bound');
  if (action.kind === 'approve') {
    decimalValue(action.amountUnits); // zero is allowed for an explicitly selected allowance cleanup.
  } else if (action.kind === 'transfer') {
    const amount = decimalValue(action.amountUnits);
    if (amount > BigInt(manifest.funding.maxUsdcUnitsPerGeneration)) throw new Error('transfer_amount_outside_fixture_bound');
    if (action.recipient.toLowerCase() === ZERO_ADDRESS.toLowerCase()) throw new Error('recipient_must_be_nonzero');
  } else if (action.kind === 'wrap' || action.kind === 'unwrap') {
    const amount = decimalValue(action.amountWei);
    if (amount === 0n) throw new Error('amount_must_be_positive');
    if (amount > BigInt(manifest.funding.nativeEthWeiPerGeneration)) throw new Error('conversion_amount_outside_fixture_bound');
  } else {
    const { inputAssetId, outputAssetId } = action;
    swapRouteAddresses(manifest, inputAssetId, outputAssetId, action.feeTier ?? 500);
    const amountIn = decimalValue(action.amountInUnits);
    decimalValue(action.amountOutMinimumUnits); // preserve the caller's exact minOut, including zero.
    if (amountIn === 0n || amountIn > maximumSwapInput(manifest, inputAssetId)) throw new Error('swap_amount_outside_manifest_bound');
    if (action.recipient.toLowerCase() === ZERO_ADDRESS.toLowerCase()) throw new Error('recipient_must_be_nonzero');
  }
  // Task goals such as reserve, expense budget, recipient success, allowance
  // cleanup, and minOut quality are measured later. They do not rewrite or
  // reject an otherwise bounded selected action here.
}

export function parseSelectedAction(kind: SelectedAction['kind'], value: unknown): SelectedAction | null {
  switch (kind) {
    case 'approve': {
      const parsed = actionSchemas.approve.safeParse(value);
      return parsed.success ? { kind, tokenAssetId: parsed.data.tokenAssetId ?? 'WETH', amountUnits: parsed.data.amountUnits, gasLimit: parsed.data.gasLimit } : null;
    }
    case 'transfer': {
      const parsed = actionSchemas.transfer.safeParse(value);
      return parsed.success ? { kind, ...parsed.data, recipient: parsed.data.recipient.toLowerCase() as Address } : null;
    }
    case 'wrap': {
      const parsed = actionSchemas.wrap.safeParse(value);
      return parsed.success ? { kind, ...parsed.data } : null;
    }
    case 'unwrap': {
      const parsed = actionSchemas.unwrap.safeParse(value);
      return parsed.success ? { kind, ...parsed.data } : null;
    }
    case 'swap': {
      const parsed = actionSchemas.swap.safeParse(value);
      if (!parsed.success) return null;
      if ('inputAssetId' in parsed.data) {
        if (parsed.data.inputAssetId === parsed.data.outputAssetId) return null;
        return {
          kind,
          inputAssetId: parsed.data.inputAssetId,
          outputAssetId: parsed.data.outputAssetId,
          feeTier: parsed.data.feeTier ?? 500,
          amountInUnits: parsed.data.amountInUnits,
          amountOutMinimumUnits: parsed.data.amountOutMinimumUnits,
          recipient: parsed.data.recipient.toLowerCase() as Address,
          gasLimit: parsed.data.gasLimit,
        };
      }
      // Address casing is not part of the selected destination. Canonicalize
      // hex casing so any valid 20-byte address spelling is accepted by viem.
      return {
        kind,
        feeTier: parsed.data.feeTier ?? 500,
        inputAssetId: 'WETH',
        outputAssetId: 'USDC',
        amountInUnits: parsed.data.amountInWei,
        amountOutMinimumUnits: parsed.data.amountOutMinimumUsdcUnits,
        recipient: parsed.data.recipient.toLowerCase() as Address,
        gasLimit: parsed.data.gasLimit,
      };
    }
  }
}

function rpcErrorUnavailable(error: unknown): boolean {
  if (!(error instanceof MethodNotFoundRpcError) || error.code !== -32601) return false;
  return error.cause instanceof RpcRequestError && error.cause.code === -32601;
}

async function waitForOriginalReceipt(client: LocalObserverClient, hash: Hex, timeoutMs: number): Promise<TransactionReceipt> {
  const deadline = Date.now() + timeoutMs;
  while (true) {
    try {
      return await client.getTransactionReceipt({ hash }) as TransactionReceipt;
    } catch (error) {
      // AICODE-NOTE: Only retry the same persisted hash after the two receipt
      // visibility failures observed on the private Anvil fork. No replacement
      // transaction or new nonce is created here.
      if (!(error instanceof TransactionReceiptNotFoundError) && !rpcErrorUnavailable(error)) throw new Error('original_receipt_lookup_failed');
      const remaining = deadline - Date.now();
      if (remaining <= 0) throw new Error('original_receipt_unavailable');
      await new Promise<void>((resolve) => setTimeout(resolve, Math.min(250, remaining)));
    }
  }
}

function safeMessageCode(error: unknown): string {
  if (error instanceof Error && error.message === 'original_receipt_unavailable') return 'original_receipt_unavailable';
  if (error instanceof Error && error.message === 'original_receipt_lookup_failed') return 'original_receipt_lookup_failed';
  return 'execution_observation_unknown';
}

function safeAction(action: SelectedAction, manifest: RuntimeManifest): Record<string, unknown> {
  switch (action.kind) {
    case 'approve': return {
      kind: action.kind,
      tokenAssetId: action.tokenAssetId,
      token: assetAddress(manifest, action.tokenAssetId),
      spender: manifest.contracts.swapRouter02.address,
      amountUnits: action.amountUnits,
      gasLimit: action.gasLimit,
    };
    case 'transfer': return {
      kind: action.kind,
      token: manifest.contracts.usdc.address,
      amountUnits: action.amountUnits,
      recipient: action.recipient,
      gasLimit: action.gasLimit,
    };
    case 'wrap': return { kind: action.kind, amountWei: action.amountWei, gasLimit: action.gasLimit };
    case 'unwrap': return { kind: action.kind, amountWei: action.amountWei, gasLimit: action.gasLimit };
    case 'swap': {
      const route = swapRouteAddresses(manifest, action.inputAssetId, action.outputAssetId, action.feeTier ?? 500);
      // Keep the historical idempotency hash for the legacy WETH->USDC fee-500
      // request. Existing operations can still be replayed after an API upgrade.
      if (route.fee === 500 && action.inputAssetId === 'WETH' && action.outputAssetId === 'USDC') return {
        kind: action.kind,
        route: 'uniswap-v3-exactInputSingle',
        router: manifest.contracts.swapRouter02.address,
        tokenIn: manifest.swap.tokenIn,
        tokenOut: manifest.swap.tokenOut,
        fee: manifest.swap.fee,
        amountInWei: action.amountInUnits,
        amountOutMinimumUsdcUnits: action.amountOutMinimumUnits,
        recipient: action.recipient,
        gasLimit: action.gasLimit,
      };
      return {
        kind: action.kind,
        route: 'uniswap-v3-exactInputSingle',
        router: manifest.contracts.swapRouter02.address,
        inputAssetId: action.inputAssetId,
        outputAssetId: action.outputAssetId,
        tokenIn: route.tokenIn,
        tokenOut: route.tokenOut,
        fee: route.fee,
        ...(route.fee === 3000 ? { poolAddress: route.poolAddress, poolCodeHash: route.poolCodeHash } : {}),
        amountInUnits: action.amountInUnits,
        amountOutMinimumUnits: action.amountOutMinimumUnits,
        recipient: action.recipient,
        gasLimit: action.gasLimit,
      };
    }
  }
}

async function authorizeParticipant(
  runtime: SelectedExecutionRuntime,
  request: FastifyRequest,
  reply: FastifyReply,
): Promise<ParticipantAuth | null> {
  const envIdValue = (request.params as { envId?: unknown }).envId;
  if (typeof envIdValue !== 'string' || envIdValue.length === 0) {
    await reply.code(404).send({ error: 'environment_not_found' });
    return null;
  }
  const envId = envIdValue;
  const env = runtime.envs.get(envId);
  if (!env) {
    await reply.code(404).send({ error: 'environment_not_found' });
    return null;
  }
  const authorization = request.headers.authorization;
  const generationId = request.headers['x-bef-generation'];
  const idempotencyKey = request.headers['idempotency-key'];
  const bearer = typeof authorization === 'string' ? /^Bearer ([A-Za-z0-9_-]{32,128})$/.exec(authorization) : null;
  if (!bearer || typeof generationId !== 'string' || !UUID.test(generationId) ||
      typeof idempotencyKey !== 'string' || idempotencyKey.length < 16 || idempotencyKey.length > 128) {
    await reply.code(401).send({ error: 'scoped_authentication_required' });
    return null;
  }
  const result = await runtime.pool.query<{
    participant_id: string;
    payer_address: string;
    run_token_sha256: string;
  }>(
    `SELECT participant_id,payer_address,run_token_sha256
       FROM bef_generation
      WHERE env_id=$1 AND generation_id=$2 AND status='active' AND expires_at>clock_timestamp()`,
    [envId, generationId],
  );
  const generation = result.rows[0];
  if (!generation || !ADDRESS.test(generation.payer_address) || !constantTimeEqual(runTokenDigest(bearer[1]!), generation.run_token_sha256)) {
    await reply.code(403).send({ error: 'generation_scope_denied' });
    return null;
  }
  return {
    env,
    envId,
    generationId,
    participantId: generation.participant_id,
    payer: generation.payer_address as Address,
    idempotencyKey,
  };
}

async function withEnvironmentLock<T>(pool: Pool, envId: string, waitMs: number, work: (client: PoolClient) => Promise<T>): Promise<T> {
  const deadline = Date.now() + waitMs;
  while (true) {
    const client = await pool.connect();
    let locked = false;
    try {
      const result = await client.query<{ locked: boolean }>(
        `SELECT pg_try_advisory_lock(hashtext('bef-runtime-environment'), hashtext($1)) AS locked`,
        [envId],
      );
      locked = result.rows[0]?.locked === true;
      if (locked) return await work(client);
    } finally {
      if (locked) await client.query(`SELECT pg_advisory_unlock(hashtext('bef-runtime-environment'), hashtext($1))`, [envId]).catch(() => undefined);
      client.release();
    }
    const remaining = deadline - Date.now();
    if (remaining <= 0) throw new Error('environment_lock_timeout');
    await new Promise<void>((resolve) => setTimeout(resolve, Math.min(50, remaining)));
  }
}

async function sendOnlyLocalTransaction(writeRpcUrl: string, serializedTransaction: Hex, expectedHash: Hex): Promise<void> {
  const response = await fetch(writeRpcUrl, {
    method: 'POST',
    redirect: 'error',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'eth_sendRawTransaction', params: [serializedTransaction] }),
    signal: AbortSignal.timeout(15_000),
  });
  if (!response.ok) throw new Error('transaction_submission_outcome_unknown');
  const body = await response.json() as { id?: unknown; result?: unknown; error?: unknown };
  if (body.id !== 1 || body.error || typeof body.result !== 'string' || body.result.toLowerCase() !== expectedHash.toLowerCase()) {
    throw new Error('transaction_submission_outcome_unknown');
  }
}

function localObserver(auth: ParticipantAuth) {
  const observerUrl = auth.env.observerRpcUrl;
  if (!observerUrl) throw new Error('local_readonly_observer_unavailable');
  const parsed = new URL(observerUrl);
  if ((parsed.protocol !== 'http:' && parsed.protocol !== 'https:') || parsed.username || parsed.password || parsed.search || parsed.hash) {
    throw new Error('local_readonly_observer_unavailable');
  }
  return createPublicClient({ chain: base, transport: http(observerUrl, { timeout: 15_000, retryCount: 0 }) });
}

type LocalObserverClient = ReturnType<typeof localObserver>;

function assertWriteEndpoint(url: string, declaredAdminUrl: string): void {
  const parsed = new URL(url);
  if (url !== declaredAdminUrl || (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') || parsed.username || parsed.password ||
      (parsed.pathname !== '' && parsed.pathname !== '/') || parsed.search || parsed.hash || url.includes('?') || url.includes('#')) {
    throw new Error('local_transaction_endpoint_invalid');
  }
}

async function readSnapshot(
  client: LocalObserverClient,
  manifest: RuntimeManifest,
  payer: Address,
  recipient: Address,
  blockNumber: bigint,
  selectedPoolAddress: Address = manifest.contracts.pool.address as Address,
): Promise<ExecutionSnapshot> {
  const weth = manifest.contracts.weth.address as Address;
  const usdc = manifest.contracts.usdc.address as Address;
  const router = manifest.contracts.swapRouter02.address as Address;
  const pool = selectedPoolAddress;
  const [native, payerWeth, payerUsdc, recipientWeth, recipientUsdc, wethAllowance, usdcAllowance, poolWeth, poolUsdc, poolLiquidity, poolSlot0] = await Promise.all([
    client.getBalance({ address: payer, blockNumber }),
    client.readContract({ address: weth, abi: WETH_ABI, functionName: 'balanceOf', args: [payer], blockNumber }),
    client.readContract({ address: usdc, abi: ERC20_ABI, functionName: 'balanceOf', args: [payer], blockNumber }),
    client.readContract({ address: weth, abi: WETH_ABI, functionName: 'balanceOf', args: [recipient], blockNumber }),
    client.readContract({ address: usdc, abi: ERC20_ABI, functionName: 'balanceOf', args: [recipient], blockNumber }),
    client.readContract({ address: weth, abi: ERC20_ABI, functionName: 'allowance', args: [payer, router], blockNumber }),
    client.readContract({ address: usdc, abi: ERC20_ABI, functionName: 'allowance', args: [payer, router], blockNumber }),
    client.readContract({ address: weth, abi: WETH_ABI, functionName: 'balanceOf', args: [pool], blockNumber }),
    client.readContract({ address: usdc, abi: ERC20_ABI, functionName: 'balanceOf', args: [pool], blockNumber }),
    client.readContract({ address: pool, abi: V3_POOL_ABI, functionName: 'liquidity', blockNumber }),
    client.readContract({ address: pool, abi: V3_POOL_ABI, functionName: 'slot0', blockNumber }) as Promise<readonly [bigint, number, number, number, number, number, boolean]>,
  ]);
  return {
    blockNumber: blockNumber.toString(),
    payerNativeWei: native.toString(),
    payerWethUnits: payerWeth.toString(),
    payerUsdcUnits: payerUsdc.toString(),
    recipientWethUnits: recipientWeth.toString(),
    recipientUsdcUnits: recipientUsdc.toString(),
    wethRouterAllowance: wethAllowance.toString(),
    usdcRouterAllowance: usdcAllowance.toString(),
    poolWethUnits: poolWeth.toString(),
    poolUsdcUnits: poolUsdc.toString(),
    poolLiquidity: poolLiquidity.toString(),
    poolSqrtPriceX96: poolSlot0[0].toString(),
  };
}

type QuoteObservation = {
  feeTier: PinnedV3FeeTier;
  poolAddress: Address;
  poolCodeHash: string;
  inputAssetId: 'WETH' | 'USDC';
  outputAssetId: 'WETH' | 'USDC';
  amountInUnits: string;
  amountOutUnits: string;
  sqrtPriceX96After: string;
  initializedTicksCrossed: string;
  gasEstimate: string;
  blockNumber: string;
  poolLiquidity: string;
  poolSqrtPriceX96: string;
};

async function quoteAtBlock(
  client: LocalObserverClient,
  manifest: RuntimeManifest,
  amountIn: bigint,
  blockNumber: bigint,
  inputAssetId: 'WETH' | 'USDC' = 'WETH',
  outputAssetId: 'WETH' | 'USDC' = inputAssetId === 'WETH' ? 'USDC' : 'WETH',
  feeTier: PinnedV3FeeTier = 500,
): Promise<QuoteObservation | null> {
  try {
    const route = swapRouteAddresses(manifest, inputAssetId, outputAssetId, feeTier);
    const result = await client.readContract({
      address: manifest.contracts.quoterV2.address as Address,
      abi: QUOTER_V2_ABI,
      functionName: 'quoteExactInputSingle',
      args: [{
        tokenIn: route.tokenIn,
        tokenOut: route.tokenOut,
        amountIn,
        fee: route.fee,
        sqrtPriceLimitX96: 0n,
      }],
      blockNumber,
    }) as readonly [bigint, bigint, number, bigint];
    const [slot0, liquidity] = await Promise.all([
      client.readContract({ address: route.poolAddress, abi: V3_POOL_ABI, functionName: 'slot0', blockNumber }) as Promise<readonly [bigint, number, number, number, number, number, boolean]>,
      client.readContract({ address: route.poolAddress, abi: V3_POOL_ABI, functionName: 'liquidity', blockNumber }),
    ]);
    return {
      feeTier,
      poolAddress: route.poolAddress,
      poolCodeHash: route.poolCodeHash,
      inputAssetId,
      outputAssetId,
      amountInUnits: amountIn.toString(),
      amountOutUnits: result[0].toString(),
      sqrtPriceX96After: result[1].toString(),
      initializedTicksCrossed: result[2].toString(),
      gasEstimate: result[3].toString(),
      blockNumber: blockNumber.toString(),
      poolLiquidity: liquidity.toString(),
      poolSqrtPriceX96: slot0[0].toString(),
    };
  } catch {
    // A quote failure is measured as an unavailable simulation. It never
    // rewrites a selected swap or blocks the actual contract execution.
    return null;
  }
}

type TransactionCall = { to: Address; data: Hex; value: bigint };

function transactionCall(action: SelectedAction, manifest: RuntimeManifest, payer: Address): TransactionCall {
  const weth = manifest.contracts.weth.address as Address;
  switch (action.kind) {
    case 'approve':
      return {
        to: assetAddress(manifest, action.tokenAssetId),
        data: encodeFunctionData({
          abi: ERC20_ABI,
          functionName: 'approve',
          args: [manifest.contracts.swapRouter02.address as Address, decimalValue(action.amountUnits)],
        }),
        value: 0n,
      };
    case 'transfer':
      return {
        to: manifest.contracts.usdc.address as Address,
        data: encodeFunctionData({
          abi: ERC20_ABI,
          functionName: 'transfer',
          args: [action.recipient, decimalValue(action.amountUnits)],
        }),
        value: 0n,
      };
    case 'wrap':
      return {
        to: weth,
        data: encodeFunctionData({ abi: WETH_ABI, functionName: 'deposit' }),
        value: decimalValue(action.amountWei),
      };
    case 'unwrap':
      return {
        to: weth,
        data: encodeFunctionData({ abi: WETH_ABI, functionName: 'withdraw', args: [decimalValue(action.amountWei)] }),
        value: 0n,
      };
    case 'swap':
      {
      const route = swapRouteAddresses(manifest, action.inputAssetId, action.outputAssetId, action.feeTier ?? 500);
      return {
        to: manifest.contracts.swapRouter02.address as Address,
        data: encodeFunctionData({
          abi: SWAP_ROUTER_ABI,
          functionName: 'exactInputSingle',
          args: [{
            tokenIn: route.tokenIn,
            tokenOut: route.tokenOut,
            fee: route.fee,
            recipient: action.recipient,
            amountIn: decimalValue(action.amountInUnits),
            // Keep the selected threshold exactly as submitted. The quote is
            // evidence only; maxSlippageBps never rewrites this value.
            amountOutMinimum: decimalValue(action.amountOutMinimumUnits),
            sqrtPriceLimitX96: 0n,
          }],
        }),
        value: 0n,
      };
      }
  }
}

function decodeApproval(receipt: TransactionReceipt, token: Address, owner: Address, spender: Address, amount: bigint): boolean {
  return receipt.logs.some((log) => {
    if (log.address.toLowerCase() !== token.toLowerCase()) return false;
    try {
      const event = decodeEventLog({ abi: ERC20_ABI, eventName: 'Approval', topics: log.topics, data: log.data }) as { args: unknown };
      const args = event.args as { owner: Address; spender: Address; value: bigint };
      return args.owner.toLowerCase() === owner.toLowerCase() && args.spender.toLowerCase() === spender.toLowerCase() && args.value === amount;
    } catch { return false; }
  });
}

function decodeTransfer(receipt: TransactionReceipt, token: Address, from: Address, to: Address, amount: bigint): boolean {
  const matches = receipt.logs.filter((log) => {
    if (log.address.toLowerCase() !== token.toLowerCase()) return false;
    try {
      const event = decodeEventLog({ abi: ERC20_ABI, eventName: 'Transfer', topics: log.topics, data: log.data }) as { args: unknown };
      const args = event.args as { from: Address; to: Address; value: bigint };
      return args.from.toLowerCase() === from.toLowerCase() &&
        args.to.toLowerCase() === to.toLowerCase() && args.value === amount;
    } catch { return false; }
  });
  return matches.length === 1;
}

function decodeWethEvent(receipt: TransactionReceipt, weth: Address, eventName: 'Deposit' | 'Withdrawal', owner: Address, amount: bigint): boolean {
  return receipt.logs.some((log) => {
    if (log.address.toLowerCase() !== weth.toLowerCase()) return false;
    try {
      if (eventName === 'Deposit') {
        const event = decodeEventLog({ abi: WETH_ABI, eventName: 'Deposit', topics: log.topics, data: log.data }) as { args: unknown };
        const args = event.args as { dst: Address; wad: bigint };
        return args.dst.toLowerCase() === owner.toLowerCase() && args.wad === amount;
      }
      const event = decodeEventLog({ abi: WETH_ABI, eventName: 'Withdrawal', topics: log.topics, data: log.data }) as { args: unknown };
      const args = event.args as { src: Address; wad: bigint };
      return args.src.toLowerCase() === owner.toLowerCase() && args.wad === amount;
    } catch { return false; }
  });
}

function decodeSwap(receipt: TransactionReceipt, manifest: RuntimeManifest, action: Extract<SelectedAction, { kind: 'swap' }>, payer: Address): { amountIn: bigint; amountOut: bigint } | null {
  const route = swapRouteAddresses(manifest, action.inputAssetId, action.outputAssetId, action.feeTier ?? 500);
  const pool = route.poolAddress.toLowerCase();
  const poolSwap = receipt.logs.filter((log) => log.address.toLowerCase() === pool).flatMap((log) => {
    try {
      const event = decodeEventLog({ abi: V3_POOL_ABI, eventName: 'Swap', topics: log.topics, data: log.data }) as { args: unknown };
      return [event.args as { sender: Address; recipient: Address; amount0: bigint; amount1: bigint }];
    } catch { return []; }
  });
  if (poolSwap.length !== 1) return null;
  const swap = poolSwap[0]!;
  const router = manifest.contracts.swapRouter02.address.toLowerCase();
  if (swap.sender.toLowerCase() !== router || swap.recipient.toLowerCase() !== action.recipient.toLowerCase()) return null;
  const amountInSigned = action.inputAssetId === 'WETH' ? swap.amount0 : swap.amount1;
  const amountOutSigned = action.outputAssetId === 'WETH' ? swap.amount0 : swap.amount1;
  const selectedMaximumInput = BigInt(action.amountInUnits);
  if (amountInSigned <= 0n || amountInSigned > selectedMaximumInput || amountOutSigned >= 0n) return null;
  const amountIn = amountInSigned;
  const amountOut = -amountOutSigned;
  if (amountOut < BigInt(action.amountOutMinimumUnits)) return null;

  const transferMatches = (token: Address, from: Address, to: Address, amount: bigint): number => receipt.logs.filter((log) => {
    if (log.address.toLowerCase() !== token.toLowerCase()) return false;
    try {
      const event = decodeEventLog({ abi: ERC20_ABI, eventName: 'Transfer', topics: log.topics, data: log.data }) as { args: unknown };
      const args = event.args as { from: Address; to: Address; value: bigint };
      return args.from.toLowerCase() === from.toLowerCase() && args.to.toLowerCase() === to.toLowerCase() && args.value === amount;
    } catch { return false; }
  }).length;
  const poolAddress = route.poolAddress;
  if (transferMatches(route.tokenIn, payer, poolAddress, amountIn) !== 1 ||
      transferMatches(route.tokenOut, poolAddress, action.recipient, amountOut) !== 1) return null;
  return { amountIn, amountOut };
}

type ExecutionDeltas = {
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

function deltas(before: ExecutionSnapshot, after: ExecutionSnapshot): ExecutionDeltas {
  return {
    payerNativeWei: (BigInt(after.payerNativeWei) - BigInt(before.payerNativeWei)).toString(),
    payerWethUnits: (BigInt(after.payerWethUnits) - BigInt(before.payerWethUnits)).toString(),
    payerUsdcUnits: (BigInt(after.payerUsdcUnits) - BigInt(before.payerUsdcUnits)).toString(),
    recipientWethUnits: (BigInt(after.recipientWethUnits) - BigInt(before.recipientWethUnits)).toString(),
    recipientUsdcUnits: (BigInt(after.recipientUsdcUnits) - BigInt(before.recipientUsdcUnits)).toString(),
    wethRouterAllowance: (BigInt(after.wethRouterAllowance) - BigInt(before.wethRouterAllowance)).toString(),
    usdcRouterAllowance: (BigInt(after.usdcRouterAllowance) - BigInt(before.usdcRouterAllowance)).toString(),
    poolWethUnits: (BigInt(after.poolWethUnits) - BigInt(before.poolWethUnits)).toString(),
    poolUsdcUnits: (BigInt(after.poolUsdcUnits) - BigInt(before.poolUsdcUnits)).toString(),
    poolLiquidity: (BigInt(after.poolLiquidity) - BigInt(before.poolLiquidity)).toString(),
    poolSqrtPriceX96: (BigInt(after.poolSqrtPriceX96) - BigInt(before.poolSqrtPriceX96)).toString(),
  };
}

export function validateActionEffects(
  action: SelectedAction,
  receipt: TransactionReceipt,
  before: ExecutionSnapshot,
  after: ExecutionSnapshot,
  payer: Address,
  manifest: RuntimeManifest,
): boolean {
  const effect = deltas(before, after);
  const gasCost = receipt.gasUsed * receipt.effectiveGasPrice;
  if (receipt.from.toLowerCase() !== payer.toLowerCase()) return false;
  if (receipt.status === 'reverted') {
    return BigInt(effect.payerNativeWei) === -gasCost &&
      Object.entries(before).every(([key, value]) => key === 'payerNativeWei' || after[key as keyof ExecutionSnapshot] === value);
  }
  if (receipt.status !== 'success') return false;
  if (action.kind === 'approve') {
    const token = assetAddress(manifest, action.tokenAssetId);
    const selectedAllowance = action.tokenAssetId === 'WETH' ? after.wethRouterAllowance : after.usdcRouterAllowance;
    const selectedAllowanceDelta = action.tokenAssetId === 'WETH' ? effect.wethRouterAllowance : effect.usdcRouterAllowance;
    const otherAllowanceDelta = action.tokenAssetId === 'WETH' ? effect.usdcRouterAllowance : effect.wethRouterAllowance;
    return receipt.to?.toLowerCase() === token.toLowerCase() &&
      BigInt(effect.payerNativeWei) === -gasCost &&
      BigInt(effect.payerWethUnits) === 0n && BigInt(effect.payerUsdcUnits) === 0n &&
      BigInt(selectedAllowanceDelta) === BigInt(action.amountUnits) - BigInt(action.tokenAssetId === 'WETH' ? before.wethRouterAllowance : before.usdcRouterAllowance) &&
      BigInt(otherAllowanceDelta) === 0n && BigInt(selectedAllowance) === BigInt(action.amountUnits) &&
      BigInt(effect.recipientWethUnits) === 0n && BigInt(effect.recipientUsdcUnits) === 0n &&
      BigInt(effect.poolWethUnits) === 0n && BigInt(effect.poolUsdcUnits) === 0n &&
      decodeApproval(receipt, token, payer, manifest.contracts.swapRouter02.address as Address, BigInt(action.amountUnits));
  }
  if (action.kind === 'wrap') {
    const amount = BigInt(action.amountWei);
    return receipt.to?.toLowerCase() === manifest.contracts.weth.address.toLowerCase() &&
      BigInt(effect.payerWethUnits) === amount && BigInt(effect.payerNativeWei) === -(amount + gasCost) &&
      BigInt(effect.payerUsdcUnits) === 0n && BigInt(effect.wethRouterAllowance) === 0n && BigInt(effect.usdcRouterAllowance) === 0n &&
      BigInt(effect.recipientUsdcUnits) === 0n &&
      BigInt(effect.poolWethUnits) === 0n && BigInt(effect.poolUsdcUnits) === 0n &&
      decodeWethEvent(receipt, manifest.contracts.weth.address as Address, 'Deposit', payer, amount);
  }
  if (action.kind === 'unwrap') {
    const amount = BigInt(action.amountWei);
    return receipt.to?.toLowerCase() === manifest.contracts.weth.address.toLowerCase() &&
      BigInt(effect.payerWethUnits) === -amount && BigInt(effect.payerNativeWei) === amount - gasCost &&
      BigInt(effect.payerUsdcUnits) === 0n && BigInt(effect.wethRouterAllowance) === 0n && BigInt(effect.usdcRouterAllowance) === 0n &&
      BigInt(effect.recipientUsdcUnits) === 0n &&
      BigInt(effect.poolWethUnits) === 0n && BigInt(effect.poolUsdcUnits) === 0n &&
      decodeWethEvent(receipt, manifest.contracts.weth.address as Address, 'Withdrawal', payer, amount);
  }
  if (action.kind === 'transfer') {
    const amount = BigInt(action.amountUnits);
    const recipient = action.recipient.toLowerCase();
    const recipientIsPayer = recipient === payer.toLowerCase();
    const recipientIsPool = recipient === manifest.contracts.pool.address.toLowerCase();
    return receipt.to?.toLowerCase() === manifest.contracts.usdc.address.toLowerCase() &&
      BigInt(effect.payerNativeWei) === -gasCost &&
      BigInt(effect.payerWethUnits) === 0n &&
      BigInt(effect.payerUsdcUnits) === (recipientIsPayer ? 0n : -amount) &&
      BigInt(effect.recipientUsdcUnits) === (recipientIsPayer ? 0n : amount) &&
      BigInt(effect.recipientWethUnits) === 0n &&
      BigInt(effect.wethRouterAllowance) === 0n &&
      BigInt(effect.usdcRouterAllowance) === 0n &&
      BigInt(effect.poolWethUnits) === 0n &&
      BigInt(effect.poolUsdcUnits) === (recipientIsPool ? amount : 0n) &&
      decodeTransfer(receipt, manifest.contracts.usdc.address as Address, payer, action.recipient, amount);
  }
  if (receipt.to?.toLowerCase() !== manifest.contracts.swapRouter02.address.toLowerCase()) return false;
  const swap = decodeSwap(receipt, manifest, action, payer);
  if (!swap) return false;
  const recipientIsPayer = action.recipient.toLowerCase() === payer.toLowerCase();
  const inputIsWeth = action.inputAssetId === 'WETH';
  const outputIsWeth = action.outputAssetId === 'WETH';
  const expectedPayerWethDelta = (inputIsWeth ? -swap.amountIn : 0n) +
    (recipientIsPayer && outputIsWeth ? swap.amountOut : 0n);
  const expectedPayerUsdcDelta = (!inputIsWeth ? -swap.amountIn : 0n) +
    (recipientIsPayer && !outputIsWeth ? swap.amountOut : 0n);
  const expectedRecipientWethDelta = (outputIsWeth ? swap.amountOut : 0n) -
    (recipientIsPayer && inputIsWeth ? swap.amountIn : 0n);
  const expectedRecipientUsdcDelta = (!outputIsWeth ? swap.amountOut : 0n) -
    (recipientIsPayer && !inputIsWeth ? swap.amountIn : 0n);
  const beforeAllowance = BigInt(inputIsWeth ? before.wethRouterAllowance : before.usdcRouterAllowance);
  const expectedAllowanceAfter = beforeAllowance === MAX_UINT256 ? MAX_UINT256 : beforeAllowance - swap.amountIn;
  const afterInputAllowance = BigInt(inputIsWeth ? after.wethRouterAllowance : after.usdcRouterAllowance);
  const otherAllowanceDelta = BigInt(inputIsWeth ? effect.usdcRouterAllowance : effect.wethRouterAllowance);
  const expectedPoolWethDelta = inputIsWeth ? swap.amountIn : -swap.amountOut;
  const expectedPoolUsdcDelta = inputIsWeth ? -swap.amountOut : swap.amountIn;
  return beforeAllowance >= swap.amountIn &&
    BigInt(effect.payerWethUnits) === expectedPayerWethDelta &&
    BigInt(effect.payerUsdcUnits) === expectedPayerUsdcDelta &&
    BigInt(effect.recipientWethUnits) === expectedRecipientWethDelta &&
    BigInt(effect.recipientUsdcUnits) === expectedRecipientUsdcDelta &&
    afterInputAllowance === expectedAllowanceAfter && otherAllowanceDelta === 0n &&
    BigInt(effect.payerNativeWei) === -gasCost &&
    BigInt(effect.poolWethUnits) === expectedPoolWethDelta && BigInt(effect.poolUsdcUnits) === expectedPoolUsdcDelta;
}

export function principalAccountingForMeasurement(
  action: SelectedAction,
  receiptStatus: 'success' | 'reverted',
): { selectedPrincipalUnits: string; principalUnits: string } {
  const selectedPrincipalUnits = action.kind === 'wrap' || action.kind === 'unwrap' ? action.amountWei
    : action.kind === 'swap' ? action.amountInUnits
      : action.kind === 'transfer' ? action.amountUnits : '0';
  return {
    selectedPrincipalUnits,
    principalUnits: receiptStatus === 'success' ? selectedPrincipalUnits : '0',
  };
}

function measurementFor(
  action: SelectedAction,
  manifest: RuntimeManifest,
  transaction: ExecutionTransactionObservation,
  receipt: TransactionReceipt,
  before: ExecutionSnapshot,
  after: ExecutionSnapshot,
  quote: QuoteObservation | null,
  recipient: Address,
  payerBlock: ExecutionPayerBlockObservation,
): ExecutionMeasurement {
  const gasCostWei = receipt.gasUsed * receipt.effectiveGasPrice;
  const modeledGasFeeUsdcUnits = gasCostWei * BigInt(manifest.feePolicy.ethUsdcRateNumerator) /
    BigInt(manifest.feePolicy.ethUsdcRateDenominator);
  const principalAsset = action.kind === 'wrap' ? 'ETH' : action.kind === 'unwrap' ? 'WETH' : action.kind === 'swap' ? action.inputAssetId : action.kind === 'transfer' ? 'USDC' : null;
  const { selectedPrincipalUnits, principalUnits } = principalAccountingForMeasurement(action, receipt.status);
  return {
    receipt: {
      transactionHash: receipt.transactionHash,
      from: receipt.from,
      to: receipt.to,
      status: receipt.status,
      blockHash: receipt.blockHash,
      blockNumber: receipt.blockNumber.toString(),
      gasUsed: receipt.gasUsed.toString(),
      effectiveGasPrice: receipt.effectiveGasPrice.toString(),
      gasCostWei: gasCostWei.toString(),
      logs: receipt.logs.map((log) => ({
        address: log.address,
        topics: log.topics,
        data: log.data,
        logIndex: log.logIndex?.toString() ?? null,
        transactionHash: log.transactionHash ?? null,
        transactionIndex: log.transactionIndex?.toString() ?? null,
        blockHash: log.blockHash ?? null,
        blockNumber: log.blockNumber?.toString() ?? null,
        removed: log.removed,
      })),
    },
    transaction,
    payerBlock,
    selectedAction: safeAction(action, manifest),
    before,
    after,
    effects: deltas(before, after),
    quote: quote ? { ...quote, feeTier: quote.feeTier.toString() } : null,
    fee: {
      modeledGasFeeUsdcUnits: modeledGasFeeUsdcUnits.toString(),
      baseL1Fee: 'unmodelled',
      principalAsset,
      selectedPrincipalUnits,
      principalUnits,
    },
    taskEvaluationInputs: {
      expenseBudgetUsdcUnits: manifest.taskGoal.expenseBudgetUsdcUnits,
      recipient: action.kind === 'swap' || action.kind === 'transfer' ? recipient : null,
      allowanceAssetId: action.kind === 'approve' ? action.tokenAssetId : action.kind === 'swap' ? action.inputAssetId : 'WETH',
      allowanceAfterUnits: action.kind === 'approve'
        ? action.tokenAssetId === 'WETH' ? after.wethRouterAllowance : after.usdcRouterAllowance
        : action.kind === 'swap'
          ? action.inputAssetId === 'WETH' ? after.wethRouterAllowance : after.usdcRouterAllowance
          : after.wethRouterAllowance,
      nativeEthReserveWei: manifest.taskGoal.nativeEthReserveWei,
      allowanceCleanupExpected: manifest.taskGoal.allowanceCleanupExpected,
      selectedMinimumOutputUnits: action.kind === 'swap' ? action.amountOutMinimumUnits : null,
    },
  };
}

async function withTransaction<T>(client: PoolClient, work: () => Promise<T>): Promise<T> {
  await client.query('BEGIN');
  try {
    const result = await work();
    await client.query('COMMIT');
    return result;
  } catch (error) {
    await client.query('ROLLBACK').catch(() => undefined);
    throw error;
  }
}

async function requireActiveGeneration(client: PoolClient, auth: ParticipantAuth): Promise<void> {
  const active = await client.query(
    `SELECT 1 FROM bef_generation WHERE env_id=$1 AND generation_id=$2 AND status='active'
       AND expires_at>clock_timestamp() FOR UPDATE`,
    [auth.envId, auth.generationId],
  );
  if (!active.rowCount) throw new Error('generation_fenced');
}

function actionRecipient(action: SelectedAction, payer: Address): Address {
  return action.kind === 'swap' || action.kind === 'transfer' ? action.recipient : payer;
}

function localTxUrl(dependencies: SelectedExecutionDependencies, auth: ParticipantAuth): string {
  const value = dependencies.transactionRpcUrls.get(auth.envId);
  if (!value) throw new Error('local_transaction_endpoint_unavailable');
  // This map must be populated from the manifest-validated environment config.
  // Even then this module sends only one fixed method, eth_sendRawTransaction.
  assertWriteEndpoint(value, auth.env.adminRpcUrl);
  return value;
}

export type RecipientKind = 'eoa' | 'contract' | 'unknown';

export function checkRecipientKind(code: unknown): RecipientKind {
  if (typeof code !== 'string' || !/^0x(?:[0-9a-fA-F]{2})*$/.test(code)) return 'unknown';
  return code === '0x' ? 'eoa' : 'contract';
}

/**
 * Read raw eth_getCode output at the selected prestate block. viem's getCode
 * action maps the valid empty-code result `0x` to undefined, so EOA detection
 * must use the unformatted observer request and validate its exact hex shape.
 */
export async function recipientKindAtBlock(
  client: LocalObserverClient,
  recipient: Address,
  blockNumber: bigint,
): Promise<RecipientKind> {
  const blockTag = `0x${blockNumber.toString(16)}` as Hex;
  try {
    const code = await client.request({ method: 'eth_getCode', params: [recipient, blockTag] }) as unknown;
    return checkRecipientKind(code);
  } catch {
    return 'unknown';
  }
}

type ObservedTransaction = {
  hash: Hex;
  type?: string | null | undefined;
  chainId?: number | null | undefined;
  blockHash?: Hex | null | undefined;
  blockNumber?: bigint | null | undefined;
  transactionIndex?: number | null | undefined;
  from: Address;
  to: Address | null;
  nonce: number;
  input: Hex;
  value: bigint;
  gas: bigint;
  maxFeePerGas?: bigint | undefined;
  maxPriorityFeePerGas?: bigint | undefined;
};

function transactionObservation(tx: ObservedTransaction): ExecutionTransactionObservation {
  return {
    hash: tx.hash,
    type: tx.type ?? null,
    chainId: tx.chainId ?? null,
    blockHash: tx.blockHash ?? null,
    blockNumber: tx.blockNumber?.toString() ?? null,
    transactionIndex: tx.transactionIndex?.toString() ?? null,
    from: tx.from,
    to: tx.to,
    nonce: tx.nonce.toString(),
    input: tx.input,
    valueWei: tx.value.toString(),
    gasLimit: tx.gas.toString(),
    maxFeePerGasWei: tx.maxFeePerGas?.toString() ?? null,
    maxPriorityFeePerGasWei: tx.maxPriorityFeePerGas?.toString() ?? null,
  };
}

function transactionMatchesIntent(transaction: ExecutionTransactionObservation, intent: ExecutionTransactionObservation): boolean {
  return transaction.hash.toLowerCase() === intent.hash.toLowerCase() &&
    transaction.type === intent.type && transaction.chainId === intent.chainId &&
    transaction.from.toLowerCase() === intent.from.toLowerCase() &&
    transaction.to?.toLowerCase() === intent.to?.toLowerCase() &&
    transaction.nonce === intent.nonce && transaction.input.toLowerCase() === intent.input.toLowerCase() &&
    transaction.valueWei === intent.valueWei && transaction.gasLimit === intent.gasLimit &&
    transaction.maxFeePerGasWei === intent.maxFeePerGasWei &&
    transaction.maxPriorityFeePerGasWei === intent.maxPriorityFeePerGasWei;
}

async function exactReceiptAndMeasurement(
  client: LocalObserverClient,
  runtime: SelectedExecutionRuntime,
  auth: ParticipantAuth,
  action: SelectedAction,
  hash: Hex,
  intent: ExecutionTransactionObservation,
  before: ExecutionSnapshot,
  quote: QuoteObservation | null,
  remainingTrialMs = runtime.manifest.guardrails.maxTrialSeconds * 1000,
): Promise<{ receipt: TransactionReceipt; after: ExecutionSnapshot; measurement: ExecutionMeasurement; effectsValid: boolean }> {
  const receiptTimeoutMs = Math.max(0, Math.min(runtime.manifest.x402.confirmationTimeoutMs, remainingTrialMs));
  const receipt = await waitForOriginalReceipt(client, hash, receiptTimeoutMs);
  if (receipt.transactionHash.toLowerCase() !== hash.toLowerCase()) throw new Error('receipt_hash_mismatch');
  const observedTransaction = transactionObservation(await client.getTransaction({ hash }));
  if (!transactionMatchesIntent(observedTransaction, intent) || observedTransaction.hash.toLowerCase() !== hash.toLowerCase()) {
    throw new Error('original_transaction_binding_mismatch');
  }
  if (receipt.from.toLowerCase() !== observedTransaction.from.toLowerCase() ||
      receipt.to?.toLowerCase() !== observedTransaction.to?.toLowerCase() ||
      observedTransaction.blockHash?.toLowerCase() !== receipt.blockHash.toLowerCase() ||
      observedTransaction.blockNumber !== receipt.blockNumber.toString() ||
      observedTransaction.transactionIndex !== receipt.transactionIndex.toString()) {
    throw new Error('original_receipt_transaction_binding_mismatch');
  }
  const receiptBlock = receipt.blockNumber;
  if (receiptBlock < 1n) throw new Error('receipt_block_invalid');
  const [prestateBlock, minedBlock] = await Promise.all([
    client.getBlock({ blockNumber: BigInt(before.blockNumber) }),
    client.getBlock({ blockNumber: receiptBlock, includeTransactions: true }),
  ]);
  if (!prestateBlock.hash || !minedBlock.hash || !minedBlock.parentHash || minedBlock.baseFeePerGas === null ||
      minedBlock.number !== receiptBlock || receiptBlock !== BigInt(before.blockNumber) + 1n ||
      minedBlock.parentHash.toLowerCase() !== prestateBlock.hash.toLowerCase() ||
      minedBlock.hash.toLowerCase() !== receipt.blockHash.toLowerCase()) {
    throw new Error('receipt_block_prestate_binding_mismatch');
  }
  const payerBlockTransactions = minedBlock.transactions.map((entry) => {
    if (typeof entry === 'string') throw new Error('receipt_block_transactions_not_expanded');
    return { hash: entry.hash, from: entry.from };
  });
  const matchingBlockTransactions = payerBlockTransactions.filter((entry) => entry.hash.toLowerCase() === hash.toLowerCase());
  const payerBlockTransactionsFromPayer = payerBlockTransactions.filter((entry) => entry.from.toLowerCase() === observedTransaction.from.toLowerCase());
  if (payerBlockTransactions.length !== 1 || matchingBlockTransactions.length !== 1 ||
      matchingBlockTransactions[0]!.from.toLowerCase() !== observedTransaction.from.toLowerCase() ||
      payerBlockTransactionsFromPayer.length !== 1 || receipt.transactionIndex !== 0) {
    throw new Error('receipt_block_sender_attribution_ambiguous');
  }
  const payerBlock: ExecutionPayerBlockObservation = {
    hash: minedBlock.hash,
    number: minedBlock.number.toString(),
    parentHash: minedBlock.parentHash,
    baseFeePerGasWei: minedBlock.baseFeePerGas.toString(),
    transactions: payerBlockTransactions,
  };
  const selectedPool = action.kind === 'swap'
    ? swapRouteAddresses(runtime.manifest, action.inputAssetId, action.outputAssetId, action.feeTier ?? 500).poolAddress
    : runtime.manifest.contracts.pool.address as Address;
  const after = await readSnapshot(client, runtime.manifest, auth.payer, actionRecipient(action, auth.payer), receiptBlock, selectedPool);
  const measurement = measurementFor(action, runtime.manifest, observedTransaction, receipt, before, after, quote, actionRecipient(action, auth.payer), payerBlock);
  return { receipt, after, measurement, effectsValid: validateActionEffects(action, receipt, before, after, auth.payer, runtime.manifest) };
}

/** Read-only reconciliation helper for a persisted, already-broadcast action.
 * It is deliberately bound to the manifest's two local proxy endpoints and
 * never accepts a signer, write URL, replacement hash, or submission hook. */
export async function observePersistedSelectedExecution(input: {
  manifest: RuntimeManifest;
  envId: string;
  observerRpcUrl: string;
  payer: Address;
  action: SelectedAction;
  transactionHash: Hex;
  intent: ExecutionTransactionObservation;
  before: ExecutionSnapshot;
}): Promise<{
  receipt: TransactionReceipt;
  after: ExecutionSnapshot;
  measurement: ExecutionMeasurement;
  effectsValid: boolean;
  sourceBlockHash: Hex;
  prestateBlockHash: Hex;
  receiptBlockHash: Hex;
  receiptBlockTransactionHashes: Hex[];
}> {
  const environment = input.manifest.local.environments.find(({ id }) => id === input.envId);
  if (!environment) throw new Error('persisted_execution_environment_not_manifest_bound');
  let url: URL;
  try { url = new URL(input.observerRpcUrl); } catch { throw new Error('persisted_execution_observer_endpoint_invalid'); }
  if (url.protocol !== 'http:' || url.username || url.password || url.search || url.hash || (url.pathname !== '' && url.pathname !== '/')) {
    throw new Error('persisted_execution_observer_endpoint_invalid');
  }
  const internal = url.hostname === environment.localProxyHost && url.port === '8545';
  const suffix = input.envId.endsWith('-a') ? 'A' : input.envId.endsWith('-b') ? 'B' : '';
  const publishedPort = suffix ? (process.env[`BEF_LOCAL_RPC_${suffix}_HOST_PORT`] ?? (suffix === 'A' ? '18545' : '28545')) : '';
  const published = suffix !== '' && ['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname) && url.port === publishedPort;
  if (!internal && !published) throw new Error('persisted_execution_observer_endpoint_not_manifest_bound');

  const observer = createPublicClient({ chain: base, transport: http(url.toString().replace(/\/$/, ''), { timeout: 15_000, retryCount: 0 }) });
  const chainId = await observer.getChainId();
  if (chainId !== input.manifest.local.chainId) throw new Error('persisted_execution_chain_id_mismatch');
  const sourceBlock = await observer.getBlock({ blockNumber: BigInt(input.manifest.local.forkBlock) });
  if (sourceBlock.number?.toString() !== BigInt(input.manifest.local.forkBlock).toString() ||
      sourceBlock.hash?.toLowerCase() !== input.manifest.source.blockHash.toLowerCase()) {
    throw new Error('persisted_execution_source_block_mismatch');
  }

  const beforeBlockNumber = BigInt(input.before.blockNumber);
  const prestateBlock = await observer.getBlock({ blockNumber: beforeBlockNumber });
  if (!prestateBlock.hash) throw new Error('persisted_execution_prestate_block_unavailable');
  const recipient = actionRecipient(input.action, input.payer);
  const selectedPool = input.action.kind === 'swap'
    ? swapRouteAddresses(input.manifest, input.action.inputAssetId, input.action.outputAssetId, input.action.feeTier ?? 500).poolAddress
    : input.manifest.contracts.pool.address as Address;
  const observedBefore = await readSnapshot(observer, input.manifest, input.payer, recipient, beforeBlockNumber, selectedPool);
  if (canonicalJson(observedBefore) !== canonicalJson(input.before)) throw new Error('persisted_execution_prestate_mismatch');
  const quote = input.action.kind === 'swap'
    ? await quoteAtBlock(observer, input.manifest, BigInt(input.action.amountInUnits), beforeBlockNumber, input.action.inputAssetId, input.action.outputAssetId, input.action.feeTier ?? 500)
    : null;
  const result = await exactReceiptAndMeasurement(
    observer,
    { manifest: input.manifest } as SelectedExecutionRuntime,
    { payer: input.payer } as ParticipantAuth,
    input.action,
    input.transactionHash,
    input.intent,
    input.before,
    quote,
    input.manifest.x402.confirmationTimeoutMs,
  );
  const receiptBlock = await observer.getBlock({ blockNumber: result.receipt.blockNumber, includeTransactions: true });
  if (!receiptBlock.hash || !receiptBlock.parentHash ||
      receiptBlock.number !== beforeBlockNumber + 1n ||
      receiptBlock.parentHash.toLowerCase() !== prestateBlock.hash.toLowerCase() ||
      receiptBlock.hash.toLowerCase() !== result.receipt.blockHash.toLowerCase()) {
    throw new Error('persisted_execution_receipt_prestate_block_binding_mismatch');
  }
  const blockTransactions = receiptBlock.transactions.map((entry) => typeof entry === 'string' ? entry : entry.hash);
  if (blockTransactions.length !== 1 || blockTransactions[0]?.toLowerCase() !== input.transactionHash.toLowerCase() ||
      result.receipt.transactionIndex !== 0) {
    throw new Error('persisted_execution_receipt_block_attribution_ambiguous');
  }
  return {
    ...result,
    sourceBlockHash: sourceBlock.hash,
    prestateBlockHash: prestateBlock.hash,
    receiptBlockHash: receiptBlock.hash,
    receiptBlockTransactionHashes: blockTransactions as Hex[],
  };
}

async function resolveExistingOperation(
  client: PoolClient,
  runtime: SelectedExecutionRuntime,
  dependencies: SelectedExecutionDependencies,
  auth: ParticipantAuth,
  operation: OperationRecord,
  requestedAction: SelectedAction,
  reply: FastifyReply,
): Promise<FastifyReply | null> {
  if (operation.status === 'settled' || operation.status === 'reverted') {
    const completed = await dependencies.persistence.readCompleted(client, operation.operationId);
    if (!completed || !operation.transactionHash || completed.transactionHash.toLowerCase() !== operation.transactionHash.toLowerCase()) {
      return reply.code(502).send({ error: 'stored_execution_observation_unavailable', operationId: operation.operationId });
    }
    const expectedOutcome = operation.status === 'reverted' ? 'reverted' : 'success';
    if (completed.outcome !== expectedOutcome) return reply.code(502).send({ error: 'stored_execution_status_conflict', operationId: operation.operationId });
    return reply.send({ outcome: completed.outcome, operationId: operation.operationId, replayed: true, ...completed.measurement });
  }
  if (!operation.transactionHash) {
    if (operation.status === 'accepted' || operation.status === 'awaiting_payment') return null;
    return reply.code(409).send({ error: 'execution_reconciliation_required', operationId: operation.operationId });
  }
  if (!['settling', 'settlement_unknown'].includes(operation.status)) {
    return reply.code(409).send({ error: 'operation_already_terminal', operationId: operation.operationId, status: operation.status });
  }
  const pending = await dependencies.persistence.readPending(client, operation.operationId);
  if (!pending || !pending.intent || canonicalJson(pending.action) !== canonicalJson(requestedAction)) {
    return reply.code(409).send({ error: 'durable_execution_input_unavailable', operationId: operation.operationId });
  }
  const observer = localObserver(auth);
  const quote = pending.action.kind === 'swap'
    ? await quoteAtBlock(observer, runtime.manifest, BigInt(pending.action.amountInUnits), BigInt(pending.before.blockNumber), pending.action.inputAssetId, pending.action.outputAssetId, pending.action.feeTier ?? 500)
    : null;
  try {
    const result = await exactReceiptAndMeasurement(observer, runtime, auth, pending.action, operation.transactionHash, pending.intent, pending.before, quote);
    if (result.receipt.status === 'reverted' && result.effectsValid) {
      await withTransaction(client, () => dependencies.persistence.finish(client, operation.operationId, operation.transactionHash!, 'reverted', result.measurement));
      return reply.send({ outcome: 'reverted', operationId: operation.operationId, ...result.measurement });
    }
    if (result.receipt.status === 'reverted') {
      await withTransaction(client, () => dependencies.persistence.markUnknown(client, operation.operationId, operation.transactionHash!, result.measurement));
      return reply.code(502).send({ error: 'execution_effects_unverified', operationId: operation.operationId, transactionHash: operation.transactionHash });
    }
    if (!result.effectsValid) {
      await withTransaction(client, () => dependencies.persistence.markUnknown(client, operation.operationId, operation.transactionHash!, result.measurement));
      return reply.code(502).send({ error: 'execution_effects_unverified', operationId: operation.operationId, transactionHash: operation.transactionHash });
    }
    await withTransaction(client, () => dependencies.persistence.finish(client, operation.operationId, operation.transactionHash!, 'success', result.measurement));
    return reply.send({ outcome: 'success', operationId: operation.operationId, ...result.measurement });
  } catch (error) {
    await withTransaction(client, () => dependencies.persistence.markUnknown(client, operation.operationId, operation.transactionHash!)).catch(() => undefined);
    return reply.code(502).send({ error: safeMessageCode(error), operationId: operation.operationId, transactionHash: operation.transactionHash });
  }
}

async function executeNewAction(
  client: PoolClient,
  runtime: SelectedExecutionRuntime,
  dependencies: SelectedExecutionDependencies,
  auth: ParticipantAuth,
  action: SelectedAction,
  operation: OperationRecord,
  writeRpcUrl: string,
  reply: FastifyReply,
): Promise<FastifyReply> {
  const observer = localObserver(auth);
  const deadline = Date.now() + runtime.manifest.guardrails.maxTrialSeconds * 1000;
  const recipient = actionRecipient(action, auth.payer);
  let boundHash: Hex | null = null;
  try {
    if (Date.now() >= deadline) throw new Error('trial_deadline_reached');
    const beforeBlock = await observer.getBlockNumber();
    if (action.kind === 'swap') {
      const recipientKind = await recipientKindAtBlock(observer, action.recipient, beforeBlock);
      if (recipientKind === 'unknown') {
        await withTransaction(client, () => dependencies.persistence.rejectBeforeBroadcast(
          client, operation.operationId, 'recipient_code_observation_unavailable',
        ));
        return reply.code(503).send({ error: 'recipient_code_observation_unavailable', operationId: operation.operationId });
      }
      if (recipientKind === 'contract') {
        await withTransaction(client, () => dependencies.persistence.rejectBeforeBroadcast(client, operation.operationId, 'selected_recipient_must_be_eoa'));
        return reply.code(400).send({ error: 'selected_recipient_must_be_eoa', operationId: operation.operationId });
      }
    }
    const selectedPool = action.kind === 'swap'
      ? swapRouteAddresses(runtime.manifest, action.inputAssetId, action.outputAssetId, action.feeTier ?? 500).poolAddress
      : runtime.manifest.contracts.pool.address as Address;
    const before = await readSnapshot(observer, runtime.manifest, auth.payer, recipient, beforeBlock, selectedPool);
    const gasLimit = BigInt(action.gasLimit);
    const maxPriorityFeePerGas = BigInt(runtime.manifest.feePolicy.priorityFeeWei);
    const maxFeePerGas = BigInt(runtime.manifest.feePolicy.baseFeeWei) + maxPriorityFeePerGas;
    const call = transactionCall(action, runtime.manifest, auth.payer);
    const minimumNativeForExecution = call.value + gasLimit * maxFeePerGas;
    if (BigInt(before.payerNativeWei) < minimumNativeForExecution) {
      await withTransaction(client, () => dependencies.persistence.rejectBeforeBroadcast(client, operation.operationId, 'insufficient_native_for_selected_transaction'));
      return reply.code(422).send({ error: 'insufficient_native_for_selected_transaction', operationId: operation.operationId });
    }
    const quote = action.kind === 'swap'
      ? await quoteAtBlock(observer, runtime.manifest, BigInt(action.amountInUnits), beforeBlock, action.inputAssetId, action.outputAssetId, action.feeTier ?? 500)
      : null;
    await withTransaction(client, () => dependencies.persistence.saveSelectedInputAndPrestate(client, operation.operationId, action, before));

    const result = await dependencies.signerStore.withAccount(
      { envId: auth.envId, generationId: auth.generationId },
      async (account) => {
        if (account.address.toLowerCase() !== auth.payer.toLowerCase()) throw new Error('generation_signer_payer_mismatch');
        if (Date.now() >= deadline) throw new Error('trial_deadline_reached');
        await requireActiveGeneration(client, auth);
        const nonce = await observer.getTransactionCount({ address: account.address, blockTag: 'pending' });
        const serializable = {
          type: 'eip1559',
          chainId: runtime.manifest.local.chainId,
          nonce,
          to: call.to,
          data: call.data,
          value: call.value,
          gas: gasLimit,
          maxFeePerGas,
          maxPriorityFeePerGas,
        } satisfies TransactionSerializableEIP1559;
        const serialized = await account.signTransaction(serializable);
        const hash = keccak256(serialized);
        if (Date.now() >= deadline || !dependencies.signerStore.has({ envId: auth.envId, generationId: auth.generationId })) {
          throw new Error('generation_signer_expired_before_broadcast');
        }
        await requireActiveGeneration(client, auth);
        const intent: ExecutionTransactionObservation = {
          hash,
          type: 'eip1559',
          chainId: runtime.manifest.local.chainId,
          blockHash: null,
          blockNumber: null,
          transactionIndex: null,
          from: account.address,
          to: call.to,
          nonce: nonce.toString(),
          input: call.data,
          valueWei: call.value.toString(),
          gasLimit: gasLimit.toString(),
          maxFeePerGasWei: maxFeePerGas.toString(),
          maxPriorityFeePerGasWei: maxPriorityFeePerGas.toString(),
        };
        await withTransaction(client, () => dependencies.persistence.bindHashBeforeBroadcast(client, operation.operationId, hash, operation.requestHash, intent));
        boundHash = hash;
        const scope = { envId: auth.envId, generationId: auth.generationId };
        if (Date.now() >= deadline || !dependencies.signerStore.has(scope)) {
          await withTransaction(client, () => dependencies.persistence.markUnknown(client, operation.operationId, hash));
          return reply.code(502).send({ error: 'generation_signer_unavailable_after_hash_binding', operationId: operation.operationId, transactionHash: hash });
        }
        try {
          await withTransaction(client, () => requireActiveGeneration(client, auth));
        } catch {
          await withTransaction(client, () => dependencies.persistence.markUnknown(client, operation.operationId, hash));
          return reply.code(502).send({ error: 'generation_fenced_after_hash_binding', operationId: operation.operationId, transactionHash: hash });
        }
        if (Date.now() >= deadline || !dependencies.signerStore.has(scope)) {
          await withTransaction(client, () => dependencies.persistence.markUnknown(client, operation.operationId, hash));
          return reply.code(502).send({ error: 'generation_signer_unavailable_after_hash_binding', operationId: operation.operationId, transactionHash: hash });
        }
        try {
          await sendOnlyLocalTransaction(writeRpcUrl, serialized, hash);
        } catch {
          await withTransaction(client, () => dependencies.persistence.markUnknown(client, operation.operationId, hash));
          return reply.code(502).send({ error: 'transaction_submission_outcome_unknown', operationId: operation.operationId, transactionHash: hash });
        }
        try {
          const measured = await exactReceiptAndMeasurement(observer, runtime, auth, action, hash, intent, before, quote, deadline - Date.now());
          if (measured.receipt.status === 'reverted') {
            await withTransaction(client, () => dependencies.persistence.finish(client, operation.operationId, hash, 'reverted', measured.measurement));
            return reply.send({ outcome: 'reverted', operationId: operation.operationId, ...measured.measurement });
          }
          if (!measured.effectsValid) {
            await withTransaction(client, () => dependencies.persistence.markUnknown(client, operation.operationId, hash, measured.measurement));
            return reply.code(502).send({ error: 'execution_effects_unverified', operationId: operation.operationId, transactionHash: hash });
          }
          await withTransaction(client, () => dependencies.persistence.finish(client, operation.operationId, hash, 'success', measured.measurement));
          return reply.send({ outcome: 'success', operationId: operation.operationId, ...measured.measurement });
        } catch (error) {
          await withTransaction(client, () => dependencies.persistence.markUnknown(client, operation.operationId, hash)).catch(() => undefined);
          return reply.code(502).send({ error: safeMessageCode(error), operationId: operation.operationId, transactionHash: hash });
        }
      },
    );
    return result;
  } catch (error) {
    if (boundHash) {
      await withTransaction(client, () => dependencies.persistence.markUnknown(client, operation.operationId, boundHash!)).catch(() => undefined);
      return reply.code(502).send({ error: safeMessageCode(error), operationId: operation.operationId, transactionHash: boundHash });
    }
    await withTransaction(client, () => dependencies.persistence.rejectBeforeBroadcast(client, operation.operationId, safeMessageCode(error))).catch(() => undefined);
    return reply.code(409).send({ error: safeMessageCode(error), operationId: operation.operationId });
  }
}

async function selectedActionRoute(
  app: FastifyInstance,
  runtime: SelectedExecutionRuntime,
  dependencies: SelectedExecutionDependencies,
  kind: SelectedAction['kind'],
): Promise<void> {
  app.post<{ Params: { envId: string } }>(`/tools/:envId/${kind}`, async (request, reply) => {
    const auth = await authorizeParticipant(runtime, request, reply);
    if (!auth) return;
    const bodyBytes = Buffer.byteLength(JSON.stringify(request.body ?? null), 'utf8');
    if (bodyBytes > runtime.manifest.guardrails.maxHttpRequestBytes) return reply.code(413).send({ error: 'request_too_large' });
    const action = parseSelectedAction(kind, request.body);
    if (!action) return reply.code(400).send({ error: 'invalid_selected_action' });
    try {
      validateHardBounds(action, runtime.manifest);
    } catch {
      return reply.code(400).send({ error: 'selected_action_outside_hard_bounds' });
    }
    let writeRpcUrl: string;
    try {
      writeRpcUrl = localTxUrl(dependencies, auth);
    } catch {
      return reply.code(503).send({ error: 'local_transaction_endpoint_unavailable' });
    }
    const path = `/tools/${kind}`;
    const requestHash = createHash('sha256').update(canonicalJson({ method: 'POST', path, action: safeAction(action, runtime.manifest) })).digest('hex');
    try {
      return await withEnvironmentLock(runtime.pool, auth.envId, runtime.manifest.guardrails.maxTrialSeconds * 1000, async (client) => {
        let operation: OperationRecord;
        try {
          operation = await withTransaction(client, async () => {
            await requireActiveGeneration(client, auth);
            const created = await dependencies.persistence.createOrGet(client, auth, kind, requestHash, action);
            if (!created.isNew && created.requestHash !== requestHash) throw new Error('idempotency_key_reused_for_different_request');
            if (created.isNew) {
              const unresolved = await client.query(
                `SELECT operation_id FROM bef_operation
                  WHERE env_id=$1 AND generation_id=$2 AND operation_id<>$3
                    AND status IN ('settling','settlement_unknown') LIMIT 1`,
                [auth.envId, auth.generationId, created.operationId],
              );
              if (unresolved.rowCount) throw new Error('unresolved_operation_blocks_execution');
            }
            return created;
          });
        } catch {
          return reply.code(409).send({ error: 'generation_or_idempotency_conflict' });
        }
        if (!operation.isNew) {
          const replay = await resolveExistingOperation(client, runtime, dependencies, auth, operation, action, reply);
          if (replay) return replay;
        }
        if (!dependencies.signerStore.has({ envId: auth.envId, generationId: auth.generationId })) {
          if (operation.isNew || !operation.transactionHash) {
            await withTransaction(client, () => dependencies.persistence.rejectBeforeBroadcast(client, operation.operationId, 'generation_signer_unavailable')).catch(() => undefined);
          }
          return reply.code(409).send({ error: 'generation_signer_unavailable', operationId: operation.operationId });
        }
        return executeNewAction(client, runtime, dependencies, auth, action, operation, writeRpcUrl, reply);
      });
    } catch {
      return reply.code(503).send({ error: 'selected_action_unavailable' });
    }
  });
}

/** The transaction URL is fixed per environment; participant fields cannot
 * select a method, chain, asset, router, RPC, or raw transaction. */
export async function registerSelectedExecutionRoutes(
  app: FastifyInstance,
  runtime: SelectedExecutionRuntime,
  dependencies: SelectedExecutionDependencies,
): Promise<void> {
  const denominator = BigInt(runtime.manifest.feePolicy.ethUsdcRateDenominator);
  const maxFee = BigInt(runtime.manifest.feePolicy.baseFeeWei) + BigInt(runtime.manifest.feePolicy.priorityFeeWei);
  if (denominator <= 0n || BigInt(runtime.manifest.feePolicy.baseFeeWei) > MAX_UINT256 ||
      BigInt(runtime.manifest.feePolicy.priorityFeeWei) > MAX_UINT256 ||
      maxFee > MAX_UINT256 || BigInt(runtime.manifest.feePolicy.ethUsdcRateNumerator) <= 0n ||
      runtime.manifest.swap.route !== 'uniswap-v3-exactInputSingle' ||
      runtime.manifest.swap.tokenIn.toLowerCase() !== runtime.manifest.contracts.weth.address.toLowerCase() ||
      runtime.manifest.swap.tokenOut.toLowerCase() !== runtime.manifest.contracts.usdc.address.toLowerCase() ||
      runtime.manifest.swap.fee !== runtime.manifest.contracts.pool.fee ||
      runtime.manifest.contracts.pool.token0.toLowerCase() !== runtime.manifest.contracts.weth.address.toLowerCase() ||
      runtime.manifest.contracts.pool.token1.toLowerCase() !== runtime.manifest.contracts.usdc.address.toLowerCase()) {
    throw new Error('selected_execution_manifest_inconsistent');
  }
  if (runtime.manifest.contracts.pool3000) {
    try { swapRouteAddresses(runtime.manifest, 'WETH', 'USDC', 3000); }
    catch { throw new Error('selected_execution_manifest_inconsistent'); }
  }
  app.get<{ Params: { envId: string } }>('/tools/:envId/balances', async (request, reply) => {
    const auth = await authorizeParticipant(runtime, request, reply);
    if (!auth) return;
    if (!balancesQuerySchema.safeParse(request.query).success || hasReadRequestBody(request)) {
      return reply.code(400).send({ error: 'invalid_balance_read_request' });
    }
    try {
      return await withEnvironmentLock(runtime.pool, auth.envId, runtime.manifest.guardrails.maxTrialSeconds * 1000, async (client) => {
        await withTransaction(client, () => requireActiveGeneration(client, auth));
        const observer = localObserver(auth);
        const blockNumber = await observer.getBlockNumber();
        const snapshot = await readSnapshot(observer, runtime.manifest, auth.payer, auth.payer, blockNumber);
        return reply.send({ boundary: 'local-chain-readonly-proxy', envId: auth.envId, generationId: auth.generationId, payer: auth.payer, balances: snapshot });
      });
    } catch {
      return reply.code(503).send({ error: 'balance_observation_unavailable' });
    }
  });

  app.get<{ Params: { envId: string }; Querystring: { inputAssetId?: 'WETH' | 'USDC'; feeTier?: PinnedV3FeeTier; amountInUnits?: string; amountInWei?: string } }>('/tools/:envId/quote', async (request, reply) => {
    const auth = await authorizeParticipant(runtime, request, reply);
    if (!auth) return;
    const parsedQuery = quoteQuerySchema.safeParse(request.query);
    if (!parsedQuery.success || hasReadRequestBody(request)) return reply.code(400).send({ error: 'invalid_quote_amount' });
    const inputAssetId = 'inputAssetId' in parsedQuery.data ? parsedQuery.data.inputAssetId : 'WETH';
    const outputAssetId = inputAssetId === 'WETH' ? 'USDC' : 'WETH';
    const amountText = 'inputAssetId' in parsedQuery.data ? parsedQuery.data.amountInUnits : parsedQuery.data.amountInWei;
    const feeTier = parsedQuery.data.feeTier ?? 500;
    let amountIn: bigint;
    try {
      amountIn = decimalValue(amountText);
      if (amountIn === 0n || amountIn > maximumSwapInput(runtime.manifest, inputAssetId)) throw new Error('quote_amount_outside_bound');
    } catch {
      return reply.code(400).send({ error: 'quote_amount_outside_hard_bounds' });
    }
    try {
      return await withEnvironmentLock(runtime.pool, auth.envId, runtime.manifest.guardrails.maxTrialSeconds * 1000, async (client) => {
        await withTransaction(client, () => requireActiveGeneration(client, auth));
        const observer = localObserver(auth);
        const blockNumber = await observer.getBlockNumber();
        const quote = await quoteAtBlock(observer, runtime.manifest, amountIn, blockNumber, inputAssetId, outputAssetId, feeTier);
        return reply.send({
          boundary: 'local-chain-readonly-proxy',
          envId: auth.envId,
          generationId: auth.generationId,
          route: 'uniswap-v3-exactInputSingle',
          inputAssetId,
          outputAssetId,
          ...swapRouteAddresses(runtime.manifest, inputAssetId, outputAssetId, feeTier),
          requestedAmountInUnits: amountText,
          blockNumber: blockNumber.toString(),
          quoteStatus: quote ? 'observed' : 'unknown',
          quote,
        });
      });
    } catch {
      return reply.code(503).send({ error: 'quote_observation_unavailable' });
    }
  });

  await selectedActionRoute(app, runtime, dependencies, 'approve');
  await selectedActionRoute(app, runtime, dependencies, 'transfer');
  await selectedActionRoute(app, runtime, dependencies, 'wrap');
  await selectedActionRoute(app, runtime, dependencies, 'unwrap');
  await selectedActionRoute(app, runtime, dependencies, 'swap');
}

/** Admin generation integration: call only after all request validation and
 * DB scoping inputs are final, before fixture funding; clear on any failed
 * fixture setup. The response may expose only the derived public address. */
export function bindGenerationSigner(
  store: EphemeralSignerStore,
  input: { envId: string; generationId: string; privateKey: Hex; payerAddress: Address; expiresAtMs: number },
): Address {
  return store.put(
    { envId: input.envId, generationId: input.generationId },
    input.privateKey,
    input.payerAddress,
    input.expiresAtMs,
  );
}

/** Reset/fence/shutdown hooks; the caller must hold the same environment lock. */
export function eraseGenerationSigner(store: EphemeralSignerStore, envId: string, generationId: string): void {
  store.eraseGeneration({ envId, generationId });
}
