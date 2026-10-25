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
  'function slot0() view returns (uint160 sqrtPriceX96,int24 tick,uint16 observationIndex,uint16 observationCardinality,uint16 observationCardinalityNext,uint8 feeProtocol,bool unlocked)',
  'function liquidity() view returns (uint128)',
  'event Swap(address indexed sender,address indexed recipient,int256 amount0,int256 amount1,uint160 sqrtPriceX96,uint128 liquidity,int24 tick)',
] as const);

export type SelectedExecutionAction =
  | { kind: 'approve'; amountUnits: string; gasLimit: string }
  | { kind: 'wrap'; amountWei: string; gasLimit: string }
  | { kind: 'unwrap'; amountWei: string; gasLimit: string }
  | { kind: 'swap'; amountInWei: string; amountOutMinimumUsdcUnits: string; recipient: Address; gasLimit: string };
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
  recipientUsdcUnits: string;
  wethRouterAllowance: string;
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
    principalAsset: 'ETH' | 'WETH' | null;
    selectedPrincipalUnits: string;
    principalUnits: string;
  };
  taskEvaluationInputs: {
    expenseBudgetUsdcUnits: string;
    recipient: Address | null;
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
  approve: z.object({ amountUnits: z.string().regex(UINT_DECIMAL), gasLimit: z.string().regex(UINT_DECIMAL) }).strict(),
  wrap: z.object({ amountWei: z.string().regex(UINT_DECIMAL), gasLimit: z.string().regex(UINT_DECIMAL) }).strict(),
  unwrap: z.object({ amountWei: z.string().regex(UINT_DECIMAL), gasLimit: z.string().regex(UINT_DECIMAL) }).strict(),
  swap: z.object({
    amountInWei: z.string().regex(UINT_DECIMAL),
    amountOutMinimumUsdcUnits: z.string().regex(UINT_DECIMAL),
    recipient: z.string().regex(ADDRESS),
    gasLimit: z.string().regex(UINT_DECIMAL),
  }).strict(),
} as const;
const balancesQuerySchema = z.object({}).strict();
const quoteQuerySchema = z.object({ amountInWei: z.string().regex(UINT_DECIMAL) }).strict();

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

function validateHardBounds(action: SelectedAction, manifest: RuntimeManifest): void {
  const maxGas = BigInt(manifest.swap.maxTransactionGas);
  const gasLimit = decimalValue(action.gasLimit);
  if (gasLimit === 0n || gasLimit > maxGas) throw new Error('gas_limit_outside_manifest_bound');
  if (action.kind === 'approve') {
    decimalValue(action.amountUnits); // zero is allowed for an explicitly selected allowance cleanup.
  } else if (action.kind === 'wrap' || action.kind === 'unwrap') {
    const amount = decimalValue(action.amountWei);
    if (amount === 0n) throw new Error('amount_must_be_positive');
    if (amount > BigInt(manifest.funding.nativeEthWeiPerGeneration)) throw new Error('conversion_amount_outside_fixture_bound');
  } else {
    const amountIn = decimalValue(action.amountInWei);
    decimalValue(action.amountOutMinimumUsdcUnits); // preserve the caller's exact minOut, including zero.
    if (amountIn === 0n || amountIn > BigInt(manifest.swap.maxAmountIn)) throw new Error('swap_amount_outside_manifest_bound');
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
      return parsed.success ? { kind, ...parsed.data } : null;
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
      // Address casing is not part of the selected destination. Canonicalize
      // hex casing so any valid 20-byte address spelling is accepted by viem.
      return parsed.success ? { kind, ...parsed.data, recipient: parsed.data.recipient.toLowerCase() as Address } : null;
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
      token: manifest.contracts.weth.address,
      spender: manifest.contracts.swapRouter02.address,
      amountUnits: action.amountUnits,
      gasLimit: action.gasLimit,
    };
    case 'wrap': return { kind: action.kind, amountWei: action.amountWei, gasLimit: action.gasLimit };
    case 'unwrap': return { kind: action.kind, amountWei: action.amountWei, gasLimit: action.gasLimit };
    case 'swap': return {
      kind: action.kind,
      route: 'uniswap-v3-exactInputSingle',
      router: manifest.contracts.swapRouter02.address,
      tokenIn: manifest.swap.tokenIn,
      tokenOut: manifest.swap.tokenOut,
      fee: manifest.swap.fee,
      amountInWei: action.amountInWei,
      amountOutMinimumUsdcUnits: action.amountOutMinimumUsdcUnits,
      recipient: action.recipient,
      gasLimit: action.gasLimit,
    };
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
): Promise<ExecutionSnapshot> {
  const weth = manifest.contracts.weth.address as Address;
  const usdc = manifest.contracts.usdc.address as Address;
  const router = manifest.contracts.swapRouter02.address as Address;
  const pool = manifest.contracts.pool.address as Address;
  const [native, payerWeth, payerUsdc, recipientUsdc, allowance, poolWeth, poolUsdc, poolLiquidity, poolSlot0] = await Promise.all([
    client.getBalance({ address: payer, blockNumber }),
    client.readContract({ address: weth, abi: WETH_ABI, functionName: 'balanceOf', args: [payer], blockNumber }),
    client.readContract({ address: usdc, abi: ERC20_ABI, functionName: 'balanceOf', args: [payer], blockNumber }),
    client.readContract({ address: usdc, abi: ERC20_ABI, functionName: 'balanceOf', args: [recipient], blockNumber }),
    client.readContract({ address: weth, abi: ERC20_ABI, functionName: 'allowance', args: [payer, router], blockNumber }),
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
    recipientUsdcUnits: recipientUsdc.toString(),
    wethRouterAllowance: allowance.toString(),
    poolWethUnits: poolWeth.toString(),
    poolUsdcUnits: poolUsdc.toString(),
    poolLiquidity: poolLiquidity.toString(),
    poolSqrtPriceX96: poolSlot0[0].toString(),
  };
}

type QuoteObservation = {
  amountInWei: string;
  amountOutUsdcUnits: string;
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
): Promise<QuoteObservation | null> {
  try {
    const result = await client.readContract({
      address: manifest.contracts.quoterV2.address as Address,
      abi: QUOTER_V2_ABI,
      functionName: 'quoteExactInputSingle',
      args: [{
        tokenIn: manifest.contracts.weth.address as Address,
        tokenOut: manifest.contracts.usdc.address as Address,
        amountIn,
        fee: manifest.swap.fee,
        sqrtPriceLimitX96: 0n,
      }],
      blockNumber,
    }) as readonly [bigint, bigint, number, bigint];
    const [slot0, liquidity] = await Promise.all([
      client.readContract({ address: manifest.contracts.pool.address as Address, abi: V3_POOL_ABI, functionName: 'slot0', blockNumber }) as Promise<readonly [bigint, number, number, number, number, number, boolean]>,
      client.readContract({ address: manifest.contracts.pool.address as Address, abi: V3_POOL_ABI, functionName: 'liquidity', blockNumber }),
    ]);
    return {
      amountInWei: amountIn.toString(),
      amountOutUsdcUnits: result[0].toString(),
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
        to: weth,
        data: encodeFunctionData({
          abi: ERC20_ABI,
          functionName: 'approve',
          args: [manifest.contracts.swapRouter02.address as Address, decimalValue(action.amountUnits)],
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
      return {
        to: manifest.contracts.swapRouter02.address as Address,
        data: encodeFunctionData({
          abi: SWAP_ROUTER_ABI,
          functionName: 'exactInputSingle',
          args: [{
            tokenIn: manifest.swap.tokenIn as Address,
            tokenOut: manifest.swap.tokenOut as Address,
            fee: manifest.swap.fee,
            recipient: action.recipient,
            amountIn: decimalValue(action.amountInWei),
            // Keep the selected threshold exactly as submitted. The quote is
            // evidence only; maxSlippageBps never rewrites this value.
            amountOutMinimum: decimalValue(action.amountOutMinimumUsdcUnits),
            sqrtPriceLimitX96: 0n,
          }],
        }),
        value: 0n,
      };
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
  const pool = manifest.contracts.pool.address.toLowerCase();
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
  const selectedMaximumInput = BigInt(action.amountInWei);
  if (swap.amount0 <= 0n || swap.amount0 > selectedMaximumInput || swap.amount1 >= 0n) return null;
  const amountIn = swap.amount0;
  const amountOut = -swap.amount1;
  if (amountOut < BigInt(action.amountOutMinimumUsdcUnits)) return null;

  const transferMatches = (token: Address, from: Address, to: Address, amount: bigint): number => receipt.logs.filter((log) => {
    if (log.address.toLowerCase() !== token.toLowerCase()) return false;
    try {
      const event = decodeEventLog({ abi: ERC20_ABI, eventName: 'Transfer', topics: log.topics, data: log.data }) as { args: unknown };
      const args = event.args as { from: Address; to: Address; value: bigint };
      return args.from.toLowerCase() === from.toLowerCase() && args.to.toLowerCase() === to.toLowerCase() && args.value === amount;
    } catch { return false; }
  }).length;
  const weth = manifest.contracts.weth.address as Address;
  const usdc = manifest.contracts.usdc.address as Address;
  const poolAddress = manifest.contracts.pool.address as Address;
  if (transferMatches(weth, payer, poolAddress, amountIn) !== 1 || transferMatches(usdc, poolAddress, action.recipient, amountOut) !== 1) return null;
  return { amountIn, amountOut };
}

type ExecutionDeltas = {
  payerNativeWei: string;
  payerWethUnits: string;
  payerUsdcUnits: string;
  recipientUsdcUnits: string;
  wethRouterAllowance: string;
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
    recipientUsdcUnits: (BigInt(after.recipientUsdcUnits) - BigInt(before.recipientUsdcUnits)).toString(),
    wethRouterAllowance: (BigInt(after.wethRouterAllowance) - BigInt(before.wethRouterAllowance)).toString(),
    poolWethUnits: (BigInt(after.poolWethUnits) - BigInt(before.poolWethUnits)).toString(),
    poolUsdcUnits: (BigInt(after.poolUsdcUnits) - BigInt(before.poolUsdcUnits)).toString(),
    poolLiquidity: (BigInt(after.poolLiquidity) - BigInt(before.poolLiquidity)).toString(),
    poolSqrtPriceX96: (BigInt(after.poolSqrtPriceX96) - BigInt(before.poolSqrtPriceX96)).toString(),
  };
}

function validateActionEffects(
  action: SelectedAction,
  receipt: TransactionReceipt,
  before: ExecutionSnapshot,
  after: ExecutionSnapshot,
  payer: Address,
  manifest: RuntimeManifest,
): boolean {
  if (receipt.status !== 'success' || receipt.from.toLowerCase() !== payer.toLowerCase()) return false;
  const effect = deltas(before, after);
  const gasCost = receipt.gasUsed * receipt.effectiveGasPrice;
  if (action.kind === 'approve') {
    return receipt.to?.toLowerCase() === manifest.contracts.weth.address.toLowerCase() &&
      BigInt(effect.payerNativeWei) === -gasCost &&
      BigInt(effect.payerWethUnits) === 0n && BigInt(effect.payerUsdcUnits) === 0n &&
      BigInt(effect.wethRouterAllowance) === BigInt(action.amountUnits) - BigInt(before.wethRouterAllowance) &&
      BigInt(effect.poolWethUnits) === 0n && BigInt(effect.poolUsdcUnits) === 0n &&
      BigInt(after.wethRouterAllowance) === BigInt(action.amountUnits) &&
      decodeApproval(receipt, manifest.contracts.weth.address as Address, payer, manifest.contracts.swapRouter02.address as Address, BigInt(action.amountUnits));
  }
  if (action.kind === 'wrap') {
    const amount = BigInt(action.amountWei);
    return receipt.to?.toLowerCase() === manifest.contracts.weth.address.toLowerCase() &&
      BigInt(effect.payerWethUnits) === amount && BigInt(effect.payerNativeWei) === -(amount + gasCost) &&
      BigInt(effect.payerUsdcUnits) === 0n && BigInt(effect.wethRouterAllowance) === 0n &&
      BigInt(effect.poolWethUnits) === 0n && BigInt(effect.poolUsdcUnits) === 0n &&
      decodeWethEvent(receipt, manifest.contracts.weth.address as Address, 'Deposit', payer, amount);
  }
  if (action.kind === 'unwrap') {
    const amount = BigInt(action.amountWei);
    return receipt.to?.toLowerCase() === manifest.contracts.weth.address.toLowerCase() &&
      BigInt(effect.payerWethUnits) === -amount && BigInt(effect.payerNativeWei) === amount - gasCost &&
      BigInt(effect.payerUsdcUnits) === 0n && BigInt(effect.wethRouterAllowance) === 0n &&
      BigInt(effect.poolWethUnits) === 0n && BigInt(effect.poolUsdcUnits) === 0n &&
      decodeWethEvent(receipt, manifest.contracts.weth.address as Address, 'Withdrawal', payer, amount);
  }
  if (receipt.to?.toLowerCase() !== manifest.contracts.swapRouter02.address.toLowerCase()) return false;
  const swap = decodeSwap(receipt, manifest, action, payer);
  if (!swap) return false;
  const recipientIsPayer = action.recipient.toLowerCase() === payer.toLowerCase();
  const expectedPayerUsdcDelta = recipientIsPayer ? swap.amountOut : 0n;
  const beforeAllowance = BigInt(before.wethRouterAllowance);
  const expectedAllowanceAfter = beforeAllowance === MAX_UINT256 ? MAX_UINT256 : beforeAllowance - swap.amountIn;
  return beforeAllowance >= swap.amountIn &&
    BigInt(effect.payerWethUnits) === -swap.amountIn &&
    BigInt(effect.payerUsdcUnits) === expectedPayerUsdcDelta &&
    BigInt(effect.recipientUsdcUnits) === swap.amountOut &&
    BigInt(after.wethRouterAllowance) === expectedAllowanceAfter &&
    BigInt(effect.payerNativeWei) === -gasCost &&
    BigInt(effect.poolWethUnits) === swap.amountIn && BigInt(effect.poolUsdcUnits) === -swap.amountOut;
}

export function principalAccountingForMeasurement(
  action: SelectedAction,
  receiptStatus: 'success' | 'reverted',
): { selectedPrincipalUnits: string; principalUnits: string } {
  const selectedPrincipalUnits = action.kind === 'wrap' || action.kind === 'unwrap' ? action.amountWei
    : action.kind === 'swap' ? action.amountInWei : '0';
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
  const principalAsset = action.kind === 'wrap' ? 'ETH' : action.kind === 'unwrap' ? 'WETH' : action.kind === 'swap' ? 'WETH' : null;
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
    quote: quote ? { ...quote } : null,
    fee: {
      modeledGasFeeUsdcUnits: modeledGasFeeUsdcUnits.toString(),
      baseL1Fee: 'unmodelled',
      principalAsset,
      selectedPrincipalUnits,
      principalUnits,
    },
    taskEvaluationInputs: {
      expenseBudgetUsdcUnits: manifest.taskGoal.expenseBudgetUsdcUnits,
      recipient: action.kind === 'swap' ? recipient : null,
      allowanceAfterUnits: after.wethRouterAllowance,
      nativeEthReserveWei: manifest.taskGoal.nativeEthReserveWei,
      allowanceCleanupExpected: manifest.taskGoal.allowanceCleanupExpected,
      selectedMinimumOutputUnits: action.kind === 'swap' ? action.amountOutMinimumUsdcUnits : null,
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
  return action.kind === 'swap' ? action.recipient : payer;
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
  const after = await readSnapshot(client, runtime.manifest, auth.payer, actionRecipient(action, auth.payer), receiptBlock);
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
  const observedBefore = await readSnapshot(observer, input.manifest, input.payer, recipient, beforeBlockNumber);
  if (canonicalJson(observedBefore) !== canonicalJson(input.before)) throw new Error('persisted_execution_prestate_mismatch');
  const quote = input.action.kind === 'swap'
    ? await quoteAtBlock(observer, input.manifest, BigInt(input.action.amountInWei), beforeBlockNumber)
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
    ? await quoteAtBlock(observer, runtime.manifest, BigInt(pending.action.amountInWei), BigInt(pending.before.blockNumber))
    : null;
  try {
    const result = await exactReceiptAndMeasurement(observer, runtime, auth, pending.action, operation.transactionHash, pending.intent, pending.before, quote);
    if (result.receipt.status === 'reverted') {
      await withTransaction(client, () => dependencies.persistence.finish(client, operation.operationId, operation.transactionHash!, 'reverted', result.measurement));
      return reply.send({ outcome: 'reverted', operationId: operation.operationId, ...result.measurement });
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
    const before = await readSnapshot(observer, runtime.manifest, auth.payer, recipient, beforeBlock);
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
      ? await quoteAtBlock(observer, runtime.manifest, BigInt(action.amountInWei), beforeBlock)
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

  app.get<{ Params: { envId: string }; Querystring: { amountInWei?: string } }>('/tools/:envId/quote', async (request, reply) => {
    const auth = await authorizeParticipant(runtime, request, reply);
    if (!auth) return;
    const parsedQuery = quoteQuerySchema.safeParse(request.query);
    if (!parsedQuery.success || hasReadRequestBody(request)) return reply.code(400).send({ error: 'invalid_quote_amount' });
    const amountText = parsedQuery.data.amountInWei;
    let amountIn: bigint;
    try {
      amountIn = decimalValue(amountText);
      if (amountIn === 0n || amountIn > BigInt(runtime.manifest.swap.maxAmountIn)) throw new Error('quote_amount_outside_bound');
    } catch {
      return reply.code(400).send({ error: 'quote_amount_outside_hard_bounds' });
    }
    try {
      return await withEnvironmentLock(runtime.pool, auth.envId, runtime.manifest.guardrails.maxTrialSeconds * 1000, async (client) => {
        await withTransaction(client, () => requireActiveGeneration(client, auth));
        const observer = localObserver(auth);
        const blockNumber = await observer.getBlockNumber();
        const quote = await quoteAtBlock(observer, runtime.manifest, amountIn, blockNumber);
        return reply.send({
          boundary: 'local-chain-readonly-proxy',
          envId: auth.envId,
          generationId: auth.generationId,
          route: 'uniswap-v3-exactInputSingle',
          tokenIn: runtime.manifest.swap.tokenIn,
          tokenOut: runtime.manifest.swap.tokenOut,
          fee: runtime.manifest.swap.fee,
          requestedAmountInWei: amountText,
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
