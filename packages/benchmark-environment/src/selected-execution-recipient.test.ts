import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { once } from 'node:events';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import test from 'node:test';
import Fastify from 'fastify';
import type { Pool } from 'pg';
import { createPublicClient, http, type Address, type TransactionReceipt } from 'viem';
import { base } from 'viem/chains';
import {
  checkRecipientKind,
  parseSelectedAction,
  recipientKindAtBlock,
  registerSelectedExecutionRoutes,
  swapRouteAddresses,
  validateActionEffects,
  type ExecutionSnapshot,
  type SelectedAction,
  type SelectedExecutionDependencies,
  type SelectedExecutionRuntime,
} from './selected-execution.js';
import type { RuntimeEnvironment } from './runtime.js';
import type { RuntimeManifest } from './manifest.js';

const PAYER = '0xb441c27dA3476936d1bDc965dC0788f3e5b12DBB' as Address;
const RECIPIENT_EOA = '0x0000000000000000000000000000000000000001' as Address;
const RECIPIENT_CONTRACT = '0x0000000000000000000000000000000000000002' as Address;
const RECIPIENT_NULL = '0x0000000000000000000000000000000000000003' as Address;
const RECIPIENT_MISSING = '0x0000000000000000000000000000000000000004' as Address;
const RECIPIENT_MALFORMED = '0x0000000000000000000000000000000000000005' as Address;
const OPERATION_ID = '31b0b927-79f7-4e07-87e3-f5ed2f9c97e6';
const GENERATION_ID = '11111111-1111-4111-8111-111111111111';
const PARTICIPANT_ID = '22222222-2222-4222-8222-222222222222';
const WETH = '0x4200000000000000000000000000000000000006' as Address;
const USDC = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913' as Address;
const ROUTER = '0x2626664c2603336E57B271c5C0b26F421741e481' as Address;
const QUOTER = '0x1111111111111111111111111111111111111111' as Address;
const POOL = '0x2222222222222222222222222222222222222222' as Address;
const ALT_POOL = '0x3333333333333333333333333333333333333333' as Address;
const BLOCK_NUMBER = 52982199n;
const NO_RESULT = Symbol('no JSON-RPC result');
const POOL_SWAP_TOPIC = `0x${'c42079f94a6350d7e6235f29174924f928cc2ac818eb64fed8004e115fbcca67'}` as const;
const TRANSFER_TOPIC = `0x${'ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef'}` as const;

function eventWord(value: bigint): `0x${string}` {
  const normalized = value < 0n ? (1n << 256n) + value : value;
  return `0x${normalized.toString(16).padStart(64, '0')}`;
}

function indexedAddress(value: Address): `0x${string}` {
  return `0x${value.slice(2).toLowerCase().padStart(64, '0')}`;
}

function swapEffectFixture(inputAssetId: 'WETH' | 'USDC', samePayer: boolean, addUnobservedUnit = false) {
  const outputAssetId = inputAssetId === 'WETH' ? 'USDC' : 'WETH';
  const recipient = samePayer ? PAYER : RECIPIENT_EOA;
  const amountIn = 100n;
  const amountOut = 70n;
  const gasCost = 10n;
  const inputIsWeth = inputAssetId === 'WETH';
  const outputIsWeth = outputAssetId === 'WETH';
  const manifest = {
    swap: { tokenIn: WETH, tokenOut: USDC },
    contracts: {
      weth: { address: WETH }, usdc: { address: USDC }, swapRouter02: { address: ROUTER },
      pool: { address: POOL, codeHash: `0x${'1'.repeat(64)}`, token0: WETH, token1: USDC, fee: 500 },
      pool3000: { address: ALT_POOL, codeHash: `0x${'2'.repeat(64)}`, token0: WETH, token1: USDC, fee: 3000 },
    },
  } as unknown as RuntimeManifest;
  const before: ExecutionSnapshot = {
    blockNumber: '1', payerNativeWei: '10000', payerWethUnits: '1000', payerUsdcUnits: '2000',
    recipientWethUnits: samePayer ? '1000' : '5000', recipientUsdcUnits: samePayer ? '2000' : '6000',
    wethRouterAllowance: inputIsWeth ? '500' : '0', usdcRouterAllowance: inputIsWeth ? '0' : '500',
    poolWethUnits: '10000', poolUsdcUnits: '20000', poolLiquidity: '1000000', poolSqrtPriceX96: '12345',
  };
  const expectedPayerWeth = (inputIsWeth ? -amountIn : 0n) + (samePayer && outputIsWeth ? amountOut : 0n);
  const expectedPayerUsdc = (!inputIsWeth ? -amountIn : 0n) + (samePayer && !outputIsWeth ? amountOut : 0n);
  const expectedRecipientWeth = (outputIsWeth ? amountOut : 0n) - (samePayer && inputIsWeth ? amountIn : 0n);
  const expectedRecipientUsdc = (!outputIsWeth ? amountOut : 0n) - (samePayer && !inputIsWeth ? amountIn : 0n);
  const after: ExecutionSnapshot = {
    ...before,
    blockNumber: '2',
    payerNativeWei: (BigInt(before.payerNativeWei) - gasCost).toString(),
    payerWethUnits: (BigInt(before.payerWethUnits) + expectedPayerWeth).toString(),
    payerUsdcUnits: (BigInt(before.payerUsdcUnits) + expectedPayerUsdc + (addUnobservedUnit ? 1n : 0n)).toString(),
    recipientWethUnits: (BigInt(before.recipientWethUnits) + expectedRecipientWeth).toString(),
    recipientUsdcUnits: (BigInt(before.recipientUsdcUnits) + expectedRecipientUsdc + (addUnobservedUnit ? 1n : 0n)).toString(),
    wethRouterAllowance: inputIsWeth ? '400' : '0',
    usdcRouterAllowance: inputIsWeth ? '0' : '400',
    poolWethUnits: (BigInt(before.poolWethUnits) + (inputIsWeth ? amountIn : -amountOut)).toString(),
    poolUsdcUnits: (BigInt(before.poolUsdcUnits) + (inputIsWeth ? -amountOut : amountIn)).toString(),
    poolSqrtPriceX96: '12346',
  };
  const amount0 = inputIsWeth ? amountIn : -amountOut;
  const amount1 = inputIsWeth ? -amountOut : amountIn;
  const swapLog = {
    topics: [POOL_SWAP_TOPIC, indexedAddress(ROUTER), indexedAddress(recipient)] as [`0x${string}`, ...`0x${string}`[]],
    data: `0x${[amount0, amount1, 12346n, 1000000n, 0n].map((value) => eventWord(value).slice(2)).join('')}` as `0x${string}`,
  };
  const inputToken = inputIsWeth ? WETH : USDC;
  const outputToken = outputIsWeth ? WETH : USDC;
  const transferLog = (from: Address, to: Address, value: bigint) => ({
    topics: [TRANSFER_TOPIC, indexedAddress(from), indexedAddress(to)] as [`0x${string}`, ...`0x${string}`[]],
    data: eventWord(value),
  });
  const receipt = {
    status: 'success', from: PAYER, to: ROUTER, gasUsed: gasCost, effectiveGasPrice: 1n,
    logs: [
      { address: ALT_POOL, ...swapLog },
      { address: inputToken, ...transferLog(PAYER, ALT_POOL, amountIn) },
      { address: outputToken, ...transferLog(ALT_POOL, recipient, amountOut) },
    ],
  } as unknown as TransactionReceipt;
  const action: SelectedAction = {
    kind: 'swap', inputAssetId, outputAssetId, feeTier: 3000,
    amountInUnits: amountIn.toString(), amountOutMinimumUnits: amountOut.toString(), recipient, gasLimit: '300000',
  };
  return { action, receipt, before, after, manifest };
}

function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') {
    const object = value as Record<string, unknown>;
    return `{${Object.keys(object).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(object[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

test('swap fee selection defaults legacy actions to fee 500 and resolves only pinned pools', () => {
  const manifest = {
    contracts: {
      weth: { address: WETH }, usdc: { address: USDC },
      pool: { address: POOL, codeHash: `0x${'1'.repeat(64)}`, token0: WETH, token1: USDC, fee: 500 },
      pool3000: { address: ALT_POOL, codeHash: `0x${'2'.repeat(64)}`, token0: WETH, token1: USDC, fee: 3000 },
    },
    swap: { tokenIn: WETH, tokenOut: USDC, fee: 500 },
  } as unknown as RuntimeManifest;
  const legacy = parseSelectedAction('swap', {
    amountInWei: '10', amountOutMinimumUsdcUnits: '1', recipient: RECIPIENT_EOA, gasLimit: '300000',
  });
  assert.equal(legacy?.kind, 'swap');
  if (legacy?.kind !== 'swap') return;
  assert.equal(legacy.feeTier, 500);
  assert.equal(swapRouteAddresses(manifest, 'WETH', 'USDC', legacy.feeTier).poolAddress, POOL);
  const selected = parseSelectedAction('swap', {
    inputAssetId: 'USDC', outputAssetId: 'WETH', feeTier: 3000, amountInUnits: '10',
    amountOutMinimumUnits: '1', recipient: RECIPIENT_EOA, gasLimit: '300000',
  });
  assert.equal(selected?.kind, 'swap');
  if (selected?.kind !== 'swap') return;
  const route = swapRouteAddresses(manifest, 'USDC', 'WETH', selected.feeTier);
  assert.equal(route.poolAddress, ALT_POOL);
  assert.equal(route.fee, 3000);
  assert.equal(route.tokenIn, USDC);
  assert.equal(route.tokenOut, WETH);
  assert.equal(parseSelectedAction('swap', {
    inputAssetId: 'USDC', outputAssetId: 'WETH', feeTier: 10000, amountInUnits: '10',
    amountOutMinimumUnits: '1', recipient: RECIPIENT_EOA, gasLimit: '300000',
  }), null);
  assert.throws(() => swapRouteAddresses(manifest, 'WETH', 'USDC', 10000 as unknown as 500));
});

test('swap effect verification counts both token deltas when the recipient is the payer', () => {
  for (const inputAssetId of ['USDC', 'WETH'] as const) {
    const samePayer = swapEffectFixture(inputAssetId, true);
    assert.equal(validateActionEffects(samePayer.action, samePayer.receipt, samePayer.before, samePayer.after, PAYER, samePayer.manifest), true, `${inputAssetId} to ${samePayer.action.outputAssetId}`);
    const distinctRecipient = swapEffectFixture(inputAssetId, false);
    assert.equal(validateActionEffects(distinctRecipient.action, distinctRecipient.receipt, distinctRecipient.before, distinctRecipient.after, PAYER, distinctRecipient.manifest), true, `${inputAssetId} to ${distinctRecipient.action.outputAssetId} with a distinct recipient`);
    const extraUnobservedTokenUnit = swapEffectFixture(inputAssetId, true, true);
    assert.equal(validateActionEffects(extraUnobservedTokenUnit.action, extraUnobservedTokenUnit.receipt, extraUnobservedTokenUnit.before, extraUnobservedTokenUnit.after, PAYER, extraUnobservedTokenUnit.manifest), false, `${inputAssetId} to ${extraUnobservedTokenUnit.action.outputAssetId} with an extra token unit`);
  }
});

type RpcCode = unknown | typeof NO_RESULT;

async function startRpcServer(initialCodes: Map<string, RpcCode> = new Map()) {
  const codes = initialCodes;
  const methods: string[] = [];
  const server = createServer((request, response) => {
    let raw = '';
    request.setEncoding('utf8');
    request.on('data', (chunk: string) => { raw += chunk; });
    request.on('end', () => {
      const body = JSON.parse(raw) as { id?: unknown; method?: unknown; params?: unknown[] };
      const method = String(body.method ?? '');
      methods.push(method);
      let result: unknown;
      let omitResult = false;
      if (method === 'eth_blockNumber') result = `0x${BLOCK_NUMBER.toString(16)}`;
      else if (method === 'eth_getCode') {
        const recipient = String(body.params?.[0] ?? '').toLowerCase();
        const configured = codes.get(recipient);
        if (configured === NO_RESULT) omitResult = true;
        else result = configured;
      } else if (method === 'eth_chainId') result = '0x2105';
      else if (method === 'eth_sendRawTransaction') result = `0x${'a'.repeat(64)}`;
      else result = null;
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(JSON.stringify({ jsonrpc: '2.0', id: body.id, ...(omitResult ? {} : { result }) }));
    });
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const address = server.address() as AddressInfo;
  return {
    url: `http://127.0.0.1:${address.port}`,
    codes,
    methods,
    close: () => new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve())),
  };
}

test('recipient code classification uses raw viem RPC output and fails closed on absent or malformed code', async (context) => {
  const rpc = await startRpcServer(new Map<string, RpcCode>([
    [RECIPIENT_EOA.toLowerCase(), '0x'],
    [RECIPIENT_CONTRACT.toLowerCase(), '0x60006000'],
    [RECIPIENT_NULL.toLowerCase(), null],
    [RECIPIENT_MISSING.toLowerCase(), NO_RESULT],
    [RECIPIENT_MALFORMED.toLowerCase(), '0x0'],
  ]));
  context.after(() => rpc.close());
  const client = createPublicClient({ chain: base, transport: http(rpc.url, { retryCount: 0 }) });

  // viem's getCode action maps valid empty bytecode to undefined. The raw
  // request used by the selected-execution preflight preserves the JSON-RPC `0x`.
  assert.equal(await client.getCode({ address: RECIPIENT_EOA, blockNumber: BLOCK_NUMBER }), undefined);
  assert.equal(await recipientKindAtBlock(client, RECIPIENT_EOA, BLOCK_NUMBER), 'eoa');
  assert.equal(await recipientKindAtBlock(client, RECIPIENT_CONTRACT, BLOCK_NUMBER), 'contract');
  assert.equal(await recipientKindAtBlock(client, RECIPIENT_NULL, BLOCK_NUMBER), 'unknown');
  assert.equal(await recipientKindAtBlock(client, RECIPIENT_MISSING, BLOCK_NUMBER), 'unknown');
  assert.equal(await recipientKindAtBlock(client, RECIPIENT_MALFORMED, BLOCK_NUMBER), 'unknown');
  assert.equal(checkRecipientKind('0X'), 'unknown');
  assert.equal(checkRecipientKind('0x01f'), 'unknown');
});

class TestPoolClient {
  async query(text: string) {
    if (text.includes('pg_try_advisory_lock')) return { rows: [{ locked: true }], rowCount: 1 };
    if (text.includes("status='active'")) return { rows: [{}], rowCount: 1 };
    if (text.includes('SELECT operation_id FROM bef_operation')) return { rows: [], rowCount: 0 };
    return { rows: [], rowCount: 0 };
  }
  release(): void {}
}

async function startQuoteRpcServer() {
  const methods: string[] = [];
  const word = (value: bigint) => value.toString(16).padStart(64, '0');
  const quoteResult = `0x${[100n, 200n, 3n, 400n].map(word).join('')}`;
  const poolResult = `0x${[12345n, 1n, 0n, 4n, 4n, 0n, 1n].map(word).join('')}`;
  const server = createServer((request, response) => {
    let raw = '';
    request.setEncoding('utf8');
    request.on('data', (chunk: string) => { raw += chunk; });
    request.on('end', () => {
      const body = JSON.parse(raw) as { id?: unknown; method?: unknown; params?: Array<{ to?: unknown }> };
      const method = String(body.method ?? '');
      methods.push(method);
      let result: unknown = null;
      if (method === 'eth_blockNumber') result = `0x${BLOCK_NUMBER.toString(16)}`;
      else if (method === 'eth_chainId') result = '0x2105';
      else if (method === 'eth_call') {
        const target = String(body.params?.[0]?.to ?? '').toLowerCase();
        if (target === QUOTER.toLowerCase()) result = quoteResult;
        else if (target === POOL.toLowerCase() || target === ALT_POOL.toLowerCase()) result = poolResult;
      }
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(JSON.stringify({ jsonrpc: '2.0', id: body.id, result }));
    });
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const address = server.address() as AddressInfo;
  return {
    url: `http://127.0.0.1:${address.port}`,
    methods,
    close: () => new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve())),
  };
}

function quoteRouteFixture(tokenSha256: string, rpcUrl: string) {
  const poolClient = new TestPoolClient();
  const pool = {
    async connect() { return poolClient; },
    async query(text: string) {
      if (text.includes('SELECT participant_id,payer_address,run_token_sha256')) {
        return { rows: [{ participant_id: PARTICIPANT_ID, payer_address: PAYER, run_token_sha256: tokenSha256 }], rowCount: 1 };
      }
      return { rows: [], rowCount: 0 };
    },
  } as unknown as Pool;
  const runtime = {
    manifest: {
      guardrails: { maxTrialSeconds: 60, maxHttpRequestBytes: 4096 },
      feePolicy: { baseFeeWei: '1', priorityFeeWei: '1', ethUsdcRateNumerator: '1', ethUsdcRateDenominator: '1' },
      funding: { maxUsdcUnitsPerGeneration: '1000000' },
      swap: { route: 'uniswap-v3-exactInputSingle', tokenIn: WETH, tokenOut: USDC, fee: 500, maxAmountIn: '1000000000000000000' },
      contracts: {
        weth: { address: WETH }, usdc: { address: USDC }, quoterV2: { address: QUOTER },
        pool: { address: POOL, codeHash: `0x${'1'.repeat(64)}`, token0: WETH, token1: USDC, fee: 500 },
        pool3000: { address: ALT_POOL, codeHash: `0x${'2'.repeat(64)}`, token0: WETH, token1: USDC, fee: 3000 },
      },
    },
    pool,
    envs: new Map([['bef-a', {
      id: 'bef-a', adminRpcUrl: rpcUrl, observerRpcUrl: rpcUrl,
      facilitatorUrl: rpcUrl, facilitatorAddress: PAYER,
      anvilIdentity: {}, facilitatorIdentity: {},
    } as RuntimeEnvironment]]),
  } as unknown as SelectedExecutionRuntime;
  const dependencies = {
    signerStore: { has: () => true },
    persistence: {},
    transactionRpcUrls: new Map([['bef-a', rpcUrl]]),
  } as unknown as SelectedExecutionDependencies;
  return { runtime, dependencies };
}

test('quote GET accepts exact string fee tiers and rejects malformed or extra query parameters before RPC', async (context) => {
  const rpc = await startQuoteRpcServer();
  context.after(() => rpc.close());
  const token = randomBytes(32).toString('base64url');
  const tokenSha256 = createHash('sha256').update(token).digest('hex');
  const { runtime, dependencies } = quoteRouteFixture(tokenSha256, rpc.url);
  const app = Fastify();
  context.after(() => app.close());
  await registerSelectedExecutionRoutes(app, runtime, dependencies);

  for (const { feeTier, poolAddress } of [
    { feeTier: '500', poolAddress: POOL },
    { feeTier: '3000', poolAddress: ALT_POOL },
  ]) {
    const response = await app.inject({
      method: 'GET',
      url: `/tools/bef-a/quote?inputAssetId=USDC&feeTier=${feeTier}&amountInUnits=1`,
      headers: {
        authorization: `Bearer ${token}`,
        'x-bef-generation': GENERATION_ID,
        'idempotency-key': randomBytes(16).toString('hex'),
      },
    });
    assert.equal(response.statusCode, 200);
    const body = response.json();
    assert.equal(body.fee, Number(feeTier));
    assert.equal(body.poolAddress.toLowerCase(), poolAddress.toLowerCase());
    assert.equal(body.quoteStatus, 'observed');
    assert.equal(body.quote.feeTier, Number(feeTier));
    assert.equal(body.quote.amountOutUnits, '100');
    assert.equal(body.quote.gasEstimate, '400');
  }

  const rpcCallCountBeforeInvalidQueries = rpc.methods.length;
  for (const query of [
    'inputAssetId=USDC&amountInUnits=1&feeTier=10000',
    'inputAssetId=USDC&amountInUnits=1&feeTier=500junk',
    'inputAssetId=USDC&amountInUnits=1&feeTier=3000.0',
    'inputAssetId=USDC&amountInUnits=1&feeTier=3000&feeTier=500',
    'inputAssetId=USDC&amountInUnits=1&feeTier=3000&unexpected=1',
  ]) {
    const response = await app.inject({
      method: 'GET',
      url: `/tools/bef-a/quote?${query}`,
      headers: {
        authorization: `Bearer ${token}`,
        'x-bef-generation': GENERATION_ID,
        'idempotency-key': randomBytes(16).toString('hex'),
      },
    });
    assert.equal(response.statusCode, 400, query);
    assert.deepEqual(response.json(), { error: 'invalid_quote_amount' }, query);
  }
  assert.equal(rpc.methods.length, rpcCallCountBeforeInvalidQueries);
});

test('legacy WETH-to-USDC fee-500 request replays an operation persisted with the pre-upgrade key hash', async (context) => {
  const token = randomBytes(32).toString('base64url');
  const tokenSha256 = createHash('sha256').update(token).digest('hex');
  const action = {
    kind: 'swap',
    route: 'uniswap-v3-exactInputSingle',
    router: ROUTER,
    tokenIn: WETH,
    tokenOut: USDC,
    fee: 500,
    amountInWei: '1',
    amountOutMinimumUsdcUnits: '0',
    recipient: RECIPIENT_EOA.toLowerCase(),
    gasLimit: '300000',
  };
  const legacyRequestHash = createHash('sha256').update(canonicalJson({
    method: 'POST', path: '/tools/swap', action,
  })).digest('hex');
  const transactionHash = `0x${'ab'.repeat(32)}`;
  const poolClient = new TestPoolClient();
  const pool = {
    async connect() { return poolClient; },
    async query(text: string) {
      if (text.includes('SELECT participant_id,payer_address,run_token_sha256')) {
        return { rows: [{ participant_id: PARTICIPANT_ID, payer_address: PAYER, run_token_sha256: tokenSha256 }], rowCount: 1 };
      }
      return { rows: [], rowCount: 0 };
    },
  } as unknown as Pool;
  let observedRequestHash: string | null = null;
  const persistence = {
    async createOrGet(_client: unknown, _auth: unknown, _kind: unknown, requestHash: string) {
      observedRequestHash = requestHash;
      return {
        operationId: OPERATION_ID, requestHash: legacyRequestHash,
        status: 'settled', transactionHash, isNew: false,
      };
    },
    async readCompleted() {
      return { outcome: 'success', transactionHash, measurement: { transaction: { hash: transactionHash }, receipt: { status: 'success' } } };
    },
  };
  const runtime = {
    manifest: {
      guardrails: { maxTrialSeconds: 60, maxHttpRequestBytes: 4096 },
      feePolicy: { baseFeeWei: '1', priorityFeeWei: '1', ethUsdcRateNumerator: '1', ethUsdcRateDenominator: '1' },
      swap: { route: 'uniswap-v3-exactInputSingle', tokenIn: WETH, tokenOut: USDC, fee: 500, maxAmountIn: '1000000000000000000', maxTransactionGas: '1200000' },
      contracts: {
        weth: { address: WETH }, usdc: { address: USDC }, swapRouter02: { address: ROUTER },
        quoterV2: { address: QUOTER }, pool: { address: POOL, token0: WETH, token1: USDC, fee: 500 },
      },
    },
    pool,
    envs: new Map([['bef-a', {
      id: 'bef-a', adminRpcUrl: 'http://127.0.0.1:18545', observerRpcUrl: 'http://127.0.0.1:18545',
      facilitatorUrl: 'http://127.0.0.1:14021', facilitatorAddress: PAYER,
      anvilIdentity: {}, facilitatorIdentity: {},
    } as RuntimeEnvironment]]),
  } as unknown as SelectedExecutionRuntime;
  const dependencies = {
    signerStore: { has: () => { throw new Error('settled operations must replay before signer access'); } },
    persistence,
    transactionRpcUrls: new Map([['bef-a', 'http://127.0.0.1:18545']]),
  } as unknown as SelectedExecutionDependencies;
  const app = Fastify();
  context.after(() => app.close());
  await registerSelectedExecutionRoutes(app, runtime, dependencies);

  const response = await app.inject({
    method: 'POST',
    url: '/tools/bef-a/swap',
    headers: {
      authorization: `Bearer ${token}`,
      'x-bef-generation': GENERATION_ID,
      'idempotency-key': 'ab'.repeat(16),
    },
    payload: {
      amountInWei: '1', amountOutMinimumUsdcUnits: '0', recipient: RECIPIENT_EOA,
      gasLimit: '300000',
    },
  });

  assert.equal(observedRequestHash, legacyRequestHash);
  assert.equal(response.statusCode, 200);
  assert.equal(response.json().replayed, true);
  assert.equal(response.json().transaction.hash, transactionHash);
});

test('unknown recipient-code observation returns operation id and durably rejects before broadcast', async (context) => {
  const rpc = await startRpcServer(new Map<string, RpcCode>([[RECIPIENT_NULL.toLowerCase(), null]]));
  context.after(() => rpc.close());
  const token = randomBytes(32).toString('base64url');
  const tokenSha256 = createHash('sha256').update(token).digest('hex');
  const poolClient = new TestPoolClient();
  const rejections: Array<{ operationId: string; reason: string }> = [];
  const pool = {
    async connect() { return poolClient; },
    async query(text: string) {
      if (text.includes('SELECT participant_id,payer_address,run_token_sha256')) {
        return { rows: [{ participant_id: PARTICIPANT_ID, payer_address: PAYER, run_token_sha256: tokenSha256 }], rowCount: 1 };
      }
      return { rows: [], rowCount: 0 };
    },
  } as unknown as Pool;
  const persistence = {
    async createOrGet(_client: unknown, _auth: unknown, _kind: unknown, requestHash: string) {
      return { operationId: OPERATION_ID, requestHash, status: 'accepted', transactionHash: null, isNew: true };
    },
    async rejectBeforeBroadcast(_client: unknown, operationId: string, reason: string) {
      rejections.push({ operationId, reason });
    },
  };
  const runtime = {
    manifest: {
      guardrails: { maxTrialSeconds: 60, maxHttpRequestBytes: 4096 },
      feePolicy: {
        baseFeeWei: '1', priorityFeeWei: '1', ethUsdcRateNumerator: '1', ethUsdcRateDenominator: '1',
      },
      swap: {
        route: 'uniswap-v3-exactInputSingle', tokenIn: WETH, tokenOut: USDC, fee: 500,
        maxAmountIn: '1000000000000000000', maxTransactionGas: '1200000',
      },
      contracts: {
        weth: { address: WETH }, usdc: { address: USDC }, swapRouter02: { address: ROUTER },
        quoterV2: { address: QUOTER }, pool: { address: POOL, token0: WETH, token1: USDC, fee: 500 },
      },
    },
    pool,
    envs: new Map([['bef-a', {
      id: 'bef-a', adminRpcUrl: rpc.url, observerRpcUrl: rpc.url,
      facilitatorUrl: rpc.url, facilitatorAddress: PAYER,
      anvilIdentity: {}, facilitatorIdentity: {},
    } as RuntimeEnvironment]]),
  } as unknown as SelectedExecutionRuntime;
  const dependencies = {
    signerStore: { has: () => true },
    persistence,
    transactionRpcUrls: new Map([['bef-a', rpc.url]]),
  } as unknown as SelectedExecutionDependencies;
  const app = Fastify();
  context.after(() => app.close());
  await registerSelectedExecutionRoutes(app, runtime, dependencies);

  const response = await app.inject({
    method: 'POST',
    url: '/tools/bef-a/swap',
    headers: {
      authorization: `Bearer ${token}`,
      'x-bef-generation': GENERATION_ID,
      'idempotency-key': randomBytes(16).toString('hex'),
    },
    payload: {
      amountInWei: '1', amountOutMinimumUsdcUnits: '0', recipient: RECIPIENT_NULL,
      gasLimit: '300000',
    },
  });

  assert.equal(response.statusCode, 503);
  assert.deepEqual(response.json(), {
    error: 'recipient_code_observation_unavailable', operationId: OPERATION_ID,
  });
  assert.deepEqual(rejections, [{ operationId: OPERATION_ID, reason: 'recipient_code_observation_unavailable' }]);
  assert.equal(rpc.methods.includes('eth_sendRawTransaction'), false);
});
