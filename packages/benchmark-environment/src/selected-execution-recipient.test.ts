import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { once } from 'node:events';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import test from 'node:test';
import Fastify from 'fastify';
import type { Pool } from 'pg';
import { createPublicClient, http, type Address } from 'viem';
import { base } from 'viem/chains';
import {
  checkRecipientKind,
  recipientKindAtBlock,
  registerSelectedExecutionRoutes,
  type SelectedExecutionDependencies,
  type SelectedExecutionRuntime,
} from './selected-execution.js';
import type { RuntimeEnvironment } from './runtime.js';

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
const BLOCK_NUMBER = 52982199n;
const NO_RESULT = Symbol('no JSON-RPC result');

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
