import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';
import type { TaskCase, TaskReleaseQuerySource, ValidatedTaskReleaseRecord } from './task-release.js';
import { sha256CanonicalTaskJson } from './task-release.js';
import {
  BefTaskPreparationAdapter,
  taskPreparationPublicPinsSha256,
  type BefPreparationDiagnostic,
  type BefTaskPreparationAdapterDependencies,
  type SafeTaskPreparationEvidence,
} from './bef-task-preparation.js';
import type { TaskPreparationIntentPins } from './task-preparation.js';

const preparationId = '11111111-1111-4111-8111-111111111111';
const runId = '22222222-2222-4222-8222-222222222222';
const claimId = '33333333-3333-4333-8333-333333333333';
const leaseId = '44444444-4444-4444-8444-444444444444';
const generationId = '55555555-5555-4555-8555-555555555555';
const environmentId = 'test-env';
const manifestHash = 'a'.repeat(64);
const environmentManifestSha256 = 'b'.repeat(64);
const applicationSourceHash = 'c'.repeat(64);
const executionIdentityHash = 'd'.repeat(64);
const caseHash = 'e'.repeat(64);
const sourceBlockHash = 'f'.repeat(64);
const forkBlockHash = `0x${sourceBlockHash}`;
const fixtureTransactionHash = `0x${'9'.repeat(64)}`;
const s4SetupTransactionHash = `0x${'8'.repeat(64)}`;
const s4SetupBlockHash = `0x${'7'.repeat(64)}`;
const usdcAddress = '0x1111111111111111111111111111111111111111';
const wethAddress = '0x5555555555555555555555555555555555555555';
const donorAddress = '0x2222222222222222222222222222222222222222';
const routerAddress = '0x4444444444444444444444444444444444444444';
const amountUnits = '1000000';
const s4AllowanceUnits = '10000';
const s4UsdcBalance = '100000000';
const s4NativeBalance = '10000000000000000000';
const s4GasUsed = 55425n;
const s4EffectiveGasPrice = 5375195n;
const s4GasCost = s4GasUsed * s4EffectiveGasPrice;
const s4TaskNativeBalance = (BigInt(s4NativeBalance) - s4GasCost).toString();
const transferTopic = '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef';
const approvalTopic = '0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925';
const topicAddress = (address: string) => `0x${address.slice(2).toLowerCase().padStart(64, '0')}`;
const hexWord = (value: bigint) => `0x${value.toString(16).padStart(64, '0')}`;
const hexQuantityForTest = (value: bigint) => `0x${value.toString(16)}`;

function makeIntent(): TaskPreparationIntentPins {
  return {
    preparationId, runId, taskIndex: 0, claimId, leaseId, environmentId,
    releaseIdentity: 'release-a', manifestHash, taskId: 'S1', caseId: 'case-s1', caseHash,
    initialStateSha256: '0'.repeat(64), executionIdentityHash,
    environmentManifestSha256, applicationSourceHash, createdAt: '2026-10-27T10:00:00.000Z',
  };
}

function makeRelease(taskId: 'S1' | 'S2' = 'S1'): { intent: TaskPreparationIntentPins; release: ValidatedTaskReleaseRecord } {
  const balances = [{ account: 'participant', assetId: 'USDC', amountUnits }];
  const allowances = [{ owner: 'participant', tokenAssetId: 'USDC', spender: routerAddress, amountUnits: '0' }];
  const projection = {
    balances,
    allowances,
    deliveredComponentIds: [],
    fulfilledObligationIds: [],
  };
  const initialStateSha256 = sha256CanonicalTaskJson(projection);
  const intent = { ...makeIntent(), taskId, initialStateSha256 };
  const taskCase = {
    caseId: intent.caseId,
    caseHash,
    taskId,
    executionIdentityHash,
    initialState: { stateSha256: initialStateSha256, ...projection },
    objective: taskId === 'S2' ? { completePaymentRequirements: { recipient: donorAddress } } : {},
  } as unknown as TaskCase;
  const executionIdentity = {
    environmentManifestSha256,
    x402ServiceSha256: applicationSourceHash,
    sourceNetwork: 'eip155:8453',
    sourceChainId: 8453,
    sourceBlockNumber: '100',
    sourceBlockHash,
    localNetwork: 'eip155:8453',
    localChainId: 8453,
    localForkBlockNumber: '100',
    assets: [{ assetId: 'USDC', kind: 'erc20', chainId: 8453, address: usdcAddress, codeHash: null, decimals: 6 }],
    contracts: [
      { contractId: 'usdc', address: usdcAddress, codeHash: 'a'.repeat(64), chainId: 8453, blockNumber: '100', blockHash: sourceBlockHash },
      { contractId: 'router', address: routerAddress, codeHash: 'b'.repeat(64), chainId: 8453, blockNumber: '100', blockHash: sourceBlockHash },
    ],
  };
  const release = {
    releaseIdentity: intent.releaseIdentity,
    manifestHash,
    manifest: {
      executionIdentityHash,
      executionIdentity,
      cases: { training: [taskCase], ranked: [] },
    },
  } as unknown as ValidatedTaskReleaseRecord;
  return { intent, release };
}

function makeS4Release(): { intent: TaskPreparationIntentPins; release: ValidatedTaskReleaseRecord } {
  const balances = [
    { account: 'participant', assetId: 'ETH', amountUnits: s4TaskNativeBalance },
    { account: 'participant', assetId: 'USDC', amountUnits: s4UsdcBalance },
    { account: 'participant', assetId: 'WETH', amountUnits: '0' },
  ];
  const allowances = [
    { owner: 'participant', tokenAssetId: 'USDC', spender: routerAddress, amountUnits: s4AllowanceUnits },
    { owner: 'participant', tokenAssetId: 'WETH', spender: routerAddress, amountUnits: '0' },
  ];
  const projection = { balances, allowances, deliveredComponentIds: [], fulfilledObligationIds: [] };
  const initialStateSha256 = sha256CanonicalTaskJson(projection);
  const intent: TaskPreparationIntentPins = { ...makeIntent(), taskId: 'S4', caseId: 'case-s4', initialStateSha256 };
  const taskCase = {
    caseId: intent.caseId, caseHash, taskId: 'S4', executionIdentityHash,
    initialState: { stateSha256: initialStateSha256, ...projection },
    objective: {
      tokenAssetId: 'USDC', owner: 'participant', spender: routerAddress,
      initialAllowanceUnits: s4AllowanceUnits,
      unrelatedAllowanceBaselineSha256: sha256CanonicalTaskJson({ wethRouterAllowanceUnits: '0' }),
    },
  } as unknown as TaskCase;
  const executionIdentity = {
    environmentManifestSha256,
    x402ServiceSha256: applicationSourceHash,
    sourceNetwork: 'eip155:8453', sourceChainId: 8453, sourceBlockNumber: '100', sourceBlockHash,
    localNetwork: 'eip155:8453', localChainId: 8453, localForkBlockNumber: '100',
    assets: [
      { assetId: 'ETH', kind: 'native', chainId: 8453, address: null, codeHash: null, decimals: 18 },
      { assetId: 'USDC', kind: 'erc20', chainId: 8453, address: usdcAddress, codeHash: null, decimals: 6 },
      { assetId: 'WETH', kind: 'erc20', chainId: 8453, address: wethAddress, codeHash: null, decimals: 18 },
    ],
    contracts: [
      { contractId: 'usdc', address: usdcAddress, codeHash: 'a'.repeat(64), chainId: 8453, blockNumber: '100', blockHash: sourceBlockHash },
      { contractId: 'weth', address: wethAddress, codeHash: 'b'.repeat(64), chainId: 8453, blockNumber: '100', blockHash: sourceBlockHash },
      { contractId: 'swapRouter02', address: routerAddress, codeHash: 'c'.repeat(64), chainId: 8453, blockNumber: '100', blockHash: sourceBlockHash },
    ],
  };
  const release = {
    releaseIdentity: intent.releaseIdentity, manifestHash,
    manifest: { executionIdentityHash, executionIdentity, cases: { training: [taskCase], ranked: [] } },
  } as unknown as ValidatedTaskReleaseRecord;
  return { intent, release };
}

function preparationRequestHash(input: {
  preparationId: string; envId: string; manifestSha256: string; publicPinsSha256: string;
  participantId: string; payerAddress: string; resourceVariant: string;
}): string {
  return createHash('sha256').update(JSON.stringify([
    input.preparationId, input.envId, input.manifestSha256, input.publicPinsSha256.toLowerCase(),
    input.participantId, input.payerAddress.toLowerCase(), input.resourceVariant,
  ])).digest('hex');
}

function publicStatus(args: {
  status: 'ready' | 'fenced' | 'unknown';
  generationId: string | null;
  request?: Record<string, unknown> | null;
  fixture?: Record<string, unknown>;
  fenceConfirmedAt?: string | null;
}): Record<string, unknown> {
  return {
    schemaVersion: 'bef-preparation-status/v1', envId: environmentId, preparationId,
    status: args.status, generationId: args.generationId,
    request: args.request ?? null,
    fixture: args.fixture ?? {
      state: 'not_started', transactionHash: null, blockHash: null, fixtureHash: null, facts: null,
    },
    baselineReset: args.status === 'ready' ? {
      identity: {
        clientVersion: 'anvil/v1.8.6', chainId: '0x2105', executionNetwork: 'ethereum', hardFork: 'Prague',
        forkBlockNumber: '0x64', forkBlockHash,
        manifestSha256: environmentManifestSha256, facilitatorRecovered: true,
      }, completedAt: '2026-10-27T10:00:01.000Z',
    } : null,
    fenceConfirmedAt: args.fenceConfirmedAt ?? null,
  };
}

function preparationStatusFromPut(intent: TaskPreparationIntentPins, input: Record<string, unknown>): Record<string, unknown> {
  const fundingAmount = intent.taskId === 'S4' ? s4UsdcBalance : amountUnits;
  const participantId = String(input.participantId);
  const payerAddress = String(input.payerAddress).toLowerCase();
  const requestSha256 = preparationRequestHash({
    preparationId: intent.preparationId,
    envId: intent.environmentId,
    manifestSha256: intent.environmentManifestSha256.toLowerCase(),
    publicPinsSha256: String(input.publicPinsSha256),
    participantId,
    payerAddress,
    resourceVariant: String(input.resourceVariant),
  });
  return publicStatus({
    status: 'ready', generationId,
    request: {
      requestSha256, publicPinsSha256: input.publicPinsSha256, participantId, payerAddress,
      resourceVariant: input.resourceVariant, manifestSha256: intent.environmentManifestSha256.toLowerCase(),
    },
    fixture: {
      state: 'observed', transactionHash: fixtureTransactionHash, blockHash: forkBlockHash,
      fixtureHash: '7'.repeat(64),
      facts: {
        amountUnits: fundingAmount,
        payerTokenBefore: '0', payerTokenAfter: fundingAmount,
        donorTokenBefore: '900000000', donorTokenAfter: (BigInt('900000000') - BigInt(fundingAmount)).toString(),
        payerNativeBalance: '1000000000000000000',
        receiptObservation: { pollCount: 1, nullReceiptCount: 0, extraDiagnostic: 'omit this untrusted field' },
      },
    },
  });
}

function testDependencies(
  release: ValidatedTaskReleaseRecord,
  mockFetch: typeof fetch,
  evidence: SafeTaskPreparationEvidence[],
): BefTaskPreparationAdapterDependencies {
  const releaseSource = {
    async getValidatedReleaseRecord() { return release; },
  } as unknown as TaskReleaseQuerySource;
  return {
    apiBaseByEnvironment: { [environmentId]: 'http://bef.test' },
    observerRpcByEnvironment: { [environmentId]: 'http://observer.test' },
    sourceRpcUrl: 'http://source.test', adminKey: 'test-admin-key', releaseSource,
    anvilManifestPinByEnvironment: { [environmentId]: {
      manifestSha256: environmentManifestSha256, executionNetwork: 'ethereum', hardFork: 'prague', anvilVersion: '1.8.6',
    } },
    evidenceSink: {
      async write(value) {
        evidence.push(value);
        return { path: `artifacts/preparation/${value.kind}.json`, sha256: createHash('sha256').update(JSON.stringify(value)).digest('hex'),
          boundary: 'actual_tool_http_x402_local_evm_application_store' };
      },
    },
    fetch: mockFetch,
    requestTimeoutMs: 5_000,
  };
}

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
}

function rpcResult(url: URL, request: Record<string, unknown>, options: { baselineMismatch?: boolean; baselineMalformedAbiResult?: boolean } = {}): unknown {
  const method = String(request.method);
  const params = request.params as unknown[];
  if (method === 'eth_chainId') return '0x2105';
  if (method === 'eth_getBlockByNumber') return { number: params[0], hash: forkBlockHash, extraSecret: 'do-not-persist' };
  if (method === 'eth_blockNumber') return '0x64';
  if (url.hostname === 'observer.test' && method === 'eth_getTransactionReceipt') {
    return {
      transactionHash: fixtureTransactionHash, blockHash: forkBlockHash, blockNumber: '0x64', status: '0x1',
      from: donorAddress, to: usdcAddress,
      logs: [{
        address: usdcAddress,
        topics: [transferTopic, topicAddress(donorAddress), topicAddress(String(request.__payerAddress ?? '0x3333333333333333333333333333333333333333'))],
        data: `0x${BigInt(amountUnits).toString(16).padStart(64, '0')}`, logIndex: '0x0', secretField: 'do-not-persist',
      }],
    };
  }
  if (url.hostname === 'observer.test' && method === 'eth_getTransactionByHash') {
    const payer = String(request.__payerAddress ?? '0x3333333333333333333333333333333333333333');
    return {
      hash: fixtureTransactionHash, blockHash: forkBlockHash, blockNumber: '0x64',
      from: donorAddress, to: usdcAddress,
      input: `0xa9059cbb${payer.slice(2).toLowerCase().padStart(64, '0')}${BigInt(amountUnits).toString(16).padStart(64, '0')}`,
      secretField: 'do-not-persist',
    };
  }
  if (method === 'eth_getBalance') return '0xde0b6b3a7640000';
  if (method === 'eth_call') {
    const call = params[0] as Record<string, unknown> | undefined;
    const data = typeof call?.data === 'string' ? call.data.toLowerCase() : '';
    if (data.startsWith('0xdd62ed3e')) return `0x${'0'.repeat(64)}`;
    const amount = BigInt(amountUnits) + (options.baselineMismatch ? 1n : 0n);
    if (options.baselineMalformedAbiResult) return `0x${amount.toString(16)}`;
    return `0x${amount.toString(16).padStart(64, '0')}`;
  }
  return null;
}

function makeFetch(intent: TaskPreparationIntentPins, options: {
  losePutReply?: boolean; baselineMismatch?: boolean; baselineMalformedAbiResult?: boolean; facilitatorAddress?: string;
  sourceHealthHttpStatuses?: Array<number | null>; localHealthHttpStatuses?: Array<number | null>; sourceHealthMalformedBody?: string;
  sourceHealthResponseVariant?: 'rpc_error' | 'correlation_invalid' | 'item_shape_invalid' | 'result_missing' | 'batch_shape_invalid';
  sourceRpcPinMismatch?: boolean;
  putFailure?: { status: number; body: unknown };
  putMalformedBody?: string;
} = {}): {
  fetch: typeof fetch; get putCount(): number; get putBody(): Record<string, unknown> | null; get reconcilePostCount(): number;
  get sourceHealthBatchCount(): number; get localHealthBatchCount(): number; calls: string[];
} {
  let putCount = 0;
  let reconcilePostCount = 0;
  let sourceHealthBatchCount = 0;
  let localHealthBatchCount = 0;
  let putBody: Record<string, unknown> | null = null;
  let status: Record<string, unknown> | null = null;
  const calls: string[] = [];
  const fetchMock: typeof fetch = async (input, init) => {
    const url = new URL(String(input));
    const method = init?.method ?? 'GET';
    calls.push(`${method} ${url.hostname}${url.pathname}`);
    if (url.pathname === '/healthz' && url.hostname === 'bef.test') {
      return jsonResponse(200, {
        status: 'ready', boundary: 'benchmark-environment-api',
        manifestSha256: environmentManifestSha256, applicationSourceSha256: applicationSourceHash,
        environments: [{ envId: environmentId, anvil: {
          clientVersion: 'anvil/v1.8.6', chainId: '0x2105', executionNetwork: 'ethereum', hardFork: 'Prague',
          forkBlockNumber: '0x64', forkBlockHash,
        }, facilitator: { address: options.facilitatorAddress ?? donorAddress } }],
      });
    }
    if (url.pathname === '/healthz' && url.hostname === 'source.test') {
      return jsonResponse(200, { status: 'ok', boundary: 'source-readonly-proxy', manifestSha256: environmentManifestSha256 });
    }
    if (url.pathname.includes('/preparations/') && url.pathname.endsWith('/fence') && method === 'POST') {
      status = publicStatus({ status: 'fenced', generationId, fenceConfirmedAt: '2026-10-27T10:01:00.000Z' });
      return jsonResponse(200, { ...status, fenceConfirmed: true, signerErased: true, chainState: 'not_touched' });
    }
    if (url.pathname.includes('/preparations/') && url.pathname.endsWith('/reconcile') && method === 'POST') {
      reconcilePostCount += 1;
      return jsonResponse(200, { outcome: 'observed' });
    }
    if (url.pathname.includes('/preparations/') && method === 'PUT') {
      putCount += 1;
      putBody = JSON.parse(String(init?.body)) as Record<string, unknown>;
      status = preparationStatusFromPut(intent, putBody);
      if (options.losePutReply) throw new Error('simulated lost PUT response');
      if (options.putFailure || options.putMalformedBody !== undefined) {
        status = publicStatus({ status: 'unknown', generationId });
        if (options.putMalformedBody !== undefined) return new Response(options.putMalformedBody, { status: 503 });
        return jsonResponse(options.putFailure!.status, options.putFailure!.body);
      }
      return jsonResponse(201, {
        envId: environmentId, preparationId, generationId, participantId: putBody.participantId,
        payerAddress: putBody.payerAddress, runToken: 'R'.repeat(43),
        expiresAt: new Date(Date.now() + 60_000).toISOString(),
      });
    }
    if (url.pathname.includes('/preparations/') && method === 'GET') {
      return status ? jsonResponse(200, status) : jsonResponse(404, { error: 'preparation_not_found' });
    }
    if (method === 'POST' && ['source.test', 'observer.test'].includes(url.hostname)) {
      const body = JSON.parse(String(init?.body)) as Record<string, unknown> | Array<Record<string, unknown>>;
      if (Array.isArray(body)) {
        const sourceHealthBatch = url.hostname === 'source.test' && body.some((item) => item.id === 'source-chain-id');
        const localHealthBatch = url.hostname === 'observer.test' && body.some((item) => item.id === 'local-chain-id');
        if (sourceHealthBatch) {
          const attempt = sourceHealthBatchCount++;
          const status = options.sourceHealthHttpStatuses?.[attempt];
          if (status !== undefined && status !== null) return jsonResponse(status, { error: 'RAW_SECRET_SENTINEL' });
          if (attempt === 0 && options.sourceHealthMalformedBody !== undefined) {
            return new Response(options.sourceHealthMalformedBody, { status: 200, headers: { 'content-type': 'application/json' } });
          }
          if (attempt === 0 && options.sourceHealthResponseVariant) {
            const responses = body.map((item) => ({ jsonrpc: '2.0', id: item.id, result: rpcResult(url, item, options) }));
            if (options.sourceHealthResponseVariant === 'batch_shape_invalid') return jsonResponse(200, responses.slice(0, 1));
            const first = responses[0]!;
            if (options.sourceHealthResponseVariant === 'rpc_error') {
              delete first.result;
              Object.assign(first, { error: { code: -32000, message: 'RAW_SECRET_SENTINEL' } });
            } else if (options.sourceHealthResponseVariant === 'correlation_invalid') first.id = 'unexpected-id';
            else if (options.sourceHealthResponseVariant === 'item_shape_invalid') first.jsonrpc = '1.0';
            else if (options.sourceHealthResponseVariant === 'result_missing') delete first.result;
            return jsonResponse(200, responses);
          }
        }
        if (localHealthBatch) {
          const attempt = localHealthBatchCount++;
          const status = options.localHealthHttpStatuses?.[attempt];
          if (status !== undefined && status !== null) return jsonResponse(status, { error: 'RAW_SECRET_SENTINEL' });
        }
        return jsonResponse(200, body.map((item) => {
          const result = rpcResult(url, item, options);
          if (options.sourceRpcPinMismatch && url.hostname === 'source.test' && item.id === 'source-pinned-block' &&
              result && typeof result === 'object') return { jsonrpc: '2.0', id: item.id, result: { ...result, hash: `0x${'0'.repeat(64)}` } };
          return { jsonrpc: '2.0', id: item.id, result };
        }));
      }
      // The payer is stored on the fixture status created by the PUT; use it to bind the transfer proof.
      const req = { ...body };
      if (String(body.method) === 'eth_getTransactionReceipt' || String(body.method) === 'eth_getTransactionByHash') {
        const requestStatus = status?.request as Record<string, unknown> | null;
        req.__payerAddress = requestStatus?.payerAddress;
      }
      return jsonResponse(200, { jsonrpc: '2.0', id: body.id, result: rpcResult(url, req, options) });
    }
    return jsonResponse(404, { error: 'not_found' });
  };
  return {
    fetch: fetchMock,
    get putCount() { return putCount; },
    get putBody() { return putBody; },
    get reconcilePostCount() { return reconcilePostCount; },
    get sourceHealthBatchCount() { return sourceHealthBatchCount; },
    get localHealthBatchCount() { return localHealthBatchCount; },
    calls,
  };
}

function makeS4Fetch(intent: TaskPreparationIntentPins, options: {
  loseApproveReply?: boolean; baselineMismatch?: boolean; badApprovalLog?: boolean; wrongSelectedSpender?: boolean;
} = {}): {
  fetch: typeof fetch; get putCount(): number; get putBody(): Record<string, unknown> | null; get approvePostCount(): number;
  get approveBody(): Record<string, unknown> | null; get approveHeaders(): Headers | null; calls: string[];
} {
  let putCount = 0;
  let putBody: Record<string, unknown> | null = null;
  let approvePostCount = 0;
  let approveBody: Record<string, unknown> | null = null;
  let approveHeaders: Headers | null = null;
  let status: Record<string, unknown> | null = null;
  let setupApplied = false;
  const calls: string[] = [];
  const rpc = (request: Record<string, unknown>): unknown => {
    const method = String(request.method);
    const params = request.params as unknown[];
    if (method === 'eth_chainId') return '0x2105';
    if (method === 'eth_blockNumber') return setupApplied ? '0x65' : '0x64';
    if (method === 'eth_getBlockByNumber') {
      const tag = String(params[0]).toLowerCase();
      if (tag === '0x64') return { number: '0x64', hash: forkBlockHash, parentHash: `0x${'6'.repeat(64)}`, transactions: [] };
      if (tag === '0x65') return {
        number: '0x65', hash: s4SetupBlockHash, parentHash: forkBlockHash,
        transactions: [{ hash: s4SetupTransactionHash,
          from: String((status?.request as Record<string, unknown> | undefined)?.payerAddress ?? '').toLowerCase() }],
      };
      return null;
    }
    if (method === 'eth_getBalance') {
      const value = setupApplied ? BigInt(s4TaskNativeBalance) : BigInt(s4NativeBalance);
      return hexQuantityForTest(value);
    }
    if (method === 'eth_call') {
      const call = params[0] as Record<string, unknown>;
      const to = String(call.to).toLowerCase();
      const data = String(call.data).toLowerCase();
      if (data.startsWith('0x70a08231')) {
        const amount = to === usdcAddress ? BigInt(s4UsdcBalance) + (options.baselineMismatch ? 1n : 0n) : 0n;
        return hexWord(amount);
      }
      if (data.startsWith('0xdd62ed3e')) {
        const spender = `0x${data.slice(98, 138)}`;
        return hexWord(setupApplied && to === usdcAddress && spender === routerAddress ? BigInt(s4AllowanceUnits) : 0n);
      }
      return null;
    }
    if (method === 'eth_getTransactionReceipt' && String(params[0]).toLowerCase() === fixtureTransactionHash) {
      const payer = String((status?.request as Record<string, unknown> | undefined)?.payerAddress ?? '0x3333333333333333333333333333333333333333').toLowerCase();
      return {
        transactionHash: fixtureTransactionHash, blockHash: forkBlockHash, blockNumber: '0x64', status: '0x1',
        from: donorAddress, to: usdcAddress,
        logs: [{ address: usdcAddress, topics: [transferTopic, topicAddress(donorAddress), topicAddress(payer)],
          data: hexWord(BigInt(s4UsdcBalance)), logIndex: '0x0' }],
      };
    }
    if (method === 'eth_getTransactionByHash' && String(params[0]).toLowerCase() === fixtureTransactionHash) {
      const payer = String((status?.request as Record<string, unknown> | undefined)?.payerAddress ?? '0x3333333333333333333333333333333333333333').toLowerCase();
      return {
        hash: fixtureTransactionHash, blockHash: forkBlockHash, blockNumber: '0x64', from: donorAddress, to: usdcAddress,
        input: `0xa9059cbb${payer.slice(2).padStart(64, '0')}${BigInt(s4UsdcBalance).toString(16).padStart(64, '0')}`,
      };
    }
    if (method === 'eth_getTransactionReceipt' && String(params[0]).toLowerCase() === s4SetupTransactionHash) {
      const payer = String((status?.request as Record<string, unknown> | undefined)?.payerAddress ?? '').toLowerCase();
      return {
        transactionHash: s4SetupTransactionHash, blockHash: s4SetupBlockHash, blockNumber: '0x65', transactionIndex: '0x0',
        status: '0x1', from: payer, to: usdcAddress, gasUsed: hexQuantityForTest(s4GasUsed),
        effectiveGasPrice: hexQuantityForTest(s4EffectiveGasPrice),
        logs: [{ address: usdcAddress, topics: [approvalTopic, topicAddress(payer), topicAddress(routerAddress)],
          data: options.badApprovalLog ? hexWord(BigInt(s4AllowanceUnits) + 1n) : hexWord(BigInt(s4AllowanceUnits)),
          transactionHash: s4SetupTransactionHash, transactionIndex: '0x0', blockHash: s4SetupBlockHash,
          blockNumber: '0x65', logIndex: '0x0', removed: false }],
      };
    }
    if (method === 'eth_getTransactionByHash' && String(params[0]).toLowerCase() === s4SetupTransactionHash) {
      const payer = String((status?.request as Record<string, unknown> | undefined)?.payerAddress ?? '').toLowerCase();
      return {
        hash: s4SetupTransactionHash, from: payer, to: usdcAddress, value: '0x0', nonce: '0x0', type: '0x2',
        chainId: '0x2105', gas: '0x186a0', blockHash: s4SetupBlockHash, blockNumber: '0x65', transactionIndex: '0x0',
        input: `0x095ea7b3${routerAddress.slice(2).toLowerCase().padStart(64, '0')}${BigInt(s4AllowanceUnits).toString(16).padStart(64, '0')}`,
      };
    }
    return null;
  };
  const fetchMock: typeof fetch = async (input, init) => {
    const url = new URL(String(input));
    const method = init?.method ?? 'GET';
    calls.push(`${method} ${url.hostname}${url.pathname}`);
    if (url.pathname === '/healthz' && url.hostname === 'bef.test') {
      return jsonResponse(200, {
        status: 'ready', boundary: 'benchmark-environment-api', manifestSha256: environmentManifestSha256,
        applicationSourceSha256: applicationSourceHash,
        environments: [{ envId: environmentId, anvil: {
          clientVersion: 'anvil/v1.8.6', chainId: '0x2105', executionNetwork: 'ethereum', hardFork: 'Prague',
          forkBlockNumber: '0x64', forkBlockHash,
        }, facilitator: { address: donorAddress } }],
      });
    }
    if (url.pathname === '/healthz' && url.hostname === 'source.test') {
      return jsonResponse(200, { status: 'ok', boundary: 'source-readonly-proxy', manifestSha256: environmentManifestSha256 });
    }
    if (url.pathname.endsWith('/fence') && method === 'POST') {
      status = publicStatus({ status: 'fenced', generationId, fenceConfirmedAt: '2026-10-27T10:01:00.000Z' });
      return jsonResponse(200, { ...status, fenceConfirmed: true, signerErased: true, chainState: 'not_touched' });
    }
    if (url.pathname.includes('/preparations/') && method === 'PUT') {
      putCount += 1;
      const body = JSON.parse(String(init?.body)) as Record<string, unknown>;
      putBody = body;
      status = preparationStatusFromPut(intent, body);
      return jsonResponse(201, {
        envId: environmentId, preparationId, generationId, participantId: body.participantId,
        payerAddress: body.payerAddress, runToken: 'R'.repeat(43),
        expiresAt: new Date(Date.now() + 60_000).toISOString(),
      });
    }
    if (url.pathname.includes('/preparations/') && method === 'GET') {
      return status ? jsonResponse(200, status) : jsonResponse(404, { error: 'preparation_not_found' });
    }
    if (url.pathname === `/tools/${environmentId}/approve` && method === 'POST') {
      approvePostCount += 1;
      approveBody = JSON.parse(String(init?.body)) as Record<string, unknown>;
      approveHeaders = new Headers(init?.headers);
      const payer = String((status?.request as Record<string, unknown> | undefined)?.payerAddress ?? '').toLowerCase();
      setupApplied = true;
      const receipt = {
        transactionHash: s4SetupTransactionHash, from: payer, to: usdcAddress, status: 'success',
        blockHash: s4SetupBlockHash, blockNumber: '101', gasUsed: s4GasUsed.toString(),
        effectiveGasPrice: s4EffectiveGasPrice.toString(), gasCostWei: s4GasCost.toString(),
        logs: [{ address: usdcAddress, topics: [approvalTopic, topicAddress(payer), topicAddress(routerAddress)],
          data: hexWord(BigInt(s4AllowanceUnits)), logIndex: '0' }],
      };
      if (options.loseApproveReply) throw new Error('simulated lost approve response');
      return jsonResponse(200, {
        outcome: 'success', operationId: '88888888-8888-4888-8888-888888888888', receipt,
        transaction: {
          hash: s4SetupTransactionHash, type: 'eip1559', chainId: 8453, blockHash: s4SetupBlockHash,
          blockNumber: '101', transactionIndex: '0', from: payer, to: usdcAddress, nonce: '0',
          input: `0x095ea7b3${routerAddress.slice(2).toLowerCase().padStart(64, '0')}${BigInt(s4AllowanceUnits).toString(16).padStart(64, '0')}`,
          valueWei: '0', gasLimit: '100000', maxFeePerGasWei: '6000000', maxPriorityFeePerGasWei: '1000000',
        },
        payerBlock: { hash: s4SetupBlockHash, number: '101', parentHash: forkBlockHash,
          transactions: [{ hash: s4SetupTransactionHash, from: payer }] },
        selectedAction: { kind: 'approve', tokenAssetId: 'USDC', token: usdcAddress,
          spender: options.wrongSelectedSpender ? donorAddress : routerAddress,
          amountUnits: s4AllowanceUnits, gasLimit: '100000' },
      });
    }
    if (method === 'POST' && ['observer.test', 'source.test'].includes(url.hostname)) {
      const body = JSON.parse(String(init?.body)) as Record<string, unknown> | Array<Record<string, unknown>>;
      if (Array.isArray(body)) return jsonResponse(200, body.map((item) => ({ jsonrpc: '2.0', id: item.id, result: rpc(item) })));
      return jsonResponse(200, { jsonrpc: '2.0', id: body.id, result: rpc(body) });
    }
    return jsonResponse(404, { error: 'not_found' });
  };
  return {
    fetch: fetchMock,
    get putCount() { return putCount; },
    get putBody() { return putBody; },
    get approvePostCount() { return approvePostCount; },
    get approveBody() { return approveBody; },
    get approveHeaders() { return approveHeaders; },
    calls,
  };
}

test('prepares from a secret-free public projection and same-block baseline', async () => {
  const { intent, release } = makeRelease();
  const evidence: SafeTaskPreparationEvidence[] = [];
  const mock = makeFetch(intent);
  const adapter = new BefTaskPreparationAdapter(testDependencies(release, mock.fetch, evidence));

  const outcome = await adapter.prepare({ intent, dispatchId: 'dispatch-is-not-sent' });

  assert.equal(outcome.status, 'prepared', JSON.stringify({ outcome, evidence, calls: mock.calls }));
  if (outcome.status !== 'prepared') return;
  assert.equal(outcome.result.generationId, generationId);
  assert.equal(outcome.result.initialStateSha256, intent.initialStateSha256);
  assert.equal(mock.putCount, 1);
  assert.equal(evidence.filter((item) => item.kind === 'fixture').length, 1);
  assert.equal(evidence.filter((item) => item.kind === 'baseline').length, 1);
  const serializedEvidence = JSON.stringify(evidence);
  assert.equal(serializedEvidence.includes(String(mock.putBody?.payerPrivateKey)), false);
  assert.equal(serializedEvidence.includes('R'.repeat(43)), false);
  assert.equal(serializedEvidence.includes('do-not-persist'), false);
  const baseline = evidence.find((item) => item.kind === 'baseline')!;
  assert.equal((baseline.evidence.state as Record<string, unknown>).sameBlock, true);
  assert.equal(JSON.stringify(baseline.evidence.state).includes('extraSecret'), false);
  const baselineReads = (baseline.evidence.state as Record<string, unknown>).reads as Array<Record<string, unknown>>;
  const allowanceRead = baselineReads.find((read) => read.method === 'eth_call' &&
    String((read.params as unknown[])[0] && ((read.params as unknown[])[0] as Record<string, unknown>).data).startsWith('0xdd62ed3e'));
  assert.equal(allowanceRead?.result, `0x${'0'.repeat(64)}`);
  const baselineAllowances = ((baseline.evidence.state as Record<string, unknown>).projection as { allowances: Array<Record<string, unknown>> }).allowances;
  assert.equal(baselineAllowances[0]?.amountUnits, '0');
  assert.equal(adapter.hasUsableStartSession(intent, new Date(Date.now() + 30_000).toISOString()), true,
    'the original RAM session is available through a task deadline within its BEF lease');
  assert.equal(adapter.hasUsableStartSession(intent, new Date(Date.now() + 90_000).toISOString()), false,
    'a generation expiring before the task deadline cannot be charged and started');
  assert.equal(adapter.hasUsableStartSession(intent, 'not-a-date'), false);
  const binding = adapter.sessionBindingAfterStart(intent);
  assert.equal(binding?.generationId, generationId);
  assert.equal(binding?.payerAddress, outcome.result.payerAddress);
  assert.equal(binding?.runToken, 'R'.repeat(43));
  assert.equal((binding?.x402Signer as { payerAddress?: string }).payerAddress?.toLowerCase(), outcome.result.payerAddress);
});

test('a case-pinned payment recipient must match the selected environment before preparation PUT', async () => {
  const { intent, release } = makeRelease('S2');
  const evidence: SafeTaskPreparationEvidence[] = [];
  const diagnostics: BefPreparationDiagnostic[] = [];
  const wrongEnvironment = makeFetch(intent, { facilitatorAddress: `0x${'8'.repeat(40)}` });
  const dependencies = testDependencies(release, wrongEnvironment.fetch, evidence);
  dependencies.preparationDiagnostic = async (value) => {
    diagnostics.push(value);
    throw new Error('diagnostic sink failure must not leak this message');
  };
  const adapter = new BefTaskPreparationAdapter(dependencies);
  const refused = await adapter.prepare({ intent, dispatchId: 'dispatch-wrong-payee-environment' });
  assert.deepEqual(refused,
    { status: 'unknown', reasonCode: 'preparation_identity_mismatch' });
  assert.equal(wrongEnvironment.putCount, 0);
  assert.equal(evidence.length, 0);
  assert.deepEqual(diagnostics, [{
    preparationId,
    environmentId,
    phase: 'facilitator_pin',
    reasonCode: 'pin_mismatch',
  }]);
  assert.deepEqual(Object.keys(diagnostics[0]!).sort(), ['environmentId', 'phase', 'preparationId', 'reasonCode']);
  assert.equal(JSON.stringify(diagnostics[0]).includes('diagnostic sink failure'), false);

  const matchingEnvironment = makeFetch(intent, { facilitatorAddress: donorAddress });
  const matchingAdapter = new BefTaskPreparationAdapter(testDependencies(release, matchingEnvironment.fetch, []));
  const prepared = await matchingAdapter.prepare({ intent, dispatchId: 'dispatch-matching-payee-environment' });
  assert.equal(prepared.status, 'prepared');
  assert.equal(matchingEnvironment.putCount, 1);
});

test('preparation PUT HTTP503 preserves only the fixed producer fixture phase/class and never resends', async () => {
 for (const failingSink of [false, true]) {
  const { intent, release } = makeRelease();
  const diagnostics: BefPreparationDiagnostic[] = [], evidence: SafeTaskPreparationEvidence[] = [];
  const mock = makeFetch(intent, { putFailure: { status: 503, body: {
   error: 'preparation_failed', fixtureState: 'unknown', fixturePhase: 'send_transfer', fixtureCauseClass: 'UnknownRpcError>RpcRequestError',
   runToken: 'RAW_SECRET_SENTINEL', payerPrivateKey: 'RAW_SECRET_SENTINEL', message: 'RAW_SECRET_SENTINEL',
  } } });
  const deps = testDependencies(release, mock.fetch, evidence);
  deps.preparationDiagnostic = (value) => { diagnostics.push(value); if (failingSink) throw new Error('RAW_SECRET_SENTINEL'); };
  const adapter = new BefTaskPreparationAdapter(deps);
  assert.deepEqual(await adapter.prepare({ intent, dispatchId: 'dispatch-put503' }), { status: 'unknown', reasonCode: 'adapter_outcome_unknown' });
  assert.deepEqual(diagnostics, [{ preparationId, environmentId, phase: 'preparation_put', reasonCode: 'http_503',
   fixturePhase: 'send_transfer', fixtureCauseClass: 'UnknownRpcError>RpcRequestError' }]);
  assert.equal(mock.putCount, 1);assert.equal(mock.reconcilePostCount, 0);assert.equal(evidence.length, 0);
  assert.equal(mock.calls.at(-1), `GET bef.test/internal/admin/environments/${environmentId}/preparations/${preparationId}`);
  const retried = await adapter.prepare({ intent, dispatchId: 'dispatch-put503-again' });
  assert.equal(retried.status, 'unknown');assert.equal(mock.putCount, 1);
  assert.equal(JSON.stringify(diagnostics).includes('RAW_SECRET_SENTINEL'), false);
 }
});

test('preparation PUT diagnostics reject malformed, unknown and secret-bearing fixture tags', async () => {
 const valid = { error: 'preparation_failed', fixtureState: 'unknown', fixturePhase: 'read_token_before', fixtureCauseClass: 'UnknownRpcError' };
 const bodies: unknown[] = [null, [], 'RAW_SECRET_SENTINEL', {}, { ...valid, fixturePhase: 'RAW_SECRET_SENTINEL' },
  { ...valid, fixtureCauseClass: 'UnknownRpcError:RAW_SECRET_SENTINEL' }, { ...valid, fixtureCauseClass: 'Error>Error>Error>Error>Error' },
  { ...valid, fixtureCauseClass: { privateKey: 'RAW_SECRET_SENTINEL' } }, { ...valid, fixtureState: 'ready' },
  { ...valid, error: 'other_error' }, { ...valid, fixtureCauseClass: undefined }, { ...valid, fixturePhase: ['send_transfer'] }];
 for (const body of bodies) {
  const { intent, release } = makeRelease();const diagnostics: BefPreparationDiagnostic[] = [];
  const mock = makeFetch(intent, { putFailure: { status: 503, body } });
  const deps = testDependencies(release, mock.fetch, []);deps.preparationDiagnostic = (value) => { diagnostics.push(value); };
  assert.deepEqual(await new BefTaskPreparationAdapter(deps).prepare({ intent, dispatchId: 'dispatch-put-invalid-tags' }),
   { status: 'unknown', reasonCode: 'adapter_outcome_unknown' });
  assert.deepEqual(diagnostics, [{ preparationId, environmentId, phase: 'preparation_put', reasonCode: 'http_503' }]);
  assert.equal(mock.putCount, 1);assert.equal(mock.reconcilePostCount, 0);
  assert.equal(JSON.stringify(diagnostics).includes('RAW_SECRET_SENTINEL'), false);
 }
});

test('preparation PUT request throws and malformed JSON emit bounded diagnostics without changing reconciliation', async () => {
 for (const variant of ['request_throw', 'invalid_json'] as const) {
  const { intent, release } = makeRelease();const diagnostics: BefPreparationDiagnostic[] = [];
  const mock = makeFetch(intent, variant === 'request_throw' ? { losePutReply: true } : { putMalformedBody: 'RAW_SECRET_SENTINEL' });
  const deps = testDependencies(release, mock.fetch, []);
  deps.preparationDiagnostic = (value) => { diagnostics.push(value);throw new Error('RAW_SECRET_SENTINEL'); };
  assert.deepEqual(await new BefTaskPreparationAdapter(deps).prepare({ intent, dispatchId: 'dispatch-put-throw-or-malformed' }),
   { status: 'unknown', reasonCode: 'adapter_outcome_unknown' });
  assert.deepEqual(diagnostics, [{ preparationId, environmentId, phase: 'preparation_put', reasonCode: variant === 'request_throw' ? 'request_failed' : 'http_503' }]);
  assert.equal(mock.putCount, 1);assert.equal(mock.reconcilePostCount, 0);
  assert.ok(mock.calls.at(-1)?.startsWith('GET bef.test/'));
  assert.equal(JSON.stringify(diagnostics).includes('RAW_SECRET_SENTINEL'), false);
 }
});

test('preparation PUT HTTP categories are bounded and accept the producer null or four-class cause shape', async () => {
 for (const [status,reasonCode] of [[502,'http_502'],[504,'http_504'],[409,'http_4xx'],[500,'http_5xx'],[200,'http_status_other']] as const) {
  const { intent, release } = makeRelease();const diagnostics: BefPreparationDiagnostic[] = [];
  const mock = makeFetch(intent, { putFailure: { status, body: { error:'preparation_failed',fixtureState:'unknown',fixturePhase:'unknown',fixtureCauseClass:null } } });
  const deps = testDependencies(release, mock.fetch, []);deps.preparationDiagnostic = (value) => { diagnostics.push(value); };
  assert.deepEqual(await new BefTaskPreparationAdapter(deps).prepare({ intent, dispatchId: 'dispatch-put-status-category' }),
   { status: 'unknown', reasonCode: 'adapter_outcome_unknown' });
  assert.deepEqual(diagnostics, [{ preparationId, environmentId, phase:'preparation_put', reasonCode,fixturePhase:'unknown',fixtureCauseClass:null }]);
  assert.equal(mock.putCount, 1);assert.equal(mock.reconcilePostCount, 0);
 }
 const { intent, release } = makeRelease();const diagnostics: BefPreparationDiagnostic[] = [];
 const cause='BaseError>UnknownRpcError>RpcRequestError>OtherError';
 const mock = makeFetch(intent, { putFailure: { status:503,body:{error:'preparation_failed',fixtureState:'unknown',fixturePhase:'read_token_before',fixtureCauseClass:cause} } });
 const deps=testDependencies(release,mock.fetch,[]);deps.preparationDiagnostic=(value)=>{diagnostics.push(value);};
 await new BefTaskPreparationAdapter(deps).prepare({intent,dispatchId:'dispatch-put-bounded-cause-chain'});
 assert.equal(diagnostics[0]?.fixtureCauseClass,cause);
});

test('a transient pre-PUT source RPC HTTP 502 retries once, then prepares with one PUT and no stale diagnostic', async () => {
  const { intent, release } = makeRelease();
  const evidence: SafeTaskPreparationEvidence[] = [];
  const diagnostics: BefPreparationDiagnostic[] = [];
  const mock = makeFetch(intent, { sourceHealthHttpStatuses: [502] });
  const dependencies = testDependencies(release, mock.fetch, evidence);
  dependencies.preparationDiagnostic = (value) => { diagnostics.push(value); };
  const adapter = new BefTaskPreparationAdapter(dependencies);

  const outcome = await adapter.prepare({ intent, dispatchId: 'dispatch-source-health-transient' });

  assert.equal(outcome.status, 'prepared');
  assert.equal(mock.sourceHealthBatchCount, 2);
  assert.equal(mock.putCount, 1);
  assert.deepEqual(diagnostics, [], 'the recovered first-attempt failure is not persisted as a refusal');
});

test('two pre-PUT source RPC HTTP 502 responses remain unknown, emit only a static class, and perform zero PUTs', async () => {
  const { intent, release } = makeRelease();
  const diagnostics: BefPreparationDiagnostic[] = [];
  const mock = makeFetch(intent, { sourceHealthHttpStatuses: [502, 502] });
  const dependencies = testDependencies(release, mock.fetch, []);
  dependencies.preparationDiagnostic = (value) => { diagnostics.push(value); };
  const adapter = new BefTaskPreparationAdapter(dependencies);

  const outcome = await adapter.prepare({ intent, dispatchId: 'dispatch-source-health-exhausted' });

  assert.deepEqual(outcome, { status: 'unknown', reasonCode: 'preparation_identity_mismatch' });
  assert.equal(mock.sourceHealthBatchCount, 2);
  assert.equal(mock.putCount, 0);
  assert.deepEqual(diagnostics, [{ preparationId, environmentId, phase: 'source_rpc_response', reasonCode: 'http_502' }]);
  assert.equal(JSON.stringify(diagnostics).includes('RAW_SECRET_SENTINEL'), false);
});

test('a non-retryable source RPC HTTP 500 is classified and stops before PUT', async () => {
  const { intent, release } = makeRelease();
  const diagnostics: BefPreparationDiagnostic[] = [];
  const mock = makeFetch(intent, { sourceHealthHttpStatuses: [500, 200] });
  const dependencies = testDependencies(release, mock.fetch, []);
  dependencies.preparationDiagnostic = (value) => { diagnostics.push(value); };
  const adapter = new BefTaskPreparationAdapter(dependencies);

  const outcome = await adapter.prepare({ intent, dispatchId: 'dispatch-source-health-non-retryable' });

  assert.deepEqual(outcome, { status: 'unknown', reasonCode: 'preparation_identity_mismatch' });
  assert.equal(mock.sourceHealthBatchCount, 1, 'only 502/503/504 may retry');
  assert.equal(mock.putCount, 0);
  assert.deepEqual(diagnostics, [{ preparationId, environmentId, phase: 'source_rpc_response', reasonCode: 'http_5xx' }]);
});

test('a valid pre-PUT source RPC response with a wrong pinned block is not retried', async () => {
  const { intent, release } = makeRelease();
  const diagnostics: BefPreparationDiagnostic[] = [];
  const mock = makeFetch(intent, { sourceRpcPinMismatch: true });
  const dependencies = testDependencies(release, mock.fetch, []);
  dependencies.preparationDiagnostic = (value) => { diagnostics.push(value); };
  const adapter = new BefTaskPreparationAdapter(dependencies);

  const outcome = await adapter.prepare({ intent, dispatchId: 'dispatch-source-health-wrong-pin' });

  assert.deepEqual(outcome, { status: 'unknown', reasonCode: 'preparation_identity_mismatch' });
  assert.equal(mock.sourceHealthBatchCount, 1);
  assert.equal(mock.putCount, 0);
  assert.deepEqual(diagnostics, [{ preparationId, environmentId, phase: 'source_rpc_pin', reasonCode: 'pin_mismatch' }]);
});

test('malformed pre-PUT RPC response diagnostics omit the raw body and do not retry HTTP 200', async () => {
  const { intent, release } = makeRelease();
  const diagnostics: BefPreparationDiagnostic[] = [];
  const mock = makeFetch(intent, { sourceHealthMalformedBody: 'RAW_SECRET_SENTINEL { malformed' });
  const dependencies = testDependencies(release, mock.fetch, []);
  dependencies.preparationDiagnostic = (value) => { diagnostics.push(value); };
  const adapter = new BefTaskPreparationAdapter(dependencies);

  const outcome = await adapter.prepare({ intent, dispatchId: 'dispatch-source-health-malformed' });

  assert.deepEqual(outcome, { status: 'unknown', reasonCode: 'preparation_identity_mismatch' });
  assert.equal(mock.sourceHealthBatchCount, 1);
  assert.equal(mock.putCount, 0);
  assert.deepEqual(diagnostics, [{ preparationId, environmentId, phase: 'source_rpc_response', reasonCode: 'invalid_json' }]);
  assert.equal(JSON.stringify(diagnostics).includes('RAW_SECRET_SENTINEL'), false);
});

test('HTTP 200 JSON-RPC, item-shape, batch-shape, and correlation failures use static diagnostics without retrying', async () => {
  const cases = [
    { variant: 'rpc_error' as const, reasonCode: 'rpc_error' as const },
    { variant: 'correlation_invalid' as const, reasonCode: 'correlation_invalid' as const },
    { variant: 'item_shape_invalid' as const, reasonCode: 'item_shape_invalid' as const },
    { variant: 'result_missing' as const, reasonCode: 'result_missing' as const },
    { variant: 'batch_shape_invalid' as const, reasonCode: 'batch_shape_invalid' as const },
  ];
  for (const { variant, reasonCode } of cases) {
    const { intent, release } = makeRelease();
    const diagnostics: BefPreparationDiagnostic[] = [];
    const mock = makeFetch(intent, { sourceHealthResponseVariant: variant });
    const dependencies = testDependencies(release, mock.fetch, []);
    dependencies.preparationDiagnostic = (value) => { diagnostics.push(value); };
    const adapter = new BefTaskPreparationAdapter(dependencies);

    const outcome = await adapter.prepare({ intent, dispatchId: `dispatch-source-rpc-${variant}` });

    assert.deepEqual(outcome, { status: 'unknown', reasonCode: 'preparation_identity_mismatch' }, variant);
    assert.equal(mock.sourceHealthBatchCount, 1, `${variant} must not trigger a retry`);
    assert.equal(mock.putCount, 0, `${variant} must remain before PUT`);
    assert.deepEqual(diagnostics, [{ preparationId, environmentId, phase: 'source_rpc_response', reasonCode }], variant);
    assert.equal(JSON.stringify(diagnostics).includes('RAW_SECRET_SENTINEL'), false, variant);
  }
});

test('a transient pre-PUT local RPC HTTP 503 retries once before the one preparation PUT', async () => {
  const { intent, release } = makeRelease();
  const diagnostics: BefPreparationDiagnostic[] = [];
  const mock = makeFetch(intent, { localHealthHttpStatuses: [503] });
  const dependencies = testDependencies(release, mock.fetch, []);
  dependencies.preparationDiagnostic = (value) => { diagnostics.push(value); };
  const adapter = new BefTaskPreparationAdapter(dependencies);

  const outcome = await adapter.prepare({ intent, dispatchId: 'dispatch-local-health-transient' });

  assert.equal(outcome.status, 'prepared');
  assert.equal(mock.sourceHealthBatchCount, 1);
  assert.equal(mock.localHealthBatchCount, 2);
  assert.equal(mock.putCount, 1);
  assert.deepEqual(diagnostics, []);
});

test('cached preparation reconciliation does not retry a transient RPC failure after the original PUT', async () => {
  const { intent, release } = makeRelease();
  const mock = makeFetch(intent, { sourceHealthHttpStatuses: [null, 502] });
  const adapter = new BefTaskPreparationAdapter(testDependencies(release, mock.fetch, []));

  const first = await adapter.prepare({ intent, dispatchId: 'dispatch-cached-reconcile-first' });
  assert.equal(first.status, 'prepared');
  assert.equal(mock.putCount, 1);
  assert.equal(mock.sourceHealthBatchCount, 1);

  const second = await adapter.prepare({ intent, dispatchId: 'dispatch-cached-reconcile-second' });

  assert.deepEqual(second, { status: 'unknown', reasonCode: 'preparation_identity_mismatch', generationId });
  assert.equal(mock.sourceHealthBatchCount, 2, 'the cached reconcile health batch is one-shot');
  assert.equal(mock.putCount, 1, 'reconciliation must not issue another PUT');
});

test('rejects non-ABI quantity-shaped eth_call results instead of accepting them as words', async () => {
  const { intent, release } = makeRelease();
  const evidence: SafeTaskPreparationEvidence[] = [];
  const mock = makeFetch(intent, { baselineMalformedAbiResult: true });
  const adapter = new BefTaskPreparationAdapter(testDependencies(release, mock.fetch, evidence));

  const outcome = await adapter.prepare({ intent, dispatchId: 'dispatch-malformed-abi-word' });

  assert.deepEqual(outcome, { status: 'unknown', reasonCode: 'adapter_call_failed', generationId });
  assert.equal(mock.putCount, 1);
  assert.equal(evidence.some((item) => item.kind === 'fixture' || item.kind === 'baseline'), false);
});

test('a lost PUT reply stays unknown and never causes an automatic second PUT', async () => {
  const { intent, release } = makeRelease();
  const evidence: SafeTaskPreparationEvidence[] = [];
  const mock = makeFetch(intent, { losePutReply: true });
  const adapter = new BefTaskPreparationAdapter(testDependencies(release, mock.fetch, evidence));

  const first = await adapter.prepare({ intent, dispatchId: 'dispatch-a' });
  const second = await adapter.prepare({ intent, dispatchId: 'dispatch-b' });

  assert.equal(first.status, 'unknown');
  assert.equal(first.status === 'unknown' ? first.generationId : 'unexpected-ready', undefined);
  assert.equal(second.status, 'unknown');
  assert.equal(mock.putCount, 1);
  assert.equal(adapter.sessionBindingAfterStart(intent), null);
});

test('lost in-memory credentials cannot be restored by status reconciliation', async () => {
  const { intent, release } = makeRelease();
  const evidence: SafeTaskPreparationEvidence[] = [];
  const mock = makeFetch(intent);
  const adapter = new BefTaskPreparationAdapter(testDependencies(release, mock.fetch, evidence));

  const prepared = await adapter.prepare({ intent, dispatchId: 'dispatch-a' });
  assert.equal(prepared.status, 'prepared', JSON.stringify(prepared));
  adapter.clearCredentials(preparationId);
  assert.equal(adapter.hasUsableStartSession(intent, new Date(Date.now() + 30_000).toISOString()), false,
    'a public ready row cannot substitute for the lost RAM token and signer');
  const reconciled = await adapter.reconcile({ intent, generationId });

  assert.deepEqual(reconciled, { status: 'unknown', reasonCode: 'restart_reconciliation_required', generationId });
  assert.equal(mock.putCount, 1);
  assert.equal(mock.reconcilePostCount, 0);
  assert.equal(adapter.sessionBindingAfterStart(intent), null);
});

test('an observed same-block baseline mismatch remains unknown with the original generation', async () => {
  const { intent, release } = makeRelease();
  const evidence: SafeTaskPreparationEvidence[] = [];
  const mock = makeFetch(intent, { baselineMismatch: true });
  const adapter = new BefTaskPreparationAdapter(testDependencies(release, mock.fetch, evidence));

  const outcome = await adapter.prepare({ intent, dispatchId: 'dispatch-baseline-mismatch' });

  assert.deepEqual(outcome, { status: 'unknown', reasonCode: 'baseline_state_mismatch', generationId });
  assert.equal(adapter.sessionBindingAfterStart(intent), null);
  const baseline = evidence.find((item) => item.kind === 'baseline')!;
  assert.notEqual(baseline.evidence.stateSha256, intent.initialStateSha256);
});

test('positive S4 setup is pinned, one-shot, independently observed, and outside the sealed task baseline', async () => {
  const { intent, release } = makeS4Release();
  const evidence: SafeTaskPreparationEvidence[] = [];
  const mock = makeS4Fetch(intent);
  const adapter = new BefTaskPreparationAdapter(testDependencies(release, mock.fetch, evidence));

  const result = await adapter.prepare({ intent, dispatchId: 'dispatch-s4-fixture' });

  assert.equal(result.status, 'prepared', JSON.stringify({ result, calls: mock.calls,
    fixture: evidence.find((item) => item.kind === 'fixture')?.evidence.s4AllowanceFixture }));
  assert.equal(mock.putCount, 1);
  assert.equal(mock.approvePostCount, 1);
  assert.deepEqual(mock.approveBody, { tokenAssetId: 'USDC', amountUnits: s4AllowanceUnits, gasLimit: '100000' });
  assert.equal(mock.approveHeaders?.get('authorization'), `Bearer ${'R'.repeat(43)}`);
  assert.equal(mock.approveHeaders?.get('x-bef-generation'), generationId);
  assert.match(mock.approveHeaders?.get('idempotency-key') ?? '', /^owner-s4-[a-f0-9]{64}$/);
  if (result.status !== 'prepared') return;
  assert.equal(result.result.initialStateSha256, intent.initialStateSha256);
  const fixtureEvidence = evidence.find((item) => item.kind === 'fixture')!;
  const fixture = fixtureEvidence.evidence.s4AllowanceFixture as Record<string, unknown>;
  assert.equal(fixture.stage, 'pre_task_fixture_setup');
  assert.equal(fixture.outcome, 'observed');
  assert.equal(fixture.operationId, '88888888-8888-4888-8888-888888888888');
  assert.equal(fixture.transactionHash, s4SetupTransactionHash);
  assert.equal(fixture.gasCostWei, s4GasCost.toString());
  const action = fixture.action as Record<string, unknown>;
  assert.deepEqual(action, { kind: 'approve', tokenAssetId: 'USDC', spender: routerAddress,
    amountUnits: s4AllowanceUnits, gasLimit: '100000' });
  const pre = fixture.preState as Record<string, unknown>;
  const post = fixture.postState as Record<string, unknown>;
  assert.equal(pre.blockHash, forkBlockHash);
  assert.equal(post.blockHash, s4SetupBlockHash);
  assert.equal(post.baselineSha256, intent.initialStateSha256);
  assert.equal(((post.projection as { allowances: Array<Record<string, unknown>> }).allowances[0]!).amountUnits, s4AllowanceUnits);
  const safeEvidence = JSON.stringify(evidence);
  assert.equal(safeEvidence.includes('R'.repeat(43)), false);
  assert.equal(safeEvidence.includes(String(mock.putBody?.payerPrivateKey)), false);
  assert.equal(safeEvidence.includes('authorization'), false);
  assert.equal(safeEvidence.includes('do-not-persist'), false);
});

test('S4 mismatched positive amount, spender, or immutable intent pins make zero external requests', async () => {
  for (const mode of ['amount', 'spender', 'intent'] as const) {
    const { intent: originalIntent, release: originalRelease } = makeS4Release();
    const release = structuredClone(originalRelease) as ValidatedTaskReleaseRecord;
    const taskCase = release.manifest.cases.training[0]! as unknown as TaskCase;
    const objective = taskCase.objective as Record<string, unknown>;
    const intent = { ...originalIntent };
    if (mode === 'amount') objective.initialAllowanceUnits = '10001';
    if (mode === 'spender') objective.spender = donorAddress;
    if (mode === 'intent') intent.caseHash = 'f'.repeat(64);
    const mock = makeS4Fetch(intent);
    const evidence: SafeTaskPreparationEvidence[] = [];
    const adapter = new BefTaskPreparationAdapter(testDependencies(release, mock.fetch, evidence));

    const result = await adapter.prepare({ intent, dispatchId: `dispatch-s4-invalid-${mode}` });

    assert.equal(result.status, 'unknown', mode);
    assert.equal(mock.calls.length, 0, mode);
    assert.equal(mock.putCount, 0, mode);
    assert.equal(mock.approvePostCount, 0, mode);
    assert.equal(evidence.length, 0, mode);
  }
});

test('S4 pre-state mismatch blocks the approve route before its one-shot action', async () => {
  const { intent, release } = makeS4Release();
  const evidence: SafeTaskPreparationEvidence[] = [];
  const mock = makeS4Fetch(intent, { baselineMismatch: true });
  const adapter = new BefTaskPreparationAdapter(testDependencies(release, mock.fetch, evidence));

  const result = await adapter.prepare({ intent, dispatchId: 'dispatch-s4-prestate-mismatch' });

  assert.deepEqual(result, { status: 'unknown', reasonCode: 'adapter_outcome_unknown', generationId });
  assert.equal(mock.putCount, 1);
  assert.equal(mock.approvePostCount, 0);
  assert.equal((evidence.find((item) => item.kind === 'fixture')?.evidence.s4AllowanceFixture as Record<string, unknown>).reasonCode,
    'baseline_state_mismatch');
});

test('S4 lost approve response stays unknown, never resubmits, and can be fenced', async () => {
  const { intent, release } = makeS4Release();
  const evidence: SafeTaskPreparationEvidence[] = [];
  const mock = makeS4Fetch(intent, { loseApproveReply: true });
  const adapter = new BefTaskPreparationAdapter(testDependencies(release, mock.fetch, evidence));

  const first = await adapter.prepare({ intent, dispatchId: 'dispatch-s4-lost-response-a' });
  const second = await adapter.prepare({ intent, dispatchId: 'dispatch-s4-lost-response-b' });

  assert.deepEqual(first, { status: 'unknown', reasonCode: 'adapter_outcome_unknown', generationId });
  assert.deepEqual(second, { status: 'unknown', reasonCode: 'adapter_outcome_unknown', generationId });
  assert.equal(mock.putCount, 1);
  assert.equal(mock.approvePostCount, 1);
  const fixture = evidence.find((item) => item.kind === 'fixture')?.evidence.s4AllowanceFixture as Record<string, unknown>;
  assert.equal(fixture.outcome, 'unknown');
  assert.equal(fixture.operationId, null);
  assert.equal(fixture.transactionHash, null);
  assert.equal(typeof fixture.idempotencyKeySha256, 'string');
  assert.equal((await adapter.fence({ intent, generationId })).confirmed, true);
  assert.equal(adapter.sessionBindingAfterStart(intent), null);
});

test('S4 inconsistent Approval evidence is unknown and never becomes a ready task', async () => {
  const { intent, release } = makeS4Release();
  const evidence: SafeTaskPreparationEvidence[] = [];
  const mock = makeS4Fetch(intent, { badApprovalLog: true });
  const adapter = new BefTaskPreparationAdapter(testDependencies(release, mock.fetch, evidence));

  const result = await adapter.prepare({ intent, dispatchId: 'dispatch-s4-bad-approval-log' });

  assert.deepEqual(result, { status: 'unknown', reasonCode: 'adapter_outcome_unknown', generationId });
  assert.equal(mock.approvePostCount, 1);
  assert.equal((evidence.find((item) => item.kind === 'fixture')?.evidence.s4AllowanceFixture as Record<string, unknown>).outcome,
    'unknown');
});

test('S4 public approve selection must echo the pinned spender before readiness', async () => {
  const { intent, release } = makeS4Release();
  const evidence: SafeTaskPreparationEvidence[] = [];
  const mock = makeS4Fetch(intent, { wrongSelectedSpender: true });
  const adapter = new BefTaskPreparationAdapter(testDependencies(release, mock.fetch, evidence));

  const result = await adapter.prepare({ intent, dispatchId: 'dispatch-s4-wrong-selected-spender' });

  assert.deepEqual(result, { status: 'unknown', reasonCode: 'adapter_outcome_unknown', generationId });
  assert.equal(mock.approvePostCount, 1);
  const firstFixture = evidence.find((item) => item.kind === 'fixture')?.evidence.s4AllowanceFixture as Record<string, unknown>;
  assert.equal(firstFixture.outcome, 'unknown');
  assert.equal(firstFixture.operationId, '88888888-8888-4888-8888-888888888888');
  assert.equal(firstFixture.transactionHash, s4SetupTransactionHash);
  assert.match(String(firstFixture.responseSha256), /^[a-f0-9]{64}$/);
  assert.match(String(firstFixture.idempotencyKeySha256), /^[a-f0-9]{64}$/);

  const repeated = await adapter.prepare({ intent, dispatchId: 'dispatch-s4-repeat-unknown' });

  assert.deepEqual(repeated, { status: 'unknown', reasonCode: 'adapter_outcome_unknown', generationId });
  assert.equal(mock.approvePostCount, 1);
  const repeatedFixtures = evidence.filter((item) => item.kind === 'fixture');
  assert.ok(repeatedFixtures.length >= 2);
  const retainedFixture = repeatedFixtures.at(-1)!.evidence.s4AllowanceFixture as Record<string, unknown>;
  for (const key of ['operationId', 'transactionHash', 'responseSha256', 'idempotencyKeySha256'] as const) {
    assert.equal(retainedFixture[key], firstFixture[key], `${key} is retained across an unknown reconciliation`);
  }
});

test('S4 lost RAM credentials cannot be restored or used to post a second fixture operation', async () => {
  const { intent, release } = makeS4Release();
  const evidence: SafeTaskPreparationEvidence[] = [];
  const mock = makeS4Fetch(intent);
  const adapter = new BefTaskPreparationAdapter(testDependencies(release, mock.fetch, evidence));

  const prepared = await adapter.prepare({ intent, dispatchId: 'dispatch-s4-ready' });
  assert.equal(prepared.status, 'prepared');
  adapter.clearCredentials(preparationId);
  const reconciled = await adapter.reconcile({ intent, generationId });

  assert.deepEqual(reconciled, { status: 'unknown', reasonCode: 'restart_reconciliation_required', generationId });
  assert.equal(mock.putCount, 1);
  assert.equal(mock.approvePostCount, 1);
  assert.equal(adapter.sessionBindingAfterStart(intent), null);
});

test('fencing by preparation ID preserves unknown owner generation despite BEF public generation', async () => {
  const { intent, release } = makeRelease();
  const evidence: SafeTaskPreparationEvidence[] = [];
  const mock = makeFetch(intent);
  const adapter = new BefTaskPreparationAdapter(testDependencies(release, mock.fetch, evidence));

  const fence = await adapter.fence({ intent, generationId: null });

  assert.equal(fence.confirmed, true);
  assert.equal(fence.generationId, null);
  assert.equal(fence.preparationId, preparationId);
  const recorded = evidence.find((item) => item.kind === 'fence')!;
  assert.equal(recorded.evidence.actualBefGenerationId, generationId);
  assert.equal(recorded.evidence.expectedOwnerGenerationId, null);
});

test('fence refuses to confirm a generation that differs from the owner pinned generation', async () => {
  const { intent, release } = makeRelease();
  const evidence: SafeTaskPreparationEvidence[] = [];
  const mock = makeFetch(intent);
  const adapter = new BefTaskPreparationAdapter(testDependencies(release, mock.fetch, evidence));

  await assert.rejects(adapter.fence({ intent, generationId: '66666666-6666-4666-8666-666666666666' }));
  assert.equal(evidence.some((item) => item.kind === 'fence'), false);
});

test('public pins remain stable for the identical immutable owner intent', () => {
  const { intent } = makeRelease();
  assert.equal(taskPreparationPublicPinsSha256(intent), taskPreparationPublicPinsSha256({ ...intent }));
  assert.equal(taskPreparationPublicPinsSha256(intent), taskPreparationPublicPinsSha256({
    ...intent,
    participantId: 'random-participant',
    payerAddress: '0x3333333333333333333333333333333333333333',
  } as TaskPreparationIntentPins));
  assert.notEqual(taskPreparationPublicPinsSha256(intent), taskPreparationPublicPinsSha256({ ...intent, createdAt: '2026-10-27T10:00:01.000Z' }));
});
