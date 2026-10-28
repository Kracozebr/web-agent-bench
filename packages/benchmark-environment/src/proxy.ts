import { timingSafeEqual } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import Fastify, { type FastifyInstance } from 'fastify';
import { loadManifest } from './manifest.js';
import { readProxyConfig, readSecret } from './config.js';

type RpcRequest = { jsonrpc: '2.0'; id: string | number | null; method: string; params: unknown[] };
type RpcResult = { jsonrpc: '2.0'; id: string | number | null; result?: unknown; error?: { code: number; message: string; data?: unknown } };

const LOCAL_READ_METHODS = new Set([
  'eth_chainId', 'eth_blockNumber', 'eth_getBlockByNumber', 'eth_getBlockByHash',
  'eth_getCode', 'eth_getStorageAt', 'eth_call', 'eth_getBalance',
  'eth_getTransactionCount', 'eth_getTransactionReceipt', 'eth_getTransactionByHash',
  'eth_getLogs', 'eth_estimateGas', 'eth_gasPrice', 'eth_maxPriorityFeePerGas',
]);
const DENIED_PREFIXES = ['anvil_', 'hardhat_', 'debug_', 'personal_', 'admin_', 'miner_', 'evm_', 'wallet_'];
const DENIED_METHODS = new Set([
  'eth_sendRawTransaction', 'eth_sendTransaction', 'eth_sign', 'eth_signTransaction',
  'eth_signTypedData', 'eth_signTypedData_v3', 'eth_signTypedData_v4',
  'eth_submitWork', 'eth_submitHashrate', 'net_peerCount', 'net_addPeer', 'net_removePeer',
]);
const SOURCE_ARITY: Readonly<Record<string, number>> = {
  eth_chainId: 0, eth_getBlockByNumber: 2, eth_getBlockByHash: 2,
  eth_getCode: 2, eth_getStorageAt: 3, eth_call: 2, eth_getBalance: 2, eth_getTransactionCount: 2,
};
const LOCAL_ARITY: Readonly<Record<string, number>> = {
  eth_chainId: 0, eth_blockNumber: 0, eth_getBlockByNumber: 2, eth_getBlockByHash: 2,
  eth_getCode: 2, eth_getStorageAt: 3, eth_call: 2, eth_getBalance: 2,
  eth_getTransactionCount: 2, eth_getTransactionReceipt: 1, eth_getTransactionByHash: 1,
  eth_getLogs: 1, eth_estimateGas: 2, eth_gasPrice: 0, eth_maxPriorityFeePerGas: 0,
};

const rpcError = (id: RpcRequest['id'], code: number, message: string): RpcResult => ({ jsonrpc: '2.0', id, error: { code, message } });
const isRecord = (value: unknown): value is Record<string, unknown> => Boolean(value && typeof value === 'object' && !Array.isArray(value));
const isAddress = (value: unknown): value is string => typeof value === 'string' && /^0x[0-9a-f]{40}$/i.test(value);
const isBlockTag = (value: unknown): value is string => typeof value === 'string' && (/^0x[0-9a-f]+$/i.test(value) || ['latest', 'earliest', 'pending', 'safe', 'finalized'].includes(value));
const idKey = (id: RpcRequest['id']): string => typeof id + ':' + String(id);

function timingSafeMatch(candidate: unknown, expected: string): boolean {
  if (typeof candidate !== 'string') return false;
  const left = Buffer.from(candidate);
  const right = Buffer.from(expected);
  return left.length === right.length && timingSafeEqual(left, right);
}

function normalizeSourceParams(method: string, params: unknown[], pinnedBlock: string, blockHash: string, contractSet: Set<string>): unknown[] | null {
  const result = [...params];
  const pinTag = (index: number): boolean => isPinnedSourceBlock(result[index], pinnedBlock, blockHash);
  switch (method) {
    case 'eth_chainId': return params.length === 0 ? [] : null;
    case 'eth_getBlockByNumber':
      return params.length === 2 && isBlockTag(params[0]) && typeof params[1] === 'boolean' && pinTag(0) ? result : null;
    case 'eth_getBlockByHash':
      return params.length === 2 && params[0] === blockHash && typeof params[1] === 'boolean' ? result : null;
    case 'eth_getCode':
    case 'eth_getBalance':
    case 'eth_getTransactionCount':
      // AICODE-NOTE: Anvil hydrates arbitrary participant/signer EOAs from the pinned fork. These are
      // read-only account observations; keep them fixed to the declared source block and
      // bounded by the source-call budget instead of inventing local zero-state answers.
      return params.length === 2 && isAddress(params[0]) && pinTag(1) ? result : null;
    case 'eth_getStorageAt':
      // AICODE-NOTE: The pinned Base fork reads OP L1Block predeploy storage while
      // executing otherwise ordinary eth_call requests. Keep this a storage-only,
      // exact-block read with strict arity and slot syntax; do not synthesize state
      // or permit a caller-selected block/state override.
      return params.length === 3 && isAddress(params[0]) &&
        typeof params[1] === 'string' && /^0x[0-9a-f]{1,64}$/i.test(params[1]) &&
        pinTag(2) ? result : null;
    case 'eth_call': {
      if (params.length !== 2 || !isRecord(params[0]) || !pinTag(1)) return null;
      const allowed = new Set(['to', 'from', 'data', 'value', 'gas', 'gasPrice', 'maxFeePerGas', 'maxPriorityFeePerGas', 'type', 'accessList']);
      if (Object.keys(params[0]).some((key) => !allowed.has(key))) return null;
      if (!isAddress(params[0].to) || !contractSet.has(params[0].to.toLowerCase())) return null;
      if (params[0].from !== undefined && !isAddress(params[0].from)) return null;
      if (params[0].data !== undefined && (typeof params[0].data !== 'string' || !/^0x(?:[0-9a-f]{2})*$/i.test(params[0].data))) return null;
      return result;
    }
    default: return null;
  }
}

function isPinnedSourceBlock(value: unknown, pinnedBlock: string, blockHash: string): boolean {
  if (value === pinnedBlock) return true;
  if (!isRecord(value) || typeof value.blockHash !== 'string' || value.blockHash.toLowerCase() !== blockHash.toLowerCase()) return false;
  if (Object.keys(value).some((key) => key !== 'blockHash' && key !== 'requireCanonical')) return false;
  return value.requireCanonical === undefined || typeof value.requireCanonical === 'boolean';
}

function safeValueShape(value: unknown, pinnedBlock: string, blockHash: string, depth = 0): unknown {
  if (value === null) return { type: 'null' };
  if (typeof value === 'boolean') return { type: 'boolean' };
  if (typeof value === 'number') return { type: 'number' };
  if (typeof value === 'string') {
    if (/^0x[0-9a-f]{40}$/i.test(value)) return { type: 'address' };
    if (/^0x[0-9a-f]{64}$/i.test(value)) return { type: 'hash32', pinnedBlockHash: value.toLowerCase() === blockHash.toLowerCase() };
    if (value === pinnedBlock) return { type: 'block-number', pinned: true };
    if (/^0x[0-9a-f]*$/i.test(value)) return { type: 'hex-data', byteLength: Math.max(0, (value.length - 2) / 2) };
    if (['latest', 'earliest', 'pending', 'safe', 'finalized'].includes(value)) return { type: 'block-tag', value };
    return { type: 'string', length: value.length };
  }
  if (Array.isArray(value)) {
    return { type: 'array', length: value.length, items: depth < 2 ? value.slice(0, 4).map((item) => safeValueShape(item, pinnedBlock, blockHash, depth + 1)) : undefined };
  }
  if (isRecord(value)) {
    const keys = Object.keys(value).sort();
    const shape: Record<string, unknown> = { type: 'object', keyCount: keys.length, keys: keys.slice(0, 16).map((key) => key.slice(0, 64)) };
    if (Object.hasOwn(value, 'blockHash')) {
      shape.blockHashPinned = typeof value.blockHash === 'string' && value.blockHash.toLowerCase() === blockHash.toLowerCase();
      shape.requireCanonicalType = Object.hasOwn(value, 'requireCanonical') ? typeof value.requireCanonical : 'absent';
    }
    return shape;
  }
  return { type: typeof value };
}

function safeParamsShape(method: string, params: unknown[], pinnedBlock: string, blockHash: string, contractSet: Set<string>): unknown {
  const items = params.slice(0, 12).map((value) => safeValueShape(value, pinnedBlock, blockHash));
  if (method === 'eth_getStorageAt' && isAddress(params[0])) {
    const address = params[0].toLowerCase();
    const isPinnedContract = contractSet.has(address);
    const isBasePredeployRange = address.startsWith('0x420000000000000000000000000000000000');
    items[0] = {
      type: 'address',
      addressClass: isPinnedContract ? 'pinned_contract' : isBasePredeployRange ? 'base_predeploy_range' : 'other',
      ...((isPinnedContract || isBasePredeployRange) ? { publicAddress: address } : {}),
    };
  }
  return { count: params.length, items };
}

function normalizeLocalParams(method: string, params: unknown[], contractSet: Set<string>): unknown[] | null {
  const arity = LOCAL_ARITY[method];
  if (arity === undefined || params.length !== arity) return null;
  if (method === 'eth_getBlockByNumber' || method === 'eth_getBlockByHash') {
    return isBlockTag(params[0]) && typeof params[1] === 'boolean' ? [...params] : null;
  }
  if (['eth_getCode', 'eth_getBalance', 'eth_getTransactionCount'].includes(method)) {
    return isAddress(params[0]) && isBlockTag(params[1]) ? [...params] : null;
  }
  if (method === 'eth_getStorageAt') {
    return isAddress(params[0]) && typeof params[1] === 'string' && /^0x[0-9a-f]{1,64}$/i.test(params[1]) && isBlockTag(params[2]) ? [...params] : null;
  }
  if (method === 'eth_call' || method === 'eth_estimateGas') {
    if (!isRecord(params[0]) || !isBlockTag(params[1])) return null;
    const allowed = new Set(['to', 'from', 'data', 'value', 'gas', 'gasPrice', 'maxFeePerGas', 'maxPriorityFeePerGas', 'type', 'accessList']);
    if (Object.keys(params[0]).some((key) => !allowed.has(key))) return null;
    if (params[0].to !== undefined && (!isAddress(params[0].to) || !contractSet.has(params[0].to.toLowerCase()))) return null;
    if (params[0].from !== undefined && !isAddress(params[0].from)) return null;
    if (params[0].data !== undefined && (typeof params[0].data !== 'string' || !/^0x(?:[0-9a-f]{2})*$/i.test(params[0].data))) return null;
    return [...params];
  }
  if (method === 'eth_getTransactionReceipt' || method === 'eth_getTransactionByHash') {
    return typeof params[0] === 'string' && /^0x[0-9a-f]{64}$/i.test(params[0]) ? [...params] : null;
  }
  if (method === 'eth_getLogs') {
    const filter = params[0];
    if (!isRecord(filter) || filter.address === undefined) return null;
    const addresses = Array.isArray(filter.address) ? filter.address : [filter.address];
    if (!addresses.length || addresses.some((item) => !isAddress(item) || !contractSet.has(item.toLowerCase()))) return null;
    const from = filter.fromBlock;
    const to = filter.toBlock;
    if (typeof from !== 'string' || typeof to !== 'string' || !/^0x[0-9a-f]+$/i.test(from) || !/^0x[0-9a-f]+$/i.test(to)) return null;
    const span = BigInt(to) - BigInt(from);
    if (span < 0n || span > 2_000n) return null;
    const allowed = new Set(['fromBlock', 'toBlock', 'address', 'topics', 'blockHash']);
    if (Object.keys(filter).some((key) => !allowed.has(key))) return null;
    return [...params];
  }
  if (method === 'eth_gasPrice' || method === 'eth_maxPriorityFeePerGas' || method === 'eth_chainId' || method === 'eth_blockNumber') return [...params];
  return null;
}

function normalizeRequest(value: unknown): RpcRequest | null {
  if (!isRecord(value) || value.jsonrpc !== '2.0' || typeof value.method !== 'string' || !/^[a-zA-Z][a-zA-Z0-9_]*$/.test(value.method)) return null;
  if (!(typeof value.id === 'string' || typeof value.id === 'number' || value.id === null)) return null;
  if (value.params !== undefined && !Array.isArray(value.params)) return null;
  return { jsonrpc: '2.0', id: value.id, method: value.method, params: (value.params ?? []) as unknown[] };
}

function isDeniedMethod(method: string): boolean {
  return DENIED_METHODS.has(method) || DENIED_PREFIXES.some((prefix) => method.startsWith(prefix)) || method.startsWith('eth_send');
}

export async function createRpcProxy(): Promise<FastifyInstance> {
  const { manifest } = await loadManifest();
  const config = readProxyConfig(manifest);
  const isSource = config.mode === 'source';
  const allowedMethods = isSource ? new Set<string>(manifest.source.allowedMethods) : LOCAL_READ_METHODS;
  const contractSet = new Set([
    ...Object.values(manifest.contracts).flatMap((contract) => contract && typeof contract === 'object' && 'address' in contract && typeof contract.address === 'string' ? [contract.address.toLowerCase()] : []),
    manifest.contracts.usdc.implementation.toLowerCase(),
  ]);
  let forwardedItems = 0;
  let deniedItems = 0;
  let upstreamErrors = 0;
  let reservedSourceCalls = 0;
  const deniedByMethod = new Map<string, number>();
  const forwardedByMethod = new Map<string, number>();
  const count = (target: Map<string, number>, method: string) => target.set(method, (target.get(method) ?? 0) + 1);
  const deniedParameterShapes = new Map<string, { method: string; count: number; paramsShape: unknown }>();
  const recordDeniedShape = (method: string, params: unknown[]) => {
    if (!isSource) return;
    const paramsShape = safeParamsShape(method, params, manifest.source.blockNumber, manifest.source.blockHash, contractSet);
    const key = `${method}:${JSON.stringify(paramsShape)}`;
    const current = deniedParameterShapes.get(key);
    if (current) current.count += 1;
    else if (deniedParameterShapes.size < 32) deniedParameterShapes.set(key, { method, count: 1, paramsShape });
  };
  const maxBody = isSource ? manifest.source.maxRequestBytes : manifest.guardrails.maxHttpRequestBytes;
  const maxResponse = isSource ? manifest.source.maxResponseBytes : 4_194_304;
  const app = Fastify({ logger: false, bodyLimit: maxBody, disableRequestLogging: true });

  app.get('/healthz', async () => ({
    status: 'ok',
    boundary: isSource ? 'source-readonly-proxy' : 'local-chain-readonly-proxy',
    envId: config.envId ?? null,
    manifestSha256: (await loadManifest()).sha256,
  }));
  app.get('/internal/admin/metrics', async (request, reply) => {
    if (!timingSafeMatch(request.headers['x-bef-service-key'], readSecret('BEF_SERVICE_KEY'))) return reply.code(403).send({ error: 'forbidden' });
    return {
      mode: config.mode, forwardedItems, deniedItems, upstreamErrors,
      sourceCallsReserved: isSource ? reservedSourceCalls : null,
      sourceCallLimit: isSource ? manifest.guardrails.maxSourceCallsPerTrial : null,
      deniedByMethod: Object.fromEntries(deniedByMethod),
      forwardedByMethod: Object.fromEntries(forwardedByMethod),
      deniedParameterShapes: [...deniedParameterShapes.values()],
    };
  });
  app.post('/', async (request, reply) => {
    const raw = request.body as unknown;
    const isBatch = Array.isArray(raw);
    const batch = isBatch ? raw as unknown[] : [raw];
    const maxBatch = isSource ? manifest.source.maxBatchItems : manifest.guardrails.maxRpcBatchItems;
    if (!batch.length || batch.length > maxBatch) return reply.code(413).send(rpcError(null, -32005, 'RPC batch limit exceeded'));
    const parsed = batch.map(normalizeRequest);
    if (parsed.some((item) => item === null)) return reply.code(400).send(rpcError(null, -32600, 'Invalid JSON-RPC request'));
    const incoming = parsed as RpcRequest[];
    if (isBatch && new Set(incoming.map((item) => idKey(item.id))).size !== incoming.length) {
      return reply.code(400).send(rpcError(null, -32600, 'Batch request ids must be unique'));
    }
    const resultsByKey = new Map<string, RpcResult>();
    const forward: Array<{ request: RpcRequest; params: unknown[] }> = [];
    const maxCalls = isSource ? manifest.guardrails.maxSourceCallsPerTrial : Number.MAX_SAFE_INTEGER;

    for (const item of incoming) {
      const key = idKey(item.id);
      const params = item.params;
      if (isDeniedMethod(item.method) || !allowedMethods.has(item.method)) {
        deniedItems += 1;
        count(deniedByMethod, item.method);
        recordDeniedShape(item.method, params);
        resultsByKey.set(key, rpcError(item.id, -32601, 'Method is not permitted by the read-only boundary'));
        continue;
      }
      const safeParams = isSource
        ? normalizeSourceParams(item.method, params, manifest.source.blockNumber, manifest.source.blockHash, contractSet)
        : normalizeLocalParams(item.method, params, contractSet);
      if (!safeParams || params.length > 12) {
        deniedItems += 1;
        count(deniedByMethod, item.method);
        recordDeniedShape(item.method, params);
        resultsByKey.set(key, rpcError(item.id, -32602, 'RPC method parameters exceed the declared read-only boundary'));
        continue;
      }
      if (isSource && reservedSourceCalls >= maxCalls) {
        deniedItems += 1;
        count(deniedByMethod, item.method);
        recordDeniedShape(item.method, params);
        resultsByKey.set(key, rpcError(item.id, -32005, 'Pinned source read-call budget exhausted'));
        continue;
      }
      forward.push({ request: item, params: safeParams });
      if (isSource) reservedSourceCalls += 1;
    }

    if (forward.length) {
      const body = isBatch
        ? forward.map(({ request: item, params }) => ({ jsonrpc: '2.0', id: item.id, method: item.method, params }))
        : { jsonrpc: '2.0', id: forward[0]!.request.id, method: forward[0]!.request.method, params: forward[0]!.params };
      const serialized = JSON.stringify(body);
      if (Buffer.byteLength(serialized) > maxBody) return reply.code(413).send(rpcError(null, -32005, 'RPC request byte limit exceeded'));
      forwardedItems += forward.length;
      for (const { request: item } of forward) count(forwardedByMethod, item.method);
      let response: Response;
      let responseText: string;
      try {
        response = await fetch(config.targetUrl, { method: 'POST', headers: { 'content-type': 'application/json' }, body: serialized, signal: AbortSignal.timeout(15_000) });
        const lengthHeader = response.headers.get('content-length');
        if (lengthHeader && Number(lengthHeader) > maxResponse) throw new Error('upstream_response_too_large');
        const reader = response.body?.getReader();
        if (!reader) throw new Error('upstream_response_unreadable');
        const chunks: Uint8Array[] = [];
        let total = 0;
        while (true) {
          const next = await reader.read();
          if (next.done) break;
          total += next.value.byteLength;
          if (total > maxResponse) {
            await reader.cancel().catch(() => undefined);
            throw new Error('upstream_response_too_large');
          }
          chunks.push(next.value);
        }
        responseText = Buffer.concat(chunks, total).toString('utf8');
      } catch {
        upstreamErrors += 1;
        return reply.code(502).send(rpcError(null, -32000, 'Upstream read failed'));
      }
      if (!response.ok) {
        upstreamErrors += 1;
        return reply.code(502).send(rpcError(null, -32000, 'Upstream read failed'));
      }
      let decoded: unknown;
      try { decoded = JSON.parse(responseText); } catch {
        upstreamErrors += 1;
        return reply.code(502).send(rpcError(null, -32000, 'Upstream response was not valid JSON-RPC'));
      }
      const upstream = Array.isArray(decoded) ? decoded : [decoded];
      const forwardMap = new Map(forward.map(({ request: item }) => [idKey(item.id), item]));
      const mapped = new Map<string, RpcResult>();
      for (const item of upstream) {
        if (!isRecord(item) || !(typeof item.id === 'string' || typeof item.id === 'number' || item.id === null)) {
          upstreamErrors += 1;
          return reply.code(502).send(rpcError(null, -32000, 'Upstream response correlation failed'));
        }
        const key = idKey(item.id);
        if (!forwardMap.has(key) || mapped.has(key)) {
          upstreamErrors += 1;
          return reply.code(502).send(rpcError(null, -32000, 'Upstream response correlation failed'));
        }
        mapped.set(key, item as RpcResult);
      }
      for (const { request: item } of forward) {
        const key = idKey(item.id);
        resultsByKey.set(key, mapped.get(key) ?? rpcError(item.id, -32000, 'Upstream response omitted request id'));
      }
    }
    const ordered = incoming.map((item) => resultsByKey.get(idKey(item.id)) ?? rpcError(item.id, -32000, 'RPC observation unavailable'));
    if (!isBatch) return reply.send(ordered[0]);
    return reply.send(ordered);
  });

  await app.listen({ port: config.port, host: config.bindAddress });
  return app;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  void createRpcProxy().catch(() => { process.exitCode = 1; });
}

