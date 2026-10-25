import { encodeFunctionData, keccak256, toBytes } from 'viem';
import type { RuntimeManifest } from '../manifest.js';
import type { EvidenceWriter } from './evidence.js';
import { sanitizeValue, sha256Bytes } from './evidence.js';
import { probeFetch } from './fetch-types.js';

const ERC20_BALANCE_OF_ABI = [{
  type: 'function',
  name: 'balanceOf',
  stateMutability: 'view',
  inputs: [{ name: 'account', type: 'address' }],
  outputs: [{ name: '', type: 'uint256' }],
}] as const;

export type RpcBoundary = 'source-readonly-proxy' | 'local-chain-readonly-proxy';

export class RpcReadOnlyBoundaryMethodDeniedError extends Error {
  readonly rpcCode = -32601;

  constructor(readonly endpointBoundary: RpcBoundary, readonly method: string) {
    super('probe_rpc_readonly_method_denied');
    this.name = 'RpcReadOnlyBoundaryMethodDeniedError';
  }
}

export type RpcResult<T = unknown> = {
  result: T;
  requestedBlock: string | null;
};

export type RpcReceipt = {
  transactionHash: string;
  status: string;
  blockNumber: string;
  blockHash: string;
  from: string;
  to: string | null;
  logs: Array<{ address: string; topics: string[]; data: string; logIndex?: string }>;
};

const PUBLIC_TRANSACTION_FIELDS = [
  'hash', 'from', 'to', 'value', 'nonce', 'type', 'chainId', 'gas',
  'maxFeePerGas', 'maxPriorityFeePerGas', 'blockHash', 'blockNumber', 'transactionIndex',
] as const;
const PUBLIC_BLOCK_FIELDS = ['number', 'hash', 'parentHash', 'baseFeePerGas'] as const;

export type SelectedExecutionTransactionEvidence = {
  environmentId: string;
  operationId: string;
  variantId: string;
  kind: 'approve' | 'wrap' | 'unwrap' | 'swap';
  transactionHash: string;
  expectedFrom: string;
  expectedTo: string;
  expectedValueWei: string;
  expectedChainId: string;
  expectedNonce: string;
  expectedGas: string;
  expectedInput: string;
};

const SELECTED_EXECUTION_CALLS = {
  approve: { signature: 'approve(address,uint256)', argumentBytes: 64 },
  wrap: { signature: 'deposit()', argumentBytes: 0 },
  unwrap: { signature: 'withdraw(uint256)', argumentBytes: 32 },
  swap: {
    signature: 'exactInputSingle((address,address,uint24,address,uint256,uint256,uint160))',
    argumentBytes: 224,
  },
} as const;

// AICODE-NOTE: Only SC007's four static contract calls can opt into calldata evidence; x402 EIP-3009 payloads stay on the public projection.
function isSelectedExecutionCalldata(
  kind: SelectedExecutionTransactionEvidence['kind'],
  input: unknown,
): input is string {
  const call = SELECTED_EXECUTION_CALLS[kind];
  if (typeof input !== 'string' || !/^0x[0-9a-f]*$/i.test(input)
    || input.length !== 10 + call.argumentBytes * 2) return false;
  const selector = keccak256(toBytes(call.signature)).slice(0, 10);
  return input.slice(0, 10).toLowerCase() === selector.toLowerCase();
}

type PublicTransactionProjection = {
  name: 'bef-public-cost-transaction/v1' | 'bef-public-cost-block/v1' | 'bef-selected-execution-transaction/v1';
  fields: readonly string[];
  blockTransactionFields?: readonly string[];
  selectedExecutionKind?: SelectedExecutionTransactionEvidence['kind'];
};

function objectRecord(value: unknown): Record<string, unknown> | null {
  return value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : null;
}

function pickPublicFields(value: unknown, fields: readonly string[]): Record<string, unknown> | null {
  const record = objectRecord(value);
  if (!record) return null;
  const projected: Record<string, unknown> = {};
  for (const field of fields) {
    if (!Object.hasOwn(record, field)) continue;
    const value = record[field];
    if (typeof value === 'string' || value === null) projected[field] = value;
  }
  return projected;
}

function rpcQuantityMatches(value: unknown, expectedDecimal: string): boolean {
  if (typeof value !== 'string' || !/^0x(?:0|[1-9a-f][0-9a-f]*)$/i.test(value)
    || !/^(?:0|[1-9][0-9]*)$/.test(expectedDecimal)) return false;
  return BigInt(value) === BigInt(expectedDecimal);
}

/**
 * Full JSON-RPC transaction objects contain signature fields and calldata. Those bytes can include
 * EIP-3009 authorization material, so persist only this fixed public fee/payer projection.
 */
function selectedExecutionProjection(
  method: string,
  params: unknown[],
  result: unknown,
  selected: SelectedExecutionTransactionEvidence,
): { result: unknown; metadata: PublicTransactionProjection } {
  const transaction = objectRecord(result);
  const transactionHash = params.length === 1 && typeof params[0] === 'string' ? params[0] : null;
  if (method !== 'eth_getTransactionByHash' || !transaction
    || !transactionHash || transactionHash.toLowerCase() !== selected.transactionHash.toLowerCase()
    || typeof transaction.hash !== 'string' || transaction.hash.toLowerCase() !== selected.transactionHash.toLowerCase()
    || typeof transaction.from !== 'string' || transaction.from.toLowerCase() !== selected.expectedFrom.toLowerCase()
    || typeof transaction.to !== 'string' || transaction.to.toLowerCase() !== selected.expectedTo.toLowerCase()
    || typeof transaction.value !== 'string' || !/^0x(?:0|[1-9a-f][0-9a-f]*)$/i.test(transaction.value)
    || !/^(?:0|[1-9][0-9]*)$/.test(selected.expectedValueWei)
    || BigInt(transaction.value) !== BigInt(selected.expectedValueWei)
    || !rpcQuantityMatches(transaction.chainId, selected.expectedChainId)
    || !rpcQuantityMatches(transaction.nonce, selected.expectedNonce)
    || !rpcQuantityMatches(transaction.gas, selected.expectedGas)
    || !isSelectedExecutionCalldata(selected.kind, selected.expectedInput)
    || !isSelectedExecutionCalldata(selected.kind, transaction.input)
    || transaction.input.toLowerCase() !== selected.expectedInput.toLowerCase()) {
    throw new Error('probe_rpc_selected_execution_transaction_binding_invalid');
  }
  const fields = [...PUBLIC_TRANSACTION_FIELDS, 'input'] as const;
  return {
    result: pickPublicFields(transaction, fields),
    metadata: {
      name: 'bef-selected-execution-transaction/v1',
      fields,
      selectedExecutionKind: selected.kind,
    },
  };
}

function publicCostProjection(method: string, params: unknown[], result: unknown): {
  result: unknown;
  metadata: PublicTransactionProjection;
} | null {
  if (method === 'eth_getTransactionByHash') {
    return {
      result: pickPublicFields(result, PUBLIC_TRANSACTION_FIELDS),
      metadata: { name: 'bef-public-cost-transaction/v1', fields: PUBLIC_TRANSACTION_FIELDS },
    };
  }
  if (method === 'eth_getBlockByNumber' && params[1] === true) {
    const block = pickPublicFields(result, PUBLIC_BLOCK_FIELDS);
    if (block && Array.isArray(objectRecord(result)?.transactions)) {
      block.transactions = (objectRecord(result)!.transactions as unknown[]).map((transaction) => {
        if (typeof transaction === 'string') return transaction;
        return pickPublicFields(transaction, ['hash', 'from']);
      });
    }
    return {
      result: block,
      metadata: {
        name: 'bef-public-cost-block/v1', fields: [...PUBLIC_BLOCK_FIELDS, 'transactions'],
        blockTransactionFields: ['hash', 'from'],
      },
    };
  }
  return null;
}

export class ReadOnlyRpcEvidence {
  private sequence = 0;
  private deadlineAtMs = Number.POSITIVE_INFINITY;
  private readonly localBindings = new Map<string, {
    environmentId: string;
    identityArtifact: string;
    endpointRef: { scheme: string; host: string; port: number };
  }>();

  constructor(private readonly evidence: EvidenceWriter, private readonly timeoutMs = 10_000) {}

  setDeadlineAt(deadlineAtMs: number): void {
    this.deadlineAtMs = deadlineAtMs;
  }

  async bindLocalEndpoint(input: {
    url: string;
    environmentId: string;
    manifestSha256: string;
    label: string;
  }): Promise<{ environmentId: string; identityArtifact: string; endpointRef: { scheme: string; host: string; port: number } }> {
    let endpoint: URL;
    try {
      endpoint = new URL(input.url);
    } catch {
      throw new Error('probe_rpc_endpoint_identity_invalid_url');
    }
    const host = endpoint.hostname.replace(/^\[|\]$/g, '').toLowerCase();
    if (endpoint.protocol !== 'http:' || endpoint.username || endpoint.password
      || endpoint.pathname !== '/' || endpoint.search || endpoint.hash
      || !['localhost', '127.0.0.1', '::1'].includes(host)
      || !/^[a-z][a-z0-9-]{1,31}$/.test(input.environmentId)
      || !/^(?:[0-9a-f]{64})$/i.test(input.manifestSha256)) {
      throw new Error('probe_rpc_endpoint_identity_invalid_url');
    }
    const origin = endpoint.origin;
    const previous = this.localBindings.get(origin);
    if (previous) {
      if (previous.environmentId !== input.environmentId) throw new Error('probe_rpc_endpoint_identity_rebound');
      return previous;
    }
    const remainingMs = Math.floor(this.deadlineAtMs - Date.now());
    if (remainingMs <= 0) throw new Error('probe_trial_guardrail_deadline_exceeded');
    const timeout = Math.min(10_000, remainingMs);
    let response;
    try {
      response = await probeFetch(`${origin}/healthz`, {
        method: 'GET',
        redirect: 'error',
        signal: AbortSignal.timeout(timeout),
      });
    } catch {
      throw new Error('probe_rpc_endpoint_identity_unavailable');
    }
    let rawBody: Buffer;
    try {
      rawBody = Buffer.from(await response.arrayBuffer());
    } catch {
      throw new Error('probe_rpc_endpoint_identity_unreadable');
    }
    if (!response.ok || rawBody.byteLength > 4096) throw new Error('probe_rpc_endpoint_identity_invalid_response');
    let health: unknown;
    try {
      health = JSON.parse(rawBody.toString('utf8')) as unknown;
    } catch {
      throw new Error('probe_rpc_endpoint_identity_invalid_response');
    }
    if (!health || typeof health !== 'object' || Array.isArray(health)) throw new Error('probe_rpc_endpoint_identity_invalid_response');
    const healthRecord = health as Record<string, unknown>;
    const allowedKeys = new Set(['status', 'boundary', 'envId', 'manifestSha256']);
    if (Object.keys(healthRecord).some((key) => !allowedKeys.has(key))
      || healthRecord.status !== 'ok'
      || healthRecord.boundary !== 'local-chain-readonly-proxy'
      || healthRecord.envId !== input.environmentId
      || typeof healthRecord.manifestSha256 !== 'string'
      || healthRecord.manifestSha256.toLowerCase() !== input.manifestSha256.toLowerCase()) {
      throw new Error('probe_rpc_endpoint_identity_mismatch');
    }

    const endpointRef = {
      scheme: endpoint.protocol.slice(0, -1),
      host: endpoint.hostname,
      port: Number(endpoint.port || '80'),
    };
    const healthArtifact = `rpc/endpoint-health-${input.environmentId}.json`;
    await this.evidence.writeRawJson(healthArtifact, rawBody, 'local-chain-readonly-proxy');
    const identityArtifact = `rpc/endpoint-binding-${input.environmentId}.json`;
    await this.evidence.writeObservation(identityArtifact, input.label, {
      schemaVersion: 'bef-rpc-endpoint-binding/v1',
      boundary: 'local-chain-readonly-proxy',
      operationId: null,
      variantId: null,
      environmentId: input.environmentId,
      endpointRef,
      healthArtifactPath: healthArtifact,
      healthArtifactSha256: sha256Bytes(rawBody),
      health: healthRecord,
    });
    const binding = { environmentId: input.environmentId, identityArtifact, endpointRef };
    this.localBindings.set(origin, binding);
    return binding;
  }

  async call<T = unknown>(input: {
    url: string;
    endpointBoundary: RpcBoundary;
    environmentId?: string;
    method: string;
    params: unknown[];
    requestedBlock?: string | null;
    operationId: string | null;
    variantId: string | null;
    label: string;
    selectedExecutionTransaction?: SelectedExecutionTransactionEvidence;
  }): Promise<RpcResult<T>> {
    const remainingMs = Math.floor(this.deadlineAtMs - Date.now());
    if (remainingMs <= 0) throw new Error('probe_trial_guardrail_deadline_exceeded');
    const selectedExecution = input.selectedExecutionTransaction;
    if (selectedExecution) {
      const validSelectedContext = input.endpointBoundary === 'local-chain-readonly-proxy'
        && ['approve', 'wrap', 'unwrap', 'swap'].includes(selectedExecution.kind)
        && selectedExecution.environmentId.length > 0
        && selectedExecution.operationId.length > 0
        && selectedExecution.variantId.length > 0
        && input.environmentId === selectedExecution.environmentId
        && typeof input.operationId === 'string' && input.operationId === selectedExecution.operationId
        && typeof input.variantId === 'string' && input.variantId === selectedExecution.variantId
        && input.method === 'eth_getTransactionByHash'
        && input.params.length === 1 && typeof input.params[0] === 'string'
        && input.params[0].toLowerCase() === selectedExecution.transactionHash.toLowerCase()
        && /^(?:0|[1-9][0-9]*)$/.test(selectedExecution.expectedValueWei)
        && /^(?:0|[1-9][0-9]*)$/.test(selectedExecution.expectedChainId)
        && /^(?:0|[1-9][0-9]*)$/.test(selectedExecution.expectedNonce)
        && /^(?:0|[1-9][0-9]*)$/.test(selectedExecution.expectedGas)
        && /^0x[0-9a-f]{40}$/i.test(selectedExecution.expectedFrom)
        && /^0x[0-9a-f]{40}$/i.test(selectedExecution.expectedTo)
        && /^0x[0-9a-f]{64}$/i.test(selectedExecution.transactionHash)
        && isSelectedExecutionCalldata(selectedExecution.kind, selectedExecution.expectedInput);
      if (!validSelectedContext) throw new Error('probe_rpc_selected_execution_context_invalid');
    }
    let response;
    try {
      response = await probeFetch(input.url, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: input.method, params: input.params }),
        redirect: 'error',
        signal: AbortSignal.timeout(Math.min(this.timeoutMs, remainingMs)),
      });
    } catch {
      throw new Error('probe_rpc_unavailable');
    }
    let responseJson: unknown;
    try {
      responseJson = await response.json() as unknown;
    } catch {
      throw new Error('probe_rpc_invalid_response');
    }
    const envelope = responseJson as { result?: unknown; error?: unknown; id?: number };
    const rawResult = envelope && envelope.result;
    let localBinding: {
      environmentId: string;
      identityArtifact: string;
      endpointRef: { scheme: string; host: string; port: number };
    } | undefined;
    if (input.endpointBoundary === 'local-chain-readonly-proxy') {
      let origin: string;
      try {
        const endpoint = new URL(input.url);
        if (endpoint.pathname !== '/' || endpoint.search || endpoint.hash || endpoint.username || endpoint.password) {
          throw new Error();
        }
        origin = endpoint.origin;
      } catch {
        throw new Error('probe_rpc_endpoint_identity_unbound');
      }
      localBinding = this.localBindings.get(origin);
      if (input.environmentId && localBinding?.environmentId !== input.environmentId) {
        throw new Error('probe_rpc_endpoint_identity_mismatch');
      }
    }
    if (selectedExecution && localBinding?.environmentId !== selectedExecution.environmentId) {
      throw new Error('probe_rpc_endpoint_identity_mismatch');
    }
    const publicProjection = input.endpointBoundary === 'local-chain-readonly-proxy'
      ? selectedExecution
        ? selectedExecutionProjection(input.method, input.params, rawResult, selectedExecution)
        : publicCostProjection(input.method, input.params, rawResult)
      : null;
    const result = publicProjection ? publicProjection.result : rawResult;
    this.sequence += 1;
    await this.evidence.writeObservation(`rpc/${String(this.sequence).padStart(4, '0')}-${input.label}.json`, input.label, {
      schemaVersion: 'bef-rpc-observation/v1',
      boundary: input.endpointBoundary,
      operationId: input.operationId,
      variantId: input.variantId,
      endpointBoundary: input.endpointBoundary,
      ...(localBinding ? {
        environmentId: localBinding.environmentId,
        endpointIdentityArtifact: localBinding.identityArtifact,
        endpointRef: localBinding.endpointRef,
      } : {}),
      method: input.method,
      params: sanitizeValue(input.params),
      requestedBlock: input.requestedBlock ?? null,
      ...(publicProjection ? { resultProjection: publicProjection.metadata } : {}),
      result: sanitizeValue(envelope?.error
        ? publicProjection
          ? { error: { ...(Number.isSafeInteger(objectRecord(envelope.error)?.code) ? { code: objectRecord(envelope.error)!.code } : {}) } }
          : { error: envelope.error }
        : result),
    });
    if (input.endpointBoundary === 'local-chain-readonly-proxy'
      && input.method === 'eth_getTransactionReceipt'
      && response.ok
      && isReadOnlyBoundaryMethodDenied(envelope?.error)) {
      throw new RpcReadOnlyBoundaryMethodDeniedError(input.endpointBoundary, input.method);
    }
    if (!response.ok || envelope?.error || result === undefined) throw new Error('probe_rpc_call_failed');
    return { result: result as T, requestedBlock: input.requestedBlock ?? null };
  }

  async block(input: {
    url: string;
    boundary: RpcBoundary;
    blockNumber: string;
    operationId: string | null;
    variantId: string | null;
    label: string;
  }): Promise<{ number: string; hash: string }> {
    const { result } = await this.call<{ number: string; hash: string } | null>({
      url: input.url,
      endpointBoundary: input.boundary,
      method: 'eth_getBlockByNumber',
      params: [input.blockNumber, false],
      requestedBlock: input.blockNumber,
      operationId: input.operationId,
      variantId: input.variantId,
      label: input.label,
    });
    if (!result || result.number?.toLowerCase() !== input.blockNumber.toLowerCase() || !/^0x[0-9a-f]{64}$/i.test(result.hash)) {
      throw new Error('probe_rpc_block_identity_missing');
    }
    return { number: result.number, hash: result.hash };
  }

  async tokenBalance(input: {
    url: string;
    boundary: RpcBoundary;
    manifest: RuntimeManifest;
    address: `0x${string}`;
    blockTag?: string;
    operationId: string | null;
    variantId: string | null;
    label: string;
  }): Promise<bigint> {
    const blockTag = input.blockTag ?? 'latest';
    const data = encodeFunctionData({ abi: ERC20_BALANCE_OF_ABI, functionName: 'balanceOf', args: [input.address] });
    const { result } = await this.call<string>({
      url: input.url,
      endpointBoundary: input.boundary,
      method: 'eth_call',
      params: [{ to: input.manifest.contracts.usdc.address, data }, blockTag],
      requestedBlock: blockTag,
      operationId: input.operationId,
      variantId: input.variantId,
      label: input.label,
    });
    if (typeof result !== 'string' || !/^0x[0-9a-f]+$/i.test(result)) throw new Error('probe_rpc_balance_invalid');
    return BigInt(result);
  }

  async receipt(input: {
    url: string;
    boundary: RpcBoundary;
    transactionHash: string;
    operationId: string;
    variantId: string | null;
    label: string;
  }): Promise<RpcReceipt> {
    const { result } = await this.call<RpcReceipt | null>({
      url: input.url,
      endpointBoundary: input.boundary,
      method: 'eth_getTransactionReceipt',
      params: [input.transactionHash],
      operationId: input.operationId,
      variantId: input.variantId,
      label: input.label,
    });
    if (!result || result.transactionHash?.toLowerCase() !== input.transactionHash.toLowerCase()) {
      throw new Error('probe_rpc_receipt_missing');
    }
    return result;
  }
}

function isReadOnlyBoundaryMethodDenied(error: unknown): boolean {
  if (!error || typeof error !== 'object' || Array.isArray(error)) return false;
  const record = error as Record<string, unknown>;
  return record.code === -32601 && record.message === 'Method is not permitted by the read-only boundary';
}

export const TRANSFER_TOPIC = keccak256(toBytes('Transfer(address,address,uint256)')).toLowerCase();

export function transferEvents(receipt: RpcReceipt, tokenAddress: string): Array<{
  from: string;
  to: string;
  amount: bigint;
}> {
  return receipt.logs
    .filter((log) => log.address.toLowerCase() === tokenAddress.toLowerCase() && log.topics[0]?.toLowerCase() === TRANSFER_TOPIC)
    .map((log) => {
      const from = `0x${(log.topics[1] ?? '').slice(-40)}`;
      const to = `0x${(log.topics[2] ?? '').slice(-40)}`;
      if (!/^0x[0-9a-f]{40}$/i.test(from) || !/^0x[0-9a-f]{40}$/i.test(to) || !/^0x[0-9a-f]+$/i.test(log.data)) {
        throw new Error('probe_rpc_transfer_log_invalid');
      }
      return { from, to, amount: BigInt(log.data) };
    });
}
