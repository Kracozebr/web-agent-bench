/*
 * AICODE-NOTE: All upstream reads go through the actual source read-only RPC
 * proxy. The offline evidence replayer is invoked as a local process against
 * captured files only; it receives no endpoint, credential, or RPC client.
 */

import { createHash, randomUUID } from 'node:crypto';
import { spawn } from 'node:child_process';
import { constants as fsConstants } from 'node:fs';
import { access, copyFile, lstat, mkdir, mkdtemp, readFile, readdir, realpath, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { encodeFunctionData, keccak256, type Hex } from 'viem';
import { apiPath, newParticipantId } from './environment.js';
import { sanitizeValue } from './evidence.js';
import { probeFetch } from './fetch-types.js';
import type { ProbeContext, ScenarioExecution } from './runner.js';
import type { ReplayedOriginalCaptureReference } from './types.js';
import { createEphemeralSigner } from './x402.js';

export const SC012_VARIANTS = [
  'wrong_source_identity',
  'send_raw_transaction',
  'admin_method',
  'sign_method',
  'secret_in_artifact',
  'missing_hash',
] as const;

export type Sc012ReplayInputs = {
  sc004EvidenceDirectory: string;
  sc005EvidenceDirectory: string;
};

type ReplaySourceProfile = 'active-delta' | 'synced-main';

const REPLAY_SOURCE_PROFILE_VERSIONS: Record<ReplaySourceProfile, string> = {
  'active-delta': 'active-delta/v1',
  'synced-main': 'synced-main/v1',
};

function selectedReplaySourceProfile(): ReplaySourceProfile {
  const configured = process.env.BEF_SPEC_PROFILE;
  if (configured === undefined) return 'active-delta';
  if (configured === 'active-delta' || configured === 'synced-main') return configured;
  throw new Error('probe_sc012_source_profile_invalid');
}

type JsonObject = Record<string, unknown>;
type StreamingProbeResponse = {
  headers: { get(name: string): string | null };
  body: ReadableStream<Uint8Array> | null;
};
type MetricCounts = { deniedByMethod: Record<string, number>; forwardedByMethod: Record<string, number> };
type MetricSnapshot = MetricCounts & {
  forwardedItems: number;
  deniedItems: number;
  sourceCallsReserved: number;
  sourceCallLimit: number;
  mode: string;
};
type JsonRpcResponse = { jsonrpc?: string; id?: string | number | null; result?: unknown; error?: { code?: number; message?: string; data?: unknown } };

const ERC20_BALANCE_OF_ABI = [{
  type: 'function',
  name: 'balanceOf',
  stateMutability: 'view',
  inputs: [{ name: 'account', type: 'address' }],
  outputs: [{ name: '', type: 'uint256' }],
}] as const;

const SAFE_REPLAY_TIMEOUT_MS = 45_000;
const REPLAY_TERMINATION_GRACE_MS = 2_000;
const REPLAY_FINAL_CLOSE_GRACE_MS = 2_000;
const MAX_REPLAY_EVIDENCE_FILES = 4_096;
const MAX_REPLAY_INDEX_BYTES = 1_048_576;
const REPLAY_EVIDENCE_ROOT = 'artifacts/benchmark-environment-feasibility/probes';
const sourceEndpointBindings = new WeakMap<ProbeContext, {
  environmentId: string;
  identityArtifact: string;
  endpointRef: { scheme: string; host: string; port: number };
  healthArtifactPath: string;
  healthArtifactSha256: string;
}>();
const DENIED_ATTEMPTS: ReadonlyArray<{ variantId: string; method: string; params: unknown[] }> = [
  { variantId: 'send_raw_transaction', method: 'eth_sendRawTransaction', params: ['0x00'] },
  { variantId: 'admin_method', method: 'anvil_reset', params: [] },
  { variantId: 'sign_method', method: 'eth_sign', params: ['0x0000000000000000000000000000000000000000', '0x00'] },
];

function isObject(value: unknown): value is JsonObject {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value));
}

function requireObject(value: unknown, label: string): JsonObject {
  if (!isObject(value)) throw new Error(`probe_sc012_invalid_${label}`);
  return value;
}

function requireString(value: unknown, label: string): string {
  if (typeof value !== 'string' || value.length === 0) throw new Error(`probe_sc012_missing_${label}`);
  return value;
}

function stableJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(',')}]`;
  if (isObject(value)) {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableJson(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value) ?? 'null';
}

function isPathWithin(parent: string, candidate: string): boolean {
  const child = relative(parent, candidate);
  return child !== '' && child !== '..' && !child.startsWith(`..${sep}`) && !isAbsolute(child);
}

function canonicalPathKey(path: string): string {
  const normalized = resolve(path).replaceAll('\\', '/');
  return process.platform === 'win32' ? normalized.toLowerCase() : normalized;
}

function sanitizedEndpointRef(rawUrl: string, errorCode: string): { scheme: string; host: string; port: number } {
  let url: URL;
  try { url = new URL(rawUrl); } catch { throw new Error(errorCode); }
  const host = url.hostname.replace(/^\[|\]$/g, '').toLowerCase();
  if (url.protocol !== 'http:' || url.username || url.password || url.pathname !== '/' || url.search || url.hash
    || !host || host.length > 253) throw new Error(errorCode);
  const port = Number(url.port || '80');
  if (!Number.isSafeInteger(port) || port < 1 || port > 65_535) throw new Error(errorCode);
  return { scheme: 'http', host, port };
}

async function assertNoSymlinkPath(root: string, target: string, errorCode: string): Promise<void> {
  const absoluteRoot = resolve(root);
  const absoluteTarget = resolve(target);
  if (absoluteTarget !== absoluteRoot && !isPathWithin(absoluteRoot, absoluteTarget)) throw new Error(errorCode);
  const rootStat = await lstat(absoluteRoot).catch(() => null);
  if (!rootStat || rootStat.isSymbolicLink() || !rootStat.isDirectory()) throw new Error(errorCode);
  const child = relative(absoluteRoot, absoluteTarget);
  let current = absoluteRoot;
  for (const segment of child ? child.split(sep) : []) {
    current = join(current, segment);
    const info = await lstat(current).catch(() => null);
    if (!info || info.isSymbolicLink()) throw new Error(errorCode);
    if (current !== absoluteTarget && !info.isDirectory()) throw new Error(errorCode);
  }
}

async function scanEvidenceTree(root: string, maxBytes: number, errorCode: string): Promise<{ files: string[]; bytes: number }> {
  const files: string[] = [];
  let bytes = 0;
  const walk = async (directory: string): Promise<void> => {
    const entries = await readdir(directory, { withFileTypes: true });
    entries.sort((left, right) => left.name < right.name ? -1 : left.name > right.name ? 1 : 0);
    for (const entry of entries) {
      const path = join(directory, entry.name);
      const info = await lstat(path).catch(() => null);
      if (!info || entry.isSymbolicLink() || info.isSymbolicLink()) throw new Error(errorCode);
      if (info.isDirectory()) {
        await walk(path);
      } else if (info.isFile()) {
        if (info.size > maxBytes || files.length >= MAX_REPLAY_EVIDENCE_FILES) throw new Error(errorCode);
        bytes += info.size;
        if (bytes > maxBytes) throw new Error(errorCode);
        files.push(path);
      } else {
        throw new Error(errorCode);
      }
    }
  };
  await walk(root);
  return { files, bytes };
}

async function canonicalReplayDirectory(root: string, evidenceDirectory: string, maxBytes: number): Promise<{
  absolutePath: string;
  files: string[];
  bytes: number;
}> {
  const absoluteRoot = resolve(root);
  const evidenceRoot = resolve(absoluteRoot, REPLAY_EVIDENCE_ROOT);
  const absolutePath = resolve(absoluteRoot, evidenceDirectory);
  if (!isPathWithin(evidenceRoot, absolutePath)) throw new Error('probe_sc012_original_capture_path_outside_root');
  await assertNoSymlinkPath(absoluteRoot, evidenceRoot, 'probe_sc012_original_capture_symlink_rejected');
  await assertNoSymlinkPath(absoluteRoot, absolutePath, 'probe_sc012_original_capture_symlink_rejected');
  const canonicalRoot = await realpath(absoluteRoot).catch(() => '');
  const canonicalEvidence = await realpath(absolutePath).catch(() => '');
  if (!canonicalRoot || !canonicalEvidence || canonicalPathKey(canonicalRoot) !== canonicalPathKey(absoluteRoot)
    || canonicalPathKey(canonicalEvidence) !== canonicalPathKey(absolutePath)) {
    throw new Error('probe_sc012_original_capture_not_canonical');
  }
  const info = await lstat(absolutePath).catch(() => null);
  if (!info || !info.isDirectory() || info.isSymbolicLink()) throw new Error('probe_sc012_original_capture_not_directory');
  const tree = await scanEvidenceTree(absolutePath, maxBytes, 'probe_sc012_original_capture_size_or_path_invalid');
  return { absolutePath, ...tree };
}

async function writeCustomObservation(
  ctx: ProbeContext,
  relativePath: string,
  observationId: string,
  boundary: string,
  body: JsonObject,
): Promise<void> {
  const payload = sanitizeValue({ ...body, boundary }, ctx.secretValues);
  const bytes = Buffer.from(`${JSON.stringify(payload, null, 2)}\n`, 'utf8');
  await ctx.evidence.writeRawJson(relativePath, bytes, boundary);
  ctx.evidence.observations.push({ id: observationId, sourceArtifact: relativePath });
}

function requireCounter(value: unknown, label: string): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) {
    throw new Error(`probe_sc012_invalid_counter_${label}`);
  }
  return value;
}

function readMethodCount(counts: Record<string, number>, method: string): number {
  return counts[method] ?? 0;
}

function counterMap(value: unknown, label: string): Record<string, number> {
  const object = requireObject(value, label);
  const result: Record<string, number> = {};
  for (const [method, count] of Object.entries(object)) result[method] = requireCounter(count, `${label}_${method}`);
  return result;
}

function sourceMetricsUrl(sourceProxyUrl: string): string {
  const url = new URL('/internal/admin/metrics', sourceProxyUrl);
  if (url.username || url.password || !['http:', 'https:'].includes(url.protocol)) {
    throw new Error('probe_sc012_source_proxy_url_invalid');
  }
  return url.toString();
}

async function readBoundedResponse(response: StreamingProbeResponse, maxBytes: number, failureCode: string): Promise<Buffer<ArrayBufferLike>> {
  const lengthHeader = response.headers.get('content-length');
  if (lengthHeader && /^\d+$/.test(lengthHeader) && Number(lengthHeader) > maxBytes) {
    throw new Error(failureCode);
  }
  const reader = response.body?.getReader();
  if (!reader) return Buffer.alloc(0);
  const chunks: Uint8Array[] = [];
  let total = 0;
  while (true) {
    const next = await reader.read();
    if (next.done) break;
    total += next.value.byteLength;
    if (total > maxBytes) {
      await reader.cancel().catch(() => undefined);
      throw new Error(failureCode);
    }
    chunks.push(next.value);
  }
  return Buffer.concat(chunks.map((chunk) => Buffer.from(chunk)), total);
}

async function sourceMetrics(ctx: ProbeContext, label: string, variantId: string | null): Promise<MetricSnapshot> {
  const response = await ctx.transport.request({
    boundary: 'private-admin-http',
    observationId: label,
    method: 'GET',
    url: sourceMetricsUrl(ctx.env.sourceProxyUrl),
    headers: { 'X-BEF-Service-Key': ctx.env.serviceKey },
    operationId: null,
    variantId,
  });
  if (response.status !== 200) throw new Error('probe_sc012_source_proxy_metrics_unavailable');
  const body = requireObject(response.body, 'source_proxy_metrics');
  if (body.mode !== 'source') throw new Error('probe_sc012_source_proxy_mode_mismatch');
  const sourceCallsReserved = requireCounter(body.sourceCallsReserved, 'source_calls_reserved');
  const sourceCallLimit = requireCounter(body.sourceCallLimit, 'source_call_limit');
  if (sourceCallLimit !== ctx.runtime.manifest.guardrails.maxSourceCallsPerTrial
    || sourceCallsReserved > sourceCallLimit) {
    throw new Error('probe_sc012_source_proxy_call_budget_mismatch');
  }
  return {
    mode: 'source',
    forwardedItems: requireCounter(body.forwardedItems, 'forwarded_items'),
    deniedItems: requireCounter(body.deniedItems, 'denied_items'),
    sourceCallsReserved,
    sourceCallLimit,
    deniedByMethod: counterMap(body.deniedByMethod, 'denied_by_method'),
    forwardedByMethod: counterMap(body.forwardedByMethod, 'forwarded_by_method'),
  };
}

function metricDelta(before: MetricSnapshot, after: MetricSnapshot, method: string): {
  denied: number;
  forwarded: number;
  sourceCallsReserved: number;
} {
  return {
    denied: readMethodCount(after.deniedByMethod, method) - readMethodCount(before.deniedByMethod, method),
    forwarded: readMethodCount(after.forwardedByMethod, method) - readMethodCount(before.forwardedByMethod, method),
    sourceCallsReserved: after.sourceCallsReserved - before.sourceCallsReserved,
  };
}

function nextDeadline(ctx: ProbeContext, startedAt: number): number {
  return startedAt + ctx.runtime.manifest.guardrails.maxTrialSeconds * 1_000;
}

function requestedBlock(method: string, params: unknown[]): string | null {
  if (method === 'eth_getBlockByNumber' || method === 'eth_getBlockByHash') {
    return typeof params[0] === 'string' ? params[0] : null;
  }
  if (method === 'eth_getCode') return typeof params[1] === 'string' ? params[1] : null;
  if (method === 'eth_getStorageAt') return typeof params[2] === 'string' ? params[2] : null;
  return null;
}

async function sourceRpc(ctx: ProbeContext, input: {
  method: string;
  params: unknown[];
  label: string;
  variantId: string | null;
  shouldForward: boolean;
  startedAt: number;
}): Promise<{ response: JsonRpcResponse; forwarded: boolean }> {
  const endpointBinding = sourceEndpointBindings.get(ctx);
  if (!endpointBinding || endpointBinding.environmentId !== ctx.env.envId) {
    throw new Error('probe_sc012_source_endpoint_identity_unbound');
  }
  if (Date.now() >= nextDeadline(ctx, input.startedAt)) throw new Error('probe_trial_guardrail_deadline_exceeded');
  if (input.shouldForward && !(ctx.runtime.manifest.source.allowedMethods as readonly string[]).includes(input.method)) {
    throw new Error('probe_sc012_source_method_not_declared_readonly');
  }
  const id = `bef-sc012-${randomUUID()}`;
  const request = { jsonrpc: '2.0', id, method: input.method, params: input.params };
  const requestText = JSON.stringify(request);
  const requestBytes = Buffer.byteLength(requestText, 'utf8');
  if (requestBytes > ctx.runtime.manifest.source.maxRequestBytes) throw new Error('probe_sc012_source_request_exceeds_manifest_limit');

  const before = await sourceMetrics(ctx, `${input.label}-metrics-before`, input.variantId);
  let httpStatus = 0;
  let responseValue: unknown;
  let rawResponse: Buffer<ArrayBufferLike> = Buffer.alloc(0);
  try {
    const response = await probeFetch(ctx.env.sourceProxyUrl, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: requestText,
      redirect: 'error',
      signal: AbortSignal.timeout(Math.min(10_000, Math.max(1, nextDeadline(ctx, input.startedAt) - Date.now()))),
    });
    httpStatus = response.status;
    rawResponse = await readBoundedResponse(
      response as unknown as StreamingProbeResponse,
      ctx.runtime.manifest.source.maxResponseBytes,
      'probe_sc012_source_response_exceeds_manifest_limit',
    );
    try {
      responseValue = JSON.parse(rawResponse.toString('utf8')) as unknown;
    } catch {
      responseValue = { invalidJsonResponse: true };
    }
  } catch (error) {
    if (error instanceof Error && error.message.startsWith('probe_sc012_')) throw error;
    throw new Error('probe_sc012_source_proxy_request_failed');
  }
  const rawResponseText = rawResponse.toString('utf8');
  if (ctx.secretValues.some((secret) => secret.length > 0 && rawResponseText.includes(secret))) {
    throw new Error('probe_sc012_source_rpc_secret_response');
  }
  const after = await sourceMetrics(ctx, `${input.label}-metrics-after`, input.variantId);
  const delta = metricDelta(before, after, input.method);
  const actuallyForwarded = delta.forwarded === 1 && delta.denied === 0 && delta.sourceCallsReserved === 1;
  const expectedBoundaryOutcome = input.shouldForward
    ? actuallyForwarded
    : delta.forwarded === 0 && delta.denied === 1 && delta.sourceCallsReserved === 0;
  if (!expectedBoundaryOutcome) throw new Error('probe_sc012_source_proxy_counter_delta_mismatch');

  const response = isObject(responseValue) ? responseValue as JsonRpcResponse : {};
  const hasError = isObject(response.error);
  const correlated = response.id === id && response.jsonrpc === '2.0';
  const result = hasError
    ? { error: { code: response.error?.code ?? null, message: response.error?.message ?? 'rpc_error' } }
    : response.result;
  await ctx.evidence.writeObservation(`source-rpc/${input.label}.json`, input.label, {
    schemaVersion: 'bef-rpc-observation/v1',
    boundary: 'source-readonly-proxy',
    operationId: null,
    variantId: input.variantId,
    envId: ctx.env.envId,
    environmentId: endpointBinding.environmentId,
    generationId: ctx.primaryGeneration?.generationId ?? null,
    endpointIdentityArtifact: endpointBinding.identityArtifact,
    endpointRef: endpointBinding.endpointRef,
    healthArtifactPath: endpointBinding.healthArtifactPath,
    healthArtifactSha256: endpointBinding.healthArtifactSha256,
    endpointBoundary: 'source-readonly-proxy',
    method: input.method,
    requestId: id,
    requestBody: sanitizeValue(request, ctx.secretValues),
    params: sanitizeValue(input.params, ctx.secretValues),
    requestedBlock: requestedBlock(input.method, input.params),
    requestBytes,
    responseStatus: httpStatus,
    responseBytes: rawResponse.byteLength,
    responseBodySha256: createHash('sha256').update(rawResponse).digest('hex'),
    responseBodyBase64: rawResponse.toString('base64'),
    responseCorrelated: correlated,
    result: sanitizeValue(result, ctx.secretValues),
    forwarded: actuallyForwarded,
    sourceProxyCounterDelta: {
      method: input.method,
      denied: delta.denied,
      forwarded: delta.forwarded,
        sourceCallsReserved: delta.sourceCallsReserved,
      sourceProxyManifestSha256: ctx.runtime.manifestSha256,
        sourceCallLimit: after.sourceCallLimit,
      before: {
        denied: readMethodCount(before.deniedByMethod, input.method),
        forwarded: readMethodCount(before.forwardedByMethod, input.method),
          sourceCallsReserved: before.sourceCallsReserved,
      },
      after: {
        denied: readMethodCount(after.deniedByMethod, input.method),
        forwarded: readMethodCount(after.forwardedByMethod, input.method),
          sourceCallsReserved: after.sourceCallsReserved,
      },
    },
  });

  if (!correlated) throw new Error('probe_sc012_source_rpc_response_uncorrelated');
  if (input.shouldForward && (!httpStatus || httpStatus < 200 || httpStatus >= 300 || hasError || response.result === undefined)) {
    throw new Error('probe_sc012_source_read_failed');
  }
  if (!input.shouldForward && (!hasError || httpStatus < 200 || httpStatus >= 300)) {
    throw new Error('probe_sc012_denied_method_not_rejected');
  }
  return { response, forwarded: actuallyForwarded };
}

async function sourceHealth(ctx: ProbeContext): Promise<JsonObject> {
  const endpointRef = sanitizedEndpointRef(ctx.env.sourceProxyUrl, 'probe_sc012_source_proxy_url_invalid');
  const allowedSourceHosts = new Set([
    'localhost', '127.0.0.1', '::1', ctx.runtime.manifest.local.sourceProxyHost.toLowerCase(),
  ]);
  if (!allowedSourceHosts.has(endpointRef.host.toLowerCase())) {
    throw new Error('probe_sc012_source_proxy_host_not_allowlisted');
  }
  const url = new URL('/healthz', ctx.env.sourceProxyUrl);
  let response;
  try {
    response = await probeFetch(url, { method: 'GET', redirect: 'error', signal: AbortSignal.timeout(5_000) });
  } catch {
    throw new Error('probe_sc012_source_proxy_health_unavailable');
  }
  let responseBytes: Buffer;
  try {
    responseBytes = await readBoundedResponse(
      response as unknown as StreamingProbeResponse,
      ctx.runtime.manifest.source.maxResponseBytes,
      'probe_sc012_source_proxy_health_too_large',
    );
  } catch (error) {
    if (error instanceof Error && error.message.startsWith('probe_sc012_')) throw error;
    throw new Error('probe_sc012_source_proxy_health_invalid');
  }
  const responseText = responseBytes.toString('utf8');
  if (ctx.secretValues.some((secret) => secret.length > 0 && responseText.includes(secret))) {
    throw new Error('probe_sc012_source_proxy_health_secret_response');
  }
  let body: unknown;
  try { body = JSON.parse(responseText) as unknown; } catch { throw new Error('probe_sc012_source_proxy_health_invalid'); }
  const record = requireObject(body, 'source_proxy_health');
  const allowedKeys = new Set(['status', 'boundary', 'envId', 'manifestSha256']);
  if (!response.ok || record.status !== 'ok' || record.boundary !== 'source-readonly-proxy'
    || record.envId !== null || record.manifestSha256 !== ctx.runtime.manifestSha256
    || Object.keys(record).some((key) => !allowedKeys.has(key))) {
    throw new Error('probe_sc012_source_proxy_identity_mismatch');
  }
  const healthArtifactPath = 'source-rpc/proxy-health-raw.json';
  const healthArtifactSha256 = createHash('sha256').update(responseBytes).digest('hex');
  await ctx.evidence.writeRawJson(healthArtifactPath, responseBytes, 'source-readonly-proxy');
  const identityArtifact = 'source-rpc/endpoint-binding.json';
  await ctx.evidence.writeObservation(identityArtifact, 'sc012-source-proxy-endpoint-binding', {
    schemaVersion: 'bef-rpc-endpoint-binding/v1',
    boundary: 'source-readonly-proxy',
    operationId: null,
    variantId: null,
    environmentId: ctx.env.envId,
    endpointRef,
    healthArtifactPath,
    healthArtifactSha256,
    health: record,
  });
  sourceEndpointBindings.set(ctx, {
    environmentId: ctx.env.envId,
    identityArtifact,
    endpointRef,
    healthArtifactPath,
    healthArtifactSha256,
  });
  return record;
}

async function resetAndCreateGeneration(ctx: ProbeContext): Promise<void> {
  const reset = ctx.capability.reset;
  if (reset?.supported !== true || typeof reset.route !== 'string') throw new Error('probe_sc012_reset_capability_missing');
  const resetPath = reset.route.replace(/^POST\s+/i, '').replace('{envId}', ctx.env.envId);
  if (resetPath !== `/internal/admin/environments/${ctx.env.envId}/reset`) {
    throw new Error('probe_sc012_reset_route_invalid');
  }
  const resetResponse = await ctx.transport.request({
    boundary: 'private-admin-http',
    observationId: 'sc012-environment-reset',
    method: 'POST',
    url: apiPath(ctx.env.apiBaseUrl, resetPath),
    headers: { 'X-BEF-Admin-Key': ctx.env.adminKey, 'content-type': 'application/json' },
    body: {},
    operationId: null,
    variantId: null,
  });
  if (resetResponse.status < 200 || resetResponse.status >= 300) throw new Error('probe_sc012_environment_reset_failed');

  const signer = createEphemeralSigner();
  ctx.secretValues.push(signer.privateKey);
  const participantId = newParticipantId(ctx.scenarioId);
  const generationResponse = await ctx.transport.request({
    boundary: 'private-admin-http',
    observationId: 'sc012-generation-create',
    method: 'POST',
    url: apiPath(ctx.env.apiBaseUrl, `/internal/admin/environments/${ctx.env.envId}/generations`),
    headers: { 'X-BEF-Admin-Key': ctx.env.adminKey, 'content-type': 'application/json' },
    body: { participantId, payerAddress: signer.payerAddress, resourceVariant: 'canonical' },
    operationId: null,
    variantId: null,
  });
  if (generationResponse.status < 200 || generationResponse.status >= 300) throw new Error('probe_sc012_generation_create_failed');
  const body = requireObject(generationResponse.body, 'generation_response');
  const envId = requireString(body.envId, 'generation_env_id');
  const generationId = requireString(body.generationId, 'generation_id');
  const returnedParticipant = requireString(body.participantId, 'participant_id');
  const payerAddress = requireString(body.payerAddress, 'payer_address');
  const runToken = requireString(body.runToken, 'run_token');
  if (envId !== ctx.env.envId || returnedParticipant !== participantId
    || payerAddress.toLowerCase() !== signer.payerAddress.toLowerCase()) {
    throw new Error('probe_sc012_generation_identity_mismatch');
  }
  ctx.secretValues.push(runToken);
  ctx.primaryGeneration = { envId, generationId, participantId, payerAddress: signer.payerAddress };
  const persisted = await ctx.database.snapshot({
    envId,
    generationId,
    variantId: null,
    label: 'sc012-generation-readonly-identity',
  });
  const row = persisted.generation.find((item) => String(item.generation_id) === generationId);
  if (!row || String(row.env_id) !== envId || String(row.participant_id) !== participantId
    || String(row.payer_address).toLowerCase() !== payerAddress.toLowerCase()) {
    throw new Error('probe_sc012_generation_database_identity_mismatch');
  }
}

function requireHexData(value: unknown, label: string): Hex {
  if (typeof value !== 'string' || !/^0x(?:[0-9a-f]{2})*$/i.test(value)) throw new Error(`probe_sc012_invalid_${label}`);
  return value as Hex;
}

async function captureSourceIdentityAndCode(ctx: ProbeContext, startedAt: number): Promise<void> {
  const { manifest } = ctx.runtime;
  const health = await sourceHealth(ctx);
  const chain = await sourceRpc(ctx, {
    method: 'eth_chainId', params: [], label: 'sc012-source-chain-id', variantId: null, shouldForward: true, startedAt,
  });
  if (typeof chain.response.result !== 'string' || BigInt(chain.response.result) !== BigInt(manifest.source.chainId)) {
    throw new Error('probe_sc012_source_chain_id_mismatch');
  }
  const block = await sourceRpc(ctx, {
    method: 'eth_getBlockByNumber', params: [manifest.source.blockNumber, false],
    label: 'sc012-source-pinned-block', variantId: null, shouldForward: true, startedAt,
  });
  const blockResult = requireObject(block.response.result, 'pinned_block');
  if (typeof blockResult.number !== 'string' || blockResult.number.toLowerCase() !== manifest.source.blockNumber.toLowerCase()
    || typeof blockResult.hash !== 'string' || blockResult.hash.toLowerCase() !== manifest.source.blockHash.toLowerCase()) {
    throw new Error('probe_sc012_source_block_identity_mismatch');
  }

  const codeExpectations = [
    ['usdc-proxy', manifest.contracts.usdc.address, manifest.contracts.usdc.proxyCodeHash],
    ['weth', manifest.contracts.weth.address, manifest.contracts.weth.codeHash],
    ['factory', manifest.contracts.factory.address, manifest.contracts.factory.codeHash],
    ['swap-router', manifest.contracts.swapRouter02.address, manifest.contracts.swapRouter02.codeHash],
    ['quoter', manifest.contracts.quoterV2.address, manifest.contracts.quoterV2.codeHash],
    ['pool', manifest.contracts.pool.address, manifest.contracts.pool.codeHash],
    ['usdc-implementation', manifest.contracts.usdc.implementation, manifest.contracts.usdc.implementationCodeHash],
  ] as const;
  const observed: Array<{ label: string; address: string; codeSha256: string; codeKeccak256: string }> = [];
  for (const [label, address, expectedHash] of codeExpectations) {
    const codeResponse = await sourceRpc(ctx, {
      method: 'eth_getCode', params: [address, manifest.source.blockNumber],
      label: `sc012-code-${label}`, variantId: null, shouldForward: true, startedAt,
    });
    const code = requireHexData(codeResponse.response.result, `code_${label}`);
    if (code === '0x') throw new Error(`probe_sc012_contract_code_missing_${label.replaceAll('-', '_')}`);
    const codeKeccak256 = keccak256(code).toLowerCase();
    if (codeKeccak256 !== expectedHash.toLowerCase()) throw new Error(`probe_sc012_contract_code_hash_mismatch_${label.replaceAll('-', '_')}`);
    observed.push({
      label,
      address: address.toLowerCase(),
      codeSha256: createHash('sha256').update(Buffer.from(code.slice(2), 'hex')).digest('hex'),
      codeKeccak256,
    });
  }

  const slot = await sourceRpc(ctx, {
    method: 'eth_getStorageAt',
    params: [manifest.contracts.usdc.address, manifest.contracts.usdc.implementationSlot, manifest.source.blockNumber],
    label: 'sc012-usdc-implementation-slot',
    variantId: null,
    shouldForward: true,
    startedAt,
  });
  const slotValue = requireHexData(slot.response.result, 'implementation_slot');
  if (slotValue.length !== 66 || `0x${slotValue.slice(-40)}`.toLowerCase() !== manifest.contracts.usdc.implementation.toLowerCase()) {
    throw new Error('probe_sc012_usdc_implementation_slot_mismatch');
  }

  await ctx.evidence.writeObservation('source-rpc/source-identity-summary.json', 'sc012-source-identity-summary', {
    schemaVersion: 'bef-source-identity-summary/v1',
    boundary: 'source-read-audit',
    operationId: null,
    variantId: null,
    envId: ctx.env.envId,
    generationId: ctx.primaryGeneration?.generationId ?? null,
    endpointBoundary: 'source-readonly-proxy',
    proxyHealth: { boundary: health.boundary, manifestSha256: health.manifestSha256 },
    observedChainId: manifest.source.chainId,
    observedSourceBlock: { number: blockResult.number, hash: blockResult.hash },
    usdcImplementationSlot: { slot: manifest.contracts.usdc.implementationSlot, value: slotValue },
    contractCode: observed,
  });
}

function precedingBlock(blockTag: string): string {
  const value = BigInt(blockTag);
  if (value <= 0n) throw new Error('probe_sc012_pinned_block_has_no_predecessor');
  return `0x${(value - 1n).toString(16)}`;
}

async function captureWrongSourceIdentityVariant(ctx: ProbeContext, startedAt: number): Promise<void> {
  const manifest = ctx.runtime.manifest;
  const readIdentity = async (phase: 'before' | 'after') => {
    const chain = await sourceRpc(ctx, {
      method: 'eth_chainId', params: [],
      label: `sc012-wrong-source-identity-${phase}-source-chain-id`,
      variantId: 'wrong_source_identity', shouldForward: true, startedAt,
    });
    const block = await sourceRpc(ctx, {
      method: 'eth_getBlockByNumber', params: [manifest.source.blockNumber, false],
      label: `sc012-wrong-source-identity-${phase}-source-pinned-block`,
      variantId: 'wrong_source_identity', shouldForward: true, startedAt,
    });
    const blockResult = requireObject(block.response.result, `wrong_source_identity_${phase}_block`);
    if (typeof chain.response.result !== 'string'
      || BigInt(chain.response.result) !== BigInt(manifest.source.chainId)
      || String(blockResult.number).toLowerCase() !== manifest.source.blockNumber.toLowerCase()
      || String(blockResult.hash).toLowerCase() !== manifest.source.blockHash.toLowerCase()) {
      throw new Error(`probe_sc012_wrong_source_identity_${phase}_observation_mismatch`);
    }
    return { chainId: chain.response.result, block: blockResult };
  };

  const before = await readIdentity('before');
  const candidateChainId = 1;
  if (BigInt(candidateChainId) === BigInt(manifest.source.chainId)) throw new Error('probe_sc012_wrong_source_candidate_not_mismatched');
  const rejection = await ctx.transport.request({
    boundary: 'private-admin-http',
    observationId: 'sc012-wrong-source-identity-candidate-validation',
    method: 'POST',
    url: apiPath(ctx.env.apiBaseUrl, `/internal/admin/environments/${ctx.env.envId}/prerequisite-validations`),
    headers: { 'X-BEF-Admin-Key': ctx.env.adminKey, 'content-type': 'application/json' },
    body: { variantId: 'wrong_chain', candidate: { chainId: candidateChainId } },
    operationId: null,
    variantId: 'wrong_source_identity',
  });
  if (rejection.status !== 200 || !isObject(rejection.body)) {
    throw new Error('probe_sc012_wrong_source_identity_candidate_validation_unavailable');
  }
  const body = rejection.body;
  const observations = requireObject(body.observations, 'wrong_source_identity_observations');
  const observedSource = requireObject(observations.source, 'wrong_source_identity_source');
  const observedChain = requireObject(observedSource.chainId, 'wrong_source_identity_source_chain');
  const observedBlock = requireObject(observedSource.block, 'wrong_source_identity_source_block');
  const observedBlockResult = requireObject(observedBlock.result, 'wrong_source_identity_source_block_result');
  if (body.boundary !== 'private-admin-prerequisite-validation'
    || body.envId !== ctx.env.envId
    || body.variantId !== 'wrong_chain'
    || body.accepted !== false
    || body.reasonCode !== 'source_chain_mismatch'
    || body.manifestSha256 !== ctx.runtime.manifestSha256
    || body.applicationSourceSha256 !== ctx.runtime.appSourceSha256
    || !isObject(body.candidate) || body.candidate.chainId !== candidateChainId
    || observedChain.method !== 'eth_chainId' || !Array.isArray(observedChain.params) || observedChain.params.length !== 0
    || String(observedChain.result).toLowerCase() !== String(before.chainId).toLowerCase()
    || observedBlock.method !== 'eth_getBlockByNumber'
    || String(observedBlockResult.number).toLowerCase() !== String(before.block.number).toLowerCase()
    || String(observedBlockResult.hash).toLowerCase() !== String(before.block.hash).toLowerCase()) {
    throw new Error('probe_sc012_wrong_source_identity_candidate_rejection_mismatch');
  }

  const wrongBlock = precedingBlock(ctx.runtime.manifest.source.blockNumber);
  await sourceRpc(ctx, {
    method: 'eth_getBlockByNumber', params: [wrongBlock, false],
    label: 'sc012-wrong-source-identity-wrong-block-denial', variantId: 'wrong_source_identity', shouldForward: false, startedAt,
  });
  const after = await readIdentity('after');
  if (String(before.chainId).toLowerCase() !== String(after.chainId).toLowerCase()
    || String(before.block.number).toLowerCase() !== String(after.block.number).toLowerCase()
    || String(before.block.hash).toLowerCase() !== String(after.block.hash).toLowerCase()) {
    throw new Error('probe_sc012_wrong_source_identity_actual_provider_changed');
  }
}

async function captureDeniedVariants(ctx: ProbeContext, startedAt: number): Promise<void> {
  await captureWrongSourceIdentityVariant(ctx, startedAt);
  for (const input of DENIED_ATTEMPTS) {
    await sourceRpc(ctx, {
      ...input,
      label: `sc012-${input.variantId}`,
      shouldForward: false,
      startedAt,
    });
  }
}

function pythonExecutable(root: string): string {
  const explicit = process.env.BEF_REPLAY_PYTHON;
  if (explicit) return explicit;
  const windowsPython = join(root, '.venv', 'Scripts', 'python.exe');
  const posixPython = join(root, '.venv', 'bin', 'python');
  return process.platform === 'win32' ? windowsPython : posixPython;
}

async function safelyRemoveTemporaryRoot(path: string, expectedPrefix: string, childMayBeLive: boolean): Promise<boolean> {
  if (childMayBeLive) return false;
  const canonicalTemp = await realpath(tmpdir()).catch(() => '');
  const target = resolve(path);
  if (!canonicalTemp || canonicalPathKey(dirname(target)) !== canonicalPathKey(canonicalTemp)
    || !basename(target).startsWith(expectedPrefix) || basename(target).length <= expectedPrefix.length
    || !isPathWithin(canonicalTemp, target)) {
    throw new Error('probe_sc012_temporary_directory_path_rejected');
  }
  const info = await lstat(target).catch(() => null);
  if (!info) return true;
  if (!info.isDirectory() || info.isSymbolicLink()) throw new Error('probe_sc012_temporary_directory_type_rejected');
  await assertNoSymlinkPath(canonicalTemp, target, 'probe_sc012_temporary_directory_symlink_rejected');
  const canonicalTarget = await realpath(target).catch(() => '');
  if (!canonicalTarget || canonicalPathKey(canonicalTarget) !== canonicalPathKey(target)
    || canonicalPathKey(dirname(canonicalTarget)) !== canonicalPathKey(canonicalTemp)) {
    throw new Error('probe_sc012_temporary_directory_not_canonical');
  }
  // Resolve and verify the final target immediately before the recursive delete.
  await rm(canonicalTarget, { recursive: true, force: true });
  return true;
}

async function runOfflineReplayer(
  root: string,
  evidenceDirectory: string,
  reportPath: string,
  onChildState: (mayBeLive: boolean) => void,
): Promise<{ exitCode: number; timedOut: boolean; processClosed: boolean }> {
  const python = pythonExecutable(root);
  try { await access(python, fsConstants.X_OK); } catch {
    if (process.platform === 'win32') {
      try { await access(python); } catch { throw new Error('probe_sc012_offline_replayer_python_unavailable'); }
    } else {
      throw new Error('probe_sc012_offline_replayer_python_unavailable');
    }
  }
  const script = join(root, 'tools', 'replay_bef_evidence.py');
  const args = [
    script,
    '--evidence-dir', evidenceDirectory,
    '--report', reportPath,
    '--source-profile',
    selectedReplaySourceProfile(),
  ];
  return await new Promise((resolvePromise, rejectPromise) => {
    let timedOut = false;
    let spawnFailed = false;
    let processClosed = false;
    let settled = false;
    let exitCode = -1;
    const child = spawn(python, args, { cwd: root, windowsHide: true, stdio: 'ignore', shell: false });
    onChildState(true);
    let timeout: ReturnType<typeof setTimeout>;
    let killGrace: ReturnType<typeof setTimeout> | undefined;
    let finalCloseGrace: ReturnType<typeof setTimeout> | undefined;
    const finish = (closed: boolean): void => {
      if (settled) return;
      settled = true;
      processClosed = closed;
      clearTimeout(timeout);
      if (killGrace) clearTimeout(killGrace);
      if (finalCloseGrace) clearTimeout(finalCloseGrace);
      onChildState(!closed);
      resolvePromise({ exitCode, timedOut, processClosed });
    };
    timeout = setTimeout(() => {
      timedOut = true;
      try { child.kill(); } catch { /* the bounded escalation below still runs */ }
      killGrace = setTimeout(() => {
        try { child.kill('SIGKILL'); } catch { /* retain temp if close is not observed */ }
        finalCloseGrace = setTimeout(() => {
          // Resolve after a bounded wait but leave the caller informed that the
          // process may still be live; the caller must retain its temp root.
          finish(false);
        }, REPLAY_FINAL_CLOSE_GRACE_MS);
      }, REPLAY_TERMINATION_GRACE_MS);
    }, SAFE_REPLAY_TIMEOUT_MS);
    child.once('error', () => {
      spawnFailed = true;
    });
    child.once('exit', (code) => {
      exitCode = code ?? -1;
    });
    child.once('close', () => {
      processClosed = true;
      onChildState(false);
      if (spawnFailed && !settled) {
        settled = true;
        clearTimeout(timeout);
        if (killGrace) clearTimeout(killGrace);
        if (finalCloseGrace) clearTimeout(finalCloseGrace);
        rejectPromise(new Error('probe_sc012_offline_replayer_unavailable'));
        return;
      }
      finish(true);
    });
  });
}

type ValidatedReplayCapture = {
  absolutePath: string;
  files: string[];
  index: JsonObject;
  indexSha256: string;
  scenarioId: string;
  envId: string;
  generationId: string;
  operationIds: string[];
  manifestPath: string;
  manifestSha256: string;
};

async function validatedReplayReportShell(
  root: string,
  evidenceDirectory: string,
  allowedEnvironmentIds: Set<string>,
  maxEvidenceBytes: number,
): Promise<ValidatedReplayCapture> {
  const tree = await canonicalReplayDirectory(root, evidenceDirectory, maxEvidenceBytes);
  const indexPath = join(tree.absolutePath, 'probe.json');
  const indexInfo = await lstat(indexPath).catch(() => null);
  if (!indexInfo || !indexInfo.isFile() || indexInfo.isSymbolicLink() || indexInfo.size > MAX_REPLAY_INDEX_BYTES) {
    throw new Error('probe_sc012_original_capture_index_invalid');
  }
  let indexBytes: Buffer;
  let index: JsonObject;
  try {
    indexBytes = await readFile(indexPath);
    index = requireObject(JSON.parse(indexBytes.toString('utf8')) as unknown, 'original_probe_index');
  } catch {
    throw new Error('probe_sc012_original_capture_unavailable');
  }
  const scenarioId = index.scenarioId;
  const envId = requireString(requireObject(index.environment, 'original_environment').envId, 'original_environment_id');
  const generation = requireObject(requireObject(index.environment, 'original_environment').generation, 'original_generation');
  const generationId = requireString(generation.generationId, 'original_generation_id');
  const manifestRef = requireObject(index.manifest, 'original_manifest');
  const manifestPath = requireString(manifestRef.path, 'original_manifest_path');
  const manifestSha256 = requireString(manifestRef.sha256, 'original_manifest_sha256').toLowerCase();
  const artifacts = index.artifacts;
  const rawOperations = index.operations;
  if (index.schemaVersion !== 'bef-runtime-probe/v1' || index.status !== 'captured'
    || (scenarioId !== 'BEF-SC-004' && scenarioId !== 'BEF-SC-005')
    || !allowedEnvironmentIds.has(envId) || !/^[0-9a-f]{64}$/.test(manifestSha256)
    || !Array.isArray(artifacts) || !artifacts.length || !Array.isArray(rawOperations) || !rawOperations.length) {
    throw new Error('probe_sc012_original_capture_invalid');
  }
  const operationIds = rawOperations.map((item) => isObject(item) ? item.operationId : null);
  if (operationIds.some((item) => typeof item !== 'string' || !item)
    || new Set(operationIds as string[]).size !== operationIds.length) {
    throw new Error('probe_sc012_original_operation_inventory_invalid');
  }
  const indexedFiles = new Set<string>(['probe.json']);
  let manifestFound = false;
  for (const artifact of artifacts) {
    if (!isObject(artifact) || typeof artifact.path !== 'string' || !artifact.path
      || isAbsolute(artifact.path) || artifact.path.split(/[\\/]/).some((part) => part === '..' || part === '')
      || typeof artifact.sha256 !== 'string' || !/^[0-9a-f]{64}$/i.test(artifact.sha256)
      || typeof artifact.boundary !== 'string' || !artifact.boundary
      || typeof artifact.contentType !== 'string' || !artifact.contentType.toLowerCase().includes('json')) {
      throw new Error('probe_sc012_original_artifact_inventory_invalid');
    }
    const normalized = artifact.path.replaceAll('\\', '/');
    if (indexedFiles.has(normalized)) throw new Error('probe_sc012_original_artifact_inventory_duplicate');
    indexedFiles.add(normalized);
    const artifactPath = resolve(tree.absolutePath, artifact.path);
    if (!isPathWithin(tree.absolutePath, artifactPath)) throw new Error('probe_sc012_original_artifact_path_invalid');
    await assertNoSymlinkPath(tree.absolutePath, artifactPath, 'probe_sc012_original_artifact_symlink_rejected');
    const info = await lstat(artifactPath).catch(() => null);
    if (!info || !info.isFile() || info.isSymbolicLink() || info.size > maxEvidenceBytes) {
      throw new Error('probe_sc012_original_artifact_file_invalid');
    }
    const bytes = await readFile(artifactPath);
    if (createHash('sha256').update(bytes).digest('hex') !== artifact.sha256.toLowerCase()) {
      throw new Error('probe_sc012_original_artifact_hash_mismatch');
    }
    if (normalized === manifestPath.replaceAll('\\', '/')) manifestFound = artifact.boundary === 'runtime-manifest'
      && createHash('sha256').update(bytes).digest('hex') === manifestSha256;
  }
  const treeFiles = new Set(tree.files.map((path) => relative(tree.absolutePath, path).replaceAll('\\', '/')));
  if (treeFiles.size !== indexedFiles.size || [...indexedFiles].some((path) => !treeFiles.has(path)) || !manifestFound) {
    throw new Error('probe_sc012_original_capture_inventory_unbound');
  }
  const environment = requireObject(index.environment, 'original_environment');
  if (!isObject(environment.generation) || !isObject(index.sourceBlock)
    || !/^[0-9a-f]{64}$/i.test(String(index.applicationSourceSha256 ?? ''))
    || !/^[0-9a-f]{64}$/i.test(String(index.probeSourceSha256 ?? ''))) {
    throw new Error('probe_sc012_original_traceability_missing');
  }
  return {
    absolutePath: tree.absolutePath,
    files: tree.files,
    index,
    indexSha256: createHash('sha256').update(indexBytes).digest('hex'),
    scenarioId,
    envId,
    generationId,
    operationIds: operationIds as string[],
    manifestPath: manifestPath.replaceAll('\\', '/'),
    manifestSha256,
  };
}

function pathAsPosix(root: string, target: string): string {
  return relative(root, target).replaceAll('\\', '/');
}

async function verifyReplayReportReferences(
  root: string,
  capture: ValidatedReplayCapture,
  report: JsonObject,
): Promise<void> {
  const original = requireObject(report.original, 'replay_original');
  const replay = requireObject(report.replay, 'replay_details');
  const replayChecks = isObject(replay.checks) ? replay.checks : null;
  const evidenceRoot = requireObject(original.evidenceRoot, 'replay_evidence_root');
  const expectedRoot = pathAsPosix(root, capture.absolutePath);
  const artifacts = capture.index.artifacts as JsonObject[];
  const originalArtifacts = original.artifacts;
  const sourceProfile = selectedReplaySourceProfile();
  const expectedVersionedProfile = REPLAY_SOURCE_PROFILE_VERSIONS[sourceProfile];
  const versionedSourceProfile = replay.sourceProfile === undefined
    ? 'active-delta/v1'
    : requireString(replay.sourceProfile, 'replay_source_profile');
  const expectedContractChange = sourceProfile === 'active-delta'
    ? 'benchmark-environment-feasibility'
    : 'synchronized-main';
  const expectedArtifacts = artifacts.map((entry) => ({ path: String(entry.path).replaceAll('\\', '/'), sha256: entry.sha256, boundary: entry.boundary }));
  if (report.schemaVersion !== 'bef-evidence-replay/v1' || report.evaluatedScenarioId !== capture.scenarioId
    || report.replayStatus !== 'matched' || report.gateStatus !== 'not_established_by_replay'
    || original.scenarioId !== capture.scenarioId || original.status !== 'captured'
    || evidenceRoot.kind !== 'repository_relative' || evidenceRoot.path !== expectedRoot
    || original.externalResolutionRequired !== false || original.probeIndexPath !== 'probe.json'
    || original.probeIndexSha256 !== capture.indexSha256 || original.manifestPath !== capture.manifestPath
    || original.manifestSha256 !== capture.manifestSha256
    || original.applicationSourceSha256 !== capture.index.applicationSourceSha256
    || original.probeSourceSha256 !== capture.index.probeSourceSha256
    || stableJson(original.sourceBlock) !== stableJson(capture.index.sourceBlock)
    || original.environmentId !== capture.envId || original.generationId !== capture.generationId
    || JSON.stringify(original.operationIds) !== JSON.stringify(capture.operationIds)
    || stableJson(originalArtifacts) !== stableJson(expectedArtifacts)) {
    throw new Error('probe_sc012_offline_replay_original_binding_mismatch');
  }
  if (versionedSourceProfile !== expectedVersionedProfile
    || replay.contractChange !== expectedContractChange
    || replay.contractScenarioId !== capture.scenarioId
    || replay.checksMatchContract !== true || replay.predicateCompleted !== true
    || replay.predicateErrorType !== null || !Array.isArray(replay.missingChecks) || replay.missingChecks.length !== 0
    || !Array.isArray(replay.requiredChecks) || !replayChecks
    || replay.requiredChecks.length === 0
    || replay.requiredChecks.some((name) => typeof name !== 'string' || replayChecks[name] !== true)) {
    throw new Error('probe_sc012_offline_replay_predicate_mismatch');
  }
  const approvedSources = requireObject(replay.approvedSources, 'replay_approved_sources');
  const expectedSourceNames = sourceProfile === 'active-delta'
    ? ['proposal', 'harnessContract', 'normativeSpec', 'predicateSource']
    : ['harnessContract', 'normativeSpec', 'predicateSource'];
  if (Object.keys(approvedSources).sort().join(',') !== [...expectedSourceNames].sort().join(',')) {
    throw new Error('probe_sc012_offline_replay_source_profile_mixed');
  }
  const sourceExpectations: Record<string, { path: string; maxPrefix?: string }> = sourceProfile === 'active-delta'
    ? {
      proposal: { path: 'openspec/changes/benchmark-environment-feasibility/bdd-harness-proposal.json' },
      harnessContract: { path: 'tests/bdd/changes/benchmark-environment-feasibility/harness-contracts.json' },
      normativeSpec: { path: '', maxPrefix: 'openspec/changes/benchmark-environment-feasibility/' },
      predicateSource: { path: 'tests/bdd/adapters/benchmark_environment_feasibility.py' },
    }
    : {
      harnessContract: { path: 'tests/bdd/harness-contracts.json' },
      normativeSpec: { path: 'openspec/specs/benchmark-environment-feasibility/spec.md' },
      predicateSource: { path: 'tests/bdd/adapters/benchmark_environment_feasibility.py' },
    };
  for (const [name, expectation] of Object.entries(sourceExpectations)) {
    const source = requireObject(approvedSources[name], `replay_source_${name}`);
    const path = requireString(source.path, `replay_source_path_${name}`).replaceAll('\\', '/');
    const digest = requireString(source.sha256, `replay_source_hash_${name}`).toLowerCase();
    if ((expectation.path && path !== expectation.path)
      || (expectation.maxPrefix && (!path.startsWith(expectation.maxPrefix) || path.includes('..')))
      || !/^[0-9a-f]{64}$/.test(digest)) {
      throw new Error('probe_sc012_offline_replay_source_reference_invalid');
    }
    const sourcePath = resolve(root, path);
    if (!isPathWithin(resolve(root), sourcePath)) throw new Error('probe_sc012_offline_replay_source_path_invalid');
    await assertNoSymlinkPath(resolve(root), sourcePath, 'probe_sc012_offline_replay_source_path_invalid');
    const sourceBytes = await readFile(sourcePath).catch(() => null);
    if (!sourceBytes || createHash('sha256').update(sourceBytes).digest('hex') !== digest) {
      throw new Error('probe_sc012_offline_replay_source_hash_mismatch');
    }
  }
  const replayerPath = requireString(replay.replayerSourcePath, 'replay_source_path').replaceAll('\\', '/');
  const replayerHash = requireString(replay.replayerSourceSha256, 'replay_source_hash').toLowerCase();
  if (replayerPath !== 'tools/replay_bef_evidence.py' || !/^[0-9a-f]{64}$/.test(replayerHash)) {
    throw new Error('probe_sc012_offline_replayer_source_invalid');
  }
  const replayerSourcePath = resolve(root, replayerPath);
  await assertNoSymlinkPath(resolve(root), replayerSourcePath, 'probe_sc012_offline_replayer_source_invalid');
  const replayerBytes = await readFile(replayerSourcePath).catch(() => null);
  if (!replayerBytes || createHash('sha256').update(replayerBytes).digest('hex') !== replayerHash) {
    throw new Error('probe_sc012_offline_replayer_source_hash_mismatch');
  }
  const execution = requireObject(replay.execution, 'replay_execution_counters');
  if (execution.mode !== 'offline_recorded_observations'
    || ['httpRequests', 'rpcCalls', 'databaseQueries', 'broadcasts', 'newTrials'].some((key) => execution[key] !== 0)) {
    throw new Error('probe_sc012_offline_replay_execution_record_invalid');
  }
}

async function validatedReplayReport(root: string, evidenceDirectory: string, allowedEnvironmentIds: Set<string>, maxEvidenceBytes: number): Promise<JsonObject> {
  const capture = await validatedReplayReportShell(root, evidenceDirectory, allowedEnvironmentIds, maxEvidenceBytes);
  const temporaryRoot = await mkdtemp(join(tmpdir(), 'bef-sc012-replay-'));
  const reportPath = join(temporaryRoot, 'replay-report.json');
  let childMayBeLive = false;
  try {
    const result = await runOfflineReplayer(root, capture.absolutePath, reportPath, (value) => { childMayBeLive = value; });
    if (!result.processClosed) throw new Error('probe_sc012_offline_replay_process_close_unconfirmed');
    let report: JsonObject;
    try {
      const info = await lstat(reportPath);
      if (!info.isFile() || info.isSymbolicLink() || info.size > 16_777_216) throw new Error();
      report = requireObject(JSON.parse((await readFile(reportPath)).toString('utf8')) as unknown, 'replay_report');
    }
    catch {
      if (result.timedOut) throw new Error('probe_sc012_offline_replay_timeout');
      if (result.exitCode === 2) throw new Error('probe_sc012_offline_replay_blocked');
      throw new Error('probe_sc012_offline_replay_rejected_original');
    }
    await verifyReplayReportReferences(root, capture, report);
    if (result.timedOut || result.exitCode !== 0) {
      throw new Error('probe_sc012_offline_replay_failed');
    }
    return report;
  } finally {
    // Never remove the directory while the bounded shutdown could not confirm
    // process close; retain it for safe later inspection instead.
    await safelyRemoveTemporaryRoot(temporaryRoot, 'bef-sc012-replay-', childMayBeLive);
  }
}

function flattenedRows(snapshot: Record<string, Array<Record<string, unknown>>>): Array<{ table: string; row: Record<string, unknown> }> {
  return Object.entries(snapshot).flatMap(([table, rows]) => rows.map((row) => ({ table, row })));
}

async function originalPaymentRecipients(
  ctx: ProbeContext,
  evidenceDirectory: string,
  report: JsonObject,
): Promise<Map<string, string>> {
  const original = requireObject(report.original, 'replay_original');
  const capture = await validatedReplayReportShell(
    ctx.runtime.root,
    evidenceDirectory,
    new Set(ctx.runtime.manifest.local.environments.map((entry) => entry.id)),
    ctx.runtime.manifest.guardrails.maxEvidenceBytesPerTrial,
  );
  if (capture.indexSha256 !== original.probeIndexSha256
    || capture.scenarioId !== original.scenarioId
    || capture.envId !== original.environmentId
    || JSON.stringify(capture.operationIds) !== JSON.stringify(original.operationIds)) {
    throw new Error('probe_sc012_payment_recipient_original_binding_mismatch');
  }
  const operationIds = new Set(capture.operationIds);
  const payToByOperation = new Map<string, string>();
  const indexedArtifacts = capture.index.artifacts;
  if (!Array.isArray(indexedArtifacts)) throw new Error('probe_sc012_original_artifacts_missing');
  for (const value of indexedArtifacts) {
    if (!isObject(value) || value.boundary !== 'actual-tool-http' || typeof value.path !== 'string') continue;
    const artifactPath = resolve(capture.absolutePath, value.path);
    if (!isPathWithin(capture.absolutePath, artifactPath)) throw new Error('probe_sc012_original_artifact_path_invalid');
    const artifact = requireObject(JSON.parse((await readFile(artifactPath)).toString('utf8')) as unknown, 'original_http_artifact');
    const operationId = artifact.operationId;
    const response = isObject(artifact.response) ? artifact.response : null;
    if (!response || response.status !== 402) continue;
    if (typeof operationId !== 'string' || !operationIds.has(operationId)) {
      throw new Error('probe_sc012_original_http_operation_unbound');
    }
    if (artifact.schemaVersion !== 'bef-http-observation/v1' || artifact.boundary !== 'actual-tool-http'
      || !isObject(response.headers)) throw new Error('probe_sc012_original_http_challenge_invalid');
    const responseOperationId = Object.entries(response.headers).find(([name]) => name.toLowerCase() === 'x-bef-operation-id')?.[1];
    if (responseOperationId !== operationId) throw new Error('probe_sc012_original_http_operation_unbound');
    const encoded = Object.entries(response.headers).find(([name]) => name.toLowerCase() === 'payment-required')?.[1];
    if (typeof encoded !== 'string' || encoded.length > 1_048_576 || !/^[A-Za-z0-9+/]*={0,2}$/.test(encoded)) {
      throw new Error('probe_sc012_original_payment_required_missing');
    }
    let declaration: JsonObject;
    try {
      const decodedBytes = Buffer.from(encoded, 'base64');
      if (decodedBytes.toString('base64').replace(/=+$/, '') !== encoded.replace(/=+$/, '')) {
        throw new Error('invalid_base64');
      }
      declaration = requireObject(JSON.parse(decodedBytes.toString('utf8')) as unknown, 'original_payment_required');
    } catch {
      throw new Error('probe_sc012_original_payment_required_invalid');
    }
    const accepts = declaration.accepts;
    if (declaration.x402Version !== 2 || !Array.isArray(accepts) || accepts.length !== 1 || !isObject(accepts[0])) {
      throw new Error('probe_sc012_original_payment_requirements_invalid');
    }
    const accepted = accepts[0];
    const payTo = accepted.payTo;
    if (accepted.scheme !== ctx.runtime.manifest.x402.scheme
      || accepted.network !== ctx.runtime.manifest.x402.network
      || typeof accepted.asset !== 'string' || accepted.asset.toLowerCase() !== ctx.runtime.manifest.x402.asset.toLowerCase()
      || accepted.amount !== ctx.runtime.manifest.x402.amount
      || typeof payTo !== 'string' || !/^0x[0-9a-f]{40}$/i.test(payTo)) {
      throw new Error('probe_sc012_original_payment_requirement_not_pinned');
    }
    const prior = payToByOperation.get(operationId);
    if (prior && prior.toLowerCase() !== payTo.toLowerCase()) {
      throw new Error('probe_sc012_original_operation_payto_changed');
    }
    payToByOperation.set(operationId, payTo.toLowerCase());
  }
  if (payToByOperation.size === 0) throw new Error('probe_sc012_original_payment_recipient_missing');
  return payToByOperation;
}

async function captureReplayDbState(
  ctx: ProbeContext,
  report: JsonObject,
  payToByOperation: Map<string, string>,
  phase: 'before' | 'after',
): Promise<{
  envId: string;
  generationIds: string[];
  payerAddress: string | null;
  expectedOperationIds: string[];
  observedOperationIds: string[];
  addresses: string[];
  generations: Array<{ generationId: string; operationIds: string[]; addresses: string[] }>;
  rows: Array<{ table: string; row: Record<string, unknown> }>;
}> {
  const original = requireObject(report.original, 'replay_original');
  const replayedOriginalCapture = replayedOriginalCaptureReference(original);
  const envId = requireString(original.environmentId, 'replay_environment_id');
  const rawOperationIds = original.operationIds;
  if (!Array.isArray(rawOperationIds) || rawOperationIds.some((item) => typeof item !== 'string' || !item)) {
    throw new Error('probe_sc012_replay_operation_ids_invalid');
  }
  const expectedOperationIds = [...rawOperationIds] as string[];
  const addresses = new Set<string>();
  const generationAddresses = new Map<string, string[]>();
  const observedOperationIds: string[] = [];
  const rows: Array<{ table: string; row: Record<string, unknown> }> = [];
  const generations = new Map<string, string[]>();
  const bindings = await ctx.database.originalOperationGenerationBindings({
    envId,
    operationIds: expectedOperationIds,
    label: `sc012-${String(original.scenarioId).toLowerCase()}-${phase}`,
    replayPhase: phase,
    replayedOriginalCapture,
  });
  for (const binding of bindings) {
    if (binding.env_id !== envId || !expectedOperationIds.includes(binding.operation_id)
      || typeof binding.generation_id !== 'string' || !binding.generation_id) continue;
    const operationIds = generations.get(binding.generation_id) ?? [];
    operationIds.push(binding.operation_id);
    generations.set(binding.generation_id, operationIds);
  }
  for (const [snapshotGenerationId, generationOperationIds] of [...generations.entries()].sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0)) {
    const snapshot = await ctx.database.snapshot({
      envId,
      generationId: snapshotGenerationId,
      variantId: null,
      label: `sc012-${String(original.scenarioId).toLowerCase()}-${phase}-${snapshotGenerationId.slice(0, 8)}-state`,
      observationScope: 'generation',
      observationOperationId: null,
      generationOperationIds: [...generationOperationIds].sort(),
      replayPhase: phase,
      replayedOriginalCapture,
    });
    observedOperationIds.push(...snapshot.operations.map((row) => String(row.operation_id)));
    rows.push(...flattenedRows(snapshot));
    const generation = snapshot.generation.find((row) => String(row.generation_id) === snapshotGenerationId);
    const generationAddressSet = new Set<string>();
    if (typeof generation?.payer_address === 'string') generationAddressSet.add(generation.payer_address.toLowerCase());
    for (const payment of snapshot.payments) {
      for (const name of ['payer_address', 'facilitator_address']) {
        const value = payment[name];
        if (typeof value === 'string' && /^0x[0-9a-f]{40}$/i.test(value)) generationAddressSet.add(value.toLowerCase());
      }
    }
    for (const operationId of generationOperationIds) {
      const payTo = payToByOperation.get(operationId);
      if (typeof payTo === 'string' && /^0x[0-9a-f]{40}$/i.test(payTo)) generationAddressSet.add(payTo.toLowerCase());
    }
    const generationAddressList = [...generationAddressSet].sort();
    generationAddresses.set(snapshotGenerationId, generationAddressList);
    for (const address of generationAddressList) addresses.add(address);
  }
  const generationIds = [...generations.keys()].sort();
  const payerAddress = rows.find((item) => item.table === 'generation'
    && typeof item.row.payer_address === 'string')?.row.payer_address;
  const payer = typeof payerAddress === 'string' ? payerAddress : null;
  const safeRows = sanitizeValue(rows, ctx.secretValues) as Array<{ table: string; row: Record<string, unknown> }>;
  return {
    envId,
    generationIds,
    payerAddress: payer,
    expectedOperationIds,
    observedOperationIds,
    addresses: [...addresses].sort(),
    generations: generationIds.map((id) => ({
      generationId: id,
      operationIds: [...(generations.get(id) ?? [])].sort(),
      addresses: generationAddresses.get(id) ?? [],
    })),
    rows: safeRows,
  };
}

function replayedOriginalCaptureReference(original: JsonObject): ReplayedOriginalCaptureReference {
  const evidenceRoot = requireObject(original.evidenceRoot, 'replay_evidence_root');
  const rawOperationIds = original.operationIds;
  if ((original.scenarioId !== 'BEF-SC-004' && original.scenarioId !== 'BEF-SC-005')
    || evidenceRoot.kind !== 'repository_relative'
    || typeof evidenceRoot.path !== 'string'
    || original.probeIndexPath !== 'probe.json'
    || typeof original.probeIndexSha256 !== 'string'
    || !/^[0-9a-f]{64}$/i.test(original.probeIndexSha256)
    || typeof original.environmentId !== 'string'
    || typeof original.generationId !== 'string'
    || !Array.isArray(rawOperationIds)
    || rawOperationIds.some((item) => typeof item !== 'string'
      || !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(item))
    || new Set(rawOperationIds).size !== rawOperationIds.length) {
    throw new Error('probe_sc012_replayed_operation_reference_invalid');
  }
  return {
    provenance: 'replayed-original',
    scenarioId: original.scenarioId,
    evidenceRoot: { kind: 'repository_relative', path: evidenceRoot.path },
    probeIndexPath: 'probe.json',
    probeIndexSha256: original.probeIndexSha256.toLowerCase(),
    environmentId: original.environmentId,
    generationId: original.generationId,
    operationIds: [...rawOperationIds] as string[],
  };
}

function envLocalRpcUrl(envId: string, ctx: ProbeContext): string {
  if (envId === ctx.env.envId) return ctx.env.localRpcUrl;
  const suffix = envId.toUpperCase().replaceAll('-', '_');
  const name = `BEF_LOCAL_RPC_PROXY_URL_${suffix}`;
  const raw = process.env[name];
  if (!raw) throw new Error('probe_sc012_original_local_rpc_unavailable');
  try {
    const url = new URL(raw);
    const host = url.hostname.replace(/^\[|\]$/g, '').toLowerCase();
    if (url.protocol !== 'http:' || url.username || url.password || url.pathname !== '/' || url.search || url.hash
      || !['localhost', '127.0.0.1', '::1'].includes(host)) throw new Error();
    return url.toString().replace(/\/$/, '');
  } catch {
    throw new Error('probe_sc012_original_local_rpc_invalid');
  }
}

async function localStateRpc(ctx: ProbeContext, input: {
  url: string;
  envId: string;
  generationId: string;
  operationIds: string[];
  endpointIdentityArtifact: string;
  endpointRef: { scheme: string; host: string; port: number };
  address: string;
  method: 'eth_getBalance' | 'eth_getTransactionCount' | 'eth_call';
  params: unknown[];
  phase: 'before' | 'after';
  replayOfProbeIndexSha256: string;
  startedAt: number;
}): Promise<unknown> {
  if (Date.now() >= nextDeadline(ctx, input.startedAt)) throw new Error('probe_trial_guardrail_deadline_exceeded');
  const id = `bef-sc012-local-${randomUUID()}`;
  const body = { jsonrpc: '2.0', id, method: input.method, params: input.params };
  const rawRequest = JSON.stringify(body);
  let response;
  let rawResponse: Buffer;
  try {
    response = await probeFetch(input.url, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: rawRequest,
      redirect: 'error',
      signal: AbortSignal.timeout(Math.min(10_000, Math.max(1, nextDeadline(ctx, input.startedAt) - Date.now()))),
    });
    rawResponse = await readBoundedResponse(response as unknown as StreamingProbeResponse, 4_194_304, 'probe_sc012_local_response_too_large');
  } catch {
    throw new Error('probe_sc012_local_state_rpc_unavailable');
  }
  let envelope: JsonRpcResponse;
  try { envelope = requireObject(JSON.parse(rawResponse.toString('utf8')) as unknown, 'local_rpc_response') as JsonRpcResponse; }
  catch { throw new Error('probe_sc012_local_state_rpc_invalid'); }
  const rawResponseText = rawResponse.toString('utf8');
  if (ctx.secretValues.some((secret) => secret.length > 0 && rawResponseText.includes(secret))) {
    throw new Error('probe_sc012_local_state_rpc_secret_response');
  }
  const hasError = isObject(envelope.error);
  const result = hasError ? { error: { code: envelope.error?.code ?? null, message: envelope.error?.message ?? 'rpc_error' } } : envelope.result;
  const replayedOriginalCapture = ctx.replayedOriginalCaptures.find(
    (item) => item.probeIndexSha256 === input.replayOfProbeIndexSha256,
  );
  if (!replayedOriginalCapture
    || replayedOriginalCapture.environmentId !== input.envId
    || input.operationIds.length === 0
    || input.operationIds.some((operationId) => !replayedOriginalCapture.operationIds.includes(operationId))) {
    throw new Error('probe_sc012_local_state_original_reference_missing');
  }
  await ctx.evidence.writeObservation(
    `replay/${input.envId}-${input.generationId.slice(0, 8)}-${input.phase}-${input.method}-${input.address.slice(2, 10)}-${randomUUID()}.json`,
    `sc012-replay-${input.envId}-${input.generationId.slice(0, 8)}-${input.phase}-${input.method}-${input.address.slice(2, 10)}`,
    {
      schemaVersion: 'bef-rpc-observation/v1',
      boundary: 'local-chain-readonly-proxy',
      operationId: null,
      variantId: null,
      endpointBoundary: 'local-chain-readonly-proxy',
      envId: input.envId,
      environmentId: input.envId,
      generationId: input.generationId,
      operationIds: input.operationIds,
      replayedOriginalCapture,
      endpointIdentityArtifact: input.endpointIdentityArtifact,
      endpointRef: input.endpointRef,
      replayOfProbeIndexSha256: input.replayOfProbeIndexSha256,
      phase: input.phase,
      account: input.address.toLowerCase(),
      method: input.method,
      requestId: id,
      requestBody: body,
      params: sanitizeValue(input.params, ctx.secretValues),
      requestedBlock: 'latest',
      requestBytes: Buffer.byteLength(rawRequest, 'utf8'),
      responseStatus: response.status,
      responseBytes: rawResponse.byteLength,
      responseBodySha256: createHash('sha256').update(rawResponse).digest('hex'),
      responseBodyBase64: rawResponse.toString('base64'),
      responseCorrelated: envelope.jsonrpc === '2.0' && envelope.id === id,
      result: sanitizeValue(result, ctx.secretValues),
      forwarded: response.ok && !hasError,
    },
  );
  if (!response.ok || hasError || envelope.id !== id || envelope.jsonrpc !== '2.0' || envelope.result === undefined) {
    throw new Error('probe_sc012_local_state_rpc_failed');
  }
  return envelope.result;
}

async function captureReplayChainState(ctx: ProbeContext, dbState: Awaited<ReturnType<typeof captureReplayDbState>>, report: JsonObject, phase: 'before' | 'after', startedAt: number): Promise<Record<string, unknown>> {
  const url = envLocalRpcUrl(dbState.envId, ctx);
  const original = requireObject(report.original, 'replay_original');
  const replayedOriginalCapture = ctx.replayedOriginalCaptures.find(
    (item) => item.probeIndexSha256 === original.probeIndexSha256,
  );
  if (!replayedOriginalCapture
    || replayedOriginalCapture.environmentId !== dbState.envId
    || dbState.expectedOperationIds.some((operationId) => !replayedOriginalCapture.operationIds.includes(operationId))) {
    throw new Error('probe_sc012_local_state_original_reference_missing');
  }
  const endpointBinding = await ctx.rpc.bindLocalEndpoint({
    url,
    environmentId: dbState.envId,
    manifestSha256: ctx.runtime.manifestSha256,
    label: `sc012-${String(original.scenarioId).toLowerCase()}-${phase}-local-endpoint-binding`,
  });
  const block = 'latest';
  const usdc = ctx.runtime.manifest.contracts.usdc.address;
  const state: Record<string, unknown> = {};
  for (const generation of dbState.generations) {
    for (const address of generation.addresses) {
      const checks: Array<{ method: 'eth_getBalance' | 'eth_getTransactionCount' | 'eth_call'; params: unknown[]; suffix: string }> = [
        { method: 'eth_getBalance', params: [address, block], suffix: 'native-balance' },
        { method: 'eth_getTransactionCount', params: [address, block], suffix: 'nonce' },
        {
          method: 'eth_call',
          params: [{ to: usdc, data: encodeFunctionData({ abi: ERC20_BALANCE_OF_ABI, functionName: 'balanceOf', args: [address as `0x${string}`] }) }, block],
          suffix: 'usdc-balance',
        },
      ];
      for (const check of checks) {
        const result = await localStateRpc(ctx, {
          url,
          envId: dbState.envId,
          generationId: generation.generationId,
          operationIds: generation.operationIds,
          endpointIdentityArtifact: endpointBinding.identityArtifact,
          endpointRef: endpointBinding.endpointRef,
          address,
          method: check.method,
          params: check.params,
          phase,
          replayOfProbeIndexSha256: String(original.probeIndexSha256),
          startedAt,
        });
        const stateKey = `${generation.generationId}:${check.suffix}:${address.toLowerCase()}`;
        state[stateKey] = result;
        // The result is repeated here to make each compare key explicit. The raw
        // RPC observation above is still the primary evidence.
        await writeCustomObservation(
          ctx,
          `replay/${dbState.envId}-${generation.generationId.slice(0, 8)}-${phase}-${address.slice(2, 10)}-${check.suffix}.json`,
          `sc012-replay-${dbState.envId}-${generation.generationId.slice(0, 8)}-${phase}-${address.slice(2, 10)}-${check.suffix}`,
          'replay-local-state',
          {
            schemaVersion: 'bef-local-state-observation/v1',
            operationId: null,
            variantId: null,
            envId: dbState.envId,
            environmentId: dbState.envId,
            generationId: generation.generationId,
            operationIds: generation.operationIds,
            replayedOriginalCapture,
            endpointIdentityArtifact: endpointBinding.identityArtifact,
            endpointRef: endpointBinding.endpointRef,
            replayOfProbeIndexSha256: original.probeIndexSha256,
            phase,
            account: address,
            stateName: check.suffix,
            stateValue: result,
          },
        );
      }
    }
  }
  return state;
}

function publicReplayDetails(report: JsonObject): JsonObject {
  const replay = requireObject(report.replay, 'replay_details');
  const checks = requireObject(replay.checks, 'replay_checks');
  const requiredChecks = replay.requiredChecks;
  if (!Array.isArray(requiredChecks) || requiredChecks.length === 0
    || requiredChecks.some((name) => typeof name !== 'string' || !name)
    || new Set(requiredChecks).size !== requiredChecks.length) {
    throw new Error('probe_sc012_replay_check_inventory_invalid');
  }
  const checkResults = requiredChecks.map((name) => {
    const result = checks[name as string];
    if (typeof result !== 'boolean') throw new Error('probe_sc012_replay_check_result_invalid');
    return { name, passed: result };
  });
  const { checks: _checks, ...publicReplay } = replay;
  return { ...publicReplay, checkResults };
}

function replayReportIdentity(report: JsonObject): JsonObject {
  return {
    schemaVersion: report.schemaVersion,
    evaluatedScenarioId: report.evaluatedScenarioId,
    replayStatus: report.replayStatus,
    gateStatus: report.gateStatus,
    original: report.original,
    replay: publicReplayDetails(report),
  };
}

function replayArtifactReferences(artifacts: Array<{ path: string; sha256: string; contentType: string; boundary: string }>): Array<{
  path: string;
  sha256: string;
  boundary: string;
}> {
  return artifacts.map(({ path, sha256, boundary }) => ({ path, sha256, boundary }));
}

async function captureAndRunReplay(ctx: ProbeContext, evidenceDirectory: string, startedAt: number): Promise<JsonObject> {
  const root = ctx.runtime.root;
  // Validate the requested file set and current predicate identity before
  // taking snapshots. The replay whose effects are checked runs later between
  // the two independent DB/RPC snapshots.
  const preflightReport = await validatedReplayReport(
    root,
    evidenceDirectory,
    new Set(ctx.runtime.manifest.local.environments.map((entry) => entry.id)),
    ctx.runtime.manifest.guardrails.maxEvidenceBytesPerTrial,
  );
  const original = requireObject(preflightReport.original, 'replay_original');
  const replayedOriginalCapture = replayedOriginalCaptureReference(original);
  if (ctx.replayedOriginalCaptures.some((item) => item.scenarioId === replayedOriginalCapture.scenarioId)) {
    throw new Error('probe_sc012_replayed_capture_duplicate');
  }
  ctx.replayedOriginalCaptures.push(replayedOriginalCapture);
  const payToByOperation = await originalPaymentRecipients(ctx, evidenceDirectory, preflightReport);
  const beforeDatabaseStart = ctx.evidence.artifacts.length;
  const before = await captureReplayDbState(ctx, preflightReport, payToByOperation, 'before');
  const beforeDatabaseArtifacts = replayArtifactReferences(ctx.evidence.artifacts.slice(beforeDatabaseStart));
  const beforeLocalRpcStart = ctx.evidence.artifacts.length;
  const beforeChain = await captureReplayChainState(ctx, before, preflightReport, 'before', startedAt);
  const beforeLocalRpcArtifacts = replayArtifactReferences(ctx.evidence.artifacts.slice(beforeLocalRpcStart));

  const report = await validatedReplayReport(
    root,
    evidenceDirectory,
    new Set(ctx.runtime.manifest.local.environments.map((entry) => entry.id)),
    ctx.runtime.manifest.guardrails.maxEvidenceBytesPerTrial,
  );
  if (stableJson(replayReportIdentity(preflightReport)) !== stableJson(replayReportIdentity(report))) {
    throw new Error('probe_sc012_bracketed_replay_identity_changed');
  }
  const replayIdentity = replayReportIdentity(report);
  const replayIdentitySha256 = createHash('sha256').update(stableJson(replayIdentity)).digest('hex');

  const afterDatabaseStart = ctx.evidence.artifacts.length;
  const after = await captureReplayDbState(ctx, report, payToByOperation, 'after');
  const afterDatabaseArtifacts = replayArtifactReferences(ctx.evidence.artifacts.slice(afterDatabaseStart));
  const afterLocalRpcStart = ctx.evidence.artifacts.length;
  const afterChain = await captureReplayChainState(ctx, after, report, 'after', startedAt);
  const afterLocalRpcArtifacts = replayArtifactReferences(ctx.evidence.artifacts.slice(afterLocalRpcStart));
  const bracketEvents = [
    { ordinal: 1, kind: 'before_database_snapshot', artifacts: beforeDatabaseArtifacts },
    { ordinal: 2, kind: 'before_local_rpc_snapshot', artifacts: beforeLocalRpcArtifacts },
    {
      ordinal: 3,
      kind: 'offline_evidence_replay',
      scenarioId: report.evaluatedScenarioId,
      originalProbeIndexSha256: original.probeIndexSha256,
      replayIdentitySha256,
    },
    { ordinal: 4, kind: 'after_database_snapshot', artifacts: afterDatabaseArtifacts },
    { ordinal: 5, kind: 'after_local_rpc_snapshot', artifacts: afterLocalRpcArtifacts },
  ];
  const reportArtifact = {
    schemaVersion: 'bef-evidence-replay-observation/v1',
    boundary: 'recorded-evidence-replay',
    operationId: null,
    variantId: null,
    evaluatedScenarioId: report.evaluatedScenarioId,
    replayStatus: report.replayStatus,
    gateStatus: report.gateStatus,
    original,
    replay: publicReplayDetails(report),
    replayBracket: {
      sequence: bracketEvents.map((event) => event.kind),
      preflightIdentitySha256: replayIdentitySha256,
      replayIdentitySha256,
      events: bracketEvents,
    },
    stateComparison: {
      databaseRowsEqual: JSON.stringify(before.rows) === JSON.stringify(after.rows),
      databaseOperationIdsMatch: JSON.stringify([...before.expectedOperationIds].sort()) === JSON.stringify([...before.observedOperationIds].sort())
        && JSON.stringify([...after.expectedOperationIds].sort()) === JSON.stringify([...after.observedOperationIds].sort()),
      databaseGenerationBindingsEqual: JSON.stringify(before.generations) === JSON.stringify(after.generations),
      environmentId: original.environmentId,
      generationIds: before.generationIds,
      operationIds: original.operationIds,
      localRpcExpectedAccounts: before.generations.map((generation) => ({
        generationId: generation.generationId,
        operationIds: generation.operationIds,
        addresses: generation.addresses,
      })),
      localChainReadsEqual: JSON.stringify(beforeChain) === JSON.stringify(afterChain),
      protectedStateReads: 'read-only-local-proxy-and-observer-before-after',
    },
    replayExecutionBoundary: 'offline-file-only-no-http-rpc-db-or-broadcast-by-replayer',
  };
  const file = `replay/${String(original.scenarioId).toLowerCase()}-offline-replay-report.json`;
  await writeCustomObservation(ctx, file, `sc012-${String(original.scenarioId).toLowerCase()}-offline-replay-report`, 'recorded-evidence-replay', reportArtifact);
  if (before.envId !== after.envId || JSON.stringify(before.generationIds) !== JSON.stringify(after.generationIds)
    || JSON.stringify(before.rows) !== JSON.stringify(after.rows)) {
    // Evidence is retained; the parent adapter should classify the comparison
    // as a failed predicate rather than treating replay as successful.
  }
  return report;
}

async function copyEvidenceTree(source: string, destination: string, maxBytes: number): Promise<void> {
  await scanEvidenceTree(source, maxBytes, 'probe_sc012_original_evidence_size_or_path_invalid');
  await mkdir(destination, { recursive: true });
  for (const entry of await readdir(source, { withFileTypes: true })) {
    const sourcePath = join(source, entry.name);
    const targetPath = join(destination, entry.name);
    const info = await lstat(sourcePath).catch(() => null);
    if (!info || entry.isSymbolicLink() || info.isSymbolicLink()) throw new Error('probe_sc012_original_evidence_symlink_rejected');
    if (info.isDirectory()) await copyEvidenceTree(sourcePath, targetPath, maxBytes);
    else if (entry.isFile()) await copyFile(sourcePath, targetPath);
    else throw new Error('probe_sc012_original_evidence_entry_rejected');
  }
}

async function evidenceTreeDigest(root: string, maxBytes: number): Promise<string> {
  const info = await lstat(root).catch(() => null);
  if (!info || !info.isDirectory() || info.isSymbolicLink()) throw new Error('probe_sc012_evidence_path_invalid');
  const { files } = await scanEvidenceTree(root, maxBytes, 'probe_sc012_evidence_size_or_path_invalid');
  const hash = createHash('sha256');
  for (const path of files.sort((left, right) => {
    const a = relative(root, left).replaceAll('\\', '/');
    const b = relative(root, right).replaceAll('\\', '/');
    return a < b ? -1 : a > b ? 1 : 0;
  })) {
    hash.update(relative(root, path).replaceAll('\\', '/'));
    hash.update('\0');
    hash.update(await readFile(path));
    hash.update('\0');
  }
  return hash.digest('hex');
}

async function rejectSyntheticFault(ctx: ProbeContext, originalDirectory: string, variantId: 'secret_in_artifact' | 'missing_hash'): Promise<void> {
  const maxBytes = ctx.runtime.manifest.guardrails.maxEvidenceBytesPerTrial;
  const validated = await validatedReplayReportShell(
    ctx.runtime.root,
    originalDirectory,
    new Set(ctx.runtime.manifest.local.environments.map((entry) => entry.id)),
    maxBytes,
  );
  const root = validated.absolutePath;
  const beforeOriginalHash = await evidenceTreeDigest(root, maxBytes);
  const temporaryRoot = await mkdtemp(join(tmpdir(), 'bef-sc012-fault-'));
  const evidenceCopy = join(temporaryRoot, 'synthetic-evidence');
  const reportPath = join(temporaryRoot, 'unexpected-report.json');
  let expectedRejectionObserved = false;
  let childMayBeLive = false;
  let replayResult: Awaited<ReturnType<typeof runOfflineReplayer>> | null = null;
  let unexpectedReportCreated = false;
  try {
    await copyEvidenceTree(root, evidenceCopy, maxBytes);
    const indexPath = join(evidenceCopy, 'probe.json');
    const index = requireObject(JSON.parse(await readFile(indexPath, 'utf8')) as unknown, 'synthetic_probe_index');
    const artifacts = index.artifacts;
    if (!Array.isArray(artifacts) || !artifacts.length) throw new Error('probe_sc012_fault_copy_has_no_artifacts');
    if (variantId === 'secret_in_artifact') {
      const entry = artifacts.find((item) => isObject(item) && item.boundary !== 'runtime-manifest');
      if (!isObject(entry) || typeof entry.path !== 'string') throw new Error('probe_sc012_fault_copy_has_no_mutable_artifact');
      const artifactPath = resolve(evidenceCopy, entry.path);
      const relativePath = relative(evidenceCopy, artifactPath);
      if (!relativePath || relativePath === '..' || relativePath.startsWith(`..${sep}`) || isAbsolute(relativePath)) {
        throw new Error('probe_sc012_fault_copy_path_invalid');
      }
      const payload = requireObject(JSON.parse(await readFile(artifactPath, 'utf8')) as unknown, 'synthetic_artifact');
      payload.canaryCredential = 'CANARY';
      const bytes = Buffer.from(`${JSON.stringify(payload, null, 2)}\n`, 'utf8');
      await writeFile(artifactPath, bytes, { flag: 'w' });
      entry.sha256 = createHash('sha256').update(bytes).digest('hex');
      index.artifacts = artifacts;
      await writeFile(indexPath, `${JSON.stringify(index, null, 2)}\n`, { flag: 'w' });
    } else {
      const entry = artifacts.find((item) => isObject(item) && item.boundary !== 'runtime-manifest');
      if (!isObject(entry)) throw new Error('probe_sc012_fault_copy_has_no_mutable_artifact');
      delete entry.sha256;
      index.artifacts = artifacts;
      await writeFile(indexPath, `${JSON.stringify(index, null, 2)}\n`, { flag: 'w' });
    }
    replayResult = await runOfflineReplayer(ctx.runtime.root, evidenceCopy, reportPath, (value) => { childMayBeLive = value; });
    unexpectedReportCreated = await fileExists(reportPath);
    expectedRejectionObserved = replayResult.processClosed && !replayResult.timedOut
      && replayResult.exitCode === 1 && !unexpectedReportCreated;
  } finally {
    await safelyRemoveTemporaryRoot(temporaryRoot, 'bef-sc012-fault-', childMayBeLive);
  }
  const afterOriginalHash = await evidenceTreeDigest(root, maxBytes);
  const originalUnchanged = beforeOriginalHash === afterOriginalHash;
  const temporaryRemoved = !(await fileExists(temporaryRoot));
  if (!replayResult || !expectedRejectionObserved || !originalUnchanged || !temporaryRemoved) {
    throw new Error(`probe_sc012_synthetic_fault_validation_failed_${variantId}`);
  }
  const validatorSourcePath = join(ctx.runtime.root, 'tools', 'replay_bef_evidence.py');
  await assertNoSymlinkPath(ctx.runtime.root, validatorSourcePath, 'probe_sc012_fault_validator_source_invalid');
  const validatorSource = await readFile(validatorSourcePath).catch(() => null);
  if (!validatorSource) throw new Error('probe_sc012_fault_validator_source_missing');
  await writeCustomObservation(ctx, `replay/${variantId}-validator-rejection.json`, `sc012-${variantId}-validator-rejection`, 'recorded-evidence-validation', {
    schemaVersion: 'bef-source-validation-fault-observation/v1',
    operationId: null,
    variantId,
    inputScenario: validated.scenarioId,
    originalEvidenceRootPath: relative(ctx.runtime.root, root).replaceAll('\\', '/'),
    originalProbeIndexSha256: validated.indexSha256,
    originalEvidenceTreeSha256Before: beforeOriginalHash,
    originalEvidenceTreeSha256After: afterOriginalHash,
    inputFault: variantId === 'secret_in_artifact' ? 'synthetic_secret_key_in_artifact' : 'artifact_sha256_field_removed',
    validator: 'tools/replay_bef_evidence.py -> ProbeEvidence.load',
    validatorSourcePath: 'tools/replay_bef_evidence.py',
    validatorSourceSha256: createHash('sha256').update(validatorSource).digest('hex'),
    replayerExitCode: replayResult.exitCode,
    replayerTimedOut: replayResult.timedOut,
    replayerProcessClosed: replayResult.processClosed,
    rejected: true,
    reportCreated: unexpectedReportCreated,
    originalEvidenceUnchanged: originalUnchanged,
    syntheticCopyRemoved: temporaryRemoved,
    recordingBoundary: 'hashed_probe_evidence_artifact',
  });
}

async function fileExists(path: string): Promise<boolean> {
  try { await lstat(path); return true; } catch { return false; }
}

export async function runSourceEvidenceScenario(ctx: ProbeContext, replayInputs: Sc012ReplayInputs): Promise<ScenarioExecution> {
  if (ctx.scenarioId !== 'BEF-SC-012') throw new Error('probe_sc012_wrong_scenario');
  const startedAt = Date.now();
  // Compare the original trials before any reset can change their local-chain
  // state. Replay itself reads captured files only, bracketed by independent
  // read-only database and local-RPC observations.
  const sc004 = await captureAndRunReplay(ctx, replayInputs.sc004EvidenceDirectory, startedAt);
  const sc005 = await captureAndRunReplay(ctx, replayInputs.sc005EvidenceDirectory, startedAt);
  const replayScenarios = [sc004.evaluatedScenarioId, sc005.evaluatedScenarioId];
  if (replayScenarios[0] !== 'BEF-SC-004' || replayScenarios[1] !== 'BEF-SC-005') {
    throw new Error('probe_sc012_replay_scenario_order_mismatch');
  }

  await rejectSyntheticFault(ctx, replayInputs.sc004EvidenceDirectory, 'secret_in_artifact');
  await rejectSyntheticFault(ctx, replayInputs.sc004EvidenceDirectory, 'missing_hash');

  // Reset and fresh generation are a clearly later, independent execution.
  await resetAndCreateGeneration(ctx);
  await captureSourceIdentityAndCode(ctx, startedAt);
  await captureDeniedVariants(ctx, startedAt);

  if (!ctx.primaryGeneration) throw new Error('probe_sc012_generation_identity_missing');
  return {
    environment: {
      envId: ctx.primaryGeneration.envId,
      generation: {
        generationId: ctx.primaryGeneration.generationId,
        participantId: ctx.primaryGeneration.participantId,
        payerAddress: ctx.primaryGeneration.payerAddress,
      },
    },
  };
}
