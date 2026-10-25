import { randomUUID } from 'node:crypto';
import { decodeFunctionResult, encodeFunctionData, keccak256, type Hex } from 'viem';
import { createSignedPayload, readPaymentRequired } from './x402.js';
import { apiPath } from './environment.js';
import { sha256Bytes, sanitizeValue } from './evidence.js';
import type { GenerationSession, ProbeCapabilityDocument, ProbeContext, ScenarioExecution } from './runner.js';
import { captureCapabilities, runCanonicalPurchase } from './runner.js';
import type { SnapshotRows } from './observer.js';
import { normalizeObservedDependencyVersions } from './versions.js';

type JsonObject = Record<string, unknown>;
type RpcBoundary = 'source-readonly-proxy' | 'local-chain-readonly-proxy';

const POOL_READ_ABI = [
  { type: 'function', name: 'token0', stateMutability: 'view', inputs: [], outputs: [{ name: '', type: 'address' }] },
  { type: 'function', name: 'token1', stateMutability: 'view', inputs: [], outputs: [{ name: '', type: 'address' }] },
  { type: 'function', name: 'fee', stateMutability: 'view', inputs: [], outputs: [{ name: '', type: 'uint24' }] },
  { type: 'function', name: 'liquidity', stateMutability: 'view', inputs: [], outputs: [{ name: '', type: 'uint128' }] },
  {
    type: 'function', name: 'slot0', stateMutability: 'view', inputs: [],
    outputs: [
      { name: 'sqrtPriceX96', type: 'uint160' }, { name: 'tick', type: 'int24' },
      { name: 'observationIndex', type: 'uint16' }, { name: 'observationCardinality', type: 'uint16' },
      { name: 'observationCardinalityNext', type: 'uint16' }, { name: 'feeProtocol', type: 'uint8' },
      { name: 'unlocked', type: 'bool' },
    ],
  },
] as const;
type PoolFunctionName = 'token0' | 'token1' | 'fee' | 'liquidity' | 'slot0';

function encodePoolRead(functionName: PoolFunctionName): Hex {
  switch (functionName) {
    case 'token0': return encodeFunctionData({ abi: POOL_READ_ABI, functionName: 'token0' });
    case 'token1': return encodeFunctionData({ abi: POOL_READ_ABI, functionName: 'token1' });
    case 'fee': return encodeFunctionData({ abi: POOL_READ_ABI, functionName: 'fee' });
    case 'liquidity': return encodeFunctionData({ abi: POOL_READ_ABI, functionName: 'liquidity' });
    case 'slot0': return encodeFunctionData({ abi: POOL_READ_ABI, functionName: 'slot0' });
  }
}

function decodePoolRead(functionName: PoolFunctionName, data: Hex): unknown {
  switch (functionName) {
    case 'token0': return decodeFunctionResult({ abi: POOL_READ_ABI, functionName: 'token0', data });
    case 'token1': return decodeFunctionResult({ abi: POOL_READ_ABI, functionName: 'token1', data });
    case 'fee': return decodeFunctionResult({ abi: POOL_READ_ABI, functionName: 'fee', data });
    case 'liquidity': return decodeFunctionResult({ abi: POOL_READ_ABI, functionName: 'liquidity', data });
    case 'slot0': return decodeFunctionResult({ abi: POOL_READ_ABI, functionName: 'slot0', data });
  }
}

const CODE_CONTRACTS = (ctx: ProbeContext): Array<{ name: string; address: string; expectedHash: string }> => {
  const { contracts } = ctx.runtime.manifest;
  return [
    { name: 'usdc-proxy', address: contracts.usdc.address, expectedHash: contracts.usdc.proxyCodeHash },
    { name: 'usdc-implementation', address: contracts.usdc.implementation, expectedHash: contracts.usdc.implementationCodeHash },
    { name: 'weth', address: contracts.weth.address, expectedHash: contracts.weth.codeHash },
    { name: 'factory', address: contracts.factory.address, expectedHash: contracts.factory.codeHash },
    { name: 'swap-router', address: contracts.swapRouter02.address, expectedHash: contracts.swapRouter02.codeHash },
    { name: 'quoter', address: contracts.quoterV2.address, expectedHash: contracts.quoterV2.codeHash },
    { name: 'pool', address: contracts.pool.address, expectedHash: contracts.pool.codeHash },
  ];
};

function objectOf(value: unknown, label: string): JsonObject {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(`probe_sc001_${label}_invalid`);
  return value as JsonObject;
}

function requiredString(value: unknown, label: string): string {
  if (typeof value !== 'string' || !value.trim()) throw new Error(`probe_sc001_${label}_missing`);
  return value;
}

function versionText(value: unknown, label: string): string {
  return requiredString(value, label).trim().replace(/^v/i, '');
}

function requireChainId(value: unknown, expected: number, label: string): void {
  if (typeof value !== 'string' || !/^0x[0-9a-f]+$/i.test(value) || BigInt(value) !== BigInt(expected)) {
    throw new Error(`probe_sc001_${label}_chain_id_mismatch`);
  }
}

/** Service health documents may report chain ids as JSON-RPC hex or decimal JSON numbers. */
export function chainIdMatches(value: unknown, expected: number): boolean {
  if (!Number.isSafeInteger(expected) || expected < 0) return false;
  let observed: bigint;
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || value < 0) return false;
    observed = BigInt(value);
  } else if (typeof value === 'string' && (/^0x[0-9a-f]+$/i.test(value) || /^\d+$/.test(value))) {
    try {
      observed = BigInt(value);
    } catch {
      return false;
    }
  } else {
    return false;
  }
  return observed === BigInt(expected);
}

function requirePinnedBlock(value: unknown, blockNumber: string, blockHash: string, label: string): JsonObject {
  const block = objectOf(value, `${label}_block`);
  if (typeof block.number !== 'string' || block.number.toLowerCase() !== blockNumber.toLowerCase()
    || typeof block.hash !== 'string' || block.hash.toLowerCase() !== blockHash.toLowerCase()) {
    throw new Error(`probe_sc001_${label}_block_mismatch`);
  }
  return block;
}

function requireCode(value: unknown, address: string, expectedHash: string, boundary: RpcBoundary, label: string): void {
  if (typeof value !== 'string' || !/^0x(?:[0-9a-f]{2})+$/i.test(value)) {
    throw new Error(`probe_sc001_${label}_code_missing`);
  }
  if (keccak256(value as Hex).toLowerCase() !== expectedHash.toLowerCase()) {
    throw new Error(`probe_sc001_${label}_code_hash_mismatch`);
  }
  void address;
  void boundary;
}

async function readRpc<T>(ctx: ProbeContext, input: {
  boundary: RpcBoundary;
  method: string;
  params: unknown[];
  block?: string | null;
  label: string;
}): Promise<T> {
  const url = input.boundary === 'source-readonly-proxy' ? ctx.env.sourceProxyUrl : ctx.env.localRpcUrl;
  const response = await ctx.rpc.call<T>({
    url,
    endpointBoundary: input.boundary,
    method: input.method,
    params: input.params,
    requestedBlock: input.block ?? null,
    operationId: null,
    variantId: null,
    label: input.label,
  });
  return response.result;
}

function supportedExactBase(value: unknown, visited = new Set<object>()): boolean {
  if (!value || typeof value !== 'object' || visited.has(value)) return false;
  visited.add(value);
  if (Array.isArray(value)) return value.some((item) => supportedExactBase(item, visited));
  const record = value as JsonObject;
  if (record.scheme === 'exact' && record.network === 'eip155:8453') return true;
  return Object.values(record).some((item) => supportedExactBase(item, visited));
}

function validateObservedVersions(ctx: ProbeContext, capability: ProbeCapabilityDocument): void {
  const { manifest, runtimeVersions } = ctx.runtime;
  const node = manifest.local.nodeVersion;
  const pins = manifest.local.versions;
  const dependencies = normalizeObservedDependencyVersions(capability.dependencyVersions);
  const services = objectOf(capability.services, 'services');
  const localRpc = objectOf(services.localRpc, 'local_rpc_service');
  const facilitator = objectOf(services.facilitator, 'facilitator_service');
  const facilitatorDependencies = normalizeObservedDependencyVersions(facilitator.dependencyVersions);
  const postgres = objectOf(services.postgres, 'postgres_service');

  if (versionText(runtimeVersions.probeNode, 'probe_node_version') !== versionText(process.version, 'process_node_version')) {
    throw new Error('probe_sc001_probe_node_observation_mismatch');
  }
  if (versionText(capability.apiNodeVersion, 'api_node_version') !== node
    || versionText(facilitator.nodeVersion, 'facilitator_node_version') !== node
    || versionText(runtimeVersions.apiNode, 'observed_api_node_version') !== node
    || versionText(runtimeVersions.facilitatorNode, 'observed_facilitator_node_version') !== node) {
    throw new Error('probe_sc001_node_runtime_pin_mismatch');
  }

  const apiPackage = requiredString(capability.apiPackageVersion, 'api_package_version');
  const facilitatorPackage = requiredString(facilitator.packageVersion, 'facilitator_package_version');
  if (apiPackage !== facilitatorPackage || runtimeVersions.apiPackage !== apiPackage) {
    throw new Error('probe_sc001_package_runtime_identity_mismatch');
  }

  const expectedDependencies: Record<string, string> = {
    fastify: manifest.local.fastifyVersion,
    x402Core: pins.x402Core,
    x402Evm: pins.x402Evm,
    x402Fastify: pins.x402Fastify,
    viem: pins.viem,
    postgresDriver: pins.postgresDriver,
  };
  for (const [name, expected] of Object.entries(expectedDependencies)) {
    if (requiredString(dependencies[name], `api_${name}_version`) !== expected
      || runtimeVersions[name] !== expected) {
      throw new Error(`probe_sc001_api_dependency_pin_mismatch_${name}`);
    }
  }
  for (const name of ['x402Core', 'x402Evm', 'x402Fastify', 'viem'] as const) {
    if (requiredString(facilitatorDependencies[name], `facilitator_${name}_version`) !== pins[name]) {
      throw new Error(`probe_sc001_facilitator_dependency_pin_mismatch_${name}`);
    }
  }

  const anvilVersion = manifest.local.anvilVersion;
  const clientVersion = requiredString(localRpc.clientVersion, 'anvil_client_version');
  if (!clientVersion.includes(anvilVersion) || runtimeVersions.anvil !== clientVersion) {
    throw new Error('probe_sc001_anvil_version_mismatch');
  }
  const executionNetwork = requiredString(localRpc.executionNetwork, 'anvil_execution_network');
  const hardFork = requiredString(localRpc.hardFork, 'anvil_hard_fork');
  if (executionNetwork.toLowerCase() !== manifest.local.executionNetwork
    || hardFork.toLowerCase() !== manifest.local.hardfork
    || runtimeVersions.anvilExecutionNetwork !== executionNetwork
    || runtimeVersions.anvilHardFork !== hardFork) {
    throw new Error('probe_sc001_anvil_execution_profile_mismatch');
  }
  const postgresVersion = requiredString(postgres.version, 'postgres_version');
  if (!postgresVersion.includes(`PostgreSQL ${manifest.local.postgresqlVersion}`)
    || !requiredString(runtimeVersions.postgresql, 'observed_postgres_version').includes(`PostgreSQL ${manifest.local.postgresqlVersion}`)) {
    throw new Error('probe_sc001_postgres_version_mismatch');
  }
  if (versionText(facilitator.packageVersion, 'facilitator_package_version') !== versionText(apiPackage, 'api_package_version')) {
    throw new Error('probe_sc001_facilitator_package_pin_mismatch');
  }
}

async function captureChainIdentity(ctx: ProbeContext, boundary: RpcBoundary): Promise<JsonObject> {
  const { manifest } = ctx.runtime;
  const chainId = await readRpc<string>(ctx, { boundary, method: 'eth_chainId', params: [], label: `sc001-${boundary}-chain-id` });
  requireChainId(chainId, manifest.source.chainId, boundary.replaceAll('-', '_'));
  const blockNumber = boundary === 'source-readonly-proxy' ? manifest.source.blockNumber : manifest.local.forkBlock;
  const block = requirePinnedBlock(
    await readRpc<unknown>(ctx, {
      boundary,
      method: 'eth_getBlockByNumber',
      params: [blockNumber, false],
      block: blockNumber,
      label: `sc001-${boundary}-pinned-block`,
    }),
    manifest.source.blockNumber,
    manifest.source.blockHash,
    boundary.replaceAll('-', '_'),
  );
  if (typeof block.timestamp !== 'string' || block.timestamp.toLowerCase() !== manifest.source.blockTimestamp.toLowerCase()) {
    throw new Error(`probe_sc001_${boundary.replaceAll('-', '_')}_block_timestamp_mismatch`);
  }
  return block;
}

async function captureContractCode(ctx: ProbeContext, boundary: RpcBoundary): Promise<void> {
  const block = boundary === 'source-readonly-proxy' ? ctx.runtime.manifest.source.blockNumber : ctx.runtime.manifest.local.forkBlock;
  for (const contract of CODE_CONTRACTS(ctx)) {
    const code = await readRpc<string>(ctx, {
      boundary,
      method: 'eth_getCode',
      params: [contract.address, block],
      block,
      label: `sc001-${boundary}-${contract.name}-code`,
    });
    requireCode(code, contract.address, contract.expectedHash, boundary, `${boundary.replaceAll('-', '_')}_${contract.name}`);
  }
}

async function captureUsdcImplementationSlot(ctx: ProbeContext, boundary: RpcBoundary): Promise<void> {
  const { usdc } = ctx.runtime.manifest.contracts;
  const block = boundary === 'source-readonly-proxy' ? ctx.runtime.manifest.source.blockNumber : ctx.runtime.manifest.local.forkBlock;
  const value = await readRpc<string>(ctx, {
    boundary,
    method: 'eth_getStorageAt',
    params: [usdc.address, usdc.implementationSlot, block],
    block,
    label: `sc001-${boundary}-usdc-implementation-slot`,
  });
  if (!/^0x[0-9a-f]{64}$/i.test(value)
    || `0x${value.slice(-40)}`.toLowerCase() !== usdc.implementation.toLowerCase()) {
    throw new Error(`probe_sc001_${boundary.replaceAll('-', '_')}_usdc_implementation_slot_mismatch`);
  }
}

async function capturePoolState(ctx: ProbeContext, boundary: RpcBoundary): Promise<void> {
  const { manifest } = ctx.runtime;
  const poolAddress = manifest.contracts.pool.address;
  const block = boundary === 'source-readonly-proxy' ? manifest.source.blockNumber : manifest.local.forkBlock;
  const readPool = async (functionName: PoolFunctionName): Promise<unknown> => {
    const data = encodePoolRead(functionName);
    const result = await readRpc<string>(ctx, {
      boundary,
      method: 'eth_call',
      params: [{ to: poolAddress, data }, block],
      block,
      label: `sc001-${boundary}-pool-${functionName}`,
    });
    return decodePoolRead(functionName, result as Hex);
  };
  const token0 = await readPool('token0') as string;
  const token1 = await readPool('token1') as string;
  const feeValue = await readPool('fee');
  const fee = typeof feeValue === 'bigint' ? feeValue : BigInt(feeValue as number);
  const liquidity = await readPool('liquidity') as bigint;
  const slot0 = await readPool('slot0') as readonly [bigint, number, number, number, number, number, boolean];
  if (token0.toLowerCase() !== manifest.contracts.pool.token0.toLowerCase()
    || token1.toLowerCase() !== manifest.contracts.pool.token1.toLowerCase()
    || fee !== BigInt(manifest.contracts.pool.fee)
    || `0x${liquidity.toString(16).padStart(64, '0')}`.toLowerCase() !== manifest.contracts.pool.liquidityAtSource.toLowerCase()
    || `0x${slot0[0].toString(16).padStart(64, '0')}`.toLowerCase() !== manifest.contracts.pool.sqrtPriceX96AtSource.toLowerCase()) {
    throw new Error(`probe_sc001_${boundary.replaceAll('-', '_')}_pool_state_mismatch`);
  }
}

async function captureFacilitatorSupport(ctx: ProbeContext): Promise<void> {
  const response = await ctx.transport.request({
    boundary: 'facilitator-http',
    observationId: 'sc001-facilitator-supported',
    method: 'GET',
    url: apiPath(ctx.env.facilitatorUrl, '/supported'),
    headers: { 'X-BEF-Service-Key': ctx.env.serviceKey },
    operationId: null,
    variantId: null,
  });
  if (response.status !== 200 || !supportedExactBase(response.body)) {
    throw new Error('probe_sc001_facilitator_exact_base_scheme_unavailable');
  }
}

async function validateMatchingCandidate(ctx: ProbeContext, candidateType: 'source_chain' | 'source_block' | 'required_code', candidate: JsonObject): Promise<void> {
  const response = await ctx.transport.request({
    boundary: 'private-admin-http',
    observationId: `sc001-positive-${candidateType}-preflight`,
    method: 'POST',
    url: apiPath(ctx.env.apiBaseUrl, `/internal/admin/environments/${ctx.env.envId}/prerequisite-validations`),
    headers: { 'X-BEF-Admin-Key': ctx.env.adminKey, 'content-type': 'application/json' },
    body: { candidateType, candidate },
    operationId: null,
    variantId: null,
  });
  if (response.status !== 200 || !response.body || typeof response.body !== 'object' || Array.isArray(response.body)) {
    throw new Error(`probe_sc001_positive_candidate_failed_${candidateType}`);
  }
  const body = response.body as JsonObject;
  if (body.accepted !== true || body.reasonCode !== 'prerequisites_match'
    || body.candidateType !== candidateType || body.candidate === null
    || JSON.stringify(body.candidate) !== JSON.stringify(candidate)
    || body.manifestSha256 !== ctx.runtime.manifestSha256
    || String(body.applicationSourceSha256).toLowerCase() !== ctx.runtime.appSourceSha256.toLowerCase()) {
    throw new Error(`probe_sc001_positive_candidate_mismatch_${candidateType}`);
  }
  const observations = objectOf(body.observations, `${candidateType}_observations`);
  if (candidateType === 'source_chain') {
    const source = objectOf(observations.source, `${candidateType}_source`);
    const chainResult = objectOf(source.chainId, `${candidateType}_chain`).result;
    if (BigInt(String(candidate.chainId)) !== BigInt(String(chainResult))) {
      throw new Error('probe_sc001_positive_chain_observation_mismatch');
    }
  } else if (candidateType === 'source_block') {
    const source = objectOf(observations.source, `${candidateType}_source`);
    const block = objectOf(source.block, `${candidateType}_block`).result;
    const observed = objectOf(block, `${candidateType}_block_result`);
    if (String(candidate.blockNumber).toLowerCase() !== String(observed.number).toLowerCase()
      || String(candidate.blockHash).toLowerCase() !== String(observed.hash).toLowerCase()) {
      throw new Error('probe_sc001_positive_block_observation_mismatch');
    }
  } else {
    const source = objectOf(observations.source, `${candidateType}_source`);
    const code = objectOf(source.code, `${candidateType}_code`);
    if (typeof code.result !== 'string' || code.result === '0x'
      || keccak256(code.result as Hex).toLowerCase() !== String(candidate.codeHash).toLowerCase()) {
      throw new Error('probe_sc001_positive_code_observation_mismatch');
    }
  }
}

/** Capture and validate the actual positive runtime prerequisites for SC001.
 * Negative variants use the separately reviewed private validation route and
 * are intentionally not synthesized by changing this probe's manifest or URL.
 */
export async function capturePrerequisitePositiveEvidence(ctx: ProbeContext): Promise<void> {
  if (ctx.scenarioId !== 'BEF-SC-001') throw new Error('probe_sc001_wrong_scenario');
  if (sha256Bytes(ctx.runtime.manifestBytes) !== ctx.runtime.manifestSha256) {
    throw new Error('probe_sc001_local_manifest_hash_mismatch');
  }

  const capability = await captureCapabilities(ctx);
  if (capability.schemaVersion !== 'bef-probe-capabilities/v1'
    || capability.ready !== true
    || capability.envId !== ctx.env.envId
    || capability.manifestSha256 !== ctx.runtime.manifestSha256
    || capability.applicationSourceSha256?.toLowerCase() !== ctx.runtime.appSourceSha256.toLowerCase()) {
    throw new Error('probe_sc001_capability_manifest_binding_mismatch');
  }
  validateObservedVersions(ctx, capability);

  await validateMatchingCandidate(ctx, 'source_chain', { chainId: ctx.runtime.manifest.source.chainId });
  await validateMatchingCandidate(ctx, 'source_block', {
    blockNumber: ctx.runtime.manifest.source.blockNumber,
    blockHash: ctx.runtime.manifest.source.blockHash,
  });
  await validateMatchingCandidate(ctx, 'required_code', {
    contractAddress: ctx.runtime.manifest.contracts.usdc.address,
    codeHash: ctx.runtime.manifest.contracts.usdc.proxyCodeHash,
  });

  const localService = objectOf(objectOf(capability.services, 'services').localRpc, 'local_rpc_service');
  const facilitatorService = objectOf(objectOf(capability.services, 'services').facilitator, 'facilitator_service');
  if (String(localService.forkBlockNumber).toLowerCase() !== ctx.runtime.manifest.local.forkBlock.toLowerCase()
    || String(localService.forkBlockHash).toLowerCase() !== ctx.runtime.manifest.source.blockHash.toLowerCase()
    || String(facilitatorService.forkBlockHash).toLowerCase() !== ctx.runtime.manifest.source.blockHash.toLowerCase()
    || !chainIdMatches(facilitatorService.chainId, ctx.runtime.manifest.local.chainId)) {
    throw new Error('probe_sc001_capability_service_identity_mismatch');
  }

  await captureChainIdentity(ctx, 'source-readonly-proxy');
  await captureChainIdentity(ctx, 'local-chain-readonly-proxy');
  await captureContractCode(ctx, 'source-readonly-proxy');
  await captureContractCode(ctx, 'local-chain-readonly-proxy');
  await captureUsdcImplementationSlot(ctx, 'source-readonly-proxy');
  await captureUsdcImplementationSlot(ctx, 'local-chain-readonly-proxy');
  await capturePoolState(ctx, 'source-readonly-proxy');
  await capturePoolState(ctx, 'local-chain-readonly-proxy');
  await captureFacilitatorSupport(ctx);
}

const SC001_NEGATIVE_REASONS: Record<string, string> = {
  wrong_block: 'source_block_mismatch',
  wrong_chain: 'source_chain_mismatch',
  missing_code: 'required_code_missing',
  per_trial_latest: 'latest_block_disallowed',
};

function operationIdFromBody(value: unknown): string | null {
  const body = value && typeof value === 'object' && !Array.isArray(value) ? value as JsonObject : null;
  const direct = body?.operationId;
  if (typeof direct === 'string' && direct) return direct;
  const nested = body?.operation && typeof body.operation === 'object' && !Array.isArray(body.operation)
    ? (body.operation as JsonObject).operationId : null;
  return typeof nested === 'string' && nested ? nested : null;
}

function snapshotFingerprint(rows: SnapshotRows): string {
  return JSON.stringify(Object.fromEntries(
    Object.entries(rows).map(([name, values]) => [
      name,
      values.map((row) => JSON.stringify(sanitizeValue(row))).sort(),
    ]),
  ));
}

async function snapshotVariantDatabase(ctx: ProbeContext, session: GenerationSession, variantId: string, phase: 'before' | 'after'): Promise<SnapshotRows> {
  return ctx.database.snapshot({
    envId: session.envId,
    generationId: session.generationId,
    variantId,
    label: `sc001-${variantId}-${phase}-database`,
  });
}

async function captureVariantPinnedIdentity(ctx: ProbeContext, variantId: string, phase: 'before' | 'after'): Promise<void> {
  const { manifest } = ctx.runtime;
  for (const boundary of ['source-readonly-proxy', 'local-chain-readonly-proxy'] as const) {
    const isSource = boundary === 'source-readonly-proxy';
    const url = isSource ? ctx.env.sourceProxyUrl : ctx.env.localRpcUrl;
    const expectedChain = isSource ? manifest.source.chainId : manifest.local.chainId;
    const blockNumber = isSource ? manifest.source.blockNumber : manifest.local.forkBlock;
    const chain = await ctx.rpc.call<string>({
      url,
      endpointBoundary: boundary,
      method: 'eth_chainId',
      params: [],
      operationId: null,
      variantId,
      label: `sc001-${variantId}-${phase}-${boundary}-chain-id`,
    });
    if (typeof chain.result !== 'string' || BigInt(chain.result) !== BigInt(expectedChain)) {
      throw new Error(`probe_sc001_${variantId}_${phase}_chain_identity_mismatch`);
    }
    const block = await ctx.rpc.call<JsonObject>({
      url,
      endpointBoundary: boundary,
      method: 'eth_getBlockByNumber',
      params: [blockNumber, false],
      requestedBlock: blockNumber,
      operationId: null,
      variantId,
      label: `sc001-${variantId}-${phase}-${boundary}-block`,
    });
    const expectedHash = manifest.source.blockHash.toLowerCase();
    if (typeof block.result?.number !== 'string' || block.result.number.toLowerCase() !== blockNumber.toLowerCase()
      || typeof block.result.hash !== 'string' || block.result.hash.toLowerCase() !== expectedHash) {
      throw new Error(`probe_sc001_${variantId}_${phase}_block_identity_mismatch`);
    }
  }
}

async function runReadOnlyMismatchVariant(
  ctx: ProbeContext,
  session: GenerationSession,
  variantId: keyof typeof SC001_NEGATIVE_REASONS,
  candidate: JsonObject,
): Promise<void> {
  await captureVariantPinnedIdentity(ctx, variantId, 'before');
  const databaseBefore = await snapshotVariantDatabase(ctx, session, variantId, 'before');
  const response = await ctx.transport.request({
    boundary: 'private-admin-http',
    observationId: `sc001-${variantId}-preflight`,
    method: 'POST',
    url: apiPath(ctx.env.apiBaseUrl, `/internal/admin/environments/${session.envId}/prerequisite-validations`),
    headers: { 'X-BEF-Admin-Key': ctx.env.adminKey, 'content-type': 'application/json' },
    body: { variantId, candidate },
    operationId: null,
    variantId,
  });
  if (response.status !== 200 || !response.body || typeof response.body !== 'object' || Array.isArray(response.body)) {
    throw new Error(`probe_sc001_preflight_rejected_${variantId}_${response.status}`);
  }
  const body = response.body as JsonObject;
  if (body.variantId !== variantId || body.envId !== session.envId || body.accepted !== false
    || body.reasonCode !== SC001_NEGATIVE_REASONS[variantId]
    || body.manifestSha256 !== ctx.runtime.manifestSha256
    || String(body.applicationSourceSha256).toLowerCase() !== ctx.runtime.appSourceSha256.toLowerCase()) {
    throw new Error(`probe_sc001_preflight_decision_invalid_${variantId}`);
  }
  if (variantId === 'missing_code') {
    const address = String(candidate.contractAddress);
    const block = ctx.runtime.manifest.source.blockNumber;
    const code = await ctx.rpc.call<string>({
      url: ctx.env.sourceProxyUrl,
      endpointBoundary: 'source-readonly-proxy',
      method: 'eth_getCode',
      params: [address, block],
      requestedBlock: block,
      operationId: null,
      variantId,
      label: `sc001-${variantId}-source-zero-address-code`,
    });
    if (code.result !== '0x') throw new Error('probe_sc001_missing_code_observation_mismatch');
  }
  await captureVariantPinnedIdentity(ctx, variantId, 'after');
  const databaseAfter = await snapshotVariantDatabase(ctx, session, variantId, 'after');
  if (snapshotFingerprint(databaseBefore) !== snapshotFingerprint(databaseAfter)) {
    throw new Error(`probe_sc001_database_state_changed_${variantId}`);
  }
}

async function runUnsupportedAssetSchemeVariant(ctx: ProbeContext, session: GenerationSession): Promise<void> {
  const variantId = 'unsupported_asset_scheme';
  const idempotencyKey = randomUUID();
  const challenge = await ctx.transport.request({
    boundary: 'actual-tool-http',
    observationId: 'sc001-unsupported-scheme-real-challenge',
    method: 'POST',
    url: apiPath(ctx.env.apiBaseUrl, `/tools/${session.envId}/purchase`),
    headers: {
      authorization: `Bearer ${session.runToken}`,
      'X-BEF-Generation': session.generationId,
      'Idempotency-Key': idempotencyKey,
      'content-type': 'application/json',
    },
    body: { resourceId: ctx.runtime.manifest.x402.resourceId, offerId: 'canonical' },
    operationId: null,
    variantId,
    resolveOperationId: async (_status, body) => {
      const direct = operationIdFromBody(body);
      if (direct) return direct;
      const rows = await ctx.database.snapshot({
        envId: session.envId,
        generationId: session.generationId,
        idempotencyKey,
        variantId,
        label: 'sc001-unsupported-scheme-operation-lookup',
      });
      return rows.operations[0] ? String(rows.operations[0].operation_id) : null;
    },
  });
  if (challenge.status !== 402 || !challenge.operationId) throw new Error('probe_sc001_unsupported_scheme_challenge_missing');
  const parsed = readPaymentRequired(session.signer, challenge.headers, challenge.body, ctx.runtime.manifest);
  const signature = await createSignedPayload(session.signer, parsed.declaration, parsed.requirements);
  ctx.operations.set(challenge.operationId, {
    operationId: challenge.operationId,
    kind: 'purchase',
    idempotencyKeyHash: sha256Bytes(Buffer.from(idempotencyKey, 'utf8')),
    observedStatus: 'awaiting_payment',
    transactionHash: null,
    receiptStatus: 'not_submitted',
  });

  await captureVariantPinnedIdentity(ctx, variantId, 'before');
  const databaseBefore = await snapshotVariantDatabase(ctx, session, variantId, 'before');
  const operation = databaseBefore.operations.find((row) => row.operation_id === challenge.operationId);
  const requestSha256 = operation?.request_sha256;
  if (typeof requestSha256 !== 'string' || !/^[0-9a-f]{64}$/i.test(requestSha256)) {
    throw new Error('probe_sc001_unsupported_scheme_operation_request_hash_missing');
  }
  const unsupportedRequirements = { ...parsed.requirements, scheme: 'unsupported-test-scheme' };
  const rejection = await ctx.transport.request({
    boundary: 'facilitator-http',
    observationId: 'sc001-unsupported-scheme-facilitator-verify',
    method: 'POST',
    url: apiPath(ctx.env.facilitatorUrl, '/verify'),
    headers: {
      'X-BEF-Service-Key': ctx.env.serviceKey,
      'X-BEF-Operation-Id': challenge.operationId,
      'X-BEF-Generation': session.generationId,
      'X-BEF-Variant-Id': variantId,
      'X-BEF-Request-SHA256': requestSha256.toLowerCase(),
      'content-type': 'application/json',
    },
    body: { paymentPayload: signature.payload, paymentRequirements: unsupportedRequirements },
    operationId: challenge.operationId,
    variantId,
  });
  const denial = rejection.body && typeof rejection.body === 'object' && !Array.isArray(rejection.body)
    ? rejection.body as JsonObject : {};
  if (rejection.status !== 400 || denial.error !== 'unsupported_payment_requirements'
    || denial.reasonCode !== 'unsupported_asset_scheme') {
    throw new Error(`probe_sc001_unsupported_scheme_not_rejected_${rejection.status}`);
  }
  await captureVariantPinnedIdentity(ctx, variantId, 'after');
  const databaseAfter = await snapshotVariantDatabase(ctx, session, variantId, 'after');
  if (snapshotFingerprint(databaseBefore) !== snapshotFingerprint(databaseAfter)) {
    throw new Error('probe_sc001_database_state_changed_unsupported_asset_scheme');
  }
}

/** Execute the full SC001 compatibility gate and then every approved invalid-prerequisite case. */
export async function runScenario001(ctx: ProbeContext): Promise<ScenarioExecution> {
  if (ctx.scenarioId !== 'BEF-SC-001') throw new Error('probe_sc001_wrong_scenario');
  await capturePrerequisitePositiveEvidence(ctx);
  await runCanonicalPurchase(ctx, 'sc001');
  const session = ctx.primarySession;
  if (!session) throw new Error('probe_sc001_primary_generation_missing');

  const blockValue = BigInt(ctx.runtime.manifest.source.blockNumber) + 1n;
  const blockNumber = `0x${blockValue.toString(16)}`;
  const originalHash = ctx.runtime.manifest.source.blockHash;
  const lastNibble = originalHash.at(-1)!.toLowerCase();
  const blockHash = `${originalHash.slice(0, -1)}${lastNibble === '0' ? '1' : '0'}`;
  const zeroAddress = `0x${'0'.repeat(40)}`;
  await runReadOnlyMismatchVariant(ctx, session, 'wrong_block', { blockNumber, blockHash });
  await runReadOnlyMismatchVariant(ctx, session, 'wrong_chain', { chainId: 1 });
  await runReadOnlyMismatchVariant(ctx, session, 'missing_code', {
    contractAddress: zeroAddress,
    codeHash: ctx.runtime.manifest.contracts.usdc.proxyCodeHash,
  });
  await runUnsupportedAssetSchemeVariant(ctx, session);
  await runReadOnlyMismatchVariant(ctx, session, 'per_trial_latest', { requestedBlock: 'latest' });

  return {
    environment: {
      envId: session.envId,
      generation: { generationId: session.generationId, participantId: session.participantId, payerAddress: session.payerAddress },
    },
  };
}
