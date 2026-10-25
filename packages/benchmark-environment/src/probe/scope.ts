/**
 * Live probe for BEF-SC-003. The probe does not treat advertised hooks as proof:
 * each denied HTTP response must bind to a fresh, independently observed denial
 * row, with unchanged read-only database and local-chain snapshots.
 */
import { createHash, randomUUID } from 'node:crypto';
import {
  encodeFunctionData,
  keccak256,
  parseAbi,
  toBytes,
  type Address,
  type Hex,
} from 'viem';
import {
  apiPath,
  newParticipantId,
  runtimeEnvironment,
  type ProbeEnvironment,
} from './environment.js';
import { createEphemeralSigner } from './x402.js';
import type { ProbeContext, GenerationSession, ScenarioExecution } from './runner.js';
import type { RawObservation } from './types.js';

const SCOPE_ABI = parseAbi([
  'function balanceOf(address account) view returns (uint256)',
  'function allowance(address owner, address spender) view returns (uint256)',
]);

/**
 * These hooks are prerequisites, not observations. The current runtime does
 * not provide them, so this probe must stop with an error after preserving its
 * raw evidence rather than manufacture audit rows or mark SC003 captured.
 */
export const REQUIRED_RUNTIME_HOOKS = [
  'authorizeParticipant-persists-operationless-denials-for-401-403-and-unknown-environment',
  'purchase-validation-persists-denial-for-unexpected-fields-before-operation-or-protocol-setup',
  'participant-namespace-not-found-handler-persists-denial-for-admin-and-write-route-attempts',
  'Fastify-preparse-body-limit-handler-persists-denial-for-413-without-retaining-raw-body',
  'X-BEF-Denial-Id-binds-response-to-one-bef_denial-row-with-route-env-and-claimed-generation',
] as const;

export const REQUIRED_READONLY_EVIDENCE_COLUMNS = [
  'bef_denial.denial_id',
  'bef_denial.env_id',
  'bef_denial.generation_id',
  'bef_denial.operation_id',
  'bef_denial.route',
  'bef_denial.reason_code',
  'bef_denial.request_sha256',
] as const;

type ScopeAttempt = {
  variantId: string;
  label: string;
  targetEnvId: string;
  claimedGenerationId: string;
  method: string;
  path: string;
  status: number;
  errorCode: string | null;
  denialId: string | null;
  operationId: string | null;
  idempotencyKeyHash: string;
};

type DatabaseProjection = {
  generation: Record<string, unknown>[];
  operations: Record<string, unknown>[];
  payments: Record<string, unknown>[];
  deliveries: Record<string, unknown>[];
  x402Observations: Record<string, unknown>[];
};

type ChainState = {
  envId: string;
  chainId: string;
  latestBlock: { number: string; hash: string };
  accounts: Array<{
    address: Address;
    nativeBalanceWei: string;
    transactionCount: string;
    usdcBalance: string;
    usdcAllowanceToSwapRouter02: string;
  }>;
  contracts: Array<{ name: string; address: Address; expectedCodeHash: string; codeHash: string; codeBytes: number }>;
};

type AttemptPlan = {
  variantId: string;
  label: string;
  method: string;
  path: string;
  session: GenerationSession;
  body?: unknown;
  query?: string;
  targetEnv: ProbeEnvironment;
};

function recordOf(value: unknown): Record<string, unknown> | null {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? value as Record<string, unknown>
    : null;
}

function requiredString(value: unknown, label: string): string {
  if (typeof value !== 'string' || value.length === 0) throw new Error(`probe_sc003_missing_${label}`);
  return value;
}

function checkLoopback(name: string, raw: string): void {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new Error(`probe_sc003_nonlocal_${name}`);
  }
  const host = url.hostname.replace(/^\[|\]$/g, '').toLowerCase();
  if (!['localhost', '127.0.0.1', '::1'].includes(host)) throw new Error(`probe_sc003_nonlocal_${name}`);
}

function ensureLocalOnly(ctx: ProbeContext, envs: ProbeEnvironment[]): void {
  checkLoopback('api', ctx.env.apiBaseUrl);
  checkLoopback('database_observer', ctx.env.databaseObserverUrl);
  for (const env of envs) checkLoopback(`local_rpc_${env.envId}`, env.localRpcUrl);
}

function scopedHeaders(session: GenerationSession, idempotencyKey: string): Record<string, string> {
  return {
    authorization: `Bearer ${session.runToken}`,
    'X-BEF-Generation': session.generationId,
    'Idempotency-Key': idempotencyKey,
    'content-type': 'application/json',
  };
}

function bodyIdentifier(responseBody: unknown, key: string): string | null {
  const body = recordOf(responseBody);
  return typeof body?.[key] === 'string' && body[key] ? body[key] as string : null;
}

function requestErrorCode(body: unknown): string | null {
  return bodyIdentifier(body, 'error');
}

function denialIdentifier(headers: { get(name: string): string | null }): string | null {
  return headers.get('x-bef-denial-id');
}

function stableValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(stableValue);
  const record = recordOf(value);
  if (record) {
    return Object.fromEntries(Object.keys(record).sort().map((key) => [key, stableValue(record[key])]));
  }
  return value;
}

function stableJson(value: unknown): string {
  return JSON.stringify(stableValue(value));
}

function protectedDbProjection(rows: Awaited<ReturnType<ProbeContext['database']['snapshot']>>): DatabaseProjection {
  return {
    generation: rows.generation,
    operations: rows.operations,
    payments: rows.payments,
    deliveries: rows.deliveries,
    x402Observations: rows.x402Observations,
  };
}

async function adminRequest(ctx: ProbeContext, env: ProbeEnvironment, label: string, method: string, path: string, body?: unknown) {
  return ctx.transport.request({
    boundary: 'private-admin-http',
    observationId: label,
    method,
    url: apiPath(env.apiBaseUrl, path),
    headers: {
      'X-BEF-Admin-Key': env.adminKey,
      ...(body === undefined ? {} : { 'content-type': 'application/json' }),
    },
    ...(body === undefined ? {} : { body }),
    operationId: null,
    variantId: null,
    resolveOperationId: async (_status, responseBody) => bodyIdentifier(responseBody, 'operationId'),
  });
}

async function resetEnvironment(ctx: ProbeContext, env: ProbeEnvironment, label: string): Promise<void> {
  const response = await adminRequest(
    ctx,
    env,
    label,
    'POST',
    `/internal/admin/environments/${env.envId}/reset`,
    {},
  );
  if (response.status < 200 || response.status >= 300) throw new Error(`probe_sc003_setup_reset_${env.envId}_${response.status}`);
}

async function createGeneration(ctx: ProbeContext, env: ProbeEnvironment, label: string): Promise<GenerationSession> {
  const signer = createEphemeralSigner();
  ctx.secretValues.push(signer.privateKey);
  const participantId = newParticipantId('BEF-SC-003');
  const response = await adminRequest(
    ctx,
    env,
    label,
    'POST',
    `/internal/admin/environments/${env.envId}/generations`,
    { participantId, payerAddress: signer.payerAddress, resourceVariant: 'canonical' },
  );
  if (response.status < 200 || response.status >= 300) throw new Error(`probe_sc003_setup_generation_${env.envId}_${response.status}`);
  const body = recordOf(response.body);
  const generationId = requiredString(body?.generationId, 'generation_id');
  const returnedEnvId = requiredString(body?.envId, 'environment_id');
  const payerAddress = requiredString(body?.payerAddress, 'payer_address');
  const runToken = requiredString(body?.runToken ?? recordOf(body?.participant)?.runToken, 'run_token');
  if (returnedEnvId !== env.envId || payerAddress.toLowerCase() !== signer.payerAddress.toLowerCase()) {
    throw new Error('probe_sc003_setup_identity_mismatch');
  }
  ctx.secretValues.push(runToken);
  return {
    envId: returnedEnvId,
    generationId,
    participantId,
    payerAddress: signer.payerAddress,
    runToken,
    signer,
  };
}

async function captureCapabilities(ctx: ProbeContext, env: ProbeEnvironment, label: string): Promise<Record<string, unknown>> {
  const response = await adminRequest(
    ctx,
    env,
    label,
    'GET',
    `/internal/admin/environments/${env.envId}/probe-capabilities`,
  );
  if (response.status !== 200) throw new Error(`probe_sc003_capabilities_${env.envId}_${response.status}`);
  const body = recordOf(response.body);
  if (!body) throw new Error(`probe_sc003_capabilities_invalid_${env.envId}`);
  return body;
}

async function participantRequest(ctx: ProbeContext, plan: AttemptPlan): Promise<ScopeAttempt> {
  const idempotencyKey = `sc003-${plan.variantId}-${randomUUID()}`;
  const url = `${apiPath(plan.targetEnv.apiBaseUrl, plan.path)}${plan.query ?? ''}`;
  const response = await ctx.transport.request({
    boundary: 'actual-tool-http',
    observationId: plan.label,
    method: plan.method,
    url,
    headers: scopedHeaders(plan.session, idempotencyKey),
    ...(plan.body === undefined ? {} : { body: plan.body }),
    operationId: null,
    variantId: plan.variantId,
    resolveOperationId: async (_status, responseBody) => bodyIdentifier(responseBody, 'operationId'),
  });
  return {
    variantId: plan.variantId,
    label: plan.label,
    targetEnvId: plan.targetEnv.envId,
    claimedGenerationId: plan.session.generationId,
    method: plan.method.toUpperCase(),
    // Keep the route path without the query to match the durable denial route.
    // The raw HTTP artifact separately records the complete request target.
    path: plan.path === `/tools/${plan.targetEnv.envId}/offer` || plan.path === `/tools/${plan.targetEnv.envId}/purchase`
      ? plan.path
      : `/tools/${plan.targetEnv.envId}/[unknown]`,
    status: response.status,
    errorCode: requestErrorCode(response.body),
    denialId: denialIdentifier(response.headers),
    operationId: response.operationId ?? bodyIdentifier(response.body, 'operationId'),
    idempotencyKeyHash: createHash('sha256').update(idempotencyKey).digest('hex'),
  };
}

function denialRows(rows: Awaited<ReturnType<ProbeContext['database']['snapshot']>>[]): Array<Record<string, unknown>> {
  const byId = new Map<string, Record<string, unknown>>();
  for (const snapshot of rows) {
    for (const row of snapshot.denials) {
      const id = row.denial_id;
      if (typeof id === 'string') byId.set(id, row);
    }
  }
  return [...byId.values()];
}

function denialMatchesAttempt(attempt: ScopeAttempt, rows: Record<string, unknown>[]): Record<string, unknown> | null {
  if (!attempt.denialId) return null;
  return rows.find((row) => row.denial_id === attempt.denialId
    && row.env_id === attempt.targetEnvId
    && row.generation_id === attempt.claimedGenerationId
    && row.operation_id === null
    && row.route === attempt.path
    && typeof row.request_sha256 === 'string'
    && /^[0-9a-f]{64}$/i.test(row.request_sha256)) ?? null;
}

async function dbSnapshots(
  ctx: ProbeContext,
  selectors: Array<{ name: string; env: ProbeEnvironment; generationId: string }>,
  phase: 'before' | 'after',
): Promise<Map<string, Awaited<ReturnType<ProbeContext['database']['snapshot']>>>> {
  const result = new Map<string, Awaited<ReturnType<ProbeContext['database']['snapshot']>>>();
  for (const selector of selectors) {
    const rows = await ctx.database.snapshot({
      envId: selector.env.envId,
      generationId: selector.generationId,
      variantId: null,
      label: `sc003-${phase}-${selector.name}`,
    });
    result.set(selector.name, rows);
  }
  return result;
}

function hexQuantity(value: unknown, label: string): string {
  if (typeof value !== 'string' || !/^0x[0-9a-f]+$/i.test(value)) throw new Error(`probe_sc003_invalid_${label}`);
  return BigInt(value).toString(10);
}

async function rpcRead<T>(ctx: ProbeContext, env: ProbeEnvironment, method: string, params: unknown[], label: string): Promise<T> {
  const { result } = await ctx.rpc.call<T>({
    url: env.localRpcUrl,
    endpointBoundary: 'local-chain-readonly-proxy',
    environmentId: env.envId,
    method,
    params,
    operationId: null,
    variantId: null,
    label,
  });
  return result;
}

async function captureChainState(
  ctx: ProbeContext,
  env: ProbeEnvironment,
  phase: 'before' | 'after',
  accounts: Address[],
): Promise<ChainState> {
  const { manifest } = ctx.runtime;
  const chainId = await rpcRead<string>(ctx, env, 'eth_chainId', [], `sc003-${phase}-${env.envId}-chain-id`);
  if (chainId.toLowerCase() !== '0x2105') throw new Error(`probe_sc003_chain_identity_mismatch_${env.envId}`);
  const block = await rpcRead<{ number: string; hash: string }>(
    ctx,
    env,
    'eth_getBlockByNumber',
    ['latest', false],
    `sc003-${phase}-${env.envId}-latest-block`,
  );
  if (!block || typeof block.number !== 'string' || typeof block.hash !== 'string') {
    throw new Error(`probe_sc003_latest_block_invalid_${env.envId}`);
  }

  const uniqueAccounts = [...new Map(accounts.map((address) => [address.toLowerCase(), address])).values()];
  const accountState: ChainState['accounts'] = [];
  for (const address of uniqueAccounts) {
    const native = await rpcRead<string>(ctx, env, 'eth_getBalance', [address, 'latest'], `sc003-${phase}-${env.envId}-${address}-native`);
    const nonce = await rpcRead<string>(ctx, env, 'eth_getTransactionCount', [address, 'latest'], `sc003-${phase}-${env.envId}-${address}-nonce`);
    const balanceData = encodeFunctionData({ abi: SCOPE_ABI, functionName: 'balanceOf', args: [address] });
    const usdcAddress = manifest.contracts.usdc.address as Address;
    const swapRouterAddress = manifest.contracts.swapRouter02.address as Address;
    const balance = await rpcRead<string>(ctx, env, 'eth_call', [{ to: usdcAddress, data: balanceData }, 'latest'], `sc003-${phase}-${env.envId}-${address}-usdc`);
    const allowanceData = encodeFunctionData({
      abi: SCOPE_ABI,
      functionName: 'allowance',
      args: [address, swapRouterAddress],
    });
    const allowance = await rpcRead<string>(ctx, env, 'eth_call', [{ to: usdcAddress, data: allowanceData }, 'latest'], `sc003-${phase}-${env.envId}-${address}-allowance`);
    accountState.push({
      address,
      nativeBalanceWei: hexQuantity(native, 'native_balance'),
      transactionCount: hexQuantity(nonce, 'transaction_count'),
      usdcBalance: hexQuantity(balance, 'usdc_balance'),
      usdcAllowanceToSwapRouter02: hexQuantity(allowance, 'usdc_allowance'),
    });
  }

  const contractEntries: Array<[string, Address, string]> = [
    ['usdc', manifest.contracts.usdc.address as Address, manifest.contracts.usdc.proxyCodeHash],
    ['usdc-implementation', manifest.contracts.usdc.implementation as Address, manifest.contracts.usdc.implementationCodeHash],
    ['weth', manifest.contracts.weth.address as Address, manifest.contracts.weth.codeHash],
    ['factory', manifest.contracts.factory.address as Address, manifest.contracts.factory.codeHash],
    ['swap-router-02', manifest.contracts.swapRouter02.address as Address, manifest.contracts.swapRouter02.codeHash],
    ['quoter-v2', manifest.contracts.quoterV2.address as Address, manifest.contracts.quoterV2.codeHash],
    ['pool', manifest.contracts.pool.address as Address, manifest.contracts.pool.codeHash],
  ];
  const contractState: ChainState['contracts'] = [];
  for (const [name, address, expectedCodeHash] of contractEntries) {
    const code = await rpcRead<string>(ctx, env, 'eth_getCode', [address, 'latest'], `sc003-${phase}-${env.envId}-${name}-code`);
    if (typeof code !== 'string' || !/^0x(?:[0-9a-f]{2})*$/i.test(code)) throw new Error(`probe_sc003_contract_code_invalid_${name}`);
    const codeHash = keccak256(toBytes(code as Hex));
    if (codeHash.toLowerCase() !== expectedCodeHash.toLowerCase()) throw new Error(`probe_sc003_contract_identity_mismatch_${name}`);
    contractState.push({
      name,
      address,
      expectedCodeHash,
      codeHash,
      codeBytes: Math.max(0, (code.length - 2) / 2),
    });
  }

  return { envId: env.envId, chainId, latestBlock: { number: block.number, hash: block.hash }, accounts: accountState, contracts: contractState };
}

function stateDifference(before: ChainState[], after: ChainState[]): string[] {
  const beforeByEnv = new Map(before.map((state) => [state.envId, state]));
  const afterByEnv = new Map(after.map((state) => [state.envId, state]));
  const differences: string[] = [];
  for (const envId of new Set([...beforeByEnv.keys(), ...afterByEnv.keys()])) {
    if (stableJson(beforeByEnv.get(envId)) !== stableJson(afterByEnv.get(envId))) differences.push(envId);
  }
  return differences.sort();
}

async function writeScopeObservation(ctx: ProbeContext, observationId: string, payload: Record<string, unknown>): Promise<void> {
  const observation = {
    schemaVersion: 'bef-sc003-scope-observation/v1',
    boundary: 'participant-scope-and-protected-state',
    operationId: null,
    variantId: null,
    ...payload,
  } as unknown as RawObservation;
  await ctx.evidence.writeObservation(`scope/${observationId}.json`, observationId, observation);
}

/**
 * Exercise only the participant-facing HTTP boundary after private fixture
 * setup. A result is returned only when every request has a newly persisted,
 * independently read denial row and DB/RPC before-after projections agree.
 */
export async function runScopeScenario(ctx: ProbeContext): Promise<ScenarioExecution> {
  if (ctx.scenarioId !== 'BEF-SC-003') throw new Error('probe_sc003_wrong_scenario');

  const environmentIds = ctx.runtime.manifest.local.environments.map((entry) => entry.id);
  if (environmentIds.length !== 2) throw new Error('probe_sc003_requires_two_environments');
  const envA = runtimeEnvironment(ctx.runtime.manifest, environmentIds[0]!);
  const envB = runtimeEnvironment(ctx.runtime.manifest, environmentIds[1]!);
  ensureLocalOnly(ctx, [envA, envB]);
  if (envA.apiBaseUrl !== envB.apiBaseUrl || envA.adminKey !== envB.adminKey) {
    throw new Error('probe_sc003_environment_configuration_inconsistent');
  }

  // Capture capabilities as private setup evidence; they are not proof of a
  // denial or of an unchanged database/chain state.
  const [capabilityA, capabilityB] = await Promise.all([
    captureCapabilities(ctx, envA, 'sc003-capabilities-env-a'),
    captureCapabilities(ctx, envB, 'sc003-capabilities-env-b'),
  ]);
  await Promise.all([
    ctx.rpc.bindLocalEndpoint({
      url: envA.localRpcUrl,
      environmentId: envA.envId,
      manifestSha256: ctx.runtime.manifestSha256,
      label: 'sc003-local-rpc-endpoint-env-a',
    }),
    ctx.rpc.bindLocalEndpoint({
      url: envB.localRpcUrl,
      environmentId: envB.envId,
      manifestSha256: ctx.runtime.manifestSha256,
      label: 'sc003-local-rpc-endpoint-env-b',
    }),
  ]);
  const implementation = recordOf(recordOf(capabilityA.implemented)?.sc003);
  const implementationB = recordOf(recordOf(capabilityB.implemented)?.sc003);
  const advertisedVariants = Array.isArray(implementation?.variants) ? implementation.variants : [];
  const advertisedVariantsB = Array.isArray(implementationB?.variants) ? implementationB.variants : [];
  const requiredVariants = [
    'foreign_environment', 'stale_generation', 'arbitrary_url', 'raw_transaction', 'admin_rpc',
    'learning_error_claim_for_foreign_or_admin_access', 'real_fund_or_external_write_route',
    'request_exceeds_preexecution_resource_bound',
  ];
  const hookFlags = recordOf(implementation?.hooks);
  const requiredHookFlags = [
    'authScopeDenialAudit',
    'requestValidationDenialAudit',
    'unknownRouteDenialAudit',
    'bodyLimitDenialAudit',
    'denialIdResponseHeader',
  ];
  const missingHookFlags = requiredHookFlags.filter((flag) => hookFlags?.[flag] !== true);
  const hookFlagsB = recordOf(implementationB?.hooks);
  const missingHookFlagsB = requiredHookFlags.filter((flag) => hookFlagsB?.[flag] !== true);
  const identityCapabilitiesMatch = capabilityA.envId === envA.envId
    && capabilityB.envId === envB.envId
    && capabilityA.manifestSha256 === ctx.runtime.manifestSha256
    && capabilityB.manifestSha256 === ctx.runtime.manifestSha256
    && capabilityA.applicationSourceSha256 === ctx.runtime.appSourceSha256
    && capabilityB.applicationSourceSha256 === ctx.runtime.appSourceSha256
    && capabilityA.ready === true
    && capabilityB.ready === true;
  if (implementation?.supported !== true
    || implementationB?.supported !== true
    || requiredVariants.some((variant) => !advertisedVariants.includes(variant))
    || requiredVariants.some((variant) => !advertisedVariantsB.includes(variant))
    || missingHookFlags.length > 0
    || missingHookFlagsB.length > 0
    || !identityCapabilitiesMatch) {
    const missing = [...missingHookFlags, ...missingHookFlagsB.map((flag) => `env-b:${flag}`)];
    throw new Error(`probe_sc003_runtime_capability_not_advertised:${missing.join(',') || 'identity_variants_or_supported'}`);
  }

  // First create a real generation, then reset its environment to make that
  // token stale; the final A and B generations remain isolated test subjects.
  await resetEnvironment(ctx, envA, 'sc003-setup-reset-env-a-before-stale');
  const staleA = await createGeneration(ctx, envA, 'sc003-setup-generation-stale-a');
  await resetEnvironment(ctx, envA, 'sc003-setup-fence-stale-a');
  const currentA = await createGeneration(ctx, envA, 'sc003-setup-generation-current-a');
  await resetEnvironment(ctx, envB, 'sc003-setup-reset-env-b');
  const foreignB = await createGeneration(ctx, envB, 'sc003-setup-generation-foreign-b');
  ctx.primaryGeneration = {
    envId: currentA.envId,
    generationId: currentA.generationId,
    participantId: currentA.participantId,
    payerAddress: currentA.payerAddress,
  };

  const selectors = [
    { name: 'stale-a', env: envA, generationId: staleA.generationId },
    { name: 'current-a', env: envA, generationId: currentA.generationId },
    { name: 'foreign-b-owner', env: envB, generationId: foreignB.generationId },
    // The cross-environment selector catches an operation mistakenly created
    // under the target environment with the claimed foreign generation ID.
    { name: 'foreign-b-at-target-a', env: envA, generationId: foreignB.generationId },
  ];

  const setupArtifacts = await Promise.all([
    ctx.database.snapshot({ envId: envA.envId, generationId: staleA.generationId, variantId: null, label: 'sc003-setup-stale-generation' }),
    ctx.database.snapshot({ envId: envA.envId, generationId: currentA.generationId, variantId: null, label: 'sc003-setup-current-generation' }),
    ctx.database.snapshot({ envId: envB.envId, generationId: foreignB.generationId, variantId: null, label: 'sc003-setup-foreign-generation' }),
  ]);
  if (setupArtifacts[0]!.generation[0]?.status !== 'fenced'
    || setupArtifacts[1]!.generation[0]?.status !== 'active'
    || setupArtifacts[2]!.generation[0]?.status !== 'active') {
    throw new Error('probe_sc003_generation_setup_state_invalid');
  }

  const payerAddresses = [staleA.payerAddress, currentA.payerAddress, foreignB.payerAddress] as Address[];
  const donorAddress = ctx.runtime.manifest.funding.donor as Address;
  const facilitatorA = recordOf(recordOf(capabilityA.services)?.facilitator);
  const facilitatorB = recordOf(recordOf(capabilityB.services)?.facilitator);
  const facilAAddress = facilitatorA?.address as Address | undefined;
  const facilBAddress = facilitatorB?.address as Address | undefined;
  if (!facilAAddress || !/^0x[0-9a-f]{40}$/i.test(facilAAddress)
    || !facilBAddress || !/^0x[0-9a-f]{40}$/i.test(facilBAddress)) {
    throw new Error('probe_sc003_facilitator_identity_missing');
  }
  const addresses = [...payerAddresses, donorAddress, facilAAddress, facilBAddress];

  const databaseBefore = await dbSnapshots(ctx, selectors, 'before');
  const chainBefore = await Promise.all([
    captureChainState(ctx, envA, 'before', addresses),
    captureChainState(ctx, envB, 'before', addresses),
  ]);

  const requestBodyForSize = { resourceId: ctx.runtime.manifest.x402.resourceId, padding: '' };
  const maxRequestBytes = ctx.runtime.manifest.guardrails.maxHttpRequestBytes;
  requestBodyForSize.padding = 'x'.repeat(maxRequestBytes + 1024);
  while (Buffer.byteLength(JSON.stringify(requestBodyForSize), 'utf8') <= maxRequestBytes) {
    requestBodyForSize.padding += 'x';
  }

  const plans: AttemptPlan[] = [
    {
      variantId: 'foreign_environment', label: 'sc003-foreign-environment-offer', method: 'GET',
      path: `/tools/${envA.envId}/offer`, query: `?resourceId=${encodeURIComponent(ctx.runtime.manifest.x402.resourceId)}`,
      session: foreignB, targetEnv: envA,
    },
    {
      variantId: 'stale_generation', label: 'sc003-stale-generation-offer', method: 'GET',
      path: `/tools/${envA.envId}/offer`, query: `?resourceId=${encodeURIComponent(ctx.runtime.manifest.x402.resourceId)}`,
      session: staleA, targetEnv: envA,
    },
    {
      variantId: 'arbitrary_url', label: 'sc003-arbitrary-url-purchase', method: 'POST',
      path: `/tools/${envA.envId}/purchase`,
      body: { resourceId: ctx.runtime.manifest.x402.resourceId, url: 'https://example.invalid/never-fetch-this' },
      session: currentA, targetEnv: envA,
    },
    {
      variantId: 'raw_transaction', label: 'sc003-raw-transaction-purchase', method: 'POST',
      path: `/tools/${envA.envId}/purchase`,
      // This is deliberately the empty invalid marker, not a signed payload.
      body: { resourceId: ctx.runtime.manifest.x402.resourceId, method: 'eth_sendRawTransaction', rawTransaction: '0x' },
      session: currentA, targetEnv: envA,
    },
    {
      variantId: 'admin_rpc', label: 'sc003-participant-admin-rpc', method: 'POST',
      path: `/tools/${envA.envId}/admin/rpc`,
      // Read-only admin method candidate: even a misrouted request cannot
      // impersonate an account or mutate the local chain.
      body: { method: 'anvil_getAutomine', params: [] },
      session: currentA, targetEnv: envA,
    },
    {
      variantId: 'learning_error_claim_for_foreign_or_admin_access', label: 'sc003-learning-error-foreign-claim', method: 'POST',
      path: `/tools/${envA.envId}/purchase`,
      body: { resourceId: ctx.runtime.manifest.x402.resourceId, learningErrorClaim: true },
      session: foreignB, targetEnv: envA,
    },
    {
      variantId: 'real_fund_or_external_write_route', label: 'sc003-external-write-purchase', method: 'POST',
      path: `/tools/${envA.envId}/purchase`,
      body: {
        resourceId: ctx.runtime.manifest.x402.resourceId,
        targetUrl: 'https://example.invalid/never-fetch-this',
        method: 'eth_sendTransaction',
        params: [{ from: 'not-an-address', to: 'not-an-address', value: '0x' }],
      },
      session: currentA, targetEnv: envA,
    },
    {
      variantId: 'request_exceeds_preexecution_resource_bound', label: 'sc003-oversized-participant-body', method: 'POST',
      path: `/tools/${envA.envId}/purchase`, body: requestBodyForSize,
      session: currentA, targetEnv: envA,
    },
  ];

  const attempts: ScopeAttempt[] = [];
  for (const plan of plans) attempts.push(await participantRequest(ctx, plan));

  const databaseAfter = await dbSnapshots(ctx, selectors, 'after');
  const chainAfter = await Promise.all([
    captureChainState(ctx, envA, 'after', addresses),
    captureChainState(ctx, envB, 'after', addresses),
  ]);

  const databaseComparisons = selectors.map((selector) => {
    const before = databaseBefore.get(selector.name);
    const after = databaseAfter.get(selector.name);
    const beforeProjection = before ? protectedDbProjection(before) : null;
    const afterProjection = after ? protectedDbProjection(after) : null;
    return {
      selector: selector.name,
      envId: selector.env.envId,
      generationId: selector.generationId,
      unchanged: beforeProjection !== null && afterProjection !== null && stableJson(beforeProjection) === stableJson(afterProjection),
      before: beforeProjection,
      after: afterProjection,
    };
  });
  const beforeDenials = denialRows([...databaseBefore.values()]);
  const afterDenials = denialRows([...databaseAfter.values()]);
  const beforeDenialIds = new Set(beforeDenials.map((row) => String(row.denial_id)));
  const newDenials = afterDenials.filter((row) => !beforeDenialIds.has(String(row.denial_id)));
  const beforeOperationIds = new Set(selectors.flatMap((selector) =>
    (databaseBefore.get(selector.name)?.operations ?? []).map((row) => String(row.operation_id))));
  const afterOperationRows = selectors.flatMap((selector) => databaseAfter.get(selector.name)?.operations ?? []);
  const indexedUnexpectedOperationIds = new Set<string>();
  for (const row of afterOperationRows) {
    const operationId = row.operation_id;
    if (typeof operationId !== 'string' || beforeOperationIds.has(operationId) || ctx.operations.has(operationId)) continue;
    const receiptStatus = row.receipt_status === 'success' || row.receipt_status === 'reverted'
      || row.receipt_status === 'not_submitted'
      ? row.receipt_status
      : 'unknown';
    ctx.operations.set(operationId, {
      operationId,
      kind: typeof row.operation_kind === 'string' ? row.operation_kind : 'scope-denial-unexpected-operation',
      idempotencyKeyHash: typeof row.idempotency_key_sha256 === 'string' ? row.idempotency_key_sha256 : 'unknown',
      observedStatus: typeof row.status === 'string' ? row.status : 'unknown',
      transactionHash: typeof row.transaction_hash === 'string' ? row.transaction_hash : null,
      receiptStatus,
    });
    indexedUnexpectedOperationIds.add(operationId);
  }
  for (const attempt of attempts) {
    if (!attempt.operationId || ctx.operations.has(attempt.operationId)) continue;
    ctx.operations.set(attempt.operationId, {
      operationId: attempt.operationId,
      kind: 'scope-denial-unexpected-http-operation-id',
      idempotencyKeyHash: attempt.idempotencyKeyHash,
      observedStatus: `http_${attempt.status}`,
      transactionHash: null,
      receiptStatus: 'unknown',
    });
    indexedUnexpectedOperationIds.add(attempt.operationId);
  }
  const attemptAssessments = attempts.map((attempt) => {
    const denial = denialMatchesAttempt(attempt, newDenials);
    return {
      variantId: attempt.variantId,
      status: attempt.status,
      errorCode: attempt.errorCode,
      denialId: attempt.denialId,
      operationId: attempt.operationId,
      idempotencyKeyHash: attempt.idempotencyKeyHash,
      denied: attempt.status >= 400 && attempt.status < 500,
      independentlyAudited: Boolean(denial),
      denialRow: denial ? {
        denial_id: denial.denial_id,
        env_id: denial.env_id,
        generation_id: denial.generation_id,
        operation_id: denial.operation_id,
        route: denial.route,
        reason_code: denial.reason_code,
        request_sha256: denial.request_sha256,
      } : null,
    };
  });
  const missingAuditVariants = attemptAssessments.filter((item) => !item.independentlyAudited).map((item) => item.variantId);
  const nonDeniedVariants = attemptAssessments.filter((item) => !item.denied).map((item) => item.variantId);
  const databaseChangedSelectors = databaseComparisons.filter((item) => !item.unchanged).map((item) => item.selector);
  const changedChains = stateDifference(chainBefore, chainAfter);
  const newlyCreatedBusinessRows = databaseComparisons.flatMap((comparison) => {
    const after = comparison.after;
    if (!after) return [`${comparison.selector}:missing_after_snapshot`];
    const before = comparison.before as DatabaseProjection;
    const afterProjection = after as DatabaseProjection;
    return (['operations', 'payments', 'deliveries', 'x402Observations'] as const)
      .filter((key) => stableJson(before?.[key] ?? []) !== stableJson(afterProjection[key] ?? []))
      .map((key) => `${comparison.selector}:${key}`);
  });

  await writeScopeObservation(ctx, 'sc003-attempt-assessment', {
    scenarioId: 'BEF-SC-003',
    requiredVariants,
    advertisedVariants,
    capabilityAdvertisesSc003: implementation?.supported === true,
    attempts: attemptAssessments,
    missingAuditVariants,
    nonDeniedVariants,
    databaseComparisons,
    databaseChangedSelectors,
    databaseBusinessRowChanges: newlyCreatedBusinessRows,
    unexpectedOperationIds: [...indexedUnexpectedOperationIds].sort(),
    chainBefore,
    chainAfter,
    changedChains,
    auditStatus: missingAuditVariants.length ? 'missing_or_unbound' : 'verified_by_denial_id_and_readonly_database_row',
    stateStatus: databaseChangedSelectors.length || newlyCreatedBusinessRows.length || changedChains.length
      ? 'changed_or_unverified'
      : 'unchanged_by_independent_db_and_rpc_reads',
    setupIdentities: {
      environmentA: envA.envId,
      environmentB: envB.envId,
      staleGenerationId: staleA.generationId,
      currentGenerationId: currentA.generationId,
      foreignGenerationId: foreignB.generationId,
      payerAddresses: addresses.map((address) => address.toLowerCase()),
    },
    missingRuntimeHooks: REQUIRED_RUNTIME_HOOKS,
    requiredReadonlyEvidenceColumns: REQUIRED_READONLY_EVIDENCE_COLUMNS,
  });

  if (nonDeniedVariants.length) throw new Error(`probe_sc003_requests_not_denied:${nonDeniedVariants.join(',')}`);
  if (databaseChangedSelectors.length || newlyCreatedBusinessRows.length || changedChains.length) {
    throw new Error('probe_sc003_protected_state_changed');
  }
  if (missingAuditVariants.length) throw new Error(`probe_sc003_denial_audit_unavailable:${missingAuditVariants.join(',')}`);
  if (implementation?.supported !== true || requiredVariants.some((variant) => !advertisedVariants.includes(variant))) {
    throw new Error('probe_sc003_runtime_capability_not_advertised');
  }

  return {
    environment: {
      envId: currentA.envId,
      generation: {
        generationId: currentA.generationId,
        participantId: currentA.participantId,
        payerAddress: currentA.payerAddress,
      },
    },
  };
}

export const runScenario003 = runScopeScenario;
