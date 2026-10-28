/**
 * Draft for packages/benchmark-environment/src/probe/resource-workload.ts.
 * Kept under ignored artifacts/runs while the accepted runtime is frozen.
 */
import { createHash, randomUUID } from 'node:crypto';
import { appendFile, mkdir, readFile, readdir, rename, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { encodeFunctionData } from 'viem';
import type { Address } from 'viem';
import {
  apiPath,
  findRepositoryRoot,
  loadProbeRuntime,
  newParticipantId,
  runtimeEnvironment,
  sourceDigests,
} from './environment.js';
import { EvidenceWriter, sanitizeValue, sha256Bytes } from './evidence.js';
import { DatabaseObserver } from './observer.js';
import { ReadOnlyRpcEvidence } from './rpc.js';
import { HttpEvidenceTransport } from './transport.js';
import {
  captureCapabilities,
  missingCapabilityPrerequisites,
  runCanonicalPurchase,
  type ProbeCapabilityDocument,
  type ProbeContext,
  type GenerationSession,
} from './runner.js';
import { createEphemeralSigner } from './x402.js';
import type { ProbeScenarioId } from './types.js';

type Mode = 'purchase' | 'read-loop' | 'fence' | 'fence-active' | 'isolation-snapshot';
type Phase = 'cold' | 'warm' | 'guardrail_exceeded';
type FencePurpose = 'readonly_guardrail' | 'protective_only' | 'trial_cleanup';
type Options = {
  mode: Mode;
  phase: Phase;
  envId: string;
  evidenceDirectory: string;
  markerPath?: string;
  continuePath?: string;
};

const TOKEN_ABI = [{
  type: 'function',
  name: 'balanceOf',
  stateMutability: 'view',
  inputs: [{ name: 'account', type: 'address' }],
  outputs: [{ name: '', type: 'uint256' }],
}] as const;

function parseArgs(argv: string[]): Options {
  let mode: string | undefined;
  let phase: string | undefined;
  let envId: string | undefined;
  let evidenceDirectory: string | undefined;
  let markerPath: string | undefined;
  let continuePath: string | undefined;
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === '--mode') mode = argv[++index];
    else if (arg === '--phase') phase = argv[++index];
    else if (arg === '--env-id') envId = argv[++index];
    else if (arg === '--evidence-dir') evidenceDirectory = argv[++index];
    else if (arg === '--marker') markerPath = argv[++index];
    else if (arg === '--continue-file') continuePath = argv[++index];
    else throw new Error('usage: resource-workload --mode purchase|read-loop|fence|isolation-snapshot --phase cold|warm|guardrail_exceeded --env-id ID --evidence-dir PATH [--marker PATH]');
  }
  if (!['purchase', 'read-loop', 'fence', 'fence-active', 'isolation-snapshot'].includes(mode ?? '')
    || !['cold', 'warm', 'guardrail_exceeded'].includes(phase ?? '')
    || !envId || !/^[a-z][a-z0-9-]{1,31}$/.test(envId)
    || !evidenceDirectory
    || ((mode === 'fence' || mode === 'read-loop' || mode === 'fence-active') && !markerPath)
    || (mode === 'read-loop' && !continuePath)) {
    throw new Error('usage: resource-workload --mode purchase|read-loop|fence|isolation-snapshot --phase cold|warm|guardrail_exceeded --env-id ID --evidence-dir PATH [--marker PATH] [--continue-file PATH]');
  }
  return {
    mode: mode as Mode,
    phase: phase as Phase,
    envId,
    evidenceDirectory,
    ...(markerPath ? { markerPath } : {}),
    ...(continuePath ? { continuePath } : {}),
  };
}

function recordOf(value: unknown): Record<string, unknown> | null {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    ? value as Record<string, unknown>
    : null;
}

function safeErrorCode(error: unknown): string {
  const text = error instanceof Error ? error.message : '';
  return /^probe_[a-z0-9_]+$/i.test(text) || /^resource_workload_[a-z0-9_]+$/i.test(text)
    ? text
    : 'resource_workload_failed';
}

async function assertEmptyDirectory(directory: string): Promise<void> {
  await mkdir(directory, { recursive: true });
  if ((await readdir(directory)).length !== 0) throw new Error('resource_workload_evidence_directory_not_empty');
}

async function writeJsonNew(path: string, value: unknown): Promise<string> {
  const bytes = Buffer.from(`${JSON.stringify(value, null, 2)}\n`, 'utf8');
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, bytes, { flag: 'wx' });
  return sha256Bytes(bytes);
}

async function writeJsonAtomic(path: string, value: unknown): Promise<void> {
  const temporary = `${path}.${randomUUID()}.tmp`;
  const bytes = Buffer.from(`${JSON.stringify(value, null, 2)}\n`, 'utf8');
  await mkdir(dirname(path), { recursive: true });
  await writeFile(temporary, bytes, { flag: 'wx' });
  await rename(temporary, path);
}

async function writeMarkerAtomically(path: string, value: unknown): Promise<void> {
  const temporary = path + '.' + randomUUID() + '.pending';
  await writeJsonNew(temporary, value);
  await rename(temporary, path);
}

function runtimeVersionSummary(context: ProbeContext): Record<string, string> {
  const capability = context.capability;
  const dependencies = capability.dependencyVersions ?? {};
  const services = capability.services ?? {};
  const serviceRecord = (value: unknown): Record<string, unknown> => recordOf(value) ?? {};
  const localRpc = serviceRecord(serviceRecord(services).localRpc);
  const facilitator = serviceRecord(serviceRecord(services).facilitator);
  return Object.fromEntries(Object.entries({
    probeNode: process.version,
    apiNode: capability.apiNodeVersion,
    apiPackage: capability.apiPackageVersion,
    fastify: dependencies.fastify,
    x402Core: dependencies.x402Core ?? dependencies['@x402/core'],
    x402Evm: dependencies.x402Evm ?? dependencies['@x402/evm'],
    x402Fastify: dependencies.x402Fastify ?? dependencies['@x402/fastify'],
    viem: dependencies.viem,
    postgresDriver: dependencies.postgresDriver ?? dependencies.pg,
    anvil: localRpc.clientVersion,
    facilitatorNode: facilitator.nodeVersion,
    postgresql: context.database.observedPostgresVersion,
  }).filter((entry): entry is [string, string] => typeof entry[1] === 'string' && entry[1].length > 0));
}

async function createContext(options: Options): Promise<{
  context: ProbeContext;
  capability: ProbeCapabilityDocument;
  sourceDigestsAtStart: { appSourceSha256: string; probeSourceSha256: string };
}> {
  const runtime = await loadProbeRuntime();
  if (!runtime.manifest.local.environments.some((environment) => environment.id === options.envId)) {
    throw new Error('resource_workload_environment_not_in_manifest');
  }
  const env = runtimeEnvironment(runtime.manifest, options.envId);
  const evidence = new EvidenceWriter(options.evidenceDirectory);
  await evidence.initialize();
  const database = new DatabaseObserver(env.databaseObserverUrl, evidence);
  try {
    await database.verifyReadOnlyRole();
    await evidence.writeManifestCopy(runtime.manifestBytes);
    await database.writePrivilegeObservation();
    const context: ProbeContext = {
      scenarioId: 'BEF-SC-011' as ProbeScenarioId,
      runtime,
      env,
      evidence,
      transport: new HttpEvidenceTransport(
        evidence,
        [env.adminKey, env.serviceKey],
        10_000,
        runtime.manifest.guardrails.maxTrialSeconds * 1_000,
      ),
      rpc: new ReadOnlyRpcEvidence(evidence),
      database,
      secretValues: [env.adminKey, env.serviceKey],
      operations: new Map(),
      replayedOriginalCaptures: [],
      capability: {} as ProbeCapabilityDocument,
      primaryGeneration: null,
      primarySession: null,
      sequence: 0,
    };
    const capability = await captureCapabilities(context);
    context.capability = capability;
    const missing = missingCapabilityPrerequisites(
      'BEF-SC-005', capability, runtime.manifestSha256, runtime.appSourceSha256, options.envId,
    );
    if (missing.length) throw new Error('resource_workload_sc005_capability_missing');
    await context.rpc.bindLocalEndpoint({
      url: env.localRpcUrl,
      environmentId: env.envId,
      manifestSha256: runtime.manifestSha256,
      label: `sc011-${options.phase}-local-rpc-identity`,
    });
    const deadlineAt = Date.now() + runtime.manifest.guardrails.maxTrialSeconds * 1_000;
    context.transport.setDeadlineAt(deadlineAt);
    context.rpc.setDeadlineAt(deadlineAt);
    database.setDeadlineAt(deadlineAt);
    return { context, capability, sourceDigestsAtStart: await sourceDigests(runtime.root) };
  } catch (error) {
    await database.close().catch(() => undefined);
    throw error;
  }
}

function baseReport(context: ProbeContext, options: Options, status: string): Record<string, unknown> {
  const variantId = options.phase === 'cold'
    ? 'empty_dedicated_cache'
    : options.phase === 'warm' ? 'warm_cache' : 'guardrail_exceeded';
  return {
    schemaVersion: 'bef-resource-purchase-workload/v1',
    boundary: 'resource-workload',
    scenarioId: 'BEF-SC-011',
    phase: options.phase,
    mode: options.mode,
    variantId,
    status,
    environmentId: context.env.envId,
    manifestSha256: context.runtime.manifestSha256,
    applicationSourceSha256: context.runtime.appSourceSha256,
    probeSourceSha256: context.runtime.probeSourceSha256,
    sourceBlock: {
      number: context.runtime.manifest.source.blockNumber,
      hash: context.runtime.manifest.source.blockHash,
    },
    runtimeVersions: runtimeVersionSummary(context),
    operations: [...context.operations.values()],
    observations: context.evidence.observations,
    artifacts: context.evidence.artifacts,
    providerComputeUnits: { status: 'unknown', value: null },
  };
}

async function writeWorkloadReport(context: ProbeContext, options: Options, extra: Record<string, unknown>): Promise<string> {
  const report = { ...baseReport(context, options, 'captured'), ...extra };
  const path = resolve(options.evidenceDirectory, 'workload.json');
  return writeJsonNew(path, report);
}

function participantHeaders(session: GenerationSession, idempotencyKey: string): Record<string, string> {
  return {
    authorization: `Bearer ${session.runToken}`,
    'X-BEF-Generation': session.generationId,
    'Idempotency-Key': idempotencyKey,
  };
}

async function adminRequest(context: ProbeContext, label: string, method: string, path: string, variantId: string | null, body?: unknown) {
  return context.transport.request({
    boundary: 'private-admin-http',
    observationId: label,
    method,
    url: apiPath(context.env.apiBaseUrl, path),
    headers: {
      'X-BEF-Admin-Key': context.env.adminKey,
      ...(body === undefined ? {} : { 'content-type': 'application/json' }),
    },
    ...(body === undefined ? {} : { body }),
    operationId: null,
    variantId,
  });
}

async function resetBeforeReadTrial(context: ProbeContext): Promise<void> {
  const route = context.capability.reset?.route?.replace(/^POST\s+/i, '').replace('{envId}', context.env.envId);
  if (!route || !route.startsWith('/internal/admin/environments/')) throw new Error('resource_workload_reset_capability_missing');
  const response = await adminRequest(context, 'sc011-guardrail-reset', 'POST', route, 'guardrail_exceeded');
  if (response.status < 200 || response.status >= 300) throw new Error(`resource_workload_reset_failed_${response.status}`);
}

async function createReadOnlyGeneration(context: ProbeContext, phase: Phase): Promise<GenerationSession> {
  const signer = createEphemeralSigner();
  context.secretValues.push(signer.privateKey);
  const participantId = newParticipantId('BEF-SC-011');
  const response = await adminRequest(
    context,
    `sc011-${phase}-generation-create`,
    'POST',
    `/internal/admin/environments/${context.env.envId}/generations`,
    'guardrail_exceeded',
    { participantId, payerAddress: signer.payerAddress, resourceVariant: 'canonical' },
  );
  if (response.status < 200 || response.status >= 300) throw new Error(`resource_workload_generation_failed_${response.status}`);
  const body = recordOf(response.body);
  const generationId = body?.generationId;
  const envId = body?.envId;
  const payerAddress = body?.payerAddress;
  const runToken = body?.runToken ?? recordOf(body?.participant)?.runToken;
  if (typeof generationId !== 'string' || typeof envId !== 'string'
    || typeof payerAddress !== 'string' || typeof runToken !== 'string'
    || envId !== context.env.envId || payerAddress.toLowerCase() !== signer.payerAddress.toLowerCase()) {
    throw new Error('resource_workload_generation_identity_invalid');
  }
  context.secretValues.push(runToken);
  const session: GenerationSession = {
    envId,
    generationId,
    participantId,
    payerAddress: signer.payerAddress,
    runToken,
    signer,
  };
  context.primaryGeneration = { envId, generationId, participantId, payerAddress: session.payerAddress };
  context.primarySession = session;
  return session;
}

async function protectedState(
  context: ProbeContext,
  account: Address,
  label: string,
  variantId: string,
): Promise<Record<string, unknown>> {
  const local = context.env.localRpcUrl;
  const envId = context.env.envId;
  const token = context.runtime.manifest.contracts.usdc.address as Address;
  const native = await context.rpc.call({
    url: local, endpointBoundary: 'local-chain-readonly-proxy', environmentId: envId,
    method: 'eth_getBalance', params: [account, 'latest'], requestedBlock: 'latest',
    operationId: null, variantId, label: `${label}-native-balance`,
  });
  const nonce = await context.rpc.call({
    url: local, endpointBoundary: 'local-chain-readonly-proxy', environmentId: envId,
    method: 'eth_getTransactionCount', params: [account, 'latest'], requestedBlock: 'latest',
    operationId: null, variantId, label: `${label}-nonce`,
  });
  const data = encodeFunctionData({ abi: TOKEN_ABI, functionName: 'balanceOf', args: [account] });
  const tokenBalance = await context.rpc.call({
    url: local, endpointBoundary: 'local-chain-readonly-proxy', environmentId: envId,
    method: 'eth_call', params: [{ to: token, data }, 'latest'], requestedBlock: 'latest',
    operationId: null, variantId, label: `${label}-token-balance`,
  });
  const code = await context.rpc.call({
    url: local, endpointBoundary: 'local-chain-readonly-proxy', environmentId: envId,
    method: 'eth_getCode', params: [token, 'latest'], requestedBlock: 'latest',
    operationId: null, variantId, label: `${label}-token-code`,
  });
  return {
    account,
    nativeBalance: native.result,
    transactionCount: nonce.result,
    tokenBalance: tokenBalance.result,
    tokenCodeSha256: sha256Bytes(Buffer.from(String(code.result).slice(2), 'hex')),
  };
}

async function protectedStateSnapshot(context: ProbeContext, payerAddress: Address, label: string, variantId: string | null): Promise<Record<string, unknown>> {
  const chain = await context.rpc.call({
    url: context.env.localRpcUrl,
    endpointBoundary: 'local-chain-readonly-proxy',
    environmentId: context.env.envId,
    method: 'eth_chainId',
    params: [],
    requestedBlock: 'latest',
    operationId: null,
    variantId,
    label: `${label}-chain-id`,
  });
  const head = await context.rpc.call({
    url: context.env.localRpcUrl,
    endpointBoundary: 'local-chain-readonly-proxy',
    environmentId: context.env.envId,
    method: 'eth_getBlockByNumber',
    params: ['latest', false],
    requestedBlock: 'latest',
    operationId: null,
    variantId,
    label: `${label}-head`,
  });
  const payer = await protectedState(context, payerAddress, `${label}-payer`, variantId ?? 'primary');
  return { chainId: chain.result, head: head.result, payer };
}

const BALANCE_READ_FIELDS = [
  'blockNumber',
  'payerNativeWei',
  'payerWethUnits',
  'payerUsdcUnits',
  'recipientWethUnits',
  'recipientUsdcUnits',
  'wethRouterAllowance',
  'usdcRouterAllowance',
  'poolWethUnits',
  'poolUsdcUnits',
  'poolLiquidity',
  'poolSqrtPriceX96',
] as const;
const UINT_DECIMAL = /^(?:0|[1-9][0-9]{0,77})$/;

function isBalanceSnapshot(value: unknown): boolean {
  const balances = recordOf(value);
  if (!balances) return false;
  const keys = Object.keys(balances);
  return keys.length === BALANCE_READ_FIELDS.length
    && BALANCE_READ_FIELDS.every((field) => Object.hasOwn(balances, field) && typeof balances[field] === 'string' && UINT_DECIMAL.test(balances[field] as string));
}

export function readResponseMatchesGeneration(
  value: unknown,
  session: Pick<GenerationSession, 'envId' | 'generationId' | 'payerAddress'>,
): boolean {
  const body = recordOf(value);
  return body?.boundary === 'local-chain-readonly-proxy'
    && body.envId === session.envId
    && body.generationId === session.generationId
    && typeof body.payer === 'string'
    && body.payer.toLowerCase() === session.payerAddress.toLowerCase()
    && isBalanceSnapshot(body.balances);
}

function stableState(value: unknown): string {
  return JSON.stringify(value, (_key, child) => child instanceof Date ? child.toISOString() : child);
}

function rowSetsMatch(before: Awaited<ReturnType<DatabaseObserver['snapshot']>>, after: Awaited<ReturnType<DatabaseObserver['snapshot']>>): boolean {
  return stableState(before.operations) === stableState(after.operations)
    && stableState(before.payments) === stableState(after.payments)
    && stableState(before.deliveries) === stableState(after.deliveries)
    && stableState(before.denials) === stableState(after.denials)
    && stableState(before.x402Observations) === stableState(after.x402Observations);
}

function persistedEffectsEqual(left: unknown, right: unknown): boolean {
  const before = recordOf(left);
  const after = recordOf(right);
  if (!before || !after) return false;
  return ['operations', 'payments', 'deliveries', 'denials', 'x402Observations'].every((key) =>
    Array.isArray(before[key]) && Array.isArray(after[key]) && stableState(before[key]) === stableState(after[key]));
}

async function appendReadProgress(path: string, value: Record<string, unknown>): Promise<void> {
  const bytes = Buffer.from(`${JSON.stringify(value)}\n`, 'utf8');
  await appendFile(path, bytes, { flag: 'a' });
}

async function runPurchase(options: Options): Promise<void> {
  await assertEmptyDirectory(options.evidenceDirectory);
  const { context, sourceDigestsAtStart } = await createContext(options);
  let status: 'captured' | 'error' = 'captured';
  let errorCode: string | undefined;
  let execution: Awaited<ReturnType<typeof runCanonicalPurchase>> | null = null;
  try {
    execution = await runCanonicalPurchase(context, `sc011-${options.phase}`);
    const current = await sourceDigests(context.runtime.root);
    if (current.appSourceSha256 !== sourceDigestsAtStart.appSourceSha256
      || current.probeSourceSha256 !== sourceDigestsAtStart.probeSourceSha256) {
      throw new Error('resource_workload_source_changed_during_trial');
    }
  } catch (error) {
    status = 'error';
    errorCode = safeErrorCode(error);
  }
  const operations = [...context.operations.values()];
  const purchase = operations.find((operation) => operation.kind === 'purchase' && operation.receiptStatus === 'success');
  const report = {
    ...baseReport(context, options, status),
    ...(execution ? { environment: execution.environment } : {}),
    operationId: purchase?.operationId ?? null,
    purchaseOperation: purchase ?? null,
    ...(errorCode ? { errorCode } : {}),
  };
  await writeJsonNew(resolve(options.evidenceDirectory, 'workload.json'), report);
  await context.database.close();
  process.stdout.write(`status=${status} mode=purchase phase=${options.phase} operations=${operations.length}\n`);
  if (status !== 'captured' || !purchase) process.exitCode = 2;
}

async function readOnlyDatabaseSnapshot(context: ProbeContext, envId: string, label: string): Promise<Record<string, unknown>> {
  const Pool = (await import('pg')).default.Pool;
  const pool = new Pool({ connectionString: context.env.databaseObserverUrl, max: 1, connectionTimeoutMillis: 5_000, statement_timeout: 5_000 });
  const client = await pool.connect();
  try {
    await client.query('BEGIN READ ONLY');
    const generations = await client.query(
      `SELECT generation_id, status, created_at, fenced_at
       FROM bef_generation WHERE env_id=$1 ORDER BY generation_id`, [envId],
    );
    const operations = await client.query(
      `SELECT status, count(*)::text AS row_count
       FROM bef_operation WHERE env_id=$1 GROUP BY status ORDER BY status`, [envId],
    );
    const role = await client.query<{ role_name: string }>('SELECT current_user AS role_name');
    if (role.rows[0]?.role_name !== context.database.databaseRole) throw new Error('resource_workload_observer_role_changed');
    await client.query('COMMIT');
    const result = { envId, generations: generations.rows, operationStatusCounts: operations.rows };
    await context.evidence.writeObservation(`db/${label}.json`, label, {
      schemaVersion: 'bef-db-observation/v1', boundary: 'readonly-database', operationId: null,
      variantId: null, readOnly: true, databaseRole: context.database.databaseRole,
      queryName: 'sc011-environment-isolation-state', rows: result,
    });
    return result;
  } catch (error) {
    await client.query('ROLLBACK').catch(() => undefined);
    throw error;
  } finally {
    client.release();
    await pool.end();
  }
}

async function runIsolationSnapshot(options: Options): Promise<void> {
  await assertEmptyDirectory(options.evidenceDirectory);
  const { context } = await createContext(options);
  const others = context.runtime.manifest.local.environments.filter((environment) => environment.id !== context.env.envId);
  if (others.length !== 1) throw new Error('resource_workload_other_environment_count_invalid');
  const observed = await readOnlyDatabaseSnapshot(context, others[0]!.id, 'sc011-other-environment-state');
  const generations = Array.isArray(observed.generations) ? observed.generations : [];
  const active = generations.some((value) => recordOf(value)?.status === 'active');
  const report = {
    ...baseReport(context, options, active ? 'blocked' : 'captured'),
    observedEnvironmentId: others[0]!.id,
    activeGenerationObserved: active,
    state: observed,
  };
  await writeJsonNew(resolve(options.evidenceDirectory, 'workload.json'), report);
  await context.database.close();
  process.stdout.write(`status=${active ? 'blocked' : 'captured'} mode=isolation-snapshot\n`);
  if (active) process.exitCode = 2;
}

async function runReadLoop(options: Options): Promise<void> {
  await assertEmptyDirectory(options.evidenceDirectory);
  const { context } = await createContext(options);
  await resetBeforeReadTrial(context);
  const session = await createReadOnlyGeneration(context, options.phase);
  const baselineRows = await context.database.snapshot({
    envId: session.envId,
    generationId: session.generationId,
    variantId: 'guardrail_exceeded',
    label: 'sc011-guardrail-database-before',
  });
  const chainBefore = await protectedStateSnapshot(context, session.payerAddress, 'sc011-guardrail-chain-before', 'guardrail_exceeded');
  const identityMarker = {
    schemaVersion: 'bef-resource-workload-identity/v1',
    phase: options.phase,
    envId: session.envId,
    generationId: session.generationId,
    participantId: session.participantId,
    payerAddress: session.payerAddress,
    manifestSha256: context.runtime.manifestSha256,
    applicationSourceSha256: context.runtime.appSourceSha256,
    probeSourceSha256: context.runtime.probeSourceSha256,
  };
  await writeJsonNew(resolve(options.evidenceDirectory, 'identity.json'), identityMarker);
  const firstRead = await context.transport.request({
    boundary: 'actual-tool-http',
    observationId: 'sc011-guardrail-read-before-deadline',
    method: 'GET',
    url: apiPath(context.env.apiBaseUrl, `/tools/${session.envId}/balances`),
    headers: participantHeaders(session, randomUUID()),
    operationId: null,
    variantId: 'guardrail_exceeded',
  });
  if (firstRead.status !== 200 || !readResponseMatchesGeneration(firstRead.body, session)) {
    throw new Error(`resource_workload_read_failed_${firstRead.status}`);
  }
  const firstObservation = context.evidence.observations.find((observation) => observation.id === 'sc011-guardrail-read-before-deadline');
  const firstArtifact = firstObservation
    ? context.evidence.artifacts.find((artifact) => artifact.path === firstObservation.sourceArtifact)
    : undefined;
  if (!firstObservation || !firstArtifact) throw new Error('resource_workload_first_read_artifact_missing');
  const marker = {
    schemaVersion: 'bef-resource-workload-ready/v1',
    phase: options.phase,
    envId: session.envId,
    generationId: session.generationId,
    participantId: session.participantId,
    payerAddress: session.payerAddress,
    manifestSha256: context.runtime.manifestSha256,
    applicationSourceSha256: context.runtime.appSourceSha256,
    probeSourceSha256: context.runtime.probeSourceSha256,
    databaseBefore: baselineRows,
    chainBefore,
    firstRead: {
      status: firstRead.status,
      observationId: 'sc011-guardrail-read-before-deadline',
      responseIdentity: {
        boundary: recordOf(firstRead.body)?.boundary,
        envId: recordOf(firstRead.body)?.envId,
        generationId: recordOf(firstRead.body)?.generationId,
        payer: recordOf(firstRead.body)?.payer,
      },
      artifact: firstArtifact,
    },
    completedReadsBeforeDeadline: 1,
    readyAtMonotonicNanoseconds: process.hrtime.bigint().toString(),
  };
  await writeJsonNew(resolve(options.evidenceDirectory, 'workload.json'), {
    ...baseReport(context, options, 'running'),
    environment: { envId: session.envId, generation: { generationId: session.generationId, participantId: session.participantId, payerAddress: session.payerAddress } },
    variantId: 'guardrail_exceeded',
    operationId: null,
    ready: true,
  });
  await writeMarkerAtomically(resolve(options.markerPath!), marker);
  const markerDigest = createHash('sha256').update(await readFile(resolve(options.markerPath!))).digest('hex');
  const releaseDeadline = Date.now() + Math.min(60_000, context.runtime.manifest.guardrails.maxTrialSeconds * 1_000);
  while (!existsSync(resolve(options.continuePath!))) {
    if (Date.now() >= releaseDeadline) throw new Error('resource_workload_release_signal_timeout');
    await new Promise((resolvePromise) => setTimeout(resolvePromise, 20));
  }
  const release = recordOf(JSON.parse(await readFile(resolve(options.continuePath!), 'utf8')) as unknown);
  if (release?.schemaVersion !== 'bef-resource-workload-release/v1' || release.markerSha256 !== markerDigest) {
    throw new Error('resource_workload_release_signal_invalid');
  }
  const progressPath = resolve(options.evidenceDirectory, 'read-progress.ndjson');
  let sequence = 1;
  while (sequence <= 1_000_000) {
    const observationId = `sc011-guardrail-read-${String(sequence).padStart(7, '0')}`;
    const response = await context.transport.request({
      boundary: 'actual-tool-http',
      observationId,
      method: 'GET',
      url: apiPath(context.env.apiBaseUrl, `/tools/${session.envId}/balances`),
      headers: participantHeaders(session, randomUUID()),
      operationId: null,
      variantId: 'guardrail_exceeded',
    });
    if (response.status !== 200 || !readResponseMatchesGeneration(response.body, session)) {
      throw new Error(`resource_workload_read_failed_${response.status}`);
    }
    const observation = context.evidence.observations.find((entry) => entry.id === observationId);
    const artifact = observation
      ? context.evidence.artifacts.find((entry) => entry.path === observation.sourceArtifact)
      : undefined;
    if (!observation || !artifact) throw new Error('resource_workload_read_artifact_missing');
    await appendReadProgress(progressPath, {
      schemaVersion: 'bef-resource-read-progress/v1',
      envId: session.envId,
      generationId: session.generationId,
      variantId: 'guardrail_exceeded',
      sequence,
      observationId,
      status: response.status,
      artifact,
      completedAtMonotonicNanoseconds: process.hrtime.bigint().toString(),
    });
    sequence += 1;
  }
  throw new Error('resource_workload_loop_safety_limit_reached');
}

export function validateResourceWorkloadMarker(input: unknown): Record<string, unknown> {
  const value = recordOf(input);
  const isReadiness = value?.schemaVersion === 'bef-resource-workload-ready/v1'
    && value.phase === 'guardrail_exceeded';
  const isFenceTarget = value?.schemaVersion === 'bef-resource-workload-fence-target/v1'
    && ['cold', 'warm', 'guardrail_exceeded'].includes(String(value.phase));
  if (!value || (!isReadiness && !isFenceTarget)
    || typeof value.envId !== 'string' || typeof value.generationId !== 'string'
    || typeof value.payerAddress !== 'string' || !/^0x[0-9a-f]{40}$/i.test(value.payerAddress)
    || !['cold', 'warm', 'guardrail_exceeded'].includes(String(value.phase))) {
    throw new Error('resource_workload_ready_marker_invalid');
  }
  return value;
}

export function fenceOutcome(input: {
  purpose: FencePurpose;
  fenceHttpStatus: number;
  responseStatus: unknown;
  responseEnvId: unknown;
  expectedEnvId: string;
  responseGenerationId: unknown;
  generationId: string;
  responseChainState: unknown;
  identityMatchesBeforeFence: boolean;
  rowsUnchanged: boolean;
  generationFenced: boolean;
  chainUnchanged: boolean;
  returnedCountsMatch: boolean;
  returnedStatusesMatch: boolean;
  persistedEffectsUnchangedSinceReadiness: boolean | null;
  protectedStateUnchangedSinceReadiness: boolean | null;
  guardrailGenerationHadNoEffects: boolean | null;
}): 'captured' | 'protected' | 'failed' {
  const coreValid = input.fenceHttpStatus === 200 && input.responseStatus === 'fenced'
    && input.responseEnvId === input.expectedEnvId && input.responseGenerationId === input.generationId
    && input.responseChainState === 'not_touched' && input.identityMatchesBeforeFence
    && input.rowsUnchanged && input.generationFenced && input.chainUnchanged
    && input.returnedCountsMatch && input.returnedStatusesMatch;
  if (!coreValid) return 'failed';
  if (input.purpose === 'readonly_guardrail') {
    return input.persistedEffectsUnchangedSinceReadiness === true
      && input.protectedStateUnchangedSinceReadiness === true
      && input.guardrailGenerationHadNoEffects === true ? 'captured' : 'failed';
  }
  if (input.persistedEffectsUnchangedSinceReadiness !== null
    || input.protectedStateUnchangedSinceReadiness !== null
    || input.guardrailGenerationHadNoEffects !== null) return 'failed';
  return input.purpose === 'protective_only' ? 'protected' : 'captured';
}

/** Return a safe copy before embedding paid-generation snapshots in a report. */
export function sanitizeFenceDatabaseSnapshot(rows: unknown): unknown {
  return sanitizeValue(rows);
}

async function readMarker(path: string): Promise<Record<string, unknown>> {
  const raw = await readFile(path, 'utf8');
  return validateResourceWorkloadMarker(JSON.parse(raw) as unknown);
}

async function runFence(options: Options): Promise<void> {
  await assertEmptyDirectory(options.evidenceDirectory);
  const marker = await readMarker(options.markerPath!);
  if (marker.envId !== options.envId || marker.phase !== options.phase) throw new Error('resource_workload_fence_marker_scope_mismatch');
  const readonlyGuardrail = marker.schemaVersion === 'bef-resource-workload-ready/v1';
  const fencePurpose: FencePurpose = readonlyGuardrail
    ? 'readonly_guardrail'
    : options.phase === 'guardrail_exceeded' ? 'protective_only' : 'trial_cleanup';
  const fenceVariant = readonlyGuardrail ? 'guardrail_exceeded' : null;
  const { context } = await createContext(options);
  if (marker.manifestSha256 !== context.runtime.manifestSha256
    || marker.applicationSourceSha256 !== context.runtime.appSourceSha256
    || marker.probeSourceSha256 !== context.runtime.probeSourceSha256) {
    throw new Error('resource_workload_fence_marker_source_identity_mismatch');
  }
  const generationId = String(marker.generationId);
  const payerAddress = String(marker.payerAddress) as Address;
  const beforeRows = await context.database.snapshot({
    envId: context.env.envId,
    generationId,
    variantId: fenceVariant,
    label: 'sc011-generation-before-fence',
  });
  const generationBefore = beforeRows.generation.length === 1 ? beforeRows.generation[0] : undefined;
  const generationIdentityMatchesBeforeFence = Boolean(
    generationBefore
      && generationBefore.generation_id === generationId
      && generationBefore.env_id === context.env.envId
      && generationBefore.status === 'active'
      && typeof marker.participantId === 'string'
      && generationBefore.participant_id === marker.participantId
      && typeof generationBefore.payer_address === 'string'
      && generationBefore.payer_address.toLowerCase() === payerAddress.toLowerCase(),
  );
  const beforeChain = await protectedStateSnapshot(context, payerAddress, 'sc011-generation-chain-before-fence', fenceVariant);
  const response = await adminRequest(
    context,
    'sc011-guardrail-generation-fence',
    'POST',
    `/internal/admin/environments/${context.env.envId}/generations/${generationId}/fence`,
    fenceVariant,
  );
  const afterRows = await context.database.snapshot({
    envId: context.env.envId,
    generationId,
    variantId: fenceVariant,
    label: 'sc011-guardrail-database-after-fence',
  });
  const chainAfter = await protectedStateSnapshot(context, payerAddress, 'sc011-generation-chain-after-fence', fenceVariant);
  const fenceBody = recordOf(response.body);
  const rowsUnchanged = rowSetsMatch(beforeRows, afterRows);
  const chainUnchanged = stableState(beforeChain) === stableState(chainAfter);
  const baselineRowsPresent = readonlyGuardrail ? persistedEffectsEqual(marker.databaseBefore, afterRows) : null;
  const baselineChain = readonlyGuardrail ? recordOf(marker.chainBefore) : null;
  const baselineChainUnchanged = readonlyGuardrail && baselineChain !== null
    ? stableState(baselineChain) === stableState(chainAfter) : null;
  const generationAfter = afterRows.generation[0];
  const generationFenced = generationAfter?.status === 'fenced';
  const guardrailGenerationHadNoEffects = readonlyGuardrail
    ? beforeRows.operations.length === 0 && beforeRows.payments.length === 0
      && beforeRows.deliveries.length === 0 && beforeRows.denials.length === 0
      && beforeRows.x402Observations.length === 0
    : null;
  const expectedCountPairs = [
    ['operationsBefore', beforeRows.operations.length], ['operationsAfter', afterRows.operations.length],
    ['paymentsBefore', beforeRows.payments.length], ['paymentsAfter', afterRows.payments.length],
    ['deliveriesBefore', beforeRows.deliveries.length], ['deliveriesAfter', afterRows.deliveries.length],
  ] as const;
  const counts = recordOf(fenceBody?.counts);
  const returnedCountsMatch = expectedCountPairs.every(([name, value]) => counts?.[name] === String(value));
  const returnedStatusesMatch = fenceBody?.generationStatusBefore === beforeRows.generation[0]?.status
    && fenceBody?.generationStatusAfter === 'fenced'
    && fenceBody?.signerErased === true;
  const report = {
    schemaVersion: 'bef-resource-fence-verification/v1',
    boundary: 'resource-fence-verification',
    scenarioId: 'BEF-SC-011',
    phase: options.phase,
    variantId: fenceVariant,
    fencePurpose,
    markerSchemaVersion: marker.schemaVersion,
    envId: context.env.envId,
    generationId,
    fenceHttpStatus: response.status,
    fenceResponse: fenceBody,
    // Keep raw rows for the comparisons above; redact nested EIP-3009
    // authorization and signature fields in the exported report copy.
    databaseBefore: sanitizeFenceDatabaseSnapshot(beforeRows),
    databaseAfter: sanitizeFenceDatabaseSnapshot(afterRows),
    protectedStateBefore: beforeChain,
    protectedStateAfter: chainAfter,
    databaseRowsUnchangedAcrossFence: rowsUnchanged,
    generationIdentityMatchesBeforeFence,
    persistedEffectsUnchangedSinceReadiness: baselineRowsPresent,
    protectedStateUnchangedSinceReadiness: baselineChainUnchanged,
    guardrailGenerationHadNoEffects,
    generationFenced,
    returnedCountsMatch,
    returnedStatusesMatch,
    protectedStateEqual: chainUnchanged,
    serverReportedChainState: fenceBody?.chainState ?? null,
    artifacts: context.evidence.artifacts,
    observations: context.evidence.observations,
  };
  await writeJsonNew(resolve(options.evidenceDirectory, 'fence-verification.json'), report);
  await context.database.close();
  const outcome = fenceOutcome({
    purpose: fencePurpose,
    fenceHttpStatus: response.status,
    responseStatus: fenceBody?.status,
    responseEnvId: fenceBody?.envId,
    expectedEnvId: context.env.envId,
    responseGenerationId: fenceBody?.generationId,
    generationId,
    responseChainState: fenceBody?.chainState,
    identityMatchesBeforeFence: generationIdentityMatchesBeforeFence,
    rowsUnchanged,
    generationFenced,
    chainUnchanged,
    returnedCountsMatch,
    returnedStatusesMatch,
    persistedEffectsUnchangedSinceReadiness: baselineRowsPresent,
    protectedStateUnchangedSinceReadiness: baselineChainUnchanged,
    guardrailGenerationHadNoEffects,
  });
  const valid = outcome !== 'failed';
  const workloadStatus = valid ? outcome : 'error';
  await writeJsonNew(resolve(options.evidenceDirectory, 'workload.json'), {
    ...baseReport(context, options, workloadStatus),
    variantId: fenceVariant,
    fencePurpose,
    environment: { envId: context.env.envId, generation: { generationId, participantId: marker.participantId ?? null, payerAddress } },
    generationId,
    fenceVerification: {
      path: 'fence-verification.json',
      sha256: sha256Bytes(await readFile(resolve(options.evidenceDirectory, 'fence-verification.json'))),
      status: valid ? 'verified' : 'failed',
    },
  });
  process.stdout.write(`status=${workloadStatus} mode=fence\n`);
  if (!valid) process.exitCode = 2;
}

async function readActiveGenerationForFence(context: ProbeContext): Promise<Array<Record<string, unknown>>> {
  const Pool = (await import('pg')).default.Pool;
  const pool = new Pool({ connectionString: context.env.databaseObserverUrl, max: 1, connectionTimeoutMillis: 5_000, statement_timeout: 5_000 });
  const client = await pool.connect();
  try {
    await client.query('BEGIN READ ONLY');
    const mode = await client.query<{ transaction_read_only: string }>('SHOW transaction_read_only');
    const role = await client.query<{ role_name: string }>('SELECT current_user AS role_name');
    if (mode.rows[0]?.transaction_read_only !== 'on' || role.rows[0]?.role_name !== context.database.databaseRole) {
      throw new Error('resource_workload_observer_identity_changed');
    }
    const result = await client.query(
      `SELECT generation_id, env_id, participant_id, payer_address, status, created_at, fenced_at
       FROM bef_generation WHERE env_id=$1 AND status='active' ORDER BY created_at`,
      [context.env.envId],
    );
    await client.query('COMMIT');
    const rows = result.rows as Array<Record<string, unknown>>;
    await context.evidence.writeObservation('db/active-generation-for-fence.json', 'active-generation-for-fence', {
      schemaVersion: 'bef-db-observation/v1', boundary: 'readonly-database', operationId: null,
      variantId: null, readOnly: true, databaseRole: context.database.databaseRole,
      queryName: 'sc011-active-generation-for-post-stop-fence', envId: context.env.envId,
      rows,
    });
    return rows;
  } catch (error) {
    await client.query('ROLLBACK').catch(() => undefined);
    throw error;
  } finally {
    client.release();
    await pool.end();
  }
}

async function runFenceActive(options: Options): Promise<void> {
  await assertEmptyDirectory(options.evidenceDirectory);
  const { context } = await createContext(options);
  const rows = await readActiveGenerationForFence(context);
  if (rows.length !== 1) {
    await writeJsonNew(resolve(options.evidenceDirectory, 'workload.json'), {
      ...baseReport(context, options, 'blocked'),
      activeGenerationRows: rows,
      errorCode: 'resource_workload_active_generation_cardinality_invalid',
    });
    await context.database.close();
    process.stdout.write(`status=blocked mode=fence-active activeRows=${rows.length}\n`);
    process.exitCode = 2;
    return;
  }
  const row = rows[0]!;
  if (typeof row.generation_id !== 'string' || typeof row.payer_address !== 'string'
    || typeof row.participant_id !== 'string' || row.env_id !== context.env.envId || row.status !== 'active') {
    await context.database.close();
    throw new Error('resource_workload_active_generation_identity_invalid');
  }
  const marker = {
    schemaVersion: 'bef-resource-workload-fence-target/v1',
    phase: options.phase,
    envId: context.env.envId,
    generationId: row.generation_id,
    participantId: row.participant_id,
    payerAddress: row.payer_address,
    manifestSha256: context.runtime.manifestSha256,
    applicationSourceSha256: context.runtime.appSourceSha256,
    probeSourceSha256: context.runtime.probeSourceSha256,
  };
  await writeMarkerAtomically(options.markerPath!, marker);
  await context.database.close();

  const fenceDirectory = resolve(options.evidenceDirectory, 'fence');
  await runFence({ ...options, mode: 'fence', evidenceDirectory: fenceDirectory });
  const verificationPath = resolve(fenceDirectory, 'fence-verification.json');
  const verificationBytes = await readFile(verificationPath);
  const verification = recordOf(JSON.parse(verificationBytes.toString('utf8')) as unknown);
  const fencePurpose: FencePurpose = options.phase === 'guardrail_exceeded' ? 'protective_only' : 'trial_cleanup';
  const valid = verification?.fenceHttpStatus === 200
    && verification.fencePurpose === fencePurpose
    && verification.generationFenced === true
    && verification.generationIdentityMatchesBeforeFence === true
    && verification.databaseRowsUnchangedAcrossFence === true
    && verification.protectedStateEqual === true
    && verification.returnedCountsMatch === true
    && verification.returnedStatusesMatch === true
    && verification.serverReportedChainState === 'not_touched';
  await writeJsonNew(resolve(options.evidenceDirectory, 'workload.json'), {
    ...baseReport(context, options, valid ? (fencePurpose === 'protective_only' ? 'protected' : 'captured') : 'error'),
    variantId: fencePurpose === 'protective_only' ? null : baseReport(context, options, 'captured').variantId,
    fencePurpose,
    activeGenerationRows: rows,
    generationId: row.generation_id,
    fenceVerification: {
      path: 'fence/fence-verification.json',
      sha256: sha256Bytes(verificationBytes),
      status: valid ? 'verified' : 'failed',
    },
  });
  process.stdout.write(`status=${valid ? (fencePurpose === 'protective_only' ? 'protected' : 'captured') : 'error'} mode=fence-active\n`);
  if (!valid) process.exitCode = 2;
}

async function main(): Promise<void> {
  let options: Options;
  try {
    options = parseArgs(process.argv.slice(2));
    const root = findRepositoryRoot();
    process.chdir(root);
  } catch {
    process.stderr.write('resource_workload_arguments_invalid\n');
    process.exitCode = 2;
    return;
  }
  try {
    if (options.mode === 'purchase') await runPurchase(options);
    else if (options.mode === 'read-loop') await runReadLoop(options);
    else if (options.mode === 'fence') await runFence(options);
    else if (options.mode === 'fence-active') await runFenceActive(options);
    else await runIsolationSnapshot(options);
  } catch (error) {
    const code = safeErrorCode(error);
    try {
      await writeJsonNew(resolve(options.evidenceDirectory, 'workload-error.json'), {
        schemaVersion: 'bef-resource-purchase-workload/v1',
        boundary: 'resource-workload',
        scenarioId: 'BEF-SC-011',
        phase: options.phase,
        mode: options.mode,
        status: 'error',
        errorCode: code,
      });
    } catch {
      // Keep the error channel limited to a stable code if evidence cannot be written.
    }
    process.stderr.write(`${code}\n`);
    process.exitCode = 2;
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) void main();
