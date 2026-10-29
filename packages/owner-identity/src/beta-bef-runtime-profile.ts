import { createHash } from 'node:crypto';
import { sql } from 'drizzle-orm';
import type { OwnerDatabase } from './db.js';
import type { BetaDeploymentManifest } from './beta-profile.js';
import type { PinnedX402Policy } from './task-action-x402.js';
import type { TaskMode } from './task-catalog.js';
import type { RunAdmissionRelease, TaskCase, TaskReleaseProvider, TaskReleaseQuerySource, ValidatedTaskRelease } from './task-release.js';
import type { RunExecutionReadinessProvider } from './run-service.js';
import type { BetaBuildObservation } from './beta-runtime-build-identity.js';

const HASH = /^[0-9a-f]{64}$/i;
const ADDRESS = /^0x[0-9a-f]{40}$/i;

export type BetaBefEnvironment = { envId: string; apiBaseUrl: string; observerRpcUrl: string; x402Policy: PinnedX402Policy };

type RuntimeDependencies = {
  db: OwnerDatabase;
  releaseSource: TaskReleaseQuerySource;
  manifest: BetaDeploymentManifest;
  build: BetaBuildObservation;
  environments: readonly BetaBefEnvironment[];
  sourceRpcUrl: string;
  fetchImpl?: typeof fetch;
};

export type BetaBefReadinessProvider = RunExecutionReadinessProvider & {
  /** Coordinator-only health check; it does not claim free execution capacity. */
  isRuntimeHealthyForRelease(releaseIdentity: string, manifestHash: string): Promise<boolean>;
};

function asRecord(value: unknown): Record<string, unknown> | null {
  return value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : null;
}
function hashText(value: string): string { return createHash('sha256').update(value).digest('hex'); }
function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (!value || typeof value !== 'object') return JSON.stringify(value) ?? 'null';
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${canonical(record[key])}`).join(',')}}`;
}
function numeric(value: unknown): bigint | null {
  try { return typeof value === 'string' || typeof value === 'number' || typeof value === 'bigint' ? BigInt(value) : null; }
  catch { return null; }
}
function exactRecipient(taskCase: TaskCase): string | null {
  switch (taskCase.taskId) {
    case 'M1': return taskCase.objective.paymentRequirements.recipient;
    case 'S2': return taskCase.objective.completePaymentRequirements.recipient;
    case 'S3': case 'M2': return taskCase.objective.required.recipient;
    default: return null;
  }
}

export function assertBetaBuildMatchesManifest(manifest: BetaDeploymentManifest, build: BetaBuildObservation): void {
  if (build.sourceClean !== true || !/^[0-9a-f]{40,64}$/i.test(build.commit) || !HASH.test(build.applicationBuildSha256) ||
      !HASH.test(build.evaluatorSourceSha256) || build.commit.toLowerCase() !== manifest.source.commit.toLowerCase() ||
      build.applicationBuildSha256.toLowerCase() !== manifest.source.applicationBuildSha256.toLowerCase() ||
      build.evaluatorSourceSha256.toLowerCase() !== manifest.source.evaluatorSourceSha256.toLowerCase()) {
    throw new Error('beta_runtime_build_profile_mismatch');
  }
}

async function boundedJson(response: Response, maxBytes: number): Promise<Record<string, unknown> | null> {
  if (!response.ok) return null;
  const declaredLength = response.headers.get('content-length');
  if (declaredLength && /^\d+$/.test(declaredLength) && Number(declaredLength) > maxBytes) {
    await response.body?.cancel().catch(() => undefined);
    return null;
  }
  const contentType = response.headers.get('content-type')?.split(';', 1)[0]?.trim().toLowerCase();
  if (contentType !== 'application/json') return null;
  if (!response.body) return null;
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel().catch(() => undefined);
        return null;
      }
      chunks.push(value);
    }
  } finally { reader.releaseLock(); }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
  try { return asRecord(JSON.parse(new TextDecoder().decode(bytes)) as unknown); }
  catch { return null; }
}

async function sourceRpc(fetchImpl: typeof fetch, sourceRpcUrl: string, chainId: number, blockNumber: string, blockHash: string) {
  const expectedBlock = BigInt(blockNumber);
  const blockTag = `0x${expectedBlock.toString(16)}`;
  async function call(method: string, params: unknown[]): Promise<unknown> {
    const response = await fetchImpl(sourceRpcUrl, { method: 'POST', redirect: 'error', signal: AbortSignal.timeout(5000),
      headers: { 'content-type': 'application/json', accept: 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }) });
    const body = await boundedJson(response, 64 * 1024);
    if (!body || body.jsonrpc !== '2.0' || body.id !== 1 || body.error !== undefined) throw new Error('beta_source_rpc_observation_invalid');
    return body.result;
  }
  const [rawChainId, rawBlock] = await Promise.all([call('eth_chainId', []), call('eth_getBlockByNumber', [blockTag, false])]);
  const result = asRecord(rawBlock);
  const observedBlockHash = typeof result?.hash === 'string' ? result.hash.toLowerCase().replace(/^0x/, '') : '';
  if (numeric(rawChainId) !== BigInt(chainId) || !result || numeric(result.number) !== expectedBlock ||
      !/^[0-9a-f]{64}$/.test(observedBlockHash) || observedBlockHash !== blockHash.toLowerCase()) {
    throw new Error('beta_source_block_pin_mismatch');
  }
  return { chainId, blockNumber: expectedBlock.toString(), blockHash: observedBlockHash };
}

export function betaReleaseMatchesManifest(
  record: Awaited<ReturnType<TaskReleaseQuerySource['getValidatedReleaseRecord']>>,
  manifest: BetaDeploymentManifest,
): boolean {
  if (!record) return false;
  const pins = manifest.release;
  const identity = record.manifest.executionIdentity;
  return record.releaseIdentity === pins.releaseIdentity && record.manifestHash.toLowerCase() === pins.manifestHash.toLowerCase() &&
    record.benchmarkHash.toLowerCase() === pins.benchmarkHash.toLowerCase() && record.policyHash.toLowerCase() === pins.policyHash.toLowerCase() &&
    record.benchmarkVersion === pins.benchmarkVersion && record.manifest.executionIdentityHash.toLowerCase() === pins.executionIdentityHash.toLowerCase() &&
    identity.environmentManifestSha256.toLowerCase() === pins.environmentManifestSha256.toLowerCase() &&
    identity.x402ServiceSha256.toLowerCase() === pins.applicationSourceSha256.toLowerCase() &&
    identity.sourceBlockHash.toLowerCase() === pins.sourceBlockHash.toLowerCase();
}

function releaseViewMatchesManifest(release: { releaseIdentity: string; manifestHash: string; benchmarkHash: string;
  policyHash: string; benchmarkVersion: string }, manifest: BetaDeploymentManifest): boolean {
  const pins = manifest.release;
  return release.releaseIdentity === pins.releaseIdentity && release.manifestHash.toLowerCase() === pins.manifestHash.toLowerCase() &&
    release.benchmarkHash.toLowerCase() === pins.benchmarkHash.toLowerCase() && release.policyHash.toLowerCase() === pins.policyHash.toLowerCase() &&
    release.benchmarkVersion === pins.benchmarkVersion;
}

export function pinBetaRunReleaseProvider(provider: TaskReleaseProvider, manifest: BetaDeploymentManifest): TaskReleaseProvider {
  return {
    async getActiveAdmissionRelease(mode: TaskMode, tx) {
      const release: RunAdmissionRelease | null = await provider.getActiveAdmissionRelease(mode, tx);
      return release && releaseViewMatchesManifest(release, manifest) ? release : null;
    },
    async getValidatedRelease(releaseIdentity: string, manifestHash: string, mode: TaskMode, tx) {
      const release: ValidatedTaskRelease | null = await provider.getValidatedRelease(releaseIdentity, manifestHash, mode, tx);
      return release && releaseViewMatchesManifest(release, manifest) ? release : null;
    },
    getPublicCatalog: () => provider.getPublicCatalog(),
  };
}

async function liveEnvironment(fetchImpl: typeof fetch, environment: BetaBefEnvironment, manifest: BetaDeploymentManifest, taskCase?: TaskCase) {
  const api = new URL(environment.apiBaseUrl);
  if (api.protocol !== 'https:' || api.username || api.password || api.search || api.hash || (api.pathname !== '' && api.pathname !== '/')) {
    throw new Error('beta_environment_api_url_invalid');
  }
  const response = await fetchImpl(new URL('/healthz', api.origin), { method: 'GET', redirect: 'error', signal: AbortSignal.timeout(5000),
    headers: { accept: 'application/json' } });
  const body = await boundedJson(response, 256 * 1024);
  const pins = manifest.release;
  if (!body || body.status !== 'ready' || body.boundary !== 'benchmark-environment-api' ||
      typeof body.manifestSha256 !== 'string' || body.manifestSha256.toLowerCase() !== pins.environmentManifestSha256.toLowerCase() ||
      typeof body.applicationSourceSha256 !== 'string' || body.applicationSourceSha256.toLowerCase() !== pins.applicationSourceSha256.toLowerCase() ||
      !Array.isArray(body.environments)) throw new Error('beta_environment_health_pin_mismatch');
  const entries = body.environments.map(asRecord).filter((entry): entry is Record<string, unknown> => entry !== null && entry.envId === environment.envId);
  if (entries.length !== 1) throw new Error('beta_environment_identity_mismatch');
  const selected = entries[0]!;
  const anvil = asRecord(selected.anvil), facilitator = asRecord(selected.facilitator), policy = environment.x402Policy;
  if (!anvil || !facilitator || typeof anvil.clientVersion !== 'string' ||
      !anvil.clientVersion.toLowerCase().includes(`anvil/v${policy.localAnvil.anvilVersion}`.toLowerCase()) ||
      numeric(anvil.chainId) !== BigInt(policy.localAnvil.chainId) || anvil.executionNetwork !== policy.localAnvil.executionNetwork ||
      anvil.hardFork !== policy.localAnvil.hardFork || numeric(anvil.forkBlockNumber) !== BigInt(policy.localAnvil.forkBlockNumber) ||
      typeof anvil.forkBlockHash !== 'string' || anvil.forkBlockHash.toLowerCase() !== policy.localAnvil.forkBlockHash.toLowerCase() ||
      typeof facilitator.address !== 'string' || !ADDRESS.test(facilitator.address) ||
      (taskCase && exactRecipient(taskCase) !== null && facilitator.address.toLowerCase() !== exactRecipient(taskCase)!.toLowerCase())) {
    throw new Error('beta_environment_execution_identity_mismatch');
  }
  return { manifestSha256: body.manifestSha256.toLowerCase(), applicationSourceSha256: body.applicationSourceSha256.toLowerCase(),
    environmentId: environment.envId, clientVersion: anvil.clientVersion, chainId: String(anvil.chainId),
    executionNetwork: anvil.executionNetwork, hardFork: anvil.hardFork, forkBlockNumber: String(anvil.forkBlockNumber),
    forkBlockHash: anvil.forkBlockHash.toLowerCase(), facilitatorAddress: facilitator.address.toLowerCase() };
}

export function createBetaBefReadinessProvider(dependencies: RuntimeDependencies): BetaBefReadinessProvider {
  const fetchImpl = dependencies.fetchImpl ?? fetch;
  assertBetaBuildMatchesManifest(dependencies.manifest, dependencies.build);
  async function observeRuntime(releaseIdentity: string, manifestHash: string, requireFreeEnvironment: boolean) {
      const pins = dependencies.manifest.release;
      if (releaseIdentity !== pins.releaseIdentity || manifestHash.toLowerCase() !== pins.manifestHash.toLowerCase()) {
        return { ready: false, reason: 'beta_release_expectation_mismatch' };
      }
      try {
        const [activeRanked, activeTraining] = await Promise.all([
          dependencies.releaseSource.getActiveAdmissionRelease('ranked'),
          dependencies.releaseSource.getActiveAdmissionRelease('training'),
        ]);
        if (!activeRanked || !activeTraining || !releaseViewMatchesManifest(activeRanked, dependencies.manifest) ||
            !releaseViewMatchesManifest(activeTraining, dependencies.manifest)) {
          return { ready: false, reason: 'beta_active_release_pin_mismatch' };
        }
        const record = await dependencies.releaseSource.getValidatedReleaseRecord(releaseIdentity, manifestHash);
        if (!betaReleaseMatchesManifest(record, dependencies.manifest)) return { ready: false, reason: 'beta_active_release_pin_mismatch' };
        const identity = record!.manifest.executionIdentity;
        const source = await sourceRpc(fetchImpl, dependencies.sourceRpcUrl, identity.sourceChainId,
          identity.sourceBlockNumber, pins.sourceBlockHash);
        if (requireFreeEnvironment) {
          const environmentIds = dependencies.environments.map((environment) => environment.envId);
          const active = await dependencies.db.execute(sql`SELECT DISTINCT environment_id FROM oid_task_environment_lease
            WHERE state='leased' AND environment_id IN (${sql.join(environmentIds.map((id) => sql`${id}`), sql`,`)})`) as unknown as unknown[];
          if (active.length > 0) return { ready: false, reason: 'beta_environment_capacity_unavailable' };
        }
        let lastReason = 'beta_environment_unavailable';
        for (const environment of dependencies.environments) {
          const policy = environment.x402Policy;
          if (policy.manifestSha256.toLowerCase() !== pins.environmentManifestSha256.toLowerCase()) continue;
          try {
            const health = await liveEnvironment(fetchImpl, environment, dependencies.manifest);
            const healthObservedAt = new Date().toISOString();
            const evidenceHash = hashText(canonical({ schemaVersion: 'beta-bef-runtime-readiness/v1', releaseIdentity,
              manifestHash: pins.manifestHash.toLowerCase(), benchmarkHash: pins.benchmarkHash.toLowerCase(),
              policyHash: pins.policyHash.toLowerCase(), benchmarkVersion: pins.benchmarkVersion,
              executionIdentityHash: pins.executionIdentityHash.toLowerCase(), source, health,
              healthObservedAt, activeLeaseCount: 0,
              workerProfile: dependencies.manifest.executionProfileId }));
            return { ready: true, environmentId: environment.envId, evidenceHash, executorId: dependencies.manifest.executionProfileId };
          } catch (error) { lastReason = error instanceof Error && /^beta_[a-z0-9_]+$/.test(error.message) ? error.message : 'beta_environment_observation_failed'; }
        }
        return { ready: false, reason: lastReason };
      } catch (error) {
        return { ready: false, reason: error instanceof Error && /^beta_[a-z0-9_]+$/.test(error.message) ? error.message : 'beta_readiness_observation_failed' };
      }
  }
  return {
    async isPreparedForRelease(releaseIdentity, manifestHash) {
      return observeRuntime(releaseIdentity, manifestHash, true);
    },
    async isRuntimeHealthyForRelease(releaseIdentity, manifestHash) {
      const result = await observeRuntime(releaseIdentity, manifestHash, false);
      return result.ready;
    }
  };
}
