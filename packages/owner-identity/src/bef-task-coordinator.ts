import { createHash, randomUUID } from 'node:crypto';
import { mkdir, readFile, realpath, stat, writeFile } from 'node:fs/promises';
import { dirname, isAbsolute, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { isIP } from 'node:net';
import postgres from 'postgres';
import { sql } from 'drizzle-orm';
import { z } from 'zod';
import { readBetaOperationsMode } from './beta-operations-control.js';
import { readBetaStorageObservation } from './beta-operations-observability.js';
import type { OwnerDatabase } from './db.js';
import { BefTaskExecutor, type ExecuteTaskActionResult, type SafeTaskActionEvidence } from './bef-task-executor.js';
import { BefTaskPreparationAdapter, type BefPreparationDiagnostic } from './bef-task-preparation.js';
import type { OwnerIdentityConfig } from './config.js';
import { claimNextQueuedRun, consumeRunCancellationOutbox, expireQueuedRuns, requestRunCancellationFromCoordinator,
  startQueuedRun, SUCCESSOR_PREPARATION_POLICY_VERSION, type RunServiceDependencies, type LocalCoordinatorCancellationReason,
  type RunExecutionReadinessProvider } from './run-service.js';
import { activatePreparedRankedSuccessor, activatePreparedTrainingSuccessor } from './task-successor-activation.js';
import { findPinnedResourceOffer, type PinnedX402Policy } from './task-action-x402.js';
import { sha256CanonicalTaskJson, type TaskCase, type TaskExecutionReadiness, type TaskReleaseQuerySource } from './task-release.js';
import { createPostgresTaskReleaseProvider } from './task-store.js';
import { getTaskEvaluatorBuildHash } from './task-result-service.js';
import { assertBetaBuildMatchesManifest, createBetaBefReadinessProvider, betaReleaseMatchesManifest, pinBetaRunReleaseProvider,
  type BetaBefReadinessProvider } from './beta-bef-runtime-profile.js';
import { observeBetaBuildIdentity } from './beta-runtime-build-identity.js';
import type { BetaDeploymentManifest } from './beta-profile.js';
import { createPreparedSuccessorTaskStartPort, createPreparedTaskStartPort, createTaskPreparationCancellationExecutor,
  fenceTaskPreparationWithEvidence, getTaskPreparation, prepareSuccessorTaskExecution, prepareTaskExecution,
  type PreparedTaskStartPort,
  type TaskPreparationDependencies, type TaskPreparationRecord, type TaskPreparationTarget,
  type SuccessorTaskPreparationDependencies } from './task-preparation.js';
import { TaskSealedEvidenceSource } from './task-sealed-evidence-source.js';
import { createBefObservationPorts, type BefObservationPorts, type BefObserverDatabaseConfig } from './bef-observation-ports.js';
import { processClosedTrainingTask } from './task-training-observation-lifecycle.js';
import { createBetaPlatformRecoveryMonitor, type BetaPlatformRecoveryMonitor } from './beta-platform-recovery-monitor.js';
import { getTaskExecutionContext } from './task-execution-binding.js';

/**
 * AICODE-NOTE: This disabled-by-default local coordinator advances only from an already evaluated,
 * fenced, and terminalized training or ranked task. It reloads the private sealed evidence and delegates
 * predecessor replay and activation to the immutable owner services; it never grades or terminalizes.
 */

const HASH = /^[0-9a-f]{64}$/i;
const ADDRESS = /^0x[0-9a-f]{40}$/i;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const ENV_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const PROJECT_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../../..');
const PRIVATE_CONFIG_DIR = '.local/owner-identity';
const EVIDENCE_DIR = 'artifacts/runs/owner-identity-bef-task-coordinator';
const LOCK_KEY_ONE = 0x4f494442; // "OIDB"
const LOCK_KEY_TWO = 0x45465731; // "BEW1"

// AICODE-NOTE: The private local policy is shared by browser admission and the worker. The
// 180-second successor-preparation value is an engineering default, not a production capacity
// guarantee or a user-selected setting; each new multi-task intent snapshots it before acceptance.
export const LOCAL_BEF_RUN_SERVICE_POLICY = Object.freeze({
  intentTtlSeconds: 900,
  maxIntentTtlSeconds: 3600,
  queueWaitSeconds: 900,
  maxQueueWaitSeconds: 3600,
  executionCapacity: 1,
  maxPendingIntentsPerOwner: 20,
  maxPendingIntentsGlobal: 100,
  trainingOverallTimeoutSeconds: 1800,
  maxTrainingOverallTimeoutSeconds: 3600,
  successorPreparationPolicyVersion: SUCCESSOR_PREPARATION_POLICY_VERSION,
  successorPreparationTimeoutSeconds: 180,
});

/**
 * AICODE-NOTE: Beta queue limits are separate from the guarded local policy. This pins only
 * admission/queue mechanics; it deliberately supplies no executor readiness or start port.
 * The beta worker must independently prove its release/environment before runs can start.
 */
export const BETA_BEF_RUN_SERVICE_POLICY = Object.freeze({
  intentTtlSeconds: 900,
  maxIntentTtlSeconds: 3600,
  queueWaitSeconds: 86400,
  maxQueueWaitSeconds: 86400,
  executionCapacity: 1,
  maxPendingIntentsPerOwner: 2,
  maxPendingIntentsGlobal: 30,
  maxAcceptedRunsPerOwner: 2,
  maxAcceptedRunsGlobal: 8,
  trainingOverallTimeoutSeconds: 1800,
  maxTrainingOverallTimeoutSeconds: 3600,
  successorPreparationPolicyVersion: SUCCESSOR_PREPARATION_POLICY_VERSION,
  successorPreparationTimeoutSeconds: 180,
});

const PolicySchema = z.object({
  manifestSha256: z.string().regex(HASH),
  scheme: z.literal('exact'),
  network: z.literal('eip155:8453'),
  asset: z.string().regex(ADDRESS),
  assetTransferMethod: z.literal('eip3009'),
  eip712Domain: z.object({ name: z.string().min(1).max(80), version: z.string().min(1).max(32) }).strict(),
  maxTimeoutSeconds: z.number().int().min(1).max(3600),
  sdkVersions: z.object({ core: z.literal('2.28.0'), evm: z.literal('2.28.0'), viem: z.string().regex(/^\d+\.\d+\.\d+$/) }).strict(),
  localAnvil: z.object({
    identity: z.literal('private-anvil-fork'), chainId: z.literal(8453), anvilVersion: z.string().regex(/^\d+\.\d+\.\d+$/),
    executionNetwork: z.string().min(1).max(64), hardFork: z.string().min(1).max(64),
    forkBlockNumber: z.string().regex(/^0x[0-9a-f]+$/i), forkBlockHash: z.string().regex(/^0x[0-9a-f]{64}$/i),
  }).strict(),
  resources: z.array(z.object({
    resourceId: z.string().min(1).max(128), resourceSha256: z.string().regex(HASH), contentType: z.string().min(1).max(128),
    dataType: z.string().min(1).max(128).optional(), schema: z.string().min(1).max(128).optional(),
    provenance: z.object({ classification: z.string().min(1), boundary: z.string().min(1), source: z.string().min(1) }).strict().optional(),
    offers: z.array(z.object({ id: z.string().min(1).max(128), amount: z.string().regex(/^[1-9][0-9]{0,77}$/) }).strict()).min(1).max(16),
  }).strict()).min(1).max(64),
}).strict();

const LocalCoordinatorFileSchema = z.object({
  schemaVersion: z.literal('local-bef-task-coordinator-config/v1'),
  adminKeyFile: z.string().min(1).max(256),
  sourceRpcUrl: z.string().min(1).max(2048),
  observationPipeline: z.object({
    schemaVersion: z.literal('local-bef-training-observation/v1'),
    database: z.object({ host: z.string().min(1).max(253), port: z.number().int().min(1).max(65535),
      database: z.literal('bef') }).strict(),
    passwordFile: z.literal('/run/secrets/bef_database_observer_password'),
  }).strict().optional(),
  environments: z.array(z.object({
    envId: z.string().regex(ENV_ID),
    apiBaseUrl: z.string().min(1).max(2048),
    observerRpcUrl: z.string().min(1).max(2048),
    x402Policy: PolicySchema,
  }).strict()).min(1).max(8),
}).strict();

const BetaCoordinatorFileSchema = z.object({
  schemaVersion: z.literal('beta-bef-task-coordinator-config/v1'),
  adminKeyFile: z.string().min(1).max(256),
  sourceRpcUrl: z.string().min(1).max(2048),
  observationPipeline: z.object({
    schemaVersion: z.literal('local-bef-training-observation/v1'),
    database: z.object({ host: z.string().min(1).max(253), port: z.number().int().min(1).max(65535),
      database: z.literal('bef') }).strict(),
    passwordFile: z.string().min(1).max(256),
  }).strict().optional(),
  environments: z.array(z.object({
    envId: z.string().regex(ENV_ID),
    apiBaseUrl: z.string().min(1).max(2048),
    observerRpcUrl: z.string().min(1).max(2048),
    x402Policy: PolicySchema,
  }).strict()).min(1).max(8),
}).strict();

type LocalCoordinatorFile = z.infer<typeof LocalCoordinatorFileSchema>;
type LocalEnvironment = LocalCoordinatorFile['environments'][number];
type BetaCoordinatorFile = z.infer<typeof BetaCoordinatorFileSchema>;
type CoordinatorEnvironment = { envId: string; apiBaseUrl: string; observerRpcUrl: string; x402Policy: PinnedX402Policy };
type LoadedCoordinatorConfig = { adminKey: string; sourceRpcUrl: string; environments: CoordinatorEnvironment[];
  observationDatabase?: BefObserverDatabaseConfig };
type PostgresClient = ReturnType<typeof postgres>;
type ReservedPostgresConnection = Awaited<ReturnType<PostgresClient['reserve']>>;

export interface LocalBefTaskCoordinator {
  /** Acquires the singleton session advisory lock. A false result means another owner is active. */
  acquire(): Promise<boolean>;
  /** One bounded non-overlapping maintenance/preparation/dispatch tick. */
  tick(): Promise<void>;
  /** Stops work, drops RAM credentials, and releases the reserved database connection. */
  stop(): Promise<void>;
  ownsLease(): boolean;
  readinessProvider?: RunExecutionReadinessProvider;
}

export type BetaBefTaskCoordinator = LocalBefTaskCoordinator & { readinessProvider: BetaBefReadinessProvider };

/** Release startup-owned resources in order, even when coordinator teardown itself fails. */
export async function cleanupFailedLocalBefTaskCoordinatorStartup(
  coordinator: Pick<LocalBefTaskCoordinator, 'stop'> | undefined,
  closeDatabase: () => Promise<unknown>,
): Promise<unknown[]> {
  const errors: unknown[] = [];
  try { await coordinator?.stop(); }
  catch (error) { errors.push(error); }
  try { await closeDatabase(); }
  catch (error) { errors.push(error); }
  return errors;
}

function under(parent: string, child: string): boolean {
  const rel = relative(parent, child);
  return rel === '' || (!isAbsolute(rel) && rel !== '..' && !rel.startsWith(`..${sep}`));
}

function privateRelativePath(root: string, raw: string, allowedPrefix: string): string {
  if (isAbsolute(raw) || raw.includes('\\') || raw.split('/').some((part) => part === '..' || part === '')) {
    throw new Error('local_bef_coordinator_config_invalid');
  }
  const normalized = raw.replaceAll('\\', '/');
  if (!normalized.startsWith(`${allowedPrefix}/`)) throw new Error('local_bef_coordinator_config_invalid');
  const target = resolve(root, normalized);
  const requiredRoot = resolve(root, allowedPrefix);
  if (!under(requiredRoot, target)) throw new Error('local_bef_coordinator_config_invalid');
  return target;
}

function assertPrivateMode(fileStat: { mode: number }): void {
  if (process.platform !== 'win32' && (fileStat.mode & 0o077) !== 0) {
    throw new Error('local_bef_coordinator_private_file_permissions_invalid');
  }
}

function allowedLocalHost(hostname: string): boolean {
  const host = hostname.toLowerCase().replace(/^\[|\]$/g, '');
  if (host === 'localhost' || host === 'host.docker.internal' || host === 'gateway.docker.internal' || host === '::1' ||
      host === 'api' || host === 'bef-api' || host === 'benchmark-environment-api') return true;
  const version = isIP(host);
  if (version === 4) {
    const parts = host.split('.').map(Number);
    if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return false;
    if (parts[0] === 127) return true;
    return parts[0] === 10 || (parts[0] === 192 && parts[1] === 168) ||
      (parts[0] === 172 && parts[1]! >= 16 && parts[1]! <= 31);
  }
  if (version === 6) return host === '::1';
  // Single-label DNS names are internal container/service names; public FQDNs are rejected.
  return /^[a-z][a-z0-9-]{0,62}$/.test(host);
}

function allowedParticipantApiHost(hostname: string): boolean {
  return new Set(['localhost', '127.0.0.1', '[::1]', '::1', 'host.docker.internal',
    'api', 'bef-api', 'benchmark-environment-api']).has(hostname.toLowerCase());
}

function validateUrl(raw: string, options: { localOnly: boolean; httpOnly?: boolean }): string {
  let url: URL;
  try { url = new URL(raw); } catch { throw new Error('local_bef_coordinator_url_invalid'); }
  if (!(options.httpOnly ? url.protocol === 'http:' : ['http:', 'https:'].includes(url.protocol)) ||
      url.username || url.password || url.search || url.hash || (url.pathname !== '' && url.pathname !== '/')) {
    throw new Error('local_bef_coordinator_url_invalid');
  }
  if (options.localOnly && (url.protocol !== 'http:' || !allowedLocalHost(url.hostname))) {
    throw new Error('local_bef_coordinator_url_must_be_private_http');
  }
  return url.origin;
}

function validateBetaPrivateServiceUrl(raw: string): string {
  let url: URL;
  try { url = new URL(raw); } catch { throw new Error('beta_bef_coordinator_url_invalid'); }
  const host = url.hostname.toLowerCase().replace(/^\[|\]$/g, '');
  const privateHost = allowedLocalHost(host) || host.endsWith('.internal') || host.endsWith('.svc');
  if (url.protocol !== 'https:' || !privateHost || url.username || url.password || url.search || url.hash ||
      (url.pathname !== '' && url.pathname !== '/')) throw new Error('beta_bef_coordinator_private_https_required');
  return url.origin;
}

function validateBetaSourceRpcUrl(raw: string): string {
  let url: URL;
  try { url = new URL(raw); } catch { throw new Error('beta_bef_source_rpc_url_invalid'); }
  if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash ||
      (url.pathname !== '' && url.pathname !== '/')) throw new Error('beta_bef_source_rpc_https_required');
  return url.origin;
}

function assertPolicy(policyValue: unknown): PinnedX402Policy {
  const policy = PolicySchema.parse(policyValue) as PinnedX402Policy;
  if (policy.network !== `eip155:${policy.localAnvil.chainId}` || policy.localAnvil.identity !== 'private-anvil-fork' ||
      policy.localAnvil.chainId !== 8453 || policy.assetTransferMethod !== 'eip3009') {
    throw new Error('local_bef_coordinator_policy_not_private_fork');
  }
  for (const resource of policy.resources) {
    for (const offer of resource.offers) {
      if (!findPinnedResourceOffer(policy, resource.resourceId, offer.id)) {
        throw new Error('local_bef_coordinator_policy_invalid');
      }
    }
  }
  return policy;
}

export function parseLocalBefTaskCoordinatorConfig(value: unknown): LocalCoordinatorFile {
  const parsed = LocalCoordinatorFileSchema.parse(value);
  if (parsed.observationPipeline && !allowedLocalHost(parsed.observationPipeline.database.host)) {
    throw new Error('local_bef_observer_database_must_be_private');
  }
  const seen = new Set<string>();
  for (const environment of parsed.environments) {
    if (seen.has(environment.envId)) throw new Error('local_bef_coordinator_environment_duplicate');
    seen.add(environment.envId);
    const apiOrigin = validateUrl(environment.apiBaseUrl, { localOnly: true, httpOnly: true });
    if (!allowedParticipantApiHost(new URL(apiOrigin).hostname)) throw new Error('local_bef_coordinator_participant_api_host_invalid');
    validateUrl(environment.observerRpcUrl, { localOnly: true, httpOnly: true });
    const policy = assertPolicy(environment.x402Policy);
    if (policy.manifestSha256.toLowerCase() !== environment.x402Policy.manifestSha256.toLowerCase()) {
      throw new Error('local_bef_coordinator_manifest_pin_mismatch');
    }
  }
  validateUrl(parsed.sourceRpcUrl, { localOnly: false });
  return parsed;
}

export function parseBetaBefTaskCoordinatorConfig(value: unknown): BetaCoordinatorFile {
  const parsed = BetaCoordinatorFileSchema.parse(value);
  if (!parsed.adminKeyFile.startsWith('secrets/')) throw new Error('beta_bef_admin_key_path_invalid');
  privateRelativePath('.', parsed.adminKeyFile, 'secrets');
  if (parsed.observationPipeline) {
    if (!parsed.observationPipeline.passwordFile.startsWith('secrets/')) throw new Error('beta_bef_observer_secret_path_invalid');
    privateRelativePath('.', parsed.observationPipeline.passwordFile, 'secrets');
  }
  if (parsed.observationPipeline && !allowedLocalHost(parsed.observationPipeline.database.host)) {
    throw new Error('beta_bef_observer_database_must_be_private');
  }
  const seen = new Set<string>();
  for (const environment of parsed.environments) {
    if (seen.has(environment.envId)) throw new Error('beta_bef_coordinator_environment_duplicate');
    seen.add(environment.envId);
    validateBetaPrivateServiceUrl(environment.apiBaseUrl);
    validateBetaPrivateServiceUrl(environment.observerRpcUrl);
    const policy = assertPolicy(environment.x402Policy);
    if (policy.manifestSha256.toLowerCase() !== environment.x402Policy.manifestSha256.toLowerCase()) {
      throw new Error('beta_bef_coordinator_manifest_pin_mismatch');
    }
  }
  validateBetaSourceRpcUrl(parsed.sourceRpcUrl);
  return parsed;
}

export async function loadLocalBefTaskCoordinatorConfig(configPath: string, projectRoot = PROJECT_ROOT): Promise<{
  adminKey: string; sourceRpcUrl: string; environments: LocalEnvironment[];
  observationDatabase?: BefObserverDatabaseConfig;
}> {
  try {
    const configAbsolute = privateRelativePath(projectRoot, configPath, PRIVATE_CONFIG_DIR);
    const configReal = await realpath(configAbsolute);
    if (!under(resolve(projectRoot, PRIVATE_CONFIG_DIR), configReal)) throw new Error('invalid_path');
    const configStats = await stat(configReal);
    assertPrivateMode(configStats);
    if (configStats.size < 2 || configStats.size > 256 * 1024) throw new Error('invalid_size');
    const parsedJson = JSON.parse((await readFile(configReal)).toString('utf8')) as unknown;
    const parsed = parseLocalBefTaskCoordinatorConfig(parsedJson);

    const keyAbsolute = privateRelativePath(projectRoot, `${PRIVATE_CONFIG_DIR}/${parsed.adminKeyFile}`, PRIVATE_CONFIG_DIR);
    if (!parsed.adminKeyFile.startsWith('secrets/')) throw new Error('invalid_key_path');
    const keyReal = await realpath(keyAbsolute);
    if (!under(resolve(projectRoot, PRIVATE_CONFIG_DIR, 'secrets'), keyReal)) throw new Error('invalid_key_path');
    const keyStats = await stat(keyReal);
    assertPrivateMode(keyStats);
    if (keyStats.size < 16 || keyStats.size > 4096) throw new Error('invalid_key_size');
    const adminKey = (await readFile(keyReal, 'utf8')).trim();
    if (adminKey.length < 16 || adminKey.length > 4096 || /[\r\n\u0000]/.test(adminKey)) throw new Error('invalid_key');
    let observationDatabase: BefObserverDatabaseConfig | undefined;
    if (parsed.observationPipeline) {
      const observerSecretStats = await stat(parsed.observationPipeline.passwordFile);
      if (!observerSecretStats.isFile() || observerSecretStats.size < 16 || observerSecretStats.size > 4096) throw new Error('invalid_observer_secret_size');
      let observerPassword = (await readFile(parsed.observationPipeline.passwordFile, 'utf8')).trim();
      if (observerPassword.length < 16 || observerPassword.length > 4096 || /[\r\n\u0000]/.test(observerPassword)) throw new Error('invalid_observer_secret');
      observationDatabase = { ...parsed.observationPipeline.database, password: observerPassword };
      observerPassword = '';
    }
    return { adminKey, sourceRpcUrl: validateUrl(parsed.sourceRpcUrl, { localOnly: false }), environments: parsed.environments,
      ...(observationDatabase ? { observationDatabase } : {}) };
  } catch {
    throw new Error('local_bef_coordinator_configuration_unavailable');
  }
}

export async function loadBetaBefTaskCoordinatorConfig(configPath: string, privateDataDir: string): Promise<LoadedCoordinatorConfig> {
  try {
    if (!isAbsolute(configPath) || !isAbsolute(privateDataDir)) throw new Error('invalid_absolute_path');
    const privateRoot = await realpath(resolve(privateDataDir));
    const configAbsolute = resolve(configPath);
    if (!under(privateRoot, configAbsolute)) throw new Error('config_outside_private_data');
    const configReal = await realpath(configAbsolute);
    if (!under(privateRoot, configReal)) throw new Error('config_symlink_escape');
    const configStats = await stat(configReal);
    assertPrivateMode(configStats);
    if (!configStats.isFile() || configStats.size < 2 || configStats.size > 256 * 1024) throw new Error('invalid_size');
    const parsed = parseBetaBefTaskCoordinatorConfig(JSON.parse((await readFile(configReal)).toString('utf8')) as unknown);

    if (!parsed.adminKeyFile.startsWith('secrets/')) throw new Error('admin_key_path_invalid');
    const keyAbsolute = privateRelativePath(privateRoot, parsed.adminKeyFile, 'secrets');
    const keyReal = await realpath(keyAbsolute);
    if (!under(resolve(privateRoot, 'secrets'), keyReal)) throw new Error('admin_key_path_escape');
    const keyStats = await stat(keyReal);
    assertPrivateMode(keyStats);
    if (!keyStats.isFile() || keyStats.size < 16 || keyStats.size > 4096) throw new Error('admin_key_size_invalid');
    let adminKey = (await readFile(keyReal, 'utf8')).trim();
    if (adminKey.length < 16 || adminKey.length > 4096 || /[\r\n\u0000]/.test(adminKey)) throw new Error('admin_key_invalid');

    let observationDatabase: BefObserverDatabaseConfig | undefined;
    if (parsed.observationPipeline) {
      const rawPasswordPath = parsed.observationPipeline.passwordFile;
      if (!rawPasswordPath.startsWith('secrets/')) throw new Error('observer_secret_path_invalid');
      const passwordAbsolute = privateRelativePath(privateRoot, rawPasswordPath, 'secrets');
      const passwordReal = await realpath(passwordAbsolute);
      if (!under(resolve(privateRoot, 'secrets'), passwordReal)) throw new Error('observer_secret_path_escape');
      const observerSecretStats = await stat(passwordReal);
      assertPrivateMode(observerSecretStats);
      if (!observerSecretStats.isFile() || observerSecretStats.size < 16 || observerSecretStats.size > 4096) {
        throw new Error('observer_secret_size_invalid');
      }
      let observerPassword = (await readFile(passwordReal, 'utf8')).trim();
      if (observerPassword.length < 16 || observerPassword.length > 4096 || /[\r\n\u0000]/.test(observerPassword)) {
        throw new Error('observer_secret_invalid');
      }
      observationDatabase = { ...parsed.observationPipeline.database, password: observerPassword };
      observerPassword = '';
    }
    const loaded = { adminKey, sourceRpcUrl: validateBetaSourceRpcUrl(parsed.sourceRpcUrl),
      environments: parsed.environments as CoordinatorEnvironment[], ...(observationDatabase ? { observationDatabase } : {}) };
    adminKey = '';
    return loaded;
  } catch {
    throw new Error('beta_bef_coordinator_configuration_unavailable');
  }
}

export interface CoordinatorReservedSql {
  unsafe(query: string, parameters?: unknown[]): Promise<Array<Record<string, unknown>>>;
  release(): void | Promise<void>;
}

/** Holds one Postgres session lock and proves the same backend still owns it before every worker action. */
export class PostgresLocalCoordinatorLease {
  private connection: CoordinatorReservedSql | null = null;
  private backendPid: number | null = null;
  private lost = false;
  private poolEnded = false;

  constructor(private readonly client: PostgresClient) {}

  private async destroyPool(connection?: CoordinatorReservedSql | null): Promise<void> {
    this.connection = null;
    this.backendPid = null;
    this.lost = true;
    if (this.poolEnded) return;
    this.poolEnded = true;
    if (connection) {
      // release() returns the reserved session to its pool; the dedicated pool is
      // ended immediately afterward so a session-level lock cannot be reused.
      try { await connection.release(); } catch { /* The session may already be gone. */ }
    }
    try { await this.client.end({ timeout: 1 }); } catch { /* Closing a broken pool is best-effort. */ }
  }

  ownsLease(): boolean { return this.connection !== null && !this.lost; }

  async acquire(): Promise<boolean> {
    if (this.lost) return false;
    if (this.connection) { await this.assertHeld(); return true; }
    const connection = await this.client.reserve() as unknown as CoordinatorReservedSql;
    try {
      const rows = await connection.unsafe(
        'SELECT pg_try_advisory_lock($1::integer, $2::integer) AS acquired, pg_backend_pid() AS backend_pid',
        [LOCK_KEY_ONE, LOCK_KEY_TWO],
      );
      if (rows[0]?.acquired !== true) {
        await this.destroyPool(connection);
        return false;
      }
      const pid = Number(rows[0]?.backend_pid);
      if (!Number.isSafeInteger(pid) || pid <= 0) throw new Error('invalid_backend_pid');
      this.connection = connection;
      this.backendPid = pid;
      await this.assertHeld();
      return true;
    } catch {
      await this.destroyPool(connection);
      throw new Error('local_bef_coordinator_advisory_lease_unavailable');
    }
  }

  async assertHeld(): Promise<void> {
    const connection = this.connection;
    if (!connection || this.lost || this.backendPid === null) throw new Error('local_bef_coordinator_lease_lost');
    try {
      const rows = await connection.unsafe(
        `SELECT pg_backend_pid() AS backend_pid, EXISTS (
          SELECT 1 FROM pg_locks WHERE locktype='advisory' AND pid=pg_backend_pid()
            AND classid=$1::oid AND objid=$2::oid AND objsubid=2 AND granted
        ) AS held`,
        [LOCK_KEY_ONE, LOCK_KEY_TWO],
      );
      if (Number(rows[0]?.backend_pid) !== this.backendPid || rows[0]?.held !== true) throw new Error('advisory_lock_not_held');
    } catch {
      await this.destroyPool(connection);
      throw new Error('local_bef_coordinator_lease_lost');
    }
  }

  async stop(): Promise<void> {
    const connection = this.connection;
    if (connection) {
      let unlocked = false;
      try {
        const rows = await connection.unsafe('SELECT pg_advisory_unlock($1::integer, $2::integer) AS unlocked',
          [LOCK_KEY_ONE, LOCK_KEY_TWO]);
        unlocked = rows[0]?.unlocked === true;
      } catch { /* Closing the dedicated pool below drops the backend session and its lock. */ }
      if (!unlocked) {
        await this.destroyPool(connection);
        return;
      }
    }
    await this.destroyPool(connection);
  }
}

function hash(value: string): string { return createHash('sha256').update(value).digest('hex'); }
function sessionKey(runId: string, taskIndex: number): string { return `${runId.toLowerCase()}:${taskIndex}`; }

export function isResumablePreDispatchPreparation(row: {
  lease_state: string; observation_status: string; dispatch_status: string | null;
}): boolean {
  return row.lease_state === 'leased' && row.dispatch_status === null && row.observation_status === 'preparing';
}

export function isValidSuccessorLocator(candidate: {
  run_id: string; predecessor_task_index: number; claim_id: string; mode?: unknown;
}): boolean {
  return UUID.test(candidate.run_id) && UUID.test(candidate.claim_id) &&
    (candidate.mode === undefined || candidate.mode === 'training' || candidate.mode === 'ranked') &&
    Number.isSafeInteger(candidate.predecessor_task_index) && candidate.predecessor_task_index >= 0 &&
    candidate.predecessor_task_index <= 10;
}

export function isBoundedSuccessorWindowFailure(code: string | null): boolean {
  return code === 'SUCCESSOR_PREPARATION_POLICY_UNAVAILABLE' ||
    code === 'SUCCESSOR_PREPARATION_WINDOW_EXPIRED' ||
    code === 'SUCCESSOR_PREPARATION_TIMEOUT';
}

function errorCode(error: unknown): string | null {
  if (!error || typeof error !== 'object' || !('code' in error)) return null;
  return typeof error.code === 'string' ? error.code : null;
}

export function predecessorFinishedBeforeOriginalDeadline(input: {
  finishedAt: Date | string | null; overallDeadline: Date | string | null;
} | null): boolean | null {
  if (!input?.finishedAt || !input.overallDeadline) return null;
  const finishedAt = input.finishedAt instanceof Date ? input.finishedAt.getTime() : Date.parse(input.finishedAt);
  const overallDeadline = input.overallDeadline instanceof Date ? input.overallDeadline.getTime() : Date.parse(input.overallDeadline);
  if (!Number.isFinite(finishedAt) || !Number.isFinite(overallDeadline)) return null;
  return finishedAt < overallDeadline;
}

type ExpiredKnownRunGap = {
  run_id:string;predecessor_task_index:number;claim_id:string;mode:'training'|'ranked';
  run_status:string;overall_deadline:Date|string;observed_at:Date|string;predecessor_finished_at:Date|string;predecessor_status:string;
  predecessor_closure_status:string;evaluation_status:string;active_task_count:number;
  stored_fence_matches:boolean;terminal_event_matches:boolean;successor_queued:boolean;claim_slot_matches:boolean;
};

export function isExpiredKnownRunGap(value:ExpiredKnownRunGap):boolean {
  // AICODE-NOTE: Pre-deadline predecessors retain their saved preparation-time exclusion after the old wall-clock deadline.
  const deadline=new Date(value.overall_deadline).getTime(),now=new Date(value.observed_at).getTime(),finished=new Date(value.predecessor_finished_at).getTime();
  return isValidSuccessorLocator(value)&&value.run_status==='running'&&Number.isFinite(deadline)&&Number.isFinite(now)&&now>=deadline&&
    Number.isFinite(finished)&&finished>=deadline&&finished<=now&&['completed','failed'].includes(value.predecessor_status)&&value.predecessor_closure_status==='closed'&&value.evaluation_status==='known'&&
    value.active_task_count===0&&value.stored_fence_matches===true&&value.terminal_event_matches===true&&
    value.successor_queued===true&&value.claim_slot_matches===true;
}

/** Terminal resource cleanup does not depend on runtime health or the admission mode. */
export async function cancelExpiredKnownRunGaps(input:{db:OwnerDatabase;assertLeaseHeld():Promise<void>;
  requestCancellation(runId:string,reason:LocalCoordinatorCancellationReason):Promise<void>;drainCancellations():Promise<void>},limit=16):Promise<number>{
  await input.assertLeaseHeld();
  const candidates=await input.db.execute(sql`SELECT r.id AS run_id,p.task_index AS predecessor_task_index,c.claim_id,r.mode,
      r.status AS run_status,r.overall_deadline,clock_timestamp() AS observed_at,p.finished_at AS predecessor_finished_at,p.status AS predecessor_status,
      p.closure_status AS predecessor_closure_status,e.result_json->>'status' AS evaluation_status,
      (SELECT count(*)::int FROM oid_run_task active WHERE active.run_id=r.id AND active.status='active') AS active_task_count,
      true AS stored_fence_matches,true AS terminal_event_matches,true AS successor_queued,true AS claim_slot_matches
    FROM oid_benchmark_run r
    JOIN oid_run_dispatch_claim c ON c.run_id=r.id AND c.status='claimed'
    JOIN oid_run_execution_slot s ON s.run_id=r.id AND s.agent_id=r.agent_id AND s.claim_id=c.claim_id
      AND s.state='running' AND s.released_at IS NULL
    JOIN oid_run_task p ON p.run_id=r.id AND p.status IN ('completed','failed') AND p.closure_status='closed' AND p.finished_at IS NOT NULL
      AND p.action_cutoff_sequence IS NOT NULL AND p.reconciled_action_sequence>=p.action_cutoff_sequence
    JOIN oid_run_task_evaluation e ON e.run_id=p.run_id AND e.task_index=p.task_index AND e.closure_id=p.closure_id
      AND e.result_json->>'status'='known'
    JOIN oid_run_task_observation_bundle b ON b.run_id=p.run_id AND b.task_index=p.task_index AND b.closure_id=p.closure_id AND b.task_id=p.task_id
    JOIN oid_task_preparation_intent i ON i.run_id=p.run_id AND i.task_index=p.task_index AND i.task_id=p.task_id
      AND i.environment_id=b.environment_id
    JOIN oid_task_environment_lease l ON l.lease_id=i.lease_id AND l.preparation_id=i.preparation_id AND l.environment_id=i.environment_id
      AND l.state='fenced' AND l.fence_evidence->>'confirmed'='true'
      AND lower(l.fence_evidence->>'preparationId')=i.preparation_id::text AND lower(l.fence_evidence->>'leaseId')=i.lease_id::text
      AND l.fence_evidence->>'environmentId'=i.environment_id AND lower(l.fence_evidence->>'generationId')=b.generation_id::text
      AND l.fence_evidence->'evidence'->>'boundary'='actual_tool_http_x402_local_evm_application_store'
      AND l.fence_evidence->'evidence'->>'sha256'~'^[0-9a-fA-F]{64}$'
    JOIN LATERAL (SELECT status,generation_id FROM oid_task_preparation_observation WHERE preparation_id=i.preparation_id ORDER BY revision DESC LIMIT 1) o
      ON o.status='fenced' AND o.generation_id=b.generation_id
    JOIN oid_task_execution_binding eb ON eb.run_id=p.run_id AND eb.task_index=p.task_index AND eb.env_id=b.environment_id AND eb.generation_id=b.generation_id
    JOIN oid_run_task n ON n.run_id=p.run_id AND n.task_index=p.task_index+1 AND n.status='queued' AND n.closure_status='open'
      AND n.started_at IS NULL AND n.finished_at IS NULL
    WHERE r.status='running' AND r.mode IN ('training','ranked') AND r.overall_deadline<=clock_timestamp()
      AND p.finished_at>=r.overall_deadline AND p.task_index BETWEEN 0 AND 10
      AND NOT EXISTS (SELECT 1 FROM oid_run_task active WHERE active.run_id=r.id AND active.status='active')
      AND EXISTS (SELECT 1 FROM oid_run_event ev WHERE ev.run_id=r.id AND ev.event_type='task.terminalized'
        AND ev.payload_json->>'taskIndex'=p.task_index::text)
    ORDER BY r.overall_deadline,r.id,p.task_index LIMIT ${limit}`) as unknown as ExpiredKnownRunGap[];
  await input.assertLeaseHeld();
  let cancelled=0;
  const seen=new Set<string>();
  for(const candidate of candidates){
    if(!isExpiredKnownRunGap(candidate)||seen.has(candidate.run_id))continue;
    await input.assertLeaseHeld();
    await input.requestCancellation(candidate.run_id,'coordinator_run_deadline');
    await input.drainCancellations();
    seen.add(candidate.run_id);cancelled++;
  }
  return cancelled;
}

type ExpiredClosedUngradedTask = {
  run_id:string;mode:string;run_status:string;overall_deadline:Date|string;observed_at:Date|string;
  task_status:string;closure_status:string;action_cutoff_sequence:string|number|null;
  accepted_action_sequence:string|number;reconciled_action_sequence:string|number;active_task_count:number;
  known_evaluation:boolean;unresolved_cutoff_action:boolean;active_platform_recovery:boolean;claim_slot_matches:boolean;
  closed_at?:Date|string|null;
};

// Reuse the existing bounded observation-recovery duration, without claiming platform attribution.
export const CLOSED_TASK_EVALUATION_RETRY_MS=180_000;

export function closedTaskEvaluationRetryExpired(value:Pick<ExpiredClosedUngradedTask,'closed_at'|'observed_at'>):boolean {
  if(value.closed_at===undefined||value.closed_at===null)return false;
  const closed=new Date(value.closed_at).getTime(),now=new Date(value.observed_at).getTime();
  return Number.isFinite(closed)&&Number.isFinite(now)&&now>=closed+CLOSED_TASK_EVALUATION_RETRY_MS;
}

function nonnegativeSequence(value:string|number|null):bigint|null {
  if(typeof value==='number')return Number.isSafeInteger(value)&&value>=0?BigInt(value):null;
  if(typeof value!=='string'||!/^\d+$/.test(value))return null;
  try{return BigInt(value);}catch{return null;}
}

export function isExpiredClosedUngradedTask(value:ExpiredClosedUngradedTask):boolean {
  const deadline=new Date(value.overall_deadline).getTime(),now=new Date(value.observed_at).getTime();
  const cutoff=nonnegativeSequence(value.action_cutoff_sequence),accepted=nonnegativeSequence(value.accepted_action_sequence),
    reconciled=nonnegativeSequence(value.reconciled_action_sequence);
  return UUID.test(value.run_id)&&['training','ranked'].includes(value.mode)&&value.run_status==='running'&&
    Number.isFinite(deadline)&&Number.isFinite(now)&&(now>=deadline||closedTaskEvaluationRetryExpired(value))&&value.task_status==='active'&&value.closure_status==='closed'&&
    cutoff!==null&&accepted===cutoff&&reconciled!==null&&reconciled>=cutoff&&value.active_task_count===1&&
    value.known_evaluation===false&&value.unresolved_cutoff_action===false&&value.active_platform_recovery===false&&
    value.claim_slot_matches===true;
}

/**
 * AICODE-NOTE: A resolved cutoff gets at most 180 seconds of grading retries after durable closed_at.
 * Exhaustion cancels/fences with evaluation_unknown, not platform attribution or a refund. Proven
 * platform recovery retains priority and its separate clock/refund authority; retries cannot reset closed_at.
 */
export async function cancelExpiredClosedUngradedTasks(input:{db:OwnerDatabase;assertLeaseHeld():Promise<void>;
  requestCancellation(runId:string,reason:LocalCoordinatorCancellationReason):Promise<void>;drainCancellations():Promise<void>},
  recoveringRunIds:ReadonlySet<string>=new Set(),limit=16):Promise<number>{
  await input.assertLeaseHeld();
  const candidates=await input.db.execute(sql`WITH expired_candidates AS (
    SELECT r.id AS run_id,r.mode,r.status AS run_status,r.overall_deadline,
      clock_timestamp() AS observed_at,t.status AS task_status,t.closure_status,t.closed_at,
      t.action_cutoff_sequence::text AS action_cutoff_sequence,t.accepted_action_sequence::text AS accepted_action_sequence,
      t.reconciled_action_sequence::text AS reconciled_action_sequence,
      (SELECT count(*)::int FROM oid_run_task active WHERE active.run_id=r.id AND active.status='active') AS active_task_count,
      EXISTS (SELECT 1 FROM oid_run_task_evaluation e WHERE e.run_id=r.id AND e.task_index=t.task_index
        AND e.result_json->>'status'='known') AS known_evaluation,
      EXISTS (SELECT 1 FROM oid_run_task_action a
        LEFT JOIN oid_run_task_action_receipt receipt ON receipt.action_id=a.id
        LEFT JOIN oid_run_task_action_outbox outbox ON outbox.action_id=a.id
        WHERE a.run_id=r.id AND a.task_index=t.task_index AND a.action_sequence<=t.action_cutoff_sequence
          AND (receipt.action_id IS NULL OR receipt.receipt_status NOT IN ('observed','rejected_before_execution')
            OR outbox.action_id IS NULL OR outbox.status<>'delivered')) AS unresolved_cutoff_action,
      EXISTS (SELECT 1 FROM oid_run_platform_recovery recovery WHERE recovery.run_id=r.id
        AND recovery.status IN ('recovering','unknown','exhausted')) AS active_platform_recovery,
      (c.status='claimed' AND s.state='running' AND s.released_at IS NULL AND s.claim_id=c.claim_id) AS claim_slot_matches
    FROM oid_benchmark_run r
    JOIN oid_run_task t ON t.run_id=r.id
    JOIN oid_run_dispatch_claim c ON c.run_id=r.id AND c.status='claimed'
    JOIN oid_run_execution_slot s ON s.run_id=r.id AND s.agent_id=r.agent_id AND s.claim_id=c.claim_id
      AND s.state='running' AND s.released_at IS NULL
    WHERE r.status='running' AND r.mode IN ('training','ranked')
      AND (r.overall_deadline<=clock_timestamp() OR t.closed_at<=clock_timestamp()-interval '180 seconds')
      AND t.status='active' AND t.closure_status='closed' AND t.action_cutoff_sequence IS NOT NULL
      AND t.accepted_action_sequence=t.action_cutoff_sequence AND t.reconciled_action_sequence>=t.action_cutoff_sequence
      AND (SELECT count(*) FROM oid_run_task active WHERE active.run_id=r.id AND active.status='active')=1
      AND (SELECT count(*)::bigint FROM oid_run_task_action a WHERE a.run_id=r.id AND a.task_index=t.task_index)=t.action_cutoff_sequence
      AND COALESCE((SELECT max(a.action_sequence) FROM oid_run_task_action a WHERE a.run_id=r.id AND a.task_index=t.task_index),0)=t.action_cutoff_sequence
  )
  SELECT * FROM expired_candidates
  WHERE known_evaluation=false AND unresolved_cutoff_action=false AND active_platform_recovery=false AND claim_slot_matches=true
  ORDER BY overall_deadline,run_id,task_status LIMIT ${limit}`) as unknown as ExpiredClosedUngradedTask[];
  await input.assertLeaseHeld();
  let cancelled=0;
  const seen=new Set<string>();
  for(const candidate of candidates){
    if(!isExpiredClosedUngradedTask(candidate)||recoveringRunIds.has(candidate.run_id)||seen.has(candidate.run_id))continue;
    await input.assertLeaseHeld();
    const overallExpired=new Date(candidate.observed_at).getTime()>=new Date(candidate.overall_deadline).getTime();
    await input.requestCancellation(candidate.run_id,overallExpired?'coordinator_run_deadline':'coordinator_evaluation_unknown');
    await input.drainCancellations();
    seen.add(candidate.run_id);cancelled++;
  }
  return cancelled;
}

export function successorFailureCancellationReason(
  code: string | null,
  hasPreparationIntent: boolean,
  predecessorBeforeDeadline: boolean | null,
): LocalCoordinatorCancellationReason | null {
  if (hasPreparationIntent) return 'coordinator_interrupted_preparation';
  if (predecessorBeforeDeadline === true && isBoundedSuccessorWindowFailure(code)) return 'coordinator_preparation_failed';
  return null;
}

export function activeTaskNeedsCancellation(
  runId: string,
  taskIndex: number,
  attached: ReadonlyMap<string, unknown>,
): boolean {
  return !Number.isSafeInteger(taskIndex) || taskIndex < 0 || taskIndex > 11 ||
    !attached.has(sessionKey(runId, taskIndex));
}

type FencedKnownTaskRecoveryRow = Record<string, unknown>;

/**
 * AICODE-NOTE: A closed, fully reconciled task needs no actor session to retry observation.
 * Restart must retain its original closed_at + 180-second bound. This classification only
 * defers lost-RAM cancellation; it never restores credentials, dispatches, grades or refunds.
 * The caller independently rechecks the execution context and immutable release case.
 */
export function classifyClosedObservationRecovery(row: FencedKnownTaskRecoveryRow): 'retry' | 'expired' | null {
  if (!['training', 'ranked'].includes(String(row.run_mode)) || row.run_status !== 'running' ||
      row.task_status !== 'active' || row.closure_status !== 'closed' ||
      row.recovery_access_current !== true || row.recovery_claim_slot_matches !== true ||
      row.recovery_active_task_count !== 1 || row.recovery_unresolved_action !== false ||
      row.run_cancellation_reason !== null || row.run_cancellation_requested_at !== null ||
      row.lease_state !== 'leased' || row.observation_status !== 'ready' ||
      typeof row.run_id !== 'string' || !UUID.test(row.run_id) ||
      typeof row.owner_id !== 'string' || !UUID.test(row.owner_id) ||
      typeof row.agent_id !== 'string' || !UUID.test(row.agent_id) ||
      !Number.isSafeInteger(row.task_index) || Number(row.task_index) < 0 || Number(row.task_index) > 11 ||
      typeof row.closure_id !== 'string' || !UUID.test(row.closure_id) ||
      typeof row.closure_payload_hash !== 'string' || !HASH.test(row.closure_payload_hash)) return null;
  const time = (value: unknown) => value instanceof Date ? value.getTime()
    : typeof value === 'string' ? Date.parse(value) : NaN;
  const now = time(row.recovery_observed_at), closed = time(row.closed_at), requested = time(row.journal_requested_at);
  const overall = time(row.overall_deadline);
  if (![now, closed, requested, overall].every(Number.isFinite) || requested > closed || closed > now) return null;
  const sequence = (value: unknown) => typeof value === 'string' || typeof value === 'number'
    ? nonnegativeSequence(value) : null;
  const cutoff = sequence(row.action_cutoff_sequence);
  if (cutoff === null || sequence(row.accepted_action_sequence) !== cutoff ||
      sequence(row.reconciled_action_sequence) !== cutoff || sequence(row.recovery_action_count) !== cutoff ||
      sequence(row.recovery_max_sequence) !== cutoff || sequence(row.journal_cutoff_sequence) !== cutoff) return null;
  const journalMatches = row.journal_closure_id === row.closure_id && row.closure_run_id === row.run_id &&
    row.closure_task_index === row.task_index && row.journal_owner_id === row.owner_id &&
    row.journal_agent_id === row.agent_id && row.journal_payload_hash === row.closure_payload_hash &&
    row.journal_operation_id === row.closure_operation_id && row.journal_reason === row.closure_reason &&
    ['agent_finish', 'task_deadline', 'run_deadline'].includes(String(row.closure_reason));
  if (!journalMatches) return null;
  return now < closed + CLOSED_TASK_EVALUATION_RETRY_MS && now < overall ? 'retry' : 'expired';
}

export function isBoundedClosedObservationRetry(row: FencedKnownTaskRecoveryRow): boolean {
  return classifyClosedObservationRecovery(row) === 'retry';
}

function recoveryObject(value: unknown): Record<string, unknown> | null {
  if (typeof value === 'string') {
    try { value = JSON.parse(value); } catch { return null; }
  }
  return value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : null;
}

function sameCanonical(left: unknown, right: unknown): boolean {
  try { return sha256CanonicalTaskJson(left) === sha256CanonicalTaskJson(right); } catch { return false; }
}

/**
 * AICODE-NOTE: The harness fences before the normal finalizer commits task.terminalized. A closed
 * and reconciled task with its exact immutable evaluation and exact fenced preparation is
 * physically stopped while the normal finalizer commits task.terminalized. It is not a lost live
 * executor session. This is a narrow recovery classification only: it never grades, finalizes, or
 * attaches RAM state, and every join identity must match the active task.
 */
export function isExactFencedKnownClosedTask(row: FencedKnownTaskRecoveryRow): boolean {
  const taskIndex = row.task_index;
  const cutoff = row.action_cutoff_sequence;
  const accepted = row.accepted_action_sequence;
  const reconciled = row.reconciled_action_sequence;
  if (!['training', 'ranked'].includes(String(row.run_mode)) || row.run_status !== 'running' || row.task_status !== 'active' ||
      !Number.isSafeInteger(taskIndex) || Number(taskIndex) < 0 || Number(taskIndex) > 11 ||
      row.closure_status !== 'closed' || typeof row.closure_id !== 'string' || !UUID.test(row.closure_id) ||
      typeof row.task_id !== 'string' || !row.task_id || typeof row.run_id !== 'string' || !UUID.test(row.run_id) ||
      cutoff === null || cutoff === undefined || accepted === null || accepted === undefined || reconciled === null || reconciled === undefined) return false;
  let cutoffValue: bigint;
  let acceptedValue: bigint;
  let reconciledValue: bigint;
  try {
    cutoffValue = BigInt(String(cutoff)); acceptedValue = BigInt(String(accepted)); reconciledValue = BigInt(String(reconciled));
  } catch { return false; }
  const cutoffNumber = Number(cutoffValue);
  const reconciledNumber = Number(reconciledValue);
  if (cutoffValue < 0n || acceptedValue !== cutoffValue || reconciledValue < cutoffValue ||
      !Number.isSafeInteger(cutoffNumber) || !Number.isSafeInteger(reconciledNumber)) return false;

  const id = row.run_id;
  const index = taskIndex;
  const taskId = row.task_id;
  const closureId = row.closure_id;
  const prepId = row.preparation_id;
  const leaseId = row.preparation_lease_id;
  const environmentId = row.preparation_environment_id;
  const generationId = row.observed_generation_id;
  const manifestHash = row.release_manifest_hash;
  if (typeof prepId !== 'string' || !UUID.test(prepId) || typeof leaseId !== 'string' || !UUID.test(leaseId) ||
      typeof environmentId !== 'string' || !ENV_ID.test(environmentId) || typeof generationId !== 'string' || !UUID.test(generationId)) return false;
  if (row.preparation_run_id !== id || row.preparation_task_index !== index || row.preparation_task_id !== taskId ||
      row.preparation_release_identity !== row.release_identity || row.preparation_manifest_hash !== manifestHash) return false;
  if (row.lease_preparation_id !== prepId || row.lease_id !== leaseId || row.lease_state !== 'fenced' ||
      row.observation_status !== 'fenced' || row.preparation_observation_generation_id !== generationId) return false;
  if (row.registered_generation_id !== generationId || row.registered_environment_id !== environmentId) return false;
  if (row.binding_run_id !== id || row.binding_task_index !== index || row.binding_environment_id !== environmentId ||
      row.binding_generation_id !== generationId || row.binding_manifest_hash !== row.preparation_environment_manifest_sha256 ||
      row.binding_source_hash !== row.preparation_application_source_hash) return false;
  if (row.preparation_case_id !== row.bundle_case_id || row.preparation_case_hash !== row.bundle_case_hash) return false;
  if (row.closure_run_id !== id || row.closure_task_index !== index || row.journal_closure_id !== closureId ||
      row.journal_operation_id !== row.closure_operation_id || row.journal_cutoff_sequence === null ||
      String(row.journal_cutoff_sequence) !== String(cutoff) || row.journal_payload_hash !== row.closure_payload_hash ||
      row.journal_reason !== row.closure_reason || row.journal_owner_id !== row.owner_id || row.journal_agent_id !== row.agent_id) return false;
  const fenceEvidence = recoveryObject(row.lease_fence_evidence);
  if (!fenceEvidence || fenceEvidence.confirmed !== true || fenceEvidence.preparationId !== prepId ||
      fenceEvidence.leaseId !== leaseId || fenceEvidence.environmentId !== environmentId || fenceEvidence.generationId !== generationId) return false;

  const bundle = recoveryObject(row.bundle_json);
  if (!bundle || row.bundle_hash !== sha256CanonicalTaskJson(bundle) || row.bundle_run_id !== id ||
      row.bundle_task_index !== index || row.bundle_owner_id !== row.owner_id || row.bundle_agent_id !== row.agent_id ||
      row.bundle_task_id !== taskId || row.bundle_closure_id !== closureId || row.bundle_preparation_id !== prepId ||
      row.bundle_lease_id !== leaseId || row.bundle_environment_id !== environmentId || row.bundle_generation_id !== generationId ||
      row.bundle_release_identity !== row.release_identity || row.bundle_release_manifest_hash !== manifestHash ||
      row.bundle_case_id !== row.preparation_case_id || row.bundle_case_hash !== row.preparation_case_hash) return false;
  if (row.bundle_closure_operation_id !== row.closure_operation_id || row.bundle_closure_payload_hash !== row.closure_payload_hash ||
      row.bundle_closure_reason !== row.closure_reason || row.bundle_rubric_hash !== row.evaluation_rubric_hash ||
      row.evaluation_case_hash !== row.preparation_case_hash) return false;
  if (row.bundle_environment_manifest_hash !== row.preparation_environment_manifest_sha256 ||
      row.bundle_application_source_hash !== row.preparation_application_source_hash ||
      row.bundle_execution_identity_hash !== row.preparation_execution_identity_hash ||
      row.preparation_initial_state_sha256 !== row.bundle_initial_state_sha256) return false;
  if (row.bundle_cutoff_sequence === null || String(row.bundle_cutoff_sequence) !== String(cutoff) ||
      row.bundle_reconciled_sequence === null || String(row.bundle_reconciled_sequence) !== String(reconciled)) return false;
  const bundleBinding = recoveryObject(bundle.binding);
  const bundleClosure = recoveryObject(bundle.closure);
  const bundleExecution = recoveryObject(bundle.execution);
  if (!bundleBinding || !bundleClosure || !bundleExecution ||
      bundleBinding.runId !== id || bundleBinding.ownerId !== row.owner_id || bundleBinding.agentId !== row.agent_id ||
      bundleBinding.taskId !== taskId || bundleBinding.environmentId !== environmentId ||
      bundleBinding.releaseIdentity !== row.release_identity || bundleBinding.manifestHash !== row.release_manifest_hash ||
      bundleBinding.caseId !== row.preparation_case_id || bundleBinding.caseHash !== row.preparation_case_hash ||
      bundleBinding.rubricHash !== row.evaluation_rubric_hash ||
      bundleClosure.closureId !== closureId || bundleClosure.operationId !== row.closure_operation_id ||
      bundleClosure.payloadHash !== row.closure_payload_hash || bundleClosure.reason !== row.closure_reason ||
      String(bundleClosure.actionCutoffSequence) !== String(cutoff) ||
      String(bundleClosure.reconciledActionSequence) !== String(reconciled) ||
      bundleExecution.preparationId !== prepId || bundleExecution.leaseId !== leaseId || bundleExecution.generationId !== generationId ||
      bundleExecution.environmentManifestHash !== row.preparation_environment_manifest_sha256 ||
      bundleExecution.applicationSourceHash !== row.preparation_application_source_hash ||
      bundleExecution.executionIdentityHash !== row.preparation_execution_identity_hash) return false;
  const bundleCutoff = recoveryObject(bundle.cutoff);
  const observations = recoveryObject(bundle.observations);
  if (!bundleCutoff || !observations || bundleCutoff.status !== 'authoritative' ||
      !Number.isSafeInteger(bundleCutoff.observationSequence) || observations.coveredThroughSequence !== bundleCutoff.observationSequence) return false;

  const result = recoveryObject(row.evaluation_result_json);
  const input = recoveryObject(row.evaluation_input_json);
  if (!result || !input || row.evaluation_run_id !== id || row.evaluation_task_index !== index ||
      row.evaluation_closure_id !== closureId || row.evaluation_task_id !== taskId ||
      row.evaluation_release_identity !== row.release_identity || row.evaluation_manifest_hash !== row.release_manifest_hash ||
      result.status !== 'known' || result.taskId !== taskId || !['passed', 'partial', 'failed'].includes(String(result.outcome)) ||
      row.evaluation_result_hash !== sha256CanonicalTaskJson(result) ||
      typeof row.evaluation_input_hash !== 'string' || row.evaluation_input_hash !== sha256CanonicalTaskJson(input)) return false;
  const inputRun = recoveryObject(input.run);
  if (!inputRun || inputRun.runId !== id || inputRun.ownerId !== row.owner_id || inputRun.agentId !== row.agent_id ||
      inputRun.environmentId !== environmentId || inputRun.taskId !== taskId ||
      inputRun.releaseIdentity !== row.release_identity || inputRun.manifestHash !== row.release_manifest_hash ||
      inputRun.acceptedActionCutoffSequence !== cutoffNumber || inputRun.reconciledThroughActionSequence !== reconciledNumber ||
      inputRun.cutoffStatus !== 'authoritative' || inputRun.observationCutoffSequence !== bundleCutoff.observationSequence ||
      !sameCanonical(inputRun.cutoffEvidence, bundleCutoff.evidence) || !sameCanonical(input.observations, bundle.observations)) return false;
  const inputCase = recoveryObject(input.taskCase);
  const inputRelease = recoveryObject(input.release);
  if (!inputCase || !inputRelease || inputCase.taskId !== taskId || inputCase.mode !== row.run_mode || inputCase.caseId !== row.preparation_case_id ||
      inputCase.caseHash !== row.preparation_case_hash || inputCase.rubricHash !== row.evaluation_rubric_hash ||
      inputRelease.releaseIdentity !== row.release_identity || inputRelease.manifestHash !== row.release_manifest_hash) return false;

  const eventPayload = recoveryObject(row.evaluation_event_payload_json);
  const expectedEvent = { taskIndex: index, taskId, closureId, releaseIdentity: row.release_identity,
    manifestHash: row.release_manifest_hash, inputHash: row.evaluation_input_hash, resultHash: row.evaluation_result_hash,
    evaluatorSourceHash: row.evaluation_evaluator_source_hash };
  return String(row.evaluation_event_count) === '1' && String(row.terminalization_event_count) === '0' &&
    row.evaluation_event_source === 'coordinator' && !!eventPayload &&
    sameCanonical(eventPayload, expectedEvent) && row.evaluation_event_payload_hash === sha256CanonicalTaskJson(expectedEvent);
}

export function activeTaskNeedsCancellationAfterRecovery(
  runId: string,
  taskIndex: number,
  attached: ReadonlyMap<string, unknown>,
  recoveryRow: FencedKnownTaskRecoveryRow,
): boolean {
  return !isExactFencedKnownClosedTask(recoveryRow) && activeTaskNeedsCancellation(runId, taskIndex, attached);
}

export function taskIndexFromFenceResult(result: {
  fenced: boolean; taskPreparation?: { taskIndex: number; preparationId: string; generationId: string | null };
}): number | null {
  const index = result.taskPreparation?.taskIndex;
  return result.fenced && Number.isSafeInteger(index) && index! >= 0 && index! <= 11 ? index! : null;
}

export function leaseGuardedPreparedTaskStartPort(
  base: PreparedTaskStartPort,
  assertLeaseHeld: () => Promise<void>,
): PreparedTaskStartPort {
  return {
    async readCandidatePreparationId(target) {
      await assertLeaseHeld();
      const preparationId = await base.readCandidatePreparationId(target);
      await assertLeaseHeld();
      return preparationId;
    },
    async assertReadyInTransaction(tx, target, preparationId, minimumValidUntil) {
      await assertLeaseHeld();
      const preparation = await base.assertReadyInTransaction(tx, target, preparationId, minimumValidUntil);
      await assertLeaseHeld();
      return preparation;
    },
    hasUsableStartSession: (preparation, minimumValidUntil) =>
      base.hasUsableStartSession(preparation, minimumValidUntil),
    assertLeaseHeld,
    async attachStartedSession(preparation, minimumValidUntil) {
      await assertLeaseHeld();
      await base.attachStartedSession(preparation, minimumValidUntil);
      await assertLeaseHeld();
    },
  };
}

export async function handoffCommittedSuccessor(input: {
  runId: string;
  taskIndex: number;
  replayed: boolean;
  preparation: TaskPreparationRecord | null;
  taskDeadline: string;
  isAttached(): boolean;
  assertLeaseHeld(): Promise<void>;
  attach(preparation: TaskPreparationRecord, taskDeadline: string): Promise<void>;
  cancelAndFence(runId: string, taskIndex: number, reason: LocalCoordinatorCancellationReason): Promise<void>;
}): Promise<'attached' | 'already_attached' | 'cancelled' | 'lease_lost'> {
  const targetMatches = input.preparation?.intent.runId === input.runId &&
    input.preparation.intent.taskIndex === input.taskIndex;
  if (input.replayed || !targetMatches) {
    if (input.isAttached()) return 'already_attached';
    try { await input.assertLeaseHeld(); }
    catch { return 'lease_lost'; }
    await input.cancelAndFence(input.runId, input.taskIndex, 'coordinator_executor_session_lost');
    return 'cancelled';
  }
  try {
    await input.assertLeaseHeld();
    await input.attach(input.preparation!, input.taskDeadline);
    await input.assertLeaseHeld();
    return 'attached';
  } catch {
    try { await input.assertLeaseHeld(); }
    catch { return 'lease_lost'; }
    await input.cancelAndFence(input.runId, input.taskIndex, 'coordinator_executor_session_lost');
    return 'cancelled';
  }
}
function parseJsonObject(value: unknown): Record<string, unknown> | null {
  return value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : null;
}
function exactRequiredRecipient(taskCase: TaskCase): string | null {
  switch (taskCase.taskId) {
    case 'M1': return taskCase.objective.paymentRequirements.recipient;
    case 'S2': return taskCase.objective.completePaymentRequirements.recipient;
    case 'S3': case 'M2': return taskCase.objective.required.recipient;
    default: return null;
  }
}
function numericIdentity(value: unknown): bigint | null {
  try {
    if (typeof value !== 'string' && typeof value !== 'number' && typeof value !== 'bigint') return null;
    return BigInt(value);
  } catch { return null; }
}

function environmentMaps(environments: CoordinatorEnvironment[], profile: 'local' | 'beta') {
  const apiBaseByEnvironment: Record<string, string> = {};
  const observerRpcByEnvironment: Record<string, string> = {};
  const participantApiByEnvironment: Record<string, string> = {};
  const anvilManifestPinByEnvironment: Record<string, { manifestSha256: string; executionNetwork: string; hardFork: string; anvilVersion: string }> = {};
  const pinnedX402PolicyByEnvironment: Record<string, PinnedX402Policy> = {};
  for (const environment of environments) {
    const id = environment.envId;
    apiBaseByEnvironment[id] = profile === 'local'
      ? validateUrl(environment.apiBaseUrl, { localOnly: true, httpOnly: true })
      : validateBetaPrivateServiceUrl(environment.apiBaseUrl);
    if (profile === 'local' && !allowedParticipantApiHost(new URL(apiBaseByEnvironment[id]!).hostname)) {
      throw new Error('local_bef_coordinator_participant_api_host_invalid');
    }
    observerRpcByEnvironment[id] = profile === 'local'
      ? validateUrl(environment.observerRpcUrl, { localOnly: true, httpOnly: true })
      : validateBetaPrivateServiceUrl(environment.observerRpcUrl);
    participantApiByEnvironment[id] = apiBaseByEnvironment[id]!;
    const policy = assertPolicy(environment.x402Policy);
    anvilManifestPinByEnvironment[id] = {
      manifestSha256: policy.manifestSha256.toLowerCase(), executionNetwork: policy.localAnvil.executionNetwork,
      hardFork: policy.localAnvil.hardFork, anvilVersion: policy.localAnvil.anvilVersion,
    };
    pinnedX402PolicyByEnvironment[id] = policy;
  }
  const expected = Object.keys(apiBaseByEnvironment).sort().join('|');
  for (const map of [observerRpcByEnvironment, participantApiByEnvironment, anvilManifestPinByEnvironment, pinnedX402PolicyByEnvironment]) {
    if (Object.keys(map).sort().join('|') !== expected) throw new Error('local_bef_coordinator_environment_map_coverage_invalid');
  }
  return { apiBaseByEnvironment, observerRpcByEnvironment, participantApiByEnvironment,
    anvilManifestPinByEnvironment, pinnedX402PolicyByEnvironment };
}

export async function writeSafeEvidence(projectRoot: string, category: 'preparation' | 'action' | 'lifecycle', id: string,
  value: unknown, evidenceDirectory = EVIDENCE_DIR): Promise<{ path: string; sha256: string }> {
  if (!UUID.test(id)) throw new Error('local_bef_coordinator_evidence_identity_invalid');
  const singleComponentDirectory = /^[A-Za-z0-9._-]{1,80}$/.test(evidenceDirectory)
    && evidenceDirectory !== '.' && evidenceDirectory !== '..';
  if (evidenceDirectory !== EVIDENCE_DIR && !singleComponentDirectory) {
    throw new Error('local_bef_coordinator_evidence_path_invalid');
  }
  const projectRootAbsolute = resolve(projectRoot);
  const evidenceRoot = resolve(projectRootAbsolute, evidenceDirectory);
  if (!under(projectRootAbsolute, evidenceRoot)) throw new Error('local_bef_coordinator_evidence_path_invalid');
  await mkdir(evidenceRoot, { recursive: true, mode: 0o700 });
  const realProjectRoot = await realpath(projectRootAbsolute);
  const realEvidenceRoot = await realpath(evidenceRoot);
  if (!under(realProjectRoot, realEvidenceRoot)) throw new Error('local_bef_coordinator_evidence_path_invalid');
  const root = resolve(realEvidenceRoot, category);
  await mkdir(root, { recursive: true, mode: 0o700 });
  const realRoot = await realpath(root);
  if (!under(realEvidenceRoot, realRoot)) throw new Error('local_bef_coordinator_evidence_path_invalid');
  const bytes = Buffer.from(`${JSON.stringify(value)}\n`, 'utf8');
  const name = `${id.toLowerCase()}-${randomUUID()}.json`;
  const absolute = resolve(realRoot, name);
  await writeFile(absolute, bytes, { flag: 'wx', mode: 0o600 });
  return { path: `${evidenceDirectory}/${category}/${name}`, sha256: hash(bytes.toString('utf8')) };
}

function buildEnvironmentSelector(input: {
  db: OwnerDatabase; releaseSource: TaskReleaseQuerySource; environments: CoordinatorEnvironment[]; fetchImpl: typeof fetch;
  profile: 'local' | 'beta'; betaManifest?: BetaDeploymentManifest; apiBaseByEnvironment: Record<string, string>;
}) {
  return {
    async selectEnvironment(target: { runId: string; taskIndex: number; manifestHash: string; environmentManifestSha256: string; taskCase: TaskCase }): Promise<string> {
      const runRows = await input.db.execute(sql`SELECT release_identity,manifest_hash,mode FROM oid_benchmark_run WHERE id=${target.runId} LIMIT 1`) as unknown as Array<{ release_identity: string; manifest_hash: string; mode: string }>;
      const run = runRows[0];
      if (!run || run.manifest_hash.toLowerCase() !== target.manifestHash.toLowerCase()) throw new Error('local_bef_coordinator_run_pin_unavailable');
      const release = await input.releaseSource.getValidatedReleaseRecord(run.release_identity, run.manifest_hash);
      if (input.profile === 'beta' && (!input.betaManifest || !betaReleaseMatchesManifest(release, input.betaManifest))) {
        throw new Error('beta_bef_coordinator_active_release_pin_mismatch');
      }
      const identity = release?.manifest.executionIdentity;
      const pinnedCase = release?.manifest.cases[run.mode as 'training' | 'ranked']?.find((item) => item.taskId === target.taskCase.taskId);
      if (!release || !identity || !pinnedCase || pinnedCase.caseId !== target.taskCase.caseId ||
          pinnedCase.caseHash.toLowerCase() !== target.taskCase.caseHash.toLowerCase() ||
          identity.environmentManifestSha256.toLowerCase() !== target.environmentManifestSha256.toLowerCase()) {
        throw new Error('local_bef_coordinator_case_pin_unavailable');
      }
      const envIds = input.environments.map((environment) => environment.envId);
      const active = await input.db.execute(sql`SELECT DISTINCT environment_id FROM oid_task_environment_lease
        WHERE state='leased' AND environment_id IN (${sql.join(envIds.map((id) => sql`${id}`), sql`,`)})`) as unknown as Array<{ environment_id: string }>;
      const activeIds = new Set(active.map((row) => row.environment_id));
      const requiredRecipient = exactRequiredRecipient(target.taskCase)?.toLowerCase() ?? null;
      for (const environment of input.environments) {
        const policy = assertPolicy(environment.x402Policy);
        if (activeIds.has(environment.envId) || policy.manifestSha256.toLowerCase() !== target.environmentManifestSha256.toLowerCase()) continue;
        let response: Response;
        let body: Record<string, unknown> | null;
        try {
          response = await input.fetchImpl(new URL('/healthz', input.apiBaseByEnvironment[environment.envId]!), {
            method: 'GET', redirect: 'error', signal: AbortSignal.timeout(5000),
          });
          const bytes = new Uint8Array(await response.arrayBuffer());
          if (bytes.length > 256 * 1024 || !response.ok) continue;
          body = parseJsonObject(JSON.parse(Buffer.from(bytes).toString('utf8')) as unknown);
        } catch { continue; }
        if (!body || body.status !== 'ready' || body.boundary !== 'benchmark-environment-api' ||
            typeof body.manifestSha256 !== 'string' || body.manifestSha256.toLowerCase() !== target.environmentManifestSha256.toLowerCase() ||
            typeof body.applicationSourceSha256 !== 'string' || body.applicationSourceSha256.toLowerCase() !== identity.x402ServiceSha256.toLowerCase() ||
            !Array.isArray(body.environments)) continue;
        const healthEnvironments = body.environments.map(parseJsonObject).filter((item): item is Record<string, unknown> => item !== null && item.envId === environment.envId);
        if (healthEnvironments.length !== 1) continue;
        const selected = healthEnvironments[0]!;
        const anvil = parseJsonObject(selected.anvil);
        const facilitator = parseJsonObject(selected.facilitator);
        const localAnvil = policy.localAnvil;
        if (!anvil || !facilitator || typeof anvil.clientVersion !== 'string' ||
            !anvil.clientVersion.toLowerCase().includes(`anvil/v${localAnvil.anvilVersion}`.toLowerCase()) ||
            numericIdentity(anvil.chainId) !== BigInt(localAnvil.chainId) ||
            typeof anvil.executionNetwork !== 'string' || anvil.executionNetwork.toLowerCase() !== localAnvil.executionNetwork.toLowerCase() ||
            typeof anvil.hardFork !== 'string' || anvil.hardFork.toLowerCase() !== localAnvil.hardFork.toLowerCase() ||
            numericIdentity(anvil.forkBlockNumber) !== BigInt(localAnvil.forkBlockNumber) ||
            typeof anvil.forkBlockHash !== 'string' || anvil.forkBlockHash.toLowerCase() !== localAnvil.forkBlockHash.toLowerCase() ||
            (requiredRecipient !== null && (typeof facilitator.address !== 'string' ||
              !ADDRESS.test(facilitator.address) || facilitator.address.toLowerCase() !== requiredRecipient))) continue;
        return environment.envId;
      }
      throw new Error('local_bef_coordinator_no_free_compatible_environment');
    },
  };
}

export async function createLocalBefTaskCoordinator(input: {
  db: OwnerDatabase;
  databaseUrl: string;
  config: Pick<OwnerIdentityConfig, 'localBefTaskCoordinatorConfigPath' | 'localBefTaskCoordinatorBatchSize' | 'localBefTaskCoordinatorTickMs'> &
    Partial<Pick<OwnerIdentityConfig, 'localReportAcceptanceEnabled' | 'privateDataDir'>>;
  projectRoot?: string;
  releaseSource: TaskReleaseQuerySource;
  fetch?: typeof fetch;
}): Promise<LocalBefTaskCoordinator> {
  const projectRoot = input.projectRoot ?? PROJECT_ROOT;
  const configPath = input.config.localBefTaskCoordinatorConfigPath;
  if (!configPath) throw new Error('local_bef_coordinator_config_path_missing');
  const loadedConfig = await loadLocalBefTaskCoordinatorConfig(configPath, projectRoot);
  const fileConfig: LoadedCoordinatorConfig = { ...loadedConfig,
    environments: loadedConfig.environments.map((environment) => ({ ...environment,
      x402Policy: assertPolicy(environment.x402Policy) })) };
  const batchSize = input.config.localBefTaskCoordinatorBatchSize;
  if (!Number.isSafeInteger(batchSize) || batchSize < 1 || batchSize > 20) throw new Error('local_bef_coordinator_batch_size_invalid');
  return createBefTaskCoordinatorCore({ db: input.db, databaseUrl: input.databaseUrl, projectRoot,
    releaseSource: input.releaseSource, ...(input.fetch ? { fetch: input.fetch } : {}), fileConfig, batchSize, profile: 'local',
    ...(input.config.localReportAcceptanceEnabled && input.config.privateDataDir
      ? { operationsPrivateDataDir: input.config.privateDataDir } : {}) });
}

export async function createBetaBefTaskCoordinator(input: {
  db: OwnerDatabase;
  databaseUrl: string;
  config: Pick<OwnerIdentityConfig, 'betaBefTaskCoordinatorConfigPath' | 'localBefTaskCoordinatorBatchSize' |
    'localBefTaskCoordinatorTickMs' | 'privateDataDir' | 'betaManifest'>;
  projectRoot?: string;
  releaseSource: TaskReleaseQuerySource;
  fetch?: typeof fetch;
}): Promise<BetaBefTaskCoordinator> {
  const manifest = input.config.betaManifest;
  const privateDataDir = input.config.privateDataDir;
  const configPath = input.config.betaBefTaskCoordinatorConfigPath;
  if (!manifest || !privateDataDir || !configPath) throw new Error('beta_bef_coordinator_profile_missing');
  const fileConfig = await loadBetaBefTaskCoordinatorConfig(configPath, privateDataDir);
  if (!fileConfig.observationDatabase) throw new Error('beta_bef_recovery_observer_required');
  const repositoryRoot = input.projectRoot ?? PROJECT_ROOT;
  const build = await observeBetaBuildIdentity({ repositoryRoot, evaluatorSourceSha256: await getTaskEvaluatorBuildHash(),
    expected: manifest.source });
  assertBetaBuildMatchesManifest(manifest, build);
  const readinessProvider = createBetaBefReadinessProvider({ db: input.db, releaseSource: input.releaseSource,
    manifest, build, environments: fileConfig.environments, sourceRpcUrl: fileConfig.sourceRpcUrl,
    ...(input.fetch ? { fetchImpl: input.fetch } : {}) });
  const coordinator = await createBefTaskCoordinatorCore({ db: input.db, databaseUrl: input.databaseUrl,
    projectRoot: resolve(privateDataDir), releaseSource: input.releaseSource, ...(input.fetch ? { fetch: input.fetch } : {}), fileConfig,
    batchSize: input.config.localBefTaskCoordinatorBatchSize, profile: 'beta', betaManifest: manifest,
    evidenceDirectory: manifest.storage.evidenceDirectory, readinessProvider });
  return Object.assign(coordinator, { readinessProvider });
}

async function createBefTaskCoordinatorCore(input: {
  db: OwnerDatabase;
  databaseUrl: string;
  projectRoot: string;
  releaseSource: TaskReleaseQuerySource;
  fetch?: typeof fetch;
  fileConfig: LoadedCoordinatorConfig;
  batchSize: number;
  profile: 'local' | 'beta';
  betaManifest?: BetaDeploymentManifest;
  evidenceDirectory?: string;
  readinessProvider?: BetaBefReadinessProvider;
  operationsPrivateDataDir?: string;
}): Promise<LocalBefTaskCoordinator> {
  const projectRoot = input.projectRoot;
  const fileConfig = input.fileConfig;
  const evidenceDirectory = input.evidenceDirectory ?? EVIDENCE_DIR;
  const maps = environmentMaps(fileConfig.environments, input.profile);
  const batchSize = input.batchSize;
  if (!Number.isSafeInteger(batchSize) || batchSize < 1 || batchSize > 20) throw new Error(`${input.profile}_bef_coordinator_batch_size_invalid`);
  const fetchImpl = input.fetch ?? fetch;
  const leaseClient = postgres(input.databaseUrl, { max: 1, idle_timeout: 0, connect_timeout: 10 });
  const lease = new PostgresLocalCoordinatorLease(leaseClient);
  const attached = new Map<string, { runId: string; taskIndex: number; preparationId: string }>();
  const observationProgress = new Map<string, string>();
  let stopped = false;
  let inFlight: Promise<void> | null = null;

  const preparationEvidenceSink = {
    async write(value: { kind: 'fixture' | 'baseline' | 'fence'; preparationId: string; environmentId: string;
      publicPinsSha256: string; evidence: Record<string, unknown> }) {
      return { ...await writeSafeEvidence(projectRoot, 'preparation', value.preparationId, value, evidenceDirectory),
        boundary: 'actual_tool_http_x402_local_evm_application_store' as const };
    },
  };
  const preparationDiagnostic = async (value: BefPreparationDiagnostic) => {
    await writeSafeEvidence(projectRoot, 'lifecycle', value.preparationId, value, evidenceDirectory);
  };
  const actionEvidenceSink = {
    async write(value: SafeTaskActionEvidence) {
      return writeSafeEvidence(projectRoot, 'action', value.actionId, value, evidenceDirectory);
    },
  };
  const adapter = new BefTaskPreparationAdapter({
    apiBaseByEnvironment: maps.apiBaseByEnvironment,
    observerRpcByEnvironment: maps.observerRpcByEnvironment,
    sourceRpcUrl: fileConfig.sourceRpcUrl,
    adminKey: fileConfig.adminKey,
    anvilManifestPinByEnvironment: maps.anvilManifestPinByEnvironment,
    releaseSource: input.releaseSource,
    evidenceSink: preparationEvidenceSink,
    preparationDiagnostic,
    fetch: fetchImpl,
  });
  const executor = new BefTaskExecutor({ db: input.db, taskReleaseSource: input.releaseSource,
    participantApiByEnvironment: maps.participantApiByEnvironment, pinnedX402PolicyByEnvironment: maps.pinnedX402PolicyByEnvironment,
    evidenceSink: actionEvidenceSink, fetch: fetchImpl });

  const guardedPreparationAdapter: TaskPreparationDependencies['preparationAdapter'] = {
    async prepare(value) { await lease.assertHeld(); return adapter.prepare(value); },
    async reconcile(value) { await lease.assertHeld(); return adapter.reconcile(value); },
    async fence(value) { await lease.assertHeld(); return adapter.fence(value); },
    hasUsableStartSession: (intent, minimum) => adapter.hasUsableStartSession(intent, minimum),
    clearCredentials: (preparationId) => adapter.clearCredentials(preparationId),
  };
  const preparationDependencies: TaskPreparationDependencies = {
    db: input.db,
    releaseSource: input.releaseSource,
    preparationAdapter: guardedPreparationAdapter,
    environmentSelector: buildEnvironmentSelector({ db: input.db, releaseSource: input.releaseSource,
      environments: fileConfig.environments, fetchImpl, profile: input.profile,
      ...(input.betaManifest ? { betaManifest: input.betaManifest } : {}), apiBaseByEnvironment: maps.apiBaseByEnvironment }),
  };
  const evidenceSource = new TaskSealedEvidenceSource({
    taskReleaseSource: input.releaseSource,
    evidenceRoot: projectRoot,
  });
  const successorPreparationDependencies: SuccessorTaskPreparationDependencies = {
    ...preparationDependencies,
    predecessorEvidenceSource: evidenceSource,
  };
  async function attachPreparedSession(record: TaskPreparationRecord, minimumValidUntil: string): Promise<void> {
    await lease.assertHeld();
    const binding = adapter.sessionBindingAfterStart(record.intent, minimumValidUntil);
    if (!binding || binding.runId !== record.intent.runId || binding.taskIndex !== record.intent.taskIndex ||
        binding.generationId !== record.observation.generationId || binding.envId !== record.intent.environmentId) {
      throw new Error('local_bef_coordinator_prepared_ram_session_missing');
    }
    await executor.attachStartedSession(binding);
    attached.set(sessionKey(binding.runId, binding.taskIndex), {
      runId: binding.runId, taskIndex: binding.taskIndex, preparationId: record.intent.preparationId,
    });
    await lease.assertHeld();
  }
  const preparedTaskStart = leaseGuardedPreparedTaskStartPort(
    createPreparedTaskStartPort(preparationDependencies, attachPreparedSession), () => lease.assertHeld(),
  );
  const runServiceDependencies: RunServiceDependencies = {
    db: input.db,
    betaOperationsEnabled: input.profile === 'beta' || Boolean(input.operationsPrivateDataDir),
    bonusOnly: input.profile === 'beta',
    ...(input.profile === 'beta' && input.betaManifest
      ? { privateDataDir: input.betaManifest.storage.privateDataDir }
      : input.operationsPrivateDataDir ? { privateDataDir: input.operationsPrivateDataDir } : {}),
    admissionReleaseProvider: input.betaManifest
      ? pinBetaRunReleaseProvider(createPostgresTaskReleaseProvider(input.db), input.betaManifest)
      : createPostgresTaskReleaseProvider(input.db),
    executionReadinessProvider: null,
    preparedTaskStart,
    ...(input.profile === 'beta' ? BETA_BEF_RUN_SERVICE_POLICY : LOCAL_BEF_RUN_SERVICE_POLICY),
  };
  const baseCancellationExecutor = createTaskPreparationCancellationExecutor(preparationDependencies, executor,{actionEvidenceSink});
  const cancellationExecutor = {
    async fenceAndStop(value: Parameters<typeof baseCancellationExecutor.fenceAndStop>[0]) {
      await lease.assertHeld();
      const result = await baseCancellationExecutor.fenceAndStop(value);
      await lease.assertHeld();
      const taskIndex = taskIndexFromFenceResult(result);
      if (taskIndex !== null) attached.delete(sessionKey(value.runId, taskIndex));
      return result;
    },
  };

  async function requestCancellation(runId: string, reason: LocalCoordinatorCancellationReason): Promise<void> {
    await lease.assertHeld();
    await requestRunCancellationFromCoordinator(input.db, { runId, reason });
    await lease.assertHeld();
  }

  async function drainCancellations(): Promise<void> {
    await lease.assertHeld();
    await consumeRunCancellationOutbox(input.db, cancellationExecutor, batchSize);
    await lease.assertHeld();
  }

  async function cancelOldPreparationIntents(): Promise<void> {
    await lease.assertHeld();
    const rows = await input.db.execute(sql`SELECT r.id AS run_id,i.preparation_id,o.status AS observation_status,
        l.state AS lease_state,
        d.state AS dispatch_status
      FROM oid_benchmark_run r
      JOIN oid_run_dispatch_claim c ON c.run_id=r.id AND c.status='claimed'
      JOIN oid_task_preparation_intent i ON i.run_id=r.id
      JOIN oid_run_task t ON t.run_id=i.run_id AND t.task_index=i.task_index
      JOIN oid_task_environment_lease l ON l.lease_id=i.lease_id AND l.preparation_id=i.preparation_id
      JOIN LATERAL (SELECT status,generation_id FROM oid_task_preparation_observation
        WHERE preparation_id=i.preparation_id ORDER BY revision DESC LIMIT 1) o ON true
      LEFT JOIN oid_task_preparation_dispatch d ON d.preparation_id=i.preparation_id
      WHERE (r.status='preparing' AND i.task_index=0) OR
        (r.status='running' AND r.mode IN ('training','ranked') AND i.task_index>0 AND t.status='queued' AND l.state='leased')
      ORDER BY i.created_at,i.preparation_id LIMIT ${batchSize}`) as unknown as Array<{ run_id: string; preparation_id: string;
        observation_status: string; lease_state: string; dispatch_status: string | null }>;
    await lease.assertHeld();
    for (const row of rows) {
      await lease.assertHeld();
      // No process-local credential survives restart. A dispatch row means a PUT may have
      // happened; a completed/ready row also cannot be started without its original RAM session.
      // Only the pre-dispatch state is safe to resume with the same immutable preparation id.
      if (isResumablePreDispatchPreparation(row)) continue;
      await requestCancellation(row.run_id, 'coordinator_interrupted_preparation');
    }
  }

  async function cancelRunningBindingsWithoutRam(recoveringRunIds: ReadonlySet<string> = new Set()): Promise<void> {
    await lease.assertHeld();
    const rows = await input.db.execute(sql`SELECT r.id AS run_id,r.owner_id,r.agent_id,r.mode AS run_mode,r.status AS run_status,
        r.release_identity,r.manifest_hash AS release_manifest_hash,r.overall_deadline,
        r.cancellation_reason AS run_cancellation_reason,r.cancellation_requested_at AS run_cancellation_requested_at,
        clock_timestamp() AS recovery_observed_at,t.closed_at,
        (SELECT count(*)::int FROM oid_run_task active WHERE active.run_id=r.id AND active.status='active') AS recovery_active_task_count,
        (SELECT count(*)::text FROM oid_run_task_action a WHERE a.run_id=r.id AND a.task_index=t.task_index) AS recovery_action_count,
        (SELECT COALESCE(max(a.action_sequence),0)::text FROM oid_run_task_action a WHERE a.run_id=r.id AND a.task_index=t.task_index) AS recovery_max_sequence,
        EXISTS (SELECT 1 FROM oid_run_task_action a
          LEFT JOIN oid_run_task_action_receipt receipt ON receipt.action_id=a.id
          LEFT JOIN oid_run_task_action_outbox outbox ON outbox.action_id=a.id
          WHERE a.run_id=r.id AND a.task_index=t.task_index AND a.action_sequence<=t.action_cutoff_sequence
            AND (receipt.action_id IS NULL OR receipt.receipt_status NOT IN ('observed','rejected_before_execution')
              OR outbox.action_id IS NULL OR outbox.status<>'delivered')) AS recovery_unresolved_action,
        EXISTS (SELECT 1 FROM oid_owner own JOIN oid_agent a ON a.owner_id=own.id
          JOIN oid_agent_policy policy ON policy.agent_id=a.id
          WHERE own.id=r.owner_id AND a.id=r.agent_id AND own.admission_status='admitted'
            AND a.access_revoked_at IS NULL AND a.access_generation=r.access_generation
            AND CASE WHEN r.mode='training' THEN policy.training ELSE policy.ranked END) AS recovery_access_current,
        EXISTS (SELECT 1 FROM oid_run_dispatch_claim claim
          JOIN oid_run_execution_slot slot ON slot.run_id=claim.run_id AND slot.claim_id=claim.claim_id
          WHERE claim.run_id=r.id AND claim.claim_id=i.claim_id AND claim.status='claimed'
            AND slot.agent_id=r.agent_id AND slot.state='running' AND slot.released_at IS NULL) AS recovery_claim_slot_matches,
        t.task_index,t.task_id,t.status AS task_status,t.closure_status,t.closure_id,
        t.closure_operation_id,t.closure_payload_hash,t.closure_reason,
        t.accepted_action_sequence::text AS accepted_action_sequence,t.action_cutoff_sequence::text AS action_cutoff_sequence,
        t.reconciled_action_sequence::text AS reconciled_action_sequence,
        i.preparation_id,i.run_id AS preparation_run_id,i.task_index AS preparation_task_index,i.task_id AS preparation_task_id,
        i.release_identity AS preparation_release_identity,i.manifest_hash AS preparation_manifest_hash,
        i.case_id AS preparation_case_id,i.case_hash AS preparation_case_hash,i.initial_state_sha256 AS preparation_initial_state_sha256,
        i.environment_manifest_sha256 AS preparation_environment_manifest_sha256,
        i.application_source_hash AS preparation_application_source_hash,i.execution_identity_hash AS preparation_execution_identity_hash,
        i.lease_id AS preparation_lease_id,i.environment_id AS preparation_environment_id,
        l.preparation_id AS lease_preparation_id,l.lease_id,l.state AS lease_state,l.fence_evidence AS lease_fence_evidence,
        o.status AS observation_status,o.generation_id AS observed_generation_id,o.generation_id AS preparation_observation_generation_id,
        g.generation_id AS registered_generation_id,g.environment_id AS registered_environment_id,
        eb.run_id AS binding_run_id,eb.task_index AS binding_task_index,eb.env_id AS binding_environment_id,
        eb.generation_id AS binding_generation_id,eb.manifest_hash AS binding_manifest_hash,
        eb.application_source_hash AS binding_source_hash,
        c.id AS journal_closure_id,c.run_id AS closure_run_id,c.task_index AS closure_task_index,c.owner_id AS journal_owner_id,
        c.agent_id AS journal_agent_id,c.operation_id AS journal_operation_id,c.payload_hash AS journal_payload_hash,c.reason AS journal_reason,
        c.requested_at AS journal_requested_at,
        c.action_cutoff_sequence::text AS journal_cutoff_sequence,t.closure_payload_hash,t.closure_reason,
        ob.run_id AS bundle_run_id,ob.task_index AS bundle_task_index,ob.owner_id AS bundle_owner_id,ob.agent_id AS bundle_agent_id,
        ob.task_id AS bundle_task_id,ob.closure_id AS bundle_closure_id,ob.preparation_id AS bundle_preparation_id,
        ob.release_identity AS bundle_release_identity,ob.release_manifest_hash AS bundle_release_manifest_hash,
        ob.closure_operation_id AS bundle_closure_operation_id,ob.closure_payload_hash AS bundle_closure_payload_hash,
        ob.closure_reason AS bundle_closure_reason,ob.case_id AS bundle_case_id,ob.case_hash AS bundle_case_hash,
        ob.rubric_hash AS bundle_rubric_hash,ob.initial_state_sha256 AS bundle_initial_state_sha256,
        ob.environment_manifest_hash AS bundle_environment_manifest_hash,ob.application_source_hash AS bundle_application_source_hash,
        ob.execution_identity_hash AS bundle_execution_identity_hash,
        ob.lease_id AS bundle_lease_id,ob.environment_id AS bundle_environment_id,ob.generation_id AS bundle_generation_id,
        ob.action_cutoff_sequence::text AS bundle_cutoff_sequence,ob.reconciled_action_sequence::text AS bundle_reconciled_sequence,
        ob.bundle_hash,ob.bundle_json,
        e.run_id AS evaluation_run_id,e.task_index AS evaluation_task_index,e.closure_id AS evaluation_closure_id,
        e.task_id AS evaluation_task_id,e.release_identity AS evaluation_release_identity,e.manifest_hash AS evaluation_manifest_hash,
        e.case_hash AS evaluation_case_hash,e.rubric_hash AS evaluation_rubric_hash,
        e.input_hash AS evaluation_input_hash,e.result_hash AS evaluation_result_hash,e.evaluator_source_hash AS evaluation_evaluator_source_hash,
        e.input_json AS evaluation_input_json,e.result_json AS evaluation_result_json,
        (SELECT COUNT(*)::text FROM oid_run_event ev WHERE ev.run_id=r.id AND ev.event_type='task.evaluated'
          AND ev.payload_json->>'taskIndex'=t.task_index::text) AS evaluation_event_count,
        (SELECT ev.payload_hash FROM oid_run_event ev WHERE ev.run_id=r.id AND ev.event_type='task.evaluated'
          AND ev.payload_json->>'taskIndex'=t.task_index::text ORDER BY ev.sequence LIMIT 1) AS evaluation_event_payload_hash,
        (SELECT ev.source FROM oid_run_event ev WHERE ev.run_id=r.id AND ev.event_type='task.evaluated'
          AND ev.payload_json->>'taskIndex'=t.task_index::text ORDER BY ev.sequence LIMIT 1) AS evaluation_event_source,
        (SELECT ev.payload_json FROM oid_run_event ev WHERE ev.run_id=r.id AND ev.event_type='task.evaluated'
          AND ev.payload_json->>'taskIndex'=t.task_index::text ORDER BY ev.sequence LIMIT 1) AS evaluation_event_payload_json,
        (SELECT COUNT(*)::text FROM oid_run_event ev WHERE ev.run_id=r.id AND ev.event_type='task.terminalized'
          AND ev.payload_json->>'taskIndex'=t.task_index::text) AS terminalization_event_count
      FROM oid_benchmark_run r JOIN oid_run_task t ON t.run_id=r.id
      LEFT JOIN oid_task_preparation_intent i ON i.run_id=r.id AND i.task_index=t.task_index
      LEFT JOIN oid_task_environment_lease l ON l.preparation_id=i.preparation_id AND l.lease_id=i.lease_id
      LEFT JOIN LATERAL (SELECT status,generation_id FROM oid_task_preparation_observation
        WHERE preparation_id=i.preparation_id ORDER BY revision DESC LIMIT 1) o ON true
      LEFT JOIN oid_task_preparation_generation g ON g.preparation_id=i.preparation_id
      LEFT JOIN oid_task_execution_binding eb ON eb.run_id=r.id AND eb.task_index=t.task_index
      LEFT JOIN oid_run_task_closure c ON c.id=t.closure_id AND c.run_id=t.run_id AND c.task_index=t.task_index
      LEFT JOIN oid_run_task_observation_bundle ob ON ob.run_id=r.id AND ob.task_index=t.task_index
      LEFT JOIN oid_run_task_evaluation e ON e.run_id=r.id AND e.task_index=t.task_index
      WHERE r.status='running' AND t.status='active'
      ORDER BY r.id,t.task_index LIMIT ${batchSize}`) as unknown as Array<FencedKnownTaskRecoveryRow & { run_id: string; task_index: number }>;
    await lease.assertHeld();
    for (const row of rows) {
      // The harness fences the exact generation before committing task.terminalized. During that
      // small gap, the task remains active but is not a live executor session. Require the full
      // closed-cutoff, immutable-bundle, known-evaluation, event, and task-scoped fence chain;
      // mismatches still follow ordinary lost-RAM cancellation.
      if (recoveringRunIds.has(row.run_id) || !activeTaskNeedsCancellationAfterRecovery(row.run_id, row.task_index, attached, row)) continue;
      const closedObservationRecovery = classifyClosedObservationRecovery(row);
      if (closedObservationRecovery !== null) {
        await lease.assertHeld();
        const context = await getTaskExecutionContext(input.db,
          { runId: row.run_id, taskIndex: row.task_index }, { requireActive: false, requireBinding: true });
        const release = context && await input.releaseSource.getValidatedReleaseRecord(context.releaseIdentity, context.releaseManifestHash);
        await lease.assertHeld();
        const taskCase = context && release?.manifest.cases[context.mode].find(candidate => candidate.taskId === context.taskId);
        if (context?.runStatus === 'running' && context.taskStatus === 'active' && context.closureStatus === 'closed' &&
            context.preparationId === row.preparation_id && context.leaseId === row.preparation_lease_id &&
            context.generationId === row.observed_generation_id && context.envId === row.preparation_environment_id &&
            context.releaseIdentity === row.release_identity && context.releaseManifestHash === row.release_manifest_hash &&
            context.executionIdentityHash === release?.manifest.executionIdentityHash &&
            taskCase?.caseId === context.caseId && taskCase.caseHash === context.caseHash) {
          // AICODE-NOTE: The grading/overall bound can cross between the earlier expiry
          // scan and this lost-RAM scan. Preserve normal expiry authority and attribution;
          // a valid expired closure must never become executor_session_lost due to that race.
          if (closedObservationRecovery === 'expired') {
            await cancelExpiredClosedUngradedTasks({ db: input.db,
              assertLeaseHeld: () => lease.assertHeld(), requestCancellation, drainCancellations }, recoveringRunIds);
          }
          continue;
        }
      }
      await requestCancellation(row.run_id, 'coordinator_executor_session_lost');
    }
  }

  async function discardFencedSessions(): Promise<void> {
    for (const session of [...attached.values()]) {
      await lease.assertHeld();
      const rows = (await input.db.execute(sql`SELECT l.state FROM oid_task_preparation_intent i
        JOIN oid_task_environment_lease l ON l.lease_id=i.lease_id AND l.preparation_id=i.preparation_id
        WHERE i.preparation_id=${session.preparationId} AND i.run_id=${session.runId} AND i.task_index=${session.taskIndex}`)) as unknown as Array<{ state: string }>;
      await lease.assertHeld();
      if (rows[0]?.state !== 'fenced') continue;
      executor.unbindSession(session.runId, session.taskIndex);
      adapter.clearCredentials(session.preparationId);
      attached.delete(sessionKey(session.runId, session.taskIndex));
    }
  }

  async function prepareAndStart(target: TaskPreparationTarget): Promise<void> {
    let preparation: TaskPreparationRecord | null = null;
    try {
      await lease.assertHeld();
      preparation = await prepareTaskExecution(preparationDependencies, target);
      await lease.assertHeld();
      if (preparation.observation.status === 'ready' && preparation.leaseStatus === 'leased' &&
          preparation.dispatchStatus === 'completed' && preparation.observation.generationId) {
        const operationId = `local-bef-start-${hash(`${target.runId}:${target.claimId}`).slice(0, 48)}`;
        await startQueuedRun(runServiceDependencies, { runId: target.runId, claimId: target.claimId, operationId });
        await lease.assertHeld();
        return;
      }
      await requestCancellation(target.runId, 'coordinator_preparation_failed');
      await drainCancellations();
    } catch (error) {
      if (error && typeof error === 'object' && 'code' in error &&
          (error.code === 'BETA_STARTS_PAUSED' || error.code === 'RUN_STORAGE_CAPACITY_LOW')) {
        // Keep the accepted run, its original queue deadline, and its durable ready preparation.
        // The worker will retry after resume/capacity recovery; the final start transaction is the fence.
        return;
      }
      // A worker that lost its singleton lease must not cancel or otherwise touch
      // another process's live RAM session. The next lease owner performs recovery.
      try { await lease.assertHeld(); } catch { return; }
      await requestCancellation(target.runId, 'coordinator_preparation_failed').catch(() => undefined);
      await drainCancellations().catch(() => undefined);
      if (preparation?.observation.status === 'ready') {
        adapter.clearCredentials(preparation.intent.preparationId);
      }
    }
  }

  async function successorCandidates(): Promise<Array<{ run_id: string; predecessor_task_index: number; claim_id: string; mode: 'training' | 'ranked' }>> {
    return await input.db.execute(sql`SELECT r.id AS run_id,p.task_index AS predecessor_task_index,c.claim_id,r.mode
      FROM oid_benchmark_run r
      JOIN oid_run_dispatch_claim c ON c.run_id=r.id AND c.status='claimed'
      JOIN oid_run_execution_slot s ON s.run_id=r.id AND s.agent_id=r.agent_id AND s.claim_id=c.claim_id
        AND s.state='running' AND s.released_at IS NULL
      JOIN oid_run_task p ON p.run_id=r.id AND p.status IN ('completed','failed')
        AND p.closure_status='closed' AND p.finished_at IS NOT NULL
        AND p.action_cutoff_sequence IS NOT NULL AND p.reconciled_action_sequence>=p.action_cutoff_sequence
      JOIN oid_run_task_evaluation e ON e.run_id=p.run_id AND e.task_index=p.task_index AND e.closure_id=p.closure_id
        AND e.result_json->>'status'='known'
      JOIN oid_run_task_observation_bundle b ON b.run_id=p.run_id AND b.task_index=p.task_index
        AND b.closure_id=p.closure_id AND b.task_id=p.task_id
      JOIN oid_task_preparation_intent i ON i.run_id=p.run_id AND i.task_index=p.task_index
      JOIN oid_task_environment_lease l ON l.lease_id=i.lease_id AND l.preparation_id=i.preparation_id AND l.state='fenced'
      JOIN LATERAL (SELECT status,generation_id FROM oid_task_preparation_observation
        WHERE preparation_id=i.preparation_id ORDER BY revision DESC LIMIT 1) o
        ON o.status='fenced' AND o.generation_id=b.generation_id
      JOIN oid_task_execution_binding eb ON eb.run_id=p.run_id AND eb.task_index=p.task_index
        AND eb.env_id=b.environment_id AND eb.generation_id=b.generation_id
      JOIN oid_run_task n ON n.run_id=p.run_id AND n.task_index=p.task_index+1
        AND n.status='queued' AND n.closure_status='open' AND n.started_at IS NULL AND n.finished_at IS NULL
      WHERE r.status='running' AND r.mode IN ('training','ranked') AND p.task_index BETWEEN 0 AND 10
        AND p.finished_at<r.overall_deadline
        AND NOT EXISTS (SELECT 1 FROM oid_task_preparation_intent next_i
          JOIN oid_task_environment_lease next_l ON next_l.lease_id=next_i.lease_id AND next_l.preparation_id=next_i.preparation_id
          WHERE next_i.run_id=r.id AND next_i.task_index=p.task_index+1 AND next_l.state='fenced')
        AND EXISTS (SELECT 1 FROM oid_run_event ev WHERE ev.run_id=r.id AND ev.event_type='task.terminalized'
          AND ev.payload_json->>'taskIndex'=p.task_index::text)
        AND NOT EXISTS (SELECT 1 FROM oid_run_task active WHERE active.run_id=r.id AND active.status='active')
      ORDER BY r.started_at,r.id,p.task_index LIMIT ${batchSize}`) as unknown as
        Array<{ run_id: string; predecessor_task_index: number; claim_id: string; mode: 'training' | 'ranked' }>;
  }

  async function prepareAndActivateSuccessor(candidate: {
    run_id: string; predecessor_task_index: number; claim_id: string; mode: 'training' | 'ranked';
  }): Promise<void> {
    const runId = candidate.run_id;
    const predecessorTaskIndex = candidate.predecessor_task_index;
    const target: TaskPreparationTarget = {
      runId, taskIndex: predecessorTaskIndex + 1, claimId: candidate.claim_id,
    };
    let preparation: TaskPreparationRecord | null = null;
    try {
      await lease.assertHeld();
      preparation = await prepareSuccessorTaskExecution(successorPreparationDependencies, target);
      await lease.assertHeld();
      if (preparation.observation.status !== 'ready' || preparation.leaseStatus !== 'leased' ||
          preparation.dispatchStatus !== 'completed' || !preparation.observation.generationId) {
        await requestCancellation(runId, 'coordinator_preparation_failed');
        await drainCancellations();
        return;
      }

      // A fresh port keeps its predecessor replay witness local to this one activation attempt.
      const successorStartPort = leaseGuardedPreparedTaskStartPort(
        createPreparedSuccessorTaskStartPort(successorPreparationDependencies, attachPreparedSession),
        () => lease.assertHeld(),
      );
      const activationDependencies = {
        db: input.db,
        taskReleaseSource: input.releaseSource,
        evidenceSource,
        preparedTaskStart: successorStartPort,
      };
      const activation = candidate.mode === 'ranked'
        ? await activatePreparedRankedSuccessor(activationDependencies, { runId, predecessorTaskIndex })
        : await activatePreparedTrainingSuccessor(activationDependencies, { runId, predecessorTaskIndex });
      await lease.assertHeld();
      const key = sessionKey(runId, target.taskIndex);
      if (!activation.replayed && (!activation.preparation ||
          activation.preparation.intent.preparationId !== preparation.intent.preparationId ||
          activation.preparation.intent.taskIndex !== target.taskIndex || activation.binding.taskIndex !== target.taskIndex)) {
        throw new Error('local_bef_coordinator_successor_activation_binding_mismatch');
      }
      const handoff = await handoffCommittedSuccessor({
        runId, taskIndex: target.taskIndex, replayed: activation.replayed,
        preparation: activation.preparation, taskDeadline: activation.taskDeadline,
        isAttached: () => attached.has(key),
        assertLeaseHeld: () => lease.assertHeld(),
        attach: (record, deadline) => successorStartPort.attachStartedSession(record, deadline),
        cancelAndFence: async (cancelRunId, _taskIndex, reason) => {
          await requestCancellation(cancelRunId, reason);
          await drainCancellations();
        },
      });
      if (handoff === 'lease_lost') return;
    } catch (error) {
      // Generic missing/contradictory predecessor evidence remains unavailable without creating a
      // successor intent. A persisted policy/window failure may cancel only while predecessor time
      // remains; an existing target intent is always fenced on ambiguous preparation/activation.
      try { await lease.assertHeld(); } catch { return; }
      const intentRows = await input.db.execute(sql`SELECT preparation_id FROM oid_task_preparation_intent
        WHERE run_id=${runId} AND task_index=${target.taskIndex}`) as unknown as Array<{ preparation_id: string }>;
      await lease.assertHeld();
      const code = errorCode(error);
      if (code === 'SUCCESSOR_OVERALL_TIME_EXHAUSTED') {
        const exactPreparation = preparation ?? (intentRows[0]
          ? await getTaskPreparation(input.db, intentRows[0].preparation_id)
          : null);
        if (exactPreparation) {
          try {
            await lease.assertHeld();
            const fence = await fenceTaskPreparationWithEvidence(preparationDependencies,
              exactPreparation.intent.preparationId, exactPreparation.observation.generationId);
            await lease.assertHeld();
            if (!fence.released) throw new Error('local_bef_coordinator_successor_expiry_fence_unconfirmed');
            adapter.clearCredentials(exactPreparation.intent.preparationId);
            executor.unbindSession(runId, target.taskIndex);
            attached.delete(sessionKey(runId, target.taskIndex));
            return;
          } catch {
            try { await lease.assertHeld(); } catch { return; }
            await requestCancellation(runId, 'coordinator_interrupted_preparation').catch(() => undefined);
            await drainCancellations().catch(() => undefined);
            return;
          }
        }
      }
      const hasPreparationIntent = Boolean(preparation || intentRows[0]);
      let predecessorBeforeDeadline: boolean | null = null;
      if (!hasPreparationIntent && isBoundedSuccessorWindowFailure(code)) {
        const deadlineRows = await input.db.execute(sql`SELECT r.overall_deadline,p.finished_at
          FROM oid_benchmark_run r JOIN oid_run_task p ON p.run_id=r.id AND p.task_index=${predecessorTaskIndex}
          WHERE r.id=${runId} AND r.mode=${candidate.mode} AND r.status='running'`) as unknown as Array<{
            overall_deadline: Date | string | null; finished_at: Date | string | null;
          }>;
        await lease.assertHeld();
        predecessorBeforeDeadline = predecessorFinishedBeforeOriginalDeadline(deadlineRows[0]
          ? { finishedAt: deadlineRows[0].finished_at, overallDeadline: deadlineRows[0].overall_deadline }
          : null);
      }
      const reason = successorFailureCancellationReason(code, hasPreparationIntent, predecessorBeforeDeadline);
      if (!reason) return;
      await requestCancellation(runId, reason).catch(() => undefined);
      await drainCancellations().catch(() => undefined);
    }
  }

  async function advanceKnownSuccessors(): Promise<void> {
    await lease.assertHeld();
    const candidates = await successorCandidates();
    await lease.assertHeld();
    for (const candidate of candidates) {
      await lease.assertHeld();
      if (!isValidSuccessorLocator(candidate)) continue;
      await prepareAndActivateSuccessor(candidate);
    }
  }

  async function resumePreDispatchPreparation(): Promise<boolean> {
    await lease.assertHeld();
    const rows = await input.db.execute(sql`SELECT r.id AS run_id,c.claim_id
      FROM oid_benchmark_run r JOIN oid_run_dispatch_claim c ON c.run_id=r.id AND c.status='claimed'
      JOIN oid_task_preparation_intent i ON i.run_id=r.id AND i.task_index=0
      JOIN oid_task_environment_lease l ON l.lease_id=i.lease_id AND l.preparation_id=i.preparation_id AND l.state='leased'
      JOIN LATERAL (SELECT status FROM oid_task_preparation_observation WHERE preparation_id=i.preparation_id
        ORDER BY revision DESC LIMIT 1) o ON true
      LEFT JOIN oid_task_preparation_dispatch d ON d.preparation_id=i.preparation_id
      WHERE r.status='preparing' AND ((o.status='preparing' AND d.preparation_id IS NULL) OR
        (${runServiceDependencies.betaOperationsEnabled} AND o.status='ready' AND d.state='completed'))
      ORDER BY r.queued_at,r.id LIMIT 1`) as unknown as Array<{ run_id: string; claim_id: string }>;
    await lease.assertHeld();
    const row = rows[0];
    if (!row) return false;
    await prepareAndStart({ runId: row.run_id, taskIndex: 0, claimId: row.claim_id });
    return true;
  }

  async function resumePreparingWithoutIntent(): Promise<boolean> {
    await lease.assertHeld();
    const rows = await input.db.execute(sql`SELECT r.id AS run_id,c.claim_id
      FROM oid_benchmark_run r JOIN oid_run_dispatch_claim c ON c.run_id=r.id AND c.status='claimed'
      WHERE r.status='preparing' AND NOT EXISTS (
        SELECT 1 FROM oid_task_preparation_intent i WHERE i.run_id=r.id AND i.task_index=0
      ) ORDER BY r.queued_at,r.id LIMIT 1`) as unknown as Array<{ run_id: string; claim_id: string }>;
    await lease.assertHeld();
    const row = rows[0];
    if (!row) return false;
    await prepareAndStart({ runId: row.run_id, taskIndex: 0, claimId: row.claim_id });
    return true;
  }

  async function dispatchAttachedSessions(recoveringRunIds: ReadonlySet<string> = new Set()): Promise<void> {
    await lease.assertHeld();
    const rows = (await input.db.execute(sql`SELECT r.id AS run_id,t.task_index FROM oid_benchmark_run r
      JOIN oid_run_task t ON t.run_id=r.id
      WHERE r.status='running' AND t.status='active' ORDER BY r.started_at,r.id,t.task_index LIMIT ${batchSize}`)) as unknown as Array<{ run_id: string; task_index: number }>;
    await lease.assertHeld();
    for (const row of rows) {
      if (recoveringRunIds.has(row.run_id) || row.task_index < 0 || row.task_index > 11 || !attached.has(sessionKey(row.run_id, row.task_index))) continue;
      await lease.assertHeld();
      const result: ExecuteTaskActionResult = await executor.executeNext(row.run_id, row.task_index);
      await lease.assertHeld();
      // The worker only dispatches already admitted actions; it never grades or closes tasks.
      if (result.status === 'recorded' && result.receiptStatus === 'unknown') continue;
    }
  }

  async function betaRuntimeHealthy(): Promise<boolean> {
    if (!input.readinessProvider || !input.betaManifest) return true;
    return input.readinessProvider.isRuntimeHealthyForRelease(input.betaManifest.release.releaseIdentity,
      input.betaManifest.release.manifestHash).catch(() => false);
  }

  async function betaEnvironmentCapacityAvailable(): Promise<boolean> {
    if (!input.betaManifest) return true;
    if (!input.readinessProvider) return false;
    const result = await input.readinessProvider.isPreparedForRelease(input.betaManifest.release.releaseIdentity,
      input.betaManifest.release.manifestHash).catch((): TaskExecutionReadiness => ({ ready: false }));
    return result.ready && typeof result.environmentId === 'string' && HASH.test(result.evidenceHash ?? '');
  }

  async function processClosedTrainingTasks(recoveringRunIds: ReadonlySet<string> = new Set()): Promise<void> {
    if (!observationPorts) return;
    await lease.assertHeld();
    const rows = await input.db.execute(sql`SELECT r.id AS run_id,t.task_index
      FROM oid_benchmark_run r JOIN oid_run_task t ON t.run_id=r.id
      JOIN oid_run_dispatch_claim c ON c.run_id=r.id AND c.status='claimed'
      JOIN oid_run_execution_slot s ON s.run_id=r.id AND s.claim_id=c.claim_id AND s.state='running'
      WHERE r.status='running' AND r.mode IN ('training','ranked') AND t.status='active'
        AND t.closure_status='closed' AND t.action_cutoff_sequence IS NOT NULL
        AND t.reconciled_action_sequence>=t.action_cutoff_sequence
      ORDER BY r.id,t.task_index LIMIT ${batchSize}`) as unknown as Array<{ run_id: string; task_index: number }>;
    await lease.assertHeld();
    for (const row of rows) {
      await lease.assertHeld();
      if (recoveringRunIds.has(row.run_id)) continue;
      const outcome = await processClosedTrainingTask({ db: input.db, taskReleaseSource: input.releaseSource,
        repositoryRoot: projectRoot, evidenceSource, observerPorts: observationPorts,
        preparationAdapter: guardedPreparationAdapter, assertLeaseHeld: () => lease.assertHeld() },
      { runId: row.run_id, taskIndex: row.task_index });
      await lease.assertHeld();
      const progress = { schemaVersion: 'local-bef-task-observation-progress/v1',
        classification: 'internal_worker_progress_not_task_grade_or_platform_attribution',
        runId: row.run_id, taskIndex: row.task_index, status: outcome.status, stage: outcome.stage,
        ...('reasonCode' in outcome ? { reasonCode: outcome.reasonCode } : {}),
        ...('evaluationUnknownReasons' in outcome ? { evaluationUnknownReasons:outcome.evaluationUnknownReasons } : {}) };
      const key = sessionKey(row.run_id, row.task_index);
      const serialized = JSON.stringify(progress);
      if (observationProgress.get(key) !== serialized) {
        // Optional safe diagnostics never replace the immutable task evidence or its grade.
        await writeSafeEvidence(projectRoot, 'lifecycle', row.run_id, progress, evidenceDirectory).catch(() => undefined);
        observationProgress.set(key, serialized);
        if (observationProgress.size > 128) observationProgress.delete(observationProgress.keys().next().value!);
      }
    }
  }

  async function workTick(): Promise<void> {
    if (stopped || !lease.ownsLease()) return;
    await lease.assertHeld();
    await expireQueuedRuns(input.db, batchSize);
    await lease.assertHeld();
    await drainCancellations();
    await cancelOldPreparationIntents();
    const recovery = await platformRecovery?.tick();
    await lease.assertHeld();
    const recoveringRunIds = new Set(recovery?.recoveringRunIds ?? []);
    // Recovery precedes grading and lost-session handling. Only the server-owned
    // monitor can defer these exact runs; participant reports cannot pause clocks.
    for (const runId of recovery?.exhaustedRunIds ?? []) {
      await lease.assertHeld();
      await requestCancellation(runId, 'coordinator_platform_failure');
    }
    await drainCancellations();
    await platformRecovery?.finalizeFencedRuns(recovery?.exhaustedRunIds ?? []);
    await lease.assertHeld();
    // AICODE-NOTE: Resume closed tasks from retained observations before lost-RAM
    // handling; grading/fencing never restores or resends an actor session.
    await processClosedTrainingTasks(recoveringRunIds);
    await cancelExpiredClosedUngradedTasks({db:input.db,assertLeaseHeld:()=>lease.assertHeld(),requestCancellation,drainCancellations},
      recoveringRunIds,batchSize);
    await cancelRunningBindingsWithoutRam(recoveringRunIds);
    await drainCancellations();
    await discardFencedSessions();
    await cancelExpiredKnownRunGaps({db:input.db,assertLeaseHeld:()=>lease.assertHeld(),requestCancellation,drainCancellations},batchSize);
    const runtimeHealthy = await betaRuntimeHealthy();
    if (runtimeHealthy) {
      let admissionsActive = !runServiceDependencies.betaOperationsEnabled;
      if (runServiceDependencies.betaOperationsEnabled) {
        try { admissionsActive = await readBetaOperationsMode(input.db) === 'active'; }
        catch { admissionsActive = false; }
      }
      const storageReady = !runServiceDependencies.betaOperationsEnabled || !runServiceDependencies.privateDataDir ||
        (await readBetaStorageObservation(runServiceDependencies.privateDataDir)).status === 'ready';
      if (admissionsActive && storageReady) {
        const resumedPreDispatch = await resumePreDispatchPreparation();
        if (!resumedPreDispatch && await betaEnvironmentCapacityAvailable()) {
          if (!(await resumePreparingWithoutIntent())) {
            await lease.assertHeld();
            const claim = await claimNextQueuedRun(runServiceDependencies, { maxCandidates: batchSize });
            await lease.assertHeld();
            if (claim?.run.status === 'preparing') {
              await prepareAndStart({ runId: claim.run.id, taskIndex: 0, claimId: claim.claimId });
            }
          }
        }
      }
      if (await betaEnvironmentCapacityAvailable()) await advanceKnownSuccessors();
    }
    await discardFencedSessions();
    if (runtimeHealthy) await dispatchAttachedSessions(recoveringRunIds);
  }

  let observationPorts: BefObservationPorts | null = null;
  let platformRecovery: BetaPlatformRecoveryMonitor | null = null;
  try {
    if (fileConfig.observationDatabase) {
      observationPorts = await createBefObservationPorts({ repositoryRoot: projectRoot,
        database: fileConfig.observationDatabase, environments: fileConfig.environments,
        fetchImpl });
      platformRecovery = createBetaPlatformRecoveryMonitor({ db: input.db, observationPorts, actionEvidenceSink,
        assertLeaseHeld: () => lease.assertHeld() });
    }
  } catch {
    adapter.clearCredentials();
    await lease.stop().catch(() => undefined);
    throw new Error('local_bef_observation_ports_unavailable');
  }

  return {
    async acquire() { return lease.acquire(); },
    ownsLease() { return lease.ownsLease(); },
    async tick() {
      if (stopped || inFlight || !lease.ownsLease()) return;
      const work = workTick();
      inFlight = work;
      try { await work; }
      finally { if (inFlight === work) inFlight = null; }
    },
    async stop() {
      stopped = true;
      await inFlight?.catch(() => undefined);
      for (const session of attached.values()) executor.unbindSession(session.runId, session.taskIndex);
      attached.clear();
      observationProgress.clear();
      adapter.clearCredentials();
      try { await lease.stop(); }
      finally { await observationPorts?.close(); }
    },
  };
}
