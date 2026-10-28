import { validateTaskChainCapturePacket } from './task-chain-capture-packet.js';
import { validatePaidDataCapturePacket } from './task-paid-data-capture-packet.js';
import { validateS3CapturePacket } from './task-s3-capture-packet.js';
import { validateCompositeCapturePacket } from './task-composite-capture-packet.js';
import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { mkdir, open, lstat, realpath } from 'node:fs/promises';
import { isAbsolute, relative, resolve, sep } from 'node:path';
import { isIP } from 'node:net';
import postgres from 'postgres';
import { canonicalTaskJson, type EvidenceReference } from './task-release.js';
import { validateM1CapturePacket } from './task-m1-capture-packet.js';

const OBSERVATION_ROOT = 'artifacts/runs/owner-identity-bef-task-coordinator/observation';
const EVIDENCE_BOUNDARY = 'actual_tool_http_x402_local_evm_application_store' as const;
const MAX_PACKET_BYTES = 8 * 1024 * 1024;
const MAX_RPC_BYTES = 4 * 1024 * 1024;
const MAX_RPC_REQUEST_BYTES = 256 * 1024;
const RPC_TIMEOUT_MS = 20_000;
const RPC_METHODS = new Set([
  'eth_blockNumber', 'eth_call', 'eth_chainId', 'eth_getBalance', 'eth_getBlockByNumber', 'eth_getCode',
  'eth_getLogs', 'eth_getTransactionByHash', 'eth_getTransactionCount', 'eth_getTransactionReceipt',
]);
const TASK_IDS = new Set(['S1','S2','S3','S4','M1','M2','M3','M4','H1','H2','H3','U1']);
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const ADDRESS = /^0x[0-9a-f]{40}$/i;
const ENV_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const SECRET_KEYS = new Set([
  'privatekey', 'privkey', 'seedphrase', 'mnemonic', 'secret', 'clientsecret', 'bearer', 'bearertoken',
  'accesstoken', 'refreshtoken', 'providertoken', 'paymenttoken', 'token', 'apitoken', 'apikey',
  'authorization', 'walletmaterial', 'walletsecret', 'signature', 'signedpayload', 'password', 'credential',
  'connectionstring', 'databaseurl', 'dsn',
]);
const M1_SIGNED_X402_KEYS = new Set(['xpayment', 'xpaymentsignature', 'xpaymentpayload', 'xpaymentauthorization',
  'paymentsignature', 'paymentauthorization', 'paymentauth', 'paymentproof', 'x402authorization', 'x402signature',
  'x402payload', 'x402proof', 'paymentpayload', 'transferpayload']);

export type BefObservationEnvironmentConfig = { envId: string; observerRpcUrl: string };
export type BefObserverDatabaseConfig = { host: string; port: number; database: 'bef'; password: string };

export interface BefReadOnlyPostgresPort {
  environmentId: string;
  withRepeatableRead<T>(callback: (query: BefReadQuery) => Promise<T>): Promise<T>;
  readFenceProof(input: { preparationId: string; generationId: string }): Promise<BefFenceProof>;
}

export interface BefReadOnlyRpcPort {
  environmentId: string;
  request(method: string, params: readonly unknown[]): Promise<unknown>;
}

export type BefReadQuery = (statement: string, parameters?: readonly unknown[]) => Promise<unknown>;
export type BefFenceProof = {
  generation: { generation_id: string; env_id: string; status: string; fenced_at: string | null } | null;
  preparation: { preparation_id: string; status: string; fence_confirmed_at: string | null;
    preparation_generation_id: string; public_pins_sha256: string; manifest_sha256: string;
    environment_manifest_hash: string } | null;
};

export interface BefObservationEvidenceSink {
  /** Accepts only the public, versioned S1/S2/S4 observation packet envelopes. */
  write(packet: unknown): Promise<EvidenceReference>;
}

export interface BefObservationPorts {
  postgresByEnvironment: Readonly<Record<string, BefReadOnlyPostgresPort>>;
  rpcByEnvironment: Readonly<Record<string, BefReadOnlyRpcPort>>;
  evidenceSink: BefObservationEvidenceSink;
  close(): Promise<void>;
}

/** Internal seam used by focused tests; production uses the bundled postgres client. */
interface BefObserverConnection {
  unsafe(statement: string, parameters?: readonly unknown[]): Promise<unknown>;
  release(): void;
}
interface BefObserverPool {
  reserve(): Promise<BefObserverConnection>;
  end(): Promise<void>;
}
type PoolFactory = (connection: Readonly<BefObserverDatabaseConfig & { user: 'bef_observer' }>) => BefObserverPool;

export interface BefObservationPortsOptions {
  repositoryRoot: string;
  /** Password is supplied by the caller's local secret loader and kept in RAM. */
  database: BefObserverDatabaseConfig;
  environments: readonly BefObservationEnvironmentConfig[];
  fetchImpl?: typeof fetch;
  /** @internal test seam. */
  poolFactory?: PoolFactory;
}

class BefObservationPortError extends Error {
  constructor(code: string) { super(code); this.name = 'BefObservationPortError'; }
}
function safeError(code: string): BefObservationPortError { return new BefObservationPortError(code); }
function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}
function isWithin(parent: string, child: string): boolean {
  const rel = relative(parent, child);
  return rel === '' || (!isAbsolute(rel) && rel !== '..' && !rel.startsWith(`..${sep}`));
}
function normalizedKey(value: string): string { return value.toLowerCase().replace(/[^a-z]/g, ''); }

function allowedLocalHost(hostname: string): boolean {
  const host = hostname.toLowerCase().replace(/^\[|\]$/g, '');
  if (new Set(['localhost', 'host.docker.internal', 'gateway.docker.internal', '::1', 'api', 'bef-api', 'benchmark-environment-api']).has(host)) {
    return true;
  }
  const version = isIP(host);
  if (version === 4) {
    const parts = host.split('.').map(Number);
    if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return false;
    return parts[0] === 127 || parts[0] === 10 || (parts[0] === 192 && parts[1] === 168) ||
      (parts[0] === 172 && parts[1]! >= 16 && parts[1]! <= 31);
  }
  if (version === 6) return host === '::1';
  return /^[a-z][a-z0-9-]{0,62}$/.test(host);
}

function validateRpcUrl(raw: string): string {
  let url: URL;
  try { url = new URL(raw); } catch { throw safeError('bef_observer_rpc_url_invalid'); }
  if (url.protocol !== 'http:' || url.username || url.password || url.search || url.hash ||
      (url.pathname !== '' && url.pathname !== '/') || !allowedLocalHost(url.hostname)) {
    throw safeError('bef_observer_rpc_url_invalid');
  }
  return url.origin;
}

function validateOptions(input: BefObservationPortsOptions): void {
  if (!input || typeof input.repositoryRoot !== 'string' || input.repositoryRoot.trim() === '') {
    throw safeError('bef_observer_config_invalid');
  }
  const db = input.database;
  if (!db || db.database !== 'bef' || !allowedLocalHost(db.host) || !Number.isSafeInteger(db.port) ||
      db.port < 1 || db.port > 65535 || typeof db.password !== 'string' || db.password.length < 16 ||
      db.password.length > 512 || /[\r\n\u0000]/.test(db.password)) {
    throw safeError('bef_observer_database_config_invalid');
  }
  if (!Array.isArray(input.environments) || input.environments.length < 1 || input.environments.length > 8) {
    throw safeError('bef_observer_environment_config_invalid');
  }
  const ids = new Set<string>();
  for (const environment of input.environments) {
    if (!environment || !ENV_ID.test(environment.envId) || ids.has(environment.envId)) {
      throw safeError('bef_observer_environment_config_invalid');
    }
    ids.add(environment.envId);
    validateRpcUrl(environment.observerRpcUrl);
  }
}

function createPostgresPool(connection: Readonly<BefObserverDatabaseConfig & { user: 'bef_observer' }>): BefObserverPool {
  let url: URL;
  try {
    url = new URL('postgres://bef_observer@localhost/bef');
    url.hostname = connection.host.replace(/^\[|\]$/g, '');
    url.port = String(connection.port);
    url.password = connection.password;
  } catch { throw safeError('bef_observer_pool_unavailable'); }
  let client: ReturnType<typeof postgres>;
  try { client = postgres(url.toString(), { max: 2, connect_timeout: 5, idle_timeout: 30, onnotice: () => undefined }); }
  catch { throw safeError('bef_observer_pool_unavailable'); }
  return {
    async reserve() {
      let reserved: Awaited<ReturnType<typeof client.reserve>>;
      try { reserved = await client.reserve(); } catch { throw safeError('bef_observer_connection_unavailable'); }
      return {
        async unsafe(statement, parameters = []) {
          try { return await reserved.unsafe(statement, [...parameters] as never[]); }
          catch { throw safeError('bef_observer_query_unavailable'); }
        },
        release() { reserved.release(); },
      };
    },
    async end() { await client.end({ timeout: 5 }); },
  };
}

function queryRows(value: unknown): Record<string, unknown>[] {
  if (!Array.isArray(value) || value.some((row) => !isRecord(row))) throw safeError('bef_observer_query_unavailable');
  return value as Record<string, unknown>[];
}

function assertReadQuery(statement: string): void {
  const trimmed = statement.trim();
  if (!/^(?:SELECT|WITH)\b/i.test(trimmed) || /;\s*\S/.test(trimmed)) {
    throw safeError('bef_observer_query_not_read_only');
  }
}

function createPostgresPort(environmentId: string, pool: BefObserverPool): BefReadOnlyPostgresPort {
  return {
    environmentId,
    async withRepeatableRead<T>(callback: (query: BefReadQuery) => Promise<T>): Promise<T> {
      let connection: BefObserverConnection;
      try { connection = await pool.reserve(); } catch { throw safeError('bef_observer_connection_unavailable'); }
      let began = false;
      let committed = false;
      try {
        try {
          await connection.unsafe('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
          began = true;
          await connection.unsafe("SET LOCAL statement_timeout = '20000ms'");
        } catch { throw safeError('bef_observer_transaction_unavailable'); }
        const query: BefReadQuery = async (statement, parameters = []) => {
          assertReadQuery(statement);
          try { return queryRows(await connection.unsafe(statement, [...parameters])); }
          catch (error) {
            if (error instanceof BefObservationPortError && error.message === 'bef_observer_query_not_read_only') throw error;
            throw safeError('bef_observer_query_unavailable');
          }
        };
        const session = queryRows(await query(`SELECT current_user AS current_user,session_user AS session_user,
            current_database() AS database_name,current_setting('transaction_read_only') AS transaction_read_only,
            current_setting('transaction_isolation') AS transaction_isolation,r.rolsuper AS superuser,r.rolbypassrls AS bypass_rls
          FROM pg_roles r WHERE r.rolname=current_user`));
        const proof = session[0];
        if (session.length !== 1 || proof?.current_user !== 'bef_observer' || proof.session_user !== 'bef_observer' ||
            proof.database_name !== 'bef' || proof.transaction_read_only !== 'on' ||
            String(proof.transaction_isolation).toLowerCase() !== 'repeatable read' || proof.superuser !== false || proof.bypass_rls !== false) {
          throw safeError('bef_observer_role_invalid');
        }
        const result = await callback(query);
        try { await connection.unsafe('COMMIT'); committed = true; }
        catch { throw safeError('bef_observer_transaction_unavailable'); }
        return result;
      } finally {
        if (began && !committed) await connection.unsafe('ROLLBACK').catch(() => undefined);
        try { connection.release(); } catch { /* Cleanup errors never expose driver details. */ }
      }
    },
    async readFenceProof({ preparationId, generationId }): Promise<BefFenceProof> {
      if (!UUID.test(preparationId) || !UUID.test(generationId)) throw safeError('bef_observer_fence_target_invalid');
      return this.withRepeatableRead(async (query) => {
        const rows = queryRows(await query(`SELECT g.generation_id::text AS generation_id,g.env_id,
            g.status AS generation_status,g.fenced_at::text AS fenced_at,p.preparation_id::text AS preparation_id,
            p.status AS preparation_status,p.fence_confirmed_at::text AS fence_confirmed_at,
            p.generation_id::text AS preparation_generation_id,p.public_pins_sha256,p.manifest_sha256,
            trim(e.manifest_sha256) AS environment_manifest_hash
          FROM public.bef_generation g
          JOIN public.bef_preparation p ON p.env_id=g.env_id AND p.generation_id=g.generation_id
          JOIN public.bef_environment e ON e.env_id=g.env_id
          WHERE g.env_id=$1 AND g.generation_id=$2::uuid AND p.preparation_id=$3::uuid`,
        [environmentId, generationId, preparationId]));
        if (rows.length > 1) throw safeError('bef_observer_fence_proof_conflict');
        const row = rows[0];
        if (!row) return { generation: null, preparation: null };
        const requiredTextFields = ['generation_id', 'env_id', 'generation_status', 'preparation_id',
          'preparation_status', 'preparation_generation_id', 'public_pins_sha256', 'manifest_sha256', 'environment_manifest_hash'];
        if (requiredTextFields.some((key) => typeof row[key] !== 'string' || row[key] === '') ||
            (row.fenced_at !== null && typeof row.fenced_at !== 'string') ||
            (row.fence_confirmed_at !== null && typeof row.fence_confirmed_at !== 'string')) {
          throw safeError('bef_observer_fence_proof_unavailable');
        }
        return {
          generation: {
            generation_id: String(row.generation_id), env_id: String(row.env_id),
            status: String(row.generation_status), fenced_at: row.fenced_at === null ? null : String(row.fenced_at),
          },
          preparation: {
            preparation_id: String(row.preparation_id), status: String(row.preparation_status),
            fence_confirmed_at: row.fence_confirmed_at === null ? null : String(row.fence_confirmed_at),
            preparation_generation_id: String(row.preparation_generation_id),
            public_pins_sha256: String(row.public_pins_sha256), manifest_sha256: String(row.manifest_sha256),
            environment_manifest_hash: String(row.environment_manifest_hash),
          },
        };
      });
    },
  };
}

async function readBoundedResponse(response: Response): Promise<Buffer> {
  const contentLength = response.headers.get('content-length');
  if (contentLength && /^\d+$/.test(contentLength) && Number(contentLength) > MAX_RPC_BYTES) {
    throw safeError('bef_observer_rpc_response_oversized');
  }
  if (!response.body) return Buffer.alloc(0);
  const reader = response.body.getReader();
  const chunks: Buffer[] = [];
  let length = 0;
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      const chunk = Buffer.from(value);
      length += chunk.length;
      if (length > MAX_RPC_BYTES) {
        await reader.cancel().catch(() => undefined);
        throw safeError('bef_observer_rpc_response_oversized');
      }
      chunks.push(chunk);
    }
  } catch (error) {
    if (error instanceof Error && error.message === 'bef_observer_rpc_response_oversized') throw error;
    throw safeError('bef_observer_rpc_response_unavailable');
  }
  return Buffer.concat(chunks, length);
}

function createRpcPort(environmentId: string, endpoint: string, fetchImpl: typeof fetch): BefReadOnlyRpcPort {
  let requestId = 0;
  return {
    environmentId,
    async request(method: string, params: readonly unknown[]): Promise<unknown> {
      if (!RPC_METHODS.has(method) || !Array.isArray(params) || params.length > 32) {
        throw safeError('bef_observer_rpc_method_not_allowed');
      }
      const id = ++requestId;
      let body: string;
      try { body = JSON.stringify({ jsonrpc: '2.0', id, method, params }); }
      catch { throw safeError('bef_observer_rpc_params_invalid'); }
      if (Buffer.byteLength(body, 'utf8') > MAX_RPC_REQUEST_BYTES) throw safeError('bef_observer_rpc_request_oversized');
      let response: Response;
      try {
        response = await fetchImpl(endpoint, {
          method: 'POST', redirect: 'error', signal: AbortSignal.timeout(RPC_TIMEOUT_MS),
          headers: { 'content-type': 'application/json' }, body,
        });
      } catch { throw safeError('bef_observer_rpc_transport_unavailable'); }
      if (!response.ok) throw safeError('bef_observer_rpc_http_unavailable');
      const bytes = await readBoundedResponse(response);
      let payload: unknown;
      try { payload = JSON.parse(bytes.toString('utf8')); }
      catch { throw safeError('bef_observer_rpc_response_invalid'); }
      if (!isRecord(payload) || payload.jsonrpc !== '2.0' || payload.id !== id || payload.error !== undefined ||
          !Object.hasOwn(payload, 'result')) {
        throw safeError('bef_observer_rpc_result_unavailable');
      }
      return payload.result;
    },
  };
}

function packetIdentity(packet: unknown): { runId: string; taskId: string; environmentId: string } {
  if (!isRecord(packet) || !isRecord(packet.binding) || !isRecord(packet.execution)) {
    throw safeError('bef_observer_packet_invalid');
  }
  const taskId = packet.binding.taskId;
  const expectedSchema = taskId === 'S1' ? 'bts-s1-run-observation-capture/v1' :
    taskId === 'S2' ? 'bts-s2-run-observation-capture/v1' :
      taskId === 'S4' ? 'bts-s4-run-observation-capture/v1' :
        taskId === 'M1' ? 'bts-m1-run-observation-capture/v1' : '';
  const genericSchemas:Record<string,readonly string[]>={
    'bts-chain-task-observation-capture/v1':['M3','M4','H2','H3','U1'],
    'bts-paid-data-run-observation-capture/v1':['M1','M2','H1','H3','U1'],
    'bts-composite-run-observation-capture/v1':['H3','U1'],
    'bts-s3-run-observation-capture/v1':['S3'],
  };
  const generic=typeof packet.schemaVersion==='string'&&genericSchemas[packet.schemaVersion]?.includes(String(taskId));
  const runId = packet.binding.runId;
  const environmentId = packet.binding.environmentId;
  if (!TASK_IDS.has(String(taskId)) || (!generic && packet.schemaVersion !== expectedSchema) ||
      packet.classification !== 'run_bound_observations_candidate_not_grade' ||
      typeof runId !== 'string' || !UUID.test(runId) || typeof environmentId !== 'string' || !ENV_ID.test(environmentId) ||
      typeof packet.binding.ownerId !== 'string' || !UUID.test(packet.binding.ownerId) ||
      typeof packet.binding.agentId !== 'string' || !UUID.test(packet.binding.agentId) ||
      typeof packet.binding.caseId !== 'string' || packet.binding.caseId.length < 1 || packet.binding.caseId.length > 128 ||
      typeof packet.binding.manifestHash !== 'string' || !/^[0-9a-f]{64}$/i.test(packet.binding.manifestHash) ||
      typeof packet.binding.caseHash !== 'string' || !/^[0-9a-f]{64}$/i.test(packet.binding.caseHash) ||
      typeof packet.binding.rubricHash !== 'string' || !/^[0-9a-f]{64}$/i.test(packet.binding.rubricHash) ||
      packet.execution.environmentId !== environmentId || typeof packet.execution.preparationId !== 'string' ||
      !UUID.test(packet.execution.preparationId) || typeof packet.execution.leaseId !== 'string' ||
      !UUID.test(packet.execution.leaseId) || typeof packet.execution.generationId !== 'string' || !UUID.test(packet.execution.generationId)) {
    throw safeError('bef_observer_packet_invalid');
  }
  return { runId: runId.toLowerCase(), taskId: taskId as string, environmentId };
}

function allowedPublicTokenAddress(path: readonly (string | number)[], value: unknown, schemaVersion: string): boolean {
  const selectedActionPath = (path.length === 3 && path[0] === 'ownerActions' && typeof path[1] === 'number' &&
    path[2] === 'selectedAction') || (path.length === 4 && path[0] === 'ownerActions' && typeof path[1] === 'number' &&
      path[2] === 'participantToolResponse' && path[3] === 'selectedAction');
  return schemaVersion === 'bts-s1-run-observation-capture/v1' && ADDRESS.test(String(value)) && selectedActionPath;
}

function hasSecretKey(value: unknown, schemaVersion: string, path: readonly (string | number)[] = [], seen = new Set<object>()): boolean {
  if (value === null || typeof value !== 'object') return false;
  if (seen.has(value)) return true;
  seen.add(value);
  const found = Array.isArray(value)
    ? value.some((item, index) => hasSecretKey(item, schemaVersion, [...path, index], seen))
    : Object.entries(value as Record<string, unknown>).some(([key, item]) => {
      const normalized = normalizedKey(key);
      const publicToken = normalized === 'token' && allowedPublicTokenAddress(path, item, schemaVersion);
      const signedX402Field = schemaVersion === 'bts-m1-run-observation-capture/v1' && M1_SIGNED_X402_KEYS.has(normalized);
      return (SECRET_KEYS.has(normalized) && !publicToken) || signedX402Field ||
        hasSecretKey(item, schemaVersion, [...path, key], seen);
    });
  seen.delete(value);
  return found;
}

async function ensureDirectory(repositoryRoot: string, segments: readonly string[]): Promise<string> {
  let current = repositoryRoot;
  for (const segment of segments) {
    current = resolve(current, segment);
    try { await mkdir(current, { mode: 0o700 }); }
    catch (error) {
      if (!isRecord(error) || error.code !== 'EEXIST') throw safeError('bef_observer_evidence_path_unavailable');
    }
    let info;
    try { info = await lstat(current); } catch { throw safeError('bef_observer_evidence_path_unavailable'); }
    if (!info.isDirectory() || info.isSymbolicLink()) throw safeError('bef_observer_evidence_path_invalid');
    let actual: string;
    try { actual = await realpath(current); } catch { throw safeError('bef_observer_evidence_path_unavailable'); }
    if (!isWithin(repositoryRoot, actual)) throw safeError('bef_observer_evidence_path_invalid');
    current = actual;
  }
  return current;
}

async function boundedExistingFile(path: string, expected: Buffer): Promise<boolean> {
  let info;
  try { info = await lstat(path); } catch { return false; }
  if (!info.isFile() || info.isSymbolicLink() || info.size !== expected.length || info.size > MAX_PACKET_BYTES) {
    throw safeError('bef_observer_evidence_content_address_conflict');
  }
  let handle;
  try { handle = await open(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0)); }
  catch { throw safeError('bef_observer_evidence_path_invalid'); }
  try {
    const bytes = Buffer.alloc(expected.length + 1);
    let offset = 0;
    while (offset < bytes.length) {
      const { bytesRead } = await handle.read(bytes, offset, bytes.length - offset, null);
      if (bytesRead === 0) break;
      offset += bytesRead;
    }
    return offset === expected.length && bytes.subarray(0, offset).equals(expected);
  } finally { await handle.close(); }
}

async function createObservationEvidenceSink(repositoryRoot: string): Promise<BefObservationEvidenceSink> {
  let root: string;
  try { root = await realpath(repositoryRoot); } catch { throw safeError('bef_observer_repository_root_unavailable'); }
  return {
    async write(packet: unknown): Promise<EvidenceReference> {
      const identity = packetIdentity(packet);
      if (isRecord(packet) && packet.schemaVersion === 'bts-m1-run-observation-capture/v1') {
        try { validateM1CapturePacket(packet); }
        catch { throw safeError('bef_observer_packet_invalid'); }
      }
      try {
        if(isRecord(packet))switch(packet.schemaVersion){
          case 'bts-chain-task-observation-capture/v1':validateTaskChainCapturePacket(packet);break;
          case 'bts-paid-data-run-observation-capture/v1':validatePaidDataCapturePacket(packet);break;
          case 'bts-s3-run-observation-capture/v1':validateS3CapturePacket(packet);break;
          case 'bts-composite-run-observation-capture/v1':validateCompositeCapturePacket(packet);break;
        }
      }catch{throw safeError('bef_observer_packet_invalid');}
      let json: string;
      try { json = canonicalTaskJson(packet); } catch { throw safeError('bef_observer_packet_invalid'); }
      const bytes = Buffer.from(`${json}\n`, 'utf8');
      if (bytes.length > MAX_PACKET_BYTES || hasSecretKey(packet, isRecord(packet) ? String(packet.schemaVersion) : "")) {
        throw safeError('bef_observer_packet_secret_or_oversized');
      }
      const digest = createHash('sha256').update(bytes).digest('hex');
      const directory = await ensureDirectory(root, [
        ...OBSERVATION_ROOT.split('/'), identity.runId, identity.taskId,
      ]);
      if (!isWithin(root, directory)) throw safeError('bef_observer_evidence_path_invalid');
      const filename = `${digest}.json`;
      const absolute = resolve(directory, filename);
      const rel = relative(root, absolute);
      if (isAbsolute(rel) || rel === '..' || rel.startsWith(`..${sep}`)) throw safeError('bef_observer_evidence_path_invalid');
      try {
        const handle = await open(absolute, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL |
          (constants.O_NOFOLLOW ?? 0), 0o600);
        try { await handle.writeFile(bytes); await handle.sync(); }
        finally { await handle.close(); }
      } catch (error) {
        if (isRecord(error) && error.code === 'EEXIST') {
          if (!(await boundedExistingFile(absolute, bytes))) throw safeError('bef_observer_evidence_content_address_conflict');
        } else throw safeError('bef_observer_evidence_write_unavailable');
      }
      return { path: `${OBSERVATION_ROOT}/${identity.runId}/${identity.taskId}/${filename}`,
        sha256: digest, boundary: EVIDENCE_BOUNDARY };
    },
  };
}

/**
 * AICODE-NOTE: This adapter supplies read-only BEF evidence ports. The HTTP action journal is only
 * a locator; PostgreSQL role proof, RPC reads, and content-addressed capture packets remain separate.
 */
export async function createBefObservationPorts(input: BefObservationPortsOptions): Promise<BefObservationPorts> {
  validateOptions(input);
  const pool = (input.poolFactory ?? createPostgresPool)({ ...input.database, user: 'bef_observer' });
  const fetchImpl = input.fetchImpl ?? fetch;
  const postgresByEnvironment: Record<string, BefReadOnlyPostgresPort> = {};
  const rpcByEnvironment: Record<string, BefReadOnlyRpcPort> = {};
  try {
    for (const environment of input.environments) {
      const endpoint = validateRpcUrl(environment.observerRpcUrl);
      postgresByEnvironment[environment.envId] = createPostgresPort(environment.envId, pool);
      rpcByEnvironment[environment.envId] = createRpcPort(environment.envId, endpoint, fetchImpl);
    }
    const evidenceSink = await createObservationEvidenceSink(input.repositoryRoot);
    let closed = false;
    return {
      postgresByEnvironment,
      rpcByEnvironment,
      evidenceSink,
      async close() {
        if (closed) return;
        closed = true;
        try { await pool.end(); } catch { throw safeError('bef_observer_pool_close_unavailable'); }
      },
    };
  } catch (error) {
    await pool.end().catch(() => undefined);
    if (error instanceof BefObservationPortError) throw error;
    throw safeError('bef_observer_ports_unavailable');
  }
}
