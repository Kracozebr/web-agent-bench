/**
 * Private run-bound S1 observation collection. This module returns an unsealed
 * candidate only; it does not grade, publish, reset, or invoke participant tools.
 *
 * AICODE-NOTE: SafeTaskActionEvidence is a locator and owner-action binding, not
 * chain proof. S1 coverage is complete only after an independently scoped BEF
 * census and read-only RPC state, transaction, receipt, nonce, and log checks.
 */
import { createHash } from 'node:crypto';
import { lstat, open, realpath } from 'node:fs/promises';
import { isAbsolute, relative, resolve, sep } from 'node:path';
import { sql } from 'drizzle-orm';
import { keccak256 } from 'viem';
import { TaskActionCommandSchema } from './task-action-service.js';
import type { TaskActionCommand } from './task-action-service.js';
import type { SafeTaskActionEvidence } from './bef-task-executor.js';
import type { OwnerDatabase } from './db.js';
import type {
  PersistedTaskObservations,
  TaskEvidenceBinding,
} from './task-evaluator.js';
import {
  canonicalTaskJson,
  sha256CanonicalTaskJson,
  type EvidenceReference,
  type TaskCase,
  type TaskReleaseQuerySource,
} from './task-release.js';
import type { TaskObservationBundleCandidate } from './task-observation-store.js';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const HASH = /^[0-9a-f]{64}$/i;
const ADDRESS = /^0x[0-9a-f]{40}$/i;
const TX_HASH = /^0x[0-9a-f]{64}$/i;
const HEX_QUANTITY = /^0x(?:0|[1-9a-f][0-9a-f]*)$/i;
const HEX_WORD = /^0x[0-9a-f]{64}$/i;
const UINT = /^(?:0|[1-9][0-9]{0,77})$/;
const EVIDENCE_BOUNDARY = 'actual_tool_http_x402_local_evm_application_store' as const;
const TRANSFER_TOPIC = '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef';
const TRANSFER_SELECTOR = '0xa9059cbb';
const BALANCE_OF_SELECTOR = '0x70a08231';
const ALLOWANCE_SELECTOR = '0xdd62ed3e';
const MAX_ACTIONS = 256;
const MAX_BLOCKS = 256;
const MAX_ROWS = 2_048;
const MAX_EVIDENCE_BYTES = 256 * 1024;
const MAX_RPC_RESULT_BYTES = 4 * 1024 * 1024;
const MAX_CAPTURE_BYTES = 8 * 1024 * 1024;
const COORDINATOR_EVIDENCE_ROOT = 'artifacts/runs/owner-identity-bef-task-coordinator';
const ACTION_EVIDENCE_ROOT = `${COORDINATOR_EVIDENCE_ROOT}/action/`;
const PREPARATION_EVIDENCE_ROOT = `${COORDINATOR_EVIDENCE_ROOT}/preparation/`;
const SECRET_KEYS = new Set([
  'privatekey', 'privkey', 'seedphrase', 'mnemonic', 'secret', 'clientsecret', 'bearer', 'bearertoken',
  'accesstoken', 'refreshtoken', 'providertoken', 'paymenttoken', 'token', 'apitoken', 'apikey',
  'authorization', 'walletmaterial', 'walletsecret', 'signature', 'signedpayload',
]);

type JsonRecord = Record<string, unknown>;
type OwnerTx = Parameters<Parameters<OwnerDatabase['transaction']>[0]>[0];
type QueryRows = Array<Record<string, unknown>>;
type ReadQuery = (statement: string, parameters?: readonly unknown[]) => Promise<unknown>;

/** This port must bind to the trusted BEF observer URL for one environment. */
export interface BefS1ReadOnlyPostgresPort {
  environmentId: string;
  /** Runs callback inside one REPEATABLE READ, READ ONLY transaction. */
  withRepeatableRead<T>(callback: (query: ReadQuery) => Promise<T>): Promise<T>;
}

/** The collector calls only the fixed JSON-RPC read methods listed below. */
export interface BefS1ReadOnlyRpcPort {
  environmentId: string;
  request(method: string, params: readonly unknown[]): Promise<unknown>;
}

export interface BefS1ObservationEvidenceSink {
  /** Stores a bounded allowlisted packet and returns its durable path and byte hash. */
  write(packet: BefS1RunObservationPacket): Promise<EvidenceReference>;
}

export interface BefS1ObservationCollectorDependencies {
  db: OwnerDatabase;
  taskReleaseSource: TaskReleaseQuerySource;
  repositoryRoot: string;
  postgresByEnvironment: Readonly<Record<string, BefS1ReadOnlyPostgresPort>>;
  rpcByEnvironment: Readonly<Record<string, BefS1ReadOnlyRpcPort>>;
  evidenceSink: BefS1ObservationEvidenceSink;
}

export type BefS1ObservationUnavailableCode =
  | 'invalid_target'
  | 'unsupported_task'
  | 'owner_cutoff_unavailable'
  | 'owner_cutoff_mismatch'
  | 'reconciliation_pending'
  | 'action_evidence_unavailable'
  | 'preparation_unavailable'
  | 'release_binding_mismatch'
  | 'source_not_configured'
  | 'observer_role_invalid'
  | 'observer_census_unavailable'
  | 'observer_census_changed'
  | 'rpc_identity_mismatch'
  | 'rpc_observation_unavailable'
  | 'rpc_interval_too_large'
  | 'rpc_mapping_incomplete'
  | 'baseline_mismatch'
  | 'capture_evidence_unavailable';

export type BefS1ObservationCollectionResult =
  | { status: 'unavailable'; reasonCode: BefS1ObservationUnavailableCode }
  | {
    status: 'candidate';
    candidate: TaskObservationBundleCandidate;
    evidence: EvidenceReference;
    classification: 'run_bound_observations_candidate_not_grade';
  };

export type BefS1RunObservationPacket = {
  schemaVersion: 'bts-s1-run-observation-capture/v1';
  classification: 'run_bound_observations_candidate_not_grade';
  binding: TaskEvidenceBinding;
  closure: { closureId: string; actionCutoffSequence: number; reconciledActionSequence: number };
  execution: {
    preparationId: string;
    leaseId: string;
    generationId: string;
    environmentId: string;
    environmentManifestHash: string;
    applicationSourceHash: string;
    executionIdentityHash: string;
    initialStateSha256: string;
  };
  preparation: { fixtureEvidence: EvidenceReference; baselineEvidence: EvidenceReference; baselineBlockNumber: string; baselineBlockHash: string };
  ownerActions: Array<{
    actionId: string;
    actionSequence: number;
    ownerOperationId: string;
    actionKind: string;
    commandSha256: string;
    receiptStatus: 'observed' | 'rejected_before_execution';
    actionEvidence: EvidenceReference;
    befOperationId: string | null;
    transactionHash: string | null;
  }>;
  bef: {
    session: { currentUser: string; sessionUser: string; databaseName: string; transactionReadOnly: 'on'; superuser: false; bypassRls: false };
    before: BefS1CensusProjection;
    after: BefS1CensusProjection;
    censusSha256: string;
  };
  rpc: {
    localChainId: string;
    taskCostRowsMatchReceipts: boolean;
    baseline: S1RpcCheckpoint;
    final: S1RpcCheckpoint;
    intervalBlocks: Array<{ number: string; hash: string; parentHash: string; transactionCount: number; participantTransactions: S1RpcTransaction[] }>;
    transferLogs: Array<S1TransferLog>;
    receipts: S1RpcReceipt[];
    responseHashes: Array<{ method: string; paramsSha256: string; resultSha256: string }>;
  };
};

type BefS1CensusProjection = {
  generation: JsonRecord;
  operations: JsonRecord[];
  selectedExecutions: JsonRecord[];
  selectedEvents: JsonRecord[];
  payments: JsonRecord[];
  deliveries: JsonRecord[];
  costs: JsonRecord[];
  counts: JsonRecord;
};

type S1RpcCheckpoint = {
  blockNumber: string;
  blockHash: string;
  parentHash: string;
  balances: Array<{ account: string; assetId: string; amountUnits: string }>;
  allowances: Array<{ owner: string; tokenAssetId: string; spender: string; amountUnits: string }>;
  participantTransactionCount: string;
};

type S1RpcTransaction = {
  hash: string;
  type: 'eip1559';
  chainId: number;
  from: string;
  to: string | null;
  nonce: string;
  valueWei: string;
  gasLimit: string;
  maxFeePerGasWei: string;
  maxPriorityFeePerGasWei: string;
  input: string;
  blockNumber: string;
  blockHash: string;
  transactionIndex: string;
};

type S1ExpectedTransfer = {
  operationId: string;
  command: Extract<TaskActionCommand, { kind: 'transfer' }>;
  transactionIntent: JsonRecord;
  finalMeasurement: JsonRecord;
  actionSequence: number;
  ownerAction: LoadedAction | null;
  transactionHash: string;
  receiptStatus: 'success' | 'reverted';
};

type S1ObservedTransfer = S1ExpectedTransfer & { receipt: S1RpcReceipt };

type S1TransferLog = {
  transactionHash: string;
  blockNumber: string;
  blockHash: string;
  logIndex: string;
  from: string;
  to: string;
  amountUnits: string;
};

type S1RpcReceipt = {
  transactionHash: string;
  from: string;
  to: string | null;
  blockNumber: string;
  blockHash: string;
  transactionIndex: string;
  status: 'success' | 'reverted';
  gasUsed: string;
  effectiveGasPriceWei: string;
  gasCostWei: string;
  logsSha256: string;
  transferLogs: S1TransferLog[];
};

type RunTaskRow = {
  owner_id: string; agent_id: string; mode: 'training' | 'ranked'; task_ids: string[];
  release_identity: string; manifest_hash: string;
  task_id: string; closure_status: string; closure_id: string | null; closure_operation_id: string | null;
  closure_payload_hash: string | null; closure_reason: string | null;
  action_cutoff_sequence: string | number | null; reconciled_action_sequence: string | number;
};

type ClosureRow = {
  id: string; operation_id: string | null; payload_hash: string; reason: string;
  action_cutoff_sequence: string | number; owner_id: string; agent_id: string;
};

type PreparationRow = {
  preparation_id: string; claim_id: string; lease_id: string; environment_id: string;
  release_identity: string; manifest_hash: string; task_id: string; case_id: string; case_hash: string;
  initial_state_sha256: string; execution_identity_hash: string; environment_manifest_sha256: string;
  application_source_hash: string; created_at: Date | string; lease_state: string; observation_status: string;
  generation_id: string | null; participant_id: string | null; payer_address: string | null;
  baseline_state_sha256: string | null; fixture_evidence: unknown; baseline_evidence: unknown;
};

type ExecutionBindingRow = { env_id: string; generation_id: string; manifest_hash: string; application_source_hash: string;
  participant_id: string | null; payer_address: string | null };

type ActionRow = {
  id: string; run_id: string; task_index: number; owner_id: string; agent_id: string; task_id: string;
  environment_id: string; action_sequence: string | number; operation_id: string; payload_hash: string;
  action_kind: string; command_json: unknown; receipt_revision: number; receipt_status: string;
  evidence_hash: string | null; evidence_path: string | null; transaction_hash: string | null;
  history_revision: number | null; history_status: string | null; history_evidence_hash: string | null;
  history_evidence_path: string | null; history_transaction_hash: string | null;
};

type LoadedAction = {
  row: ActionRow;
  sequence: number;
  command: Extract<TaskActionCommand, { kind: 'transfer' }>;
  evidence: SafeTaskActionEvidence;
  evidenceReference: EvidenceReference;
};

class CollectionUnavailable extends Error {
  constructor(readonly reasonCode: BefS1ObservationUnavailableCode) { super(reasonCode); }
}

function unavailable(reasonCode: BefS1ObservationUnavailableCode): BefS1ObservationCollectionResult {
  return { status: 'unavailable', reasonCode };
}

function isRecord(value: unknown): value is JsonRecord {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value) &&
    (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null));
}

function text(value: unknown): string | null { return typeof value === 'string' ? value : null; }

function rows<T extends Record<string, unknown>>(value: unknown): T[] {
  if (!Array.isArray(value)) throw new CollectionUnavailable('owner_cutoff_unavailable');
  return value as T[];
}

async function ownerRows<T extends Record<string, unknown>>(tx: OwnerTx, statement: ReturnType<typeof sql>): Promise<T[]> {
  return rows<T>(await tx.execute(statement));
}

function decimalSequence(value: string | number | null | undefined): number | null {
  if (value === null || value === undefined) return null;
  try {
    const parsed = BigInt(value);
    return parsed >= 0n && parsed <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(parsed) : null;
  } catch { return null; }
}

function decimal(value: unknown): bigint | null {
  return typeof value === 'string' && UINT.test(value) ? BigInt(value) : null;
}

function hexUint(value: unknown): bigint | null {
  return typeof value === 'string' && HEX_QUANTITY.test(value) ? BigInt(value) : null;
}

function normalizeHash(value: unknown): string | null {
  return typeof value === 'string' && TX_HASH.test(value) ? value.toLowerCase() : null;
}

function normalizeAddress(value: unknown): string | null {
  return typeof value === 'string' && ADDRESS.test(value) ? value.toLowerCase() : null;
}

function iso(value: Date | string): string | null {
  const date = value instanceof Date ? value : new Date(value);
  return Number.isFinite(date.getTime()) ? date.toISOString() : null;
}

function hasSecretKey(value: unknown, seen = new Set<object>()): boolean {
  if (value === null || typeof value !== 'object') return false;
  if (seen.has(value)) return true;
  seen.add(value);
  const found = Array.isArray(value)
    ? value.some((item) => hasSecretKey(item, seen))
    : Object.entries(value as JsonRecord).some(([key, item]) =>
      SECRET_KEYS.has(key.toLowerCase().replace(/[^a-z]/g, '')) || hasSecretKey(item, seen));
  seen.delete(value);
  return found;
}

function hasActionEvidenceSecretKey(value: unknown, path: readonly string[] = [], seen = new Set<object>()): boolean {
  if (value === null || typeof value !== 'object') return false;
  if (seen.has(value)) return true;
  seen.add(value);
  const found = Array.isArray(value)
    ? value.some((item, index) => hasActionEvidenceSecretKey(item, [...path, String(index)], seen))
    : Object.entries(value as JsonRecord).some(([key, item]) => {
      const normalized = key.toLowerCase().replace(/[^a-z]/g, '');
      const isPublicSelectedActionToken = normalized === 'token' && path.length === 2 &&
        path[0] === 'participantToolResponse' && path[1] === 'selectedAction' && normalizeAddress(item) !== null;
      return (SECRET_KEYS.has(normalized) && !isPublicSelectedActionToken) ||
        hasActionEvidenceSecretKey(item, [...path, key], seen);
    });
  seen.delete(value);
  return found;
}

function hasEventSecretKey(value: unknown, seen = new Set<object>()): boolean {
  if (value === null || typeof value !== 'object') return false;
  if (seen.has(value)) return true;
  seen.add(value);
  const found = Array.isArray(value)
    ? value.some((item) => hasEventSecretKey(item, seen))
    : Object.entries(value as JsonRecord).some(([key, item]) => {
      const normalized = key.toLowerCase().replace(/[^a-z]/g, '');
      if (normalized === 'token' && normalizeAddress(item)) return false;
      return SECRET_KEYS.has(normalized) || hasEventSecretKey(item, seen);
    });
  seen.delete(value);
  return found;
}

function evidenceReference(value: unknown): EvidenceReference | null {
  if (!isRecord(value) || Object.keys(value).sort().join(',') !== 'boundary,path,sha256' ||
      value.boundary !== EVIDENCE_BOUNDARY || typeof value.path !== 'string' ||
      typeof value.sha256 !== 'string' || !HASH.test(value.sha256)) return null;
  const path = value.path;
  if (!/^(?![A-Za-z]:)(?!\/)(?!.*(?:^|\/)\.\.(?:\/|$))[A-Za-z0-9._/-]{1,512}$/.test(path) || path.includes('\\')) return null;
  return { path, sha256: value.sha256.toLowerCase(), boundary: EVIDENCE_BOUNDARY };
}

async function readEvidenceBytes(
  repositoryRoot: string,
  reference: EvidenceReference,
  allowedPrefix: string,
  reasonCode: BefS1ObservationUnavailableCode = 'action_evidence_unavailable',
): Promise<Buffer> {
  if (!reference.path.startsWith(allowedPrefix) || reference.path.includes('\\') || reference.path.includes('\0') ||
      isAbsolute(reference.path) || reference.path.split('/').some((part) => !part || part === '.' || part === '..')) {
    throw new CollectionUnavailable(reasonCode);
  }
  const root = await realpath(repositoryRoot).catch(() => { throw new CollectionUnavailable(reasonCode); });
  const candidate = resolve(root, ...reference.path.split('/'));
  const actual = await realpath(candidate).catch(() => { throw new CollectionUnavailable(reasonCode); });
  const rel = relative(root, actual);
  const normalizedRel = rel.split(sep).join('/');
  if (!rel || rel === '..' || rel.startsWith(`..${sep}`) || isAbsolute(rel) || !normalizedRel.startsWith(allowedPrefix)) {
    throw new CollectionUnavailable(reasonCode);
  }
  const handle = await open(actual, 'r').catch(() => { throw new CollectionUnavailable(reasonCode); });
  let bytes: Buffer;
  try {
    const before = await handle.stat({ bigint: true });
    const pathBefore = await lstat(actual, { bigint: true });
    if (!before.isFile() || !pathBefore.isFile() || before.dev !== pathBefore.dev || before.ino !== pathBefore.ino ||
        before.size < 1n || before.size > BigInt(MAX_EVIDENCE_BYTES)) {
      throw new CollectionUnavailable(reasonCode);
    }
    const bounded = Buffer.alloc(MAX_EVIDENCE_BYTES + 1);
    let total = 0;
    while (total < bounded.length) {
      const result = await handle.read(bounded, total, bounded.length - total, null);
      if (result.bytesRead === 0) break;
      total += result.bytesRead;
    }
    if (total < 1 || total > MAX_EVIDENCE_BYTES) throw new CollectionUnavailable(reasonCode);
    const after = await handle.stat({ bigint: true });
    const pathAfter = await lstat(actual, { bigint: true });
    if (!pathAfter.isFile() || before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size ||
        before.mtimeNs !== after.mtimeNs || before.ctimeNs !== after.ctimeNs || after.size !== BigInt(total) ||
        pathAfter.dev !== after.dev || pathAfter.ino !== after.ino) {
      throw new CollectionUnavailable(reasonCode);
    }
    bytes = bounded.subarray(0, total);
  } catch (error) {
    if (error instanceof CollectionUnavailable) throw error;
    throw new CollectionUnavailable(reasonCode);
  } finally {
    await handle.close().catch(() => undefined);
  }
  if (createHash('sha256').update(bytes).digest('hex') !== reference.sha256) {
    throw new CollectionUnavailable(reasonCode);
  }
  return bytes;
}

function parseEvidenceJson(bytes: Buffer, allowPublicSelectedActionToken = false): JsonRecord {
  let value: unknown;
  try { value = JSON.parse(bytes.toString('utf8')) as unknown; }
  catch { throw new CollectionUnavailable('action_evidence_unavailable'); }
  const hasSecret = allowPublicSelectedActionToken ? hasActionEvidenceSecretKey(value) : hasSecretKey(value);
  if (!isRecord(value) || hasSecret) throw new CollectionUnavailable('action_evidence_unavailable');
  return value;
}

function exactPublicPins(preparation: PreparationRow, runId: string, taskIndex: number): string {
  const createdAt = iso(preparation.created_at);
  if (!createdAt) throw new CollectionUnavailable('preparation_unavailable');
  return sha256CanonicalTaskJson({
    preparationId: preparation.preparation_id,
    runId,
    taskIndex,
    claimId: preparation.claim_id,
    leaseId: preparation.lease_id,
    environmentId: preparation.environment_id,
    releaseIdentity: preparation.release_identity,
    manifestHash: preparation.manifest_hash,
    taskId: preparation.task_id,
    caseId: preparation.case_id,
    caseHash: preparation.case_hash,
    initialStateSha256: preparation.initial_state_sha256,
    executionIdentityHash: preparation.execution_identity_hash,
    environmentManifestSha256: preparation.environment_manifest_sha256,
    applicationSourceHash: preparation.application_source_hash,
    createdAt,
  }).toLowerCase();
}

async function loadPreparationEvidence(
  repositoryRoot: string,
  preparation: PreparationRow,
  runId: string,
  taskIndex: number,
  taskCase: Extract<TaskCase, { taskId: 'S1' }>,
): Promise<{ fixture: EvidenceReference; baseline: EvidenceReference; blockNumber: bigint; blockHash: string }> {
  const fixtureRef = evidenceReference(preparation.fixture_evidence);
  const baselineRef = evidenceReference(preparation.baseline_evidence);
  if (!fixtureRef || !baselineRef || fixtureRef.path === baselineRef.path ||
      fixtureRef.sha256 === baselineRef.sha256) throw new CollectionUnavailable('preparation_unavailable');
  const [fixtureBytes, baselineBytes] = await Promise.all([
    readEvidenceBytes(repositoryRoot, fixtureRef, PREPARATION_EVIDENCE_ROOT, 'preparation_unavailable'),
    readEvidenceBytes(repositoryRoot, baselineRef, PREPARATION_EVIDENCE_ROOT, 'preparation_unavailable'),
  ]);
  const fixture = parseEvidenceJson(fixtureBytes);
  const baseline = parseEvidenceJson(baselineBytes);
  const publicPinsSha256 = exactPublicPins(preparation, runId, taskIndex);
  for (const [document, kind] of [[fixture, 'fixture'], [baseline, 'baseline']] as const) {
    if (document.schemaVersion !== 'owner-bef-task-preparation-evidence/v1' || document.kind !== kind ||
        document.preparationId !== preparation.preparation_id || document.environmentId !== preparation.environment_id ||
        document.publicPinsSha256 !== publicPinsSha256 || !isRecord(document.evidence)) {
      throw new CollectionUnavailable('preparation_unavailable');
    }
  }
  const body = baseline.evidence as JsonRecord;
  const state = body.state;
  if (body.stateSha256 !== taskCase.initialState.stateSha256.toLowerCase() ||
      body.expectedStateSha256 !== taskCase.initialState.stateSha256.toLowerCase() ||
      preparation.baseline_state_sha256?.toLowerCase() !== taskCase.initialState.stateSha256.toLowerCase() ||
      !isRecord(state) || state.sameBlock !== true || !isRecord(state.projection) || !Array.isArray(state.reads)) {
    throw new CollectionUnavailable('baseline_mismatch');
  }
  const baselineBlockNumber = hexUint(state.blockNumber);
  const baselineBlockHash = normalizeHash(state.blockHash);
  const pinnedProjection = {
    balances: taskCase.initialState.balances,
    allowances: taskCase.initialState.allowances,
    deliveredComponentIds: taskCase.initialState.deliveredComponentIds,
    fulfilledObligationIds: taskCase.initialState.fulfilledObligationIds,
  };
  if (baselineBlockNumber === null || baselineBlockHash === null ||
      canonicalTaskJson(state.projection) !== canonicalTaskJson(pinnedProjection) ||
      sha256CanonicalTaskJson(state.projection).toLowerCase() !== taskCase.initialState.stateSha256.toLowerCase()) {
    throw new CollectionUnavailable('baseline_mismatch');
  }
  return { fixture: fixtureRef, baseline: baselineRef, blockNumber: baselineBlockNumber, blockHash: baselineBlockHash };
}

function exactActionEvidenceKeys(value: JsonRecord): boolean {
  const allowed = new Set([
    'schema', 'actionId', 'runId', 'taskIndex', 'actionSequence', 'ownerOperationId', 'actionKind', 'commandSha256',
    'environmentId', 'generationId', 'manifestSha256', 'applicationSourceSha256', 'idempotencyKey', 'status', 'reasonCode',
    'requestStartedAt', 'requestFinishedAt', 'httpStatus', 'befOperationId', 'transactionHash', 'outcome', 'receiptStatus',
    'rawResponseSha256', 'participantToolResponse', 'receiptGasUsed', 'receiptEffectiveGasPriceWei', 'paymentProtocol', 'environmentHealth',
  ]);
  return Object.keys(value).every((key) => allowed.has(key));
}

async function loadActions(
  repositoryRoot: string,
  run: RunTaskRow,
  preparation: PreparationRow,
  runId: string,
  taskIndex: number,
  actionCutoff: number,
  actionRows: ActionRow[],
): Promise<LoadedAction[]> {
  if (actionCutoff > MAX_ACTIONS || actionRows.length !== actionCutoff) {
    throw new CollectionUnavailable('owner_cutoff_mismatch');
  }
  const loaded: LoadedAction[] = [];
  for (let index = 0; index < actionRows.length; index += 1) {
    const row = actionRows[index]!;
    const actionSequence = decimalSequence(row.action_sequence);
    const evidenceReferenceValue = row.evidence_path && row.evidence_hash
      ? evidenceReference({ path: row.evidence_path, sha256: row.evidence_hash.toLowerCase(), boundary: EVIDENCE_BOUNDARY }) : null;
    if (actionSequence !== index + 1 || row.id !== row.id.toLowerCase() || !UUID.test(row.id) ||
        row.run_id !== runId || row.task_index !== taskIndex || row.owner_id !== run.owner_id || row.agent_id !== run.agent_id ||
        row.task_id !== 'S1' || row.environment_id !== preparation.environment_id || row.action_kind !== 'transfer' ||
        !HASH.test(row.payload_hash) || !evidenceReferenceValue || !HASH.test(row.evidence_hash ?? '') ||
        row.history_revision !== row.receipt_revision || row.history_status !== row.receipt_status ||
        row.history_evidence_hash !== row.evidence_hash || row.history_evidence_path !== row.evidence_path ||
        (row.history_transaction_hash?.toLowerCase() ?? null) !== (row.transaction_hash?.toLowerCase() ?? null) ||
        row.receipt_status === 'pending' || row.receipt_status === 'unknown' ||
        !['observed', 'rejected_before_execution'].includes(row.receipt_status)) {
      throw new CollectionUnavailable('action_evidence_unavailable');
    }
    const parsedCommand = TaskActionCommandSchema.safeParse(row.command_json);
    if (!parsedCommand.success || parsedCommand.data.kind !== 'transfer' ||
        sha256CanonicalTaskJson({ runId, taskIndex, command: parsedCommand.data }).toLowerCase() !== row.payload_hash.toLowerCase()) {
      throw new CollectionUnavailable('action_evidence_unavailable');
    }
    const bytes = await readEvidenceBytes(repositoryRoot, evidenceReferenceValue, ACTION_EVIDENCE_ROOT);
    const document = parseEvidenceJson(bytes, true);
    if (!exactActionEvidenceKeys(document) || document.schema !== 'bef-task-action-observation-v1' ||
        document.actionId !== row.id || document.runId !== runId || document.taskIndex !== taskIndex ||
        document.actionSequence !== String(actionSequence) || document.ownerOperationId !== row.operation_id ||
        document.actionKind !== 'transfer' || document.commandSha256 !== row.payload_hash.toLowerCase() ||
        document.environmentId !== preparation.environment_id || document.generationId !== preparation.generation_id ||
        document.manifestSha256 !== preparation.environment_manifest_sha256.toLowerCase() ||
        document.applicationSourceSha256 !== preparation.application_source_hash.toLowerCase() ||
        document.idempotencyKey !== `task-action-${row.id}` || document.status !== row.receipt_status ||
        (typeof document.rawResponseSha256 === 'string' && !HASH.test(document.rawResponseSha256))) {
      throw new CollectionUnavailable('action_evidence_unavailable');
    }
    if (row.receipt_status === 'observed') {
      const txHash = normalizeHash(row.transaction_hash);
      const safeResponse = document.participantToolResponse;
      const safeReceipt = isRecord(safeResponse) && isRecord(safeResponse.receipt) ? safeResponse.receipt : null;
      const safeTransaction = isRecord(safeResponse) && isRecord(safeResponse.transaction) ? safeResponse.transaction : null;
      const safeSelected = isRecord(safeResponse) && isRecord(safeResponse.selectedAction) ? safeResponse.selectedAction : null;
      if (!txHash || document.transactionHash !== txHash ||
          !UUID.test(String(document.befOperationId ?? '')) ||
          !['success', 'reverted'].includes(String(document.receiptStatus)) ||
          document.outcome !== document.receiptStatus || document.httpStatus !== 200 ||
          typeof document.rawResponseSha256 !== 'string' || !HASH.test(document.rawResponseSha256) ||
          !isRecord(safeResponse) || safeResponse.operationId !== document.befOperationId ||
          safeResponse.outcome !== document.outcome || !safeReceipt || !safeTransaction ||
          !safeSelected || safeSelected.kind !== 'transfer' || !normalizeAddress(safeSelected.token) ||
          normalizeHash(safeReceipt.transactionHash) !== txHash || normalizeHash(safeTransaction.hash) !== txHash ||
          safeReceipt.status !== document.receiptStatus || String(safeReceipt.gasUsed) !== String(document.receiptGasUsed) ||
          String(safeReceipt.effectiveGasPrice) !== String(document.receiptEffectiveGasPriceWei)) {
        throw new CollectionUnavailable('action_evidence_unavailable');
      }
    } else if (row.transaction_hash || document.transactionHash || document.receiptStatus || document.outcome ||
        !Number.isSafeInteger(document.httpStatus) && typeof document.reasonCode !== 'string') {
      throw new CollectionUnavailable('action_evidence_unavailable');
    }
    loaded.push({ row, sequence: actionSequence, command: parsedCommand.data, evidence: document as unknown as SafeTaskActionEvidence,
      evidenceReference: evidenceReferenceValue });
  }
  return loaded;
}

function pgResultRows(value: unknown): QueryRows {
  if (!Array.isArray(value) || value.length > MAX_ROWS || value.some((row) => !isRecord(row))) {
    throw new CollectionUnavailable('observer_census_unavailable');
  }
  return value as QueryRows;
}

function safeProjection(value: unknown): unknown {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return value;
  if (typeof value === 'number') return Number.isFinite(value) ? value : String(value);
  if (Array.isArray(value)) return value.map(safeProjection);
  if (isRecord(value)) {
    const output: JsonRecord = {};
    for (const [key, item] of Object.entries(value)) {
      if (SECRET_KEYS.has(key.toLowerCase().replace(/[^a-z]/g, ''))) continue;
      output[key] = safeProjection(item);
    }
    return output;
  }
  return String(value);
}

function safeSelectedAction(value: unknown): JsonRecord {
  if (!isRecord(value)) return {};
  const allowed = ['kind', 'token', 'tokenAssetId', 'amountUnits', 'amountWei', 'recipient', 'spender', 'inputAssetId', 'outputAssetId', 'amountInUnits', 'amountOutMinimumUnits', 'feeTier', 'gasLimit'];
  if (Object.keys(value).some((key) => !allowed.includes(key))) {
    throw new CollectionUnavailable('observer_census_unavailable');
  }
  return Object.fromEntries(Object.entries(value).map(([key, item]) => [key === 'token' ? 'tokenAddress' : key, safeProjection(item)]));
}

function selectedTransferCommand(
  value: unknown,
  pinnedTokenAddress?: string,
  requireTokenAddress = false,
): Extract<TaskActionCommand, { kind: 'transfer' }> | null {
  if (!isRecord(value) || value.kind !== 'transfer') return null;
  const hasTokenAddress = Object.hasOwn(value, 'tokenAddress');
  const expectedKeys = hasTokenAddress
    ? 'amountUnits,gasLimit,kind,recipient,tokenAddress'
    : 'amountUnits,gasLimit,kind,recipient';
  if (Object.keys(value).sort().join(',') !== expectedKeys || (requireTokenAddress && !hasTokenAddress)) return null;
  if (hasTokenAddress) {
    const tokenAddress = normalizeAddress(value.tokenAddress);
    if (!tokenAddress || (pinnedTokenAddress && tokenAddress !== pinnedTokenAddress.toLowerCase())) return null;
  }
  const parsed = TaskActionCommandSchema.safeParse({
    kind: 'transfer', amountUnits: value.amountUnits, gasLimit: value.gasLimit, recipient: value.recipient,
  });
  return parsed.success && parsed.data.kind === 'transfer' ? parsed.data : null;
}

function safeExecutionSnapshot(value: unknown): JsonRecord {
  if (!isRecord(value)) throw new CollectionUnavailable('observer_census_unavailable');
  const keys = ['blockNumber', 'payerNativeWei', 'payerWethUnits', 'payerUsdcUnits', 'recipientWethUnits', 'recipientUsdcUnits',
    'wethRouterAllowance', 'usdcRouterAllowance', 'poolWethUnits', 'poolUsdcUnits', 'poolLiquidity', 'poolSqrtPriceX96'];
  if (Object.keys(value).sort().join(',') !== [...keys].sort().join(',') ||
      keys.some((key) => typeof value[key] !== 'string' || !UINT.test(value[key] as string))) {
    throw new CollectionUnavailable('observer_census_unavailable');
  }
  return Object.fromEntries(keys.map((key) => [key, value[key] as string]));
}

function safeTransactionProjection(value: unknown): JsonRecord {
  if (!isRecord(value)) throw new CollectionUnavailable('observer_census_unavailable');
  const keys = ['hash', 'type', 'chainId', 'blockHash', 'blockNumber', 'transactionIndex', 'from', 'to', 'nonce', 'input',
    'valueWei', 'gasLimit', 'maxFeePerGasWei', 'maxPriorityFeePerGasWei'];
  if (Object.keys(value).sort().join(',') !== [...keys].sort().join(',')) throw new CollectionUnavailable('observer_census_unavailable');
  const hash = normalizeHash(value.hash);
  const from = normalizeAddress(value.from);
  const to = value.to === null ? null : normalizeAddress(value.to);
  const blockHash = value.blockHash === null ? null : normalizeHash(value.blockHash);
  const blockNumber = value.blockNumber === null ? null : decimal(value.blockNumber);
  const transactionIndex = value.transactionIndex === null ? null : decimal(value.transactionIndex);
  const chainId = value.chainId;
  if (!hash || value.type !== 'eip1559' || !Number.isSafeInteger(chainId) || Number(chainId) <= 0 || !from ||
      (value.to !== null && !to) || (value.blockHash !== null && !blockHash) ||
      (value.blockNumber !== null && blockNumber === null) || (value.transactionIndex !== null && transactionIndex === null) ||
      typeof value.nonce !== 'string' || !UINT.test(value.nonce) || typeof value.input !== 'string' ||
      !/^0x(?:[0-9a-f]{2})*$/i.test(value.input) || typeof value.valueWei !== 'string' || !UINT.test(value.valueWei) ||
      typeof value.gasLimit !== 'string' || !UINT.test(value.gasLimit) ||
      (value.maxFeePerGasWei !== null && (typeof value.maxFeePerGasWei !== 'string' || !UINT.test(value.maxFeePerGasWei))) ||
      (value.maxPriorityFeePerGasWei !== null && (typeof value.maxPriorityFeePerGasWei !== 'string' || !UINT.test(value.maxPriorityFeePerGasWei)))) {
    throw new CollectionUnavailable('observer_census_unavailable');
  }
  return {
    hash, type: 'eip1559', chainId: Number(chainId), blockHash, blockNumber: blockNumber?.toString() ?? null,
    transactionIndex: transactionIndex?.toString() ?? null, from, to, nonce: value.nonce, input: value.input.toLowerCase(),
    valueWei: value.valueWei, gasLimit: value.gasLimit, maxFeePerGasWei: value.maxFeePerGasWei,
    maxPriorityFeePerGasWei: value.maxPriorityFeePerGasWei,
  };
}

function decimalQuantity(value: unknown): string | null {
  if (typeof value === 'string' && UINT.test(value)) return BigInt(value).toString();
  const quantity = hexUint(value);
  return quantity === null ? null : quantity.toString();
}

function safeReceiptLogProjection(value: unknown): JsonRecord {
  if (!isRecord(value) || !Array.isArray(value.topics) || value.topics.length > 8 ||
      value.topics.some((topic) => typeof topic !== 'string' || !HEX_WORD.test(topic)) ||
      typeof value.data !== 'string' || !/^0x(?:[0-9a-f]{2})*$/i.test(value.data) || typeof value.removed !== 'boolean') {
    throw new CollectionUnavailable('observer_census_unavailable');
  }
  const address = normalizeAddress(value.address);
  const logIndex = value.logIndex === null ? null : decimalQuantity(value.logIndex);
  const transactionHash = value.transactionHash === null ? null : normalizeHash(value.transactionHash);
  const transactionIndex = value.transactionIndex === null ? null : decimalQuantity(value.transactionIndex);
  const blockHash = value.blockHash === null ? null : normalizeHash(value.blockHash);
  const blockNumber = value.blockNumber === null ? null : decimalQuantity(value.blockNumber);
  if (!address || (value.logIndex !== null && logIndex === null) ||
      (value.transactionHash !== null && !transactionHash) || (value.transactionIndex !== null && transactionIndex === null) ||
      (value.blockHash !== null && !blockHash) || (value.blockNumber !== null && blockNumber === null)) {
    throw new CollectionUnavailable('observer_census_unavailable');
  }
  return {
    address, topics: value.topics.map((topic) => (topic as string).toLowerCase()), data: value.data.toLowerCase(),
    logIndex, transactionHash, transactionIndex, blockHash, blockNumber, removed: value.removed,
  };
}

function safeReceiptProjection(value: unknown): JsonRecord {
  if (!isRecord(value) || !Array.isArray(value.logs) || value.logs.length > MAX_ROWS) {
    throw new CollectionUnavailable('observer_census_unavailable');
  }
  const transactionHash = normalizeHash(value.transactionHash);
  const from = normalizeAddress(value.from);
  const to = value.to === null ? null : normalizeAddress(value.to);
  const blockHash = normalizeHash(value.blockHash);
  const blockNumber = decimalQuantity(value.blockNumber);
  const gasUsed = decimalQuantity(value.gasUsed);
  const effectiveGasPrice = decimalQuantity(value.effectiveGasPrice);
  const gasCostWei = decimalQuantity(value.gasCostWei);
  if (!transactionHash || !from || (value.to !== null && !to) || !blockHash || blockNumber === null ||
      (value.status !== 'success' && value.status !== 'reverted') || gasUsed === null ||
      effectiveGasPrice === null || gasCostWei === null) throw new CollectionUnavailable('observer_census_unavailable');
  const logs = value.logs.map(safeReceiptLogProjection);
  return {
    transactionHash, from, to, status: value.status, blockHash, blockNumber, gasUsed,
    effectiveGasPrice, gasCostWei, logsSha256: sha256CanonicalTaskJson(logs),
  };
}

function safePayerBlockProjection(value: unknown): JsonRecord {
  if (!isRecord(value) || !Array.isArray(value.transactions) || value.transactions.length > MAX_ROWS) {
    throw new CollectionUnavailable('observer_census_unavailable');
  }
  const hash = normalizeHash(value.hash);
  const number = decimalQuantity(value.number);
  const parentHash = normalizeHash(value.parentHash);
  const baseFeePerGasWei = decimalQuantity(value.baseFeePerGasWei);
  const transactions = value.transactions.map((item) => {
    if (!isRecord(item) || Object.keys(item).sort().join(',') !== 'from,hash') throw new CollectionUnavailable('observer_census_unavailable');
    const txHash = normalizeHash(item.hash);
    const from = normalizeAddress(item.from);
    if (!txHash || !from) throw new CollectionUnavailable('observer_census_unavailable');
    return { hash: txHash, from };
  });
  if (!hash || number === null || !parentHash || baseFeePerGasWei === null) throw new CollectionUnavailable('observer_census_unavailable');
  return { hash, number, parentHash, baseFeePerGasWei, transactions };
}

function safeMeasurementProjection(value: unknown): JsonRecord {
  if (!isRecord(value) || hasEventSecretKey(value) ||
      Buffer.byteLength(canonicalTaskJson(value), 'utf8') > MAX_EVIDENCE_BYTES) {
    throw new CollectionUnavailable('observer_census_unavailable');
  }
  const expectedKeys = ['receipt', 'transaction', 'payerBlock', 'selectedAction', 'before', 'after', 'effects', 'quote', 'fee', 'taskEvaluationInputs'];
  if (Object.keys(value).sort().join(',') !== [...expectedKeys].sort().join(',')) {
    throw new CollectionUnavailable('observer_census_unavailable');
  }
  return {
    measurement_sha256: sha256CanonicalTaskJson(value),
    selected_action: safeSelectedAction(value.selectedAction),
    transaction: safeTransactionProjection(value.transaction),
    receipt: safeReceiptProjection(value.receipt),
    payer_block: safePayerBlockProjection(value.payerBlock),
    before: safeExecutionSnapshot(value.before),
    after: safeExecutionSnapshot(value.after),
  };
}

function safeSelectedEvent(row: QueryRows[number]): JsonRecord {
  const eventJson = row.event_json;
  if (!isRecord(eventJson) || hasEventSecretKey(eventJson) ||
      Buffer.byteLength(canonicalTaskJson(eventJson), 'utf8') > MAX_EVIDENCE_BYTES) {
    throw new CollectionUnavailable('observer_census_unavailable');
  }
  const eventKind = String(row.event_kind);
  const eventPayloadSha256 = sha256CanonicalTaskJson(eventJson);
  let payload: JsonRecord;
  if (eventKind === 'selected_action_bound') {
    if (Object.keys(eventJson).sort().join(',') !== 'actionKind,requestSha256,selectedAction' ||
        eventJson.actionKind !== 'transfer' || typeof eventJson.requestSha256 !== 'string' || !HASH.test(eventJson.requestSha256)) {
      throw new CollectionUnavailable('observer_census_unavailable');
    }
    payload = { actionKind: 'transfer', requestSha256: eventJson.requestSha256.toLowerCase(), selectedAction: safeSelectedAction(eventJson.selectedAction) };
  } else if (eventKind === 'prestate_observed') {
    if (Object.keys(eventJson).some((key) => !['prestate', 'idempotentReplay'].includes(key)) ||
        (eventJson.idempotentReplay !== undefined && eventJson.idempotentReplay !== true)) {
      throw new CollectionUnavailable('observer_census_unavailable');
    }
    payload = { prestate: safeExecutionSnapshot(eventJson.prestate), ...(eventJson.idempotentReplay === true ? { idempotentReplay: true } : {}) };
  } else if (eventKind === 'original_tx_hash_bound') {
    if (Object.keys(eventJson).sort().join(',') !== 'requestSha256,transactionHash,transactionIntent' ||
        typeof eventJson.requestSha256 !== 'string' || !HASH.test(eventJson.requestSha256)) {
      throw new CollectionUnavailable('observer_census_unavailable');
    }
    payload = {
      requestSha256: eventJson.requestSha256.toLowerCase(), transactionHash: normalizeHash(eventJson.transactionHash) ?? '',
      transactionIntent: safeTransactionProjection(eventJson.transactionIntent),
    };
    if (!payload.transactionHash) throw new CollectionUnavailable('observer_census_unavailable');
  } else if (eventKind === 'receipt_finalized') {
    if (Object.keys(eventJson).sort().join(',') !== 'measurement,outcome' ||
        (eventJson.outcome !== 'success' && eventJson.outcome !== 'reverted') || !isRecord(eventJson.measurement)) {
      throw new CollectionUnavailable('observer_census_unavailable');
    }
    payload = {
      outcome: eventJson.outcome,
      measurement: safeMeasurementProjection(eventJson.measurement),
    };
  } else if (eventKind === 'rejected_before_broadcast') {
    if (Object.keys(eventJson).sort().join(',') !== 'reasonCode' || typeof eventJson.reasonCode !== 'string' ||
        !/^[a-z0-9_]{1,80}$/.test(eventJson.reasonCode)) throw new CollectionUnavailable('observer_census_unavailable');
    payload = { reasonCode: eventJson.reasonCode };
  } else if (eventKind === 'settlement_unknown') {
    if (Object.keys(eventJson).sort().join(',') !== 'measurement,transactionHash' ||
        (eventJson.measurement !== null && eventJson.measurement !== undefined && !isRecord(eventJson.measurement))) {
      throw new CollectionUnavailable('observer_census_unavailable');
    }
    if (typeof eventJson.transactionHash !== 'string' || !normalizeHash(eventJson.transactionHash)) {
      throw new CollectionUnavailable('observer_census_unavailable');
    }
    payload = {
      transactionHash: normalizeHash(eventJson.transactionHash)!,
      ...(eventJson.measurement === null || eventJson.measurement === undefined
        ? { measurement: null } : { measurement: safeMeasurementProjection(eventJson.measurement) }),
    };
  } else if (eventKind === 'observer_reconciliation') {
    const expectedKeys = ['persistedManifestSha256', 'observerManifestSha256', 'transactionHash', 'observerEvidenceSha256',
      'observerEvidenceRef', 'previousMeasurementSha256', 'originalEventRefs', 'observerEvidence'];
    if (Object.keys(eventJson).sort().join(',') !== [...expectedKeys].sort().join(',') ||
        !isRecord(eventJson.observerEvidence) || !Array.isArray(eventJson.originalEventRefs) ||
        Buffer.byteLength(canonicalTaskJson(eventJson.observerEvidence), 'utf8') > MAX_EVIDENCE_BYTES ||
        !HASH.test(String(eventJson.persistedManifestSha256)) || !HASH.test(String(eventJson.observerManifestSha256)) ||
        !HASH.test(String(eventJson.observerEvidenceSha256)) ||
        (eventJson.previousMeasurementSha256 !== null && !HASH.test(String(eventJson.previousMeasurementSha256))) ||
        !/^bef_selected_execution_event:[0-9a-f-]{36}$/i.test(String(eventJson.observerEvidenceRef)) ||
        eventJson.originalEventRefs.length > MAX_ROWS) throw new CollectionUnavailable('observer_census_unavailable');
    const originalEventRefs = eventJson.originalEventRefs.map((item) => {
      if (!isRecord(item) || Object.keys(item).sort().join(',') !== 'eventId,eventKind,eventSequence,eventSha256,transactionHash' ||
          !UUID.test(String(item.eventId)) || decimalSequence(String(item.eventSequence)) === null ||
          !['selected_action_bound', 'prestate_observed', 'original_tx_hash_bound', 'settlement_unknown',
            'observer_reconciliation', 'receipt_finalized', 'rejected_before_broadcast'].includes(String(item.eventKind)) ||
          !HASH.test(String(item.eventSha256)) ||
          (item.transactionHash !== null && !normalizeHash(item.transactionHash))) {
        throw new CollectionUnavailable('observer_census_unavailable');
      }
      return {
        eventSequence: String(item.eventSequence), eventId: String(item.eventId).toLowerCase(), eventKind: item.eventKind,
        transactionHash: item.transactionHash === null ? null : normalizeHash(item.transactionHash),
        eventSha256: String(item.eventSha256).toLowerCase(),
      };
    });
    const observerEvidenceSha256 = sha256CanonicalTaskJson(eventJson.observerEvidence);
    const eventId = typeof row.event_id === 'string' ? row.event_id.toLowerCase() : '';
    if (observerEvidenceSha256.toLowerCase() !== String(eventJson.observerEvidenceSha256).toLowerCase() ||
        !UUID.test(eventId) || eventJson.observerEvidenceRef !== `bef_selected_execution_event:${eventId}`) {
      throw new CollectionUnavailable('observer_census_unavailable');
    }
    payload = {
      persistedManifestSha256: String(eventJson.persistedManifestSha256).toLowerCase(),
      observerManifestSha256: String(eventJson.observerManifestSha256).toLowerCase(),
      transactionHash: normalizeHash(eventJson.transactionHash) ?? '',
      observerEvidenceSha256: observerEvidenceSha256.toLowerCase(),
      observerEvidenceRef: String(eventJson.observerEvidenceRef),
      previousMeasurementSha256: eventJson.previousMeasurementSha256 === null ? null : String(eventJson.previousMeasurementSha256).toLowerCase(),
      originalEventRefs,
    };
    if (!payload.transactionHash) throw new CollectionUnavailable('observer_census_unavailable');
  } else throw new CollectionUnavailable('observer_census_unavailable');
  return {
    event_sequence: row.event_sequence, event_id: row.event_id, operation_id: row.operation_id,
    env_id: row.env_id, generation_id: row.generation_id, event_kind: row.event_kind,
    transaction_hash: row.transaction_hash, created_at: row.created_at,
    event_json_sha256: eventPayloadSha256, event_payload: payload,
  };
}

function validateObserverSession(proof: QueryRows[number], privilegeRows: QueryRows): BefS1RunObservationPacket['bef']['session'] {
  const expectedTables = ['bef_generation', 'bef_operation', 'bef_selected_execution', 'bef_selected_execution_event',
    'bef_payment', 'bef_delivery', 'bef_transaction_cost'];
  const privileges = new Map(privilegeRows.map((row) => [String(row.table_name), row]));
  if (proof.current_user !== 'bef_observer' || proof.session_user !== 'bef_observer' ||
      proof.transaction_read_only !== 'on' || proof.transaction_isolation !== 'repeatable read' ||
      proof.rolsuper !== false || proof.rolbypassrls !== false ||
      proof.schema_create !== false || expectedTables.some((table) => {
        const privilege = privileges.get(table);
        return !privilege || privilege.can_select !== true || privilege.can_insert !== false ||
          privilege.can_update !== false || privilege.can_delete !== false || privilege.can_truncate !== false;
      })) throw new CollectionUnavailable('observer_role_invalid');
  if (typeof proof.database_name !== 'string' || proof.database_name.length < 1 || proof.database_name.length > 128) {
    throw new CollectionUnavailable('observer_role_invalid');
  }
  return { currentUser: 'bef_observer', sessionUser: 'bef_observer', databaseName: proof.database_name,
    transactionReadOnly: 'on', superuser: false, bypassRls: false };
}

async function captureBefCensus(
  port: BefS1ReadOnlyPostgresPort,
  environmentId: string,
  generationId: string,
): Promise<{ session: BefS1RunObservationPacket['bef']['session']; census: BefS1CensusProjection }> {
  if (port.environmentId !== environmentId) throw new CollectionUnavailable('source_not_configured');
  try {
    return await port.withRepeatableRead(async (query) => {
      const sessionRows = pgResultRows(await query(`SELECT current_user AS current_user, session_user AS session_user,
          current_database() AS database_name, current_setting('transaction_read_only') AS transaction_read_only,
          current_setting('transaction_isolation') AS transaction_isolation,
          r.rolsuper AS rolsuper, r.rolbypassrls AS rolbypassrls,
          has_schema_privilege(current_user,'public','CREATE') AS schema_create
        FROM pg_roles r WHERE r.rolname=current_user`));
      const privilegeRows = pgResultRows(await query(`SELECT table_name,
          has_table_privilege(current_user,'public.'||table_name,'SELECT') AS can_select,
          has_table_privilege(current_user,'public.'||table_name,'INSERT') AS can_insert,
          has_table_privilege(current_user,'public.'||table_name,'UPDATE') AS can_update,
          has_table_privilege(current_user,'public.'||table_name,'DELETE') AS can_delete,
          has_table_privilege(current_user,'public.'||table_name,'TRUNCATE') AS can_truncate
        FROM unnest(ARRAY['bef_generation','bef_operation','bef_selected_execution','bef_selected_execution_event',
          'bef_payment','bef_delivery','bef_transaction_cost']) AS table_name`));
      if (sessionRows.length !== 1) throw new CollectionUnavailable('observer_role_invalid');
      const session = validateObserverSession(sessionRows[0]!, privilegeRows);
      const generationRows = pgResultRows(await query(`SELECT g.generation_id::text,g.env_id,g.participant_id,g.payer_address,
          trim(g.manifest_sha256) AS manifest_sha256,g.status,g.resource_variant,g.fixture_transaction_hash,
          g.fixture_block_hash,g.fixture_token_delta_units::text,g.fixture_native_balance_wei::text,
          g.expires_at::text,g.fenced_at::text,e.chain_id::text,e.node_identity,trim(e.manifest_sha256) AS environment_manifest_sha256
        FROM public.bef_generation g JOIN public.bef_environment e ON e.env_id=g.env_id
        WHERE g.env_id=$1 AND g.generation_id=$2::uuid`, [environmentId, generationId]));
      if (generationRows.length !== 1) throw new CollectionUnavailable('observer_census_unavailable');
      const operationRows = pgResultRows(await query(`SELECT operation_id::text,env_id,generation_id::text,participant_id,
          idempotency_key_sha256,trim(request_sha256) AS request_sha256,operation_kind,status,receipt_status,transaction_hash,trim(response_sha256) AS response_sha256,
          started_at::text,completed_at::text
        FROM public.bef_operation WHERE env_id=$1 AND generation_id=$2::uuid ORDER BY started_at,operation_id LIMIT ${MAX_ROWS + 1}`,
      [environmentId, generationId]));
      const executionRows = pgResultRows(await query(`SELECT operation_id::text,env_id,generation_id::text,action_kind,
          selected_action_json,prestate_json,transaction_intent_json,measurement_json,transaction_hash,outcome,reason_code,completed_at::text
        FROM public.bef_selected_execution WHERE env_id=$1 AND generation_id=$2::uuid ORDER BY created_at,operation_id LIMIT ${MAX_ROWS + 1}`,
      [environmentId, generationId]));
      const eventRows = pgResultRows(await query(`SELECT event_sequence::text,event_id::text,operation_id::text,env_id,
          generation_id::text,event_kind,transaction_hash,event_json,created_at::text
        FROM public.bef_selected_execution_event WHERE env_id=$1 AND generation_id=$2::uuid ORDER BY event_sequence LIMIT ${MAX_ROWS + 1}`,
      [environmentId, generationId]));
      const paymentRows = pgResultRows(await query(`SELECT payment_id::text,operation_id::text,env_id,generation_id::text,
          payer_address,network,asset_address,amount_units::text,facilitator_address,transaction_hash,receipt_status,token_delta_units::text,
          payer_balance_before::text,payer_balance_after::text,facilitator_balance_before::text,facilitator_balance_after::text,observed_at::text
        FROM public.bef_payment WHERE env_id=$1 AND generation_id=$2::uuid ORDER BY observed_at,payment_id LIMIT ${MAX_ROWS + 1}`,
      [environmentId, generationId]));
      const deliveryRows = pgResultRows(await query(`SELECT d.delivery_id::text,d.operation_id::text,o.env_id,o.generation_id::text,
          d.resource_id,trim(d.content_sha256) AS content_sha256,d.content_bytes::text,d.delivered_at::text
        FROM public.bef_delivery d JOIN public.bef_operation o ON o.operation_id=d.operation_id
        WHERE o.env_id=$1 AND o.generation_id=$2::uuid ORDER BY d.delivered_at,d.delivery_id LIMIT ${MAX_ROWS + 1}`,
      [environmentId, generationId]));
      const costRows = pgResultRows(await query(`SELECT operation_id::text,env_id,generation_id::text,transaction_hash,payer_address,
          payer_role,receipt_status,transaction_from,receipt_from,receipt_block_number::text,receipt_block_hash,
          receipt_block_parent_hash,gas_used::text,effective_gas_price_wei::text,gas_cost_wei::text,
          modeled_gas_fee_usdc_units::text,manifest_sha256,selected_principal_asset,selected_principal_units::text,
          observed_principal_units::text,created_at::text
        FROM public.bef_transaction_cost WHERE env_id=$1 AND generation_id=$2::uuid ORDER BY transaction_hash LIMIT ${MAX_ROWS + 1}`,
      [environmentId, generationId]));
      const countsRows = pgResultRows(await query(`SELECT
          (SELECT count(*)::text FROM public.bef_operation WHERE env_id=$1 AND generation_id=$2::uuid) AS operations,
          (SELECT count(*)::text FROM public.bef_selected_execution WHERE env_id=$1 AND generation_id=$2::uuid) AS selected_executions,
          (SELECT count(*)::text FROM public.bef_selected_execution_event WHERE env_id=$1 AND generation_id=$2::uuid) AS selected_events,
          (SELECT count(*)::text FROM public.bef_payment WHERE env_id=$1 AND generation_id=$2::uuid) AS payments,
          (SELECT count(*)::text FROM public.bef_delivery d JOIN public.bef_operation o ON o.operation_id=d.operation_id
            WHERE o.env_id=$1 AND o.generation_id=$2::uuid) AS deliveries,
          (SELECT count(*)::text FROM public.bef_transaction_cost WHERE env_id=$1 AND generation_id=$2::uuid) AS costs`,
      [environmentId, generationId]));
      if (countsRows.length !== 1 || [operationRows, executionRows, eventRows, paymentRows, deliveryRows, costRows]
        .some((list) => list.length > MAX_ROWS)) throw new CollectionUnavailable('observer_census_unavailable');
      const counts = countsRows[0]!;
      const countPairs: Array<[string, QueryRows]> = [
        ['operations', operationRows], ['selected_executions', executionRows], ['selected_events', eventRows],
        ['payments', paymentRows], ['deliveries', deliveryRows], ['costs', costRows],
      ];
      if (countPairs.some(([key, list]) => decimal(counts[key]) !== BigInt(list.length))) {
        throw new CollectionUnavailable('observer_census_unavailable');
      }
      const safeRows = (list: QueryRows, project: (row: QueryRows[number]) => JsonRecord) => list.map(project);
      const census: BefS1CensusProjection = {
        generation: safeProjection(generationRows[0]) as JsonRecord,
        operations: safeRows(operationRows, (row) => safeProjection(row) as JsonRecord),
        selectedExecutions: safeRows(executionRows, (row) => ({
          operation_id: row.operation_id, env_id: row.env_id, generation_id: row.generation_id,
          action_kind: row.action_kind, selected_action: safeSelectedAction(row.selected_action_json),
          prestate: row.prestate_json === null ? null : safeExecutionSnapshot(row.prestate_json),
          transaction_intent: row.transaction_intent_json === null ? null : safeTransactionProjection(row.transaction_intent_json),
          measurement: row.measurement_json === null ? null : safeMeasurementProjection(row.measurement_json),
          transaction_hash: row.transaction_hash, outcome: row.outcome, reason_code: row.reason_code, completed_at: row.completed_at,
        })),
        selectedEvents: safeRows(eventRows, safeSelectedEvent),
        payments: safeRows(paymentRows, (row) => safeProjection(row) as JsonRecord),
        deliveries: safeRows(deliveryRows, (row) => safeProjection(row) as JsonRecord),
        costs: safeRows(costRows, (row) => safeProjection(row) as JsonRecord),
        counts: safeProjection(counts) as JsonRecord,
      };
      if (hasSecretKey(census) || Buffer.byteLength(canonicalTaskJson(census), 'utf8') > MAX_CAPTURE_BYTES) {
        throw new CollectionUnavailable('observer_census_unavailable');
      }
      return { session, census };
    });
  } catch (error) {
    if (error instanceof CollectionUnavailable) throw error;
    throw new CollectionUnavailable('observer_census_unavailable');
  }
}

class RpcRecorder {
  readonly responseHashes: Array<{ method: string; paramsSha256: string; resultSha256: string }> = [];
  constructor(private readonly port: BefS1ReadOnlyRpcPort) {}

  async request(method: string, params: readonly unknown[]): Promise<unknown> {
    if (!['eth_chainId', 'eth_blockNumber', 'eth_getBlockByNumber', 'eth_getBalance', 'eth_call', 'eth_getCode',
      'eth_getTransactionCount', 'eth_getTransactionByHash', 'eth_getTransactionReceipt', 'eth_getLogs'].includes(method)) {
      throw new CollectionUnavailable('rpc_observation_unavailable');
    }
    let result: unknown;
    try { result = await this.port.request(method, params); }
    catch { throw new CollectionUnavailable('rpc_observation_unavailable'); }
    let size: number;
    try { size = Buffer.byteLength(canonicalTaskJson(result), 'utf8'); }
    catch { throw new CollectionUnavailable('rpc_observation_unavailable'); }
    if (size > MAX_RPC_RESULT_BYTES || hasSecretKey(result)) throw new CollectionUnavailable('rpc_observation_unavailable');
    this.responseHashes.push({ method, paramsSha256: sha256CanonicalTaskJson(params), resultSha256: sha256CanonicalTaskJson(result) });
    return result;
  }
}

function blockHeader(value: unknown, expectedNumber?: bigint): { number: bigint; hash: string; parentHash: string } {
  if (!isRecord(value)) throw new CollectionUnavailable('rpc_observation_unavailable');
  const number = hexUint(value.number);
  const hash = normalizeHash(value.hash);
  const parentHash = normalizeHash(value.parentHash);
  if (number === null || hash === null || parentHash === null || (expectedNumber !== undefined && number !== expectedNumber)) {
    throw new CollectionUnavailable('rpc_observation_unavailable');
  }
  return { number, hash, parentHash };
}

function accountAddress(value: string, participant: string): string {
  const address = value === 'participant' ? participant : normalizeAddress(value);
  if (!address) throw new CollectionUnavailable('release_binding_mismatch');
  return address;
}

function encodeBalanceOf(account: string): string { return `${BALANCE_OF_SELECTOR}${account.slice(2).padStart(64, '0')}`; }
function encodeAllowance(owner: string, spender: string): string {
  return `${ALLOWANCE_SELECTOR}${owner.slice(2).padStart(64, '0')}${spender.slice(2).padStart(64, '0')}`;
}

async function readCheckpoint(
  rpc: RpcRecorder,
  identity: { localChainId: number; assets: Array<{ assetId: string; kind: string; chainId: number; address: string | null; codeHash: string | null }>;
    contracts: Array<{ address: string; codeHash: string }> },
  taskCase: Extract<TaskCase, { taskId: 'S1' }>,
  participantAddress: string,
  blockNumber: bigint,
): Promise<S1RpcCheckpoint> {
  const blockTag = `0x${blockNumber.toString(16)}`;
  const header = blockHeader(await rpc.request('eth_getBlockByNumber', [blockTag, false]), blockNumber);
  const assets = new Map(identity.assets.map((asset) => [asset.assetId, asset]));
  const balances: S1RpcCheckpoint['balances'] = [];
  for (const item of taskCase.initialState.balances) {
    const account = accountAddress(item.account, participantAddress);
    const asset = assets.get(item.assetId);
    if (!asset || asset.chainId !== identity.localChainId) throw new CollectionUnavailable('release_binding_mismatch');
    let value: bigint | null;
    if (asset.kind === 'native' && asset.address === null) {
      value = hexUint(await rpc.request('eth_getBalance', [account, blockTag]));
    } else if (asset.kind === 'erc20' && normalizeAddress(asset.address)) {
      const result = await rpc.request('eth_call', [{ to: asset.address, data: encodeBalanceOf(account) }, blockTag]);
      value = typeof result === 'string' && HEX_WORD.test(result) ? BigInt(result) : null;
    } else throw new CollectionUnavailable('release_binding_mismatch');
    if (value === null) throw new CollectionUnavailable('rpc_observation_unavailable');
    balances.push({ account: item.account, assetId: item.assetId, amountUnits: value.toString() });
  }
  const contractAddresses = new Set(identity.contracts.map((contract) => contract.address.toLowerCase()));
  const allowances: S1RpcCheckpoint['allowances'] = [];
  for (const item of taskCase.initialState.allowances) {
    const asset = assets.get(item.tokenAssetId);
    const owner = accountAddress(item.owner, participantAddress);
    const spender = normalizeAddress(item.spender);
    if (!asset || asset.kind !== 'erc20' || !normalizeAddress(asset.address) || !spender || !contractAddresses.has(spender)) {
      throw new CollectionUnavailable('release_binding_mismatch');
    }
    const result = await rpc.request('eth_call', [{ to: asset.address, data: encodeAllowance(owner, spender) }, blockTag]);
    if (typeof result !== 'string' || !HEX_WORD.test(result)) throw new CollectionUnavailable('rpc_observation_unavailable');
    allowances.push({ owner: item.owner, tokenAssetId: item.tokenAssetId, spender: item.spender, amountUnits: BigInt(result).toString() });
  }
  return {
    blockNumber: blockNumber.toString(), blockHash: header.hash, parentHash: header.parentHash,
    balances: balances.sort((a, b) => `${a.account.toLowerCase()}|${a.assetId}`.localeCompare(`${b.account.toLowerCase()}|${b.assetId}`)),
    allowances: allowances.sort((a, b) => `${a.owner.toLowerCase()}|${a.tokenAssetId}|${a.spender.toLowerCase()}`.localeCompare(`${b.owner.toLowerCase()}|${b.tokenAssetId}|${b.spender.toLowerCase()}`)),
    participantTransactionCount: '0',
  };
}

async function verifyPinnedCodeAt(
  rpc: RpcRecorder,
  identity: { assets: Array<{ kind: string; address: string | null; codeHash: string | null }>;
    contracts: Array<{ address: string; codeHash: string }> },
  blockNumber: string,
): Promise<void> {
  const tag = `0x${BigInt(blockNumber).toString(16)}`;
  const expected = new Map<string, string>();
  for (const asset of identity.assets) {
    if (asset.kind !== 'erc20') continue;
    const address = normalizeAddress(asset.address);
    if (!address || !asset.codeHash || !HASH.test(asset.codeHash)) throw new CollectionUnavailable('rpc_identity_mismatch');
    expected.set(address, asset.codeHash.toLowerCase());
  }
  for (const contract of identity.contracts) {
    const address = normalizeAddress(contract.address);
    if (!address || !HASH.test(contract.codeHash)) throw new CollectionUnavailable('rpc_identity_mismatch');
    const previous = expected.get(address);
    if (previous && previous !== contract.codeHash.toLowerCase()) throw new CollectionUnavailable('rpc_identity_mismatch');
    expected.set(address, contract.codeHash.toLowerCase());
  }
  for (const [address, expectedHash] of expected) {
    const code = await rpc.request('eth_getCode', [address, tag]);
    if (typeof code !== 'string' || !/^0x(?:[0-9a-f]{2})*$/i.test(code) || code === '0x' ||
        keccak256(code as `0x${string}`).slice(2).toLowerCase() !== expectedHash) {
      throw new CollectionUnavailable('rpc_identity_mismatch');
    }
  }
}

function stateProjection(checkpoint: S1RpcCheckpoint, taskCase: Extract<TaskCase, { taskId: 'S1' }>): JsonRecord {
  return {
    balances: checkpoint.balances,
    allowances: checkpoint.allowances,
    deliveredComponentIds: taskCase.initialState.deliveredComponentIds,
    fulfilledObligationIds: taskCase.initialState.fulfilledObligationIds,
  };
}

function caseProjection(taskCase: Extract<TaskCase, { taskId: 'S1' }>): JsonRecord {
  return {
    balances: taskCase.initialState.balances,
    allowances: taskCase.initialState.allowances,
    deliveredComponentIds: taskCase.initialState.deliveredComponentIds,
    fulfilledObligationIds: taskCase.initialState.fulfilledObligationIds,
  };
}

function hexAddressWord(value: unknown): string | null {
  return typeof value === 'string' && /^0x[0-9a-f]{64}$/i.test(value) ? `0x${value.slice(-40).toLowerCase()}` : null;
}

function transferLog(value: unknown): S1TransferLog | null {
  if (!isRecord(value) || !Array.isArray(value.topics) || value.topics.length !== 3 ||
      value.topics[0]?.toString().toLowerCase() !== TRANSFER_TOPIC) return null;
  const from = hexAddressWord(value.topics[1]);
  const to = hexAddressWord(value.topics[2]);
  const amount = typeof value.data === 'string' && HEX_WORD.test(value.data) ? BigInt(value.data).toString() : null;
  const transactionHash = normalizeHash(value.transactionHash);
  const blockHash = normalizeHash(value.blockHash);
  const blockNumber = hexUint(value.blockNumber);
  const logIndex = hexUint(value.logIndex);
  if (!from || !to || amount === null || !transactionHash || !blockHash || blockNumber === null || logIndex === null || value.removed === true) return null;
  return { transactionHash, blockNumber: blockNumber.toString(), blockHash, logIndex: logIndex.toString(), from, to, amountUnits: amount };
}

function decodeTransferInput(value: unknown): { recipient: string; amountUnits: string } | null {
  if (typeof value !== 'string' || !/^0xa9059cbb[0-9a-f]{128}$/i.test(value)) return null;
  const recipient = `0x${value.slice(34, 74).toLowerCase()}`;
  const amountUnits = BigInt(`0x${value.slice(74)}`).toString();
  return ADDRESS.test(recipient) ? { recipient, amountUnits } : null;
}

function rpcTransaction(value: unknown): S1RpcTransaction | null {
  if (!isRecord(value)) return null;
  const hash = normalizeHash(value.hash);
  const type = hexUint(value.type);
  const chainId = hexUint(value.chainId);
  const from = normalizeAddress(value.from);
  const to = value.to === null ? null : normalizeAddress(value.to);
  const nonce = hexUint(value.nonce);
  const valueWei = hexUint(value.value);
  const gasLimit = hexUint(value.gas);
  const maxFeePerGasWei = hexUint(value.maxFeePerGas);
  const maxPriorityFeePerGasWei = hexUint(value.maxPriorityFeePerGas);
  const input = typeof value.input === 'string' ? value.input.toLowerCase() : null;
  const blockNumber = hexUint(value.blockNumber);
  const blockHash = normalizeHash(value.blockHash);
  const transactionIndex = hexUint(value.transactionIndex);
  if (!hash || type !== 2n || chainId === null || chainId > BigInt(Number.MAX_SAFE_INTEGER) || !from ||
      (value.to !== null && !to) || nonce === null || valueWei === null || gasLimit === null ||
      maxFeePerGasWei === null || maxPriorityFeePerGasWei === null || input === null ||
      blockNumber === null || !blockHash || transactionIndex === null) return null;
  return { hash, type: 'eip1559', chainId: Number(chainId), from, to, nonce: nonce.toString(), valueWei: valueWei.toString(),
    gasLimit: gasLimit.toString(), maxFeePerGasWei: maxFeePerGasWei.toString(), maxPriorityFeePerGasWei: maxPriorityFeePerGasWei.toString(), input,
    blockNumber: blockNumber.toString(), blockHash, transactionIndex: transactionIndex.toString() };
}

function rpcReceipt(value: unknown, expectedTransaction: S1RpcTransaction, usdcAddress: string): S1RpcReceipt {
  if (!isRecord(value) || !Array.isArray(value.logs)) throw new CollectionUnavailable('rpc_observation_unavailable');
  const txHash = normalizeHash(value.transactionHash);
  const blockHash = normalizeHash(value.blockHash);
  const blockNumber = hexUint(value.blockNumber);
  const transactionIndex = hexUint(value.transactionIndex);
  const statusValue = hexUint(value.status);
  const gasUsed = hexUint(value.gasUsed);
  const effectiveGasPriceWei = hexUint(value.effectiveGasPrice);
  if (txHash !== expectedTransaction.hash || blockHash !== expectedTransaction.blockHash ||
      blockNumber?.toString() !== expectedTransaction.blockNumber || transactionIndex?.toString() !== expectedTransaction.transactionIndex ||
      (statusValue !== 0n && statusValue !== 1n) ||
      gasUsed === null || effectiveGasPriceWei === null || normalizeAddress(value.from) !== expectedTransaction.from ||
      (value.to === null ? null : normalizeAddress(value.to)) !== expectedTransaction.to) {
    throw new CollectionUnavailable('rpc_observation_unavailable');
  }
  if (value.logs.length > MAX_ROWS) throw new CollectionUnavailable('rpc_observation_unavailable');
  const safeLogs = value.logs.map(safeReceiptLogProjection);
  const usdcLogs = value.logs.filter((entry) => isRecord(entry) && normalizeAddress(entry.address) === usdcAddress)
    .map(transferLog);
  if (usdcLogs.some((log) => log === null)) throw new CollectionUnavailable('rpc_observation_unavailable');
  const gasCostWei = gasUsed * effectiveGasPriceWei;
  return {
    transactionHash: txHash, from: expectedTransaction.from, to: expectedTransaction.to,
    blockNumber: blockNumber.toString(), blockHash, transactionIndex: transactionIndex.toString(),
    status: statusValue === 1n ? 'success' : 'reverted', gasUsed: gasUsed.toString(),
    effectiveGasPriceWei: effectiveGasPriceWei.toString(), gasCostWei: gasCostWei.toString(),
    logsSha256: sha256CanonicalTaskJson(safeLogs),
    transferLogs: usdcLogs as S1TransferLog[],
  };
}

function safeRpcTransaction(transaction: S1RpcTransaction): JsonRecord {
  return {
    hash: transaction.hash, type: transaction.type, chainId: transaction.chainId,
    blockHash: transaction.blockHash, blockNumber: transaction.blockNumber,
    transactionIndex: transaction.transactionIndex, from: transaction.from, to: transaction.to,
    nonce: transaction.nonce, input: transaction.input, valueWei: transaction.valueWei,
    gasLimit: transaction.gasLimit, maxFeePerGasWei: transaction.maxFeePerGasWei,
    maxPriorityFeePerGasWei: transaction.maxPriorityFeePerGasWei,
  };
}

function transactionIntentMatches(intent: JsonRecord, transaction: S1RpcTransaction): boolean {
  const actual = safeRpcTransaction(transaction);
  const keys = ['hash', 'type', 'chainId', 'from', 'to', 'nonce', 'input', 'valueWei', 'gasLimit',
    'maxFeePerGasWei', 'maxPriorityFeePerGasWei'];
  if (keys.some((key) => canonicalTaskJson(intent[key]) !== canonicalTaskJson(actual[key]))) return false;
  return (intent.blockHash === null || normalizeHash(intent.blockHash) === transaction.blockHash) &&
    (intent.blockNumber === null || decimal(intent.blockNumber)?.toString() === transaction.blockNumber) &&
    (intent.transactionIndex === null || decimal(intent.transactionIndex)?.toString() === transaction.transactionIndex);
}

function rpcReceiptProjection(receipt: S1RpcReceipt): JsonRecord {
  return {
    transactionHash: receipt.transactionHash, from: receipt.from, to: receipt.to, status: receipt.status,
    blockHash: receipt.blockHash, blockNumber: receipt.blockNumber, gasUsed: receipt.gasUsed,
    effectiveGasPrice: receipt.effectiveGasPriceWei, gasCostWei: receipt.gasCostWei, logsSha256: receipt.logsSha256,
  };
}

function measurementStateMatchesTransfer(measurement: JsonRecord, command: Extract<TaskActionCommand, { kind: 'transfer' }>,
  receipt: S1RpcReceipt, participant: string): boolean {
  const before = measurement.before;
  const after = measurement.after;
  if (!isRecord(before) || !isRecord(after)) return false;
  const values = [
    'payerNativeWei', 'payerWethUnits', 'payerUsdcUnits', 'recipientWethUnits', 'recipientUsdcUnits',
    'wethRouterAllowance', 'usdcRouterAllowance', 'poolWethUnits', 'poolUsdcUnits', 'poolLiquidity', 'poolSqrtPriceX96',
  ];
  if (BigInt(before.blockNumber as string) + 1n !== BigInt(receipt.blockNumber) ||
      BigInt(after.blockNumber as string) !== BigInt(receipt.blockNumber)) return false;
  const beforeNative = BigInt(before.payerNativeWei as string);
  const afterNative = BigInt(after.payerNativeWei as string);
  const nativeMatches = beforeNative - afterNative === BigInt(receipt.gasCostWei);
  const selfRecipient = command.recipient.toLowerCase() === participant;
  const expectedTokenDelta = receipt.status === 'success' && !selfRecipient ? BigInt(command.amountUnits) : 0n;
  const payerUsdcMatches = BigInt(before.payerUsdcUnits as string) - BigInt(after.payerUsdcUnits as string) === expectedTokenDelta;
  const recipientUsdcMatches = BigInt(after.recipientUsdcUnits as string) - BigInt(before.recipientUsdcUnits as string) === expectedTokenDelta;
  const unchanged = values.filter((key) => !['payerNativeWei', 'payerUsdcUnits', 'recipientUsdcUnits'].includes(key))
    .every((key) => before[key] === after[key]);
  return nativeMatches && payerUsdcMatches && recipientUsdcMatches && unchanged;
}

function expectedTransferCalldata(transaction: S1RpcTransaction, command: Extract<TaskActionCommand, { kind: 'transfer' }>, usdcAddress: string): boolean {
  const decoded = decodeTransferInput(transaction.input);
  return transaction.to === usdcAddress && transaction.valueWei === '0' && decoded !== null &&
    decoded.recipient === command.recipient.toLowerCase() && decoded.amountUnits === command.amountUnits;
}

function compareCensuses(left: BefS1CensusProjection, right: BefS1CensusProjection): boolean {
  return canonicalTaskJson(left) === canonicalTaskJson(right);
}

function participantCostRowsMatchReceipts(
  census: BefS1CensusProjection,
  receipts: S1RpcReceipt[],
  transfers: Map<string, S1ExpectedTransfer>,
  participantAddress: string,
  environmentManifestHash: string,
): boolean {
  const receiptByHash = new Map(receipts.map((receipt) => [receipt.transactionHash, receipt]));
  const operationByHash = new Map([...transfers.values()].map((transfer) => [transfer.transactionHash, transfer.operationId]));
  const participantRows = census.costs.filter((row) => row.payer_role === 'participant');
  if (participantRows.length !== census.costs.length) throw new CollectionUnavailable('rpc_mapping_incomplete');
  const seen = new Set<string>();
  for (const row of participantRows) {
    const hash = normalizeHash(row.transaction_hash);
    const receipt = hash ? receiptByHash.get(hash) : undefined;
    const operationId = hash ? operationByHash.get(hash) : undefined;
    if (!hash || !receipt || !operationId || seen.has(hash) || String(row.operation_id).toLowerCase() !== operationId ||
        String(row.payer_address).toLowerCase() !== participantAddress ||
        String(row.transaction_from).toLowerCase() !== participantAddress || String(row.receipt_from).toLowerCase() !== participantAddress ||
        row.receipt_status !== receipt.status || String(row.receipt_block_number) !== receipt.blockNumber ||
        String(row.receipt_block_hash).toLowerCase() !== receipt.blockHash ||
        String(row.gas_used) !== receipt.gasUsed || String(row.effective_gas_price_wei) !== receipt.effectiveGasPriceWei ||
        String(row.gas_cost_wei) !== receipt.gasCostWei || String(row.manifest_sha256).toLowerCase() !== environmentManifestHash.toLowerCase()) {
      throw new CollectionUnavailable('rpc_mapping_incomplete');
    }
    seen.add(hash);
  }
  return seen.size === receipts.length;
}

function bindOperationsToActions(
  census: BefS1CensusProjection,
  actions: LoadedAction[],
  environmentId: string,
  generationId: string,
  participantId: string,
  pinnedUsdcAddress: string,
): Map<string, S1ExpectedTransfer> {
  if (census.payments.length || census.deliveries.length ||
      census.selectedExecutions.length !== census.operations.length) throw new CollectionUnavailable('rpc_mapping_incomplete');
  const byIdempotency = new Map<string, JsonRecord>();
  const operationById = new Map<string, JsonRecord>();
  for (const operation of census.operations) {
    if (operation.env_id !== environmentId || operation.generation_id !== generationId ||
        operation.participant_id !== participantId || typeof operation.idempotency_key_sha256 !== 'string' ||
        !HASH.test(operation.idempotency_key_sha256) || typeof operation.operation_id !== 'string' ||
        !UUID.test(operation.operation_id) || byIdempotency.has(operation.idempotency_key_sha256.toLowerCase())) {
      throw new CollectionUnavailable('rpc_mapping_incomplete');
    }
    byIdempotency.set(operation.idempotency_key_sha256.toLowerCase(), operation);
    operationById.set(operation.operation_id.toLowerCase(), operation);
  }
  const ownerActionsByOperation = new Map<string, LoadedAction>();
  for (const action of actions) {
    const idempotencyHash = createHash('sha256').update(`task-action-${action.row.id}`).digest('hex');
    const operation = byIdempotency.get(idempotencyHash);
    const evidenceOperationId = typeof action.evidence.befOperationId === 'string' ? action.evidence.befOperationId.toLowerCase() : null;
    const evidenceTx = normalizeHash(action.evidence.transactionHash);
    if (action.evidence.status === 'rejected_before_execution') {
      if (operation) {
        if (operation.operation_id !== evidenceOperationId || operation.status !== 'rejected' ||
            operation.receipt_status !== 'not_submitted' || operation.transaction_hash !== null) {
          throw new CollectionUnavailable('rpc_mapping_incomplete');
        }
        ownerActionsByOperation.set(String(operation.operation_id).toLowerCase(), action);
      } else if (evidenceOperationId !== null) throw new CollectionUnavailable('rpc_mapping_incomplete');
      continue;
    }
    const responseHashValid = operation?.response_sha256 === null ||
      (typeof operation?.response_sha256 === 'string' && HASH.test(operation.response_sha256));
    if (!operation || operation.operation_id !== evidenceOperationId || operation.operation_kind !== 'transfer' ||
        !['settled', 'reverted'].includes(String(operation.status)) ||
        !['success', 'reverted'].includes(String(operation.receipt_status)) ||
        normalizeHash(operation.transaction_hash) !== evidenceTx || !evidenceTx ||
        !responseHashValid ||
        operation.receipt_status !== action.evidence.receiptStatus ||
        (operation.status === 'settled') !== (operation.receipt_status === 'success')) {
      throw new CollectionUnavailable('rpc_mapping_incomplete');
    }
    ownerActionsByOperation.set(String(operation.operation_id).toLowerCase(), action);
  }
  const selectedByOperation = new Map<string, JsonRecord>();
  for (const selected of census.selectedExecutions) {
    const operationId = String(selected.operation_id).toLowerCase();
    const operation = operationById.get(operationId);
    if (!operation || selectedByOperation.has(operationId) || selected.env_id !== environmentId ||
        selected.generation_id !== generationId || selected.action_kind !== 'transfer' || operation.operation_kind !== 'transfer') {
      throw new CollectionUnavailable('rpc_mapping_incomplete');
    }
    const selectedActionRecord = isRecord(selected.selected_action) ? selected.selected_action : null;
    const selectedAction = selectedTransferCommand(selectedActionRecord, pinnedUsdcAddress);
    if (!selectedAction || !selectedActionRecord ||
        normalizeHash(selected.transaction_hash) !== normalizeHash(operation.transaction_hash)) {
      throw new CollectionUnavailable('rpc_mapping_incomplete');
    }
    const action = ownerActionsByOperation.get(operationId);
    if (action && canonicalTaskJson(selectedAction) !== canonicalTaskJson(action.command)) {
      throw new CollectionUnavailable('rpc_mapping_incomplete');
    }
    if (action) {
      const response = action.evidence.participantToolResponse;
      const responseSelected = isRecord(response) && isRecord(response.selectedAction) ? response.selectedAction : null;
      if (!responseSelected || normalizeAddress(responseSelected.token) !== pinnedUsdcAddress) {
        throw new CollectionUnavailable('rpc_mapping_incomplete');
      }
    }
    if (operation.status === 'settled' || operation.status === 'reverted') {
      const expectedReceiptStatus = operation.status === 'settled' ? 'success' : 'reverted';
      const transactionHash = normalizeHash(operation.transaction_hash);
      if (!transactionHash || operation.receipt_status !== expectedReceiptStatus || selected.outcome !== expectedReceiptStatus ||
          (action?.evidence.status === 'rejected_before_execution')) throw new CollectionUnavailable('rpc_mapping_incomplete');
      if (action && action.evidence.receiptStatus !== expectedReceiptStatus) throw new CollectionUnavailable('rpc_mapping_incomplete');
    } else if (operation.status === 'rejected') {
      if (operation.receipt_status !== 'not_submitted' || operation.transaction_hash !== null || selected.outcome !== 'rejected' ||
          (action && action.evidence.status !== 'rejected_before_execution')) throw new CollectionUnavailable('rpc_mapping_incomplete');
    } else throw new CollectionUnavailable('rpc_mapping_incomplete');
    selectedByOperation.set(operationId, selected);
  }
  const eventsByOperation = new Map<string, JsonRecord[]>();
  const eventSequences = new Set<string>();
  for (const event of census.selectedEvents) {
    const operationId = String(event.operation_id).toLowerCase();
    const operation = operationById.get(operationId);
    const selected = selectedByOperation.get(operationId);
    const sequence = decimal(event.event_sequence);
    const eventId = typeof event.event_id === 'string' ? event.event_id.toLowerCase() : '';
    const eventKind = String(event.event_kind);
    if (!operation || !selected || event.env_id !== environmentId || event.generation_id !== generationId ||
        !UUID.test(eventId) || sequence === null || eventSequences.has(String(sequence)) ||
        !['selected_action_bound', 'prestate_observed', 'original_tx_hash_bound', 'settlement_unknown',
          'observer_reconciliation', 'receipt_finalized', 'rejected_before_broadcast'].includes(eventKind) ||
        (event.transaction_hash !== null && normalizeHash(event.transaction_hash) !== normalizeHash(operation.transaction_hash))) {
      throw new CollectionUnavailable('rpc_mapping_incomplete');
    }
    eventSequences.add(String(sequence));
    const events = eventsByOperation.get(operationId) ?? [];
    events.push(event);
    eventsByOperation.set(operationId, events);
  }
  const transfers = new Map<string, S1ExpectedTransfer>();
  for (const [operationId, operation] of operationById) {
    const selected = selectedByOperation.get(operationId);
    const events = eventsByOperation.get(operationId) ?? [];
    const kinds = events.map((event) => String(event.event_kind));
    const action = ownerActionsByOperation.get(operationId);
    if (!selected || !kinds.includes('selected_action_bound') || !kinds.includes('prestate_observed')) {
      throw new CollectionUnavailable('rpc_mapping_incomplete');
    }
    const parsedSelectedAction = selectedTransferCommand(selected.selected_action, pinnedUsdcAddress);
    if (!parsedSelectedAction) {
      throw new CollectionUnavailable('rpc_mapping_incomplete');
    }
    const eventPayload = (event: JsonRecord): JsonRecord => isRecord(event.event_payload)
      ? event.event_payload : (() => { throw new CollectionUnavailable('rpc_mapping_incomplete'); })();
    const reconciliationEvents = events.filter((event) => event.event_kind === 'observer_reconciliation');
    const environmentManifestHash = String(census.generation.manifest_sha256 ?? '').toLowerCase();
    if (reconciliationEvents.length && !HASH.test(environmentManifestHash)) throw new CollectionUnavailable('rpc_mapping_incomplete');
    for (const reconciliationEvent of reconciliationEvents) {
      const reconciliationSequence = decimal(reconciliationEvent.event_sequence);
      const payload = eventPayload(reconciliationEvent);
      const referencedEvents = payload.originalEventRefs;
      const earlierEvents = events.filter((event) => {
        const sequence = decimal(event.event_sequence);
        return sequence !== null && reconciliationSequence !== null && sequence < reconciliationSequence;
      });
      if (payload.persistedManifestSha256 !== environmentManifestHash || payload.observerManifestSha256 !== environmentManifestHash ||
          payload.transactionHash !== normalizeHash(operation.transaction_hash) || !Array.isArray(referencedEvents) ||
          referencedEvents.length !== earlierEvents.length || referencedEvents.some((reference, index) => {
            if (!isRecord(reference)) return true;
            const event = earlierEvents[index]!;
            return String(reference.eventSequence) !== String(event.event_sequence) ||
              reference.eventId !== String(event.event_id).toLowerCase() || reference.eventKind !== event.event_kind ||
              reference.transactionHash !== (event.transaction_hash === null ? null : normalizeHash(event.transaction_hash)) ||
              reference.eventSha256 !== event.event_json_sha256;
          })) throw new CollectionUnavailable('rpc_mapping_incomplete');
    }
    const selectedBoundEvents = events.filter((event) => event.event_kind === 'selected_action_bound');
    const prestateEvents = events.filter((event) => event.event_kind === 'prestate_observed');
    if (selectedBoundEvents.length !== 1 || prestateEvents.length !== 1 ||
        typeof operation.request_sha256 !== 'string' || !HASH.test(operation.request_sha256) ||
        canonicalTaskJson(eventPayload(selectedBoundEvents[0]!).selectedAction) !== canonicalTaskJson(selected.selected_action) ||
        eventPayload(selectedBoundEvents[0]!).actionKind !== 'transfer' ||
        String(eventPayload(selectedBoundEvents[0]!).requestSha256).toLowerCase() !== operation.request_sha256.toLowerCase() ||
        !isRecord(selected.prestate) ||
        canonicalTaskJson(eventPayload(prestateEvents[0]!).prestate) !== canonicalTaskJson(selected.prestate)) {
      throw new CollectionUnavailable('rpc_mapping_incomplete');
    }
    const boundSequence = decimal(selectedBoundEvents[0]!.event_sequence);
    const prestateSequence = decimal(prestateEvents[0]!.event_sequence);
    if (boundSequence === null || prestateSequence === null || prestateSequence <= boundSequence) {
      throw new CollectionUnavailable('rpc_mapping_incomplete');
    }
    if (operation.status === 'rejected') {
      const rejectedEvents = events.filter((event) => event.event_kind === 'rejected_before_broadcast');
      if (rejectedEvents.length !== 1 || kinds.some((kind) =>
        ['original_tx_hash_bound', 'receipt_finalized', 'settlement_unknown', 'observer_reconciliation'].includes(kind))) {
        throw new CollectionUnavailable('rpc_mapping_incomplete');
      }
      if (eventPayload(rejectedEvents[0]!).reasonCode !== selected.reason_code) {
        throw new CollectionUnavailable('rpc_mapping_incomplete');
      }
    } else {
      const originalHashEvents = events.filter((event) => event.event_kind === 'original_tx_hash_bound');
      const finalEvents = events.filter((event) => event.event_kind === 'receipt_finalized');
      const unresolvedAtEnd = kinds.lastIndexOf('settlement_unknown') > kinds.lastIndexOf('receipt_finalized');
      if (originalHashEvents.length !== 1 || finalEvents.length !== 1 || unresolvedAtEnd || kinds.includes('rejected_before_broadcast') ||
          !['settled', 'reverted'].includes(String(operation.status))) {
        throw new CollectionUnavailable('rpc_mapping_incomplete');
      }
      const originalEvent = originalHashEvents[0]!;
      const finalEvent = finalEvents[0]!;
      const originalPayload = eventPayload(originalEvent);
      const finalPayload = eventPayload(finalEvent);
      const originalSequence = decimal(originalEvent.event_sequence);
      const finalSequence = decimal(finalEvent.event_sequence);
      if (originalSequence === null || finalSequence === null || originalSequence <= prestateSequence || finalSequence <= originalSequence ||
          String(originalPayload.requestSha256).toLowerCase() !== operation.request_sha256.toLowerCase() ||
          normalizeHash(originalPayload.transactionHash) !== normalizeHash(operation.transaction_hash) ||
          !isRecord(selected.transaction_intent) ||
          canonicalTaskJson(originalPayload.transactionIntent) !== canonicalTaskJson(selected.transaction_intent) ||
          (finalPayload.outcome !== 'success' && finalPayload.outcome !== 'reverted') ||
          finalPayload.outcome !== selected.outcome || !isRecord(finalPayload.measurement) || !isRecord(selected.measurement) ||
          canonicalTaskJson(finalPayload.measurement) !== canonicalTaskJson(selected.measurement) ||
          canonicalTaskJson(selected.measurement.before) !== canonicalTaskJson(selected.prestate)) {
        throw new CollectionUnavailable('rpc_mapping_incomplete');
      }
      const measurementAction = selectedTransferCommand(selected.measurement.selected_action, pinnedUsdcAddress, true);
      if (!measurementAction || canonicalTaskJson(measurementAction) !== canonicalTaskJson(parsedSelectedAction)) {
        throw new CollectionUnavailable('rpc_mapping_incomplete');
      }
      const transactionHash = normalizeHash(operation.transaction_hash);
      if (!transactionHash) throw new CollectionUnavailable('rpc_mapping_incomplete');
      transfers.set(operationId, {
        operationId,
        command: parsedSelectedAction,
        transactionIntent: selected.transaction_intent as JsonRecord,
        finalMeasurement: selected.measurement as JsonRecord,
        actionSequence: action?.sequence ?? 0,
        ownerAction: action ?? null,
        transactionHash,
        receiptStatus: operation.status === 'settled' ? 'success' : 'reverted',
      });
    }
  }
  for (const action of actions) {
    if (action.evidence.status === 'observed' && !ownerActionsByOperation.has(String(action.evidence.befOperationId).toLowerCase())) {
      throw new CollectionUnavailable('rpc_mapping_incomplete');
    }
  }
  return transfers;
}

function resolveUsdc(taskCase: Extract<TaskCase, { taskId: 'S1' }>, executionIdentity: {
  localChainId: number; assets: Array<{ assetId: string; kind: string; chainId: number; address: string | null }>;
}): { token: string; recipient: string } {
  const usdc = executionIdentity.assets.filter((asset) => asset.assetId === 'USDC');
  const participantUsdc = taskCase.initialState.balances.filter((item) => item.account === 'participant' && item.assetId === 'USDC');
  const participantEth = taskCase.initialState.balances.filter((item) => item.account === 'participant' && item.assetId === 'ETH');
  const recipientUsdc = taskCase.initialState.balances.filter((item) =>
    item.account === taskCase.objective.recipient && item.assetId === 'USDC');
  if (usdc.length !== 1 || usdc[0]!.kind !== 'erc20' || !normalizeAddress(usdc[0]!.address) ||
      usdc[0]!.chainId !== executionIdentity.localChainId || participantUsdc.length !== 1 || participantEth.length !== 1 ||
      recipientUsdc.length !== 1 || taskCase.objective.sender !== 'participant') {
    throw new CollectionUnavailable('release_binding_mismatch');
  }
  return {
    token: normalizeAddress(usdc[0]!.address)!,
    recipient: taskCase.objective.recipient === 'participant' ? '' : taskCase.objective.recipient.toLowerCase(),
  };
}

async function readInterval(
  rpc: RpcRecorder,
  baseline: S1RpcCheckpoint,
  final: S1RpcCheckpoint,
  participant: string,
  objectiveRecipient: string,
  usdcAddress: string,
  expectedOperations: Map<string, S1ExpectedTransfer>,
): Promise<{ blocks: BefS1RunObservationPacket['rpc']['intervalBlocks']; logs: S1TransferLog[]; receipts: S1RpcReceipt[]; transfers: S1ObservedTransfer[] }> {
  const baselineNumber = BigInt(baseline.blockNumber);
  const finalNumber = BigInt(final.blockNumber);
  const count = finalNumber - baselineNumber;
  if (count < 0n || count > BigInt(MAX_BLOCKS)) throw new CollectionUnavailable('rpc_interval_too_large');
  const expectedHashes = new Map<string, S1ExpectedTransfer>();
  for (const transfer of expectedOperations.values()) {
    if (!normalizeHash(transfer.transactionHash) || expectedHashes.has(transfer.transactionHash)) {
      throw new CollectionUnavailable('rpc_mapping_incomplete');
    }
    expectedHashes.set(transfer.transactionHash, transfer);
  }
  const blockSummary: BefS1RunObservationPacket['rpc']['intervalBlocks'] = [];
  const participantTransactions: S1RpcTransaction[] = [];
  const payerBlocksByNumber = new Map<string, JsonRecord>();
  let previousBlockHash = baseline.blockHash;
  for (let number = baselineNumber + 1n; number <= finalNumber; number += 1n) {
    const tag = `0x${number.toString(16)}`;
    const raw = await rpc.request('eth_getBlockByNumber', [tag, true]);
    if (!isRecord(raw) || !Array.isArray(raw.transactions)) throw new CollectionUnavailable('rpc_observation_unavailable');
    const header = blockHeader(raw, number);
    if (header.parentHash !== previousBlockHash) throw new CollectionUnavailable('rpc_mapping_incomplete');
    previousBlockHash = header.hash;
    const payerBlockProjection = safePayerBlockProjection({
      hash: header.hash, number: number.toString(), parentHash: header.parentHash,
      baseFeePerGasWei: raw.baseFeePerGas, transactions: raw.transactions.map((item) => {
        if (!isRecord(item)) throw new CollectionUnavailable('rpc_observation_unavailable');
        return { hash: item.hash, from: item.from };
      }),
    });
    payerBlocksByNumber.set(number.toString(), payerBlockProjection);
    const participants: S1RpcTransaction[] = [];
    for (const value of raw.transactions) {
      if (!isRecord(value) || normalizeAddress(value.from) !== participant) continue;
      const transaction = rpcTransaction(value);
      if (!transaction || transaction.blockNumber !== number.toString() || transaction.blockHash !== header.hash) {
        throw new CollectionUnavailable('rpc_observation_unavailable');
      }
      participants.push(transaction);
      participantTransactions.push(transaction);
    }
    blockSummary.push({ number: number.toString(), hash: header.hash, parentHash: header.parentHash,
      transactionCount: raw.transactions.length, participantTransactions: participants });
  }
  if (previousBlockHash !== final.blockHash) throw new CollectionUnavailable('rpc_mapping_incomplete');
  const beforeNonce = BigInt(baseline.participantTransactionCount);
  const afterNonce = BigInt(final.participantTransactionCount);
  if (afterNonce < beforeNonce || afterNonce - beforeNonce !== BigInt(participantTransactions.length) ||
      participantTransactions.some((transaction) => {
        const nonce = BigInt(transaction.nonce);
        return nonce < beforeNonce || nonce >= afterNonce;
      })) throw new CollectionUnavailable('rpc_mapping_incomplete');
  const nonces = participantTransactions.map((transaction) => BigInt(transaction.nonce)).sort((a, b) => a < b ? -1 : a > b ? 1 : 0);
  if (nonces.some((nonce, index) => nonce !== beforeNonce + BigInt(index))) throw new CollectionUnavailable('rpc_mapping_incomplete');
  const actualByHash = new Map(participantTransactions.map((transaction) => [transaction.hash, transaction]));
  if (actualByHash.size !== participantTransactions.length || actualByHash.size !== expectedHashes.size ||
      [...expectedHashes.keys()].some((hash) => !actualByHash.has(hash))) throw new CollectionUnavailable('rpc_mapping_incomplete');

  const txReceipts: S1RpcReceipt[] = [];
  const observedTransfers: S1ObservedTransfer[] = [];
  const orderedParticipantTransactions = [...participantTransactions].sort((left, right) => {
    const blockOrder = BigInt(left.blockNumber) - BigInt(right.blockNumber);
    if (blockOrder !== 0n) return blockOrder < 0n ? -1 : 1;
    const transactionOrder = BigInt(left.transactionIndex) - BigInt(right.transactionIndex);
    return transactionOrder < 0n ? -1 : transactionOrder > 0n ? 1 : 0;
  });
  for (const transaction of orderedParticipantTransactions) {
    const hash = transaction.hash;
    const expectedTransfer = expectedHashes.get(hash);
    if (!expectedTransfer || !expectedTransferCalldata(transaction, expectedTransfer.command, usdcAddress)) {
      throw new CollectionUnavailable('rpc_mapping_incomplete');
    }
    const transactionResult = rpcTransaction(await rpc.request('eth_getTransactionByHash', [hash]));
    if (!transactionResult || canonicalTaskJson(transactionResult) !== canonicalTaskJson(transaction)) {
      throw new CollectionUnavailable('rpc_mapping_incomplete');
    }
    if (!transactionIntentMatches(expectedTransfer.transactionIntent, transaction) ||
        canonicalTaskJson(expectedTransfer.finalMeasurement.transaction) !== canonicalTaskJson(safeRpcTransaction(transaction))) {
      throw new CollectionUnavailable('rpc_mapping_incomplete');
    }
    const receipt = rpcReceipt(await rpc.request('eth_getTransactionReceipt', [hash]), transaction, usdcAddress);
    if (receipt.status !== expectedTransfer.receiptStatus) throw new CollectionUnavailable('rpc_mapping_incomplete');
    const payerBlock = payerBlocksByNumber.get(transaction.blockNumber);
    if (!payerBlock || canonicalTaskJson(expectedTransfer.finalMeasurement.receipt) !== canonicalTaskJson(rpcReceiptProjection(receipt)) ||
        canonicalTaskJson(expectedTransfer.finalMeasurement.payer_block) !== canonicalTaskJson(payerBlock) ||
        !Array.isArray(payerBlock.transactions) || payerBlock.transactions.length !== 1 ||
        !isRecord(payerBlock.transactions[0]) || payerBlock.transactions[0].hash !== transaction.hash ||
        payerBlock.transactions[0].from !== participant ||
        !measurementStateMatchesTransfer(expectedTransfer.finalMeasurement, expectedTransfer.command, receipt, participant)) {
      throw new CollectionUnavailable('rpc_mapping_incomplete');
    }
    if (receipt.status === 'success') {
      if (receipt.transferLogs.length !== 1 || receipt.transferLogs[0]!.from !== participant ||
          receipt.transferLogs[0]!.to !== expectedTransfer.command.recipient.toLowerCase() ||
          receipt.transferLogs[0]!.amountUnits !== expectedTransfer.command.amountUnits) {
        throw new CollectionUnavailable('rpc_mapping_incomplete');
      }
    } else if (receipt.transferLogs.length !== 0) throw new CollectionUnavailable('rpc_mapping_incomplete');
    txReceipts.push(receipt);
    observedTransfers.push({ ...expectedTransfer, receipt });
  }
  const logsRaw = count === 0n ? [] : await rpc.request('eth_getLogs', [{ address: usdcAddress,
    fromBlock: `0x${(baselineNumber + 1n).toString(16)}`, toBlock: `0x${finalNumber.toString(16)}`, topics: [TRANSFER_TOPIC] }]);
  if (!Array.isArray(logsRaw) || logsRaw.length > MAX_ROWS) throw new CollectionUnavailable('rpc_observation_unavailable');
  if (logsRaw.some((entry) => !isRecord(entry) || normalizeAddress(entry.address) !== usdcAddress)) {
    throw new CollectionUnavailable('rpc_observation_unavailable');
  }
  const decodedLogs = logsRaw.map(transferLog);
  if (decodedLogs.some((log) => log === null)) throw new CollectionUnavailable('rpc_observation_unavailable');
  const allLogs = decodedLogs as S1TransferLog[];
  const relevantAccounts = new Set([participant, objectiveRecipient, ...[...expectedOperations.values()].map((transfer) => transfer.command.recipient.toLowerCase())]);
  const relevantLogs = allLogs.filter((log) => log.from === participant || relevantAccounts.has(log.from) || relevantAccounts.has(log.to));
  const receiptsLogs = txReceipts.flatMap((receipt) => receipt.transferLogs);
  const canonicalLogMap = new Map(receiptsLogs.map((log) => [`${log.transactionHash}:${log.logIndex}`, log]));
  if (relevantLogs.some((log) => !canonicalLogMap.has(`${log.transactionHash}:${log.logIndex}`)) ||
      receiptsLogs.some((log) => !relevantLogs.some((item) => item.transactionHash === log.transactionHash && item.logIndex === log.logIndex))) {
    throw new CollectionUnavailable('rpc_mapping_incomplete');
  }
  const blockHashes = new Map(blockSummary.map((block) => [block.number, block.hash]));
  for (const log of relevantLogs) {
    const canonicalHash = blockHashes.get(log.blockNumber);
    if (!canonicalHash || canonicalHash !== log.blockHash) throw new CollectionUnavailable('rpc_mapping_incomplete');
  }
  const balanceOf = (checkpoint: S1RpcCheckpoint, account: string) => {
    const rows = checkpoint.balances.filter((item) => item.account === account && item.assetId === 'USDC');
    return rows.length === 1 ? BigInt(rows[0]!.amountUnits) : null;
  };
  const checkedAccounts = new Set([participant, objectiveRecipient]);
  for (const account of checkedAccounts) {
    const caseAccount = account === participant ? 'participant' : account;
    const before = balanceOf(baseline, caseAccount);
    const after = balanceOf(final, caseAccount);
    if (before === null || after === null) throw new CollectionUnavailable('rpc_mapping_incomplete');
    const incoming = relevantLogs.filter((log) => log.to === account).reduce((sum, log) => sum + BigInt(log.amountUnits), 0n);
    const outgoing = relevantLogs.filter((log) => log.from === account).reduce((sum, log) => sum + BigInt(log.amountUnits), 0n);
    if (after - before !== incoming - outgoing) throw new CollectionUnavailable('rpc_mapping_incomplete');
  }
  const nativeBalance = (checkpoint: S1RpcCheckpoint) => {
    const matches = checkpoint.balances.filter((item) => item.account === 'participant' && item.assetId === 'ETH');
    return matches.length === 1 ? BigInt(matches[0]!.amountUnits) : null;
  };
  const nativeBefore = nativeBalance(baseline);
  const nativeAfter = nativeBalance(final);
  if (nativeBefore === null || nativeAfter === null) throw new CollectionUnavailable('rpc_mapping_incomplete');
  const participantGasCost = txReceipts.reduce((sum, receipt) => sum + BigInt(receipt.gasCostWei), 0n);
  if (nativeBefore - nativeAfter !== participantGasCost) throw new CollectionUnavailable('rpc_mapping_incomplete');
  relevantLogs.sort((a, b) => {
    const blockOrder = BigInt(a.blockNumber) - BigInt(b.blockNumber);
    if (blockOrder !== 0n) return blockOrder < 0n ? -1 : 1;
    const logOrder = BigInt(a.logIndex) - BigInt(b.logIndex);
    if (logOrder !== 0n) return logOrder < 0n ? -1 : 1;
    return a.transactionHash.localeCompare(b.transactionHash);
  });
  return { blocks: blockSummary, logs: relevantLogs, receipts: txReceipts, transfers: observedTransfers };
}

function projectedAction(action: LoadedAction): BefS1RunObservationPacket['ownerActions'][number] {
  return {
    actionId: action.row.id, actionSequence: action.sequence, ownerOperationId: action.row.operation_id,
    actionKind: action.row.action_kind, commandSha256: action.row.payload_hash.toLowerCase(),
    receiptStatus: action.evidence.status as 'observed' | 'rejected_before_execution',
    actionEvidence: action.evidenceReference,
    befOperationId: typeof action.evidence.befOperationId === 'string' ? action.evidence.befOperationId.toLowerCase() : null,
    transactionHash: normalizeHash(action.evidence.transactionHash),
  };
}

async function collectLocked(
  deps: BefS1ObservationCollectorDependencies,
  target: { runId: string; taskIndex: number },
  tx: OwnerTx,
): Promise<BefS1ObservationCollectionResult> {
  const ownerRowsFound = await ownerRows<{ owner_id: string; agent_id: string }>(tx,
    sql`SELECT owner_id,agent_id FROM oid_benchmark_run WHERE id=${target.runId}`);
  const owner = ownerRowsFound[0];
  if (!owner) return unavailable('owner_cutoff_unavailable');
  await tx.execute(sql`SELECT id FROM oid_owner WHERE id=${owner.owner_id} FOR NO KEY UPDATE`);
  await tx.execute(sql`SELECT id FROM oid_agent WHERE id=${owner.agent_id} AND owner_id=${owner.owner_id} FOR NO KEY UPDATE`);
  const runRows = await ownerRows<RunTaskRow>(tx, sql`SELECT r.owner_id,r.agent_id,r.mode,r.task_ids,r.release_identity,r.manifest_hash,
      t.task_id,t.closure_status,t.closure_id,t.closure_operation_id,t.closure_payload_hash,t.closure_reason,
      t.action_cutoff_sequence::text AS action_cutoff_sequence,t.reconciled_action_sequence::text AS reconciled_action_sequence
    FROM oid_benchmark_run r JOIN oid_run_task t ON t.run_id=r.id
    WHERE r.id=${target.runId} AND r.owner_id=${owner.owner_id} AND r.agent_id=${owner.agent_id} AND t.task_index=${target.taskIndex}
    FOR UPDATE OF r,t`);
  const run = runRows[0];
  if (!run || run.task_id !== 'S1' || run.task_ids[target.taskIndex] !== 'S1') {
    return unavailable(run ? 'unsupported_task' : 'owner_cutoff_unavailable');
  }
  if (run.closure_status !== 'closed' || !run.closure_id || run.action_cutoff_sequence === null) return unavailable('owner_cutoff_unavailable');
  const actionCutoff = decimalSequence(run.action_cutoff_sequence);
  const reconciled = decimalSequence(run.reconciled_action_sequence);
  if (actionCutoff === null || reconciled === null || reconciled < actionCutoff) return unavailable('reconciliation_pending');
  const closureRows = await ownerRows<ClosureRow>(tx, sql`SELECT id,operation_id,payload_hash,reason,action_cutoff_sequence::text AS action_cutoff_sequence,owner_id,agent_id
    FROM oid_run_task_closure WHERE id=${run.closure_id} AND run_id=${target.runId} AND task_index=${target.taskIndex} FOR KEY SHARE`);
  const closure = closureRows[0];
  if (!closure || closure.owner_id !== run.owner_id || closure.agent_id !== run.agent_id ||
      decimalSequence(closure.action_cutoff_sequence) !== actionCutoff || closure.operation_id !== run.closure_operation_id ||
      closure.payload_hash !== run.closure_payload_hash || closure.reason !== run.closure_reason) return unavailable('owner_cutoff_mismatch');

  const prepRows = await ownerRows<PreparationRow>(tx, sql`SELECT i.preparation_id::text,i.claim_id::text,i.lease_id::text,i.environment_id,
      i.release_identity,i.manifest_hash,i.task_id,i.case_id,i.case_hash,i.initial_state_sha256,i.execution_identity_hash,
      i.environment_manifest_sha256,i.application_source_hash,i.created_at,
      l.state AS lease_state,o.status AS observation_status,o.generation_id::text,o.participant_id,o.payer_address,
      o.baseline_state_sha256,o.fixture_evidence,o.baseline_evidence
    FROM oid_task_preparation_intent i JOIN oid_task_environment_lease l ON l.preparation_id=i.preparation_id AND l.lease_id=i.lease_id
    JOIN LATERAL (SELECT status,generation_id,participant_id,payer_address,baseline_state_sha256,fixture_evidence,baseline_evidence
      FROM oid_task_preparation_observation WHERE preparation_id=i.preparation_id ORDER BY revision DESC LIMIT 1) o ON true
    WHERE i.run_id=${target.runId} AND i.task_index=${target.taskIndex} FOR UPDATE OF i,l`);
  const preparation = prepRows[0];
  if (!preparation || preparation.lease_state !== 'leased' || preparation.observation_status !== 'ready' ||
      !preparation.generation_id || !preparation.participant_id || !normalizeAddress(preparation.payer_address) ||
      preparation.task_id !== 'S1' ||
      preparation.release_identity !== run.release_identity || preparation.manifest_hash !== run.manifest_hash ||
      preparation.baseline_state_sha256 !== preparation.initial_state_sha256) return unavailable('preparation_unavailable');
  const payerAddress = normalizeAddress(preparation.payer_address);
  if (!payerAddress) return unavailable('preparation_unavailable');
  const executionRows = await ownerRows<ExecutionBindingRow>(tx, sql`SELECT env_id,generation_id::text,manifest_hash,application_source_hash,participant_id,payer_address
    FROM oid_task_execution_binding WHERE run_id=${target.runId} AND task_index=${target.taskIndex} FOR KEY SHARE`);
  const execution = executionRows[0];
  if (!execution || execution.env_id !== preparation.environment_id || execution.generation_id !== preparation.generation_id ||
      execution.manifest_hash !== preparation.environment_manifest_sha256 || execution.application_source_hash !== preparation.application_source_hash ||
      execution.participant_id !== preparation.participant_id || execution.payer_address?.toLowerCase() !== payerAddress) {
    return unavailable('preparation_unavailable');
  }
  const release = await deps.taskReleaseSource.getValidatedReleaseRecord(run.release_identity, run.manifest_hash, tx);
  if (!release || release.releaseIdentity !== run.release_identity || release.manifestHash !== run.manifest_hash ||
      release.manifest.releaseIdentity !== run.release_identity || release.manifest.manifestHash !== run.manifest_hash) {
    return unavailable('release_binding_mismatch');
  }
  const rawCase = release.manifest.cases[run.mode].find((item) => item.taskId === 'S1');
  if (!rawCase || rawCase.taskId !== 'S1' || rawCase.caseId !== preparation.case_id || rawCase.caseHash !== preparation.case_hash ||
      rawCase.executionIdentityHash !== preparation.execution_identity_hash ||
      rawCase.initialState.stateSha256 !== preparation.initial_state_sha256) return unavailable('release_binding_mismatch');
  const taskCase = rawCase as Extract<TaskCase, { taskId: 'S1' }>;
  const binding: TaskEvidenceBinding = {
    ownerId: run.owner_id, agentId: run.agent_id, runId: target.runId, environmentId: preparation.environment_id,
    releaseIdentity: run.release_identity, manifestHash: run.manifest_hash, caseId: taskCase.caseId,
    caseHash: taskCase.caseHash, rubricHash: taskCase.rubricHash, taskId: 'S1',
  };
  const actionRows = await ownerRows<ActionRow>(tx, sql`SELECT a.id::text,a.run_id::text,a.task_index,a.owner_id::text,a.agent_id::text,a.task_id,
      a.environment_id,a.action_sequence::text,a.operation_id,a.payload_hash,a.action_kind,a.command_json,
      r.receipt_revision,r.receipt_status,r.evidence_hash,r.evidence_path,r.transaction_hash,
      h.revision AS history_revision,h.receipt_status AS history_status,h.evidence_hash AS history_evidence_hash,
      h.evidence_path AS history_evidence_path,h.transaction_hash AS history_transaction_hash
    FROM oid_run_task_action a JOIN oid_run_task_action_receipt r ON r.action_id=a.id
    LEFT JOIN LATERAL (SELECT revision,receipt_status,evidence_hash,evidence_path,transaction_hash
      FROM oid_run_task_action_reconciliation WHERE action_id=a.id ORDER BY revision DESC LIMIT 1) h ON true
    WHERE a.run_id=${target.runId} AND a.task_index=${target.taskIndex} ORDER BY a.action_sequence FOR UPDATE OF a,r`);
  let actions: LoadedAction[];
  try { actions = await loadActions(deps.repositoryRoot, run, preparation, target.runId, target.taskIndex, actionCutoff, actionRows); }
  catch (error) { if (error instanceof CollectionUnavailable) return unavailable(error.reasonCode); throw error; }

  const postgres = deps.postgresByEnvironment[preparation.environment_id];
  const rpcPort = deps.rpcByEnvironment[preparation.environment_id];
  if (!postgres || !rpcPort) return unavailable('source_not_configured');
  const usdc = resolveUsdc(taskCase, release.manifest.executionIdentity);
  const participantAddress = payerAddress;
  const objectiveRecipient = accountAddress(String(taskCase.objective.recipient), participantAddress);
  if (usdc.recipient && usdc.recipient !== objectiveRecipient) return unavailable('release_binding_mismatch');
  if (rpcPort.environmentId !== preparation.environment_id) return unavailable('source_not_configured');
  let preparationEvidence: Awaited<ReturnType<typeof loadPreparationEvidence>>;
  try { preparationEvidence = await loadPreparationEvidence(deps.repositoryRoot, preparation, target.runId, target.taskIndex, taskCase); }
  catch (error) { if (error instanceof CollectionUnavailable) return unavailable(error.reasonCode); throw error; }

  let censusBefore: Awaited<ReturnType<typeof captureBefCensus>>;
  try { censusBefore = await captureBefCensus(postgres, preparation.environment_id, preparation.generation_id); }
  catch (error) { if (error instanceof CollectionUnavailable) return unavailable(error.reasonCode); throw error; }
  const generation = censusBefore.census.generation;
  if (generation.env_id !== preparation.environment_id || generation.generation_id !== preparation.generation_id ||
      generation.participant_id !== preparation.participant_id || String(generation.payer_address).toLowerCase() !== participantAddress ||
      String(generation.chain_id) !== String(release.manifest.executionIdentity.localChainId) ||
      generation.status !== 'active' || generation.manifest_sha256 !== preparation.environment_manifest_sha256.toLowerCase() ||
      generation.environment_manifest_sha256 !== preparation.environment_manifest_sha256.toLowerCase()) {
    return unavailable('rpc_mapping_incomplete');
  }
  let operationMap: Map<string, S1ExpectedTransfer>;
  try { operationMap = bindOperationsToActions(censusBefore.census, actions, preparation.environment_id,
    preparation.generation_id, preparation.participant_id, usdc.token); }
  catch (error) { if (error instanceof CollectionUnavailable) return unavailable(error.reasonCode); throw error; }

  const rpc = new RpcRecorder(rpcPort);
  let localChainId: bigint;
  let baselineCheckpoint: S1RpcCheckpoint;
  let finalCheckpoint: S1RpcCheckpoint;
  let interval: Awaited<ReturnType<typeof readInterval>>;
  try {
    const chainIdResult = hexUint(await rpc.request('eth_chainId', []));
    if (chainIdResult === null || chainIdResult !== BigInt(release.manifest.executionIdentity.localChainId)) {
      return unavailable('rpc_identity_mismatch');
    }
    localChainId = chainIdResult;
    baselineCheckpoint = await readCheckpoint(rpc, release.manifest.executionIdentity, taskCase, participantAddress, preparationEvidence.blockNumber);
    await verifyPinnedCodeAt(rpc, release.manifest.executionIdentity, preparationEvidence.blockNumber.toString());
    if (baselineCheckpoint.blockHash !== preparationEvidence.blockHash ||
        canonicalTaskJson(stateProjection(baselineCheckpoint, taskCase)) !== canonicalTaskJson(caseProjection(taskCase))) {
      return unavailable('baseline_mismatch');
    }
    const initialNonce = hexUint(await rpc.request('eth_getTransactionCount', [participantAddress, `0x${preparationEvidence.blockNumber.toString(16)}`]));
    if (initialNonce === null) return unavailable('rpc_observation_unavailable');
    baselineCheckpoint.participantTransactionCount = initialNonce.toString();
    const head = hexUint(await rpc.request('eth_blockNumber', []));
    if (head === null || head < preparationEvidence.blockNumber) return unavailable('rpc_observation_unavailable');
    finalCheckpoint = await readCheckpoint(rpc, release.manifest.executionIdentity, taskCase, participantAddress, head);
    await verifyPinnedCodeAt(rpc, release.manifest.executionIdentity, head.toString());
    const finalNonce = hexUint(await rpc.request('eth_getTransactionCount', [participantAddress, `0x${head.toString(16)}`]));
    if (finalNonce === null) return unavailable('rpc_observation_unavailable');
    finalCheckpoint.participantTransactionCount = finalNonce.toString();
    interval = await readInterval(rpc, baselineCheckpoint, finalCheckpoint, participantAddress, objectiveRecipient,
      usdc.token, operationMap);
    const baselineAgain = blockHeader(await rpc.request('eth_getBlockByNumber', [`0x${preparationEvidence.blockNumber.toString(16)}`, false]), preparationEvidence.blockNumber);
    const finalAgain = blockHeader(await rpc.request('eth_getBlockByNumber', [`0x${head.toString(16)}`, false]), head);
    if (baselineAgain.hash !== baselineCheckpoint.blockHash || finalAgain.hash !== finalCheckpoint.blockHash) {
      return unavailable('rpc_mapping_incomplete');
    }
    // The final checkpoint is retained at one immutable block tag, with its final header re-read above.
  } catch (error) {
    if (error instanceof CollectionUnavailable) return unavailable(error.reasonCode);
    return unavailable('rpc_observation_unavailable');
  }
  let costRowsMatchReceipts: boolean;
  try {
    costRowsMatchReceipts = participantCostRowsMatchReceipts(censusBefore.census, interval.receipts, operationMap,
      participantAddress, preparation.environment_manifest_sha256);
  } catch (error) {
    if (error instanceof CollectionUnavailable) return unavailable(error.reasonCode);
    return unavailable('observer_census_unavailable');
  }

  let censusAfter: Awaited<ReturnType<typeof captureBefCensus>>;
  try { censusAfter = await captureBefCensus(postgres, preparation.environment_id, preparation.generation_id); }
  catch (error) { if (error instanceof CollectionUnavailable) return unavailable(error.reasonCode); throw error; }
  if (canonicalTaskJson(censusBefore.session) !== canonicalTaskJson(censusAfter.session) ||
      !compareCensuses(censusBefore.census, censusAfter.census)) return unavailable('observer_census_changed');

  const bindingRef = binding;
  const observations: PersistedTaskObservations = {
    schemaVersion: 'bts-task-observations/v1', binding: bindingRef, coveredThroughSequence: 0,
    captureEvidence: { path: `${COORDINATOR_EVIDENCE_ROOT}/observation/pending`, sha256: '0'.repeat(64), boundary: EVIDENCE_BOUNDARY },
    coverage: { transfers: 'complete', balances: 'complete', expenses: costRowsMatchReceipts ? 'complete' : 'incomplete' },
    transfers: [], payments: [], stateMutations: [], finalStates: [], allowanceChanges: [], allowanceUses: [],
    answers: [], selections: [], deliveries: [], trades: [], conversions: [], expenses: [],
  };
  let sequence = 0;
  for (const transfer of interval.transfers) {
    const action = transfer.ownerAction;
    const observationId = action ? `s1-transfer-${action.row.id}` : `s1-transfer-operation-${transfer.operationId}`;
    sequence += 1;
    observations.transfers.push({
      kind: 'transfer', observationId, sequence, actionSequence: transfer.actionSequence,
      source: 'persisted_observer', binding, evidence: observations.captureEvidence,
      from: 'participant', to: transfer.command.recipient.toLowerCase(), assetId: 'USDC',
      amountUnits: transfer.command.amountUnits, receiptStatus: transfer.receipt.status,
      transactionHash: transfer.receipt.transactionHash, operation: 'principal',
    });
    sequence += 1;
    observations.expenses.push({
      kind: 'expense', component: 'participant_gas', observationId: `s1-gas-operation-${transfer.operationId}`, sequence,
      actionSequence: transfer.actionSequence, source: 'persisted_observer', binding, evidence: observations.captureEvidence,
      sourceEffectId: `bef-operation:${transfer.operationId}`,
      gasUsed: transfer.receipt.gasUsed, effectiveGasPriceWei: transfer.receipt.effectiveGasPriceWei,
      receiptStatus: transfer.receipt.status, transactionHash: transfer.receipt.transactionHash,
    });
  }
  sequence += 1;
  observations.finalStates.push({
    kind: 'final_state', observationId: `s1-final-${target.runId}-${target.taskIndex}`, sequence, actionSequence: 0,
    source: 'persisted_observer', binding, evidence: observations.captureEvidence,
    balances: finalCheckpoint.balances, allowances: finalCheckpoint.allowances,
  });
  observations.coveredThroughSequence = sequence;

  const packetWithoutReference: Omit<BefS1RunObservationPacket, 'bef'> & { bef?: never } = undefined as never;
  void packetWithoutReference;
  const packet = {
    schemaVersion: 'bts-s1-run-observation-capture/v1' as const,
    classification: 'run_bound_observations_candidate_not_grade' as const,
    binding,
    closure: { closureId: closure.id, actionCutoffSequence: actionCutoff, reconciledActionSequence: reconciled },
    execution: {
      preparationId: preparation.preparation_id, leaseId: preparation.lease_id, generationId: preparation.generation_id,
      environmentId: preparation.environment_id, environmentManifestHash: preparation.environment_manifest_sha256.toLowerCase(),
      applicationSourceHash: preparation.application_source_hash.toLowerCase(), executionIdentityHash: preparation.execution_identity_hash.toLowerCase(),
      initialStateSha256: preparation.initial_state_sha256.toLowerCase(),
    },
    preparation: {
      fixtureEvidence: preparationEvidence.fixture, baselineEvidence: preparationEvidence.baseline,
      baselineBlockNumber: preparationEvidence.blockNumber.toString(), baselineBlockHash: preparationEvidence.blockHash,
    },
    ownerActions: actions.map(projectedAction),
    bef: {
      session: censusBefore.session, before: censusBefore.census, after: censusAfter.census,
      censusSha256: sha256CanonicalTaskJson(censusBefore.census),
    },
    rpc: {
      localChainId: localChainId.toString(), taskCostRowsMatchReceipts: costRowsMatchReceipts,
      baseline: baselineCheckpoint, final: finalCheckpoint,
      intervalBlocks: interval.blocks, transferLogs: interval.logs, receipts: interval.receipts,
      responseHashes: rpc.responseHashes,
    },
  } satisfies BefS1RunObservationPacket;
  if (hasSecretKey(packet) || Buffer.byteLength(canonicalTaskJson(packet), 'utf8') > MAX_CAPTURE_BYTES) {
    return unavailable('capture_evidence_unavailable');
  }
  let captureEvidence: EvidenceReference;
  try {
    captureEvidence = evidenceReference(await deps.evidenceSink.write(packet))!;
    if (!captureEvidence) return unavailable('capture_evidence_unavailable');
  } catch { return unavailable('capture_evidence_unavailable'); }
  observations.captureEvidence = captureEvidence;
  for (const domain of ['transfers', 'expenses', 'finalStates'] as const) {
    for (const observation of observations[domain]) observation.evidence = captureEvidence;
  }
  const candidate: TaskObservationBundleCandidate = {
    schemaVersion: 'bts-task-observation-bundle-candidate/v1',
    observationCutoffSequence: sequence,
    cutoffStatus: 'authoritative',
    cutoffEvidence: captureEvidence,
    observations,
  };
  return { status: 'candidate', candidate, evidence: captureEvidence, classification: 'run_bound_observations_candidate_not_grade' };
}

/** Collects one closed S1 task while its exact environment lease remains locked and leased. */
export async function collectBefS1TaskObservationCandidate(
  deps: BefS1ObservationCollectorDependencies,
  target: { runId: string; taskIndex: number },
): Promise<BefS1ObservationCollectionResult> {
  if (!UUID.test(target.runId) || !Number.isSafeInteger(target.taskIndex) || target.taskIndex < 0 || target.taskIndex > 11) {
    return unavailable('invalid_target');
  }
  try {
    return await deps.db.transaction(async (tx) => collectLocked(deps, target, tx));
  } catch (error) {
    if (error instanceof CollectionUnavailable) return unavailable(error.reasonCode);
    return unavailable('owner_cutoff_unavailable');
  }
}
