/**
 * Run-bound S3 observation collection. This emits an unsealed observation
 * candidate only; it never grades, seals, advances, resets, or invokes tools.
 *
 * AICODE-NOTE: S3's zero-effect claim is established from owner closure/action
 * evidence, a role-checked BEF generation census, and independent block-tagged
 * RPC reads. A copied answer or HTTP body alone is not sufficient evidence.
 */
import { createHash } from 'node:crypto';
import { lstat, open, realpath } from 'node:fs/promises';
import { isAbsolute, relative, resolve, sep } from 'node:path';
import { sql } from 'drizzle-orm';
import { keccak256 } from 'viem';
import { readOnlyToolResponseMatches } from './bef-task-executor.js';
import type { OwnerDatabase } from './db.js';
import { TaskActionCommandSchema, TaskFinishAnswerSchemas } from './task-action-service.js';
import type { TaskActionCommand } from './task-action-service.js';
import type { PersistedTaskObservations, TaskEvidenceBinding } from './task-evaluator.js';
import {
  canonicalTaskJson, sha256CanonicalTaskJson, type EvidenceReference, type TaskCase,
  type TaskReleaseQuerySource,
} from './task-release.js';
import type { TaskObservationBundleCandidate } from './task-observation-store.js';
import { m1PreparationHealthMatches, parseM1PreparationEvidence } from './bef-m1-observation-collector.js';
import {
  projectS3PacketObservations, validateS3CapturePacket,
  type S3CapturePacket,
} from './task-s3-capture-packet.js';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const HASH = /^[0-9a-f]{64}$/i;
const ADDRESS = /^0x[0-9a-f]{40}$/i;
const HEX_WORD = /^0x[0-9a-f]{64}$/i;
const SECRET_KEYS = new Set([
  'privatekey', 'privkey', 'seedphrase', 'mnemonic', 'secret', 'clientsecret', 'bearer', 'bearertoken',
  'accesstoken', 'refreshtoken', 'providertoken', 'paymenttoken', 'token', 'apitoken', 'apikey',
  'authorization', 'walletmaterial', 'walletsecret', 'signature', 'signedpayload',
]);
const EVIDENCE_BOUNDARY = 'actual_tool_http_x402_local_evm_application_store' as const;
const ACTION_ROOT = 'artifacts/runs/owner-identity-bef-task-coordinator/action/';
const PREPARATION_ROOT = 'artifacts/runs/owner-identity-bef-task-coordinator/preparation/';
const OBSERVATION_ROOT = 'artifacts/runs/owner-identity-bef-task-coordinator/observation/';
const MAX_ACTIONS = 256;
const MAX_BLOCKS = 256;
const MAX_ROWS = 2048;
const MAX_EVIDENCE_BYTES = 256 * 1024;
const MAX_RPC_BYTES = 4 * 1024 * 1024;
const MAX_CAPTURE_BYTES = 8 * 1024 * 1024;
const TRANSFER_TOPIC = '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef';
const APPROVAL_TOPIC = '0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925';
const BALANCE_OF_SELECTOR = '0x70a08231';
const ALLOWANCE_SELECTOR = '0xdd62ed3e';

type JsonRecord = Record<string, unknown>;
type OwnerTx = Parameters<Parameters<OwnerDatabase['transaction']>[0]>[0];
type ReadQuery = (statement: string, parameters?: readonly unknown[]) => Promise<unknown>;
type Row = Record<string, unknown>;

export interface BefS3ReadOnlyPostgresPort {
  environmentId: string;
  /** Executes the callback in a fresh REPEATABLE READ, READ ONLY transaction. */
  withRepeatableRead<T>(callback: (query: ReadQuery) => Promise<T>): Promise<T>;
}

export interface BefS3ReadOnlyRpcPort {
  environmentId: string;
  request(method: string, params: readonly unknown[]): Promise<unknown>;
}

export interface BefS3ObservationEvidenceSink {
  write(packet: BefS3RunObservationPacket): Promise<EvidenceReference>;
}

export interface BefS3ObservationCollectorDependencies {
  db: OwnerDatabase;
  taskReleaseSource: TaskReleaseQuerySource;
  repositoryRoot: string;
  postgresByEnvironment: Readonly<Record<string, BefS3ReadOnlyPostgresPort>>;
  rpcByEnvironment: Readonly<Record<string, BefS3ReadOnlyRpcPort>>;
  evidenceSink: BefS3ObservationEvidenceSink;
}

export type BefS3UnavailableCode =
  | 'invalid_target' | 'unsupported_task' | 'owner_cutoff_unavailable' | 'owner_cutoff_mismatch'
  | 'reconciliation_pending' | 'action_evidence_unavailable' | 'preparation_unavailable'
  | 'release_binding_mismatch' | 'source_not_configured' | 'observer_role_invalid'
  | 'observer_census_unavailable' | 'observer_census_changed' | 'rpc_identity_mismatch'
  | 'rpc_observation_unavailable' | 'rpc_interval_too_large' | 'rpc_mapping_incomplete'
  | 'baseline_mismatch' | 'state_effect_detected' | 'capture_evidence_unavailable';

export type BefS3CollectionResult =
  | { status: 'unavailable'; reasonCode: BefS3UnavailableCode }
  | {
    status: 'candidate'; candidate: TaskObservationBundleCandidate; evidence: EvidenceReference;
    classification: 'run_bound_observations_candidate_not_grade';
  };

type SessionProjection = {
  currentUser: 'bef_observer'; sessionUser: 'bef_observer'; databaseName: string;
  transactionReadOnly: 'on'; superuser: false; bypassRls: false;
};

type Census = {
  generation: JsonRecord;
  operations: JsonRecord[];
  selectedExecutions: JsonRecord[];
  selectedEvents: JsonRecord[];
  payments: JsonRecord[];
  deliveries: JsonRecord[];
  costs: JsonRecord[];
  denials: JsonRecord[];
  x402Observations: JsonRecord[];
  rpcObservations: JsonRecord[];
  evidenceArtifacts: JsonRecord[];
};

type RpcCheckpoint = {
  blockNumber: string; blockHash: string; parentHash: string;
  balances: Array<{ account: string; assetId: string; amountUnits: string }>;
  allowances: Array<{ owner: string; tokenAssetId: string; spender: string; amountUnits: string }>;
  participantTransactionCount: string;
};

type RpcBlock = { number: string; hash: string; parentHash: string; transactionCount: number; transactions: Array<{
  hash: string; from: string; to: string | null; nonce: string; valueWei: string; blockNumber: string; blockHash: string; inputSha256: string;
}> };

export type BefS3RunObservationPacket = S3CapturePacket;

type RunRow = {
  owner_id: string; agent_id: string; mode: 'training' | 'ranked'; run_status: string; task_status: string; task_ids: unknown;
  release_identity: string; manifest_hash: string; task_id: string; closure_status: string;
  closure_id: string | null; closure_operation_id: string | null; closure_payload_hash: string | null;
  closure_reason: string | null; action_cutoff_sequence: string | number | null;
  reconciled_action_sequence: string | number;
};

type ClosureRow = {
  id: string; operation_id: string | null; payload_hash: string; reason: string;
  action_cutoff_sequence: string | number; owner_id: string; agent_id: string;
  answer_json: unknown;
};

type PreparationRow = {
  preparation_id: string; claim_id: string; lease_id: string; environment_id: string;
  release_identity: string; manifest_hash: string; task_id: string; case_id: string; case_hash: string;
  initial_state_sha256: string; execution_identity_hash: string; environment_manifest_sha256: string;
  application_source_hash: string; created_at: Date | string; lease_state: string; observation_status: string;
  generation_id: string | null; participant_id: string | null; payer_address: string | null;
  baseline_state_sha256: string | null; fixture_evidence: unknown; baseline_evidence: unknown;
};

type ActionRow = {
  id: string; run_id: string; task_index: number; owner_id: string; agent_id: string; task_id: string;
  environment_id: string; action_sequence: string | number; operation_id: string; payload_hash: string;
  action_kind: string; command_json: unknown; receipt_revision: number; receipt_status: string;
  evidence_hash: string | null; evidence_path: string | null; transaction_hash: string | null;
  history_revision: number | null; history_status: string | null; history_evidence_hash: string | null;
  history_evidence_path: string | null; history_transaction_hash: string | null;
};

type LoadedAction = {
  row: ActionRow; sequence: number; command: TaskActionCommand; evidence: JsonRecord; reference: EvidenceReference;
  body: JsonRecord | null; befOperationId: string | null; receiptStatus: 'observed' | 'rejected_before_execution'; reasonCode: string | null;
};

class Unavailable extends Error {
  constructor(readonly reasonCode: BefS3UnavailableCode) { super(reasonCode); }
}

function unavailable(reasonCode: BefS3UnavailableCode): BefS3CollectionResult { return { status: 'unavailable', reasonCode }; }
function isRecord(value: unknown): value is JsonRecord {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value) &&
    (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null));
}
function parseJson(value: unknown, reasonCode: BefS3UnavailableCode = 'owner_cutoff_mismatch'): unknown {
  if (typeof value !== 'string') return value;
  try { return JSON.parse(value) as unknown; } catch { throw new Unavailable(reasonCode); }
}
function rows<T extends Row>(value: unknown, reasonCode: BefS3UnavailableCode = 'owner_cutoff_unavailable'): T[] {
  if (Array.isArray(value)) return value as T[];
  if (isRecord(value) && Array.isArray(value.rows)) return value.rows as T[];
  throw new Unavailable(reasonCode);
}
async function ownerRows<T extends Row>(tx: OwnerTx, statement: ReturnType<typeof sql>): Promise<T[]> {
  return rows<T>(await tx.execute(statement));
}
function sequence(value: unknown): number | null {
  try {
    if (value === null || value === undefined) return null;
    const number = BigInt(value as string | number | bigint);
    return number >= 0n && number <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(number) : null;
  } catch { return null; }
}
function decimal(value: unknown): bigint | null {
  if (typeof value !== 'string' && typeof value !== 'number' && typeof value !== 'bigint') return null;
  try { const parsed = BigInt(value); return parsed >= 0n ? parsed : null; } catch { return null; }
}
function hexUint(value: unknown): bigint | null {
  if (typeof value !== 'string' || !/^0x(?:0|[1-9a-f][0-9a-f]*)$/i.test(value)) return null;
  try { return BigInt(value); } catch { return null; }
}
function hash(value: unknown): string { return createHash('sha256').update(canonicalTaskJson(value)).digest('hex'); }
function normalizeHash(value: unknown): string | null { return typeof value === 'string' && /^0x[0-9a-f]{64}$/i.test(value) ? value.toLowerCase() : null; }
function normalizeAddress(value: unknown): string | null { return typeof value === 'string' && ADDRESS.test(value) ? value.toLowerCase() : null; }
function asDate(value: unknown): string | null {
  const date = value instanceof Date ? value : typeof value === 'string' ? new Date(value) : null;
  return date && Number.isFinite(date.getTime()) ? date.toISOString() : null;
}

function hasSecretKey(value: unknown, seen = new Set<object>()): boolean {
  if (value === null || typeof value !== 'object') return false;
  if (seen.has(value)) return true;
  seen.add(value);
  const found = Array.isArray(value) ? value.some((item) => hasSecretKey(item, seen)) :
    Object.entries(value as JsonRecord).some(([key, item]) => SECRET_KEYS.has(key.toLowerCase().replace(/[^a-z]/g, '')) || hasSecretKey(item, seen));
  seen.delete(value);
  return found;
}

function evidenceReference(value: unknown): EvidenceReference | null {
  if (!isRecord(value) || Object.keys(value).sort().join(',') !== 'boundary,path,sha256' || value.boundary !== EVIDENCE_BOUNDARY ||
      typeof value.path !== 'string' || typeof value.sha256 !== 'string' || !HASH.test(value.sha256) || value.path.includes('\\') ||
      !/^(?![A-Za-z]:)(?!\/)(?!.*(?:^|\/)\.\.(?:\/|$))[A-Za-z0-9._/-]{1,512}$/.test(value.path)) return null;
  return { path: value.path, sha256: value.sha256.toLowerCase(), boundary: EVIDENCE_BOUNDARY };
}

async function readEvidence(repositoryRoot: string, ref: EvidenceReference, prefix: string,
  reasonCode: BefS3UnavailableCode): Promise<Buffer> {
  if (!ref.path.startsWith(prefix) || ref.path.includes('\\') || ref.path.includes('\0') || isAbsolute(ref.path) ||
      ref.path.split('/').some((part) => !part || part === '.' || part === '..')) throw new Unavailable(reasonCode);
  const root = await realpath(repositoryRoot).catch(() => { throw new Unavailable(reasonCode); });
  const candidate = resolve(root, ...ref.path.split('/'));
  const actual = await realpath(candidate).catch(() => { throw new Unavailable(reasonCode); });
  const rel = relative(root, actual);
  if (!rel || rel === '..' || rel.startsWith(`..${sep}`) || isAbsolute(rel) ||
      !rel.split(sep).join('/').startsWith(prefix)) throw new Unavailable(reasonCode);
  const handle = await open(actual, 'r').catch(() => { throw new Unavailable(reasonCode); });
  try {
    const before = await handle.stat({ bigint: true });
    const pathBefore = await lstat(actual, { bigint: true });
    if (!before.isFile() || !pathBefore.isFile() || before.dev !== pathBefore.dev || before.ino !== pathBefore.ino ||
        before.size < 1n || before.size > BigInt(MAX_EVIDENCE_BYTES)) throw new Unavailable(reasonCode);
    const buffer = Buffer.alloc(MAX_EVIDENCE_BYTES + 1);
    let total = 0;
    while (total < buffer.length) {
      const read = await handle.read(buffer, total, buffer.length - total, null);
      if (read.bytesRead === 0) break;
      total += read.bytesRead;
    }
    const after = await handle.stat({ bigint: true });
    const pathAfter = await lstat(actual, { bigint: true });
    if (total < 1 || total > MAX_EVIDENCE_BYTES || !pathAfter.isFile() || before.dev !== after.dev || before.ino !== after.ino ||
        before.size !== after.size || before.mtimeNs !== after.mtimeNs || before.ctimeNs !== after.ctimeNs || after.size !== BigInt(total) ||
        pathAfter.dev !== after.dev || pathAfter.ino !== after.ino) throw new Unavailable(reasonCode);
    const bytes = buffer.subarray(0, total);
    if (createHash('sha256').update(bytes).digest('hex') !== ref.sha256) throw new Unavailable(reasonCode);
    return bytes;
  } catch (error) {
    if (error instanceof Unavailable) throw error;
    throw new Unavailable(reasonCode);
  } finally { await handle.close().catch(() => undefined); }
}

function parseSafeJson(bytes: Buffer, reason: BefS3UnavailableCode): JsonRecord {
  let value: unknown;
  try { value = JSON.parse(bytes.toString('utf8')) as unknown; } catch { throw new Unavailable(reason); }
  if (!isRecord(value) || hasSecretKey(value)) throw new Unavailable(reason);
  return value;
}

function exactPublicPins(prep: PreparationRow, runId: string, taskIndex: number): string {
  const createdAt = asDate(prep.created_at);
  if (!createdAt) throw new Unavailable('preparation_unavailable');
  return sha256CanonicalTaskJson({
    preparationId: prep.preparation_id, runId, taskIndex, claimId: prep.claim_id, leaseId: prep.lease_id,
    environmentId: prep.environment_id, releaseIdentity: prep.release_identity, manifestHash: prep.manifest_hash,
    taskId: prep.task_id, caseId: prep.case_id, caseHash: prep.case_hash,
    initialStateSha256: prep.initial_state_sha256, executionIdentityHash: prep.execution_identity_hash,
    environmentManifestSha256: prep.environment_manifest_sha256, applicationSourceHash: prep.application_source_hash, createdAt,
  }).toLowerCase();
}

type LoadedPreparationEvidence = { fixture: EvidenceReference; baseline: EvidenceReference; blockNumber: bigint; blockHash: string };
async function loadPreparationEvidence(root: string, prep: PreparationRow, runId: string, taskIndex: number,
  taskCase: Extract<TaskCase, { taskId: 'S3' }>): Promise<LoadedPreparationEvidence> {
  const fixture = evidenceReference(prep.fixture_evidence);
  const baseline = evidenceReference(prep.baseline_evidence);
  if (!fixture || !baseline || fixture.path === baseline.path || fixture.sha256 === baseline.sha256) throw new Unavailable('preparation_unavailable');
  const [fixtureBytes, baselineBytes] = await Promise.all([
    readEvidence(root, fixture, PREPARATION_ROOT, 'preparation_unavailable'),
    readEvidence(root, baseline, PREPARATION_ROOT, 'preparation_unavailable'),
  ]);
  const fixtureDoc = parseM1PreparationEvidence(fixtureBytes, 'fixture') as JsonRecord;
  const baselineDoc = parseM1PreparationEvidence(baselineBytes, 'baseline') as JsonRecord;
  const pins = exactPublicPins(prep, runId, taskIndex);
  for (const [document, kind] of [[fixtureDoc, 'fixture'], [baselineDoc, 'baseline']] as const) {
    if (document.schemaVersion !== 'owner-bef-task-preparation-evidence/v1' || document.kind !== kind ||
        document.preparationId !== prep.preparation_id || document.environmentId !== prep.environment_id ||
        document.publicPinsSha256 !== pins || !isRecord(document.evidence)) throw new Unavailable('preparation_unavailable');
  }
  const fixtureEvidence = fixtureDoc.evidence as JsonRecord;
  if (!m1PreparationHealthMatches(fixtureEvidence.environmentHealth, fixtureEvidence.publicStatus, {
    environmentId: prep.environment_id, preparationId: prep.preparation_id, generationId: prep.generation_id,
    environmentManifestHash: prep.environment_manifest_sha256, applicationSourceHash: prep.application_source_hash,
  })) throw new Unavailable('preparation_unavailable');
  const evidence = baselineDoc.evidence as JsonRecord;
  const state = evidence.state;
  const projection = state && isRecord(state) ? state.projection : null;
  const blockNumber = state && isRecord(state) ? hexUint(state.blockNumber) : null;
  const blockHash = state && isRecord(state) ? normalizeHash(state.blockHash) : null;
  const expectedProjection = stateProjection(taskCase.initialState);
  if (!isRecord(state) || state.sameBlock !== true || !isRecord(projection) || !Array.isArray(state.reads) ||
      evidence.stateSha256 !== taskCase.initialState.stateSha256.toLowerCase() ||
      evidence.expectedStateSha256 !== taskCase.initialState.stateSha256.toLowerCase() ||
      prep.baseline_state_sha256?.toLowerCase() !== taskCase.initialState.stateSha256.toLowerCase() ||
      blockNumber === null || blockHash === null || canonicalTaskJson(projection) !== canonicalTaskJson(expectedProjection) ||
      sha256CanonicalTaskJson(projection).toLowerCase() !== taskCase.initialState.stateSha256.toLowerCase()) {
    throw new Unavailable('baseline_mismatch');
  }
  return { fixture, baseline, blockNumber, blockHash };
}

function stateProjection(state: Extract<TaskCase, { taskId: 'S3' }>['initialState'] | RpcCheckpoint): JsonRecord {
  const balances = state.balances.map((item) => ({ ...item })).sort((a, b) =>
    `${a.account.toLowerCase()}|${a.assetId}`.localeCompare(`${b.account.toLowerCase()}|${b.assetId}`));
  const allowances = state.allowances.map((item) => ({ ...item })).sort((a, b) =>
    `${a.owner.toLowerCase()}|${a.tokenAssetId}|${a.spender.toLowerCase()}`.localeCompare(`${b.owner.toLowerCase()}|${b.tokenAssetId}|${b.spender.toLowerCase()}`));
  const deliveredComponentIds = 'deliveredComponentIds' in state ? [...state.deliveredComponentIds].sort() : [];
  const fulfilledObligationIds = 'fulfilledObligationIds' in state ? [...state.fulfilledObligationIds].sort() : [];
  return { balances, allowances, deliveredComponentIds, fulfilledObligationIds };
}

function actionReference(value: unknown): EvidenceReference | null { return evidenceReference(value); }
const ACTION_KEYS = new Set([
  'schema', 'actionId', 'runId', 'taskIndex', 'actionSequence', 'ownerOperationId', 'actionKind', 'commandSha256',
  'environmentId', 'generationId', 'manifestSha256', 'applicationSourceSha256', 'idempotencyKey', 'status',
  'reasonCode', 'requestStartedAt', 'requestFinishedAt', 'httpStatus', 'befOperationId', 'transactionHash',
  'outcome', 'receiptStatus', 'rawResponseSha256', 'participantToolResponse', 'receiptGasUsed',
  'receiptEffectiveGasPriceWei', 'paymentProtocol', 'environmentHealth',
]);

async function loadActions(root: string, run: RunRow, prep: PreparationRow, runId: string, taskIndex: number,
  cutoff: number, actionRows: ActionRow[], taskCase: Extract<TaskCase, { taskId: 'S3' }>,
  assetAddresses: ReadonlyMap<string, string>): Promise<LoadedAction[]> {
  if (cutoff > MAX_ACTIONS || actionRows.length !== cutoff) throw new Unavailable('owner_cutoff_mismatch');
  const loaded: LoadedAction[] = [];
  for (let index = 0; index < actionRows.length; index += 1) {
    const row = actionRows[index]!;
    const actionSequence = sequence(row.action_sequence);
    const ref = row.evidence_path && row.evidence_hash ? actionReference({
      path: row.evidence_path, sha256: row.evidence_hash.toLowerCase(), boundary: EVIDENCE_BOUNDARY,
    }) : null;
    if (actionSequence !== index + 1 || !UUID.test(row.id) || row.id !== row.id.toLowerCase() ||
        row.run_id !== runId || row.task_index !== taskIndex || row.owner_id !== run.owner_id || row.agent_id !== run.agent_id ||
        row.task_id !== 'S3' || row.environment_id !== prep.environment_id || row.action_kind !== 'inspect_catalog' ||
        !HASH.test(row.payload_hash) || !ref || !HASH.test(row.evidence_hash ?? '') ||
        row.history_revision !== row.receipt_revision || row.history_status !== row.receipt_status ||
        row.history_evidence_hash !== row.evidence_hash || row.history_evidence_path !== row.evidence_path ||
        (row.history_transaction_hash?.toLowerCase() ?? null) !== (row.transaction_hash?.toLowerCase() ?? null) ||
        !['observed', 'rejected_before_execution'].includes(row.receipt_status) || row.transaction_hash !== null) throw new Unavailable('action_evidence_unavailable');
    const parsedCommand = TaskActionCommandSchema.safeParse(parseJson(row.command_json, 'action_evidence_unavailable'));
    if (!parsedCommand.success || parsedCommand.data.kind !== 'inspect_catalog' || Object.keys(parsedCommand.data).length !== 1 ||
        sha256CanonicalTaskJson({ runId, taskIndex, command: parsedCommand.data }).toLowerCase() !== row.payload_hash.toLowerCase()) {
      throw new Unavailable('action_evidence_unavailable');
    }
    const evidence = parseSafeJson(await readEvidence(root, ref, ACTION_ROOT, 'action_evidence_unavailable'), 'action_evidence_unavailable');
    if (Object.keys(evidence).some((key) => !ACTION_KEYS.has(key)) || evidence.schema !== 'bef-task-action-observation-v1' ||
        evidence.actionId !== row.id || evidence.runId !== runId || evidence.taskIndex !== taskIndex ||
        evidence.actionSequence !== String(actionSequence) || evidence.ownerOperationId !== row.operation_id ||
        evidence.actionKind !== 'inspect_catalog' || evidence.commandSha256 !== row.payload_hash.toLowerCase() ||
        evidence.environmentId !== prep.environment_id || evidence.generationId !== prep.generation_id ||
        evidence.manifestSha256 !== prep.environment_manifest_sha256.toLowerCase() ||
        evidence.applicationSourceSha256 !== prep.application_source_hash.toLowerCase() ||
        evidence.idempotencyKey !== `task-action-${row.id}` || evidence.status !== row.receipt_status ||
        evidence.transactionHash !== undefined || evidence.receiptStatus !== undefined || evidence.outcome !== undefined) {
      throw new Unavailable('action_evidence_unavailable');
    }
    if (row.receipt_status === 'rejected_before_execution') {
      if (typeof evidence.reasonCode !== 'string' || !/^[a-z0-9_:-]{1,128}$/i.test(evidence.reasonCode) ||
          evidence.httpStatus !== undefined || evidence.requestStartedAt !== undefined || evidence.requestFinishedAt !== undefined ||
          evidence.rawResponseSha256 !== undefined || evidence.befOperationId !== undefined || evidence.participantToolResponse !== undefined ||
          evidence.paymentProtocol !== undefined) throw new Unavailable('action_evidence_unavailable');
      loaded.push({ row, sequence: actionSequence, command: parsedCommand.data, evidence, reference: ref, body: null,
        befOperationId: null, receiptStatus: 'rejected_before_execution', reasonCode: evidence.reasonCode });
      continue;
    }
    if (evidence.httpStatus !== 200 || typeof evidence.rawResponseSha256 !== 'string' || !HASH.test(evidence.rawResponseSha256) ||
        typeof evidence.befOperationId !== 'string' || !UUID.test(evidence.befOperationId) || !isRecord(evidence.participantToolResponse)) {
      throw new Unavailable('action_evidence_unavailable');
    }
    const body = evidence.participantToolResponse;
    if (!readOnlyToolResponseMatches(parsedCommand.data, body) || body.operationId !== evidence.befOperationId ||
        !validatePublicCatalog(taskCase, body, assetAddresses)) throw new Unavailable('action_evidence_unavailable');
    loaded.push({ row, sequence: actionSequence, command: parsedCommand.data, evidence, reference: ref, body,
      befOperationId: evidence.befOperationId, receiptStatus: 'observed', reasonCode: null });
  }
  return loaded;
}

function validatePublicCatalog(taskCase: Extract<TaskCase, { taskId: 'S3' }>, body: JsonRecord,
  assetAddresses: ReadonlyMap<string, string>): boolean {
  const handle = body.readHandle;
  if (Object.keys(body).sort().join(',') !== 'catalog,deliveryState,freeInspection,operationId,readHandle' ||
      typeof body.operationId !== 'string' || !UUID.test(body.operationId) || body.freeInspection !== true ||
      body.deliveryState !== 'not_delivered' || !isRecord(handle) || Object.keys(handle).sort().join(',') !== 'kind,operationId' ||
      handle.kind !== 'catalog' || handle.operationId !== body.operationId || !Array.isArray(body.catalog)) return false;
  const expected = new Map<string, typeof taskCase.objective.catalog>();
  for (const offer of taskCase.objective.catalog) expected.set(offer.resourceId, [...(expected.get(offer.resourceId) ?? []), offer]);
  if (body.catalog.length !== expected.size) return false;
  const seenResources = new Set<string>();
  for (const item of body.catalog) {
    if (!isRecord(item) || typeof item.resourceId !== 'string' || seenResources.has(item.resourceId) ||
        typeof item.resourceSha256 !== 'string' || !HASH.test(item.resourceSha256) || typeof item.contentType !== 'string' ||
        item.contentType.length < 1 || item.contentType.length > 128 || !Array.isArray(item.offers)) return false;
    const pinned = expected.get(item.resourceId);
    if (!pinned || item.offers.length !== pinned.length || item.dataType !== pinned[0]!.dataType) return false;
    const expectedOfferById = new Map(pinned.map((offer) => [offer.offerId, offer]));
    const seenOffers = new Set<string>();
    for (const candidate of item.offers) {
      if (!isRecord(candidate) || typeof candidate.id !== 'string' || seenOffers.has(candidate.id) || !isRecord(candidate.payment)) return false;
      const offer = expectedOfferById.get(candidate.id);
      const payment = candidate.payment;
      const assetAddress = offer ? assetAddresses.get(offer.assetId)?.toLowerCase() : null;
      const transferMethod = offer?.paymentRequirements.authFields.find((field) => field.name === 'assetTransferMethod')?.value;
      if (!offer || !assetAddress || !transferMethod || payment.scheme !== offer.paymentRequirements.scheme ||
          payment.network !== offer.paymentRequirements.network || payment.amount !== offer.paymentRequirements.amountUnits ||
          String(payment.asset).toLowerCase() !== assetAddress || String(payment.payTo).toLowerCase() !== offer.recipient.toLowerCase() ||
          payment.transferMethod !== transferMethod) return false;
      seenOffers.add(candidate.id);
    }
    if (seenOffers.size !== expectedOfferById.size) return false;
    seenResources.add(item.resourceId);
  }
  return seenResources.size === expected.size;
}

function pgRows(value: unknown): Row[] {
  if (Array.isArray(value)) return value as Row[];
  if (isRecord(value) && Array.isArray(value.rows)) return value.rows as Row[];
  if (isRecord(value) && Array.isArray(value.result)) return value.result as Row[];
  throw new Unavailable('observer_census_unavailable');
}

function safeValue(value: unknown): unknown {
  if (typeof value === 'bigint') return value.toString();
  if (value instanceof Date) return value.toISOString();
  if (Array.isArray(value)) return value.map(safeValue);
  if (isRecord(value)) return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, safeValue(item)]));
  return value;
}

function projection(row: Row, keys: readonly string[]): JsonRecord {
  const output: JsonRecord = {};
  for (const key of keys) output[key] = safeValue(row[key]);
  return output;
}

function validateSession(proof: Row, privileges: Row[]): SessionProjection {
  const required = [
    'bef_environment', 'bef_generation', 'bef_operation', 'bef_selected_execution', 'bef_selected_execution_event',
    'bef_payment', 'bef_delivery', 'bef_transaction_cost', 'bef_denial', 'bef_x402_observation',
    'bef_rpc_observation', 'bef_evidence_artifact',
  ];
  const byName = new Map(privileges.map((item) => [String(item.table_name), item]));
  if (proof.current_user !== 'bef_observer' || proof.session_user !== 'bef_observer' ||
      proof.transaction_read_only !== 'on' || proof.transaction_isolation !== 'repeatable read' ||
      proof.rolsuper !== false || proof.rolbypassrls !== false || proof.schema_create !== false || required.some((name) => {
        const item = byName.get(name);
        return !item || item.can_select !== true || item.can_insert !== false || item.can_update !== false ||
          item.can_delete !== false || item.can_truncate !== false;
      }) || typeof proof.database_name !== 'string' || proof.database_name.length < 1 || proof.database_name.length > 128) {
    throw new Unavailable('observer_role_invalid');
  }
  return { currentUser: 'bef_observer', sessionUser: 'bef_observer', databaseName: proof.database_name,
    transactionReadOnly: 'on', superuser: false, bypassRls: false };
}

async function captureCensus(port: BefS3ReadOnlyPostgresPort, environmentId: string, generationId: string,
  operationIds: string[]): Promise<{ session: SessionProjection; census: Census }> {
  if (port.environmentId !== environmentId) throw new Unavailable('source_not_configured');
  try {
    return await port.withRepeatableRead(async (query) => {
      const sessionRows = pgRows(await query(`SELECT current_user AS current_user, session_user AS session_user,
          current_database() AS database_name, current_setting('transaction_read_only') AS transaction_read_only,
          current_setting('transaction_isolation') AS transaction_isolation, r.rolsuper AS rolsuper,
          r.rolbypassrls AS rolbypassrls, has_schema_privilege(current_user,'public','CREATE') AS schema_create
        FROM pg_roles r WHERE r.rolname=current_user`));
      const privilegeRows = pgRows(await query(`SELECT table_name,
          has_table_privilege(current_user,'public.'||table_name,'SELECT') AS can_select,
          has_table_privilege(current_user,'public.'||table_name,'INSERT') AS can_insert,
          has_table_privilege(current_user,'public.'||table_name,'UPDATE') AS can_update,
          has_table_privilege(current_user,'public.'||table_name,'DELETE') AS can_delete,
          has_table_privilege(current_user,'public.'||table_name,'TRUNCATE') AS can_truncate
        FROM unnest(ARRAY['bef_environment','bef_generation','bef_operation','bef_selected_execution','bef_selected_execution_event',
          'bef_payment','bef_delivery','bef_transaction_cost','bef_denial','bef_x402_observation','bef_rpc_observation',
          'bef_evidence_artifact']) AS table_name`));
      if (sessionRows.length !== 1) throw new Unavailable('observer_role_invalid');
      const session = validateSession(sessionRows[0]!, privilegeRows);
      const generationRows = pgRows(await query(`SELECT g.generation_id::text,g.env_id,g.participant_id,g.payer_address,
          trim(g.manifest_sha256) AS manifest_sha256,g.status,g.resource_variant,g.fixture_transaction_hash,
          g.fixture_block_hash,g.fixture_token_delta_units::text,g.fixture_native_balance_wei::text,g.expires_at::text,
          g.fenced_at::text,e.chain_id::text,e.node_identity,trim(e.manifest_sha256) AS environment_manifest_sha256
        FROM public.bef_generation g JOIN public.bef_environment e ON e.env_id=g.env_id
        WHERE g.env_id=$1 AND g.generation_id=$2::uuid`, [environmentId, generationId]));
      if (generationRows.length !== 1) throw new Unavailable('observer_census_unavailable');
      const operationRows = pgRows(await query(`SELECT operation_id::text,env_id,generation_id::text,participant_id,
          idempotency_key_sha256,trim(request_sha256) AS request_sha256,operation_kind,status,receipt_status,transaction_hash,
          trim(response_sha256) AS response_sha256,started_at::text,completed_at::text
        FROM public.bef_operation WHERE env_id=$1 AND generation_id=$2::uuid ORDER BY started_at,operation_id LIMIT ${MAX_ROWS + 1}`,
      [environmentId, generationId]));
      const selectedRows = pgRows(await query(`SELECT operation_id::text,env_id,generation_id::text,action_kind,transaction_hash,outcome
        FROM public.bef_selected_execution WHERE env_id=$1 AND generation_id=$2::uuid ORDER BY created_at,operation_id LIMIT ${MAX_ROWS + 1}`,
      [environmentId, generationId]));
      const selectedEventRows = pgRows(await query(`SELECT event_sequence::text,event_id::text,operation_id::text,env_id,
          generation_id::text,event_kind,transaction_hash,created_at::text FROM public.bef_selected_execution_event
        WHERE env_id=$1 AND generation_id=$2::uuid ORDER BY event_sequence LIMIT ${MAX_ROWS + 1}`,
      [environmentId, generationId]));
      const paymentRows = pgRows(await query(`SELECT payment_id::text,operation_id::text,env_id,generation_id::text,payer_address,
          network,asset_address,amount_units::text,facilitator_address,transaction_hash,receipt_status,token_delta_units::text,
          observed_at::text FROM public.bef_payment WHERE env_id=$1 AND generation_id=$2::uuid ORDER BY observed_at,payment_id LIMIT ${MAX_ROWS + 1}`,
      [environmentId, generationId]));
      const deliveryRows = pgRows(await query(`SELECT d.delivery_id::text,d.operation_id::text,o.env_id,o.generation_id::text,
          d.resource_id,trim(d.content_sha256) AS content_sha256,d.content_bytes::text,d.delivered_at::text
        FROM public.bef_delivery d JOIN public.bef_operation o ON o.operation_id=d.operation_id
        WHERE o.env_id=$1 AND o.generation_id=$2::uuid ORDER BY d.delivered_at,d.delivery_id LIMIT ${MAX_ROWS + 1}`,
      [environmentId, generationId]));
      const costRows = pgRows(await query(`SELECT operation_id::text,env_id,generation_id::text,transaction_hash,payer_address,
          payer_role,receipt_status,gas_used::text,effective_gas_price_wei::text,gas_cost_wei::text,manifest_sha256,created_at::text
        FROM public.bef_transaction_cost WHERE env_id=$1 AND generation_id=$2::uuid ORDER BY transaction_hash LIMIT ${MAX_ROWS + 1}`,
      [environmentId, generationId]));
      const denialRows = pgRows(await query(`SELECT denial_id::text,env_id,generation_id::text,operation_id::text,route,reason_code,
          request_sha256,protected_state_sha256,created_at::text FROM public.bef_denial
        WHERE generation_id=$1::uuid ORDER BY created_at,denial_id LIMIT ${MAX_ROWS + 1}`, [generationId]));
      const x402Rows = pgRows(await query(`SELECT observation_id::text,env_id,generation_id::text,operation_id::text,
          variant_id,phase,request_sha256,response_sha256,outcome,transaction_hash,observed_at::text
        FROM public.bef_x402_observation WHERE generation_id=$1::uuid ORDER BY observed_at,observation_id LIMIT ${MAX_ROWS + 1}`,
      [generationId]));
      const rpcRows = pgRows(await query(`SELECT r.observation_id::text,r.operation_id::text,r.boundary,r.method,
          r.params_sha256,r.result_sha256,r.forwarded,r.response_status,r.source_block_hash,r.created_at::text
        FROM public.bef_rpc_observation r JOIN public.bef_operation o ON o.operation_id=r.operation_id
        WHERE o.env_id=$1 AND o.generation_id=$2::uuid ORDER BY r.created_at,r.observation_id LIMIT ${MAX_ROWS + 1}`,
      [environmentId, generationId]));
      const artifactRows = pgRows(await query(`SELECT artifact_id::text,operation_id::text,generation_id::text,relative_path,
          sha256,boundary,content_type,created_at::text FROM public.bef_evidence_artifact
        WHERE generation_id=$1::uuid OR operation_id=ANY($2::uuid[]) ORDER BY created_at,artifact_id LIMIT ${MAX_ROWS + 1}`,
      [generationId, operationIds]));
      const all = [operationRows, selectedRows, selectedEventRows, paymentRows, deliveryRows, costRows,
        denialRows, x402Rows, rpcRows, artifactRows];
      if (all.some((list) => list.length > MAX_ROWS)) throw new Unavailable('observer_census_unavailable');
      const census: Census = {
        generation: projection(generationRows[0]!, ['generation_id', 'env_id', 'participant_id', 'payer_address', 'manifest_sha256',
          'status', 'resource_variant', 'fixture_transaction_hash', 'fixture_block_hash', 'fixture_token_delta_units',
          'fixture_native_balance_wei', 'expires_at', 'fenced_at', 'chain_id', 'node_identity', 'environment_manifest_sha256']),
        operations: operationRows.map((row) => projection(row, ['operation_id', 'env_id', 'generation_id', 'participant_id',
          'idempotency_key_sha256', 'request_sha256', 'operation_kind', 'status', 'receipt_status', 'transaction_hash', 'response_sha256',
          'started_at', 'completed_at'])),
        selectedExecutions: selectedRows.map((row) => projection(row, ['operation_id', 'env_id', 'generation_id', 'action_kind', 'transaction_hash', 'outcome'])),
        selectedEvents: selectedEventRows.map((row) => projection(row, ['event_sequence', 'event_id', 'operation_id', 'env_id', 'generation_id', 'event_kind', 'transaction_hash', 'created_at'])),
        payments: paymentRows.map((row) => projection(row, ['payment_id', 'operation_id', 'env_id', 'generation_id', 'payer_address', 'network', 'asset_address', 'amount_units', 'facilitator_address', 'transaction_hash', 'receipt_status', 'token_delta_units', 'observed_at'])),
        deliveries: deliveryRows.map((row) => projection(row, ['delivery_id', 'operation_id', 'env_id', 'generation_id', 'resource_id', 'content_sha256', 'content_bytes', 'delivered_at'])),
        costs: costRows.map((row) => projection(row, ['operation_id', 'env_id', 'generation_id', 'transaction_hash', 'payer_address', 'payer_role', 'receipt_status', 'gas_used', 'effective_gas_price_wei', 'gas_cost_wei', 'manifest_sha256', 'created_at'])),
        denials: denialRows.map((row) => projection(row, ['denial_id', 'env_id', 'generation_id', 'operation_id', 'route', 'reason_code', 'request_sha256', 'protected_state_sha256', 'created_at'])),
        x402Observations: x402Rows.map((row) => projection(row, ['observation_id', 'env_id', 'generation_id', 'operation_id', 'variant_id', 'phase', 'request_sha256', 'response_sha256', 'outcome', 'transaction_hash', 'observed_at'])),
        rpcObservations: rpcRows.map((row) => projection(row, ['observation_id', 'operation_id', 'boundary', 'method', 'params_sha256', 'result_sha256', 'forwarded', 'response_status', 'source_block_hash', 'created_at'])),
        evidenceArtifacts: artifactRows.map((row) => projection(row, ['artifact_id', 'operation_id', 'generation_id', 'relative_path', 'sha256', 'boundary', 'content_type', 'created_at'])),
      };
      if (hasSecretKey(census) || Buffer.byteLength(canonicalTaskJson(census), 'utf8') > MAX_CAPTURE_BYTES) throw new Unavailable('observer_census_unavailable');
      return { session, census };
    });
  } catch (error) {
    if (error instanceof Unavailable) throw error;
    throw new Unavailable('observer_census_unavailable');
  }
}

class RpcRecorder {
  readonly responseHashes: Array<{ method: string; paramsSha256: string; resultSha256: string }> = [];
  constructor(private readonly port: BefS3ReadOnlyRpcPort) {}
  async request(method: string, params: readonly unknown[]): Promise<unknown> {
    if (!['eth_chainId', 'eth_blockNumber', 'eth_getBlockByNumber', 'eth_getBalance', 'eth_call', 'eth_getCode',
      'eth_getTransactionCount', 'eth_getLogs'].includes(method)) throw new Unavailable('rpc_observation_unavailable');
    let result: unknown;
    try { result = await this.port.request(method, params); } catch { throw new Unavailable('rpc_observation_unavailable'); }
    let size: number;
    try { size = Buffer.byteLength(canonicalTaskJson(result), 'utf8'); } catch { throw new Unavailable('rpc_observation_unavailable'); }
    if (size > MAX_RPC_BYTES) throw new Unavailable('rpc_observation_unavailable');
    this.responseHashes.push({ method, paramsSha256: sha256CanonicalTaskJson(params), resultSha256: sha256CanonicalTaskJson(result) });
    return result;
  }
}

function blockHeader(value: unknown, expectedNumber?: bigint): { number: bigint; hash: string; parentHash: string; transactions?: unknown[] } {
  if (!isRecord(value)) throw new Unavailable('rpc_observation_unavailable');
  const number = hexUint(value.number), blockHash = normalizeHash(value.hash), parentHash = normalizeHash(value.parentHash);
  if (number === null || !blockHash || !parentHash || (expectedNumber !== undefined && number !== expectedNumber)) throw new Unavailable('rpc_observation_unavailable');
  if (value.transactions !== undefined && (!Array.isArray(value.transactions) || value.transactions.length > 10000)) throw new Unavailable('rpc_observation_unavailable');
  return { number, hash: blockHash, parentHash, ...(Array.isArray(value.transactions) ? { transactions: value.transactions } : {}) };
}
function addressRef(value: string, participant: string): string {
  const resolved = value === 'participant' ? participant : normalizeAddress(value);
  if (!resolved) throw new Unavailable('release_binding_mismatch');
  return resolved;
}
function wordAddress(value: string): string { return value.slice(2).padStart(64, '0'); }
function encodeBalanceOf(account: string): string { return `${BALANCE_OF_SELECTOR}${wordAddress(account)}`; }
function encodeAllowance(owner: string, spender: string): string { return `${ALLOWANCE_SELECTOR}${wordAddress(owner)}${wordAddress(spender)}`; }
function paddedAddressTopic(account: string): string { return `0x${wordAddress(account)}`; }

async function verifyCode(rpc: RpcRecorder, identity: {
  localChainId: number;
  assets: Array<{ assetId: string; kind: string; chainId: number; address: string | null; codeHash: string | null }>;
  contracts: Array<{ address: string; codeHash: string }>;
}, blockNumber: bigint): Promise<void> {
  const expected = new Map<string, string>();
  for (const asset of identity.assets) {
    if (asset.kind !== 'erc20') continue;
    const address = normalizeAddress(asset.address);
    if (!address || !asset.codeHash || !HASH.test(asset.codeHash) || asset.chainId !== identity.localChainId) throw new Unavailable('rpc_identity_mismatch');
    expected.set(address, asset.codeHash.toLowerCase());
  }
  for (const item of identity.contracts) {
    const address = normalizeAddress(item.address);
    if (!address || !HASH.test(item.codeHash)) throw new Unavailable('rpc_identity_mismatch');
    if (expected.has(address) && expected.get(address) !== item.codeHash.toLowerCase()) throw new Unavailable('rpc_identity_mismatch');
    expected.set(address, item.codeHash.toLowerCase());
  }
  const tag = `0x${blockNumber.toString(16)}`;
  for (const [address, expectedHash] of expected) {
    const code = await rpc.request('eth_getCode', [address, tag]);
    if (typeof code !== 'string' || !/^0x(?:[0-9a-f]{2})+$/i.test(code) || keccak256(code as `0x${string}`).slice(2).toLowerCase() !== expectedHash) {
      throw new Unavailable('rpc_identity_mismatch');
    }
  }
}

async function readCheckpoint(rpc: RpcRecorder, identity: {
  localChainId: number; assets: Array<{ assetId: string; kind: string; chainId: number; address: string | null; codeHash: string | null }>;
  contracts: Array<{ address: string; codeHash: string }>;
}, taskCase: Extract<TaskCase, { taskId: 'S3' }>, participant: string, block: bigint): Promise<RpcCheckpoint> {
  const tag = `0x${block.toString(16)}`;
  const header = blockHeader(await rpc.request('eth_getBlockByNumber', [tag, false]), block);
  const assets = new Map(identity.assets.map((asset) => [asset.assetId, asset]));
  const balances: RpcCheckpoint['balances'] = [];
  for (const item of taskCase.initialState.balances) {
    const account = addressRef(item.account, participant);
    const asset = assets.get(item.assetId);
    if (!asset || asset.chainId !== identity.localChainId) throw new Unavailable('release_binding_mismatch');
    let value: bigint | null;
    if (asset.kind === 'native' && asset.address === null) value = hexUint(await rpc.request('eth_getBalance', [account, tag]));
    else if (asset.kind === 'erc20' && normalizeAddress(asset.address)) {
      const result = await rpc.request('eth_call', [{ to: asset.address, data: encodeBalanceOf(account) }, tag]);
      value = typeof result === 'string' && HEX_WORD.test(result) ? BigInt(result) : null;
    } else throw new Unavailable('release_binding_mismatch');
    if (value === null) throw new Unavailable('rpc_observation_unavailable');
    balances.push({ account: item.account, assetId: item.assetId, amountUnits: value.toString() });
  }
  const pinnedContracts = new Set(identity.contracts.map((item) => item.address.toLowerCase()));
  const allowances: RpcCheckpoint['allowances'] = [];
  for (const item of taskCase.initialState.allowances) {
    const asset = assets.get(item.tokenAssetId);
    const owner = addressRef(item.owner, participant), spender = normalizeAddress(item.spender);
    if (!asset || asset.kind !== 'erc20' || !normalizeAddress(asset.address) || !spender || !pinnedContracts.has(spender)) {
      throw new Unavailable('release_binding_mismatch');
    }
    const result = await rpc.request('eth_call', [{ to: asset.address, data: encodeAllowance(owner, spender) }, tag]);
    if (typeof result !== 'string' || !HEX_WORD.test(result)) throw new Unavailable('rpc_observation_unavailable');
    allowances.push({ owner: item.owner, tokenAssetId: item.tokenAssetId, spender: item.spender, amountUnits: BigInt(result).toString() });
  }
  return {
    blockNumber: block.toString(), blockHash: header.hash, parentHash: header.parentHash,
    balances: balances.sort((a, b) => `${a.account.toLowerCase()}|${a.assetId}`.localeCompare(`${b.account.toLowerCase()}|${b.assetId}`)),
    allowances: allowances.sort((a, b) => `${a.owner.toLowerCase()}|${a.tokenAssetId}|${a.spender.toLowerCase()}`
      .localeCompare(`${b.owner.toLowerCase()}|${b.tokenAssetId}|${b.spender.toLowerCase()}`)), participantTransactionCount: '0',
  };
}

type RpcInterval = { blocks: RpcBlock[]; trackedTokenAddresses: string[]; participantLogQueries: Array<{ address: string; fromBlock: string; toBlock: string;
  topics: Array<string | null>; logCount: number }>; participantLogQueryCount: number };
async function readNoEffectInterval(rpc: RpcRecorder, identity: {
  assets: Array<{ assetId: string; kind: string; chainId: number; address: string | null; codeHash: string | null }>;
}, baseline: RpcCheckpoint, final: RpcCheckpoint, participant: string): Promise<RpcInterval> {
  const from = BigInt(baseline.blockNumber), to = BigInt(final.blockNumber);
  if (to < from || to - from > BigInt(MAX_BLOCKS)) throw new Unavailable('rpc_interval_too_large');
  const blocks: RpcBlock[] = [];
  const participantLogQueries: RpcInterval['participantLogQueries'] = [];
  let previousHash = baseline.blockHash;
  for (let number = from + 1n; number <= to; number += 1n) {
    const raw = await rpc.request('eth_getBlockByNumber', [`0x${number.toString(16)}`, true]);
    const header = blockHeader(raw, number);
    if (header.parentHash !== previousHash || !header.transactions) throw new Unavailable('rpc_mapping_incomplete');
    const transactions: RpcBlock['transactions'] = [];
    for (const transaction of header.transactions) {
      if (!isRecord(transaction) || !normalizeHash(transaction.hash) || !normalizeAddress(transaction.from) ||
          (transaction.to !== null && !normalizeAddress(transaction.to)) || typeof transaction.input !== 'string' ||
          !/^0x(?:[0-9a-f]{2})*$/i.test(transaction.input) || hexUint(transaction.nonce) === null ||
          hexUint(transaction.value) === null || hexUint(transaction.blockNumber) !== number ||
          normalizeHash(transaction.blockHash) !== header.hash) throw new Unavailable('rpc_observation_unavailable');
      if (normalizeAddress(transaction.from) === participant) throw new Unavailable('state_effect_detected');
      transactions.push({ hash: String(transaction.hash).toLowerCase(), from: normalizeAddress(transaction.from)!,
        to: transaction.to === null ? null : normalizeAddress(transaction.to), nonce: hexUint(transaction.nonce)!.toString(),
        valueWei: hexUint(transaction.value)!.toString(), blockNumber: number.toString(), blockHash: header.hash,
        inputSha256: createHash('sha256').update(transaction.input.toLowerCase()).digest('hex') });
    }
    blocks.push({ number: number.toString(), hash: header.hash, parentHash: header.parentHash, transactionCount: header.transactions.length, transactions });
    previousHash = header.hash;
  }
  if (to > from && previousHash !== final.blockHash) throw new Unavailable('rpc_mapping_incomplete');
  const tokenAddresses = [...new Set(identity.assets.filter((asset) => asset.kind === 'erc20')
    .map((asset) => normalizeAddress(asset.address)).filter((item): item is string => item !== null))];
  let participantLogQueryCount = 0;
  if (to > from) {
    for (const address of tokenAddresses) {
      const participantTopic = paddedAddressTopic(participant);
      const topicsToCheck = [
        [TRANSFER_TOPIC, participantTopic],
        [TRANSFER_TOPIC, null, participantTopic],
        [APPROVAL_TOPIC, participantTopic],
      ] as const;
      for (const topics of topicsToCheck) {
        const fromBlock = `0x${(from + 1n).toString(16)}`, toBlock = `0x${to.toString(16)}`;
        const logs = await rpc.request('eth_getLogs', [{ address, fromBlock, toBlock, topics }]);
        participantLogQueryCount += 1;
        if (!Array.isArray(logs) || logs.length > MAX_ROWS) throw new Unavailable('rpc_observation_unavailable');
        if (logs.length) throw new Unavailable('state_effect_detected');
        participantLogQueries.push({ address, fromBlock, toBlock, topics: [...topics], logCount: logs.length });
      }
    }
  }
  return { blocks, trackedTokenAddresses: tokenAddresses, participantLogQueries, participantLogQueryCount: participantLogQueries.length };
}

function assertNoEffects(census: Census, actions: LoadedAction[], environmentId: string, generationId: string,
  participantId: string, participantAddress: string, caseAsset: string): void {
  const generation = census.generation;
  if (generation.env_id !== environmentId || generation.generation_id !== generationId || generation.participant_id !== participantId ||
      String(generation.payer_address).toLowerCase() !== participantAddress || generation.status !== 'active' ||
      generation.resource_variant !== 'canonical' || generation.manifest_sha256 !== caseAsset || generation.fenced_at !== null) {
    throw new Unavailable('rpc_mapping_incomplete');
  }
  if (census.operations.length !== actions.filter((action) => action.receiptStatus === 'observed').length || census.selectedExecutions.length || census.selectedEvents.length ||
      census.payments.length || census.deliveries.length || census.costs.length || census.denials.length ||
      census.x402Observations.length || census.rpcObservations.length || census.evidenceArtifacts.length) {
    throw new Unavailable('state_effect_detected');
  }
}

function expectedRequestHash(): string {
  return createHash('sha256').update(JSON.stringify({ method: 'GET', path: '/catalog' })).digest('hex');
}
function expectedResponseHash(body: JsonRecord): string {
  const response: JsonRecord = { operationId: body.operationId, readHandle: body.readHandle, catalog: body.catalog,
    freeInspection: body.freeInspection, deliveryState: body.deliveryState };
  return createHash('sha256').update(Buffer.from(JSON.stringify(response))).digest('hex');
}
function operationForAction(census: Census, actions: LoadedAction[], environmentId: string, generationId: string,
  participantId: string): void {
  const operationsById = new Map(census.operations.map((item) => [String(item.operation_id).toLowerCase(), item]));
  const consumed = new Set<string>();
  for (const action of actions) {
    const expectedIdempotency = createHash('sha256').update(`task-action-${action.row.id}`).digest('hex');
    if (action.receiptStatus === 'rejected_before_execution') {
      if (census.operations.some((op) => String(op.idempotency_key_sha256).toLowerCase() === expectedIdempotency)) {
        throw new Unavailable('rpc_mapping_incomplete');
      }
      continue;
    }
    const id = String(action.befOperationId).toLowerCase();
    const operation = operationsById.get(id);
    if (!operation || consumed.has(id) || operation.env_id !== environmentId || operation.generation_id !== generationId ||
        operation.participant_id !== participantId || String(operation.idempotency_key_sha256).toLowerCase() !== expectedIdempotency ||
        String(operation.request_sha256).toLowerCase() !== expectedRequestHash() ||
        operation.operation_kind !== 'catalog' || operation.status !== 'accepted' || operation.receipt_status !== 'not_submitted' ||
        operation.transaction_hash !== null || !action.body ||
        String(operation.response_sha256).toLowerCase() !== expectedResponseHash(action.body) ||
        String(operation.response_sha256).toLowerCase() !== String(action.evidence.rawResponseSha256).toLowerCase()) {
      throw new Unavailable('rpc_mapping_incomplete');
    }
    consumed.add(id);
  }
  if (consumed.size !== census.operations.length) throw new Unavailable('rpc_mapping_incomplete');
}

function parseAnswer(row: ClosureRow, runId: string, taskIndex: number): JsonRecord | null {
  const answer = parseJson(row.answer_json, 'owner_cutoff_mismatch');
  if (row.reason === 'agent_finish') {
    if (row.operation_id === null) throw new Unavailable('owner_cutoff_mismatch');
    if (answer !== null) {
      const parsed = TaskFinishAnswerSchemas.S3.safeParse(answer);
      if (!parsed.success || !isRecord(parsed.data)) throw new Unavailable('owner_cutoff_mismatch');
    }
    const expected = sha256CanonicalTaskJson({ action: 'task_finish', runId, taskIndex, answer: answer ?? null }).toLowerCase();
    if (expected !== row.payload_hash.toLowerCase()) throw new Unavailable('owner_cutoff_mismatch');
    return answer === null ? null : answer as JsonRecord;
  }
  if (!['task_deadline', 'run_deadline'].includes(row.reason) || row.operation_id !== null || answer !== null ||
      sha256CanonicalTaskJson({ runId, taskIndex, reason: row.reason }).toLowerCase() !== row.payload_hash.toLowerCase()) {
    throw new Unavailable('owner_cutoff_mismatch');
  }
  return null;
}

async function collectLocked(deps: BefS3ObservationCollectorDependencies, target: { runId: string; taskIndex: number },
  tx: OwnerTx): Promise<BefS3CollectionResult> {
  await tx.execute(sql`SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY`);
  const owner = (await ownerRows<{ owner_id: string; agent_id: string }>(tx,
    sql`SELECT owner_id,agent_id FROM oid_benchmark_run WHERE id=${target.runId}`))[0];
  if (!owner) return unavailable('owner_cutoff_unavailable');
  const run = (await ownerRows<RunRow>(tx, sql`SELECT r.owner_id,r.agent_id,r.mode,r.status AS run_status,r.task_ids,r.release_identity,r.manifest_hash,
      t.status AS task_status,
      t.task_id,t.closure_status,t.closure_id,t.closure_operation_id,t.closure_payload_hash,t.closure_reason,
      t.action_cutoff_sequence::text AS action_cutoff_sequence,t.reconciled_action_sequence::text AS reconciled_action_sequence
    FROM oid_benchmark_run r JOIN oid_run_task t ON t.run_id=r.id
    WHERE r.id=${target.runId} AND r.owner_id=${owner.owner_id} AND r.agent_id=${owner.agent_id} AND t.task_index=${target.taskIndex}`))[0];
  const taskIds = Array.isArray(run?.task_ids) ? run.task_ids : parseJson(run?.task_ids, 'owner_cutoff_unavailable');
  if (!run || run.mode !== 'ranked' || run.run_status !== 'running' || run.task_status !== 'active' || run.task_id !== 'S3' ||
      !Array.isArray(taskIds) || taskIds[target.taskIndex] !== 'S3') {
    return unavailable(run ? 'unsupported_task' : 'owner_cutoff_unavailable');
  }
  if (run.closure_status !== 'closed' || !run.closure_id || run.action_cutoff_sequence === null) return unavailable('owner_cutoff_unavailable');
  const cutoff = sequence(run.action_cutoff_sequence), reconciled = sequence(run.reconciled_action_sequence);
  if (cutoff === null || reconciled === null || reconciled < cutoff) return unavailable('reconciliation_pending');
  const closure = (await ownerRows<ClosureRow>(tx, sql`SELECT id,operation_id,payload_hash,reason,
      action_cutoff_sequence::text AS action_cutoff_sequence,owner_id,agent_id,answer_json
    FROM oid_run_task_closure WHERE id=${run.closure_id} AND run_id=${target.runId} AND task_index=${target.taskIndex}`))[0];
  if (!closure || closure.id !== run.closure_id || closure.owner_id !== run.owner_id || closure.agent_id !== run.agent_id ||
      sequence(closure.action_cutoff_sequence) !== cutoff || closure.operation_id !== run.closure_operation_id ||
      closure.payload_hash !== run.closure_payload_hash || closure.reason !== run.closure_reason) return unavailable('owner_cutoff_mismatch');
  let answer: JsonRecord | null;
  try { answer = parseAnswer(closure, target.runId, target.taskIndex); }
  catch (error) { return unavailable(error instanceof Unavailable ? error.reasonCode : 'owner_cutoff_mismatch'); }

  const prep = (await ownerRows<PreparationRow>(tx, sql`SELECT i.preparation_id::text,i.claim_id::text,i.lease_id::text,i.environment_id,
      i.release_identity,i.manifest_hash,i.task_id,i.case_id,i.case_hash,i.initial_state_sha256,i.execution_identity_hash,
      i.environment_manifest_sha256,i.application_source_hash,i.created_at,l.state AS lease_state,o.status AS observation_status,
      o.generation_id::text,o.participant_id,o.payer_address,o.baseline_state_sha256,o.fixture_evidence,o.baseline_evidence
    FROM oid_task_preparation_intent i JOIN oid_task_environment_lease l ON l.preparation_id=i.preparation_id AND l.lease_id=i.lease_id
    JOIN LATERAL (SELECT status,generation_id,participant_id,payer_address,baseline_state_sha256,fixture_evidence,baseline_evidence
      FROM oid_task_preparation_observation WHERE preparation_id=i.preparation_id ORDER BY revision DESC LIMIT 1) o ON true
    WHERE i.run_id=${target.runId} AND i.task_index=${target.taskIndex}`))[0];
  if (!prep || prep.lease_state !== 'leased' || prep.observation_status !== 'ready' || !prep.generation_id ||
      !prep.participant_id || !normalizeAddress(prep.payer_address) || prep.task_id !== 'S3' ||
      prep.release_identity !== run.release_identity || prep.manifest_hash !== run.manifest_hash ||
      prep.baseline_state_sha256 !== prep.initial_state_sha256) return unavailable('preparation_unavailable');
  const execution = (await ownerRows<{ env_id: string; generation_id: string; manifest_hash: string; application_source_hash: string;
    participant_id: string | null; payer_address: string | null }>(tx, sql`SELECT env_id,generation_id::text,manifest_hash,application_source_hash,participant_id,payer_address
    FROM oid_task_execution_binding WHERE run_id=${target.runId} AND task_index=${target.taskIndex}`))[0];
  const payerAddress = normalizeAddress(prep.payer_address);
  if (!payerAddress || !execution || execution.env_id !== prep.environment_id || execution.generation_id !== prep.generation_id ||
      execution.manifest_hash !== prep.environment_manifest_sha256 || execution.application_source_hash !== prep.application_source_hash ||
      execution.participant_id !== prep.participant_id || normalizeAddress(execution.payer_address) !== payerAddress) return unavailable('preparation_unavailable');
  const release = await deps.taskReleaseSource.getValidatedReleaseRecord(run.release_identity, run.manifest_hash, tx);
  if (!release || release.releaseIdentity !== run.release_identity || release.manifestHash !== run.manifest_hash ||
      release.manifest.releaseIdentity !== run.release_identity || release.manifest.manifestHash !== run.manifest_hash) return unavailable('release_binding_mismatch');
  const rawCase = release.manifest.cases.ranked.find((item) => item.taskId === 'S3');
  if (!rawCase || rawCase.taskId !== 'S3' || rawCase.mode !== 'ranked' || rawCase.caseId !== prep.case_id || rawCase.caseHash !== prep.case_hash ||
      rawCase.executionIdentityHash !== prep.execution_identity_hash || rawCase.initialState.stateSha256 !== prep.initial_state_sha256) {
    return unavailable('release_binding_mismatch');
  }
  const taskCase = rawCase as Extract<TaskCase, { taskId: 'S3' }>;
  const binding: TaskEvidenceBinding = { ownerId: run.owner_id, agentId: run.agent_id, runId: target.runId,
    environmentId: prep.environment_id, releaseIdentity: run.release_identity, manifestHash: run.manifest_hash,
    caseId: taskCase.caseId, caseHash: taskCase.caseHash, rubricHash: taskCase.rubricHash, taskId: 'S3' };
  const assetAddresses = new Map(release.manifest.executionIdentity.assets.filter((item) => item.kind === 'erc20' && item.address)
    .map((item) => [item.assetId, normalizeAddress(item.address)] as const).filter((item): item is readonly [string, string] => Boolean(item[1])));
  if (taskCase.mode !== 'ranked' || taskCase.objective.catalog.some((offer) => !assetAddresses.has(offer.assetId)) ||
      release.manifest.executionIdentity.environmentManifestSha256.toLowerCase() !== prep.environment_manifest_sha256.toLowerCase() ||
      release.manifest.executionIdentityHash !== prep.execution_identity_hash.toLowerCase()) return unavailable('release_binding_mismatch');
  const actionRows = await ownerRows<ActionRow>(tx, sql`SELECT a.id::text,a.run_id::text,a.task_index,a.owner_id::text,a.agent_id::text,a.task_id,
      a.environment_id,a.action_sequence::text,a.operation_id,a.payload_hash,a.action_kind,a.command_json,
      r.receipt_revision,r.receipt_status,r.evidence_hash,r.evidence_path,r.transaction_hash,
      h.revision AS history_revision,h.receipt_status AS history_status,h.evidence_hash AS history_evidence_hash,
      h.evidence_path AS history_evidence_path,h.transaction_hash AS history_transaction_hash
    FROM oid_run_task_action a JOIN oid_run_task_action_receipt r ON r.action_id=a.id
    LEFT JOIN LATERAL (SELECT revision,receipt_status,evidence_hash,evidence_path,transaction_hash
      FROM oid_run_task_action_reconciliation WHERE action_id=a.id ORDER BY revision DESC LIMIT 1) h ON true
    WHERE a.run_id=${target.runId} AND a.task_index=${target.taskIndex} ORDER BY a.action_sequence`);
  let actions: LoadedAction[];
  try { actions = await loadActions(deps.repositoryRoot, run, prep, target.runId, target.taskIndex, cutoff, actionRows, taskCase, assetAddresses); }
  catch (error) { return unavailable(error instanceof Unavailable ? error.reasonCode : 'action_evidence_unavailable'); }
  const postgres = deps.postgresByEnvironment[prep.environment_id];
  const rpcPort = deps.rpcByEnvironment[prep.environment_id];
  if (!postgres || !rpcPort || rpcPort.environmentId !== prep.environment_id) return unavailable('source_not_configured');
  let prepEvidence: LoadedPreparationEvidence;
  try { prepEvidence = await loadPreparationEvidence(deps.repositoryRoot, prep, target.runId, target.taskIndex, taskCase); }
  catch (error) { return unavailable(error instanceof Unavailable ? error.reasonCode : 'preparation_unavailable'); }
  const operationIds = actions.filter((action) => action.receiptStatus === 'observed')
    .map((action) => String(action.befOperationId).toLowerCase());
  let befBefore: Awaited<ReturnType<typeof captureCensus>>;
  try { befBefore = await captureCensus(postgres, prep.environment_id, prep.generation_id, operationIds); }
  catch (error) { return unavailable(error instanceof Unavailable ? error.reasonCode : 'observer_census_unavailable'); }
  const generation = befBefore.census.generation;
  const generationManifestHash = typeof generation.manifest_sha256 === 'string' ? generation.manifest_sha256.trim().toLowerCase() : null;
  const environmentManifestHash = typeof generation.environment_manifest_sha256 === 'string'
    ? generation.environment_manifest_sha256.trim().toLowerCase() : null;
  if (generation.env_id !== prep.environment_id || generation.generation_id !== prep.generation_id ||
      generation.participant_id !== prep.participant_id || normalizeAddress(generation.payer_address) !== payerAddress ||
      String(generation.chain_id) !== String(release.manifest.executionIdentity.localChainId) || generation.status !== 'active' ||
      generation.resource_variant !== 'canonical' || generationManifestHash !== prep.environment_manifest_sha256.toLowerCase() ||
      environmentManifestHash !== prep.environment_manifest_sha256.toLowerCase()) return unavailable('rpc_mapping_incomplete');
  try {
    assertNoEffects(befBefore.census, actions, prep.environment_id, prep.generation_id, prep.participant_id, payerAddress,
      prep.environment_manifest_sha256.toLowerCase());
    operationForAction(befBefore.census, actions, prep.environment_id, prep.generation_id, prep.participant_id);
  } catch (error) { return unavailable(error instanceof Unavailable ? error.reasonCode : 'rpc_mapping_incomplete'); }
  const rpc = new RpcRecorder(rpcPort);
  let localChainId: bigint, baseline: RpcCheckpoint, final: RpcCheckpoint, interval: RpcInterval;
  try {
    const chain = hexUint(await rpc.request('eth_chainId', []));
    if (chain === null || chain !== BigInt(release.manifest.executionIdentity.localChainId)) return unavailable('rpc_identity_mismatch');
    localChainId = chain;
    baseline = await readCheckpoint(rpc, release.manifest.executionIdentity, taskCase, payerAddress, prepEvidence.blockNumber);
    await verifyCode(rpc, release.manifest.executionIdentity, prepEvidence.blockNumber);
    if (baseline.blockHash !== prepEvidence.blockHash ||
        canonicalTaskJson(stateProjection(baseline)) !== canonicalTaskJson(stateProjection(taskCase.initialState)) ||
        sha256CanonicalTaskJson(stateProjection(baseline)).toLowerCase() !== taskCase.initialState.stateSha256.toLowerCase()) return unavailable('baseline_mismatch');
    const initialNonce = hexUint(await rpc.request('eth_getTransactionCount', [payerAddress, `0x${prepEvidence.blockNumber.toString(16)}`]));
    const head = hexUint(await rpc.request('eth_blockNumber', []));
    if (initialNonce === null || head === null || head < prepEvidence.blockNumber) return unavailable('rpc_observation_unavailable');
    final = await readCheckpoint(rpc, release.manifest.executionIdentity, taskCase, payerAddress, head);
    await verifyCode(rpc, release.manifest.executionIdentity, head);
    const finalNonce = hexUint(await rpc.request('eth_getTransactionCount', [payerAddress, `0x${head.toString(16)}`]));
    if (finalNonce === null) return unavailable('rpc_observation_unavailable');
    baseline.participantTransactionCount = initialNonce.toString();
    final.participantTransactionCount = finalNonce.toString();
    if (initialNonce !== finalNonce || canonicalTaskJson(stateProjection(baseline)) !== canonicalTaskJson(stateProjection(final))) {
      return unavailable('state_effect_detected');
    }
    if (canonicalTaskJson(stateProjection(final)) !== canonicalTaskJson(stateProjection(taskCase.initialState))) return unavailable('state_effect_detected');
    interval = await readNoEffectInterval(rpc, release.manifest.executionIdentity, baseline, final, payerAddress);
    const baselineAgain = blockHeader(await rpc.request('eth_getBlockByNumber', [`0x${prepEvidence.blockNumber.toString(16)}`, false]), prepEvidence.blockNumber);
    const finalAgain = blockHeader(await rpc.request('eth_getBlockByNumber', [`0x${head.toString(16)}`, false]), head);
    if (baselineAgain.hash !== baseline.blockHash || finalAgain.hash !== final.blockHash) return unavailable('rpc_mapping_incomplete');
  } catch (error) { return unavailable(error instanceof Unavailable ? error.reasonCode : 'rpc_observation_unavailable'); }
  let befAfter: Awaited<ReturnType<typeof captureCensus>>;
  try { befAfter = await captureCensus(postgres, prep.environment_id, prep.generation_id, operationIds); }
  catch (error) { return unavailable(error instanceof Unavailable ? error.reasonCode : 'observer_census_unavailable'); }
  if (canonicalTaskJson(befBefore.session) !== canonicalTaskJson(befAfter.session) ||
      canonicalTaskJson(befBefore.census) !== canonicalTaskJson(befAfter.census)) return unavailable('observer_census_changed');

  const packet: BefS3RunObservationPacket = {
    schemaVersion: 'bts-s3-run-observation-capture/v1', classification: 'run_bound_observations_candidate_not_grade', binding,
    taskCase,
    closure: { closureId: closure.id, actionCutoffSequence: cutoff, reconciledActionSequence: reconciled,
      taskIndex: target.taskIndex, reason: closure.reason as BefS3RunObservationPacket['closure']['reason'],
      operationId: closure.operation_id, payloadHash: closure.payload_hash.toLowerCase(), answer },
    execution: { preparationId: prep.preparation_id, leaseId: prep.lease_id, generationId: prep.generation_id,
      environmentId: prep.environment_id, environmentManifestHash: prep.environment_manifest_sha256.toLowerCase(),
      applicationSourceHash: prep.application_source_hash.toLowerCase(), executionIdentityHash: prep.execution_identity_hash.toLowerCase(),
      initialStateSha256: prep.initial_state_sha256.toLowerCase() },
    preparation: { fixtureEvidence: prepEvidence.fixture, baselineEvidence: prepEvidence.baseline,
      baselineBlockNumber: prepEvidence.blockNumber.toString(), baselineBlockHash: prepEvidence.blockHash },
    ownerActions: actions.map((action) => ({ actionId: action.row.id, actionSequence: action.sequence,
      ownerOperationId: action.row.operation_id, commandSha256: action.row.payload_hash.toLowerCase(), command: { kind: 'inspect_catalog' as const },
      receiptStatus: action.receiptStatus, reasonCode: action.reasonCode, actionEvidence: action.reference,
      befOperationId: action.befOperationId, response: action.body })),
    bef: { session: befBefore.session, before: befBefore.census, after: befAfter.census,
      censusSha256: sha256CanonicalTaskJson(befBefore.census).toLowerCase() },
    rpc: { localChainId: localChainId.toString(), participant: payerAddress, baseline, final, intervalBlocks: interval.blocks,
      trackedTokenAddresses: interval.trackedTokenAddresses,
      participantLogQueries: interval.participantLogQueries, responseHashes: rpc.responseHashes },
  };
  try { validateS3CapturePacket(packet); }
  catch { return unavailable('capture_evidence_unavailable'); }
  if (hasSecretKey(packet) || Buffer.byteLength(canonicalTaskJson(packet), 'utf8') > MAX_CAPTURE_BYTES) return unavailable('capture_evidence_unavailable');
  let captureEvidence: EvidenceReference | null;
  try { captureEvidence = evidenceReference(await deps.evidenceSink.write(packet)); }
  catch { return unavailable('capture_evidence_unavailable'); }
  if (!captureEvidence || !captureEvidence.path.startsWith(OBSERVATION_ROOT)) return unavailable('capture_evidence_unavailable');
  let observations: PersistedTaskObservations;
  try { observations = projectS3PacketObservations(packet, { binding, taskCase, captureEvidence }); }
  catch { return unavailable('capture_evidence_unavailable'); }
  const candidate: TaskObservationBundleCandidate = { schemaVersion: 'bts-task-observation-bundle-candidate/v1',
    observationCutoffSequence: observations.coveredThroughSequence, cutoffStatus: 'authoritative', cutoffEvidence: captureEvidence, observations };
  return { status: 'candidate', candidate, evidence: captureEvidence, classification: 'run_bound_observations_candidate_not_grade' };
}

/** Collects one closed S3 task while its exact environment lease remains active and leased. */
export async function collectBefS3TaskObservationCandidate(
  deps: BefS3ObservationCollectorDependencies, target: { runId: string; taskIndex: number },
): Promise<BefS3CollectionResult> {
  if (!UUID.test(target.runId) || !Number.isSafeInteger(target.taskIndex) || target.taskIndex < 0 || target.taskIndex > 11) return unavailable('invalid_target');
  try { return await deps.db.transaction(async (tx) => collectLocked(deps, target, tx)); }
  catch (error) { return unavailable(error instanceof Unavailable ? error.reasonCode : 'owner_cutoff_unavailable'); }
}
