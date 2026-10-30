/**
 * Private run-bound S4 observation collection. This module returns an unsealed
 * candidate only; it does not grade, publish, reset, or invoke participant tools.
 *
 * AICODE-NOTE: The owner S4 allowance fixture is pre-task setup, not a participant
 * action. It is admitted only by matching its preparation proof to the scoped BEF
 * operation and independent RPC receipt, then excluded from the task interval.
 */
import { createHash } from 'node:crypto';
import { lstat, open, realpath } from 'node:fs/promises';
import { isAbsolute, relative, resolve, sep } from 'node:path';
import { sql } from 'drizzle-orm';
import { keccak256 } from 'viem';
import { TaskActionCommandSchema } from './task-action-service.js';
import type { TaskActionCommand } from './task-action-service.js';
import type { OwnerDatabase } from './db.js';
import { readOnlyToolResponseMatches } from './bef-task-executor.js';
import { recoveredActionEvidenceIsOwnerBound, recoveredOwnerLineageJoinSql, recoveredOwnerLineageSelectSql,
  recoverySourceEvidenceMatchesFacts, type RecoveredOwnerLineageRow,
  type RecoverySourceFacts } from './bef-recovery-observation.js';
import type { RecoveryActionEvidence } from './beta-platform-recovery-source-evidence.js';
import type { PersistedTaskObservations, TaskEvidenceBinding } from './task-evaluator.js';
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
const SELECTOR_APPROVE = '0x095ea7b3';
const SELECTOR_TRANSFER = '0xa9059cbb';
const BALANCE_OF_SELECTOR = '0x70a08231';
const ALLOWANCE_SELECTOR = '0xdd62ed3e';
const APPROVAL_TOPIC = '0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925';
const TRANSFER_TOPIC = '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef';
const MAX_ACTIONS = 256;
const MAX_BLOCKS = 256;
const MAX_ROWS = 2048;
const MAX_EVIDENCE_BYTES = 256 * 1024;
const MAX_RPC_BYTES = 4 * 1024 * 1024;
const MAX_PACKET_BYTES = 8 * 1024 * 1024;
const EVIDENCE_BOUNDARY = 'actual_tool_http_x402_local_evm_application_store' as const;
const ACTION_ROOT = 'artifacts/runs/owner-identity-bef-task-coordinator/action/';
const PREPARATION_ROOT = 'artifacts/runs/owner-identity-bef-task-coordinator/preparation/';
const OBSERVATION_ROOT = 'artifacts/runs/owner-identity-bef-task-coordinator/observation/';
const SECRET_KEYS = new Set([
  'privatekey', 'privkey', 'seedphrase', 'mnemonic', 'secret', 'clientsecret', 'bearer', 'bearertoken',
  'accesstoken', 'refreshtoken', 'providertoken', 'paymenttoken', 'token', 'apitoken', 'apikey',
  'authorization', 'walletmaterial', 'walletsecret', 'signature', 'signedpayload',
]);

type JsonRecord = Record<string, unknown>;
type OwnerTx = Parameters<Parameters<OwnerDatabase['transaction']>[0]>[0];
type ReadQuery = (statement: string, parameters?: readonly unknown[]) => Promise<unknown>;
type QueryRows = Array<Record<string, unknown>>;

export interface BefS4ReadOnlyPostgresPort {
  environmentId: string;
  withRepeatableRead<T>(callback: (query: ReadQuery) => Promise<T>): Promise<T>;
}

export interface BefS4ReadOnlyRpcPort {
  environmentId: string;
  request(method: string, params: readonly unknown[]): Promise<unknown>;
}

export type BefS4RunObservationPacket = {
  schemaVersion: 'bts-s4-run-observation-capture/v1';
  classification: 'run_bound_observations_candidate_not_grade';
  binding: TaskEvidenceBinding;
  closure: { closureId: string; actionCutoffSequence: number; reconciledActionSequence: number };
  execution: {
    preparationId: string; leaseId: string; generationId: string; environmentId: string;
    environmentManifestHash: string; applicationSourceHash: string; executionIdentityHash: string; initialStateSha256: string;
  };
  preparation: {
    fixtureEvidence: EvidenceReference; baselineEvidence: EvidenceReference;
    baselineBlockNumber: string; baselineBlockHash: string;
    fixtureOperationId: string; fixtureTransactionHash: string; fixtureBlockNumber: string; fixtureBlockHash: string;
    fixtureProofSha256: string;
  };
  ownerActions: Array<{
    actionId: string; actionSequence: number; ownerOperationId: string; actionKind: string;
    commandSha256: string; actionEvidence: EvidenceReference; befOperationId: string; transactionHash: string | null;
  }>;
  bef: { session: JsonRecord; before: S4Census; after: S4Census; censusSha256: string };
  rpc: {
    localChainId: string;
    baseline: S4Checkpoint;
    final: S4Checkpoint;
    intervalBlocks: Array<{ number: string; hash: string; parentHash: string; transactionCount: number; participantTransactions: S4Transaction[] }>;
    approvals: S4ApprovalLog[];
    transfers: S4TransferLog[];
    receipts: S4Receipt[];
    responseHashes: Array<{ method: string; paramsSha256: string; resultSha256: string }>;
  };
};

export interface BefS4ObservationEvidenceSink {
  write(packet: BefS4RunObservationPacket): Promise<EvidenceReference>;
}

export interface BefS4ObservationCollectorDependencies {
  db: OwnerDatabase;
  taskReleaseSource: TaskReleaseQuerySource;
  repositoryRoot: string;
  postgresByEnvironment: Readonly<Record<string, BefS4ReadOnlyPostgresPort>>;
  rpcByEnvironment: Readonly<Record<string, BefS4ReadOnlyRpcPort>>;
  evidenceSink: BefS4ObservationEvidenceSink;
}

export type BefS4ObservationUnavailableCode =
  | 'invalid_target' | 'unsupported_task' | 'owner_cutoff_unavailable' | 'owner_cutoff_mismatch'
  | 'reconciliation_pending' | 'action_evidence_unavailable' | 'preparation_unavailable'
  | 'release_binding_mismatch' | 'source_not_configured' | 'observer_role_invalid'
  | 'observer_census_unavailable' | 'observer_census_changed' | 'rpc_identity_mismatch'
  | 'rpc_observation_unavailable' | 'rpc_interval_too_large' | 'rpc_mapping_incomplete'
  | 'baseline_mismatch' | 'capture_evidence_unavailable';

export type BefS4ObservationCollectionResult =
  | { status: 'unavailable'; reasonCode: BefS4ObservationUnavailableCode }
  | { status: 'candidate'; candidate: TaskObservationBundleCandidate; evidence: EvidenceReference;
      classification: 'run_bound_observations_candidate_not_grade' };

type Census = {
  generation: JsonRecord; operations: JsonRecord[]; selectedExecutions: JsonRecord[];
  selectedEvents: JsonRecord[]; costs: JsonRecord[]; paymentsCount: string; deliveriesCount: string; counts: JsonRecord;
};
type S4Census = Census;
type S4Checkpoint = {
  blockNumber: string; blockHash: string; parentHash: string; balances: Array<{ account: string; assetId: string; amountUnits: string }>;
  allowances: Array<{ owner: string; tokenAssetId: string; spender: string; amountUnits: string }>;
  participantTransactionCount: string;
};
type S4Transaction = {
  hash: string; from: string; to: string | null; nonce: string; input: string; valueWei: string;
  gasLimit: string; blockNumber: string; blockHash: string; transactionIndex: string; chainId: string;
};
type S4Receipt = {
  transactionHash: string; from: string; to: string | null; blockNumber: string; blockHash: string;
  transactionIndex: string; status: 'success' | 'reverted'; gasUsed: string; effectiveGasPriceWei: string;
  gasCostWei: string; logsSha256: string;
};
type S4ApprovalLog = {
  tokenAddress: string; owner: string; spender: string; amountUnits: string;
  transactionHash: string; blockNumber: string; blockHash: string; transactionIndex: string; logIndex: string;
};
type S4TransferLog = {
  tokenAddress: string; from: string; to: string; amountUnits: string;
  transactionHash: string; blockNumber: string; blockHash: string; transactionIndex: string; logIndex: string;
};
type EvidenceRef = EvidenceReference;
type RunTaskRow = {
  owner_id: string; agent_id: string; mode: 'training' | 'ranked'; task_ids: string[];
  release_identity: string; manifest_hash: string; task_id: string; closure_status: string;
  closure_id: string | null; closure_operation_id: string | null; closure_payload_hash: string | null;
  closure_reason: string | null; action_cutoff_sequence: string | number | null; reconciled_action_sequence: string | number;
};
type ClosureRow = { id: string; operation_id: string | null; payload_hash: string; reason: string;
  action_cutoff_sequence: string | number; owner_id: string; agent_id: string };
type PreparationRow = {
  preparation_id: string; claim_id: string; lease_id: string; environment_id: string; release_identity: string;
  manifest_hash: string; task_id: string; case_id: string; case_hash: string; initial_state_sha256: string;
  execution_identity_hash: string; environment_manifest_sha256: string; application_source_hash: string;
  created_at: Date | string; lease_state: string; observation_status: string; generation_id: string | null;
  participant_id: string | null; payer_address: string | null; baseline_state_sha256: string | null;
  fixture_evidence: unknown; baseline_evidence: unknown;
};
type ActionRow = {
  id: string; run_id: string; task_index: number; owner_id: string; agent_id: string; task_id: string;
  environment_id: string; action_sequence: string | number; operation_id: string; payload_hash: string;
  action_kind: string; command_json: unknown; receipt_revision: number; receipt_status: string;
  evidence_hash: string | null; evidence_path: string | null; transaction_hash: string | null;
  history_revision: number | null; history_status: string | null; history_evidence_hash: string | null;
  history_evidence_path: string | null; history_transaction_hash: string | null;
} & RecoveredOwnerLineageRow;
type MutableCommand = Extract<TaskActionCommand, { kind: 'approve' | 'transfer' }>;
type ReadCommand = Extract<TaskActionCommand, { kind: 'inspect_catalog' | 'inspect_offer' }>;
type LoadedMutableAction = { category: 'mutable'; row: ActionRow; sequence: number; command: MutableCommand;
  evidence: RecoveryActionEvidence; evidenceReference: EvidenceRef };
type LoadedReadAction = { category: 'read'; row: ActionRow; sequence: number; command: ReadCommand;
  evidence: JsonRecord; evidenceReference: EvidenceRef };
type LoadedAction = LoadedMutableAction | LoadedReadAction;
type FixtureProof = { operationId: string; transactionHash: string; blockNumber: bigint; blockHash: string; parentHash: string;
  amountUnits: bigint; spender: string; tokenAddress: string; idempotencyKeySha256: string; proofSha256: string; reference: EvidenceRef;
  baselineReference: EvidenceRef; baselineNumber: bigint; baselineHash: string;
  preState: { blockNumber: bigint; blockHash: string; projection: JsonRecord } };
type TransferSource = { op: JsonRecord; selected: JsonRecord; action: LoadedMutableAction | null; tx: S4Transaction;
  receipt: S4Receipt; selectedAction: JsonRecord; actionSequence: number };

export type S4AllowanceHistoryInput = {
  participant: string;
  router: string;
  tokenAddresses: Readonly<Record<'USDC' | 'WETH', string>>;
  baseline: Array<{ owner: string; tokenAssetId: 'USDC' | 'WETH'; spender: string; amountUnits: string }>;
  transactions: Array<{ transactionHash: string; actionSequence: number; receiptStatus: 'success' | 'reverted';
    action: { kind: 'approve' | 'transfer'; tokenAssetId: 'USDC' | 'WETH'; tokenAddress: string; spender?: string; amountUnits?: string } }>;
  approvals: Array<{ tokenAddress: string; owner: string; spender: string; amountUnits: string; transactionHash: string }>;
};

/** Maps all observed post-baseline Approval logs to BEF-selected participant transactions. */
export function deriveS4AllowanceHistory(input: S4AllowanceHistoryInput): {
  changes: Array<{ owner: string; tokenAssetId: 'USDC' | 'WETH'; spender: string; amountBeforeUnits: string;
    amountAfterUnits: string; transactionHash: string; actionSequence: number }>;
  finalAmounts: Map<string, bigint>;
} {
  const participant=normalizeAddress(input.participant),router=normalizeAddress(input.router);
  if(!participant||!router)throw new Error('S4 allowance history has invalid identities');
  const tokenAddresses={USDC:normalizeAddress(input.tokenAddresses.USDC),WETH:normalizeAddress(input.tokenAddresses.WETH)};
  if(!tokenAddresses.USDC||!tokenAddresses.WETH)throw new Error('S4 allowance history has invalid token addresses');
  const amounts=new Map<string,bigint>();
  for(const item of input.baseline){
    const owner=item.owner==='participant'?participant:normalizeAddress(item.owner),spender=normalizeAddress(item.spender),value=decimal(item.amountUnits);
    if(!owner||!spender||value===null||!['USDC','WETH'].includes(item.tokenAssetId))throw new Error('S4 allowance history has invalid baseline');
    const key=allowanceKey(owner,item.tokenAssetId,spender);
    if(amounts.has(key))throw new Error('S4 allowance history has duplicate baseline');
    amounts.set(key,value);
  }
  const byHash=new Map<string,S4AllowanceHistoryInput['transactions'][number]>();
  for(const tx of input.transactions){
    const hash=normalizeHash(tx.transactionHash);
    if(!hash||byHash.has(hash)||!Number.isSafeInteger(tx.actionSequence)||tx.actionSequence<0||
        !['success','reverted'].includes(tx.receiptStatus))throw new Error('S4 allowance history has invalid transaction');
    byHash.set(hash,{...tx,transactionHash:hash});
  }
  const logsByHash=new Map<string,S4AllowanceHistoryInput['approvals']>();
  for(const log of input.approvals){
    const hash=normalizeHash(log.transactionHash),token=normalizeAddress(log.tokenAddress),owner=normalizeAddress(log.owner),spender=normalizeAddress(log.spender);
    if(!hash||!token||!owner||!spender||decimal(log.amountUnits)===null)throw new Error('S4 allowance history has invalid Approval log');
    const list=logsByHash.get(hash)??[];list.push({...log,transactionHash:hash,tokenAddress:token,owner,spender});logsByHash.set(hash,list);
  }
  for(const hash of logsByHash.keys())if(!byHash.has(hash))throw new Error('S4 Approval log has no participant transaction');
  const rows:Array<{owner:string;tokenAssetId:'USDC'|'WETH';spender:string;amountBeforeUnits:string;amountAfterUnits:string;transactionHash:string;actionSequence:number}> = [];
  const ordered=[...byHash.values()];
  for(const tx of ordered){
    const hash=normalizeHash(tx.transactionHash)!;
    const logs=logsByHash.get(hash)??[];
    if(tx.action.kind==='transfer'){
      if(logs.length)throw new Error('Transfer transaction unexpectedly emitted Approval');
      continue;
    }
    const token=tokenAddresses[tx.action.tokenAssetId],spender=router,expectedAmount=decimal(tx.action.amountUnits);
    if(tx.action.tokenAddress!==token||normalizeAddress(tx.action.spender??'')!==router||expectedAmount===null) {
      throw new Error('BEF approve action is outside the pinned S4 scope');
    }
    if(tx.receiptStatus==='reverted'){
      if(logs.length)throw new Error('Reverted approval emitted an Approval log');
      continue;
    }
    if(logs.length!==1||logs[0]!.owner!==participant||logs[0]!.tokenAddress!==token||logs[0]!.spender!==router||
        decimal(logs[0]!.amountUnits)!==expectedAmount)throw new Error('Successful approve action does not match its Approval log');
    const key=allowanceKey(participant,tx.action.tokenAssetId,router),before=amounts.get(key);
    if(before===undefined)throw new Error('S4 Approval log lacks a pinned baseline allowance');
    const after=expectedAmount;
    amounts.set(key,after);
    rows.push({owner:'participant',tokenAssetId:tx.action.tokenAssetId,spender:router,amountBeforeUnits:before.toString(),
      amountAfterUnits:after.toString(),transactionHash:hash,actionSequence:tx.actionSequence});
  }
  return {changes:rows,finalAmounts:amounts};
}

class CollectionUnavailable extends Error {
  constructor(readonly reasonCode: BefS4ObservationUnavailableCode) { super(reasonCode); }
}

function unavailable(reasonCode: BefS4ObservationUnavailableCode): BefS4ObservationCollectionResult { return { status: 'unavailable', reasonCode }; }
function isRecord(value: unknown): value is JsonRecord {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value) &&
    (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null));
}
function normalizeHash(value: unknown): string | null { return typeof value === 'string' && TX_HASH.test(value) ? value.toLowerCase() : null; }
function normalizeAddress(value: unknown): string | null { return typeof value === 'string' && ADDRESS.test(value) ? value.toLowerCase() : null; }
function decimal(value: unknown): bigint | null { return typeof value === 'string' && UINT.test(value) ? BigInt(value) : null; }
// AICODE-NOTE: Fixture evidence is parsed into bigint for arithmetic; this boundary also accepts its
// canonical decimal source string, but never coerces JS numbers or negative values.
function nonnegativeDecimal(value: unknown): bigint | null {
  if (typeof value === 'bigint') return value >= 0n ? value : null;
  return decimal(value);
}
function hexUint(value: unknown): bigint | null {
  if (typeof value !== 'string' || !HEX_QUANTITY.test(value)) return null;
  try { return BigInt(value); } catch { return null; }
}
function sequence(value: string | number | null | undefined): number | null {
  if (value === null || value === undefined) return null;
  try { const parsed = BigInt(value); return parsed >= 0n && parsed <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(parsed) : null; }
  catch { return null; }
}
function objectRows<T extends Record<string, unknown>>(value: unknown): T[] {
  if (!Array.isArray(value)) throw new CollectionUnavailable('owner_cutoff_unavailable');
  return value as T[];
}
async function ownerRows<T extends Record<string, unknown>>(tx: OwnerTx, statement: ReturnType<typeof sql>): Promise<T[]> {
  return objectRows<T>(await tx.execute(statement));
}
function sha256(value: Uint8Array | string): string { return createHash('sha256').update(value).digest('hex'); }
function hasSecret(value: unknown, allowedTokenPaths: readonly string[][] = [], path: string[] = [], seen = new Set<object>()): boolean {
  if (value === null || typeof value !== 'object') return false;
  if (seen.has(value)) return true;
  seen.add(value);
  const found = Array.isArray(value)
    ? value.some((item, index) => hasSecret(item, allowedTokenPaths, [...path, String(index)], seen))
    : Object.entries(value as JsonRecord).some(([key, item]) => {
      const normalized = key.toLowerCase().replace(/[^a-z]/g, '');
      const candidatePath = [...path, key];
      const publicToken = normalized === 'token' && allowedTokenPaths.some((allowed) =>
        allowed.length === candidatePath.length && allowed.every((part, index) => part === candidatePath[index])) && normalizeAddress(item) !== null;
      return (SECRET_KEYS.has(normalized) && !publicToken) || hasSecret(item, allowedTokenPaths, candidatePath, seen);
    });
  seen.delete(value);
  return found;
}
function readJson(bytes: Buffer, reason: BefS4ObservationUnavailableCode, allowedTokenPaths: readonly string[][] = []): JsonRecord {
  let parsed: unknown;
  try { parsed = JSON.parse(bytes.toString('utf8')) as unknown; } catch { throw new CollectionUnavailable(reason); }
  if (!isRecord(parsed) || hasSecret(parsed, allowedTokenPaths)) throw new CollectionUnavailable(reason);
  return parsed;
}
function parseJson(value: unknown): unknown {
  if (typeof value !== 'string') return value;
  try { return JSON.parse(value) as unknown; } catch { return null; }
}
function ref(value: unknown): EvidenceRef | null {
  if (!isRecord(value) || Object.keys(value).sort().join(',') !== 'boundary,path,sha256' ||
      value.boundary !== EVIDENCE_BOUNDARY || typeof value.path !== 'string' || typeof value.sha256 !== 'string' || !HASH.test(value.sha256)) return null;
  if (!/^(?![A-Za-z]:)(?!\/)(?!.*(?:^|\/)\.\.(?:\/|$))[A-Za-z0-9._/-]{1,512}$/.test(value.path) || value.path.includes('\\')) return null;
  return { path: value.path, sha256: value.sha256.toLowerCase(), boundary: EVIDENCE_BOUNDARY };
}
async function readEvidence(rootPath: string, reference: EvidenceRef, prefix: string,
  reason: BefS4ObservationUnavailableCode): Promise<Buffer> {
  if (!reference.path.startsWith(prefix) || reference.path.includes('\\') || reference.path.includes('\0') ||
      isAbsolute(reference.path) || reference.path.split('/').some((part) => !part || part === '.' || part === '..')) {
    throw new CollectionUnavailable(reason);
  }
  const root = await realpath(rootPath).catch(() => { throw new CollectionUnavailable(reason); });
  const file = resolve(root, ...reference.path.split('/'));
  const actual = await realpath(file).catch(() => { throw new CollectionUnavailable(reason); });
  const rel = relative(root, actual);
  const normalizedRel = rel.split(sep).join('/');
  if (!rel || rel === '..' || rel.startsWith(`..${sep}`) || isAbsolute(rel) || !normalizedRel.startsWith(prefix)) throw new CollectionUnavailable(reason);
  const handle = await open(actual, 'r').catch(() => { throw new CollectionUnavailable(reason); });
  let bytes: Buffer;
  try {
    const before = await handle.stat({ bigint: true });
    const pathBefore = await lstat(actual, { bigint: true });
    if (!before.isFile() || !pathBefore.isFile() || before.dev !== pathBefore.dev || before.ino !== pathBefore.ino ||
        before.size < 1n || before.size > BigInt(MAX_EVIDENCE_BYTES)) throw new CollectionUnavailable(reason);
    const bounded = Buffer.alloc(MAX_EVIDENCE_BYTES + 1);
    let total = 0;
    while (total < bounded.length) { const result = await handle.read(bounded, total, bounded.length - total, null); if (!result.bytesRead) break; total += result.bytesRead; }
    const after = await handle.stat({ bigint: true });
    const pathAfter = await lstat(actual, { bigint: true });
    if (total < 1 || total > MAX_EVIDENCE_BYTES || after.size !== BigInt(total) || before.size !== after.size ||
        before.mtimeNs !== after.mtimeNs || before.ctimeNs !== after.ctimeNs || before.dev !== after.dev || before.ino !== after.ino ||
        !pathAfter.isFile() || pathAfter.dev !== after.dev || pathAfter.ino !== after.ino) throw new CollectionUnavailable(reason);
    bytes = bounded.subarray(0, total);
  } catch (error) {
    if (error instanceof CollectionUnavailable) throw error;
    throw new CollectionUnavailable(reason);
  } finally { await handle.close().catch(() => undefined); }
  if (sha256(bytes) !== reference.sha256) throw new CollectionUnavailable(reason);
  return bytes;
}
function publicPins(preparation: PreparationRow, runId: string, taskIndex: number): string {
  const createdAt = preparation.created_at instanceof Date ? preparation.created_at.toISOString() : new Date(preparation.created_at).toISOString();
  if (!Number.isFinite(Date.parse(createdAt))) throw new CollectionUnavailable('preparation_unavailable');
  return sha256CanonicalTaskJson({
    preparationId: preparation.preparation_id, runId, taskIndex, claimId: preparation.claim_id, leaseId: preparation.lease_id,
    environmentId: preparation.environment_id, releaseIdentity: preparation.release_identity, manifestHash: preparation.manifest_hash,
    taskId: preparation.task_id, caseId: preparation.case_id, caseHash: preparation.case_hash,
    initialStateSha256: preparation.initial_state_sha256, executionIdentityHash: preparation.execution_identity_hash,
    environmentManifestSha256: preparation.environment_manifest_sha256, applicationSourceHash: preparation.application_source_hash, createdAt,
  }).toLowerCase();
}
function caseProjection(taskCase: Extract<TaskCase, { taskId: 'S4' }>): JsonRecord {
  return { balances: taskCase.initialState.balances, allowances: taskCase.initialState.allowances,
    deliveredComponentIds: taskCase.initialState.deliveredComponentIds, fulfilledObligationIds: taskCase.initialState.fulfilledObligationIds };
}
function s4CheckpointProjection(checkpoint: JsonRecord, taskCase: Extract<TaskCase, { taskId: 'S4' }>): JsonRecord | null {
  if (!Array.isArray(checkpoint.balances) || !Array.isArray(checkpoint.allowances)) return null;
  return { balances: checkpoint.balances, allowances: checkpoint.allowances,
    deliveredComponentIds: taskCase.initialState.deliveredComponentIds,
    fulfilledObligationIds: taskCase.initialState.fulfilledObligationIds };
}
/** Tests whether an independently read parent-block checkpoint matches the preparation artifact. */
export function s4FixtureParentCheckpointMatches(taskCase: Extract<TaskCase, { taskId: 'S4' }>,
  preStateValue: unknown, checkpointValue: unknown): boolean {
  if (!isRecord(preStateValue) || !isRecord(preStateValue.projection) || !isRecord(checkpointValue)) return false;
  // AICODE-NOTE: The evidence reader retains the producer's hex string while its internal FixtureProof
  // normalizes that same value to bigint. Accept those two explicit representations only.
  const expectedNumber = typeof preStateValue.blockNumber === 'bigint'
    ? (preStateValue.blockNumber >= 0n ? preStateValue.blockNumber : null)
    : hexUint(preStateValue.blockNumber);
  const expectedHash = normalizeHash(preStateValue.blockHash);
  const actualNumber = decimal(checkpointValue.blockNumber), actualHash = normalizeHash(checkpointValue.blockHash);
  const actualProjection = s4CheckpointProjection(checkpointValue, taskCase);
  return expectedNumber !== null && expectedHash !== null && actualNumber === expectedNumber && actualHash === expectedHash &&
    actualProjection !== null && sameCanonical(actualProjection, preStateValue.projection);
}
/** Tests the producer's post-fixture state tag and projection against the actual fixture block and pinned case. */
export function s4FixturePostStateMatchesBlock(taskCase: Extract<TaskCase, { taskId: 'S4' }>, postStateValue: unknown,
  fixtureBlockNumber: bigint, fixtureBlockHash: string): boolean {
  if (!isRecord(postStateValue) || !isRecord(postStateValue.projection)) return false;
  return hexUint(postStateValue.blockNumber) === fixtureBlockNumber && normalizeHash(postStateValue.blockHash) === fixtureBlockHash &&
    postStateValue.baselineSha256 === taskCase.initialState.stateSha256.toLowerCase() &&
    sha256CanonicalTaskJson(postStateValue.projection).toLowerCase() === taskCase.initialState.stateSha256.toLowerCase() &&
    sameCanonical(postStateValue.projection, caseProjection(taskCase));
}
export function s4FixtureTransitionMatches(taskCase: Extract<TaskCase, { taskId: 'S4' }>, payer: string,
  beforeValue: unknown, afterValue: unknown, gasCostWei: unknown): boolean {
  if (!isRecord(beforeValue) || !isRecord(afterValue) || !Array.isArray(beforeValue.balances) || !Array.isArray(afterValue.balances) ||
      !Array.isArray(beforeValue.allowances) || !Array.isArray(afterValue.allowances)) return false;
  const gasCost = nonnegativeDecimal(gasCostWei);
  const targetAmount = decimal(taskCase.objective.initialAllowanceUnits);
  if (gasCost === null || gasCost <= 0n || targetAmount === null || targetAmount <= 0n) return false;
  const balanceMap = (rows: unknown[]): Map<string,bigint> | null => {
    const result = new Map<string,bigint>();
    for (const row of rows) {
      if (!isRecord(row) || typeof row.account !== 'string' || typeof row.assetId !== 'string') return null;
      const amount = decimal(row.amountUnits), accountId = row.account === 'participant' ? payer : normalizeAddress(row.account);
      if (amount === null || !accountId) return null;
      const key = `${accountId}|${row.assetId}`;
      if (result.has(key)) return null;
      result.set(key, amount);
    }
    return result;
  };
  const allowanceMap = (rows: unknown[]): Map<string,bigint> | null => {
    const result = new Map<string,bigint>();
    for (const row of rows) {
      if (!isRecord(row) || typeof row.owner !== 'string' || typeof row.tokenAssetId !== 'string' || typeof row.spender !== 'string') return null;
      const amount = decimal(row.amountUnits), owner = row.owner === 'participant' ? payer : normalizeAddress(row.owner), spender = normalizeAddress(row.spender);
      if (amount === null || !owner || !spender) return null;
      const key = allowanceKey(owner,row.tokenAssetId,spender);
      if (result.has(key)) return null;
      result.set(key,amount);
    }
    return result;
  };
  const beforeBalances=balanceMap(beforeValue.balances),afterBalances=balanceMap(afterValue.balances);
  const beforeAllowances=allowanceMap(beforeValue.allowances),afterAllowances=allowanceMap(afterValue.allowances);
  if (!beforeBalances || !afterBalances || !beforeAllowances || !afterAllowances || beforeBalances.size!==afterBalances.size ||
      beforeAllowances.size!==afterAllowances.size) return false;
  const nativeKey=`${payer}|ETH`, beforeNative=beforeBalances.get(nativeKey),afterNative=afterBalances.get(nativeKey);
  if (beforeNative===undefined || afterNative===undefined || beforeNative-afterNative!==gasCost) return false;
  const targetKey=allowanceKey(payer,'USDC',taskCase.objective.spender),beforeTarget=beforeAllowances.get(targetKey),afterTarget=afterAllowances.get(targetKey);
  if (beforeTarget!==0n || afterTarget!==targetAmount) return false;
  for (const [key,value] of beforeBalances) {
    if (key===nativeKey) continue;
    if (afterBalances.get(key)!==value) return false;
  }
  for (const [key,value] of beforeAllowances) {
    if (key===targetKey) continue;
    if (afterAllowances.get(key)!==value) return false;
  }
  return true;
}
function allowanceKey(owner: string, tokenAssetId: string, spender: string): string {
  return `${owner.toLowerCase()}|${tokenAssetId}|${spender.toLowerCase()}`;
}
function normalizedCaseAccount(value: string, participant: string): string {
  const address = value === 'participant' ? participant : normalizeAddress(value);
  if (!address) throw new CollectionUnavailable('release_binding_mismatch');
  return address;
}
function codeWord(address: string): string { return address.slice(2).toLowerCase().padStart(64, '0'); }
function encodeBalance(account: string): string { return `${BALANCE_OF_SELECTOR}${codeWord(account)}`; }
function encodeAllowance(owner: string, spender: string): string { return `${ALLOWANCE_SELECTOR}${codeWord(owner)}${codeWord(spender)}`; }
function exactKeys(value: JsonRecord, expected: string[]): boolean { return Object.keys(value).sort().join(',') === [...expected].sort().join(','); }

function selectedAction(value: unknown, tokenAddresses: Readonly<Record<'USDC' | 'WETH', string>>, router: string): JsonRecord | null {
  if (!isRecord(value) || value.kind !== 'approve' || !exactKeys(value, ['kind', 'tokenAssetId', 'token', 'spender', 'amountUnits', 'gasLimit'])) return null;
  const asset = value.tokenAssetId;
  const token = asset === 'USDC' || asset === 'WETH' ? tokenAddresses[asset] : null;
  const tokenAddress = normalizeAddress(value.token);
  const spender = normalizeAddress(value.spender);
  const amount = decimal(value.amountUnits);
  const gas = decimal(value.gasLimit);
  if (!token || tokenAddress !== token || spender !== router || amount === null || gas === null || gas <= 0n) return null;
  return { kind: 'approve', tokenAssetId: asset, tokenAddress, spender, amountUnits: amount.toString(), gasLimit: gas.toString() };
}
function selectedTransfer(value: unknown, tokenAddresses: Readonly<Record<'USDC' | 'WETH', string>>): JsonRecord | null {
  if (!isRecord(value) || value.kind !== 'transfer' || !exactKeys(value, ['kind', 'token', 'amountUnits', 'recipient', 'gasLimit'])) return null;
  const token = normalizeAddress(value.token);
  const asset = Object.entries(tokenAddresses).find(([, address]) => address === token)?.[0];
  const recipient = normalizeAddress(value.recipient);
  const amount = decimal(value.amountUnits);
  const gas = decimal(value.gasLimit);
  if (!asset || !recipient || amount === null || gas === null || gas <= 0n) return null;
  return { kind: 'transfer', tokenAssetId: asset, tokenAddress: token, amountUnits: amount.toString(), recipient, gasLimit: gas.toString() };
}
function persistedSelectedAction(value: unknown, tokenAddresses: Readonly<Record<'USDC' | 'WETH', string>>, router: string): JsonRecord | null {
  if (!isRecord(value)) return null;
  if (value.kind === 'approve') {
    if (!exactKeys(value, ['kind', 'tokenAssetId', 'amountUnits', 'gasLimit']) ||
        (value.tokenAssetId !== 'USDC' && value.tokenAssetId !== 'WETH')) return null;
    const amount = decimal(value.amountUnits), gas = decimal(value.gasLimit);
    if (amount === null || gas === null || gas <= 0n) return null;
    return { kind: 'approve', tokenAssetId: value.tokenAssetId, tokenAddress: tokenAddresses[value.tokenAssetId],
      spender: router, amountUnits: amount.toString(), gasLimit: gas.toString() };
  }
  if (value.kind === 'transfer') {
    if (!exactKeys(value, ['kind', 'amountUnits', 'recipient', 'gasLimit'])) return null;
    const amount = decimal(value.amountUnits), gas = decimal(value.gasLimit), recipient = normalizeAddress(value.recipient);
    if (amount === null || gas === null || gas <= 0n || !recipient) return null;
    return { kind: 'transfer', tokenAssetId: 'USDC', tokenAddress: tokenAddresses.USDC,
      amountUnits: amount.toString(), recipient, gasLimit: gas.toString() };
  }
  return null;
}
function commandFromSelected(value: JsonRecord, taskCase: Extract<TaskCase, { taskId: 'S4' }>): Extract<TaskActionCommand, { kind: 'approve' | 'transfer' }> | null {
  if (value.kind === 'approve') {
    const parsed = TaskActionCommandSchema.safeParse({ kind: 'approve', tokenAssetId: value.tokenAssetId, amountUnits: value.amountUnits, gasLimit: value.gasLimit });
    return parsed.success && parsed.data.kind === 'approve' ? parsed.data : null;
  }
  if (value.kind === 'transfer') {
    const parsed = TaskActionCommandSchema.safeParse({ kind: 'transfer', amountUnits: value.amountUnits, recipient: value.recipient, gasLimit: value.gasLimit });
    return parsed.success && parsed.data.kind === 'transfer' ? parsed.data : null;
  }
  void taskCase;
  return null;
}
function snapshot(value: unknown): JsonRecord | null {
  if (!isRecord(value)) return null;
  const keys = ['blockNumber', 'payerNativeWei', 'payerWethUnits', 'payerUsdcUnits', 'recipientWethUnits', 'recipientUsdcUnits',
    'wethRouterAllowance', 'usdcRouterAllowance', 'poolWethUnits', 'poolUsdcUnits', 'poolLiquidity', 'poolSqrtPriceX96'];
  if (!exactKeys(value, keys) || keys.some((key) => typeof value[key] !== 'string' || !UINT.test(value[key] as string))) return null;
  return Object.fromEntries(keys.map((key) => [key, value[key]]));
}
function transactionIntent(value: unknown): JsonRecord | null {
  if (!isRecord(value)) return null;
  const keys = ['hash', 'type', 'chainId', 'blockHash', 'blockNumber', 'transactionIndex', 'from', 'to', 'nonce', 'input', 'valueWei', 'gasLimit', 'maxFeePerGasWei', 'maxPriorityFeePerGasWei'];
  if (!exactKeys(value, keys)) return null;
  const hash = normalizeHash(value.hash), from = normalizeAddress(value.from), to = value.to === null ? null : normalizeAddress(value.to);
  const blockNumber = value.blockNumber === null ? null : decimal(value.blockNumber);
  const transactionIndex = value.transactionIndex === null ? null : decimal(value.transactionIndex);
  if (!hash || value.type !== 'eip1559' || !Number.isSafeInteger(value.chainId) || !from || (value.to !== null && !to) ||
      (value.blockHash !== null && !normalizeHash(value.blockHash)) || (value.blockNumber !== null && blockNumber === null) ||
      (value.transactionIndex !== null && transactionIndex === null) || typeof value.nonce !== 'string' || !UINT.test(value.nonce) ||
      typeof value.input !== 'string' || !/^0x(?:[0-9a-f]{2})*$/i.test(value.input) || typeof value.valueWei !== 'string' || !UINT.test(value.valueWei) ||
      typeof value.gasLimit !== 'string' || !UINT.test(value.gasLimit)) return null;
  for (const key of ['maxFeePerGasWei', 'maxPriorityFeePerGasWei']) {
    if (value[key] !== null && (typeof value[key] !== 'string' || !UINT.test(value[key] as string))) return null;
  }
  return { hash, type: value.type, chainId: value.chainId, blockHash: value.blockHash === null ? null : normalizeHash(value.blockHash),
    blockNumber: blockNumber?.toString() ?? null,
    transactionIndex: transactionIndex?.toString() ?? null,
    from, to, nonce: value.nonce, input: value.input.toLowerCase(), valueWei: value.valueWei, gasLimit: value.gasLimit,
    maxFeePerGasWei: value.maxFeePerGasWei, maxPriorityFeePerGasWei: value.maxPriorityFeePerGasWei };
}
function matchesOriginalTransactionIntent(measured: JsonRecord, intent: JsonRecord): boolean {
  // AICODE-NOTE: The original transaction is bound before mining. Its null block
  // tags cannot equal the mined measurement; immutable transaction fields must.
  const fields=['hash','type','chainId','from','to','nonce','input','valueWei','gasLimit','maxFeePerGasWei','maxPriorityFeePerGasWei'];
  return fields.every((key)=>measured[key]===intent[key]) &&
    ['blockHash','blockNumber','transactionIndex'].every((key)=>intent[key]===null||measured[key]===intent[key]);
}
function safeReceipt(value: unknown): JsonRecord | null {
  if (!isRecord(value) || !Array.isArray(value.logs) || !exactKeys(value, ['transactionHash', 'from', 'to', 'status', 'blockHash', 'blockNumber', 'gasUsed', 'effectiveGasPrice', 'gasCostWei', 'logs'])) return null;
  const transactionHash = normalizeHash(value.transactionHash), from = normalizeAddress(value.from);
  const to = value.to === null ? null : normalizeAddress(value.to);
  const blockHash = normalizeHash(value.blockHash), blockNumber = decimal(value.blockNumber);
  const gasUsed = decimal(value.gasUsed), effectiveGasPrice = decimal(value.effectiveGasPrice), gasCostWei = decimal(value.gasCostWei);
  if (!transactionHash || !from || (value.to !== null && !to) || !blockHash || blockNumber === null || gasUsed === null || effectiveGasPrice === null || gasCostWei === null ||
      (value.status !== 'success' && value.status !== 'reverted') || gasUsed * effectiveGasPrice !== gasCostWei) return null;
  return { transactionHash, from, to, status: value.status, blockHash, blockNumber: blockNumber.toString(),
    gasUsed: gasUsed.toString(), effectiveGasPrice: effectiveGasPrice.toString(), gasCostWei: gasCostWei.toString(),
    logsSha256: sha256CanonicalTaskJson(value.logs).toLowerCase() };
}
function projectMeasurement(value: unknown, tokenAddresses: Readonly<Record<'USDC' | 'WETH', string>>, router: string): JsonRecord | null {
  const allowed = [['selectedAction', 'token'], ['selectedAction', 'spender']];
  if (!isRecord(value) || hasSecret(value, allowed) || !exactKeys(value, ['receipt', 'transaction', 'payerBlock', 'selectedAction', 'before', 'after', 'effects', 'quote', 'fee', 'taskEvaluationInputs'])) return null;
  const selected = selectedAction(value.selectedAction, tokenAddresses, router) ?? selectedTransfer(value.selectedAction, tokenAddresses);
  const transaction = transactionIntent(value.transaction);
  const receipt = safeReceipt(value.receipt);
  const before = snapshot(value.before), after = snapshot(value.after);
  if (!selected || !transaction || !receipt || !before || !after || !isRecord(value.payerBlock) || !isRecord(value.effects) ||
      (value.quote !== null && !isRecord(value.quote)) || !isRecord(value.fee) || !isRecord(value.taskEvaluationInputs)) return null;
  return { measurementSha256: sha256CanonicalTaskJson(value).toLowerCase(), selectedAction: selected, transaction, receipt, before, after };
}
function projectEvent(row: QueryRows[number], tokenAddresses: Readonly<Record<'USDC' | 'WETH', string>>, router: string): JsonRecord {
  const raw = parseJson(row.event_json);
  const eventKind = String(row.event_kind);
  if (!isRecord(raw) || hasSecret(raw, [['selectedAction', 'token'], ['selectedAction', 'spender'], ['measurement', 'selectedAction', 'token'], ['measurement', 'selectedAction', 'spender']])) {
    throw new CollectionUnavailable('observer_census_unavailable');
  }
  const eventSha256 = sha256CanonicalTaskJson(raw).toLowerCase();
  let payload: JsonRecord;
  if (eventKind === 'selected_action_bound') {
    if (!exactKeys(raw, ['actionKind', 'requestSha256', 'selectedAction']) || typeof raw.requestSha256 !== 'string' || !HASH.test(raw.requestSha256)) {
      throw new CollectionUnavailable('observer_census_unavailable');
    }
    const selected = persistedSelectedAction(raw.selectedAction, tokenAddresses, router);
    if (!selected) throw new CollectionUnavailable('observer_census_unavailable');
    payload = { actionKind: raw.actionKind, requestSha256: raw.requestSha256.toLowerCase(), selectedAction: selected };
  } else if (eventKind === 'prestate_observed') {
    if (Object.keys(raw).some((key) => !['prestate', 'idempotentReplay'].includes(key)) ||
        (raw.idempotentReplay !== undefined && raw.idempotentReplay !== true)) throw new CollectionUnavailable('observer_census_unavailable');
    const prestate = snapshot(raw.prestate);
    if (!prestate) throw new CollectionUnavailable('observer_census_unavailable');
    payload = { prestate, ...(raw.idempotentReplay === true ? { idempotentReplay: true } : {}) };
  } else if (eventKind === 'original_tx_hash_bound') {
    if (!exactKeys(raw, ['requestSha256', 'transactionHash', 'transactionIntent']) || typeof raw.requestSha256 !== 'string' || !HASH.test(raw.requestSha256)) {
      throw new CollectionUnavailable('observer_census_unavailable');
    }
    const transaction = transactionIntent(raw.transactionIntent), txHash = normalizeHash(raw.transactionHash);
    if (!transaction || !txHash) throw new CollectionUnavailable('observer_census_unavailable');
    payload = { requestSha256: raw.requestSha256.toLowerCase(), transactionHash: txHash, transactionIntent: transaction };
  } else if (eventKind === 'receipt_finalized') {
    if (!exactKeys(raw, ['measurement', 'outcome']) || (raw.outcome !== 'success' && raw.outcome !== 'reverted')) throw new CollectionUnavailable('observer_census_unavailable');
    const measurement = projectMeasurement(raw.measurement, tokenAddresses, router);
    if (!measurement) throw new CollectionUnavailable('observer_census_unavailable');
    payload = { outcome: raw.outcome, measurementSha256: measurement.measurementSha256 };
  } else {
    throw new CollectionUnavailable('rpc_mapping_incomplete');
  }
  return { eventId: String(row.event_id).toLowerCase(), eventSequence: String(row.event_sequence), operationId: String(row.operation_id).toLowerCase(),
    eventKind, transactionHash: row.transaction_hash === null ? null : normalizeHash(row.transaction_hash), eventJsonSha256: eventSha256, eventPayload: payload };
}

/** Projects the producer's compact JSON columns together with their full measurement records. */
export function projectS4SelectedExecutionRows(
  executionValues: readonly unknown[],
  eventValues: readonly unknown[],
  tokenAddresses: Readonly<Record<'USDC' | 'WETH', string>>,
  router: string,
): { selectedExecutions: JsonRecord[]; selectedEvents: JsonRecord[] } | null {
  const selectedExecutions: JsonRecord[] = [];
  for (const value of executionValues) {
    if (!isRecord(value)) return null;
    const compactAction = persistedSelectedAction(parseJson(value.selected_action_json), tokenAddresses, router);
    const prestate = value.prestate_json === null ? null : snapshot(parseJson(value.prestate_json));
    const intent = value.transaction_intent_json === null ? null : transactionIntent(parseJson(value.transaction_intent_json));
    const measurementRaw = parseJson(value.measurement_json);
    const measurement = measurementRaw === null ? null : projectMeasurement(measurementRaw, tokenAddresses, router);
    if (!compactAction || value.action_kind !== compactAction.kind ||
        (value.prestate_json !== null && !prestate) || (value.transaction_intent_json !== null && !intent) ||
        (value.measurement_json !== null && (!measurement || !sameCanonical(compactAction, measurement.selectedAction)))) return null;
    selectedExecutions.push({ operation_id: value.operation_id, env_id: value.env_id, generation_id: value.generation_id,
      action_kind: value.action_kind, selected_action: compactAction, prestate, transaction_intent: intent, measurement,
      transaction_hash: value.transaction_hash === null ? null : normalizeHash(value.transaction_hash), outcome: value.outcome,
      reason_code: value.reason_code, completed_at: value.completed_at });
  }
  const selectedEvents: JsonRecord[] = [];
  for (const value of eventValues) {
    if (!isRecord(value)) return null;
    selectedEvents.push(projectEvent(value, tokenAddresses, router));
  }
  return { selectedExecutions, selectedEvents };
}

function pgRows(value: unknown): QueryRows {
  const parsed = parseJson(value);
  if (!Array.isArray(parsed) || parsed.some((row) => !isRecord(row))) throw new CollectionUnavailable('observer_census_unavailable');
  return parsed as QueryRows;
}
function pgResultRows(value: unknown): QueryRows {
  if (Array.isArray(value)) return pgRows(value);
  if (isRecord(value) && Array.isArray(value.rows)) return pgRows(value.rows);
  if (isRecord(value) && Array.isArray(value.result)) return pgRows(value.result);
  throw new CollectionUnavailable('observer_census_unavailable');
}
async function captureCensus(port: BefS4ReadOnlyPostgresPort, envId: string, generationId: string,
  tokenAddresses: Readonly<Record<'USDC' | 'WETH', string>>, router: string): Promise<{ session: JsonRecord; census: Census }> {
  if (port.environmentId !== envId) throw new CollectionUnavailable('source_not_configured');
  try {
    return await port.withRepeatableRead(async (query) => {
      const sessions = pgResultRows(await query(`SELECT current_user AS current_user,session_user AS session_user,current_database() AS database_name,
          current_setting('transaction_read_only') AS transaction_read_only,current_setting('transaction_isolation') AS transaction_isolation,
          r.rolsuper AS rolsuper,r.rolbypassrls AS rolbypassrls,has_schema_privilege(current_user,'public','CREATE') AS schema_create
        FROM pg_roles r WHERE r.rolname=current_user`));
      const privileges = pgResultRows(await query(`SELECT table_name,
          has_table_privilege(current_user,'public.'||table_name,'SELECT') AS can_select,
          has_table_privilege(current_user,'public.'||table_name,'INSERT') AS can_insert,
          has_table_privilege(current_user,'public.'||table_name,'UPDATE') AS can_update,
          has_table_privilege(current_user,'public.'||table_name,'DELETE') AS can_delete,
          has_table_privilege(current_user,'public.'||table_name,'TRUNCATE') AS can_truncate
        FROM unnest(ARRAY['bef_generation','bef_operation','bef_selected_execution','bef_selected_execution_event','bef_payment','bef_delivery','bef_transaction_cost']) AS table_name`));
      if (sessions.length !== 1 || sessions[0]!.current_user !== 'bef_observer' || sessions[0]!.session_user !== 'bef_observer' ||
          sessions[0]!.transaction_read_only !== 'on' || sessions[0]!.transaction_isolation !== 'repeatable read' ||
          sessions[0]!.rolsuper !== false || sessions[0]!.rolbypassrls !== false || sessions[0]!.schema_create !== false ||
          privileges.length !== 7 || privileges.some((row) => row.can_select !== true || row.can_insert === true || row.can_update === true || row.can_delete === true || row.can_truncate === true)) {
        throw new CollectionUnavailable('observer_role_invalid');
      }
      const generationRows = pgResultRows(await query(`SELECT g.generation_id::text,g.env_id,g.participant_id,g.payer_address,
          trim(g.manifest_sha256) AS manifest_sha256,g.status,e.chain_id::text,trim(e.manifest_sha256) AS environment_manifest_sha256
        FROM public.bef_generation g JOIN public.bef_environment e ON e.env_id=g.env_id
        WHERE g.env_id=$1 AND g.generation_id=$2::uuid`, [envId, generationId]));
      const operationRows = pgResultRows(await query(`SELECT operation_id::text,env_id,generation_id::text,participant_id,
          trim(idempotency_key_sha256) AS idempotency_key_sha256,trim(request_sha256) AS request_sha256,operation_kind,status,receipt_status,transaction_hash,trim(response_sha256) AS response_sha256,
          started_at::text,completed_at::text
        FROM public.bef_operation WHERE env_id=$1 AND generation_id=$2::uuid ORDER BY started_at,operation_id LIMIT ${MAX_ROWS + 1}`,
      [envId, generationId]));
      const executionRows = pgResultRows(await query(`SELECT operation_id::text,env_id,generation_id::text,action_kind,
          selected_action_json,prestate_json,transaction_intent_json,measurement_json,transaction_hash,outcome,reason_code,completed_at::text
        FROM public.bef_selected_execution WHERE env_id=$1 AND generation_id=$2::uuid ORDER BY created_at,operation_id LIMIT ${MAX_ROWS + 1}`,
      [envId, generationId]));
      const eventRows = pgResultRows(await query(`SELECT event_sequence::text,event_id::text,operation_id::text,env_id,generation_id::text,
          event_kind,transaction_hash,event_json,created_at::text FROM public.bef_selected_execution_event
        WHERE env_id=$1 AND generation_id=$2::uuid ORDER BY event_sequence LIMIT ${MAX_ROWS + 1}`,[envId,generationId]));
      const costRows = pgResultRows(await query(`SELECT operation_id::text,env_id,generation_id::text,transaction_hash,payer_address,payer_role,
          receipt_status,transaction_from,receipt_from,receipt_block_number::text,receipt_block_hash,receipt_block_parent_hash,
          gas_used::text,effective_gas_price_wei::text,gas_cost_wei::text,modeled_gas_fee_usdc_units::text,manifest_sha256,
          selected_principal_asset,selected_principal_units::text,observed_principal_units::text,created_at::text
        FROM public.bef_transaction_cost WHERE env_id=$1 AND generation_id=$2::uuid ORDER BY transaction_hash LIMIT ${MAX_ROWS + 1}`,[envId,generationId]));
      const ancillary = pgResultRows(await query(`SELECT
          (SELECT count(*)::text FROM public.bef_payment WHERE env_id=$1 AND generation_id=$2::uuid) AS payments,
          (SELECT count(*)::text FROM public.bef_delivery d JOIN public.bef_operation o ON o.operation_id=d.operation_id
            WHERE o.env_id=$1 AND o.generation_id=$2::uuid) AS deliveries`,[envId,generationId]));
      if (generationRows.length !== 1 || ancillary.length !== 1 || [operationRows,executionRows,eventRows,costRows].some((list) => list.length > MAX_ROWS)) {
        throw new CollectionUnavailable('observer_census_unavailable');
      }
      const countRows = pgResultRows(await query(`SELECT
          (SELECT count(*)::text FROM public.bef_operation WHERE env_id=$1 AND generation_id=$2::uuid) AS operations,
          (SELECT count(*)::text FROM public.bef_selected_execution WHERE env_id=$1 AND generation_id=$2::uuid) AS selected_executions,
          (SELECT count(*)::text FROM public.bef_selected_execution_event WHERE env_id=$1 AND generation_id=$2::uuid) AS selected_events,
          (SELECT count(*)::text FROM public.bef_transaction_cost WHERE env_id=$1 AND generation_id=$2::uuid) AS costs`,[envId,generationId]));
      const counts = countRows[0];
      if (!counts || BigInt(String(counts.operations)) !== BigInt(operationRows.length) || BigInt(String(counts.selected_executions)) !== BigInt(executionRows.length) ||
          BigInt(String(counts.selected_events)) !== BigInt(eventRows.length) || BigInt(String(counts.costs)) !== BigInt(costRows.length)) {
        throw new CollectionUnavailable('observer_census_unavailable');
      }
      const selectedProjection = projectS4SelectedExecutionRows(executionRows, eventRows, tokenAddresses, router);
      if (!selectedProjection) throw new CollectionUnavailable('observer_census_unavailable');
      const { selectedExecutions, selectedEvents } = selectedProjection;
      const census: Census = {
        generation: { generation_id: String(generationRows[0]!.generation_id).toLowerCase(), env_id: generationRows[0]!.env_id,
          participant_id: generationRows[0]!.participant_id, payer_address: normalizeAddress(generationRows[0]!.payer_address),
          manifest_sha256: String(generationRows[0]!.manifest_sha256).toLowerCase(), status: generationRows[0]!.status,
          chain_id: String(generationRows[0]!.chain_id), environment_manifest_sha256: String(generationRows[0]!.environment_manifest_sha256).toLowerCase() },
        operations: operationRows.map((row) => ({ operation_id: String(row.operation_id).toLowerCase(), env_id: row.env_id,
          generation_id: String(row.generation_id).toLowerCase(), participant_id: row.participant_id,
          idempotency_key_sha256: row.idempotency_key_sha256===null?null:String(row.idempotency_key_sha256).toLowerCase(),
          request_sha256: String(row.request_sha256).toLowerCase(), operation_kind: row.operation_kind, status: row.status,
          receipt_status: row.receipt_status, transaction_hash: row.transaction_hash === null ? null : normalizeHash(row.transaction_hash),
          response_sha256: row.response_sha256 === null ? null : String(row.response_sha256).toLowerCase(),
          started_at: row.started_at, completed_at: row.completed_at })),
        selectedExecutions, selectedEvents,
        costs: costRows.map((row) => ({ ...row, operation_id: String(row.operation_id).toLowerCase(),
          generation_id: String(row.generation_id).toLowerCase(), transaction_hash: normalizeHash(row.transaction_hash),
          payer_address: normalizeAddress(row.payer_address), transaction_from: normalizeAddress(row.transaction_from),
          receipt_from: normalizeAddress(row.receipt_from), manifest_sha256: String(row.manifest_sha256).toLowerCase() })),
        paymentsCount: String(ancillary[0]!.payments), deliveriesCount: String(ancillary[0]!.deliveries),
        counts: { operations: String(counts.operations), selectedExecutions: String(counts.selected_executions),
          selectedEvents: String(counts.selected_events), costs: String(counts.costs) },
      };
      if (hasSecret(census) || Buffer.byteLength(canonicalTaskJson(census), 'utf8') > MAX_PACKET_BYTES) throw new CollectionUnavailable('observer_census_unavailable');
      return { session: { currentUser: 'bef_observer', sessionUser: 'bef_observer', transactionReadOnly: 'on',
        transactionIsolation: 'repeatable read', superuser: false, bypassRls: false }, census };
    });
  } catch (error) { if (error instanceof CollectionUnavailable) throw error; throw new CollectionUnavailable('observer_census_unavailable'); }
}

class RpcRecorder {
  readonly responseHashes: Array<{ method: string; paramsSha256: string; resultSha256: string }> = [];
  constructor(private readonly port: BefS4ReadOnlyRpcPort) {}
  async request(method: string, params: readonly unknown[]): Promise<unknown> {
    if (!['eth_chainId','eth_blockNumber','eth_getBlockByNumber','eth_getBalance','eth_call','eth_getCode','eth_getTransactionCount',
      'eth_getTransactionByHash','eth_getTransactionReceipt','eth_getLogs'].includes(method)) throw new CollectionUnavailable('rpc_observation_unavailable');
    let result: unknown;
    try { result = await this.port.request(method, params); } catch { throw new CollectionUnavailable('rpc_observation_unavailable'); }
    if (Buffer.byteLength(canonicalTaskJson(result), 'utf8') > MAX_RPC_BYTES || hasSecret(result)) throw new CollectionUnavailable('rpc_observation_unavailable');
    this.responseHashes.push({ method, paramsSha256: sha256CanonicalTaskJson(params).toLowerCase(), resultSha256: sha256CanonicalTaskJson(result).toLowerCase() });
    return result;
  }
}
function blockHeader(value: unknown, expectedNumber?: bigint): { number: bigint; hash: string; parentHash: string } {
  if (!isRecord(value)) throw new CollectionUnavailable('rpc_observation_unavailable');
  const number = hexUint(value.number), hash = normalizeHash(value.hash), parentHash = normalizeHash(value.parentHash);
  if (number === null || !hash || !parentHash || (expectedNumber !== undefined && number !== expectedNumber)) throw new CollectionUnavailable('rpc_observation_unavailable');
  return { number, hash, parentHash };
}
function rpcTransaction(value: unknown): S4Transaction | null {
  if (!isRecord(value)) return null;
  const hash = normalizeHash(value.hash), from = normalizeAddress(value.from), to = value.to === null ? null : normalizeAddress(value.to);
  const nonce = hexUint(value.nonce), valueWei = hexUint(value.value), gas = hexUint(value.gas), blockNumber = hexUint(value.blockNumber);
  const blockHash = normalizeHash(value.blockHash), transactionIndex = hexUint(value.transactionIndex), chainId = hexUint(value.chainId);
  if (!hash || !from || (value.to !== null && !to) || nonce === null || valueWei === null || gas === null || blockNumber === null || !blockHash ||
      transactionIndex === null || chainId === null || typeof value.input !== 'string' || !/^0x(?:[0-9a-f]{2})*$/i.test(value.input)) return null;
  return { hash, from, to, nonce: nonce.toString(), input: value.input.toLowerCase(), valueWei: valueWei.toString(), gasLimit: gas.toString(),
    blockNumber: blockNumber.toString(), blockHash, transactionIndex: transactionIndex.toString(), chainId: chainId.toString() };
}
function rpcReceipt(value: unknown, tx: S4Transaction): S4Receipt | null {
  if (!isRecord(value) || !Array.isArray(value.logs)) return null;
  const transactionHash = normalizeHash(value.transactionHash), from = normalizeAddress(value.from), to = value.to === null ? null : normalizeAddress(value.to);
  const blockNumber = hexUint(value.blockNumber), blockHash = normalizeHash(value.blockHash), index = hexUint(value.transactionIndex);
  const status = value.status === '0x1' ? 'success' : value.status === '0x0' ? 'reverted' : null;
  const gasUsed = hexUint(value.gasUsed), effectiveGasPrice = hexUint(value.effectiveGasPrice);
  if (transactionHash !== tx.hash || from !== tx.from || to !== tx.to || blockNumber?.toString() !== tx.blockNumber || blockHash !== tx.blockHash ||
      index?.toString() !== tx.transactionIndex || !status || gasUsed === null || effectiveGasPrice === null) return null;
  return { transactionHash, from, to, blockNumber: blockNumber.toString(), blockHash, transactionIndex: index!.toString(), status,
    gasUsed: gasUsed.toString(), effectiveGasPriceWei: effectiveGasPrice.toString(), gasCostWei: (gasUsed * effectiveGasPrice).toString(),
    logsSha256: sha256CanonicalTaskJson(value.logs).toLowerCase() };
}
function codeHash(value: unknown): string | null {
  if (typeof value !== 'string' || !/^0x(?:[0-9a-f]{2})*$/i.test(value) || value === '0x') return null;
  return keccak256(value as `0x${string}`).slice(2).toLowerCase();
}
function account(value: string, participant: string): string { return value === 'participant' ? participant : normalizeAddress(value) ?? ''; }
async function verifyCode(rpc: RpcRecorder, identity: { assets: Array<{ kind: string; address: string | null; codeHash: string | null }>;
  contracts: Array<{ address: string; codeHash: string }> }, block: bigint): Promise<void> {
  const expected = new Map<string,string>();
  for (const item of [...identity.assets, ...identity.contracts] as Array<{ kind?: string; address: string | null; codeHash: string | null }>) {
    if (item.kind === 'native') continue;
    const address = normalizeAddress(item.address), hash = item.codeHash;
    if (!address || !hash || !HASH.test(hash) || (expected.has(address) && expected.get(address) !== hash.toLowerCase())) throw new CollectionUnavailable('rpc_identity_mismatch');
    expected.set(address, hash.toLowerCase());
  }
  const tag = `0x${block.toString(16)}`;
  for (const [address, expectedHash] of expected) if (codeHash(await rpc.request('eth_getCode',[address,tag])) !== expectedHash) {
    throw new CollectionUnavailable('rpc_identity_mismatch');
  }
}
function caseAccount(value: string, participant: string): string { const result = account(value, participant); if (!result) throw new CollectionUnavailable('release_binding_mismatch'); return result; }
async function readCheckpoint(rpc: RpcRecorder, identity: { localChainId: number; assets: Array<{ assetId: string; kind: string; chainId: number; address: string | null }> },
  taskCase: Extract<TaskCase, { taskId: 'S4' }>, participant: string, block: bigint): Promise<S4Checkpoint> {
  const tag = `0x${block.toString(16)}`, header = blockHeader(await rpc.request('eth_getBlockByNumber',[tag,false]),block);
  const assets = new Map(identity.assets.map((item) => [item.assetId,item]));
  const balances: S4Checkpoint['balances'] = [];
  for (const item of taskCase.initialState.balances) {
    const a = caseAccount(item.account,participant), asset = assets.get(item.assetId);
    if (!asset || asset.chainId !== identity.localChainId) throw new CollectionUnavailable('release_binding_mismatch');
    let amount: bigint | null = null;
    if (asset.kind === 'native' && asset.address === null) amount = hexUint(await rpc.request('eth_getBalance',[a,tag]));
    else if (asset.kind === 'erc20' && normalizeAddress(asset.address)) {
      const value = await rpc.request('eth_call',[{to:asset.address,data:`${BALANCE_OF_SELECTOR}${codeWord(a)}`},tag]);
      if (typeof value === 'string' && HEX_WORD.test(value)) amount = BigInt(value);
    }
    if (amount === null) throw new CollectionUnavailable('rpc_observation_unavailable');
    balances.push({account:item.account,assetId:item.assetId,amountUnits:amount.toString()});
  }
  const allowances: S4Checkpoint['allowances'] = [];
  for (const item of taskCase.initialState.allowances) {
    const asset = assets.get(item.tokenAssetId), owner = caseAccount(item.owner,participant), spender = normalizeAddress(item.spender);
    if (!asset || asset.kind !== 'erc20' || !normalizeAddress(asset.address) || !spender) throw new CollectionUnavailable('release_binding_mismatch');
    const value = await rpc.request('eth_call',[{to:asset.address,data:encodeAllowance(owner,spender)},tag]);
    if (typeof value !== 'string' || !HEX_WORD.test(value)) throw new CollectionUnavailable('rpc_observation_unavailable');
    allowances.push({owner:item.owner,tokenAssetId:item.tokenAssetId,spender:item.spender,amountUnits:BigInt(value).toString()});
  }
  return {blockNumber:block.toString(),blockHash:header.hash,parentHash:header.parentHash,
    balances:balances.sort((a,b)=>`${a.account}|${a.assetId}`.localeCompare(`${b.account}|${b.assetId}`)),
    allowances:allowances.sort((a,b)=>allowanceKey(a.owner,a.tokenAssetId,a.spender).localeCompare(allowanceKey(b.owner,b.tokenAssetId,b.spender))),participantTransactionCount:'0'};
}
async function readAllowance(rpc: RpcRecorder, token: string, owner: string, spender: string, block: bigint): Promise<bigint> {
  const value = await rpc.request('eth_call',[{to:token,data:encodeAllowance(owner,spender)},`0x${block.toString(16)}`]);
  if (typeof value !== 'string' || !HEX_WORD.test(value)) throw new CollectionUnavailable('rpc_observation_unavailable');
  return BigInt(value);
}
function expectedInput(action: JsonRecord): string {
  if (action.kind === 'approve') return `${SELECTOR_APPROVE}${codeWord(String(action.spender))}${BigInt(String(action.amountUnits)).toString(16).padStart(64,'0')}`;
  if (action.kind === 'transfer') return `${SELECTOR_TRANSFER}${codeWord(String(action.recipient))}${BigInt(String(action.amountUnits)).toString(16).padStart(64,'0')}`;
  throw new CollectionUnavailable('rpc_mapping_incomplete');
}
function decodeApproval(value: unknown, token: string): S4ApprovalLog | null {
  if (!isRecord(value) || !Array.isArray(value.topics) || value.topics.length !== 3 || value.topics[0]?.toString().toLowerCase() !== APPROVAL_TOPIC ||
      typeof value.data !== 'string' || !HEX_WORD.test(value.data) || value.removed !== false) return null;
  const owner = topicAddress(value.topics[1]), spender = topicAddress(value.topics[2]);
  const txHash = normalizeHash(value.transactionHash), blockHash = normalizeHash(value.blockHash);
  const blockNumber = hexUint(value.blockNumber), txIndex = hexUint(value.transactionIndex), logIndex = hexUint(value.logIndex);
  if (normalizeAddress(value.address) !== token || !owner || !spender || !txHash || !blockHash || blockNumber === null || txIndex === null || logIndex === null) return null;
  return {tokenAddress:token,owner,spender,amountUnits:BigInt(value.data).toString(),transactionHash:txHash,
    blockNumber:blockNumber.toString(),blockHash,transactionIndex:txIndex.toString(),logIndex:logIndex.toString()};
}
function decodeTransfer(value: unknown, token: string): S4TransferLog | null {
  if (!isRecord(value) || !Array.isArray(value.topics) || value.topics.length !== 3 || value.topics[0]?.toString().toLowerCase() !== TRANSFER_TOPIC ||
      typeof value.data !== 'string' || !HEX_WORD.test(value.data) || value.removed !== false) return null;
  const from = topicAddress(value.topics[1]), to = topicAddress(value.topics[2]);
  const txHash = normalizeHash(value.transactionHash), blockHash = normalizeHash(value.blockHash);
  const blockNumber = hexUint(value.blockNumber), txIndex = hexUint(value.transactionIndex), logIndex = hexUint(value.logIndex);
  if (normalizeAddress(value.address) !== token || !from || !to || !txHash || !blockHash || blockNumber === null || txIndex === null || logIndex === null) return null;
  return {tokenAddress:token,from,to,amountUnits:BigInt(value.data).toString(),transactionHash:txHash,
    blockNumber:blockNumber.toString(),blockHash,transactionIndex:txIndex.toString(),logIndex:logIndex.toString()};
}
function topicAddress(value: unknown): string | null { return typeof value === 'string' && HEX_WORD.test(value) ? `0x${value.slice(-40).toLowerCase()}` : null; }
function ownerTopic(owner: string): string { return `0x${codeWord(owner)}`; }
function sortLogs<T extends {blockNumber:string;transactionIndex:string;logIndex:string;transactionHash:string}>(logs:T[]):T[] {
  return [...logs].sort((a,b)=>BigInt(a.blockNumber)<BigInt(b.blockNumber)?-1:BigInt(a.blockNumber)>BigInt(b.blockNumber)?1:
    BigInt(a.transactionIndex)<BigInt(b.transactionIndex)?-1:BigInt(a.transactionIndex)>BigInt(b.transactionIndex)?1:
      BigInt(a.logIndex)<BigInt(b.logIndex)?-1:BigInt(a.logIndex)>BigInt(b.logIndex)?1:a.transactionHash.localeCompare(b.transactionHash));
}
function sameCanonical(left: unknown, right: unknown): boolean { return canonicalTaskJson(left) === canonicalTaskJson(right); }

async function loadPreparationEvidence(root: string, prep: PreparationRow, runId: string, taskIndex: number,
  taskCase: Extract<TaskCase, {taskId:'S4'}>): Promise<FixtureProof> {
  const fixtureRef = ref(prep.fixture_evidence), baselineRef = ref(prep.baseline_evidence);
  if (!fixtureRef || !baselineRef || fixtureRef.path === baselineRef.path || fixtureRef.sha256 === baselineRef.sha256) throw new CollectionUnavailable('preparation_unavailable');
  const [fixtureBytes,baselineBytes] = await Promise.all([
    readEvidence(root,fixtureRef,PREPARATION_ROOT,'preparation_unavailable'),readEvidence(root,baselineRef,PREPARATION_ROOT,'preparation_unavailable')]);
  const fixture = readJson(fixtureBytes,'preparation_unavailable');
  const baseline = readJson(baselineBytes,'preparation_unavailable');
  const pins = publicPins(prep,runId,taskIndex);
  for (const [doc,kind] of [[fixture,'fixture'],[baseline,'baseline']] as const) {
    if (doc.schemaVersion !== 'owner-bef-task-preparation-evidence/v1' || doc.kind !== kind || doc.preparationId !== prep.preparation_id ||
        doc.environmentId !== prep.environment_id || doc.publicPinsSha256 !== pins || !isRecord(doc.evidence)) throw new CollectionUnavailable('preparation_unavailable');
  }
  const state = (baseline.evidence as JsonRecord).state;
  const stateEvidence = baseline.evidence as JsonRecord;
  const projection = isRecord(state) ? state.projection : null;
  if (!isRecord(state) || state.sameBlock !== true || !Array.isArray(state.reads) || !isRecord(projection) ||
      stateEvidence.stateSha256 !== taskCase.initialState.stateSha256.toLowerCase() ||
      stateEvidence.expectedStateSha256 !== taskCase.initialState.stateSha256.toLowerCase() ||
      prep.baseline_state_sha256?.toLowerCase() !== taskCase.initialState.stateSha256.toLowerCase() ||
      !sameCanonical(projection,caseProjection(taskCase)) || sha256CanonicalTaskJson(projection).toLowerCase() !== taskCase.initialState.stateSha256.toLowerCase()) {
    throw new CollectionUnavailable('baseline_mismatch');
  }
  const blockNumber = hexUint(state.blockNumber), blockHash = normalizeHash(state.blockHash);
  if (blockNumber === null || !blockHash) throw new CollectionUnavailable('baseline_mismatch');
  const s4 = (fixture.evidence as JsonRecord).s4AllowanceFixture;
  if (!isRecord(s4) || s4.stage !== 'pre_task_fixture_setup' || s4.outcome !== 'observed' || s4.preparationId !== prep.preparation_id ||
      s4.generationId !== prep.generation_id || !isRecord(s4.action) || !isRecord(s4.preState) || !isRecord(s4.postState) ||
      !isRecord(s4.transaction) || !isRecord(s4.receipt) || !isRecord(s4.block) || typeof s4.operationId !== 'string' ||
      !UUID.test(s4.operationId) || !normalizeHash(s4.transactionHash)) throw new CollectionUnavailable('preparation_unavailable');
  const action = s4.action;
  if (!exactKeys(action,['kind','tokenAssetId','spender','amountUnits','gasLimit']) || action.kind !== 'approve' || action.tokenAssetId !== 'USDC' ||
      action.spender !== taskCase.objective.spender.toLowerCase() || action.amountUnits !== taskCase.objective.initialAllowanceUnits || action.gasLimit !== '100000') {
    throw new CollectionUnavailable('preparation_unavailable');
  }
  const preState = s4.preState, postState = s4.postState;
  const preProjection = isRecord(preState.projection) ? preState.projection : null;
  const postProjection = isRecord(postState.projection) ? postState.projection : null;
  const fixturePayer=normalizeAddress(prep.payer_address);
  const fixtureGasUsed=isRecord(s4.receipt)?decimal(s4.receipt.gasUsed):null;
  const fixtureGasPrice=isRecord(s4.receipt)?decimal(s4.receipt.effectiveGasPrice):null;
  const fixtureGasCost=decimal(s4.gasCostWei);
  const receiptLogs=isRecord(s4.receipt)&&Array.isArray(s4.receipt.logs)?s4.receipt.logs:null;
  const receiptLog=receiptLogs?.length===1&&isRecord(receiptLogs[0])?receiptLogs[0]:null;
  const fixtureTransaction=isRecord(s4.transaction)?s4.transaction:null;
  const fixtureReceipt=isRecord(s4.receipt)?s4.receipt:null;
  const preBlockNumber=hexUint(preState.blockNumber),preBlockHash=normalizeHash(preState.blockHash);
  if (!preProjection || !postProjection || !isRecord(preState.projection) || !isRecord(postState.projection) ||
      preBlockNumber===null || !preBlockHash || !fixturePayer || fixtureGasUsed===null || fixtureGasUsed<=0n ||
      fixtureGasPrice===null || fixtureGasCost===null || fixtureGasCost!==fixtureGasUsed*fixtureGasPrice ||
      !s4FixtureTransitionMatches(taskCase,fixturePayer,preProjection,postProjection,fixtureGasCost)) throw new CollectionUnavailable('baseline_mismatch');
  const fixtureBlockNumber = hexUint(s4.block.number), fixtureBlockHash = normalizeHash(s4.block.hash);
  const transactionHash = normalizeHash(s4.transactionHash);
  const amountUnits = decimal(action.amountUnits);
  if (fixtureBlockNumber === null || !fixtureBlockHash || !transactionHash || amountUnits === null || amountUnits <= 0n ||
      fixtureBlockNumber > blockNumber || (fixtureBlockNumber === blockNumber && fixtureBlockHash !== blockHash) ||
      preBlockNumber + 1n !== fixtureBlockNumber || normalizeHash(s4.transaction.blockHash) !== fixtureBlockHash ||
      normalizeHash(s4.receipt.blockHash) !== fixtureBlockHash || normalizeHash(s4.block.parentHash)!==normalizeHash(preState.blockHash) ||
      !s4FixturePostStateMatchesBlock(taskCase,postState,fixtureBlockNumber,fixtureBlockHash) ||
      s4.block.transactionCount!==1 ||
      !fixtureTransaction || fixtureTransaction.from?.toString().toLowerCase()!==fixturePayer ||
      normalizeAddress(fixtureTransaction.to)!==normalizeAddress(s4.transaction.to) ||
      fixtureTransaction.input?.toString().toLowerCase()!==expectedInput({kind:'approve',spender:taskCase.objective.spender,amountUnits:amountUnits?.toString()??''}) ||
      fixtureTransaction.valueWei!=='0' || fixtureTransaction.gasLimit!=='100000' ||
      !fixtureReceipt || fixtureReceipt.status!=='success' || normalizeHash(fixtureReceipt.transactionHash)!==transactionHash ||
      normalizeAddress(fixtureReceipt.from)!==fixturePayer || normalizeAddress(fixtureReceipt.to)!==normalizeAddress(fixtureTransaction.to) ||
      String(fixtureReceipt.gasUsed)!==fixtureGasUsed?.toString() || String(fixtureReceipt.effectiveGasPrice)!==fixtureGasPrice?.toString() ||
      !receiptLog ||
      normalizeAddress(receiptLog.address)!==normalizeAddress(fixtureTransaction.to) || normalizeAddress(receiptLog.owner)!==fixturePayer ||
      normalizeAddress(receiptLog.spender)!==taskCase.objective.spender.toLowerCase() || String(receiptLog.amountUnits)!==amountUnits?.toString() ||
      normalizeAddress(s4.transaction.to) === null || normalizeAddress(s4.receipt.to) !== normalizeAddress(s4.transaction.to) ||
      typeof s4.responseSha256 !== 'string' || !HASH.test(s4.responseSha256) || typeof s4.idempotencyKeySha256 !== 'string' || !HASH.test(s4.idempotencyKeySha256)) {
    throw new CollectionUnavailable('preparation_unavailable');
  }
  return {operationId:s4.operationId.toLowerCase(),transactionHash,blockNumber:fixtureBlockNumber,blockHash:fixtureBlockHash,
    parentHash:normalizeHash(s4.block.parentHash)!,
    amountUnits,spender:taskCase.objective.spender.toLowerCase(),tokenAddress:normalizeAddress(s4.transaction.to)!,
    idempotencyKeySha256:s4.idempotencyKeySha256.toLowerCase(),
    proofSha256:sha256CanonicalTaskJson(s4).toLowerCase(),reference:fixtureRef,baselineReference:baselineRef,baselineNumber:blockNumber,baselineHash:blockHash,
    preState:{blockNumber:preBlockNumber,blockHash:preBlockHash,projection:preProjection}};
}

function exactActionKeys(value: JsonRecord): boolean {
  const allowed=['schema','actionId','runId','taskIndex','actionSequence','ownerOperationId','actionKind','commandSha256','environmentId','generationId',
    'manifestSha256','applicationSourceSha256','idempotencyKey','status','reasonCode','requestStartedAt','requestFinishedAt','httpStatus','recoverySource','befOperationId',
    'transactionHash','outcome','receiptStatus','rawResponseSha256','participantToolResponse','receiptGasUsed','receiptEffectiveGasPriceWei','paymentProtocol','environmentHealth'];
  return Object.keys(value).every((key)=>allowed.includes(key));
}
async function loadActions(root:string,run:RunTaskRow,prep:PreparationRow,runId:string,taskIndex:number,cutoff:number,rows:ActionRow[]):Promise<LoadedAction[]> {
  if (cutoff>MAX_ACTIONS||rows.length!==cutoff) throw new CollectionUnavailable('owner_cutoff_mismatch');
  const loaded:LoadedAction[]=[];
  for (let index=0;index<rows.length;index+=1) {
    const row=rows[index]!, seq=sequence(row.action_sequence);
    const evidenceRef=row.evidence_path&&row.evidence_hash?ref({path:row.evidence_path,sha256:row.evidence_hash,boundary:EVIDENCE_BOUNDARY}):null;
    if (seq!==index+1||row.id!==row.id.toLowerCase()||!UUID.test(row.id)||row.run_id!==runId||row.task_index!==taskIndex||
        row.owner_id!==run.owner_id||row.agent_id!==run.agent_id||row.task_id!=='S4'||row.environment_id!==prep.environment_id||
        !['approve','transfer','inspect_catalog','inspect_offer'].includes(row.action_kind)||!HASH.test(row.payload_hash)||!evidenceRef||!HASH.test(row.evidence_hash??'')||
        row.receipt_revision!==row.history_revision||row.receipt_status!==row.history_status||row.history_evidence_hash!==row.evidence_hash||
        row.history_evidence_path!==row.evidence_path||(row.history_transaction_hash?.toLowerCase()??null)!==(row.transaction_hash?.toLowerCase()??null)||
        row.receipt_status!=='observed') throw new CollectionUnavailable('action_evidence_unavailable');
    const command=TaskActionCommandSchema.safeParse(row.command_json);
    if (!command.success||!['approve','transfer','inspect_catalog','inspect_offer'].includes(command.data.kind)||
        sha256CanonicalTaskJson({runId,taskIndex,command:command.data}).toLowerCase()!==row.payload_hash.toLowerCase()||command.data.kind!==row.action_kind) {
      throw new CollectionUnavailable('action_evidence_unavailable');
    }
    const bytes=await readEvidence(root,evidenceRef,ACTION_ROOT,'action_evidence_unavailable');
    const doc=readJson(bytes,'action_evidence_unavailable',[['participantToolResponse','selectedAction','token'],['participantToolResponse','selectedAction','spender']]);
    const recoverySourceBacked=doc.recoverySource!==undefined;
    if (!exactActionKeys(doc)||doc.schema!=='bef-task-action-observation-v1'||doc.actionId!==row.id||doc.runId!==runId||doc.taskIndex!==taskIndex||
        doc.actionSequence!==String(seq)||doc.ownerOperationId!==row.operation_id||doc.actionKind!==row.action_kind||doc.commandSha256!==row.payload_hash.toLowerCase()||
        doc.environmentId!==prep.environment_id||doc.generationId!==prep.generation_id||doc.manifestSha256!==prep.environment_manifest_sha256.toLowerCase()||
        doc.applicationSourceSha256!==prep.application_source_hash.toLowerCase()||doc.idempotencyKey!==`task-action-${row.id}`||doc.status!=='observed') {
      throw new CollectionUnavailable('action_evidence_unavailable');
    }
    if (command.data.kind==='inspect_catalog'||command.data.kind==='inspect_offer') {
      if (recoverySourceBacked||row.transaction_hash!==null||typeof doc.rawResponseSha256!=='string'||!HASH.test(doc.rawResponseSha256)||
          doc.httpStatus!==200||typeof doc.befOperationId!=='string'||!UUID.test(doc.befOperationId)||
          doc.transactionHash!==undefined||doc.outcome!==undefined||doc.receiptStatus!==undefined||doc.receiptGasUsed!==undefined||
          doc.receiptEffectiveGasPriceWei!==undefined||doc.paymentProtocol!==undefined||!isRecord(doc.participantToolResponse)||
          !isS4ReadResponse(command.data,doc.participantToolResponse,doc.befOperationId)) throw new CollectionUnavailable('action_evidence_unavailable');
      loaded.push({category:'read',row,sequence:seq,command:command.data as ReadCommand,evidence:doc,evidenceReference:evidenceRef});
      continue;
    }
    if ((recoverySourceBacked ? (!recoveredActionEvidenceIsOwnerBound(doc,row,{actionId:row.id,runId,ownerId:run.owner_id,
            agentId:run.agent_id,taskIndex,environmentId:prep.environment_id,operationId:row.operation_id,payloadHash:row.payload_hash,
            evidenceHash:row.evidence_hash!})) : (typeof doc.rawResponseSha256!=='string'||!HASH.test(doc.rawResponseSha256)||doc.httpStatus!==200))||
        typeof doc.befOperationId!=='string'||!UUID.test(doc.befOperationId)||typeof doc.transactionHash!=='string'||!TX_HASH.test(doc.transactionHash)||
        !isRecord(doc.participantToolResponse)||!isRecord(doc.participantToolResponse.selectedAction)) throw new CollectionUnavailable('action_evidence_unavailable');
    if (command.data.kind==='approve') {
      const selected=doc.participantToolResponse.selectedAction;
      if (!exactKeys(selected,['kind','tokenAssetId','token','spender','amountUnits','gasLimit'])||selected.kind!=='approve'||
          selected.tokenAssetId!==(command.data.tokenAssetId??'WETH')||!normalizeAddress(selected.token)||!normalizeAddress(selected.spender)||
          selected.amountUnits!==command.data.amountUnits||selected.gasLimit!==command.data.gasLimit) throw new CollectionUnavailable('action_evidence_unavailable');
    } else if (command.data.kind==='transfer') {
      const selected=doc.participantToolResponse.selectedAction;
      const token=normalizeAddress(selected.token),recipient=normalizeAddress(selected.recipient);
      if (!exactKeys(selected,['kind','token','amountUnits','recipient','gasLimit'])||selected.kind!=='transfer'||!token||!recipient||
          selected.amountUnits!==command.data.amountUnits||recipient!==command.data.recipient.toLowerCase()||selected.gasLimit!==command.data.gasLimit) {
        throw new CollectionUnavailable('action_evidence_unavailable');
      }
    } else throw new CollectionUnavailable('action_evidence_unavailable');
    const response=doc.participantToolResponse;
    if (response.operationId!==doc.befOperationId||response.outcome!==doc.outcome||!isRecord(response.transaction)||!isRecord(response.receipt)||
        normalizeHash(response.transaction.hash)!==normalizeHash(doc.transactionHash)||normalizeHash(response.receipt.transactionHash)!==normalizeHash(doc.transactionHash)||
        response.receipt.status!==doc.receiptStatus||!['success','reverted'].includes(String(doc.receiptStatus))||doc.outcome!==doc.receiptStatus||
        String(response.receipt.gasUsed)!==String(doc.receiptGasUsed)||String(response.receipt.effectiveGasPrice)!==String(doc.receiptEffectiveGasPriceWei)) {
      throw new CollectionUnavailable('action_evidence_unavailable');
    }
    loaded.push({category:'mutable',row,sequence:seq,command:command.data as MutableCommand,
      evidence:doc as unknown as RecoveryActionEvidence,evidenceReference:evidenceRef});
  }
  return loaded;
}

function isS4ReadResponse(command:ReadCommand,body:JsonRecord,operationId:string):boolean {
  const handle=body.readHandle;
  if(!readOnlyToolResponseMatches(command,body)||body.operationId!==operationId||!isRecord(handle)||
      Object.keys(handle).sort().join(',')!=='kind,operationId'||handle.kind!==(command.kind==='inspect_catalog'?'catalog':'offer')||
      handle.operationId!==operationId) return false;
  if(command.kind==='inspect_catalog') {
    return Object.keys(body).sort().join(',')==='catalog,deliveryState,freeInspection,operationId,readHandle';
  }
  const required=['operationId','readHandle','resourceId','resourceSha256','contentType','payment','offers','freeInspection','deliveryState'];
  const allowed=new Set([...required,'dataType','schema','provenance']);
  return !Object.keys(body).some((key)=>!allowed.has(key))&&required.every((key)=>key in body)&&body.resourceId===command.resourceId&&
    (body.dataType===undefined||typeof body.dataType==='string')&&(body.schema===undefined||typeof body.schema==='string')&&
    (body.provenance===undefined||isRecord(body.provenance));
}

function expectedS4ReadRequestHash(command:ReadCommand):string {
  const request=command.kind==='inspect_catalog'?{method:'GET',path:'/catalog'}:{method:'GET',path:'/offer',resourceId:command.resourceId};
  return sha256(JSON.stringify(request)).toLowerCase();
}
function expectedS4ReadResponseHash(command:ReadCommand,body:JsonRecord):string {
  if(command.kind==='inspect_catalog') return sha256(JSON.stringify({operationId:body.operationId,readHandle:body.readHandle,catalog:body.catalog,
    freeInspection:body.freeInspection,deliveryState:body.deliveryState})).toLowerCase();
  const response:JsonRecord={operationId:body.operationId,readHandle:body.readHandle,resourceId:body.resourceId,
    resourceSha256:body.resourceSha256,contentType:body.contentType};
  if(body.dataType!==undefined)response.dataType=body.dataType;
  if(body.schema!==undefined)response.schema=body.schema;
  if(body.provenance!==undefined)response.provenance=body.provenance;
  response.payment=body.payment;response.offers=body.offers;response.freeInspection=body.freeInspection;response.deliveryState=body.deliveryState;
  return sha256(JSON.stringify(response)).toLowerCase();
}

function validateS4ReadOperations(census:Census,actions:LoadedAction[],environmentId:string,generationId:string,participantId:string):Set<string> {
  const reads=actions.filter((action):action is LoadedReadAction=>action.category==='read');
  const ids=new Set<string>();
  for(const action of reads){
    const id=String(action.evidence.befOperationId).toLowerCase();
    const operation=census.operations.find((item)=>String(item.operation_id).toLowerCase()===id);
    if(ids.has(id)||!operation||operation.env_id!==environmentId||String(operation.generation_id).toLowerCase()!==generationId.toLowerCase()||
        operation.participant_id!==participantId||String(operation.idempotency_key_sha256).toLowerCase()!==sha256(`task-action-${action.row.id}`).toLowerCase()||
        String(operation.request_sha256).toLowerCase()!==expectedS4ReadRequestHash(action.command)||
        operation.operation_kind!==(action.command.kind==='inspect_catalog'?'catalog':'offer')||operation.status!=='accepted'||
        operation.receipt_status!=='not_submitted'||operation.transaction_hash!==null||!action.evidence.participantToolResponse||
        String(operation.response_sha256).toLowerCase()!==expectedS4ReadResponseHash(action.command,action.evidence.participantToolResponse as JsonRecord)) {
      throw new CollectionUnavailable('rpc_mapping_incomplete');
    }
    ids.add(id);
  }
  if(ids.size!==reads.length||ids.size!==census.operations.filter((item)=>['catalog','offer'].includes(String(item.operation_kind))).length||
      census.selectedExecutions.some((item)=>ids.has(String(item.operation_id).toLowerCase()))||
      census.selectedEvents.some((item)=>ids.has(String(item.operationId).toLowerCase()))||
      census.costs.some((item)=>ids.has(String(item.operation_id).toLowerCase()))) throw new CollectionUnavailable('rpc_mapping_incomplete');
  return ids;
}

function verifyFixtureOperation(census:Census,fixture:FixtureProof,prep:PreparationRow,payer:string,
  tokens:Readonly<Record<'USDC'|'WETH',string>>,router:string):{operation:JsonRecord;selected:JsonRecord;events:JsonRecord[]} {
  const operation=census.operations.find((row)=>row.operation_id===fixture.operationId);
  const selected=census.selectedExecutions.find((row)=>row.operation_id===fixture.operationId);
  const events=census.selectedEvents.filter((row)=>row.operationId===fixture.operationId).sort((a,b)=>{
    const left=BigInt(String(a.eventSequence)),right=BigInt(String(b.eventSequence));
    return left<right?-1:left>right?1:0;
  });
  const selectedAction=selected?.selected_action;
  const expected={kind:'approve',tokenAssetId:'USDC',tokenAddress:tokens.USDC,spender:router,amountUnits:fixture.amountUnits.toString(),gasLimit:'100000'};
  if (!operation||!selected||operation.env_id!==prep.environment_id||operation.generation_id!==prep.generation_id?.toLowerCase()||
      operation.participant_id!==prep.participant_id||operation.operation_kind!=='approve'||operation.status!=='settled'||operation.receipt_status!=='success'||
      operation.idempotency_key_sha256!==fixture.idempotencyKeySha256||
      normalizeHash(operation.transaction_hash)!==fixture.transactionHash||selected.action_kind!=='approve'||!sameCanonical(selectedAction,expected)||
      normalizeHash(selected.transaction_hash)!==fixture.transactionHash||selected.outcome!=='success'||events.length!==4||
      events.map((event)=>event.eventKind).join(',')!=='selected_action_bound,prestate_observed,original_tx_hash_bound,receipt_finalized') {
    throw new CollectionUnavailable('preparation_unavailable');
  }
  const selectedPayload=events[0]!.eventPayload, prestatePayload=events[1]!.eventPayload, originalPayload=events[2]!.eventPayload, finalPayload=events[3]!.eventPayload;
  const measurement=isRecord(selected.measurement)?selected.measurement:null;
  const measuredTransaction=measurement&&isRecord(measurement.transaction)?measurement.transaction:null;
  const selectedIntent=transactionIntent(selected.transaction_intent);
  if (!isRecord(selectedPayload)||selectedPayload.actionKind!=='approve'||selectedPayload.requestSha256!==operation.request_sha256||
      !sameCanonical(selectedPayload.selectedAction,expected)||
      !isRecord(prestatePayload)||!isRecord(prestatePayload.prestate)||!isRecord(originalPayload)||
      !sameCanonical(prestatePayload.prestate,selected.prestate)||originalPayload.transactionHash!==fixture.transactionHash||
      originalPayload.requestSha256!==operation.request_sha256||!selectedIntent||!sameCanonical(originalPayload.transactionIntent,selectedIntent)||
      events[0]!.transactionHash!==null||events[1]!.transactionHash!==null||events[2]!.transactionHash!==fixture.transactionHash||
      events[3]!.transactionHash!==fixture.transactionHash||
      !isRecord(finalPayload)||finalPayload.outcome!=='success'||!measurement||!measuredTransaction||
      finalPayload.measurementSha256!==measurement.measurementSha256||
      normalizeAddress(measuredTransaction.from)!==payer||normalizeAddress(measuredTransaction.to)!==tokens.USDC||
      !sameCanonical(measurement.selectedAction,expected)) throw new CollectionUnavailable('preparation_unavailable');
  return {operation,selected,events};
}

function recoveredSourceFacts(operation:JsonRecord,selected:JsonRecord,generation:JsonRecord,events:JsonRecord[]):RecoverySourceFacts|null{
  const measurement=isRecord(selected.measurement)?selected.measurement:null;
  if(!measurement||typeof measurement.measurementSha256!=='string'||!isRecord(selected.selected_action))return null;
  const bound=events.filter((event)=>event.eventKind==='selected_action_bound');
  const selectedActionEventBound=bound.flatMap((event)=>{
    const payload=isRecord(event.eventPayload)?event.eventPayload:null;
    if(!payload||typeof payload.actionKind!=='string'||typeof payload.requestSha256!=='string'||typeof event.eventJsonSha256!=='string')return [];
    return [{eventKind:String(event.eventKind),actionKind:payload.actionKind,requestSha256:payload.requestSha256,
      selectedAction:payload.selectedAction,eventJsonSha256:event.eventJsonSha256}];
  });
  if(bound.length!==selectedActionEventBound.length)return null;
  return {operation:{operationId:String(operation.operation_id??''),environmentId:String(operation.env_id??''),
    generationId:String(operation.generation_id??''),participantId:String(operation.participant_id??''),
    idempotencyKeySha256:String(operation.idempotency_key_sha256??''),requestSha256:String(operation.request_sha256??''),
    operationKind:String(operation.operation_kind??''),status:String(operation.status??''),
    transactionHash:operation.transaction_hash===null?null:normalizeHash(operation.transaction_hash),
    receiptStatus:String(operation.receipt_status??''),responseSha256:operation.response_sha256===null?null:
      typeof operation.response_sha256==='string'?operation.response_sha256.toLowerCase():''},
    generationManifestSha256:String(generation.manifest_sha256??''),environmentManifestSha256:String(generation.environment_manifest_sha256??''),
    selectedExecution:{actionKind:String(selected.action_kind??''),selectedAction:selected.selected_action,
      outcome:typeof selected.outcome==='string'?selected.outcome:null,
      transactionHash:selected.transaction_hash===null?null:normalizeHash(selected.transaction_hash),
      measurementSha256:measurement.measurementSha256},selectedActionBoundEvents:selectedActionEventBound};
}

function recoveredToolResponseMatchesSelection(action:LoadedAction,selected:JsonRecord,txHash:string,outcome:string):boolean{
  const response=action.evidence.participantToolResponse,measurement=isRecord(selected.measurement)?selected.measurement:null;
  if(!action.evidence.recoverySource)return true;
  const responseSelected=isRecord(response)&&isRecord(response.selectedAction)?response.selectedAction:null;
  const selectedFromMeasurement=measurement&&isRecord(measurement.selectedAction)?measurement.selectedAction:null;
  if(!isRecord(response)||!measurement||!responseSelected||!selectedFromMeasurement||
      response.operationId!==action.evidence.befOperationId||response.outcome!==outcome||
      responseSelected.kind!==selectedFromMeasurement.kind||responseSelected.amountUnits!==selectedFromMeasurement.amountUnits||
      responseSelected.gasLimit!==selectedFromMeasurement.gasLimit||
      normalizeAddress(responseSelected.token)!==normalizeAddress(selectedFromMeasurement.tokenAddress)||
      (responseSelected.kind==='approve'&&(responseSelected.tokenAssetId!==selectedFromMeasurement.tokenAssetId||
        normalizeAddress(responseSelected.spender)!==normalizeAddress(selectedFromMeasurement.spender)))||
      (responseSelected.kind==='transfer'&&normalizeAddress(responseSelected.recipient)!==normalizeAddress(selectedFromMeasurement.recipient)))return false;
  const responseTransaction=isRecord(response.transaction)?response.transaction:null,responseReceipt=isRecord(response.receipt)?response.receipt:null;
  const selectedTransaction=isRecord(measurement.transaction)?measurement.transaction:null,selectedReceipt=isRecord(measurement.receipt)?measurement.receipt:null;
  return Boolean(responseTransaction&&responseReceipt&&selectedTransaction&&selectedReceipt&&
    normalizeHash(responseTransaction.hash)===txHash&&normalizeHash(selectedTransaction.hash)===txHash&&
    normalizeHash(responseReceipt.transactionHash)===txHash&&normalizeHash(selectedReceipt.transactionHash)===txHash&&
    responseReceipt.status===selectedReceipt.status&&responseReceipt.gasUsed===selectedReceipt.gasUsed&&
    responseReceipt.effectiveGasPrice===selectedReceipt.effectiveGasPrice&&
    action.evidence.receiptGasUsed===String(selectedReceipt.gasUsed)&&
    action.evidence.receiptEffectiveGasPriceWei===String(selectedReceipt.effectiveGasPrice));
}

function verifyS4CostRows(census:Census,expected:Array<{operationId:string;receipt:S4Receipt;parentHash:string}>,
  envId:string,generationId:string,payer:string,environmentManifestHash:string):void {
  if(census.costs.length!==expected.length)throw new CollectionUnavailable('rpc_mapping_incomplete');
  const byHash=new Map(expected.map((item)=>[item.receipt.transactionHash,item]));
  const seen=new Set<string>();
  for(const row of census.costs){
    const hash=normalizeHash(row.transaction_hash),item=hash?byHash.get(hash):undefined;
    if(!hash||!item||seen.has(hash)||String(row.operation_id).toLowerCase()!==item.operationId.toLowerCase()||row.env_id!==envId||
        String(row.generation_id).toLowerCase()!==generationId.toLowerCase()||row.payer_role!=='participant'||
        normalizeAddress(row.payer_address)!==payer||normalizeAddress(row.transaction_from)!==payer||normalizeAddress(row.receipt_from)!==payer||
        row.receipt_status!==item.receipt.status||String(row.receipt_block_number)!==item.receipt.blockNumber||
        normalizeHash(row.receipt_block_hash)!==item.receipt.blockHash||normalizeHash(row.receipt_block_parent_hash)!==item.parentHash||
        String(row.gas_used)!==item.receipt.gasUsed||String(row.effective_gas_price_wei)!==item.receipt.effectiveGasPriceWei||
        String(row.gas_cost_wei)!==item.receipt.gasCostWei||String(row.manifest_sha256).toLowerCase()!==environmentManifestHash.toLowerCase()) {
      throw new CollectionUnavailable('rpc_mapping_incomplete');
    }
    seen.add(hash);
  }
  if(seen.size!==expected.length)throw new CollectionUnavailable('rpc_mapping_incomplete');
}

async function readLogs(rpc:RpcRecorder,tokens:Readonly<Record<'USDC'|'WETH',string>>,participant:string,from:bigint,to:bigint):Promise<{approvals:S4ApprovalLog[];transfers:S4TransferLog[]}> {
  if (to<from||to-from>BigInt(MAX_BLOCKS)) throw new CollectionUnavailable('rpc_interval_too_large');
  const fromTag=`0x${from.toString(16)}`,toTag=`0x${to.toString(16)}`,topic=ownerTopic(participant);
  const approvals:S4ApprovalLog[]=[],transfers:S4TransferLog[]=[];
  for (const token of [tokens.USDC,tokens.WETH]) {
    const approvalRaw=await rpc.request('eth_getLogs',[{address:token,fromBlock:fromTag,toBlock:toTag,topics:[APPROVAL_TOPIC,topic]}]);
    const transferRaw=await rpc.request('eth_getLogs',[{address:token,fromBlock:fromTag,toBlock:toTag,topics:[TRANSFER_TOPIC,topic]}]);
    if (!Array.isArray(approvalRaw)||!Array.isArray(transferRaw)||approvalRaw.length>MAX_ROWS||transferRaw.length>MAX_ROWS) throw new CollectionUnavailable('rpc_observation_unavailable');
    for (const raw of approvalRaw) { const log=decodeApproval(raw,token); if (!log||log.owner!==participant) throw new CollectionUnavailable('rpc_mapping_incomplete'); approvals.push(log); }
    for (const raw of transferRaw) { const log=decodeTransfer(raw,token); if (!log||log.from!==participant) throw new CollectionUnavailable('rpc_mapping_incomplete'); transfers.push(log); }
  }
  const unique=<T extends {blockNumber:string;transactionIndex:string;logIndex:string;transactionHash:string}>(items:T[]):T[]=>{
    const map=new Map<string,T>();
    for(const item of items){const key=`${item.transactionHash}:${item.logIndex}`;const previous=map.get(key);if(previous&&!sameCanonical(previous,item))throw new CollectionUnavailable('rpc_mapping_incomplete');map.set(key,item);}
    return [...map.values()];
  };
  return {approvals:sortLogs(unique(approvals)),transfers:sortLogs(unique(transfers))};
}

function projectCaseState(checkpoint:S4Checkpoint,taskCase:Extract<TaskCase,{taskId:'S4'}>,extraAllowances:Array<{owner:string;tokenAssetId:string;spender:string;amountUnits:string}>):{
  balances:S4Checkpoint['balances'];allowances:S4Checkpoint['allowances'];deliveredComponentIds:string[];fulfilledObligationIds:string[]
} {
  const allowMap=new Map(checkpoint.allowances.map((item)=>[allowanceKey(item.owner,item.tokenAssetId,item.spender),item]));
  for(const item of extraAllowances) allowMap.set(allowanceKey(item.owner,item.tokenAssetId,item.spender),item);
  return {balances:checkpoint.balances,allowances:[...allowMap.values()].sort((a,b)=>allowanceKey(a.owner,a.tokenAssetId,a.spender).localeCompare(allowanceKey(b.owner,b.tokenAssetId,b.spender))),
    deliveredComponentIds:taskCase.initialState.deliveredComponentIds,fulfilledObligationIds:taskCase.initialState.fulfilledObligationIds};
}

async function collectLocked(deps:BefS4ObservationCollectorDependencies,target:{runId:string;taskIndex:number},tx:OwnerTx):Promise<BefS4ObservationCollectionResult> {
  const ownerFound=await ownerRows<{owner_id:string;agent_id:string}>(tx,sql`SELECT owner_id,agent_id FROM oid_benchmark_run WHERE id=${target.runId}`);
  const owner=ownerFound[0];if(!owner)return unavailable('owner_cutoff_unavailable');
  await tx.execute(sql`SELECT id FROM oid_owner WHERE id=${owner.owner_id} FOR NO KEY UPDATE`);
  await tx.execute(sql`SELECT id FROM oid_agent WHERE id=${owner.agent_id} AND owner_id=${owner.owner_id} FOR NO KEY UPDATE`);
  const runRows=await ownerRows<RunTaskRow>(tx,sql`SELECT r.owner_id,r.agent_id,r.mode,r.task_ids,r.release_identity,r.manifest_hash,
      t.task_id,t.closure_status,t.closure_id,t.closure_operation_id,t.closure_payload_hash,t.closure_reason,
      t.action_cutoff_sequence::text AS action_cutoff_sequence,t.reconciled_action_sequence::text AS reconciled_action_sequence
    FROM oid_benchmark_run r JOIN oid_run_task t ON t.run_id=r.id WHERE r.id=${target.runId} AND r.owner_id=${owner.owner_id} AND r.agent_id=${owner.agent_id}
      AND t.task_index=${target.taskIndex} FOR UPDATE OF r,t`);
  const run=runRows[0];if(!run||run.task_id!=='S4'||run.task_ids[target.taskIndex]!=='S4')return unavailable(run?'unsupported_task':'owner_cutoff_unavailable');
  if(run.closure_status!=='closed'||!run.closure_id||run.action_cutoff_sequence===null)return unavailable('owner_cutoff_unavailable');
  const cutoff=sequence(run.action_cutoff_sequence),reconciled=sequence(run.reconciled_action_sequence);
  if(cutoff===null||reconciled===null||reconciled<cutoff)return unavailable('reconciliation_pending');
  const closureRows=await ownerRows<ClosureRow>(tx,sql`SELECT id,operation_id,payload_hash,reason,action_cutoff_sequence::text AS action_cutoff_sequence,owner_id,agent_id
    FROM oid_run_task_closure WHERE id=${run.closure_id} AND run_id=${target.runId} AND task_index=${target.taskIndex} FOR KEY SHARE`);
  const closure=closureRows[0];
  if(!closure||closure.owner_id!==run.owner_id||closure.agent_id!==run.agent_id||sequence(closure.action_cutoff_sequence)!==cutoff||
      closure.operation_id!==run.closure_operation_id||closure.payload_hash!==run.closure_payload_hash||closure.reason!==run.closure_reason)return unavailable('owner_cutoff_mismatch');
  const prepRows=await ownerRows<PreparationRow>(tx,sql`SELECT i.preparation_id::text,i.claim_id::text,i.lease_id::text,i.environment_id,i.release_identity,i.manifest_hash,
      i.task_id,i.case_id,i.case_hash,i.initial_state_sha256,i.execution_identity_hash,i.environment_manifest_sha256,i.application_source_hash,i.created_at,
      l.state AS lease_state,o.status AS observation_status,o.generation_id::text,o.participant_id,o.payer_address,o.baseline_state_sha256,o.fixture_evidence,o.baseline_evidence
    FROM oid_task_preparation_intent i JOIN oid_task_environment_lease l ON l.preparation_id=i.preparation_id AND l.lease_id=i.lease_id
    JOIN LATERAL (SELECT status,generation_id,participant_id,payer_address,baseline_state_sha256,fixture_evidence,baseline_evidence
      FROM oid_task_preparation_observation WHERE preparation_id=i.preparation_id ORDER BY revision DESC LIMIT 1) o ON true
    WHERE i.run_id=${target.runId} AND i.task_index=${target.taskIndex} FOR UPDATE OF i,l`);
  const prep=prepRows[0];
  if(!prep||prep.lease_state!=='leased'||prep.observation_status!=='ready'||!prep.generation_id||!prep.participant_id||!normalizeAddress(prep.payer_address)||
      prep.task_id!=='S4'||prep.release_identity!==run.release_identity||prep.manifest_hash!==run.manifest_hash||prep.baseline_state_sha256!==prep.initial_state_sha256)return unavailable('preparation_unavailable');
  const executionRows=await ownerRows<{env_id:string;generation_id:string;manifest_hash:string;application_source_hash:string;participant_id:string;payer_address:string}>(tx,
    sql`SELECT env_id,generation_id::text,manifest_hash,application_source_hash,participant_id,payer_address FROM oid_task_execution_binding
      WHERE run_id=${target.runId} AND task_index=${target.taskIndex} FOR KEY SHARE`);
  const execution=executionRows[0];
  if(!execution||execution.env_id!==prep.environment_id||execution.generation_id!==prep.generation_id||execution.manifest_hash!==prep.environment_manifest_sha256||
      execution.application_source_hash!==prep.application_source_hash||execution.participant_id!==prep.participant_id||execution.payer_address?.toLowerCase()!==prep.payer_address?.toLowerCase())return unavailable('preparation_unavailable');
  const release=await deps.taskReleaseSource.getValidatedReleaseRecord(run.release_identity,run.manifest_hash,tx);
  if(!release||release.releaseIdentity!==run.release_identity||release.manifestHash!==run.manifest_hash||release.manifest.releaseIdentity!==run.release_identity||release.manifest.manifestHash!==run.manifest_hash)return unavailable('release_binding_mismatch');
  const rawCase=release.manifest.cases[run.mode].find((item)=>item.taskId==='S4');
  if(!rawCase||rawCase.taskId!=='S4'||rawCase.caseId!==prep.case_id||rawCase.caseHash!==prep.case_hash||rawCase.executionIdentityHash!==prep.execution_identity_hash||
      rawCase.initialState.stateSha256!==prep.initial_state_sha256)return unavailable('release_binding_mismatch');
  const taskCase=rawCase as Extract<TaskCase,{taskId:'S4'}>;
  const binding:TaskEvidenceBinding={ownerId:run.owner_id,agentId:run.agent_id,runId:target.runId,environmentId:prep.environment_id,
    releaseIdentity:run.release_identity,manifestHash:run.manifest_hash,caseId:taskCase.caseId,caseHash:taskCase.caseHash,rubricHash:taskCase.rubricHash,taskId:'S4'};
  const identity=release.manifest.executionIdentity;
  const usdcRows=identity.assets.filter((asset)=>asset.assetId==='USDC'&&asset.kind==='erc20'),wethRows=identity.assets.filter((asset)=>asset.assetId==='WETH'&&asset.kind==='erc20');
  const routerRows=identity.contracts.filter((item)=>item.contractId==='swapRouter02');
  const usdc=usdcRows.length===1?normalizeAddress(usdcRows[0]!.address):null,weth=wethRows.length===1?normalizeAddress(wethRows[0]!.address):null;
  const router=routerRows.length===1?normalizeAddress(routerRows[0]!.address):null;
  if(!usdc||!weth||!router||router!==taskCase.objective.spender.toLowerCase()||identity.localChainId!==usdcRows[0]!.chainId||identity.localChainId!==wethRows[0]!.chainId||
      taskCase.objective.tokenAssetId!=='USDC'||taskCase.objective.owner!=='participant')return unavailable('release_binding_mismatch');
  const tokenAddresses={USDC:usdc,WETH:weth} as const;
  let fixture:FixtureProof;
  try{fixture=await loadPreparationEvidence(deps.repositoryRoot,prep,target.runId,target.taskIndex,taskCase);}catch(error){if(error instanceof CollectionUnavailable)return unavailable(error.reasonCode);throw error;}
  const actionRows=await ownerRows<ActionRow>(tx,sql`SELECT a.id::text,a.run_id::text,a.task_index,a.owner_id::text,a.agent_id::text,a.task_id,a.environment_id,
      a.action_sequence::text,a.operation_id,a.payload_hash,a.action_kind,a.command_json,r.receipt_revision,r.receipt_status,r.evidence_hash,r.evidence_path,r.transaction_hash,
      h.revision AS history_revision,h.receipt_status AS history_status,h.evidence_hash AS history_evidence_hash,h.evidence_path AS history_evidence_path,h.transaction_hash AS history_transaction_hash
      ${recoveredOwnerLineageSelectSql}
    FROM oid_run_task_action a JOIN oid_run_task_action_receipt r ON r.action_id=a.id
    ${recoveredOwnerLineageJoinSql}
    LEFT JOIN LATERAL(SELECT revision,receipt_status,evidence_hash,evidence_path,transaction_hash FROM oid_run_task_action_reconciliation
      WHERE action_id=a.id ORDER BY revision DESC LIMIT 1) h ON true WHERE a.run_id=${target.runId} AND a.task_index=${target.taskIndex}
    ORDER BY a.action_sequence FOR UPDATE OF a,r`);
  let actions:LoadedAction[];try{actions=await loadActions(deps.repositoryRoot,run,prep,target.runId,target.taskIndex,cutoff,actionRows);}catch(error){if(error instanceof CollectionUnavailable)return unavailable(error.reasonCode);throw error;}
  const postgres=deps.postgresByEnvironment[prep.environment_id],rpcPort=deps.rpcByEnvironment[prep.environment_id];
  if(!postgres||!rpcPort||rpcPort.environmentId!==prep.environment_id)return unavailable('source_not_configured');
  let before:Awaited<ReturnType<typeof captureCensus>>;try{before=await captureCensus(postgres,prep.environment_id,prep.generation_id,tokenAddresses,router);}catch(error){if(error instanceof CollectionUnavailable)return unavailable(error.reasonCode);throw error;}
  const generation=before.census.generation,payer=normalizeAddress(prep.payer_address),participantId=prep.participant_id;
  if(!payer||generation.env_id!==prep.environment_id||generation.generation_id!==prep.generation_id.toLowerCase()||generation.participant_id!==participantId||
      generation.payer_address!==payer||generation.chain_id!==String(identity.localChainId)||generation.status!=='active'||
      generation.manifest_sha256!==prep.environment_manifest_sha256.toLowerCase()||generation.environment_manifest_sha256!==prep.environment_manifest_sha256.toLowerCase()||
      before.census.paymentsCount!=='0'||before.census.deliveriesCount!=='0')return unavailable('rpc_mapping_incomplete');
  let fixtureRows:{operation:JsonRecord;selected:JsonRecord;events:JsonRecord[]};
  try{fixtureRows=verifyFixtureOperation(before.census,fixture,prep,payer,tokenAddresses,router);}catch(error){if(error instanceof CollectionUnavailable)return unavailable(error.reasonCode);throw error;}
  const actionByBefId=new Map<string,LoadedMutableAction>();
  let readOperationIds:Set<string>;
  try{readOperationIds=validateS4ReadOperations(before.census,actions,prep.environment_id,prep.generation_id,participantId!);}
  catch(error){if(error instanceof CollectionUnavailable)return unavailable(error.reasonCode);throw error;}
  for(const action of actions){if(action.category!=='mutable')continue;const id=String(action.evidence.befOperationId).toLowerCase();
    if(actionByBefId.has(id))return unavailable('action_evidence_unavailable');actionByBefId.set(id,action);}
  let rpc=new RpcRecorder(rpcPort),chainId:bigint,baseline:S4Checkpoint,final:S4Checkpoint,blocks:BefS4RunObservationPacket['rpc']['intervalBlocks'],approvals:S4ApprovalLog[],transfers:S4TransferLog[],receipts:S4Receipt[];
  try{
    const chain=hexUint(await rpc.request('eth_chainId',[]));if(chain===null||chain!==BigInt(identity.localChainId))return unavailable('rpc_identity_mismatch');chainId=chain;
    const fixtureTx=rpcTransaction(await rpc.request('eth_getTransactionByHash',[fixture.transactionHash]));
    const fixtureReceiptRaw=await rpc.request('eth_getTransactionReceipt',[fixture.transactionHash]);
    if(!fixtureTx) return unavailable('preparation_unavailable');
    const fixtureReceipt=rpcReceipt(fixtureReceiptRaw,fixtureTx);
    if(!fixtureReceipt||fixtureReceipt.status!=='success'||fixtureTx.from!==payer||fixtureTx.to!==usdc||fixtureTx.chainId!==chain.toString()||
        fixtureTx.blockNumber!==fixture.blockNumber.toString()||fixtureTx.blockHash!==fixture.blockHash||fixtureTx.input!==expectedInput({kind:'approve',spender:router,amountUnits:fixture.amountUnits.toString()})||
        fixtureTx.valueWei!=='0'||fixtureReceipt.gasCostWei!==String((BigInt(String(fixtureReceiptRaw && isRecord(fixtureReceiptRaw)?hexUint(fixtureReceiptRaw.gasUsed):0n))*BigInt(String(fixtureReceiptRaw && isRecord(fixtureReceiptRaw)?hexUint(fixtureReceiptRaw.effectiveGasPrice):0n))))) {
      return unavailable('preparation_unavailable');
    }
    const fixtureLogs=Array.isArray(isRecord(fixtureReceiptRaw)?fixtureReceiptRaw.logs:null)?(fixtureReceiptRaw as JsonRecord).logs as unknown[]:[];
    const fixtureApproval=fixtureLogs.map((raw)=>decodeApproval(raw,usdc)).filter((item):item is S4ApprovalLog=>item!==null);
    if(fixtureApproval.length!==1||fixtureApproval[0]!.owner!==payer||fixtureApproval[0]!.spender!==router||fixtureApproval[0]!.amountUnits!==fixture.amountUnits.toString()||
        fixtureApproval[0]!.transactionHash!==fixture.transactionHash||!isRecord(fixtureReceiptRaw)||fixtureReceiptRaw.status!=='0x1')return unavailable('preparation_unavailable');
    const fixtureParentCheckpoint=await readCheckpoint(rpc,identity,taskCase,payer,fixture.preState.blockNumber);
    await verifyCode(rpc,identity,fixture.preState.blockNumber);
    if(!s4FixtureParentCheckpointMatches(taskCase,fixture.preState,fixtureParentCheckpoint))return unavailable('baseline_mismatch');
    const baselineHeader=blockHeader(await rpc.request('eth_getBlockByNumber',[`0x${fixture.baselineNumber.toString(16)}`,false]),fixture.baselineNumber);
    if(baselineHeader.hash!==fixture.baselineHash||fixture.baselineNumber<fixture.blockNumber)return unavailable('baseline_mismatch');
    baseline=await readCheckpoint(rpc,identity,taskCase,payer,fixture.baselineNumber);
    if(baseline.blockHash!==fixture.baselineHash||!sameCanonical({balances:baseline.balances,allowances:baseline.allowances,deliveredComponentIds:taskCase.initialState.deliveredComponentIds,
      fulfilledObligationIds:taskCase.initialState.fulfilledObligationIds},caseProjection(taskCase)))return unavailable('baseline_mismatch');
    await verifyCode(rpc,identity,fixture.baselineNumber);
    baseline.participantTransactionCount=String(hexUint(await rpc.request('eth_getTransactionCount',[payer,`0x${fixture.baselineNumber.toString(16)}`]))??'');
    if(!UINT.test(baseline.participantTransactionCount))return unavailable('rpc_observation_unavailable');
    const head=hexUint(await rpc.request('eth_blockNumber',[]));if(head===null||head<fixture.baselineNumber)return unavailable('rpc_observation_unavailable');
    final=await readCheckpoint(rpc,identity,taskCase,payer,head);await verifyCode(rpc,identity,head);
    final.participantTransactionCount=String(hexUint(await rpc.request('eth_getTransactionCount',[payer,`0x${head.toString(16)}`]))??'');
    if(!UINT.test(final.participantTransactionCount))return unavailable('rpc_observation_unavailable');
    const blockCount=head-fixture.baselineNumber;if(blockCount>BigInt(MAX_BLOCKS))return unavailable('rpc_interval_too_large');
    const blockMap=new Map<string,{number:string;hash:string;parentHash:string;transactionCount:number;participantTransactions:S4Transaction[];allTransactions:Array<{hash:string;from:string}>}>();
    let prev=baseline.blockHash;
    for(let number=fixture.baselineNumber+1n;number<=head;number+=1n){
      const raw=await rpc.request('eth_getBlockByNumber',[`0x${number.toString(16)}`,true]);
      if(!isRecord(raw)||!Array.isArray(raw.transactions))throw new CollectionUnavailable('rpc_observation_unavailable');
      const header=blockHeader(raw,number);if(header.parentHash!==prev)throw new CollectionUnavailable('rpc_mapping_incomplete');prev=header.hash;
      const allTransactions:Array<{hash:string;from:string}>=[],participantTransactions:S4Transaction[]=[];
      for(const item of raw.transactions){if(!isRecord(item))throw new CollectionUnavailable('rpc_observation_unavailable');const hash=normalizeHash(item.hash),from=normalizeAddress(item.from);
        if(!hash||!from)throw new CollectionUnavailable('rpc_observation_unavailable');allTransactions.push({hash,from});
        if(from===payer){const txValue=rpcTransaction(item);if(!txValue||txValue.blockNumber!==number.toString()||txValue.blockHash!==header.hash||txValue.chainId!==chain.toString())throw new CollectionUnavailable('rpc_mapping_incomplete');participantTransactions.push(txValue);}
      }
      blockMap.set(number.toString(),{number:number.toString(),hash:header.hash,parentHash:header.parentHash,transactionCount:raw.transactions.length,participantTransactions,allTransactions});
    }
    if(prev!==final.blockHash)throw new CollectionUnavailable('rpc_mapping_incomplete');
    const participants=[...blockMap.values()].flatMap((item)=>item.participantTransactions);
    const beforeNonce=BigInt(baseline.participantTransactionCount),afterNonce=BigInt(final.participantTransactionCount);
    if(afterNonce<beforeNonce||afterNonce-beforeNonce!==BigInt(participants.length))throw new CollectionUnavailable('rpc_mapping_incomplete');
    const nonces=participants.map((item)=>BigInt(item.nonce)).sort((a,b)=>a<b?-1:a>b?1:0);
    if(nonces.some((nonce,index)=>nonce!==beforeNonce+BigInt(index)))throw new CollectionUnavailable('rpc_mapping_incomplete');
    const operationTxs=before.census.operations.filter((op)=>op.operation_id!==fixture.operationId&&
      !readOperationIds.has(String(op.operation_id).toLowerCase()));
    if(operationTxs.length!==actions.filter((action)=>action.category==='mutable').length||operationTxs.length!==participants.length||
        operationTxs.some((op)=>!normalizeHash(op.transaction_hash)||!participants.some((p)=>p.hash===op.transaction_hash)))throw new CollectionUnavailable('rpc_mapping_incomplete');
    const fixtureBlockRaw=await rpc.request('eth_getBlockByNumber',[`0x${fixture.blockNumber.toString(16)}`,true]);
    const fixtureBlock=blockHeader(fixtureBlockRaw,fixture.blockNumber);
    if(!isRecord(fixtureBlockRaw)||!Array.isArray(fixtureBlockRaw.transactions)||fixtureBlock.hash!==fixture.blockHash||
        fixtureBlock.parentHash!==fixture.parentHash||fixtureBlockRaw.transactions.length!==1||
        !sameCanonical(rpcTransaction(fixtureBlockRaw.transactions[0]),fixtureTx))throw new CollectionUnavailable('preparation_unavailable');
    const taskTransactions=participants;
    const txByHash=new Map(taskTransactions.map((item)=>[item.hash,item]));
    const allReceipts:S4Receipt[]=[];
    for(const txValue of taskTransactions){
      const receiptValue=await rpc.request('eth_getTransactionReceipt',[txValue.hash]);
      const receipt=rpcReceipt(receiptValue,txValue);if(!receipt)throw new CollectionUnavailable('rpc_mapping_incomplete');
      allReceipts.push(receipt);
    }
    const logs=head===fixture.baselineNumber?{approvals:[] as S4ApprovalLog[],transfers:[] as S4TransferLog[]}:
      await readLogs(rpc,tokenAddresses,payer,fixture.baselineNumber+1n,head);
    const canonicalBlocks=new Map([...blockMap.values()].map((item)=>[item.number,item.hash]));
    for(const log of [...logs.approvals,...logs.transfers]){
      if(canonicalBlocks.get(log.blockNumber)!==log.blockHash||!txByHash.has(log.transactionHash))throw new CollectionUnavailable('rpc_mapping_incomplete');
    }
    const beforeCensusOps=new Map(before.census.operations.map((op)=>[String(op.operation_id),op]));
    const selectedByOp=new Map(before.census.selectedExecutions.map((row)=>[String(row.operation_id),row]));
    const eventsByOp=new Map<string,JsonRecord[]>();for(const event of before.census.selectedEvents){const id=String(event.operationId),list=eventsByOp.get(id)??[];list.push(event);eventsByOp.set(id,list);}
    const sourceByTx=new Map<string,TransferSource>();
    for(const op of operationTxs){
      const txHash=normalizeHash(op.transaction_hash),selected=selectedByOp.get(String(op.operation_id));
      const action=actionByBefId.get(String(op.operation_id));
      const txValue=txHash?txByHash.get(txHash):undefined,receipt=txValue?allReceipts.find((item)=>item.transactionHash===txValue.hash):undefined;
      if(!txHash||!selected||!txValue||!receipt||typeof op.idempotency_key_sha256!=='string'||!HASH.test(op.idempotency_key_sha256)||
          !['approve','transfer'].includes(String(op.operation_kind))||
          selected.action_kind!==op.operation_kind||!['settled','reverted'].includes(String(op.status))||
          op.receipt_status!==receipt.status||(op.status==='settled')!==(receipt.status==='success')||
          normalizeHash(selected.transaction_hash)!==txHash||selected.outcome!==receipt.status||
          (op.response_sha256!==null&&(typeof op.response_sha256!=='string'||!HASH.test(op.response_sha256))))throw new CollectionUnavailable('rpc_mapping_incomplete');
      const selectedPublic=isRecord(selected.selected_action)?selected.selected_action:null;
      if(!selectedPublic)throw new CollectionUnavailable('rpc_mapping_incomplete');
      const command=commandFromSelected(selectedPublic,taskCase);
      if(!command||command.kind!==op.operation_kind||!isRecord(selected.transaction_intent)||!isRecord(selected.measurement)||!isRecord(selected.prestate))throw new CollectionUnavailable('rpc_mapping_incomplete');
      if(action){
        const expectedIdempotencySha256=sha256(`task-action-${action.row.id}`);
        if(op.idempotency_key_sha256!==expectedIdempotencySha256||action.evidence.transactionHash?.toLowerCase()!==txHash||action.evidence.receiptStatus!==receipt.status||
            action.evidence.befOperationId?.toLowerCase()!==String(op.operation_id)||
            !sameCanonical(action.command,command)||normalizeAddress((action.evidence.participantToolResponse?.selectedAction as JsonRecord|undefined)?.token)!==
              (command.kind==='approve'?selectedPublic.tokenAddress:selectedPublic.tokenAddress))throw new CollectionUnavailable('rpc_mapping_incomplete');
      }
      const intent=transactionIntent(selected.transaction_intent),measurement=isRecord(selected.measurement)?selected.measurement:null;
      const measuredTransaction=measurement&&isRecord(measurement.transaction)?measurement.transaction:null;
      const measuredReceipt=measurement&&isRecord(measurement.receipt)?measurement.receipt:null;
      if(!intent||!measurement||!measuredTransaction||!measuredReceipt||intent.hash!==txHash||intent.from!==payer||intent.to!==selectedPublic.tokenAddress||
          intent.input!==expectedInput(selectedPublic)||intent.valueWei!=='0'||!matchesOriginalTransactionIntent(measuredTransaction,intent)||
          String(intent.chainId)!==txValue.chainId||intent.nonce!==txValue.nonce||intent.gasLimit!==txValue.gasLimit||
          measuredTransaction.blockNumber!==txValue.blockNumber||measuredTransaction.blockHash!==txValue.blockHash||
          measuredTransaction.transactionIndex!==txValue.transactionIndex||
          normalizeHash(measuredReceipt.transactionHash)!==txHash||normalizeAddress(measuredReceipt.from)!==payer||
          normalizeAddress(measuredReceipt.to)!==selectedPublic.tokenAddress||measuredReceipt.status!==receipt.status||
          String(measuredReceipt.blockNumber)!==receipt.blockNumber||normalizeHash(measuredReceipt.blockHash)!==receipt.blockHash||
          String(measuredReceipt.gasUsed)!==receipt.gasUsed||String(measuredReceipt.effectiveGasPrice)!==receipt.effectiveGasPriceWei||
          String(measuredReceipt.gasCostWei)!==receipt.gasCostWei)throw new CollectionUnavailable('rpc_mapping_incomplete');
      const events=eventsByOp.get(String(op.operation_id))??[];
      const selectedBound=events[0]?.eventPayload,prestateBound=events[1]?.eventPayload,intentBound=events[2]?.eventPayload,receiptBound=events[3]?.eventPayload;
      if(events.length!==4||events.map((item)=>item.eventKind).join(',')!=='selected_action_bound,prestate_observed,original_tx_hash_bound,receipt_finalized'||
          !isRecord(selectedBound)||!isRecord(prestateBound)||!isRecord(intentBound)||!isRecord(receiptBound)||
          events[0]!.transactionHash!==null||events[1]!.transactionHash!==null||events[2]!.transactionHash!==txHash||events[3]!.transactionHash!==txHash||
          !sameCanonical(selectedBound.selectedAction,selectedPublic)||selectedBound.actionKind!==op.operation_kind||
          selectedBound.requestSha256!==op.request_sha256||!sameCanonical(prestateBound.prestate,selected.prestate)||
          intentBound.requestSha256!==op.request_sha256||intentBound.transactionHash!==txHash||!sameCanonical(intentBound.transactionIntent,intent)||
          receiptBound.outcome!==receipt.status||receiptBound.measurementSha256!==measurement.measurementSha256)throw new CollectionUnavailable('rpc_mapping_incomplete');
      if(action?.evidence.recoverySource){
        const facts=recoveredSourceFacts(op,selected,before.census.generation,events);
        if(!facts||!recoverySourceEvidenceMatchesFacts(action.evidence.recoverySource,facts)||
            !recoveredToolResponseMatchesSelection(action,selected,txHash,receipt.status))throw new CollectionUnavailable('rpc_mapping_incomplete');
      }
      if(!action&&op.operation_id===fixture.operationId)throw new CollectionUnavailable('rpc_mapping_incomplete');
      sourceByTx.set(txHash,{op,selected,action:action??null,tx:txValue,receipt,selectedAction:selectedPublic,actionSequence:action?.sequence??0});
    }
    if(sourceByTx.size!==taskTransactions.length||actions.some((item)=>item.category==='mutable'&&
        !sourceByTx.has(String(item.evidence.transactionHash).toLowerCase())))throw new CollectionUnavailable('rpc_mapping_incomplete');
    const expectedCosts:Array<{operationId:string;receipt:S4Receipt;parentHash:string}>=[
      {operationId:fixture.operationId,receipt:fixtureReceipt,parentHash:fixture.parentHash},
    ];
    for(const source of sourceByTx.values()){
      const parentHash=blockMap.get(source.tx.blockNumber)?.parentHash;
      if(!parentHash)throw new CollectionUnavailable('rpc_mapping_incomplete');
      expectedCosts.push({operationId:String(source.op.operation_id),receipt:source.receipt,parentHash});
    }
    verifyS4CostRows(before.census,expectedCosts,prep.environment_id,prep.generation_id,payer,prep.environment_manifest_sha256);
    approvals=logs.approvals;transfers=logs.transfers;receipts=allReceipts;
    blocks=[...blockMap.values()].map(({number,hash,parentHash,transactionCount,participantTransactions})=>({number,hash,parentHash,transactionCount,participantTransactions}));
    const txOrder=[...sourceByTx.values()].sort((a,b)=>BigInt(a.tx.blockNumber)<BigInt(b.tx.blockNumber)?-1:BigInt(a.tx.blockNumber)>BigInt(b.tx.blockNumber)?1:
      BigInt(a.tx.transactionIndex)<BigInt(b.tx.transactionIndex)?-1:BigInt(a.tx.transactionIndex)>BigInt(b.tx.transactionIndex)?1:0);
    const dynamicKeys=new Map<string,{owner:string;tokenAssetId:string;spender:string}>();
    for(const log of approvals){const asset=log.tokenAddress===usdc?'USDC':log.tokenAddress===weth?'WETH':null;if(!asset)throw new CollectionUnavailable('rpc_mapping_incomplete');
      const key=allowanceKey('participant',asset,log.spender);dynamicKeys.set(key,{owner:'participant',tokenAssetId:asset,spender:log.spender});}
    const baselineAllowances:Array<{owner:string;tokenAssetId:'USDC'|'WETH';spender:string;amountUnits:string}>=[];
    for(const [key,item] of dynamicKeys){const token=tokenAddresses[item.tokenAssetId as 'USDC'|'WETH'],owner=payer;
      const initial=await readAllowance(rpc,token,owner,item.spender,fixture.baselineNumber);
      baselineAllowances.push({...item,tokenAssetId:item.tokenAssetId as 'USDC'|'WETH',amountUnits:initial.toString()});void key;}
    let allowanceHistory:Map<string,bigint>,approvalChangeByTx:Map<string,ReturnType<typeof deriveS4AllowanceHistory>['changes'][number]>;
    try{
      const derived=deriveS4AllowanceHistory({participant:payer,router,tokenAddresses,baseline:baselineAllowances,
        transactions:txOrder.map((source)=>({transactionHash:source.tx.hash,actionSequence:source.actionSequence,
          receiptStatus:source.receipt.status,action:{kind:source.selectedAction.kind as 'approve'|'transfer',
            tokenAssetId:source.selectedAction.tokenAssetId as 'USDC'|'WETH',tokenAddress:String(source.selectedAction.tokenAddress),
            ...(source.selectedAction.kind==='approve'?{spender:String(source.selectedAction.spender)}:{}),
            ...(typeof source.selectedAction.amountUnits==='string'?{amountUnits:source.selectedAction.amountUnits}:{})}})),
        approvals});
      allowanceHistory=derived.finalAmounts;approvalChangeByTx=new Map(derived.changes.map((item)=>[item.transactionHash,item]));
    }catch{throw new CollectionUnavailable('rpc_mapping_incomplete');}
    const observationEvents:Array<{sequence:number;kind:'allowance_change'|'transfer'|'expense';txHash:string;actionSequence:number;data:JsonRecord}> = [];
    let nextSequence=1;
    const approvalByTx=new Map<string,S4ApprovalLog[]>();for(const log of approvals){const list=approvalByTx.get(log.transactionHash)??[];list.push(log);approvalByTx.set(log.transactionHash,list);}
    for(const source of txOrder){
      const action=source.selectedAction;
      const txApprovals=approvalByTx.get(source.tx.hash)??[];
      if(action.kind==='approve'){
        const change=approvalChangeByTx.get(source.tx.hash);
        if(source.receipt.status==='success'&&!change||source.receipt.status==='reverted'&&change||txApprovals.length!==(change?1:0)) {
          throw new CollectionUnavailable('rpc_mapping_incomplete');
        }
        if(change){
          observationEvents.push({sequence:nextSequence++,kind:'allowance_change',txHash:source.tx.hash,actionSequence:source.actionSequence,
            data:{owner:change.owner,tokenAssetId:change.tokenAssetId,spender:change.spender,amountBeforeUnits:change.amountBeforeUnits,
              amountAfterUnits:change.amountAfterUnits,transactionHash:source.tx.hash}});
        }
      } else if(txApprovals.length) throw new CollectionUnavailable('rpc_mapping_incomplete');
      const txTransfers=transfers.filter((log)=>log.transactionHash===source.tx.hash);
      for(const log of txTransfers){
        const asset=log.tokenAddress===usdc?'USDC':log.tokenAddress===weth?'WETH':null;if(!asset)throw new CollectionUnavailable('rpc_mapping_incomplete');
        observationEvents.push({sequence:nextSequence++,kind:'transfer',txHash:source.tx.hash,actionSequence:source.actionSequence,
          data:{from:'participant',to:log.to,assetId:asset,amountUnits:log.amountUnits,receiptStatus:source.receipt.status,transactionHash:source.tx.hash,operation:'principal'}});
      }
      observationEvents.push({sequence:nextSequence++,kind:'expense',txHash:source.tx.hash,actionSequence:source.actionSequence,
        data:{component:'participant_gas',sourceEffectId:`bef-operation:${String(source.op.operation_id)}`,gasUsed:source.receipt.gasUsed,
          effectiveGasPriceWei:source.receipt.effectiveGasPriceWei,receiptStatus:source.receipt.status,transactionHash:source.tx.hash}});
    }
    const finalAllowances:Array<{owner:string;tokenAssetId:string;spender:string;amountUnits:string}>=[...final.allowances];
    const existingFinal=new Set(finalAllowances.map((item)=>allowanceKey(item.owner,item.tokenAssetId,item.spender)));
    for(const [key,item] of dynamicKeys){
      const token=tokenAddresses[item.tokenAssetId as 'USDC'|'WETH'];const amount=await readAllowance(rpc,token,payer,item.spender,head);
      const history=allowanceHistory.get(key);if(history!==undefined&&history!==amount)throw new CollectionUnavailable('rpc_mapping_incomplete');
      const current=finalAllowances.find((value)=>allowanceKey(value.owner,value.tokenAssetId,value.spender)===key);
      if(current){if(BigInt(current.amountUnits)!==amount)throw new CollectionUnavailable('rpc_mapping_incomplete');}
      else finalAllowances.push({...item,amountUnits:amount.toString()});
    }
    // Every task-period approval event must have a BEF-selected transaction and was applied in log order above.
    for(const log of approvals){const source=sourceByTx.get(log.transactionHash);if(!source||source.selectedAction.kind!=='approve')throw new CollectionUnavailable('rpc_mapping_incomplete');}
    const expectedNative=BigInt(baseline.balances.find((item)=>item.account==='participant'&&item.assetId==='ETH')?.amountUnits??'-1')-
      receipts.reduce((sum,item)=>sum+BigInt(item.gasCostWei),0n);
    const finalNative=BigInt(final.balances.find((item)=>item.account==='participant'&&item.assetId==='ETH')?.amountUnits??'-2');
    if(expectedNative!==finalNative)throw new CollectionUnavailable('rpc_mapping_incomplete');
    const finalProjection=projectCaseState(final,taskCase,finalAllowances.filter((item)=>!existingFinal.has(allowanceKey(item.owner,item.tokenAssetId,item.spender))));
    const baselineAgain=blockHeader(await rpc.request('eth_getBlockByNumber',[`0x${fixture.baselineNumber.toString(16)}`,false]),fixture.baselineNumber);
    const finalAgain=blockHeader(await rpc.request('eth_getBlockByNumber',[`0x${head.toString(16)}`,false]),head);
    if(baselineAgain.hash!==baseline.blockHash||finalAgain.hash!==final.blockHash)throw new CollectionUnavailable('rpc_mapping_incomplete');
    const after=await captureCensus(postgres,prep.environment_id,prep.generation_id,tokenAddresses,router);
    if(!sameCanonical(before.census,after.census)||after.census.generation.status!=='active')return unavailable('observer_census_changed');
    const packetBase={schemaVersion:'bts-s4-run-observation-capture/v1' as const,classification:'run_bound_observations_candidate_not_grade' as const,binding,
      closure:{closureId:closure.id,actionCutoffSequence:cutoff,reconciledActionSequence:reconciled},
      execution:{preparationId:prep.preparation_id,leaseId:prep.lease_id,generationId:prep.generation_id,environmentId:prep.environment_id,
        environmentManifestHash:prep.environment_manifest_sha256.toLowerCase(),applicationSourceHash:prep.application_source_hash.toLowerCase(),
        executionIdentityHash:prep.execution_identity_hash.toLowerCase(),initialStateSha256:prep.initial_state_sha256.toLowerCase()},
      preparation:{fixtureEvidence:fixture.reference,baselineEvidence:fixture.baselineReference,baselineBlockNumber:fixture.baselineNumber.toString(),baselineBlockHash:fixture.baselineHash,
        fixtureOperationId:fixture.operationId,fixtureTransactionHash:fixture.transactionHash,fixtureBlockNumber:fixture.blockNumber.toString(),fixtureBlockHash:fixture.blockHash,fixtureProofSha256:fixture.proofSha256},
      ownerActions:actions.map((action)=>({actionId:action.row.id,actionSequence:action.sequence,ownerOperationId:action.row.operation_id,actionKind:action.row.action_kind,
        commandSha256:action.row.payload_hash.toLowerCase(),actionEvidence:action.evidenceReference,befOperationId:String(action.evidence.befOperationId).toLowerCase(),
        transactionHash:action.category==='mutable'?String(action.evidence.transactionHash).toLowerCase():null})),
      bef:{session:before.session,before:before.census,after:after.census,censusSha256:sha256CanonicalTaskJson(before.census).toLowerCase()},
      rpc:{localChainId:chainId.toString(),baseline,final,intervalBlocks:blocks,approvals,transfers,receipts,responseHashes:rpc.responseHashes}};
    if(hasSecret(packetBase)||Buffer.byteLength(canonicalTaskJson(packetBase),'utf8')>MAX_PACKET_BYTES)return unavailable('capture_evidence_unavailable');
    const evidence=await deps.evidenceSink.write(packetBase);
    if(!ref(evidence)||!evidence.path.startsWith(OBSERVATION_ROOT))return unavailable('capture_evidence_unavailable');
    const baseMeta=(sequenceValue:number,actionSequence:number,observationId:string)=>({observationId,sequence:sequenceValue,actionSequence,source:'persisted_observer' as const,binding,evidence});
    const changes:PersistedTaskObservations['allowanceChanges']=observationEvents.filter((item)=>item.kind==='allowance_change').map((item)=>({
      kind:'allowance_change' as const,...baseMeta(item.sequence,item.actionSequence,`s4-allowance-${item.txHash.slice(2)}-${item.sequence}`),
      owner:String(item.data.owner),tokenAssetId:String(item.data.tokenAssetId),spender:String(item.data.spender),
      amountBeforeUnits:String(item.data.amountBeforeUnits),amountAfterUnits:String(item.data.amountAfterUnits),transactionHash:item.txHash,
    }));
    const typedTransfers:PersistedTaskObservations['transfers']=observationEvents.filter((item)=>item.kind==='transfer').map((item)=>({
      kind:'transfer' as const,...baseMeta(item.sequence,item.actionSequence,`s4-transfer-${item.txHash.slice(2)}-${item.sequence}`),
      from:String(item.data.from),to:String(item.data.to),assetId:String(item.data.assetId),amountUnits:String(item.data.amountUnits),
      receiptStatus:item.data.receiptStatus as 'success'|'reverted',transactionHash:item.txHash,operation:'principal' as const,
    }));
    const expenses:PersistedTaskObservations['expenses']=observationEvents.filter((item)=>item.kind==='expense').map((item)=>({
      kind:'expense' as const,...baseMeta(item.sequence,item.actionSequence,`s4-gas-${item.txHash.slice(2)}`),component:'participant_gas' as const,
      sourceEffectId:String(item.data.sourceEffectId),gasUsed:String(item.data.gasUsed),effectiveGasPriceWei:String(item.data.effectiveGasPriceWei),
      receiptStatus:item.data.receiptStatus as 'success'|'reverted',transactionHash:item.txHash,
    }));
    const finalSequence=nextSequence;
    const finalState:PersistedTaskObservations['finalStates'][number]={kind:'final_state',...baseMeta(finalSequence,cutoff,`s4-final-${target.runId}-${target.taskIndex}-${cutoff}`),
      balances:final.balances,allowances:finalProjection.allowances};
    const observationCutoffSequence=finalSequence;
    const observations:PersistedTaskObservations={schemaVersion:'bts-task-observations/v1',binding,coveredThroughSequence:observationCutoffSequence,captureEvidence:evidence,
      coverage:{transfers:'complete',balances:'complete',allowances:'complete'},transfers:typedTransfers,payments:[],stateMutations:[],
      finalStates:[finalState],allowanceChanges:changes,allowanceUses:[],answers:[],selections:[],deliveries:[],trades:[],conversions:[],expenses};
    const candidate:TaskObservationBundleCandidate={schemaVersion:'bts-task-observation-bundle-candidate/v1',observationCutoffSequence,cutoffStatus:'authoritative',cutoffEvidence:evidence,observations};
    return {status:'candidate',candidate,evidence,classification:'run_bound_observations_candidate_not_grade'};
  }catch(error){if(error instanceof CollectionUnavailable)return unavailable(error.reasonCode);return unavailable('rpc_observation_unavailable');}
}

export async function collectBefS4TaskObservationCandidate(deps:BefS4ObservationCollectorDependencies,target:{runId:string;taskIndex:number}):Promise<BefS4ObservationCollectionResult>{
  if(!UUID.test(target.runId)||!Number.isSafeInteger(target.taskIndex)||target.taskIndex<0||target.taskIndex>11)return unavailable('invalid_target');
  try{return await deps.db.transaction((tx)=>collectLocked(deps,target,tx));}
  catch(error){if(error instanceof CollectionUnavailable)return unavailable(error.reasonCode);throw error;}
}
