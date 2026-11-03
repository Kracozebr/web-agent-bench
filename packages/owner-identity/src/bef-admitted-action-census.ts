import { createHash } from 'node:crypto';
import {rejectedSwapGuardMarkerMatches} from './task-rejected-swap-proof.js';
import { constants as fsConstants } from 'node:fs';
import { lstat, open, realpath } from 'node:fs/promises';
import { isAbsolute, relative, resolve, sep } from 'node:path';
import { sql } from 'drizzle-orm';
import type { OwnerDatabase } from './db.js';
import { TaskActionCommandSchema, type TaskActionCommand } from './task-action-service.js';
import { readOnlyToolResponseMatches } from './bef-task-executor.js';
import { observationHealthMatches } from './bef-observation-health.js';
import { recoverySourceEvidenceEnvelope } from './bef-recovery-observation.js';
import type { TaskEvidenceBinding } from './task-evaluator.js';
import { canonicalTaskJson, sha256CanonicalTaskJson, type EvidenceReference } from './task-release.js';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const HASH = /^[0-9a-f]{64}$/;
const TX = /^0x[0-9a-f]{64}$/;
const OP = /^[A-Za-z0-9_-]{12,128}$/;
const ACTION_ROOT = 'artifacts/runs/owner-identity-bef-task-coordinator/action/';
const BOUNDARY = 'actual_tool_http_x402_local_evm_application_store' as const;
const MAX_ACTIONS = 256;
const MAX_BYTES = 2 * 1024 * 1024;
// Same aggregate ceiling as TaskSealedEvidenceSource; fail before decoding/retaining over-budget docs.
const MAX_TOTAL_BYTES = 32 * 1024 * 1024;
const DOCUMENT_KEYS = new Set([
  'schema', 'actionId', 'runId', 'taskIndex', 'actionSequence', 'ownerOperationId', 'actionKind',
  'commandSha256', 'environmentId', 'generationId', 'manifestSha256', 'applicationSourceSha256',
  'idempotencyKey', 'status', 'reasonCode', 'requestStartedAt', 'requestFinishedAt', 'httpStatus',
  'befOperationId', 'transactionHash', 'outcome', 'receiptStatus', 'rawResponseSha256',
  'participantToolResponse', 'receiptGasUsed', 'receiptEffectiveGasPriceWei', 'paymentProtocol',
  'environmentHealth', 'recoverySource', 'rejectionProof',
]);

export type AdmittedActionFamily = 'read' | 'payment' | 'chain';
export type AdmittedActionExecution = {
  preparationId: string; leaseId: string; generationId: string; environmentId: string;
  environmentManifestHash: string; applicationSourceHash: string; executionIdentityHash: string;
  initialStateSha256: string;
};
export type AdmittedActionClosure = {
  closureId: string; operationId: string | null; payloadHash: string;
  reason: 'agent_finish' | 'task_deadline' | 'run_deadline';
  actionCutoffSequence: number; reconciledActionSequence: number;
};
/** Selected under the same owner snapshot as binding, preparation and closure. */
export type AdmittedActionRow = {
  id: string; run_id: string; task_index: number; owner_id: string; agent_id: string;
  task_id: string; environment_id: string; action_sequence: string | number;
  operation_id: string; payload_hash: string; action_kind: string; command_json: unknown;
  receipt_revision: number; receipt_status: string; evidence_hash: string | null;
  evidence_path: string | null; transaction_hash: string | null;
  history_revision: number | null; history_status: string | null;
  history_evidence_hash: string | null; history_evidence_path: string | null;
  history_transaction_hash: string | null;
  tool_response_json: unknown; tool_response_hash: string | null;
  history_tool_response_json: unknown; history_tool_response_hash: string | null;
};
export type AdmittedActionEntry = {
  actionId: string; actionSequence: number; ownerOperationId: string;
  actionKind: TaskActionCommand['kind']; command: TaskActionCommand; commandSha256: string;
  receiptRevision: number; receiptStatus: 'observed' | 'rejected_before_execution';
  transactionHash: string | null; family: AdmittedActionFamily;
  actionEvidence: EvidenceReference; document: Record<string, unknown>;
};
export type AdmittedActionCensus = {
  schemaVersion: 'bts-admitted-action-census/v1';
  classification: 'identity_and_evidence_census_not_effect_proof';
  binding: TaskEvidenceBinding; taskIndex: number; execution: AdmittedActionExecution;
  closure: AdmittedActionClosure; entries: AdmittedActionEntry[];
};
export type AdmittedActionProof = Pick<AdmittedActionEntry,
  'actionId' | 'actionSequence' | 'ownerOperationId' | 'actionKind' | 'commandSha256' |
  'receiptStatus' | 'transactionHash' | 'actionEvidence'>;
export type AdmittedActionTarget = { runId: string; taskIndex: number };
type OwnerTransaction = Parameters<Parameters<OwnerDatabase['transaction']>[0]>[0];

/** No nested transaction or implicit lock: the caller owns the authoritative snapshot/fence. */
export async function loadAdmittedActionRows(tx: Pick<OwnerTransaction, 'execute'>,
  target: AdmittedActionTarget): Promise<AdmittedActionRow[]> {
  if (!UUID.test(target.runId) || !Number.isSafeInteger(target.taskIndex) || target.taskIndex < 0 || target.taskIndex > 11) fail();
  // LEFT JOIN deliberately retains an admitted action with a missing receipt/history; it must not
  // disappear from the census. Such a row fails validation instead of becoming absence-of-effect.
  return await tx.execute(sql`SELECT a.id::text AS id,a.run_id::text AS run_id,a.task_index,
      a.owner_id::text AS owner_id,a.agent_id::text AS agent_id,a.task_id,a.environment_id,
      a.action_sequence::text AS action_sequence,a.operation_id,a.payload_hash,a.action_kind,a.command_json,
      r.receipt_revision,r.receipt_status,r.evidence_hash,r.evidence_path,r.transaction_hash,
      r.tool_response_json,r.tool_response_hash,h.revision AS history_revision,h.receipt_status AS history_status,
      h.evidence_hash AS history_evidence_hash,h.evidence_path AS history_evidence_path,
      h.transaction_hash AS history_transaction_hash,h.tool_response_json AS history_tool_response_json,
      h.tool_response_hash AS history_tool_response_hash
    FROM oid_run_task_action a
    LEFT JOIN oid_run_task_action_receipt r ON r.action_id=a.id
    LEFT JOIN LATERAL (SELECT revision,receipt_status,evidence_hash,evidence_path,transaction_hash,
      tool_response_json,tool_response_hash FROM oid_run_task_action_reconciliation
      WHERE action_id=a.id ORDER BY revision DESC LIMIT 1) h ON true
    WHERE a.run_id=${target.runId} AND a.task_index=${target.taskIndex}
    ORDER BY a.action_sequence LIMIT ${MAX_ACTIONS + 1}`) as unknown as AdmittedActionRow[];
}

export class AdmittedActionCensusUnavailable extends Error {
  constructor(readonly reasonCode: 'owner_cutoff_mismatch' | 'action_evidence_unavailable' | 'action_coverage_incomplete') {
    super(reasonCode);
  }
}
function fail(reasonCode: AdmittedActionCensusUnavailable['reasonCode'] = 'action_evidence_unavailable'): never {
  throw new AdmittedActionCensusUnavailable(reasonCode);
}
function record(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}
function json(value: unknown): unknown {
  if (typeof value !== 'string') return value;
  try { return JSON.parse(value); } catch { return fail(); }
}
function integer(value: unknown): number | null {
  if (typeof value !== 'string' && typeof value !== 'number') return null;
  if (typeof value === 'string' && !/^(0|[1-9][0-9]*)$/.test(value)) return null;
  const n = Number(value);
  return Number.isSafeInteger(n) && n >= 0 ? n : null;
}
function normalizedTx(value: unknown): string | null {
  return typeof value === 'string' && TX.test(value.toLowerCase()) ? value.toLowerCase() : null;
}
function validReference(ref: EvidenceReference): boolean {
  return ref.boundary === BOUNDARY && typeof ref.sha256 === 'string' && HASH.test(ref.sha256) &&
    typeof ref.path === 'string' && ref.path.length <= 512 && ref.path.startsWith(ACTION_ROOT) &&
    /^[A-Za-z0-9._/-]+$/.test(ref.path) && !ref.path.split('/').some(p => !p || p === '.' || p === '..');
}
function family(kind: TaskActionCommand['kind']): AdmittedActionFamily {
  if (kind === 'inspect_catalog' || kind === 'inspect_offer') return 'read';
  if (kind === 'pay' || kind === 'retrieve' || kind === 'purchase') return 'payment';
  return 'chain';
}

/** Bounded immutable file read; it does not access chain/actor tools or grant effect coverage. */
export async function readAdmittedActionEvidenceFile(repositoryRoot: string, ref: EvidenceReference,
  maximumBytes = MAX_BYTES): Promise<Uint8Array> {
  if (!validReference(ref) || !Number.isSafeInteger(maximumBytes) || maximumBytes < 1 || maximumBytes > MAX_BYTES) fail();
  const root = await realpath(repositoryRoot);
  const candidate = resolve(root, ...ref.path.split('/'));
  const path = await realpath(candidate);
  const rel = relative(root, path);
  if (isAbsolute(rel) || rel === '..' || rel.startsWith('..' + sep) ||
    !rel.split(sep).join('/').startsWith(ACTION_ROOT)) fail();
  const beforePath = await lstat(path, { bigint: true });
  if (!beforePath.isFile() || beforePath.isSymbolicLink()) fail();
  const handle = await open(path, fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0));
  try {
    const before = await handle.stat({ bigint: true });
    if (!before.isFile() || before.size < 1n || before.size > BigInt(maximumBytes) ||
      before.dev !== beforePath.dev || before.ino !== beforePath.ino) fail();
    // Never let a concurrent append turn the size check into an unbounded allocation.
    const bounded = Buffer.alloc(Number(before.size) + 1);
    let offset = 0;
    while (offset < bounded.length) {
      const { bytesRead } = await handle.read(bounded, offset, bounded.length - offset, offset);
      if (bytesRead === 0) break;
      offset += bytesRead;
    }
    const bytes = bounded.subarray(0, offset);
    const after = await handle.stat({ bigint: true });
    const afterPath = await lstat(path, { bigint: true });
    if (await realpath(candidate).catch(() => '') !== path || bytes.length !== Number(before.size) || before.dev !== after.dev || before.ino !== after.ino ||
      before.size !== after.size || before.mtimeNs !== after.mtimeNs || before.ctimeNs !== after.ctimeNs ||
      afterPath.dev !== after.dev || afterPath.ino !== after.ino || afterPath.size !== after.size ||
      afterPath.mtimeNs !== after.mtimeNs || afterPath.ctimeNs !== after.ctimeNs || !afterPath.isFile() ||
      createHash('sha256').update(bytes).digest('hex') !== ref.sha256) fail();
    return bytes;
  } finally { await handle.close(); }
}

/**
 * AICODE-NOTE: This is an action identity/evidence census, never a chain-effect verifier.
 * Callers retain ONE authoritative owner snapshot; family collectors must independently verify
 * every returned action before asserting complete rubric-domain coverage. No task-goal filters.
 */
export async function validateAdmittedActionCensus(input: {
  binding: TaskEvidenceBinding; taskIndex: number; execution: AdmittedActionExecution;
  closure: AdmittedActionClosure; rows: readonly AdmittedActionRow[];
  readActionEvidence: (reference: EvidenceReference) => Promise<Uint8Array>;
  maximumEvidenceBytes?: number;
  maximumTotalEvidenceBytes?: number;
}): Promise<AdmittedActionCensus> {
  // Capture scalar row identities before awaiting files. Do not clone all potentially large
  // JSONB responses first: their immutable hashes bind them, and files have an aggregate budget.
  const { binding, taskIndex, execution, closure } = structuredClone({
    binding: input.binding, taskIndex: input.taskIndex, execution: input.execution,
    closure: input.closure,
  });
  const rows = input.rows.map(row => ({ ...row }));
  const maximumBytes = input.maximumEvidenceBytes ?? MAX_BYTES;
  const maximumTotalBytes = input.maximumTotalEvidenceBytes ?? MAX_TOTAL_BYTES;
  if (!Number.isSafeInteger(maximumBytes) || maximumBytes < 1 || maximumBytes > MAX_BYTES ||
    !Number.isSafeInteger(maximumTotalBytes) || maximumTotalBytes < 1 || maximumTotalBytes > MAX_TOTAL_BYTES ||
    !Number.isSafeInteger(taskIndex) || taskIndex < 0 || taskIndex > 11 ||
    !['ownerId', 'agentId', 'runId'].every(k => UUID.test(String(binding[k as keyof TaskEvidenceBinding]))) ||
    !['manifestHash', 'caseHash', 'rubricHash'].every(k => HASH.test(String(binding[k as keyof TaskEvidenceBinding]))) ||
    !['preparationId', 'leaseId', 'generationId'].every(k => UUID.test(String(execution[k as keyof AdmittedActionExecution]))) ||
    !['environmentManifestHash', 'applicationSourceHash', 'executionIdentityHash', 'initialStateSha256']
      .every(k => HASH.test(String(execution[k as keyof AdmittedActionExecution]))) ||
    execution.environmentId !== binding.environmentId || !UUID.test(closure.closureId) ||
    !(closure.operationId === null || OP.test(closure.operationId)) || !HASH.test(closure.payloadHash) ||
    !['agent_finish', 'task_deadline', 'run_deadline'].includes(closure.reason)) fail();
  const cutoff = integer(closure.actionCutoffSequence);
  if (cutoff === null || cutoff > MAX_ACTIONS || closure.reconciledActionSequence !== cutoff || rows.length !== cutoff)
    fail('owner_cutoff_mismatch');
  const ids = new Set<string>(), operations = new Set<string>();
  const entries: AdmittedActionEntry[] = [];
  let totalBytes = 0;
  for (let index = 0; index < rows.length; index++) {
    const row = rows[index]!;
    const actionSequence = integer(row.action_sequence);
    const actionEvidence: EvidenceReference = { path: row.evidence_path ?? '', sha256: row.evidence_hash ?? '', boundary: BOUNDARY };
    const tx = row.transaction_hash === null ? null : normalizedTx(row.transaction_hash);
    const response = json(row.tool_response_json);
    const historyResponse = json(row.history_tool_response_json);
    if (actionSequence !== index + 1 || !UUID.test(row.id) || ids.has(row.id) ||
      !OP.test(row.operation_id) || operations.has(row.operation_id) || row.run_id !== binding.runId ||
      row.task_index !== taskIndex || row.owner_id !== binding.ownerId || row.agent_id !== binding.agentId ||
      row.task_id !== binding.taskId || row.environment_id !== binding.environmentId || !HASH.test(row.payload_hash) ||
      !Number.isSafeInteger(row.receipt_revision) || row.receipt_revision < 1 ||
      !['observed', 'rejected_before_execution'].includes(row.receipt_status) ||
      row.history_revision !== row.receipt_revision || row.history_status !== row.receipt_status ||
      row.history_evidence_hash !== row.evidence_hash || row.history_evidence_path !== row.evidence_path ||
      (row.transaction_hash !== null && tx === null) ||
      (row.history_transaction_hash !== null && normalizedTx(row.history_transaction_hash) === null) ||
      normalizedTx(row.history_transaction_hash) !== tx || !validReference(actionEvidence) ||
      response === undefined || historyResponse === undefined ||
      canonicalTaskJson(response) !== canonicalTaskJson(historyResponse) ||
      row.tool_response_hash !== row.history_tool_response_hash ||
      (row.tool_response_hash === null ? response !== null :
        !HASH.test(row.tool_response_hash) || sha256CanonicalTaskJson(response) !== row.tool_response_hash)) fail();
    let rawCommand: unknown = row.command_json;
    if (typeof rawCommand === 'string') { try { rawCommand = JSON.parse(rawCommand); } catch { fail(); } }
    const parsed = TaskActionCommandSchema.safeParse(rawCommand);
    if (!parsed.success || parsed.data.kind !== row.action_kind ||
      sha256CanonicalTaskJson({ runId: binding.runId, taskIndex, command: parsed.data }) !== row.payload_hash) fail();
    const bytes = await input.readActionEvidence(actionEvidence);
    if (!(bytes instanceof Uint8Array) || bytes.length === 0 || bytes.length > maximumBytes ||
      bytes.length > maximumTotalBytes - totalBytes ||
      createHash('sha256').update(bytes).digest('hex') !== actionEvidence.sha256) fail();
    totalBytes += bytes.length;
    let document: unknown;
    try { document = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); } catch { fail(); }
    if (!record(document) || Object.keys(document).some(k => !DOCUMENT_KEYS.has(k)) ||
      document.schema !== 'bef-task-action-observation-v1' || document.actionId !== row.id ||
      document.runId !== binding.runId || document.taskIndex !== taskIndex || document.actionSequence !== String(actionSequence) ||
      document.ownerOperationId !== row.operation_id || document.actionKind !== row.action_kind ||
      document.commandSha256 !== row.payload_hash || document.environmentId !== binding.environmentId ||
      document.generationId !== execution.generationId || document.manifestSha256 !== execution.environmentManifestHash ||
      document.applicationSourceSha256 !== execution.applicationSourceHash ||
      document.idempotencyKey !== 'task-action-' + row.id || document.status !== row.receipt_status ||
      (document.rawResponseSha256 !== undefined && !HASH.test(String(document.rawResponseSha256))) ||
      (document.transactionHash !== undefined && document.transactionHash !== tx) ||
      (tx !== null && document.transactionHash !== tx) ||
      canonicalTaskJson(document.participantToolResponse ?? null) !== canonicalTaskJson(response) ||
      (row.receipt_status === 'rejected_before_execution' && (tx !== null || document.participantToolResponse != null))) fail();
    if(Object.hasOwn(document,'rejectionProof')&&(parsed.data.kind!=='swap'||row.receipt_status!=='rejected_before_execution'||tx!==null||!rejectedSwapGuardMarkerMatches(document.rejectionProof,document.befOperationId)))fail();
    if (!observationHealthMatches(document.environmentHealth, { environmentId: binding.environmentId,
      manifestSha256: execution.environmentManifestHash, applicationSourceSha256: execution.applicationSourceHash })) fail();
    if (row.receipt_status === 'observed') {
      if (!record(response) || (document.recoverySource === undefined ?
        document.httpStatus !== 200 || typeof document.rawResponseSha256 !== 'string' || !HASH.test(document.rawResponseSha256) :
        family(parsed.data.kind) !== 'chain' || !recoverySourceEvidenceEnvelope(document))) fail();
      if (parsed.data.kind === 'inspect_catalog' || parsed.data.kind === 'inspect_offer') {
        const forbidden = ['transactionHash', 'outcome', 'receiptStatus', 'receiptGasUsed',
          'receiptEffectiveGasPriceWei', 'paymentProtocol', 'recoverySource', 'reasonCode'];
        if (tx !== null || forbidden.some(k => Object.hasOwn(document, k)) ||
          !readOnlyToolResponseMatches(parsed.data, response)) fail();
      }
    }
    ids.add(row.id); operations.add(row.operation_id);
    entries.push({ actionId: row.id, actionSequence: actionSequence!, ownerOperationId: row.operation_id,
      actionKind: parsed.data.kind, command: parsed.data, commandSha256: row.payload_hash,
      receiptRevision: row.receipt_revision, receiptStatus: row.receipt_status as AdmittedActionEntry['receiptStatus'],
      transactionHash: tx, family: family(parsed.data.kind), actionEvidence, document });
  }
  return { schemaVersion: 'bts-admitted-action-census/v1', classification: 'identity_and_evidence_census_not_effect_proof',
    binding, taskIndex, execution, closure, entries };
}

/**
 * Proof entries must come from independently verified retained family packets. This checks exact
 * census reconciliation only; calling it with copied census entries cannot prove economic effects.
 */
export function assertAdmittedActionCoverage(census: AdmittedActionCensus, proofs: readonly AdmittedActionProof[]): void {
  if (census.schemaVersion !== 'bts-admitted-action-census/v1' ||
    census.classification !== 'identity_and_evidence_census_not_effect_proof' ||
    census.entries.length !== census.closure.actionCutoffSequence || proofs.length !== census.entries.length)
    fail('action_coverage_incomplete');
  const byId = new Map<string, AdmittedActionProof>();
  for (const proof of proofs) {
    if (byId.has(proof.actionId)) fail('action_coverage_incomplete');
    byId.set(proof.actionId, proof);
  }
  for (const entry of census.entries) {
    const proof = byId.get(entry.actionId);
    if (!proof || !['actionId', 'actionSequence', 'ownerOperationId', 'actionKind', 'commandSha256',
      'receiptStatus', 'transactionHash', 'actionEvidence'].every(key =>
      canonicalTaskJson(proof[key as keyof AdmittedActionProof]) === canonicalTaskJson(entry[key as keyof AdmittedActionProof])))
      fail('action_coverage_incomplete');
  }
}
