import { constants as fsConstants } from 'node:fs';
import { open, realpath } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { isAbsolute, relative, resolve, sep } from 'node:path';
import { sql } from 'drizzle-orm';
import type { OwnerDatabase } from './db.js';
import { HttpError } from './http-error.js';
import type { PersistedTaskObservations, TaskEvidenceBinding, TrustedTaskRun } from './task-evaluator.js';
import type { TaskEvaluationEvidenceSource } from './task-result-service.js';
import { verifyS4CapturePacketChildren, S4CapturePacketError } from './task-s4-capture-packet.js';
import { readOnlyToolResponseMatches } from './bef-task-executor.js';
import { TaskActionCommandSchema, TaskFinishAnswerSchemas, type TaskActionCommand } from './task-action-service.js';
import { M1CapturePacketError, parseM1CapturePacket, projectM1PacketObservations, type M1CaptureAction, type M1CapturePacket } from './task-m1-capture-packet.js';
import {
  canonicalTaskJson,
  sha256CanonicalTaskJson,
  type EvidenceReference,
  type TaskCase,
  type TaskReleaseQuerySource,
} from './task-release.js';

type Transaction = Parameters<Parameters<OwnerDatabase['transaction']>[0]>[0];

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const HASH = /^[0-9a-f]{64}$/i;
const EVIDENCE_PATH = /^(?![A-Za-z]:)(?!\/)(?!.*(?:^|\/)\.\.(?:\/|$))[A-Za-z0-9._/-]{1,512}$/;
const EVIDENCE_BOUNDARY = 'actual_tool_http_x402_local_evm_application_store';
const COORDINATOR_EVIDENCE_ROOT = 'artifacts/runs/owner-identity-bef-task-coordinator/';
const CAPTURE_EVIDENCE_PREFIX = `${COORDINATOR_EVIDENCE_ROOT}observation/`;
const PREPARATION_EVIDENCE_PREFIX = `${COORDINATOR_EVIDENCE_ROOT}preparation/`;
const ACTION_EVIDENCE_PREFIX = `${COORDINATOR_EVIDENCE_ROOT}action/`;
const MAX_EVIDENCE_FILES = 256;
const DEFAULT_MAX_EVIDENCE_FILE_BYTES = 8 * 1024 * 1024;
const DEFAULT_MAX_EVIDENCE_TOTAL_BYTES = 32 * 1024 * 1024;
const SECRET_KEYS = new Set(['privatekey', 'privkey', 'seedphrase', 'mnemonic', 'secret', 'clientsecret', 'bearer', 'bearertoken',
  'accesstoken', 'refreshtoken', 'providertoken', 'paymenttoken', 'token', 'apitoken', 'apikey', 'authorization',
  'walletmaterial', 'walletsecret', 'signature', 'signedpayload', 'paymentpayload', 'paymentauthorization', 'paymentauth',
  'paymentproof', 'xpayment', 'xpaymentsignature', 'xpaymentpayload', 'xpaymentauthorization', 'x402authorization',
  'x402signature', 'x402payload', 'x402proof', 'rawsignedtransaction']);

type EvidenceRow = {
  run_id: string;
  owner_id: string;
  agent_id: string;
  mode: 'training' | 'ranked';
  task_ids: string[];
  release_identity: string;
  manifest_hash: string;
  environment_id: string;
  task_index: number;
  task_id: string;
  closure_id: string;
  closure_status: string;
  action_cutoff_sequence: string | number;
  reconciled_action_sequence: string | number;
  closure_operation_id: string | null;
  closure_payload_hash: string;
  closure_reason: string;
  closure_answer_json: unknown;
  closure_action_cutoff_sequence: string | number;
  bundle_owner_id: string;
  bundle_agent_id: string;
  bundle_closure_id: string;
  bundle_closure_operation_id: string | null;
  bundle_closure_payload_hash: string;
  bundle_closure_reason: string;
  bundle_task_id: string;
  bundle_release_identity: string;
  bundle_manifest_hash: string;
  bundle_case_id: string;
  bundle_case_hash: string;
  bundle_rubric_hash: string;
  bundle_environment_id: string;
  preparation_id: string;
  lease_id: string;
  generation_id: string;
  environment_manifest_hash: string;
  application_source_hash: string;
  execution_identity_hash: string;
  initial_state_sha256: string;
  bundle_action_cutoff_sequence: string | number;
  bundle_reconciled_action_sequence: string | number;
  observation_cutoff_sequence: string | number;
  cutoff_evidence: EvidenceReference | string;
  bundle_hash: string;
  bundle_json: unknown;
  prepared_preparation_id: string;
  prepared_lease_id: string;
  prepared_environment_id: string;
  prepared_release_identity: string;
  prepared_manifest_hash: string;
  prepared_task_id: string;
  prepared_case_id: string;
  prepared_case_hash: string;
  prepared_initial_state_sha256: string;
  prepared_environment_manifest_hash: string;
  prepared_application_source_hash: string;
  prepared_execution_identity_hash: string;
  lease_state: 'leased' | 'fenced';
  execution_environment_id: string;
  execution_generation_id: string;
  execution_manifest_hash: string;
  execution_application_source_hash: string;
  has_ready_generation: boolean;
};

export type TaskSealedEvidenceSourceDependencies = {
  taskReleaseSource: TaskReleaseQuerySource;
  /** Repository root against which the stored, relative EvidenceReference paths are resolved. */
  evidenceRoot: string;
  maxEvidenceFileBytes?: number;
  maxEvidenceTotalBytes?: number;
};

function fail(status: number, code: string, message: string): never {
  throw new HttpError(status, code, message);
}

function plainObject(value: unknown): value is Record<string, unknown> {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value) &&
    (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null));
}

function exactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  return Object.keys(value).sort().join('\u0000') === [...keys].sort().join('\u0000');
}

function validEvidence(value: unknown): value is EvidenceReference {
  if (!plainObject(value) || !exactKeys(value, ['path', 'sha256', 'boundary'])) return false;
  return typeof value.path === 'string' && EVIDENCE_PATH.test(value.path) && !value.path.includes('\\') &&
    typeof value.sha256 === 'string' && HASH.test(value.sha256) && value.boundary === EVIDENCE_BOUNDARY;
}

function safeSequence(value: string | number): number | null {
  try {
    const parsed = BigInt(value);
    if (parsed < 0n || parsed > BigInt(Number.MAX_SAFE_INTEGER)) return null;
    return Number(parsed);
  } catch { return null; }
}

function jsonValue<T = unknown>(value: T | string): T {
  try { return typeof value === 'string' ? JSON.parse(value) as T : value; }
  catch { return fail(503, 'TASK_EVIDENCE_BUNDLE_UNAVAILABLE', 'The sealed task evidence bundle is malformed'); }
}

function containsSecretKey(value: unknown, seen = new Set<object>()): boolean {
  if (value === null || typeof value !== 'object') return false;
  if (seen.has(value)) return true;
  seen.add(value);
  if (Array.isArray(value)) return value.some((item) => containsSecretKey(item, seen));
  if (!plainObject(value)) return true;
  return Object.entries(value).some(([key, item]) => SECRET_KEYS.has(key.toLowerCase().replace(/[^a-z]/g, '')) || containsSecretKey(item, seen));
}

/**
 * The reader verifies persisted bindings and the bytes named by evidence references.
 * AICODE-NOTE: Matching hashes establishes integrity of retained bytes, not chain semantics,
 * source authenticity, or completeness. Coverage is passed through unchanged to the evaluator.
 */
export class TaskSealedEvidenceSource implements TaskEvaluationEvidenceSource {
  private readonly maxFileBytes: number;
  private readonly maxTotalBytes: number;

  constructor(private readonly deps: TaskSealedEvidenceSourceDependencies) {
    this.maxFileBytes = deps.maxEvidenceFileBytes ?? DEFAULT_MAX_EVIDENCE_FILE_BYTES;
    this.maxTotalBytes = deps.maxEvidenceTotalBytes ?? DEFAULT_MAX_EVIDENCE_TOTAL_BYTES;
    if (!Number.isSafeInteger(this.maxFileBytes) || this.maxFileBytes <= 0 ||
        !Number.isSafeInteger(this.maxTotalBytes) || this.maxTotalBytes < this.maxFileBytes) {
      throw new Error('Task evidence file bounds are invalid');
    }
  }

  async load(input: { runId: string; taskIndex: number; closureId: string }, tx: Transaction) {
    if (!UUID.test(input.runId) || !UUID.test(input.closureId) || !Number.isSafeInteger(input.taskIndex) ||
        input.taskIndex < 0 || input.taskIndex > 11) {
      fail(400, 'INVALID_TASK_EVIDENCE_TARGET', 'A run UUID, closure UUID, and bounded task index are required');
    }

    // All database reads, including the immutable release lookup, use the caller's transaction.
    // There is intentionally no db dependency here and no nested transaction path.
    const rows = await tx.execute(sql`SELECT
        r.id AS run_id,r.owner_id,r.agent_id,r.mode,r.task_ids,r.release_identity,r.manifest_hash,
        b.environment_id,
        t.task_id,t.task_index,t.closure_id,t.closure_status,t.action_cutoff_sequence,t.reconciled_action_sequence,
        c.operation_id AS closure_operation_id,c.payload_hash AS closure_payload_hash,c.reason AS closure_reason,
        c.action_cutoff_sequence AS closure_action_cutoff_sequence,c.answer_json AS closure_answer_json,
        b.owner_id AS bundle_owner_id,b.agent_id AS bundle_agent_id,b.closure_id AS bundle_closure_id,
        b.closure_operation_id AS bundle_closure_operation_id,b.closure_payload_hash AS bundle_closure_payload_hash,
        b.closure_reason AS bundle_closure_reason,b.task_id AS bundle_task_id,b.release_identity AS bundle_release_identity,
        b.release_manifest_hash AS bundle_manifest_hash,b.case_id AS bundle_case_id,b.case_hash AS bundle_case_hash,
        b.rubric_hash AS bundle_rubric_hash,b.environment_id AS bundle_environment_id,b.preparation_id,b.lease_id,b.generation_id,
        b.environment_manifest_hash,b.application_source_hash,b.execution_identity_hash,b.initial_state_sha256,
        b.action_cutoff_sequence AS bundle_action_cutoff_sequence,b.reconciled_action_sequence AS bundle_reconciled_action_sequence,
        b.observation_cutoff_sequence,b.cutoff_evidence,b.bundle_hash,b.bundle_json,
        i.preparation_id AS prepared_preparation_id,i.lease_id AS prepared_lease_id,i.environment_id AS prepared_environment_id,
        i.release_identity AS prepared_release_identity,i.manifest_hash AS prepared_manifest_hash,i.task_id AS prepared_task_id,
        i.case_id AS prepared_case_id,i.case_hash AS prepared_case_hash,i.initial_state_sha256 AS prepared_initial_state_sha256,
        i.environment_manifest_sha256 AS prepared_environment_manifest_hash,i.application_source_hash AS prepared_application_source_hash,
        i.execution_identity_hash AS prepared_execution_identity_hash,l.state AS lease_state,
        eb.env_id AS execution_environment_id,eb.generation_id AS execution_generation_id,eb.manifest_hash AS execution_manifest_hash,
        eb.application_source_hash AS execution_application_source_hash,
        EXISTS(SELECT 1 FROM oid_task_preparation_observation po
          WHERE po.preparation_id=i.preparation_id AND po.status='ready' AND po.generation_id=b.generation_id
            AND po.baseline_state_sha256=b.initial_state_sha256) AS has_ready_generation
      FROM oid_benchmark_run r
      JOIN oid_run_task t ON t.run_id=r.id AND t.task_index=${input.taskIndex}
      JOIN oid_run_task_closure c ON c.id=t.closure_id AND c.run_id=r.id AND c.task_index=t.task_index
      JOIN oid_run_task_observation_bundle b ON b.run_id=r.id AND b.task_index=t.task_index
      JOIN oid_task_preparation_intent i ON i.preparation_id=b.preparation_id
      JOIN oid_task_environment_lease l ON l.preparation_id=i.preparation_id AND l.lease_id=i.lease_id
      JOIN oid_task_execution_binding eb ON eb.run_id=r.id AND eb.task_index=t.task_index
      WHERE r.id=${input.runId} AND b.closure_id=${input.closureId}`) as unknown as EvidenceRow[];
    const row = rows[0];
    if (!row) return null;
    if (row.task_id !== 'S1' && row.task_id !== 'S2' && row.task_id !== 'S4' && row.task_id !== 'M1') return null;
    if (rows.length !== 1) fail(409, 'TASK_EVIDENCE_BINDING_CONFLICT', 'More than one sealed evidence binding matches this task');
    if (Number(row.task_index) !== input.taskIndex) fail(409, 'TASK_EVIDENCE_BINDING_MISMATCH', 'The sealed task index does not match PostgreSQL');

    const release = await this.deps.taskReleaseSource.getValidatedReleaseRecord(row.release_identity, row.manifest_hash, tx);
    if (!release || release.releaseIdentity !== row.release_identity || release.manifestHash !== row.manifest_hash ||
        release.manifest.releaseIdentity !== row.release_identity || release.manifest.manifestHash !== row.manifest_hash) {
      fail(503, 'TASK_EVIDENCE_RELEASE_UNAVAILABLE', 'The immutable admitted release cannot be verified');
    }
    const taskCase = release.manifest.cases[row.mode]?.find((entry) => entry.taskId === row.task_id);
    if (!taskCase || row.task_ids[input.taskIndex] !== row.task_id) return null;

    const bundle = jsonValue(row.bundle_json);
    this.validateEnvelope(row, input.runId, bundle, taskCase, release.manifest.executionIdentity.environmentManifestSha256);
    const bundleHash = sha256CanonicalTaskJson(bundle);
    if (!HASH.test(row.bundle_hash) || bundleHash.toLowerCase() !== row.bundle_hash.toLowerCase()) {
      fail(409, 'TASK_EVIDENCE_BUNDLE_HASH_MISMATCH', 'The immutable sealed task evidence hash does not match its retained bundle');
    }
    await this.verifyEvidenceFiles(bundle, taskCase, row, tx, release.manifest.executionIdentity.localChainId,
      release.manifest.executionIdentity.assets);

    const actionCutoff = safeSequence(row.action_cutoff_sequence);
    const reconciled = safeSequence(row.reconciled_action_sequence);
    const observationCutoff = safeSequence(row.observation_cutoff_sequence);
    if (actionCutoff === null || reconciled === null || observationCutoff === null) {
      fail(409, 'TASK_EVIDENCE_CUTOFF_INVALID', 'The sealed task evidence cutoff is outside the supported sequence range');
    }
    const run: TrustedTaskRun = {
      ownerId: row.owner_id,
      agentId: row.agent_id,
      runId: input.runId,
      environmentId: row.environment_id,
      releaseIdentity: row.release_identity,
      manifestHash: row.manifest_hash,
      caseId: taskCase.caseId,
      caseHash: taskCase.caseHash,
      rubricHash: taskCase.rubricHash,
      taskId: taskCase.taskId,
      acceptedActionCutoffSequence: actionCutoff,
      reconciledThroughActionSequence: reconciled,
      observationCutoffSequence: observationCutoff,
      cutoffStatus: 'authoritative',
      cutoffEvidence: bundle.cutoff.evidence as EvidenceReference,
    };
    return {
      taskCase,
      release: release.manifest,
      run,
      // Keep declared coverage and observations exactly as sealed; no facts are inferred here.
      observations: bundle.observations as PersistedTaskObservations,
    };
  }

  private validateEnvelope(
    row: EvidenceRow,
    expectedRunId: string,
    bundleValue: unknown,
    taskCase: TaskCase,
    releaseEnvironmentManifestHash: string,
  ): asserts bundleValue is {
    schemaVersion: 'bts-task-observation-bundle/v1';
    binding: Record<string, unknown>;
    closure: Record<string, unknown>;
    execution: Record<string, unknown>;
    cutoff: Record<string, unknown>;
    observations: PersistedTaskObservations;
  } {
    if (!plainObject(bundleValue) || !exactKeys(bundleValue, ['schemaVersion', 'binding', 'closure', 'execution', 'cutoff', 'observations']) ||
        bundleValue.schemaVersion !== 'bts-task-observation-bundle/v1' || !plainObject(bundleValue.binding) ||
        !plainObject(bundleValue.closure) || !plainObject(bundleValue.execution) || !plainObject(bundleValue.cutoff) ||
        !plainObject(bundleValue.observations)) {
      fail(503, 'TASK_EVIDENCE_BUNDLE_UNAVAILABLE', 'The sealed task evidence bundle has an unsupported shape');
    }
    const binding = bundleValue.binding;
    const closure = bundleValue.closure;
    const execution = bundleValue.execution;
    const cutoff = bundleValue.cutoff;
    if (!exactKeys(binding, ['ownerId', 'agentId', 'runId', 'environmentId', 'releaseIdentity', 'manifestHash', 'caseId', 'caseHash', 'rubricHash', 'taskId']) ||
        binding.ownerId !== row.owner_id || binding.agentId !== row.agent_id || binding.runId !== expectedRunId || row.run_id !== expectedRunId) {
      fail(409, 'TASK_EVIDENCE_BINDING_MISMATCH', 'The sealed task evidence owner or agent binding does not match PostgreSQL');
    }
    if (row.bundle_closure_id !== row.closure_id ||
        binding.environmentId !== row.environment_id || binding.releaseIdentity !== row.release_identity || binding.manifestHash !== row.manifest_hash ||
        binding.caseId !== taskCase.caseId || binding.caseHash !== taskCase.caseHash || binding.rubricHash !== taskCase.rubricHash || binding.taskId !== taskCase.taskId ||
        row.bundle_owner_id !== row.owner_id || row.bundle_agent_id !== row.agent_id || row.bundle_task_id !== taskCase.taskId ||
        row.bundle_release_identity !== row.release_identity || row.bundle_manifest_hash !== row.manifest_hash ||
        row.bundle_case_id !== taskCase.caseId || row.bundle_case_hash !== taskCase.caseHash || row.bundle_rubric_hash !== taskCase.rubricHash ||
        row.bundle_environment_id !== row.environment_id) {
      fail(409, 'TASK_EVIDENCE_BINDING_MISMATCH', 'The sealed task evidence binding does not match its immutable run and case');
    }
    if (!exactKeys(closure, ['closureId', 'operationId', 'payloadHash', 'reason', 'actionCutoffSequence', 'reconciledActionSequence']) ||
        closure.closureId !== row.closure_id || closure.operationId !== row.closure_operation_id || closure.payloadHash !== row.closure_payload_hash ||
        closure.reason !== row.closure_reason || !['agent_finish', 'task_deadline', 'run_deadline'].includes(String(closure.reason)) ||
        safeSequence(row.action_cutoff_sequence) !== safeSequence(row.closure_action_cutoff_sequence) ||
        safeSequence(row.action_cutoff_sequence) !== safeSequence(row.bundle_action_cutoff_sequence) ||
        safeSequence(row.reconciled_action_sequence) !== safeSequence(row.bundle_reconciled_action_sequence) ||
        safeSequence(row.action_cutoff_sequence) !== safeSequence(closure.actionCutoffSequence as string | number) ||
        safeSequence(row.reconciled_action_sequence) !== safeSequence(closure.reconciledActionSequence as string | number) ||
        row.closure_status !== 'closed' || row.closure_id !== row.bundle_closure_id) {
      fail(409, 'TASK_EVIDENCE_CLOSURE_MISMATCH', 'The sealed task evidence closure or action cutoff does not match PostgreSQL');
    }
    if (!exactKeys(execution, ['preparationId', 'leaseId', 'generationId', 'environmentManifestHash', 'applicationSourceHash', 'executionIdentityHash', 'initialStateSha256']) ||
        execution.preparationId !== row.preparation_id || execution.leaseId !== row.lease_id || execution.generationId !== row.generation_id ||
        execution.environmentManifestHash !== row.environment_manifest_hash || execution.applicationSourceHash !== row.application_source_hash ||
        execution.executionIdentityHash !== row.execution_identity_hash || execution.initialStateSha256 !== row.initial_state_sha256 ||
        row.prepared_preparation_id !== row.preparation_id || row.prepared_lease_id !== row.lease_id ||
        row.prepared_environment_id !== row.environment_id || row.prepared_release_identity !== row.release_identity ||
        row.prepared_manifest_hash !== row.manifest_hash || row.prepared_task_id !== taskCase.taskId || row.prepared_case_id !== taskCase.caseId ||
        row.prepared_case_hash !== taskCase.caseHash || row.prepared_initial_state_sha256 !== taskCase.initialState.stateSha256 ||
        row.prepared_environment_manifest_hash !== row.environment_manifest_hash || row.prepared_application_source_hash !== row.application_source_hash ||
        row.prepared_execution_identity_hash !== taskCase.executionIdentityHash || row.execution_environment_id !== row.environment_id ||
        row.execution_generation_id !== row.generation_id || row.execution_manifest_hash !== row.environment_manifest_hash ||
        row.execution_application_source_hash !== row.application_source_hash || row.lease_state !== 'leased' && row.lease_state !== 'fenced' ||
        !row.has_ready_generation || row.environment_manifest_hash !== releaseEnvironmentManifestHash ||
        row.execution_identity_hash !== taskCase.executionIdentityHash || row.initial_state_sha256 !== taskCase.initialState.stateSha256) {
      fail(409, 'TASK_EVIDENCE_EXECUTION_MISMATCH', 'The sealed task evidence does not match the original prepared execution');
    }
    if (!exactKeys(cutoff, ['observationSequence', 'status', 'evidence']) || cutoff.status !== 'authoritative' ||
        safeSequence(row.observation_cutoff_sequence) !== safeSequence(cutoff.observationSequence as string | number) ||
        !validEvidence(cutoff.evidence) || canonicalTaskJson(cutoff.evidence) !== canonicalTaskJson(jsonValue(row.cutoff_evidence)) ||
        !plainObject(bundleValue.observations) || bundleValue.observations.schemaVersion !== 'bts-task-observations/v1' ||
        bundleValue.observations.coveredThroughSequence !== cutoff.observationSequence ||
        !plainObject(bundleValue.observations.binding) || canonicalTaskJson(bundleValue.observations.binding) !== canonicalTaskJson(binding)) {
      fail(409, 'TASK_EVIDENCE_CUTOFF_MISMATCH', 'The sealed task evidence observation cutoff is malformed or inconsistent');
    }
  }

  private async verifyEvidenceFiles(
    bundle: {
    binding: Record<string, unknown>;
    closure: Record<string, unknown>;
    execution: Record<string, unknown>;
    cutoff: Record<string, unknown>;
    observations: Record<string, unknown>;
    },
    taskCase: TaskCase,
    row: EvidenceRow,
    tx: Transaction,
    localChainId: number,
    assets: Array<{ assetId: string; address: string | null; kind: 'native' | 'erc20'; chainId: number }>,
  ): Promise<void> {
    const references = new Map<string, EvidenceReference>();
    const addReference = (value: unknown): EvidenceReference => {
      if (!validEvidence(value)) fail(503, 'TASK_EVIDENCE_REFERENCE_INVALID', 'A sealed raw evidence reference is malformed');
      const prior = references.get(value.path);
      if (prior && prior.sha256.toLowerCase() !== value.sha256.toLowerCase()) {
        fail(409, 'TASK_EVIDENCE_REFERENCE_CONFLICT', 'One evidence path has conflicting sealed hashes');
      }
      references.set(value.path, value);
      return value;
    };
    const captureEvidence = addReference(bundle.observations.captureEvidence);
    const cutoffEvidence = addReference(bundle.cutoff.evidence);
    if (canonicalTaskJson(cutoffEvidence) !== canonicalTaskJson(captureEvidence)) {
      fail(409, 'TASK_EVIDENCE_REFERENCE_CONFLICT', 'The cutoff and capture evidence must use one immutable packet');
    }
    if (!captureEvidence.path.startsWith(CAPTURE_EVIDENCE_PREFIX)) {
      fail(503, 'TASK_EVIDENCE_PATH_INVALID', 'The capture packet is outside its private evidence namespace');
    }
    const observationDomains = [
      'transfers', 'payments', 'stateMutations', 'finalStates', 'allowanceChanges', 'allowanceUses',
      'answers', 'selections', 'deliveries', 'trades', 'conversions', 'expenses',
    ] as const;
    for (const domain of observationDomains) {
      const entries = bundle.observations[domain];
      if (!Array.isArray(entries)) fail(503, 'TASK_EVIDENCE_BUNDLE_UNAVAILABLE', 'A sealed observation domain is malformed');
      for (const entry of entries) {
        if (!plainObject(entry)) fail(503, 'TASK_EVIDENCE_BUNDLE_UNAVAILABLE', 'A sealed observation entry is malformed');
        const ref = addReference(entry.evidence);
        if (canonicalTaskJson(ref) !== canonicalTaskJson(captureEvidence)) {
          fail(409, 'TASK_EVIDENCE_REFERENCE_CONFLICT', 'Observations must reference their sealed capture packet');
        }
      }
    }
    if (!references.size || references.size > MAX_EVIDENCE_FILES) {
      fail(503, 'TASK_EVIDENCE_REFERENCE_COUNT_INVALID', 'The sealed evidence reference count is outside its supported bound');
    }

    let root: string;
    try { root = await realpath(this.deps.evidenceRoot); }
    catch { fail(503, 'TASK_EVIDENCE_ROOT_UNAVAILABLE', 'The private evidence root is unavailable'); }
    const verified = new Map<string, string>();
    const s2ActionsByPath = new Map<string, Record<string, unknown>>();
    const s2EvidenceByPath = new Map<string, Record<string, unknown>>();
    let s2Packet: Record<string, unknown> | null = null;
    const m1ActionsByPath = new Map<string, M1CaptureAction>();
    const m1EvidenceByPath = new Map<string, Record<string, unknown>>();
    let m1Packet: M1CapturePacket | null = null;
    const queue: Array<{ reference: EvidenceReference; ancestors: ReadonlySet<string> }> =
      [...references.values()].map((reference) => ({ reference, ancestors: new Set<string>() }));
    let totalBytes = 0;
    for (let index = 0; index < queue.length; index += 1) {
      const { reference: ref, ancestors } = queue[index]!;
      if (ancestors.has(ref.path)) fail(409, 'TASK_EVIDENCE_REFERENCE_CYCLE', 'Sealed evidence references contain a cycle');
      const existingDigest = verified.get(ref.path);
      if (existingDigest !== undefined) {
        if (existingDigest !== ref.sha256.toLowerCase()) fail(409, 'TASK_EVIDENCE_REFERENCE_CONFLICT', 'One evidence path has conflicting sealed hashes');
        continue;
      }
      const segments = ref.path.split('/');
      if (!EVIDENCE_PATH.test(ref.path) || ref.path.includes('\\') || segments.some((part) => !part || part === '.' || part === '..')) {
        fail(503, 'TASK_EVIDENCE_PATH_INVALID', 'A sealed evidence reference path is unsafe');
      }
      const candidate = resolve(root, ...segments);
      let actual: string;
      try { actual = await realpath(candidate); }
      catch { fail(503, 'TASK_EVIDENCE_FILE_UNAVAILABLE', 'A sealed raw evidence file is unavailable'); }
      const rel = relative(root, actual);
      if (!rel || rel === '..' || rel.startsWith(`..${sep}`) || isAbsolute(rel)) {
        fail(503, 'TASK_EVIDENCE_PATH_ESCAPE', 'A sealed raw evidence path resolves outside its private root');
      }
      const handle = await open(actual, fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0)).catch(() => null);
      if (!handle) fail(503, 'TASK_EVIDENCE_FILE_UNAVAILABLE', 'A sealed raw evidence file cannot be opened safely');
      try {
        const before = await handle.stat();
        if (!before.isFile() || before.size <= 0 || before.size > this.maxFileBytes) {
          fail(503, 'TASK_EVIDENCE_FILE_SIZE_INVALID', 'A sealed raw evidence file exceeds its supported size bound');
        }
        totalBytes += before.size;
        if (totalBytes > this.maxTotalBytes) fail(503, 'TASK_EVIDENCE_TOTAL_SIZE_INVALID', 'The sealed raw evidence total exceeds its supported size bound');
        // Read at most the observed size plus one byte. The extra byte detects growth without
        // allowing a concurrent append to turn this bounded check into an unbounded allocation.
        const bounded = Buffer.alloc(before.size + 1);
        let offset = 0;
        while (offset < bounded.length) {
          const { bytesRead } = await handle.read(bounded, offset, bounded.length - offset, offset);
          if (bytesRead === 0) break;
          offset += bytesRead;
        }
        const after = await handle.stat();
        const actualAgain = await realpath(candidate).catch(() => '');
        if (before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size ||
            before.mtimeMs !== after.mtimeMs || before.ctimeMs !== after.ctimeMs || offset !== before.size || actualAgain !== actual) {
          fail(503, 'TASK_EVIDENCE_FILE_CHANGED', 'A sealed raw evidence file changed while it was being verified');
        }
        const digest = createHash('sha256').update(bounded.subarray(0, offset)).digest('hex');
        if (digest.toLowerCase() !== ref.sha256.toLowerCase()) {
          fail(409, 'TASK_EVIDENCE_FILE_HASH_MISMATCH', 'A sealed raw evidence file does not match its retained hash');
        }
        verified.set(ref.path, digest.toLowerCase());
        if (ref.path === captureEvidence.path) {
          let children: EvidenceReference[];
          if (taskCase.taskId === 'S2') {
            const parsed = this.readS2CapturePacketChildren(bounded.subarray(0, offset), bundle, row, taskCase, localChainId);
            s2Packet = parsed.packet;
            children = parsed.children;
            for (const action of parsed.actions) {
              const actionReference = action.actionEvidence as EvidenceReference;
              s2ActionsByPath.set(actionReference.path, action);
            }
          } else if (taskCase.taskId === 'M1') {
            const parsed = this.readM1CapturePacketChildren(bounded.subarray(0, offset), bundle, row, taskCase, localChainId);
            m1Packet = parsed.packet;
            children = parsed.children;
            for (const action of parsed.actions) m1ActionsByPath.set(action.actionEvidence.path, action);
          } else if (taskCase.taskId === 'S4') {
            children = this.readS4CapturePacketChildren(bounded.subarray(0, offset), bundle);
          } else {
            children = this.readS1CapturePacketChildren(bounded.subarray(0, offset), bundle);
          }
          const nextAncestors = new Set([...ancestors, ref.path]);
          for (const child of children) {
            if (nextAncestors.has(child.path)) {
              fail(409, 'TASK_EVIDENCE_REFERENCE_CYCLE', 'The S1 capture packet references itself');
            }
            const existing = references.get(child.path);
            if (existing && existing.sha256.toLowerCase() !== child.sha256.toLowerCase()) {
              fail(409, 'TASK_EVIDENCE_REFERENCE_CONFLICT', 'One evidence path has conflicting sealed hashes');
            }
            if (!existing) references.set(child.path, child);
            if (references.size > MAX_EVIDENCE_FILES) {
              fail(503, 'TASK_EVIDENCE_REFERENCE_COUNT_INVALID', 'The sealed evidence reference count is outside its supported bound');
            }
            queue.push({ reference: child, ancestors: nextAncestors });
          }
        } else if (taskCase.taskId === 'S2' && s2ActionsByPath.has(ref.path)) {
          const evidence = this.validateS2ActionEvidence(bounded.subarray(0, offset), ref, s2ActionsByPath.get(ref.path)!, bundle,
            taskCase, assets, localChainId, row.task_index);
          s2EvidenceByPath.set(ref.path, evidence);
        } else if (taskCase.taskId === 'M1' && m1ActionsByPath.has(ref.path)) {
          const evidence = this.validateM1ActionEvidence(bounded.subarray(0, offset), ref, m1ActionsByPath.get(ref.path)!, bundle, row);
          m1EvidenceByPath.set(ref.path, evidence);
        }
      } finally {
        await handle.close();
      }
    }
    if (taskCase.taskId === 'S2') {
      if (!s2Packet) fail(409, 'TASK_EVIDENCE_CAPTURE_BINDING_MISMATCH', 'The S2 capture packet was not verified');
      await this.verifyS2OwnerActions(tx, row, taskCase, s2Packet.ownerActions as Record<string, unknown>[],
        s2EvidenceByPath, (s2Packet.bef as Record<string, unknown>).before as Record<string, unknown>);
    } else if (taskCase.taskId === 'M1') {
      if (!m1Packet) fail(409, 'TASK_EVIDENCE_CAPTURE_BINDING_MISMATCH', 'The M1 capture packet was not verified');
      await this.verifyM1OwnerActions(tx, row, taskCase, m1Packet, m1EvidenceByPath, bundle, assets, localChainId);
    }
  }

  private readM1CapturePacketChildren(
    bytes: Buffer,
    bundle: { binding: Record<string, unknown>; closure: Record<string, unknown>; execution: Record<string, unknown>; cutoff: Record<string, unknown> },
    row: EvidenceRow,
    taskCase: Extract<TaskCase, { taskId: 'M1' }>,
    localChainId: number,
  ): { children: EvidenceReference[]; actions: M1CaptureAction[]; packet: M1CapturePacket } {
    let packet: M1CapturePacket;
    try { packet = parseM1CapturePacket(bytes); }
    catch (error) {
      if (error instanceof M1CapturePacketError) {
        fail(409, 'TASK_EVIDENCE_CAPTURE_BINDING_MISMATCH', 'The M1 capture packet is malformed or contains an unsupported projection');
      }
      throw error;
    }
    const cutoff = safeSequence(row.action_cutoff_sequence);
    const reconciled = safeSequence(row.reconciled_action_sequence);
    const answer = jsonValue(row.closure_answer_json);
    const packetClosure = packet.closure as Record<string, unknown>;
    const packetPreparation = packet.preparation as Record<string, unknown>;
    const fixtureEvidence = packetPreparation.fixtureEvidence;
    const baselineEvidence = packetPreparation.baselineEvidence;
    const expectedPayloadHash = row.closure_reason === 'agent_finish'
      ? sha256CanonicalTaskJson({ action: 'task_finish', runId: row.run_id, taskIndex: row.task_index, answer: null })
      : sha256CanonicalTaskJson({ runId: row.run_id, taskIndex: row.task_index, reason: row.closure_reason });
    if (canonicalTaskJson(packet.binding) !== canonicalTaskJson(bundle.binding) || cutoff === null || reconciled === null ||
        packet.closure.closureId !== row.closure_id || packet.closure.closureId !== bundle.closure.closureId ||
        packet.closure.actionCutoffSequence !== cutoff || packet.closure.reconciledActionSequence !== reconciled ||
        packet.closure.reason !== row.closure_reason || packet.closure.operationId !== row.closure_operation_id || answer !== null ||
        typeof packetClosure.payloadHash !== 'string' || packetClosure.payloadHash.toLowerCase() !== row.closure_payload_hash.toLowerCase() ||
        packetClosure.payloadHash.toLowerCase() !== expectedPayloadHash.toLowerCase() ||
        packet.execution.preparationId !== bundle.execution.preparationId || packet.execution.leaseId !== bundle.execution.leaseId ||
        packet.execution.generationId !== bundle.execution.generationId || packet.execution.environmentId !== row.environment_id ||
        packet.execution.environmentManifestHash !== bundle.execution.environmentManifestHash ||
        packet.execution.applicationSourceHash !== bundle.execution.applicationSourceHash ||
        packet.execution.executionIdentityHash !== bundle.execution.executionIdentityHash ||
        packet.execution.initialStateSha256 !== bundle.execution.initialStateSha256 ||
        packet.bef.before.generation.generation_id !== row.generation_id || packet.bef.before.generation.env_id !== row.environment_id ||
        packet.bef.before.generation.manifest_sha256 !== row.environment_manifest_hash ||
        packet.bef.before.generation.environment_manifest_sha256 !== row.environment_manifest_hash ||
        packet.bef.after.generation.generation_id !== row.generation_id || packet.bef.after.generation.env_id !== row.environment_id ||
        packet.bef.after.generation.manifest_sha256 !== row.environment_manifest_hash ||
        packet.bef.after.generation.environment_manifest_sha256 !== row.environment_manifest_hash ||
        String(packet.bef.before.generation.chain_id) !== String(localChainId) ||
        String(packet.bef.after.generation.chain_id) !== String(localChainId) ||
        !validEvidence(fixtureEvidence) || !validEvidence(baselineEvidence) || fixtureEvidence.path === baselineEvidence.path) {
      fail(409, 'TASK_EVIDENCE_CAPTURE_BINDING_MISMATCH', 'The M1 capture packet does not match the immutable run, case, closure, or execution pins');
    }
    const children: EvidenceReference[] = [fixtureEvidence, baselineEvidence];
    for (const action of packet.ownerActions) children.push(action.actionEvidence);
    return { children, actions: packet.ownerActions, packet };
  }

  private validateM1ActionEvidence(
    bytes: Buffer,
    reference: EvidenceReference,
    action: M1CaptureAction,
    bundle: { binding: Record<string, unknown>; execution: Record<string, unknown> },
    row: EvidenceRow,
  ): Record<string, unknown> {
    let value: unknown;
    try { value = JSON.parse(bytes.toString('utf8')) as unknown; }
    catch { fail(503, 'TASK_EVIDENCE_ACTION_PACKET_INVALID', 'A retained M1 action file is malformed'); }
    const allowed = ['schema','actionId','runId','taskIndex','actionSequence','ownerOperationId','actionKind','commandSha256','environmentId',
      'generationId','manifestSha256','applicationSourceSha256','idempotencyKey','status','reasonCode','requestStartedAt','requestFinishedAt',
      'httpStatus','befOperationId','transactionHash','outcome','receiptStatus','rawResponseSha256','participantToolResponse','receiptGasUsed',
      'receiptEffectiveGasPriceWei','paymentProtocol','environmentHealth'];
    if (!plainObject(value) || containsSecretKey(value) || Object.keys(value).some((key) => !allowed.includes(key)) ||
        value.schema !== 'bef-task-action-observation-v1' || value.actionId !== action.actionId || value.runId !== row.run_id ||
        Number(value.taskIndex) !== row.task_index || value.actionSequence !== action.actionSequence ||
        value.ownerOperationId !== action.ownerOperationId || value.actionKind !== action.actionKind ||
        typeof value.commandSha256 !== 'string' || value.commandSha256.toLowerCase() !== action.commandSha256.toLowerCase() ||
        value.environmentId !== bundle.binding.environmentId || value.generationId !== bundle.execution.generationId ||
        value.manifestSha256 !== bundle.execution.environmentManifestHash || value.applicationSourceSha256 !== bundle.execution.applicationSourceHash ||
        value.idempotencyKey !== `task-action-${action.actionId}` || value.status !== action.receiptStatus ||
        (value.befOperationId ?? null) !== action.befOperationId || (value.transactionHash ?? null) !== action.transactionHash ||
        (value.rawResponseSha256 ?? null) !== action.rawResponseSha256 ||
        canonicalTaskJson(value.participantToolResponse ?? null) !== canonicalTaskJson(action.participantToolResponse) ||
        canonicalTaskJson(value.paymentProtocol ?? null) !== canonicalTaskJson(action.paymentProtocol) ||
        action.receiptStatus === 'rejected_before_execution' &&
          (typeof value.reasonCode !== 'string' || value.reasonCode.length < 1 || value.reasonCode.length > 128 ||
            !Number.isSafeInteger(value.httpStatus) || (value.httpStatus as number) < 400 || (value.httpStatus as number) > 499) ||
        reference.path !== action.actionEvidence.path || reference.sha256.toLowerCase() !== action.actionEvidence.sha256.toLowerCase()) {
      fail(409, 'TASK_EVIDENCE_CAPTURE_ACTION_MISMATCH', 'A retained M1 action child does not match its immutable packet projection');
    }
    return value;
  }

  private async verifyM1OwnerActions(
    tx: Transaction,
    row: EvidenceRow,
    taskCase: Extract<TaskCase, { taskId: 'M1' }>,
    packet: M1CapturePacket,
    actionEvidenceByPath: ReadonlyMap<string, Record<string, unknown>>,
    bundle: { binding: Record<string, unknown>; observations: Record<string, unknown> },
    assets: Array<{ assetId: string; address: string | null; kind: 'native' | 'erc20'; chainId: number }>,
    localChainId: number,
  ): Promise<void> {
    const actionRows = await tx.execute(sql`SELECT a.id::text AS id,a.run_id::text AS run_id,a.task_index,a.owner_id::text AS owner_id,
        a.agent_id::text AS agent_id,a.task_id,a.environment_id,a.action_sequence::text AS action_sequence,a.operation_id,a.payload_hash,
        a.action_kind,a.command_json,r.receipt_revision,r.receipt_status,r.evidence_hash,r.evidence_path,r.transaction_hash,
        r.tool_response_json,r.tool_response_hash,h.revision AS history_revision,h.receipt_status AS history_status,
        h.evidence_hash AS history_evidence_hash,h.evidence_path AS history_evidence_path,h.transaction_hash AS history_transaction_hash,
        h.tool_response_json AS history_tool_response_json,h.tool_response_hash AS history_tool_response_hash
      FROM oid_run_task_action a JOIN oid_run_task_action_receipt r ON r.action_id=a.id
      LEFT JOIN LATERAL (SELECT revision,receipt_status,evidence_hash,evidence_path,transaction_hash,tool_response_json,tool_response_hash
        FROM oid_run_task_action_reconciliation WHERE action_id=a.id ORDER BY revision DESC LIMIT 1) h ON true
      WHERE a.run_id=${row.run_id} AND a.task_index=${row.task_index}
      ORDER BY a.action_sequence LIMIT ${MAX_EVIDENCE_FILES + 1}`) as unknown as Array<Record<string, unknown>>;
    const cutoff = safeSequence(row.action_cutoff_sequence);
    if (cutoff === null || cutoff > MAX_EVIDENCE_FILES || actionRows.length !== cutoff || packet.ownerActions.length !== cutoff) {
      fail(409, 'TASK_EVIDENCE_CAPTURE_ACTION_MISMATCH', 'The sealed M1 owner-action list does not match its immutable cutoff');
    }
    const actionById = new Map<string, { action: M1CaptureAction; command: TaskActionCommand }>();
    for (let index = 0; index < actionRows.length; index += 1) {
      const value = actionRows[index]!;
      const action = packet.ownerActions[index]!;
      const sequence = safeSequence(value.action_sequence as string | number);
      const parsedCommand = TaskActionCommandSchema.safeParse(jsonValue(value.command_json));
      const actionRef = action.actionEvidence;
      const child = actionEvidenceByPath.get(actionRef.path);
      const response = value.tool_response_json === null || value.tool_response_json === undefined ? null : jsonValue(value.tool_response_json);
      const historyResponse = value.history_tool_response_json === null || value.history_tool_response_json === undefined ? null : jsonValue(value.history_tool_response_json);
      const actualTransaction = typeof value.transaction_hash === 'string' ? value.transaction_hash.toLowerCase() : null;
      const expectedTransaction = action.transactionHash?.toLowerCase() ?? null;
      if (sequence !== index + 1 || !UUID.test(String(value.id)) || value.run_id !== row.run_id || value.owner_id !== row.owner_id ||
          value.agent_id !== row.agent_id || Number(value.task_index) !== row.task_index || value.task_id !== 'M1' || value.environment_id !== row.environment_id ||
          value.id !== action.actionId || value.operation_id !== action.ownerOperationId || sequence !== action.actionSequence ||
          value.action_kind !== action.actionKind || typeof value.payload_hash !== 'string' || !HASH.test(value.payload_hash) ||
          value.payload_hash.toLowerCase() !== action.commandSha256.toLowerCase() || !parsedCommand.success ||
          parsedCommand.data.kind !== action.actionKind || sha256CanonicalTaskJson({ runId: row.run_id, taskIndex: row.task_index, command: parsedCommand.data }).toLowerCase() !== value.payload_hash.toLowerCase() ||
          value.receipt_status !== action.receiptStatus || value.history_revision !== value.receipt_revision || value.history_status !== value.receipt_status ||
          value.history_evidence_hash !== value.evidence_hash || value.history_evidence_path !== value.evidence_path ||
          (typeof value.history_transaction_hash === 'string' ? value.history_transaction_hash.toLowerCase() : null) !== actualTransaction ||
          value.evidence_path !== actionRef.path || typeof value.evidence_hash !== 'string' || value.evidence_hash.toLowerCase() !== actionRef.sha256.toLowerCase() ||
          actualTransaction !== expectedTransaction || !child ||
          canonicalTaskJson(response) !== canonicalTaskJson(action.participantToolResponse) ||
          canonicalTaskJson(historyResponse) !== canonicalTaskJson(response) ||
          typeof value.tool_response_hash === 'string' && value.tool_response_hash.toLowerCase() !== sha256CanonicalTaskJson(response).toLowerCase() ||
          value.tool_response_hash === null && response !== null || value.history_tool_response_hash !== value.tool_response_hash) {
        fail(409, 'TASK_EVIDENCE_CAPTURE_ACTION_MISMATCH', 'A sealed M1 owner action differs from its durable action and receipt rows');
      }
      if (action.receiptStatus === 'observed') {
        if (!action.participantToolResponse || !child ||
            canonicalTaskJson(child.participantToolResponse ?? null) !== canonicalTaskJson(action.participantToolResponse) ||
            !child.rawResponseSha256 || child.rawResponseSha256 !== action.rawResponseSha256) {
          fail(409, 'TASK_EVIDENCE_CAPTURE_ACTION_MISMATCH', 'An observed M1 action has no matching original response evidence');
        }
        if ((parsedCommand.data.kind === 'inspect_catalog' || parsedCommand.data.kind === 'inspect_offer') &&
            !readOnlyToolResponseMatches(parsedCommand.data, action.participantToolResponse)) {
          fail(409, 'TASK_EVIDENCE_CAPTURE_ACTION_MISMATCH', 'An M1 public read response does not match its admitted command');
        }
      } else if (response !== null || action.participantToolResponse !== null || actualTransaction !== null) {
        fail(409, 'TASK_EVIDENCE_CAPTURE_ACTION_MISMATCH', 'A rejected M1 action must have an immutable no-response receipt');
      }
      actionById.set(action.actionId, { action, command: parsedCommand.data });
    }
    for (const { action, command } of actionById.values()) {
      if (action.receiptStatus === 'rejected_before_execution') continue;
      if (command.kind === 'pay') {
        const previous = actionById.get(command.offerReadActionId);
        if (!previous || previous.action.actionSequence >= action.actionSequence ||
            !['inspect_catalog', 'inspect_offer'].includes(previous.command.kind) || action.paymentProtocol === null ||
            canonicalTaskJson(action.paymentProtocol.readHandle) !== canonicalTaskJson(previous.action.participantToolResponse?.readHandle)) {
          fail(409, 'TASK_EVIDENCE_CAPTURE_ACTION_MISMATCH', 'An M1 payment does not reference its exact prior public read');
        }
      } else if (command.kind === 'retrieve') {
        const previous = actionById.get(command.payActionId);
        if (!previous || previous.command.kind !== 'pay' || previous.action.actionSequence >= action.actionSequence ||
            previous.action.receiptStatus !== 'observed' || action.actionSequence <= previous.action.actionSequence) {
          fail(409, 'TASK_EVIDENCE_CAPTURE_ACTION_MISMATCH', 'An M1 retrieval does not reference its exact prior payment action');
        }
      }
    }
    const projected = projectM1PacketObservations(packet, {
      taskCase, binding: bundle.binding as unknown as TaskEvidenceBinding, taskIndex: row.task_index,
      closureId: row.closure_id, captureEvidence: bundle.observations.captureEvidence as EvidenceReference, assets,
    });
    for (const domain of ['transfers', 'payments', 'stateMutations', 'deliveries', 'expenses'] as const) {
      if (canonicalTaskJson(bundle.observations[domain]) !== canonicalTaskJson(projected[domain])) {
        fail(409, 'TASK_EVIDENCE_CAPTURE_OBSERVATION_MISMATCH', `The sealed M1 ${domain} observations do not match the retained packet`);
      }
      if ((bundle.observations.coverage as Record<string, unknown>)[domain] !== projected.coverage[domain]) {
        fail(409, 'TASK_EVIDENCE_CAPTURE_OBSERVATION_MISMATCH', `The sealed M1 ${domain} coverage does not match the retained packet`);
      }
    }
    for (const domain of ['finalStates', 'allowanceChanges', 'allowanceUses', 'answers', 'selections', 'trades', 'conversions'] as const) {
      if (!Array.isArray(bundle.observations[domain]) || (bundle.observations[domain] as unknown[]).length !== 0) {
        fail(409, 'TASK_EVIDENCE_CAPTURE_OBSERVATION_MISMATCH', `The M1 ${domain} domain contains unsupported observations`);
      }
    }
    if (String(packet.rpc.localChainId) !== String(localChainId)) {
      fail(409, 'TASK_EVIDENCE_CAPTURE_RPC_MISMATCH', 'The M1 RPC chain does not match the admitted execution');
    }
  }

  private readS4CapturePacketChildren(bytes: Buffer, bundle: {
    binding: Record<string, unknown>; closure: Record<string, unknown>;
    execution: Record<string, unknown>; observations: Record<string, unknown>;
  }): EvidenceReference[] {
    try { return verifyS4CapturePacketChildren(bytes, bundle); }
    catch (error) {
      if (error instanceof S4CapturePacketError) {
        fail(409, 'TASK_EVIDENCE_CAPTURE_BINDING_MISMATCH', 'The S4 capture packet or observation bindings do not match the sealed task');
      }
      throw error;
    }
  }

  private readS2CapturePacketChildren(
    bytes: Buffer,
    bundle: { binding: Record<string, unknown>; closure: Record<string, unknown>; execution: Record<string, unknown>; cutoff: Record<string, unknown>; observations: Record<string, unknown> },
    row: EvidenceRow,
    taskCase: Extract<TaskCase, { taskId: 'S2' }>,
    localChainId: number,
  ): { children: EvidenceReference[]; actions: Record<string, unknown>[]; packet: Record<string, unknown> } {
    let packet: unknown;
    try { packet = JSON.parse(bytes.toString('utf8')) as unknown; }
    catch { fail(503, 'TASK_EVIDENCE_CAPTURE_PACKET_INVALID', 'The sealed S2 capture packet is malformed'); }
    const cutoff = safeSequence(bundle.closure.actionCutoffSequence as string | number);
    if (!plainObject(packet) || containsSecretKey(packet) ||
        !exactKeys(packet, ['schemaVersion', 'classification', 'binding', 'closure', 'execution', 'preparation', 'ownerActions', 'bef', 'rpc']) ||
        packet.schemaVersion !== 'bts-s2-run-observation-capture/v1' || packet.classification !== 'run_bound_observations_candidate_not_grade' ||
        !plainObject(packet.binding) || !plainObject(packet.closure) || !plainObject(packet.execution) || !plainObject(packet.preparation) ||
        !Array.isArray(packet.ownerActions) || !plainObject(packet.bef) || !plainObject(packet.rpc) ||
        canonicalTaskJson(packet.binding) !== canonicalTaskJson(bundle.binding) || cutoff === null ||
        !exactKeys(packet.closure, ['closureId', 'actionCutoffSequence', 'reconciledActionSequence', 'reason', 'operationId', 'payloadHash', 'answer']) ||
        packet.closure.closureId !== row.closure_id || packet.closure.closureId !== bundle.closure.closureId ||
        safeSequence(packet.closure.actionCutoffSequence as string | number) !== cutoff ||
        safeSequence(packet.closure.reconciledActionSequence as string | number) !== safeSequence(bundle.closure.reconciledActionSequence as string | number) ||
        packet.closure.reason !== row.closure_reason || packet.closure.operationId !== row.closure_operation_id ||
        typeof packet.closure.payloadHash !== 'string' || packet.closure.payloadHash.toLowerCase() !== row.closure_payload_hash.toLowerCase() ||
        !this.s2ClosureAnswerMatches(packet.closure, row) ||
        !exactKeys(packet.execution, ['preparationId', 'leaseId', 'generationId', 'environmentId', 'environmentManifestHash',
          'applicationSourceHash', 'executionIdentityHash', 'initialStateSha256']) ||
        packet.execution.preparationId !== bundle.execution.preparationId || packet.execution.leaseId !== bundle.execution.leaseId ||
        packet.execution.generationId !== bundle.execution.generationId || packet.execution.environmentId !== bundle.binding.environmentId ||
        packet.execution.environmentManifestHash !== bundle.execution.environmentManifestHash ||
        packet.execution.applicationSourceHash !== bundle.execution.applicationSourceHash ||
        packet.execution.executionIdentityHash !== bundle.execution.executionIdentityHash ||
        packet.execution.initialStateSha256 !== bundle.execution.initialStateSha256 ||
        packet.ownerActions.length > MAX_EVIDENCE_FILES || packet.ownerActions.length !== cutoff) {
      fail(409, 'TASK_EVIDENCE_CAPTURE_BINDING_MISMATCH', 'The S2 capture packet does not match the sealed run binding or closure');
    }

    const preparation = packet.preparation;
    if (!exactKeys(preparation, ['fixtureEvidence', 'baselineEvidence', 'baselineBlockNumber', 'baselineBlockHash']) ||
        !validEvidence(preparation.fixtureEvidence) || !validEvidence(preparation.baselineEvidence) ||
        !preparation.fixtureEvidence.path.startsWith(PREPARATION_EVIDENCE_PREFIX) ||
        !preparation.baselineEvidence.path.startsWith(PREPARATION_EVIDENCE_PREFIX) ||
        preparation.fixtureEvidence.path === preparation.baselineEvidence.path ||
        typeof preparation.baselineBlockNumber !== 'string' || !/^(?:0|[1-9][0-9]*)$/.test(preparation.baselineBlockNumber) ||
        typeof preparation.baselineBlockHash !== 'string' || !/^0x[0-9a-f]{64}$/i.test(preparation.baselineBlockHash)) {
      fail(409, 'TASK_EVIDENCE_CAPTURE_PREPARATION_MISMATCH', 'The S2 preparation evidence references are malformed');
    }
    const children: EvidenceReference[] = [preparation.fixtureEvidence, preparation.baselineEvidence];
    const actionSequences = new Set<number>();
    const actionIds = new Set<string>();
    const operationIds = new Set<string>();
    const actions: Record<string, unknown>[] = [];
    for (const value of packet.ownerActions) {
      const allowedKeys = ['actionId', 'actionSequence', 'ownerOperationId', 'actionKind', 'commandSha256',
        'receiptStatus', 'actionEvidence', 'befOperationId'];
      if (!plainObject(value) || !exactKeys(value, allowedKeys) || typeof value.actionId !== 'string' || !UUID.test(value.actionId) ||
          !Number.isSafeInteger(value.actionSequence) || (value.actionSequence as number) < 1 ||
          (value.actionSequence as number) > cutoff || actionSequences.has(value.actionSequence as number) || actionIds.has(value.actionId) ||
          typeof value.ownerOperationId !== 'string' || value.ownerOperationId.length < 12 || value.ownerOperationId.length > 128 ||
          value.actionKind !== 'inspect_offer' || typeof value.commandSha256 !== 'string' || !HASH.test(value.commandSha256) ||
          value.receiptStatus !== 'observed' || !validEvidence(value.actionEvidence) ||
          !value.actionEvidence.path.startsWith(ACTION_EVIDENCE_PREFIX) || typeof value.befOperationId !== 'string' ||
          !UUID.test(value.befOperationId) || operationIds.has(value.befOperationId)) {
        fail(409, 'TASK_EVIDENCE_CAPTURE_ACTION_MISMATCH', 'An S2 owner action reference is malformed or outside the sealed cutoff');
      }
      actionSequences.add(value.actionSequence as number);
      actionIds.add(value.actionId);
      operationIds.add(value.befOperationId);
      actions.push(value);
      children.push(value.actionEvidence as EvidenceReference);
    }
    if ([...actionSequences].some((sequence, index) => sequence !== index + 1)) {
      fail(409, 'TASK_EVIDENCE_CAPTURE_ACTION_MISMATCH', 'S2 owner actions do not match their contiguous admitted sequence');
    }

    this.validateS2ObserverPacket(packet, bundle, row, taskCase, localChainId, preparation);
    return { children, actions, packet };
  }

  private s2ClosureAnswerMatches(closure: Record<string, unknown>, row: EvidenceRow): boolean {
    let databaseAnswer: unknown;
    try { databaseAnswer = jsonValue(row.closure_answer_json); }
    catch { return false; }
    if (canonicalTaskJson(closure.answer) !== canonicalTaskJson(databaseAnswer)) return false;
    if (databaseAnswer !== null) {
      const parsed = TaskFinishAnswerSchemas.S2.safeParse(databaseAnswer);
      if (!parsed.success || canonicalTaskJson(parsed.data) !== canonicalTaskJson(databaseAnswer)) return false;
    }
    if (closure.reason === 'agent_finish') {
      if (row.closure_operation_id === null || typeof closure.operationId !== 'string' ||
          closure.operationId.length < 12 || closure.operationId.length > 128) return false;
      return sha256CanonicalTaskJson({ action: 'task_finish', runId: row.run_id,
        taskIndex: row.task_index, answer: databaseAnswer ?? null }).toLowerCase() === row.closure_payload_hash.toLowerCase();
    }
    return ['task_deadline', 'run_deadline'].includes(String(closure.reason)) && row.closure_operation_id === null &&
      databaseAnswer === null && sha256CanonicalTaskJson({ runId: row.run_id, taskIndex: row.task_index,
        reason: closure.reason }).toLowerCase() === row.closure_payload_hash.toLowerCase();
  }

  private validateS2ObserverPacket(
    packet: Record<string, unknown>,
    bundle: { binding: Record<string, unknown>; execution: Record<string, unknown>; cutoff: Record<string, unknown>; observations: Record<string, unknown> },
    row: EvidenceRow,
    taskCase: Extract<TaskCase, { taskId: 'S2' }>,
    localChainId: number,
    preparation: Record<string, unknown>,
  ): void {
    const closure = packet.closure as Record<string, unknown>;
    const cutoff = safeSequence(closure.actionCutoffSequence as string | number);
    if (cutoff === null) fail(409, 'TASK_EVIDENCE_CAPTURE_BINDING_MISMATCH', 'The S2 action cutoff is invalid');
    const bef = packet.bef as Record<string, unknown>;
    if (!exactKeys(bef, ['session', 'before', 'after', 'censusSha256']) || !plainObject(bef.session) ||
        !plainObject(bef.before) || !plainObject(bef.after) || typeof bef.censusSha256 !== 'string' || !HASH.test(bef.censusSha256) ||
        !exactKeys(bef.session, ['currentUser', 'sessionUser', 'databaseName', 'transactionReadOnly', 'superuser', 'bypassRls']) ||
        bef.session.currentUser !== 'bef_observer' || bef.session.sessionUser !== 'bef_observer' ||
        typeof bef.session.databaseName !== 'string' || bef.session.databaseName.length < 1 || bef.session.databaseName.length > 128 ||
        bef.session.transactionReadOnly !== 'on' || bef.session.superuser !== false || bef.session.bypassRls !== false ||
        canonicalTaskJson(bef.before) !== canonicalTaskJson(bef.after) ||
        sha256CanonicalTaskJson(bef.before).toLowerCase() !== bef.censusSha256.toLowerCase()) {
      fail(409, 'TASK_EVIDENCE_CAPTURE_OBSERVER_MISMATCH', 'The S2 read-only observer census is malformed or changed');
    }
    const census = bef.before;
    const censusKeys = ['generation', 'operations', 'selectedExecutions', 'selectedEvents', 'payments', 'deliveries', 'costs',
      'denials', 'x402Observations', 'rpcObservations', 'evidenceArtifacts'];
    if (!exactKeys(census, censusKeys) || !plainObject(census.generation) ||
        !['operations', 'selectedExecutions', 'selectedEvents', 'payments', 'deliveries', 'costs', 'denials', 'x402Observations',
          'rpcObservations', 'evidenceArtifacts'].every((key) => Array.isArray(census[key]) && (census[key] as unknown[]).length <= 2048)) {
      fail(409, 'TASK_EVIDENCE_CAPTURE_OBSERVER_MISMATCH', 'The S2 read-only census shape is malformed');
    }
    const generation = census.generation;
    if (!exactKeys(generation, ['generation_id', 'env_id', 'participant_id', 'payer_address', 'manifest_sha256', 'status',
      'resource_variant', 'fixture_transaction_hash', 'fixture_block_hash', 'fixture_token_delta_units', 'fixture_native_balance_wei',
      'expires_at', 'fenced_at', 'chain_id', 'node_identity', 'environment_manifest_sha256']) ||
        generation.generation_id !== bundle.execution.generationId || generation.env_id !== bundle.binding.environmentId ||
        generation.manifest_sha256 !== bundle.execution.environmentManifestHash || generation.environment_manifest_sha256 !== bundle.execution.environmentManifestHash ||
        String(generation.chain_id) !== String(localChainId) || generation.resource_variant !== 'canonical' ||
        generation.status !== 'active' || generation.fenced_at !== null) {
      fail(409, 'TASK_EVIDENCE_CAPTURE_OBSERVER_MISMATCH', 'The S2 observer generation does not match the sealed execution');
    }
    const actions = packet.ownerActions as Record<string, unknown>[];
    const operations = census.operations as unknown[];
    if (operations.length !== actions.length ||
        !operations.every((value) => plainObject(value) && exactKeys(value, ['operation_id', 'env_id', 'generation_id', 'participant_id',
          'idempotency_key_sha256', 'request_sha256', 'operation_kind', 'status', 'receipt_status', 'transaction_hash',
          'response_sha256', 'started_at', 'completed_at']) &&
          value.env_id === bundle.binding.environmentId && value.generation_id === bundle.execution.generationId &&
          actions.some((action) => action.befOperationId === value.operation_id)) ||
        new Set(operations.filter(plainObject).map((value) => value.operation_id)).size !== actions.length ||
        ['selectedExecutions', 'selectedEvents', 'payments', 'deliveries', 'costs', 'denials', 'x402Observations', 'rpcObservations', 'evidenceArtifacts']
          .some((key) => (census[key] as unknown[]).length !== 0)) {
      fail(409, 'TASK_EVIDENCE_CAPTURE_NO_EFFECT_MISMATCH', 'The S2 observer census does not bind only the declared free reads');
    }

    const rpc = packet.rpc as Record<string, unknown>;
    if (!exactKeys(rpc, ['localChainId', 'baseline', 'final', 'intervalBlocks', 'participantLogQueryCount', 'responseHashes']) ||
        String(rpc.localChainId) !== String(localChainId) || !plainObject(rpc.baseline) || !plainObject(rpc.final) ||
        !Array.isArray(rpc.intervalBlocks) || rpc.intervalBlocks.length > 256 ||
        !Number.isSafeInteger(rpc.participantLogQueryCount) || (rpc.participantLogQueryCount as number) < 0 ||
        (rpc.participantLogQueryCount as number) > 2048 || !Array.isArray(rpc.responseHashes) || rpc.responseHashes.length > 4096) {
      fail(409, 'TASK_EVIDENCE_CAPTURE_RPC_MISMATCH', 'The S2 RPC proof is malformed');
    }
    const validCheckpoint = (value: Record<string, unknown>) => exactKeys(value, ['blockNumber', 'blockHash', 'parentHash', 'balances', 'allowances', 'participantTransactionCount']) &&
      typeof value.blockNumber === 'string' && /^(?:0|[1-9][0-9]*)$/.test(value.blockNumber) &&
      typeof value.blockHash === 'string' && /^0x[0-9a-f]{64}$/i.test(value.blockHash) &&
      typeof value.parentHash === 'string' && /^0x[0-9a-f]{64}$/i.test(value.parentHash) &&
      typeof value.participantTransactionCount === 'string' && /^(?:0|[1-9][0-9]*)$/.test(value.participantTransactionCount) &&
      Array.isArray(value.balances) && value.balances.length <= 256 && value.balances.every((item) => plainObject(item) &&
        exactKeys(item, ['account', 'assetId', 'amountUnits']) && typeof item.account === 'string' && typeof item.assetId === 'string' &&
        typeof item.amountUnits === 'string' && /^(?:0|[1-9][0-9]*)$/.test(item.amountUnits)) &&
      Array.isArray(value.allowances) && value.allowances.length <= 256 && value.allowances.every((item) => plainObject(item) &&
        exactKeys(item, ['owner', 'tokenAssetId', 'spender', 'amountUnits']) && typeof item.owner === 'string' &&
        typeof item.tokenAssetId === 'string' && typeof item.spender === 'string' && typeof item.amountUnits === 'string' &&
        /^(?:0|[1-9][0-9]*)$/.test(item.amountUnits));
    const baseline = rpc.baseline as Record<string, unknown>;
    const final = rpc.final as Record<string, unknown>;
    if (!validCheckpoint(baseline) || !validCheckpoint(final) || baseline.blockNumber !== preparation.baselineBlockNumber ||
        String(baseline.blockHash).toLowerCase() !== String(preparation.baselineBlockHash).toLowerCase() ||
        BigInt(final.blockNumber as string) < BigInt(baseline.blockNumber as string) ||
        baseline.participantTransactionCount !== final.participantTransactionCount ||
        canonicalTaskJson(baseline.balances) !== canonicalTaskJson(final.balances) ||
        canonicalTaskJson(baseline.allowances) !== canonicalTaskJson(final.allowances) ||
        (baseline.balances as unknown[]).length !== taskCase.initialState.balances.length ||
        (baseline.allowances as unknown[]).length !== taskCase.initialState.allowances.length) {
      fail(409, 'TASK_EVIDENCE_CAPTURE_NO_EFFECT_MISMATCH', 'The S2 block-tagged state checkpoints show an effect or do not match preparation');
    }
    const blockRange = BigInt(final.blockNumber as string) - BigInt(baseline.blockNumber as string);
    if (blockRange !== BigInt(rpc.intervalBlocks.length) || rpc.intervalBlocks.some((item, index) => !plainObject(item) ||
        !exactKeys(item, ['number', 'hash', 'parentHash', 'transactionCount']) || item.number !== (BigInt(baseline.blockNumber as string) + BigInt(index + 1)).toString() ||
        typeof item.hash !== 'string' || !/^0x[0-9a-f]{64}$/i.test(item.hash) || typeof item.parentHash !== 'string' ||
        !/^0x[0-9a-f]{64}$/i.test(item.parentHash) || !Number.isSafeInteger(item.transactionCount) || (item.transactionCount as number) < 0)) {
      fail(409, 'TASK_EVIDENCE_CAPTURE_RPC_MISMATCH', 'The S2 block interval is incomplete or malformed');
    }
    const balanceKey = (item: { account: string; assetId: string }) => `${item.account.toLowerCase()}|${item.assetId}`;
    const allowanceKey = (item: { owner: string; tokenAssetId: string; spender: string }) =>
      `${item.owner.toLowerCase()}|${item.tokenAssetId}|${item.spender.toLowerCase()}`;
    const expectedBalances = [...taskCase.initialState.balances].sort((a, b) => balanceKey(a).localeCompare(balanceKey(b)));
    const expectedAllowances = [...taskCase.initialState.allowances].sort((a, b) => allowanceKey(a).localeCompare(allowanceKey(b)));
    const actualBalances = [...baseline.balances as Array<{ account: string; assetId: string; amountUnits: string }>]
      .sort((a, b) => balanceKey(a).localeCompare(balanceKey(b)));
    const actualAllowances = [...baseline.allowances as Array<{ owner: string; tokenAssetId: string; spender: string; amountUnits: string }>]
      .sort((a, b) => allowanceKey(a).localeCompare(allowanceKey(b)));
    if (canonicalTaskJson(actualBalances) !== canonicalTaskJson(expectedBalances) ||
        canonicalTaskJson(actualAllowances) !== canonicalTaskJson(expectedAllowances)) {
      fail(409, 'TASK_EVIDENCE_CAPTURE_NO_EFFECT_MISMATCH', 'The S2 RPC checkpoints do not match the pinned initial balances and allowances');
    }
    for (const item of rpc.responseHashes) {
      if (!plainObject(item) || !exactKeys(item, ['method', 'paramsSha256', 'resultSha256']) || typeof item.method !== 'string' ||
          item.method.length < 1 || item.method.length > 80 || typeof item.paramsSha256 !== 'string' || !HASH.test(item.paramsSha256) ||
          typeof item.resultSha256 !== 'string' || !HASH.test(item.resultSha256)) {
        fail(409, 'TASK_EVIDENCE_CAPTURE_RPC_MISMATCH', 'An S2 RPC response hash is malformed');
      }
    }
    this.validateS2AnswerObservations(bundle.observations, closure, bundle.binding, bundle.observations.captureEvidence, row);
    this.validateS2FinalStateObservation(bundle.observations, bundle.binding, bundle.observations.captureEvidence, final,
      cutoff, closure.answer !== null);
  }

  private validateS2FinalStateObservation(
    observations: Record<string, unknown>, binding: Record<string, unknown>, captureEvidence: unknown,
    final: Record<string, unknown>, cutoff: number, hasAnswer: boolean,
  ): void {
    const finalStates = observations.finalStates;
    const expectedSequence = hasAnswer ? 2 : 1;
    if (!Array.isArray(finalStates) || finalStates.length !== 1 || !plainObject(finalStates[0]) ||
        !exactKeys(finalStates[0], ['kind', 'observationId', 'sequence', 'actionSequence', 'source', 'binding', 'evidence', 'balances', 'allowances']) ||
        finalStates[0].kind !== 'final_state' || finalStates[0].sequence !== expectedSequence ||
        finalStates[0].actionSequence !== cutoff || finalStates[0].source !== 'persisted_observer' ||
        canonicalTaskJson(finalStates[0].binding) !== canonicalTaskJson(binding) ||
        canonicalTaskJson(finalStates[0].evidence) !== canonicalTaskJson(captureEvidence) ||
        canonicalTaskJson(finalStates[0].balances) !== canonicalTaskJson(final.balances) ||
        canonicalTaskJson(finalStates[0].allowances) !== canonicalTaskJson(final.allowances) ||
        observations.coveredThroughSequence !== expectedSequence) {
      fail(409, 'TASK_EVIDENCE_FINAL_STATE_MISMATCH', 'The S2 final-state observation does not match its block-tagged RPC checkpoint');
    }
  }

  private validateS2AnswerObservations(
    observations: Record<string, unknown>, closure: Record<string, unknown>, binding: Record<string, unknown>, captureEvidence: unknown, row: EvidenceRow,
  ): void {
    if (!Array.isArray(observations.answers)) fail(409, 'TASK_EVIDENCE_ANSWER_MISMATCH', 'The S2 answer observation domain is malformed');
    let answer: unknown;
    try { answer = jsonValue(row.closure_answer_json); }
    catch { fail(409, 'TASK_EVIDENCE_ANSWER_MISMATCH', 'The S2 database answer is malformed'); }
    if (canonicalTaskJson(closure.answer) !== canonicalTaskJson(answer)) {
      fail(409, 'TASK_EVIDENCE_ANSWER_MISMATCH', 'The S2 packet answer does not match the immutable closure answer');
    }
    const entries = observations.answers as unknown[];
    if (answer === null) {
      if (entries.length !== 0) fail(409, 'TASK_EVIDENCE_ANSWER_MISMATCH', 'An S2 answer observation exists without a submitted answer');
      return;
    }
    if (entries.length !== 1 || !plainObject(entries[0])) fail(409, 'TASK_EVIDENCE_ANSWER_MISMATCH', 'The S2 submitted answer lacks one matching observation');
    const entry = entries[0];
    if (!exactKeys(entry, ['kind', 'observationId', 'sequence', 'actionSequence', 'source', 'binding', 'evidence', 'answer']) ||
        entry.kind !== 'final_answer' || entry.observationId !== `s2-answer-${row.closure_id}` || entry.sequence !== 1 ||
        entry.actionSequence !== safeSequence(closure.actionCutoffSequence as string | number) || entry.source !== 'persisted_observer' ||
        canonicalTaskJson(entry.binding) !== canonicalTaskJson(binding) || canonicalTaskJson(entry.evidence) !== canonicalTaskJson(captureEvidence) ||
        canonicalTaskJson(entry.answer) !== canonicalTaskJson(answer)) {
      fail(409, 'TASK_EVIDENCE_ANSWER_MISMATCH', 'The S2 answer observation does not match the immutable closure answer');
    }
  }

  private validateS2ActionEvidence(
    bytes: Buffer,
    reference: EvidenceReference,
    action: Record<string, unknown>,
    bundle: { binding: Record<string, unknown>; execution: Record<string, unknown> },
    taskCase: Extract<TaskCase, { taskId: 'S2' }>,
    assets: Array<{ assetId: string; address: string | null; kind: 'native' | 'erc20'; chainId: number }>,
    localChainId: number,
    taskIndex: number,
  ): Record<string, unknown> {
    let value: unknown;
    try { value = JSON.parse(bytes.toString('utf8')) as unknown; }
    catch { fail(503, 'TASK_EVIDENCE_ACTION_PACKET_INVALID', 'A retained S2 owner action file is malformed'); }
    const actionKeys = ['schema', 'actionId', 'runId', 'taskIndex', 'actionSequence', 'ownerOperationId', 'actionKind', 'commandSha256',
      'environmentId', 'generationId', 'manifestSha256', 'applicationSourceSha256', 'idempotencyKey', 'status', 'reasonCode',
      'requestStartedAt', 'requestFinishedAt', 'httpStatus', 'befOperationId', 'transactionHash', 'outcome', 'receiptStatus',
      'rawResponseSha256', 'participantToolResponse', 'receiptGasUsed', 'receiptEffectiveGasPriceWei', 'paymentProtocol', 'environmentHealth'];
    if (!plainObject(value) || containsSecretKey(value) || Object.keys(value).some((key) => !actionKeys.includes(key)) ||
        value.schema !== 'bef-task-action-observation-v1' || value.actionId !== action.actionId || value.runId !== bundle.binding.runId ||
        Number(value.taskIndex) !== taskIndex || String(value.actionSequence) !== String(action.actionSequence) ||
        value.ownerOperationId !== action.ownerOperationId || value.actionKind !== 'inspect_offer' ||
        typeof value.commandSha256 !== 'string' || value.commandSha256.toLowerCase() !== String(action.commandSha256).toLowerCase() ||
        value.environmentId !== bundle.binding.environmentId || value.generationId !== bundle.execution.generationId ||
        value.manifestSha256 !== bundle.execution.environmentManifestHash || value.applicationSourceSha256 !== bundle.execution.applicationSourceHash ||
        value.idempotencyKey !== `task-action-${action.actionId}` || value.status !== 'observed' || value.httpStatus !== 200 ||
        value.befOperationId !== action.befOperationId || value.transactionHash !== undefined || value.receiptStatus !== undefined ||
        value.outcome !== undefined || typeof value.rawResponseSha256 !== 'string' || !HASH.test(value.rawResponseSha256) ||
        !plainObject(value.participantToolResponse)) {
      fail(409, 'TASK_EVIDENCE_CAPTURE_ACTION_MISMATCH', 'A retained S2 owner action does not match its sealed packet reference');
    }
    const actionReference = action.actionEvidence as EvidenceReference;
    if (reference.path !== actionReference.path || reference.sha256.toLowerCase() !== actionReference.sha256.toLowerCase()) {
      fail(409, 'TASK_EVIDENCE_CAPTURE_ACTION_MISMATCH', 'A retained S2 owner action file reference changed');
    }
    const command = { kind: 'inspect_offer' as const, resourceId: taskCase.objective.resourceId, offerId: taskCase.objective.offerId };
    const body = value.participantToolResponse;
    const handle = body.readHandle;
    const expected = taskCase.objective.completePaymentRequirements;
    const pinnedAsset = assets.find((item) => item.assetId === expected.assetId);
    const selected = Array.isArray(body.offers) ? body.offers.find((offer) => plainObject(offer) && offer.id === taskCase.objective.offerId) : null;
    const payment = plainObject(selected) && plainObject(selected.payment) ? selected.payment : null;
    const asset = payment && typeof payment.asset === 'string' ? payment.asset.toLowerCase() : '';
    if (!readOnlyToolResponseMatches(command, body) || body.resourceId !== taskCase.objective.resourceId ||
        body.operationId !== action.befOperationId || !plainObject(handle) || !exactKeys(handle, ['kind', 'operationId']) ||
        handle.kind !== 'offer' || handle.operationId !== action.befOperationId || !payment ||
        payment.scheme !== expected.scheme || payment.network !== expected.network || payment.amount !== expected.amountUnits ||
        typeof payment.payTo !== 'string' || payment.payTo.toLowerCase() !== expected.recipient.toLowerCase() || !asset ||
        !pinnedAsset || pinnedAsset.kind !== 'erc20' || pinnedAsset.chainId !== localChainId ||
        !pinnedAsset.address || asset !== pinnedAsset.address.toLowerCase() ||
        typeof payment.transferMethod !== 'string' || payment.transferMethod !== expected.authFields.find((field) => field.name === 'assetTransferMethod')?.value) {
      fail(409, 'TASK_EVIDENCE_CAPTURE_ACTION_MISMATCH', 'The S2 free offer response or scoped read handle is invalid');
    }
    return value;
  }

  private async verifyS2OwnerActions(
    tx: Transaction,
    row: EvidenceRow,
    taskCase: Extract<TaskCase, { taskId: 'S2' }>,
    packetActions: Record<string, unknown>[],
    actionEvidenceByPath: ReadonlyMap<string, Record<string, unknown>>,
    census: Record<string, unknown>,
  ): Promise<void> {
    const actionRows = await tx.execute(sql`SELECT a.id::text AS id,a.run_id::text AS run_id,a.task_index,a.owner_id::text AS owner_id,
        a.agent_id::text AS agent_id,a.task_id,a.environment_id,a.action_sequence::text AS action_sequence,a.operation_id,a.payload_hash,
        a.action_kind,a.command_json,r.receipt_revision,r.receipt_status,r.evidence_hash,r.evidence_path,r.transaction_hash,
        h.revision AS history_revision,h.receipt_status AS history_status,h.evidence_hash AS history_evidence_hash,
        h.evidence_path AS history_evidence_path,h.transaction_hash AS history_transaction_hash
      FROM oid_run_task_action a JOIN oid_run_task_action_receipt r ON r.action_id=a.id
      LEFT JOIN LATERAL (SELECT revision,receipt_status,evidence_hash,evidence_path,transaction_hash
        FROM oid_run_task_action_reconciliation WHERE action_id=a.id ORDER BY revision DESC LIMIT 1) h ON true
      WHERE a.run_id=${row.run_id} AND a.task_index=${row.task_index}
      ORDER BY a.action_sequence LIMIT ${MAX_EVIDENCE_FILES + 1}`) as unknown as Array<Record<string, unknown>>;
    const cutoff = safeSequence(row.action_cutoff_sequence);
    if (cutoff === null || cutoff > MAX_EVIDENCE_FILES || actionRows.length !== cutoff || packetActions.length !== cutoff) {
      fail(409, 'TASK_EVIDENCE_CAPTURE_ACTION_MISMATCH', 'The sealed S2 owner-action list does not match its immutable cutoff');
    }
    for (let index = 0; index < actionRows.length; index += 1) {
      const value = actionRows[index]!;
      const action = packetActions[index]!;
      const sequence = safeSequence(value.action_sequence as string | number);
      const parsedCommand = TaskActionCommandSchema.safeParse(jsonValue(value.command_json));
      const actionRef = action.actionEvidence as EvidenceReference;
      if (sequence !== index + 1 || !UUID.test(String(value.id)) || value.run_id !== row.run_id ||
          value.owner_id !== row.owner_id || value.agent_id !== row.agent_id || Number(value.task_index) !== row.task_index ||
          value.task_id !== 'S2' || value.environment_id !== row.environment_id || value.action_kind !== 'inspect_offer' ||
          typeof value.payload_hash !== 'string' || !HASH.test(value.payload_hash) || value.receipt_status !== 'observed' ||
          value.transaction_hash !== null || value.history_revision !== value.receipt_revision || value.history_status !== value.receipt_status ||
          value.history_evidence_hash !== value.evidence_hash || value.history_evidence_path !== value.evidence_path ||
          value.history_transaction_hash !== value.transaction_hash || value.id !== action.actionId ||
          value.operation_id !== action.ownerOperationId || sequence !== action.actionSequence ||
          value.payload_hash.toLowerCase() !== String(action.commandSha256).toLowerCase() ||
          typeof value.evidence_path !== 'string' || value.evidence_path !== actionRef.path ||
          typeof value.evidence_hash !== 'string' || value.evidence_hash.toLowerCase() !== actionRef.sha256.toLowerCase() ||
          !parsedCommand.success || parsedCommand.data.kind !== 'inspect_offer' ||
          parsedCommand.data.resourceId !== taskCase.objective.resourceId ||
          (parsedCommand.data.offerId !== undefined && parsedCommand.data.offerId !== taskCase.objective.offerId) ||
          sha256CanonicalTaskJson({ runId: row.run_id, taskIndex: Number(value.task_index), command: parsedCommand.data }).toLowerCase() !== value.payload_hash.toLowerCase()) {
        fail(409, 'TASK_EVIDENCE_CAPTURE_ACTION_MISMATCH', 'A sealed S2 owner action differs from the durable action and receipt rows');
      }
      const actionEvidence = actionEvidenceByPath.get(actionRef.path);
      const body = actionEvidence?.participantToolResponse;
      const operation = Array.isArray(census.operations) ? census.operations.find((candidate) => plainObject(candidate) &&
        candidate.operation_id === action.befOperationId) : null;
      if (!actionEvidence || !plainObject(body) || !plainObject(operation)) {
        fail(409, 'TASK_EVIDENCE_CAPTURE_ACTION_MISMATCH', 'An S2 BEF operation is missing its action evidence join');
      }
      const expectedRequestHash = createHash('sha256').update(JSON.stringify({ method: 'GET', path: '/offer',
        resourceId: taskCase.objective.resourceId })).digest('hex');
      const response: Record<string, unknown> = {
        operationId: body.operationId, readHandle: body.readHandle, resourceId: body.resourceId,
        resourceSha256: body.resourceSha256, contentType: body.contentType,
      };
      if (body.dataType !== undefined) response.dataType = body.dataType;
      if (body.schema !== undefined) response.schema = body.schema;
      if (body.provenance !== undefined) response.provenance = body.provenance;
      response.payment = body.payment;
      response.offers = body.offers;
      response.freeInspection = body.freeInspection;
      response.deliveryState = body.deliveryState;
      const expectedResponseHash = createHash('sha256').update(JSON.stringify(response)).digest('hex');
      const expectedIdempotencyHash = createHash('sha256').update(`task-action-${action.actionId}`).digest('hex');
      if (operation.env_id !== row.environment_id || operation.generation_id !== row.generation_id ||
          operation.participant_id !== (census.generation as Record<string, unknown>).participant_id ||
          String(operation.idempotency_key_sha256).toLowerCase() !== expectedIdempotencyHash ||
          String(operation.request_sha256).toLowerCase() !== expectedRequestHash || operation.operation_kind !== 'offer' ||
          operation.status !== 'accepted' || operation.receipt_status !== 'not_submitted' || operation.transaction_hash !== null ||
          String(operation.response_sha256).toLowerCase() !== expectedResponseHash) {
        fail(409, 'TASK_EVIDENCE_CAPTURE_ACTION_MISMATCH', 'An S2 free read does not match its immutable BEF operation projection');
      }
    }
  }

  private readS1CapturePacketChildren(
    bytes: Buffer,
    bundle: { binding: Record<string, unknown>; closure: Record<string, unknown>; execution: Record<string, unknown>; observations: Record<string, unknown> },
  ): EvidenceReference[] {
    let packet: unknown;
    try { packet = JSON.parse(bytes.toString('utf8')) as unknown; }
    catch { fail(503, 'TASK_EVIDENCE_CAPTURE_PACKET_INVALID', 'The sealed S1 capture packet is malformed'); }
    if (!plainObject(packet) || !exactKeys(packet, ['schemaVersion', 'classification', 'binding', 'closure', 'execution', 'preparation', 'ownerActions', 'bef', 'rpc']) ||
        packet.schemaVersion !== 'bts-s1-run-observation-capture/v1' ||
        packet.classification !== 'run_bound_observations_candidate_not_grade' || !plainObject(packet.binding) ||
        !plainObject(packet.closure) || !plainObject(packet.execution) || !plainObject(packet.preparation) ||
        !Array.isArray(packet.ownerActions) || !plainObject(packet.bef) || !plainObject(packet.rpc) ||
        canonicalTaskJson(packet.binding) !== canonicalTaskJson(bundle.binding) ||
        !exactKeys(packet.closure, ['closureId', 'actionCutoffSequence', 'reconciledActionSequence']) ||
        packet.closure.closureId !== bundle.closure.closureId ||
        safeSequence(packet.closure.actionCutoffSequence as string | number) !== safeSequence(bundle.closure.actionCutoffSequence as string | number) ||
        safeSequence(packet.closure.reconciledActionSequence as string | number) !== safeSequence(bundle.closure.reconciledActionSequence as string | number) ||
        !exactKeys(packet.execution, ['preparationId', 'leaseId', 'generationId', 'environmentId', 'environmentManifestHash',
          'applicationSourceHash', 'executionIdentityHash', 'initialStateSha256']) ||
        packet.execution.preparationId !== bundle.execution.preparationId || packet.execution.leaseId !== bundle.execution.leaseId ||
        packet.execution.generationId !== bundle.execution.generationId || packet.execution.environmentId !== bundle.binding.environmentId ||
        packet.execution.environmentManifestHash !== bundle.execution.environmentManifestHash ||
        packet.execution.applicationSourceHash !== bundle.execution.applicationSourceHash ||
        packet.execution.executionIdentityHash !== bundle.execution.executionIdentityHash ||
        packet.execution.initialStateSha256 !== bundle.execution.initialStateSha256 ||
        !exactKeys(packet.preparation, ['fixtureEvidence', 'baselineEvidence', 'baselineBlockNumber', 'baselineBlockHash']) ||
        typeof packet.preparation.baselineBlockNumber !== 'string' || !/^(?:0|[1-9][0-9]*)$/.test(packet.preparation.baselineBlockNumber) ||
        typeof packet.preparation.baselineBlockHash !== 'string' || !/^0x[0-9a-f]{64}$/i.test(packet.preparation.baselineBlockHash) ||
        packet.ownerActions.length > MAX_EVIDENCE_FILES ||
        packet.ownerActions.length !== safeSequence(bundle.closure.actionCutoffSequence as string | number)) {
      fail(409, 'TASK_EVIDENCE_CAPTURE_BINDING_MISMATCH', 'The S1 capture packet does not match the sealed run binding');
    }

    const fixtureEvidence = packet.preparation.fixtureEvidence;
    const baselineEvidence = packet.preparation.baselineEvidence;
    if (!validEvidence(fixtureEvidence) || !validEvidence(baselineEvidence) ||
        !fixtureEvidence.path.startsWith(PREPARATION_EVIDENCE_PREFIX) || !baselineEvidence.path.startsWith(PREPARATION_EVIDENCE_PREFIX) ||
        fixtureEvidence.path === baselineEvidence.path) {
      fail(503, 'TASK_EVIDENCE_REFERENCE_INVALID', 'The S1 preparation evidence references are malformed');
    }
    const children: EvidenceReference[] = [fixtureEvidence, baselineEvidence];
    const actionSequences = new Set<number>();
    const actionIds = new Set<string>();
    for (const value of packet.ownerActions) {
      const allowedKeys = ['actionId', 'actionSequence', 'ownerOperationId', 'actionKind', 'commandSha256',
        'receiptStatus', 'actionEvidence', 'befOperationId', 'transactionHash'];
      if (!plainObject(value) || !exactKeys(value, allowedKeys) || typeof value.actionId !== 'string' || !UUID.test(value.actionId) ||
          !Number.isSafeInteger(value.actionSequence) || (value.actionSequence as number) < 1 ||
          (value.actionSequence as number) > (safeSequence(bundle.closure.actionCutoffSequence as string | number) ?? -1) ||
          actionSequences.has(value.actionSequence as number) || actionIds.has(value.actionId) ||
          typeof value.ownerOperationId !== 'string' || value.ownerOperationId.length < 12 || value.ownerOperationId.length > 128 ||
          value.actionKind !== 'transfer' || typeof value.commandSha256 !== 'string' || !HASH.test(value.commandSha256) ||
          !['observed', 'rejected_before_execution'].includes(String(value.receiptStatus)) ||
          !validEvidence(value.actionEvidence) || !value.actionEvidence.path.startsWith(ACTION_EVIDENCE_PREFIX) ||
          (value.befOperationId !== null && (typeof value.befOperationId !== 'string' || !UUID.test(value.befOperationId))) ||
          (value.transactionHash !== null && (typeof value.transactionHash !== 'string' || !/^0x[0-9a-f]{64}$/i.test(value.transactionHash)))) {
        fail(409, 'TASK_EVIDENCE_CAPTURE_ACTION_MISMATCH', 'An S1 owner action reference is malformed or outside the sealed cutoff');
      }
      actionSequences.add(value.actionSequence as number);
      actionIds.add(value.actionId);
      children.push(value.actionEvidence as EvidenceReference);
    }
    if ([...actionSequences].some((sequence, index) => sequence !== index + 1)) {
      fail(409, 'TASK_EVIDENCE_CAPTURE_ACTION_MISMATCH', 'S1 owner actions do not match their contiguous admitted sequence');
    }

    // The collector seals the packet itself as each observation's evidence reference. Action and
    // preparation references are verified separately; their bytes are not interpreted as facts here.
    const transferObservations = bundle.observations.transfers;
    if (!Array.isArray(transferObservations)) fail(503, 'TASK_EVIDENCE_BUNDLE_UNAVAILABLE', 'S1 transfer observations are malformed');
    const actionBySequence = new Map(packet.ownerActions.map((value) => {
      const action = value as Record<string, unknown>;
      return [action.actionSequence as number, action] as const;
    }));
    for (const observation of transferObservations) {
      if (!plainObject(observation) || !Number.isSafeInteger(observation.actionSequence) ||
          (observation.actionSequence as number) < 0) {
        fail(503, 'TASK_EVIDENCE_BUNDLE_UNAVAILABLE', 'S1 transfer observations are malformed');
      }
      if (observation.actionSequence === 0) continue;
      const action = actionBySequence.get(observation.actionSequence as number);
      if (!action || action.receiptStatus !== 'observed' || observation.observationId !== `s1-transfer-${action.actionId}` ||
          observation.transactionHash !== action.transactionHash) {
        fail(409, 'TASK_EVIDENCE_CAPTURE_ACTION_MISMATCH', 'An S1 transfer observation does not match its sealed owner action');
      }
    }
    for (const action of packet.ownerActions) {
      if (action.receiptStatus === 'observed' && !transferObservations.some((observation) =>
        plainObject(observation) && observation.actionSequence === action.actionSequence &&
        observation.observationId === `s1-transfer-${action.actionId}` && observation.transactionHash === action.transactionHash)) {
        fail(409, 'TASK_EVIDENCE_CAPTURE_ACTION_MISMATCH', 'An observed S1 owner action has no matching sealed transfer');
      }
    }
    return children;
  }
}
