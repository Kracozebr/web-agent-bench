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
import { observationHealthMatches } from './bef-observation-health.js';
import { TaskActionCommandSchema, TaskFinishAnswerSchemas, type TaskActionCommand } from './task-action-service.js';
import { M1CapturePacketError, parseM1CapturePacket, projectM1PacketObservations, splitPayRequestSha256, type M1CaptureAction, type M1CapturePacket } from './task-m1-capture-packet.js';
import { parsePaidDataCapturePacket, projectPaidDataObservationBundle, validatePaidDataCapturePacketPins, type PaidDataAction, type PaidDataCapturePacket } from './task-paid-data-capture-packet.js';
import { parseTaskChainCapturePacket, projectTaskChainCapturePacket, verifyTaskChainCapturePacketChildren } from './task-chain-capture-packet.js';
import type { ChainTaskCase } from './task-chain-capture-packet.js';
import { sameActionEnvelope } from './bef-chain-observation-collector.js';
import { parseS3CapturePacket, projectS3PacketObservations, type S3CaptureAction, type S3CapturePacket } from './task-s3-capture-packet.js';
import { composeTaskObservationCandidates, parseCompositeCapturePacket, verifyCompositeCaptureChildren } from './task-composite-capture-packet.js';
import type { TaskObservationBundleCandidate } from './task-observation-store.js';
import {
  canonicalTaskJson,
  sha256CanonicalTaskJson,
  type EvidenceReference,
  type TaskCase,
  type TaskReleaseQuerySource,
} from './task-release.js';

type Transaction = Parameters<Parameters<OwnerDatabase['transaction']>[0]>[0];
type S1SealedActionProof = { action: Record<string, unknown>; command: TaskActionCommand; operation: Record<string, unknown> };

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
const DEFAULT_MAX_EVIDENCE_TOTAL_BYTES = 32 * 1024 * 1024;const SECRET_KEYS = new Set(['privatekey', 'privkey', 'seedphrase', 'mnemonic', 'secret', 'clientsecret', 'bearer', 'bearertoken',
  'accesstoken', 'refreshtoken', 'providertoken', 'paymenttoken', 'token', 'apitoken', 'apikey', 'authorization',
  'walletmaterial', 'walletsecret', 'signature', 'signedpayload', 'paymentpayload', 'paymentauthorization', 'paymentauth',
  'paymentproof', 'xpayment', 'xpaymentsignature', 'xpaymentpayload', 'xpaymentauthorization', 'x402authorization',
  'x402signature', 'x402payload', 'x402proof', 'rawsignedtransaction']);
const M1_COMMON_NO_REQUEST_REJECTIONS = new Set([
  'owner_admission_fenced', 'agent_access_generation_changed', 'run_or_environment_fenced', 'agent_grant_revoked',
  'run_mode_permission_revoked', 'run_mode_fenced', 'action_sequence_invalid', 'task_cutoff_fenced', 'task_closed',
  'task_not_active', 'task_execution_binding_unavailable', 'release_identity_changed',
]);
const M1_LOCAL_NO_REQUEST_REJECTIONS: Record<M1CaptureAction['actionKind'], ReadonlySet<string>> = {
  inspect_catalog: new Set([...M1_COMMON_NO_REQUEST_REJECTIONS, 'bef_environment_health_unavailable', 'bef_environment_identity_mismatch']),
  inspect_offer: new Set([...M1_COMMON_NO_REQUEST_REJECTIONS, 'bef_environment_health_unavailable', 'bef_environment_identity_mismatch']),
  pay: new Set([...M1_COMMON_NO_REQUEST_REJECTIONS, 'task_payment_protocol_unavailable', 'task_payment_reference_unavailable',
    'task_payment_reference_invalid', 'task_payment_offer_not_inspected', 'task_payment_reference_unavailable',
    'task_x402_local_bef_unavailable', 'bef_environment_identity_mismatch', 'task_split_pay_pinned_context_unavailable']),
  retrieve: new Set([...M1_COMMON_NO_REQUEST_REJECTIONS, 'task_payment_protocol_unavailable', 'task_payment_reference_unavailable',
    'task_payment_reference_invalid', 'task_payment_offer_not_inspected', 'task_x402_local_bef_unavailable',
    'bef_environment_identity_mismatch', 'task_split_retrieve_pinned_context_unavailable', 'task_split_retrieve_pinned_resource_invalid']),
};

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
    if (!['S1','S2','S3','S4','M1','M2','H1','H2','H3','M3','M4','U1'].includes(row.task_id)) return null;
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
      release.manifest.executionIdentity.assets, release.manifest.executionIdentity.contracts, release.manifest.costPolicy.ethValuation);

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
    contracts: Array<{ contractId: string; address: string; codeHash: string }>,
    ethValuation: { numerator: string; denominator: string },
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
        const compositeTask = taskCase.taskId === 'H3' || taskCase.taskId === 'U1';
        if (!compositeTask && canonicalTaskJson(ref) !== canonicalTaskJson(captureEvidence)) {
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
    const s1ActionsByPath = new Map<string, S1SealedActionProof>();
    const s4ActionsByPath = new Map<string, S1SealedActionProof>();
    const m1ActionsByPath = new Map<string, M1CaptureAction>();
    const m1EvidenceByPath = new Map<string, Record<string, unknown>>();
    let m1Packet: M1CapturePacket | null = null;
    let paidPacket: PaidDataCapturePacket | null = null;
    let paidPacketEvidence: EvidenceReference | null = null;
    let compositePacket: ReturnType<typeof parseCompositeCapturePacket> | null = null;
    let chainPacket: ReturnType<typeof parseTaskChainCapturePacket> | null = null;
    let chainPacketEvidence: EvidenceReference | null = null;
    let s3Packet: S3CapturePacket | null = null;
    const s3ActionsByPath = new Map<string, S3CaptureAction>();
    const s3EvidenceByPath = new Map<string, Record<string, unknown>>();
    const paidActionsByPath = new Map<string, PaidDataAction>();
    const paidEvidenceByPath = new Map<string, Record<string, unknown>>();
    const paidResponsesByActionId = new Map<string, Record<string, unknown>>();
    const chainActionsByPath = new Map<string, Record<string, unknown>>();
    const chainEvidenceByPath = new Map<string, Record<string, unknown>>();
    const queue: Array<{ reference: EvidenceReference; ancestors: ReadonlySet<string> }> =
      [...references.values()].map((reference) => ({ reference, ancestors: new Set<string>() }));
    let totalBytes = 0;
    const enqueueChildren = (children: EvidenceReference[], ancestors: ReadonlySet<string>, parentPath: string) => {
      const nextAncestors = new Set([...ancestors, parentPath]);
      for (const child of children) {
        if (nextAncestors.has(child.path)) fail(409, 'TASK_EVIDENCE_REFERENCE_CYCLE', 'Sealed evidence references contain a cycle');
        const existing = references.get(child.path);
        if (existing && existing.sha256.toLowerCase() !== child.sha256.toLowerCase())
          fail(409, 'TASK_EVIDENCE_REFERENCE_CONFLICT', 'One evidence path has conflicting sealed hashes');
        if (!existing) references.set(child.path, child);
        if (references.size > MAX_EVIDENCE_FILES) fail(503, 'TASK_EVIDENCE_REFERENCE_COUNT_INVALID', 'The sealed evidence reference count is outside its supported bound');
        queue.push({ reference: child, ancestors: nextAncestors });
      }
    };
    const verifyPaidPacket = (bytes: Uint8Array, packetRef: EvidenceReference): EvidenceReference[] => {
      let packet: PaidDataCapturePacket;
      try { packet = validatePaidDataCapturePacketPins(parsePaidDataCapturePacket(bytes), localChainId); }
      catch { fail(409, 'TASK_EVIDENCE_CAPTURE_BINDING_MISMATCH', 'The paid-data capture packet is malformed'); }
      const closure = packet.closure,execution = packet.execution;
      if (canonicalTaskJson(packet.binding) !== canonicalTaskJson(bundle.binding) || packet.binding.taskId !== taskCase.taskId ||
          closure.closureId !== row.closure_id || closure.operationId !== row.closure_operation_id || closure.payloadHash !== row.closure_payload_hash ||
          closure.reason !== row.closure_reason || closure.actionCutoffSequence !== safeSequence(row.action_cutoff_sequence) ||
          closure.reconciledActionSequence !== safeSequence(row.reconciled_action_sequence) ||
          execution.preparationId !== row.preparation_id || execution.leaseId !== row.lease_id || execution.generationId !== row.generation_id ||
          execution.environmentId !== row.environment_id || execution.environmentManifestHash !== row.environment_manifest_hash ||
          execution.applicationSourceHash !== row.application_source_hash || execution.executionIdentityHash !== row.execution_identity_hash ||
          execution.initialStateSha256 !== row.initial_state_sha256 || packet.manifest.sha256 !== row.environment_manifest_hash)
        fail(409, 'TASK_EVIDENCE_CAPTURE_BINDING_MISMATCH', 'The paid-data packet does not match its sealed task and execution');
      paidPacket = packet; paidPacketEvidence = packetRef;
      for (const action of packet.ownerActions) {
        paidActionsByPath.set(action.actionEvidence.path, action);
        chainActionsByPath.set(action.actionEvidence.path, action as unknown as Record<string, unknown>);
      }
      return [packet.preparation.fixtureEvidence,packet.preparation.baselineEvidence,...packet.ownerActions.map((action)=>action.actionEvidence)];
    };
    const verifyChainPacket = (bytes: Uint8Array, packetRef: EvidenceReference): EvidenceReference[] => {
      let packet: ReturnType<typeof parseTaskChainCapturePacket>;
      try { packet = parseTaskChainCapturePacket(bytes, taskCase as never); }
      catch { fail(409, 'TASK_EVIDENCE_CAPTURE_BINDING_MISMATCH', 'The chain capture packet is malformed'); }
      const childBundle = { binding: bundle.binding as unknown as TaskEvidenceBinding,
        closure: { closureId: row.closure_id, actionCutoffSequence: safeSequence(row.action_cutoff_sequence)!,
          reconciledActionSequence: safeSequence(row.reconciled_action_sequence)! },
        execution: { ...(bundle.execution as Record<string, unknown>), environmentId: row.environment_id },
        observations: { ...bundle.observations, captureEvidence: packetRef }, taskCase: taskCase as never, ethValuation };
      let children: EvidenceReference[];
      try { children = verifyTaskChainCapturePacketChildren(bytes, childBundle as never); }
      catch { fail(409, 'TASK_EVIDENCE_CAPTURE_BINDING_MISMATCH', 'The chain capture packet does not match its sealed task'); }
      if (packet.taskId !== taskCase.taskId || packet.binding.runId !== row.run_id || packet.execution.environmentManifestHash !== row.environment_manifest_hash ||
          packet.execution.applicationSourceHash !== row.application_source_hash || packet.execution.executionIdentityHash !== row.execution_identity_hash ||
          packet.execution.initialStateSha256 !== row.initial_state_sha256)
        fail(409, 'TASK_EVIDENCE_CAPTURE_BINDING_MISMATCH', 'The chain packet execution pins differ from PostgreSQL');
      chainPacket = packet; chainPacketEvidence = packetRef;
      for (const action of [...packet.ownerActions, ...packet.externalActions]) {
        const key = action.actionEvidence.path;
        const prior = chainActionsByPath.get(key);
        const normalized = { actionId: action.actionId, actionSequence: action.actionSequence, ownerOperationId: action.ownerOperationId,
          actionKind: action.actionKind, commandSha256: action.commandSha256,
          receiptStatus: 'receiptStatus' in action ? action.receiptStatus : 'observed',
          actionEvidence: action.actionEvidence, befOperationId: action.befOperationId, transactionHash: action.transactionHash,
          ...('command' in action ? { command: action.command, selectedAction: action.selectedAction, approvalSpender: action.approvalSpender } : {}),
          ...('inspection' in action && plainObject(action.inspection)
            ? { command: action.inspection.command, rawResponseSha256: action.inspection.rawResponseSha256 } : {}) };
        if (prior && canonicalTaskJson({ actionId: prior.actionId, actionSequence: prior.actionSequence, ownerOperationId: prior.ownerOperationId,
            actionKind: prior.actionKind, commandSha256: prior.commandSha256, receiptStatus: prior.receiptStatus,
            actionEvidence: prior.actionEvidence, befOperationId: prior.befOperationId, transactionHash: prior.transactionHash }) !== canonicalTaskJson(normalized))
          fail(409, 'TASK_EVIDENCE_CAPTURE_ACTION_MISMATCH', 'Paid and chain child packets disagree about a shared owner action');
        chainActionsByPath.set(key, normalized);
      }
      return children;
    };
    const verifyS3Packet = (bytes: Uint8Array, packetRef: EvidenceReference): EvidenceReference[] => {
      let packet: S3CapturePacket;
      try { packet = parseS3CapturePacket(bytes); }
      catch { fail(409, 'TASK_EVIDENCE_CAPTURE_BINDING_MISMATCH', 'The S3 capture packet is malformed'); }
      if (canonicalTaskJson(packet.binding) !== canonicalTaskJson(bundle.binding) || canonicalTaskJson(packet.taskCase) !== canonicalTaskJson(taskCase) ||
          packet.closure.closureId !== row.closure_id || packet.closure.actionCutoffSequence !== safeSequence(row.action_cutoff_sequence) ||
          packet.closure.reconciledActionSequence !== safeSequence(row.reconciled_action_sequence) || packet.closure.taskIndex !== row.task_index ||
          packet.execution.preparationId !== row.preparation_id || packet.execution.leaseId !== row.lease_id || packet.execution.generationId !== row.generation_id ||
          packet.execution.environmentId !== row.environment_id || packet.execution.environmentManifestHash !== row.environment_manifest_hash ||
          packet.execution.applicationSourceHash !== row.application_source_hash || packet.execution.executionIdentityHash !== row.execution_identity_hash ||
          packet.execution.initialStateSha256 !== row.initial_state_sha256)
        fail(409, 'TASK_EVIDENCE_CAPTURE_BINDING_MISMATCH', 'The S3 packet does not match its sealed task and execution');
      s3Packet = packet;
      for (const action of packet.ownerActions) {
        if (s3ActionsByPath.has(action.actionEvidence.path))
          fail(409, 'TASK_EVIDENCE_CAPTURE_ACTION_MISMATCH', 'The S3 packet repeats an action evidence path');
        s3ActionsByPath.set(action.actionEvidence.path, action);
      }
      return [packet.preparation.fixtureEvidence,packet.preparation.baselineEvidence,...packet.ownerActions.map((action)=>action.actionEvidence)];
    };
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
        let discoveredChildren: EvidenceReference[] | null = null;
        if (ref.path === captureEvidence.path) {
          if (taskCase.taskId === 'S2') {
            const parsed = this.readS2CapturePacketChildren(bounded.subarray(0, offset), bundle, row, taskCase, localChainId);
            s2Packet = parsed.packet; discoveredChildren = parsed.children;
            for (const action of parsed.actions) s2ActionsByPath.set((action.actionEvidence as EvidenceReference).path, action);
          } else if (taskCase.taskId === 'M1' && row.mode === 'training') {
            const parsed = this.readM1CapturePacketChildren(bounded.subarray(0, offset), bundle, row, taskCase, localChainId);
            m1Packet = parsed.packet; discoveredChildren = parsed.children;
            for (const action of parsed.actions) m1ActionsByPath.set(action.actionEvidence.path, action);
          } else if ((taskCase.taskId === 'H3' || taskCase.taskId === 'U1')) {
            try { compositePacket = parseCompositeCapturePacket(bounded.subarray(0, offset)); }
            catch { fail(409, 'TASK_EVIDENCE_CAPTURE_BINDING_MISMATCH', 'The composite capture packet is malformed'); }
            const expectedExecution = { ...(bundle.execution as Record<string, unknown>), environmentId: row.environment_id };
            const closure = compositePacket.closure;
            if (canonicalTaskJson(compositePacket.binding) !== canonicalTaskJson(bundle.binding) ||
                canonicalTaskJson(compositePacket.execution) !== canonicalTaskJson(expectedExecution) ||
                closure.closureId !== row.closure_id || closure.operationId !== row.closure_operation_id || closure.payloadHash !== row.closure_payload_hash ||
                closure.reason !== row.closure_reason || closure.actionCutoffSequence !== safeSequence(row.action_cutoff_sequence) ||
                closure.reconciledActionSequence !== safeSequence(row.reconciled_action_sequence))
              fail(409, 'TASK_EVIDENCE_CAPTURE_BINDING_MISMATCH', 'The composite packet does not match its sealed closure');
            discoveredChildren = [compositePacket.children.paid.evidence,compositePacket.children.chain.evidence];
          } else if ((taskCase.taskId === 'M1' && row.mode === 'ranked') || taskCase.taskId === 'M2' || taskCase.taskId === 'H1') {
            discoveredChildren = verifyPaidPacket(bounded.subarray(0, offset), captureEvidence);
          } else if (taskCase.taskId === 'M3' || taskCase.taskId === 'M4' || taskCase.taskId === 'H2') {
            discoveredChildren = verifyChainPacket(bounded.subarray(0, offset), captureEvidence);
          } else if (taskCase.taskId === 'S3') {
            discoveredChildren = verifyS3Packet(bounded.subarray(0, offset), captureEvidence);
          } else if (taskCase.taskId === 'S4') {
            const parsed = await this.readS4CapturePacketChildren(bounded.subarray(0, offset), bundle, tx, row);
            discoveredChildren = parsed.children;
            for (const action of parsed.actions) s4ActionsByPath.set((action.action.actionEvidence as EvidenceReference).path, action);
          }
          else {
            const parsed = await this.readS1CapturePacketChildren(bounded.subarray(0, offset), bundle, tx, row);
            discoveredChildren = parsed.children;
            for (const action of parsed.actions) s1ActionsByPath.set((action.action.actionEvidence as EvidenceReference).path, action);
          }
        } else if (compositePacket && canonicalTaskJson(ref) === canonicalTaskJson(compositePacket.children.paid.evidence)) {
          discoveredChildren = verifyPaidPacket(bounded.subarray(0, offset), ref);
        } else if (compositePacket && canonicalTaskJson(ref) === canonicalTaskJson(compositePacket.children.chain.evidence)) {
          discoveredChildren = verifyChainPacket(bounded.subarray(0, offset), ref);
        } else if (paidActionsByPath.has(ref.path)) {
          const action = paidActionsByPath.get(ref.path)!;
          let evidenceValue: unknown;
          try { evidenceValue = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bounded.subarray(0, offset))) as unknown; }
          catch { fail(409, 'TASK_EVIDENCE_CAPTURE_ACTION_MISMATCH', 'A paid-data action evidence file is malformed'); }
          if (!plainObject(evidenceValue) || containsSecretKey(evidenceValue) || evidenceValue.schema !== 'bef-task-action-observation-v1' || evidenceValue.actionId !== action.actionId ||
              evidenceValue.ownerOperationId !== action.ownerOperationId || evidenceValue.actionKind !== action.actionKind ||
              evidenceValue.commandSha256 !== action.commandSha256 || evidenceValue.status !== action.receiptStatus ||
              evidenceValue.rawResponseSha256 !== action.rawResponseSha256 || evidenceValue.befOperationId !== action.befOperationId ||
              (typeof evidenceValue.transactionHash === 'string' ? evidenceValue.transactionHash.toLowerCase() : null) !== (action.transactionHash?.toLowerCase() ?? null))
            fail(409, 'TASK_EVIDENCE_CAPTURE_ACTION_MISMATCH', 'A paid-data action differs from its retained action packet');
          const response = plainObject(evidenceValue.participantToolResponse) ? evidenceValue.participantToolResponse : null;
          if (action.receiptStatus === 'observed' && (!response || !action.rawResponseSha256) ||
              action.receiptStatus === 'rejected_before_execution' && (response || action.transactionHash || action.befOperationId))
            fail(409, 'TASK_EVIDENCE_CAPTURE_ACTION_MISMATCH', 'A paid-data action response differs from its receipt status');
          paidEvidenceByPath.set(ref.path, evidenceValue);
          if (response) paidResponsesByActionId.set(action.actionId, response);
        } else if (chainActionsByPath.has(ref.path)) {
          const action = chainActionsByPath.get(ref.path)!;
          let evidenceValue: unknown;
          try { evidenceValue = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bounded.subarray(0, offset))) as unknown; }
          catch { fail(409, 'TASK_EVIDENCE_CAPTURE_ACTION_MISMATCH', 'A chain action evidence file is malformed'); }
          const response = plainObject(evidenceValue) && plainObject(evidenceValue.participantToolResponse)
            ? evidenceValue.participantToolResponse : null;
          const selected = response && plainObject(response.selectedAction) ? response.selectedAction : null;
          const command = plainObject(action.command) ? action.command : null;
          const tokenAssetId = command?.kind === 'approve' ? String(command.tokenAssetId ?? 'WETH') :
            command?.kind === 'transfer' ? 'USDC' : null;
          const releasedToken = tokenAssetId ? assets.find((asset) => asset.assetId === tokenAssetId)?.address?.toLowerCase() ?? null : null;
          const hasPublicToken = selected && Object.hasOwn(selected, 'token');
          const tokenMatchesRelease = tokenAssetId === null ? !hasPublicToken :
            Boolean(releasedToken && typeof selected?.token === 'string' && selected.token.toLowerCase() === releasedToken);
          const scrubbedEvidence = plainObject(evidenceValue) ? structuredClone(evidenceValue) : null;
          if (scrubbedEvidence && tokenMatchesRelease && selected && hasPublicToken) {
            const scrubbedResponse = plainObject(scrubbedEvidence.participantToolResponse) ? scrubbedEvidence.participantToolResponse : null;
            if (scrubbedResponse && plainObject(scrubbedResponse.selectedAction)) delete scrubbedResponse.selectedAction.token;
          }
          const parsedCommand = plainObject(action.command) ? TaskActionCommandSchema.safeParse(action.command) : null;
          const chainAction = ['approve', 'transfer', 'wrap', 'unwrap', 'swap'].includes(String(action.actionKind));
          const selectedEnvelopeMatches = !chainAction || Boolean(selected && parsedCommand?.success && plainObject(action.selectedAction) &&
            sameActionEnvelope(selected, action.selectedAction, parsedCommand.data, taskCase as ChainTaskCase, assets, contracts) &&
            (action.actionKind !== 'approve' || (typeof selected.spender === 'string' &&
              typeof action.approvalSpender === 'string' && selected.spender.toLowerCase() === action.approvalSpender.toLowerCase())));
          if (!plainObject(evidenceValue) || !scrubbedEvidence || containsSecretKey(scrubbedEvidence) || !tokenMatchesRelease ||
              evidenceValue.schema !== 'bef-task-action-observation-v1' || evidenceValue.actionId !== action.actionId ||
              evidenceValue.runId !== row.run_id || Number(evidenceValue.taskIndex) !== row.task_index ||
              String(evidenceValue.actionSequence) !== String(action.actionSequence) || evidenceValue.ownerOperationId !== action.ownerOperationId ||
              evidenceValue.actionKind !== action.actionKind || evidenceValue.commandSha256 !== action.commandSha256 ||
              evidenceValue.environmentId !== row.environment_id || evidenceValue.generationId !== row.generation_id ||
              evidenceValue.manifestSha256 !== row.environment_manifest_hash.toLowerCase() ||
              evidenceValue.applicationSourceSha256 !== row.application_source_hash.toLowerCase() ||
              evidenceValue.idempotencyKey !== `task-action-${action.actionId}` || evidenceValue.status !== action.receiptStatus ||
              (evidenceValue.befOperationId ?? null) !== action.befOperationId ||
              (typeof evidenceValue.transactionHash === 'string' ? evidenceValue.transactionHash.toLowerCase() : null) !==
                (typeof action.transactionHash === 'string' ? action.transactionHash.toLowerCase() : null) ||
              !selectedEnvelopeMatches)
            fail(409, 'TASK_EVIDENCE_CAPTURE_ACTION_MISMATCH', 'A chain action differs from its retained action packet');
          if (action.receiptStatus === 'observed') {
            if (!response || !selected) fail(409, 'TASK_EVIDENCE_CAPTURE_ACTION_MISMATCH', 'A chain action response differs from its receipt status');
            if (!plainObject(response.transaction) || !plainObject(response.receipt) ||
                String(response.operationId).toLowerCase() !== String(action.befOperationId).toLowerCase() ||
                String(response.transaction.hash).toLowerCase() !== String(action.transactionHash).toLowerCase() ||
                String(response.receipt.transactionHash).toLowerCase() !== String(action.transactionHash).toLowerCase() ||
                (response.outcome !== 'success' && response.outcome !== 'reverted') ||
                response.receipt.status !== response.outcome || evidenceValue.receiptStatus !== response.outcome)
              fail(409, 'TASK_EVIDENCE_CAPTURE_ACTION_MISMATCH', 'A chain action response does not match its retained transaction receipt');
          } else if (action.receiptStatus === 'rejected_before_execution' && (response !== null || action.transactionHash !== null)) {
            fail(409, 'TASK_EVIDENCE_CAPTURE_ACTION_MISMATCH', 'A chain action response differs from its receipt status');
          }
          chainEvidenceByPath.set(ref.path, evidenceValue);
        } else if (taskCase.taskId === 'S3' && s3ActionsByPath.has(ref.path)) {
          let evidenceValue: unknown;
          try { evidenceValue = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bounded.subarray(0, offset))) as unknown; }
          catch { fail(409, 'TASK_EVIDENCE_CAPTURE_ACTION_MISMATCH', 'An S3 action evidence file is malformed'); }
          if (!plainObject(evidenceValue)) fail(409, 'TASK_EVIDENCE_CAPTURE_ACTION_MISMATCH', 'An S3 action evidence file is malformed');
          s3EvidenceByPath.set(ref.path, evidenceValue);
        } else if (taskCase.taskId === 'S2' && s2ActionsByPath.has(ref.path)) {
          const evidence = this.validateS2ActionEvidence(bounded.subarray(0, offset), ref, s2ActionsByPath.get(ref.path)!, bundle,
            taskCase, assets, localChainId, row.task_index);
          s2EvidenceByPath.set(ref.path, evidence);
        } else if (taskCase.taskId === 'S1' && s1ActionsByPath.has(ref.path)) {
          const proof = s1ActionsByPath.get(ref.path)!;
          this.validateSealedInspectionAction(bounded.subarray(0, offset), ref, proof, row, 'S1');
        } else if (taskCase.taskId === 'S4' && s4ActionsByPath.has(ref.path)) {
          this.validateSealedInspectionAction(bounded.subarray(0, offset), ref, s4ActionsByPath.get(ref.path)!, row, 'S4');
        } else if (taskCase.taskId === 'M1' && m1ActionsByPath.has(ref.path)) {
          const evidence = this.validateM1ActionEvidence(bounded.subarray(0, offset), ref, m1ActionsByPath.get(ref.path)!, bundle, row);
          m1EvidenceByPath.set(ref.path, evidence);
        }
        if (discoveredChildren) enqueueChildren(discoveredChildren, ancestors, ref.path);
      } finally {
        await handle.close();
      }
    }
    if (chainPacket) await this.verifyChainOwnerActions(tx, row, chainPacket, chainEvidenceByPath, paidEvidenceByPath);
    if (paidPacket) await this.verifyPaidOwnerActions(tx, row, paidPacket, paidEvidenceByPath, taskCase.taskId === 'H3' || taskCase.taskId === 'U1');
    if (s3Packet) await this.verifyS3OwnerActions(tx, row, s3Packet, s3EvidenceByPath);
    const verifyProjectedObservations = (candidate: TaskObservationBundleCandidate): void => {
      if (candidate.schemaVersion !== 'bts-task-observation-bundle-candidate/v1' || candidate.cutoffStatus !== 'authoritative' ||
          candidate.cutoffEvidence === null || canonicalTaskJson(candidate.cutoffEvidence) !== canonicalTaskJson(captureEvidence) ||
          !candidate.observations || candidate.observationCutoffSequence !== candidate.observations.coveredThroughSequence ||
          canonicalTaskJson(candidate.observations) !== canonicalTaskJson(bundle.observations)) {
        fail(409, 'TASK_EVIDENCE_CAPTURE_OBSERVATION_MISMATCH', 'The sealed observations do not match their independently projected capture packet');
      }
    };
    const verifiedPaidPacket = paidPacket as PaidDataCapturePacket | null;
    const verifiedPaidPacketEvidence = paidPacketEvidence as EvidenceReference | null;
    const verifiedChainPacket = chainPacket as ReturnType<typeof parseTaskChainCapturePacket> | null;
    const verifiedChainPacketEvidence = chainPacketEvidence as EvidenceReference | null;
    const verifiedCompositePacket = compositePacket as ReturnType<typeof parseCompositeCapturePacket> | null;
    const verifiedS3Packet = s3Packet as S3CapturePacket | null;
    let paidTypedCandidate: TaskObservationBundleCandidate | null = null;
    let chainTypedCandidate: TaskObservationBundleCandidate | null = null;
    if (verifiedPaidPacket) {
      if (!verifiedPaidPacketEvidence) fail(409, 'TASK_EVIDENCE_CAPTURE_BINDING_MISMATCH', 'The paid-data packet has no sealed evidence reference');
      try {
        paidTypedCandidate = projectPaidDataObservationBundle(verifiedPaidPacket, { taskCase, binding: bundle.binding as unknown as TaskEvidenceBinding,
          captureEvidence: verifiedPaidPacketEvidence, assets: assets as Array<{ assetId: string; kind: 'native' | 'erc20'; chainId: number; address: string | null }>,
          actionResponses: paidResponsesByActionId });
      } catch { fail(409, 'TASK_EVIDENCE_CAPTURE_OBSERVATION_MISMATCH', 'The paid-data packet cannot be independently projected'); }
      if (paidTypedCandidate.observationCutoffSequence !== verifiedPaidPacket.coverage.observationCutoffSequence) {
        fail(409, 'TASK_EVIDENCE_CAPTURE_OBSERVATION_MISMATCH', 'The paid-data child cutoff does not match its projected observations');
      }
    }
    if (verifiedChainPacket) {
      if (!verifiedChainPacketEvidence) fail(409, 'TASK_EVIDENCE_CAPTURE_BINDING_MISMATCH', 'The chain packet has no sealed evidence reference');
      try {
        const projection = projectTaskChainCapturePacket(verifiedChainPacket, { binding: bundle.binding as unknown as TaskEvidenceBinding,
          taskCase: taskCase as never, evidence: verifiedChainPacketEvidence, ethValuation });
        const arrays = [projection.transfers, projection.finalStates, projection.allowanceChanges, projection.allowanceUses,
          projection.trades, projection.conversions, projection.expenses];
        const coveredThroughSequence = Math.max(0, ...arrays.flatMap((entries) => entries.map((entry) => entry.sequence)));
        const observations: PersistedTaskObservations = { schemaVersion: 'bts-task-observations/v1', binding: bundle.binding as unknown as TaskEvidenceBinding,
          coveredThroughSequence, captureEvidence: verifiedChainPacketEvidence, coverage: projection.coverage, transfers: projection.transfers,
          payments: [], stateMutations: [], finalStates: projection.finalStates, allowanceChanges: projection.allowanceChanges,
          allowanceUses: projection.allowanceUses, answers: [], selections: [], deliveries: [], trades: projection.trades,
          conversions: projection.conversions, expenses: projection.expenses };
        chainTypedCandidate = { schemaVersion: 'bts-task-observation-bundle-candidate/v1', observationCutoffSequence: coveredThroughSequence,
          cutoffStatus: 'authoritative', cutoffEvidence: verifiedChainPacketEvidence, observations };
      } catch { fail(409, 'TASK_EVIDENCE_CAPTURE_OBSERVATION_MISMATCH', 'The chain packet cannot be independently projected'); }
    }
    if (verifiedCompositePacket) {
      if (!verifiedPaidPacket || !verifiedChainPacket || !paidTypedCandidate || !chainTypedCandidate || !verifiedPaidPacketEvidence || !verifiedChainPacketEvidence) {
        fail(409, 'TASK_EVIDENCE_CAPTURE_BINDING_MISMATCH', 'The composite capture is missing a verified child packet');
      }
      if (verifiedCompositePacket.children.paid.boundary.observationCutoffSequence !== paidTypedCandidate.observationCutoffSequence ||
          verifiedCompositePacket.children.chain.boundary.observationCutoffSequence !== chainTypedCandidate.observationCutoffSequence) {
        fail(409, 'TASK_EVIDENCE_CUTOFF_MISMATCH', 'A composite child observation boundary does not match its projected facts');
      }
      try { verifyCompositeCaptureChildren(verifiedCompositePacket, verifiedPaidPacket, verifiedChainPacket); }
      catch { fail(409, 'TASK_EVIDENCE_CAPTURE_BINDING_MISMATCH', 'The paid and chain capture packets do not share the sealed execution and block interval'); }
      let merged: TaskObservationBundleCandidate;
      try { merged = composeTaskObservationCandidates(verifiedCompositePacket, paidTypedCandidate, chainTypedCandidate, captureEvidence); }
      catch { fail(409, 'TASK_EVIDENCE_CAPTURE_OBSERVATION_MISMATCH', 'The independently projected composite children cannot be composed'); }
      verifyProjectedObservations(merged);
    } else if (paidTypedCandidate) {
      verifyProjectedObservations(paidTypedCandidate);
    } else if (chainTypedCandidate) {
      verifyProjectedObservations(chainTypedCandidate);
    } else if (taskCase.taskId === 'S3') {
      if (!verifiedS3Packet) fail(409, 'TASK_EVIDENCE_CAPTURE_BINDING_MISMATCH', 'The S3 capture packet was not verified');
      let projected: PersistedTaskObservations;
      try { projected = projectS3PacketObservations(verifiedS3Packet, { binding: bundle.binding as unknown as TaskEvidenceBinding,
        taskCase: taskCase as never, captureEvidence }); }
      catch { fail(409, 'TASK_EVIDENCE_CAPTURE_OBSERVATION_MISMATCH', 'The S3 packet cannot be independently projected'); }
      verifyProjectedObservations({ schemaVersion: 'bts-task-observation-bundle-candidate/v1',
        observationCutoffSequence: projected.coveredThroughSequence, cutoffStatus: 'authoritative', cutoffEvidence: captureEvidence, observations: projected });
    } else if ((taskCase.taskId === 'M1' && row.mode === 'ranked') || taskCase.taskId === 'M2' || taskCase.taskId === 'H1' ||
        taskCase.taskId === 'H3' || taskCase.taskId === 'U1' || taskCase.taskId === 'M3' || taskCase.taskId === 'M4' || taskCase.taskId === 'H2') {
      fail(409, 'TASK_EVIDENCE_CAPTURE_BINDING_MISMATCH', 'The task capture packet was not verified');
    }

    if (taskCase.taskId === 'S2') {
      if (!s2Packet) fail(409, 'TASK_EVIDENCE_CAPTURE_BINDING_MISMATCH', 'The S2 capture packet was not verified');
      await this.verifyS2OwnerActions(tx, row, taskCase, s2Packet.ownerActions as Record<string, unknown>[],
        s2EvidenceByPath, (s2Packet.bef as Record<string, unknown>).before as Record<string, unknown>);
    } else if (taskCase.taskId === 'M1' && row.mode === 'training') {
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
        Number(value.taskIndex) !== row.task_index || safeSequence(value.actionSequence as string | number) !== action.actionSequence ||
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
          !this.validM1RejectedActionEvidence(value, action) ||
        reference.path !== action.actionEvidence.path || reference.sha256.toLowerCase() !== action.actionEvidence.sha256.toLowerCase()) {
      fail(409, 'TASK_EVIDENCE_CAPTURE_ACTION_MISMATCH', 'A retained M1 action child does not match its immutable packet projection');
    }
    return value;
  }

  private validM1RejectedActionEvidence(value: Record<string, unknown>, action: M1CaptureAction): boolean {
    if (typeof value.reasonCode !== 'string' || value.reasonCode.length < 1 || value.reasonCode.length > 128 ||
        value.transactionHash !== undefined || value.outcome !== undefined || value.receiptStatus !== undefined ||
        value.participantToolResponse !== undefined) return false;
    const hasResponseHash = typeof value.rawResponseSha256 === 'string' && HASH.test(value.rawResponseSha256);
    const hasHttpStatus = value.httpStatus !== undefined;
    if (hasHttpStatus) {
      return Number.isSafeInteger(value.httpStatus) && (value.httpStatus as number) >= 400 && (value.httpStatus as number) <= 499 &&
        hasResponseHash && (action.actionKind !== 'pay' || action.paymentProtocol === null ||
          action.paymentProtocol.challengeResponseSha256 === undefined ||
          String(action.paymentProtocol.challengeResponseSha256).toLowerCase() === String(value.rawResponseSha256).toLowerCase());
    }

    if (hasResponseHash) {
      return value.reasonCode === 'task_split_pay_authorization_invalid' && action.actionKind === 'pay' &&
        action.befOperationId !== null && action.paymentProtocol !== null &&
        action.paymentProtocol.befOperationId === action.befOperationId &&
        typeof action.paymentProtocol.challengeResponseSha256 === 'string' &&
        action.paymentProtocol.challengeResponseSha256.toLowerCase() === String(value.rawResponseSha256).toLowerCase();
    }

    if (value.rawResponseSha256 !== undefined || action.befOperationId !== null ||
        !M1_LOCAL_NO_REQUEST_REJECTIONS[action.actionKind].has(value.reasonCode)) return false;
    if (action.actionKind === 'pay' && action.paymentProtocol !== null) {
      return action.paymentProtocol.befOperationId === undefined && action.paymentProtocol.challengeResponseSha256 === undefined &&
        action.paymentProtocol.challengeHeaderSha256 === undefined && action.paymentProtocol.settlementHeaderSha256 === undefined;
    }
    return action.paymentProtocol === null;
  }

  private async verifyChainOwnerActions(
    tx: Transaction,
    row: EvidenceRow,
    packet: ReturnType<typeof parseTaskChainCapturePacket>,
    chainEvidenceByPath: ReadonlyMap<string, Record<string, unknown>>,
    paidEvidenceByPath: ReadonlyMap<string, Record<string, unknown>>,
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
    const expectedActions: Array<Record<string, unknown>> = [
      ...packet.ownerActions.map((action) => ({ ...action, receiptStatus: 'observed' })),
      ...packet.externalActions.map((action) => ({ ...action, ...(plainObject(action.inspection)
        ? { command: action.inspection.command, rawResponseSha256: action.inspection.rawResponseSha256 } : {}) })),
    ];
    if (cutoff === null || cutoff > MAX_EVIDENCE_FILES || actionRows.length !== cutoff || expectedActions.length !== cutoff) {
      fail(409, 'TASK_EVIDENCE_CAPTURE_ACTION_MISMATCH', 'The sealed chain owner-action list does not match its immutable cutoff');
    }
    const expectedById = new Map(expectedActions.map((action) => [String(action.actionId), action]));
    if (expectedById.size !== expectedActions.length || new Set(expectedActions.map((action) => String(action.ownerOperationId))).size !== expectedActions.length ||
        new Set(expectedActions.map((action) => Number(action.actionSequence))).size !== expectedActions.length) {
      fail(409, 'TASK_EVIDENCE_CAPTURE_ACTION_MISMATCH', 'The sealed chain packet repeats an owner action identity');
    }
    const failAction: () => never = () => fail(409, 'TASK_EVIDENCE_CAPTURE_ACTION_MISMATCH', 'A chain action differs from its durable owner receipt or retained evidence');
    for (let index = 0; index < actionRows.length; index += 1) {
      const value = actionRows[index]!;
      const sequence = safeSequence(value.action_sequence as string | number);
      const expected = typeof value.id === 'string' ? expectedById.get(value.id) : undefined;
      const parsedCommand = TaskActionCommandSchema.safeParse(jsonValue(value.command_json));
      if (!parsedCommand.success) failAction();
      const command = parsedCommand.data;
      const response = value.tool_response_json === null || value.tool_response_json === undefined ? null : jsonValue(value.tool_response_json);
      const historyResponse = value.history_tool_response_json === null || value.history_tool_response_json === undefined ? null : jsonValue(value.history_tool_response_json);
      const transactionHash = typeof value.transaction_hash === 'string' ? value.transaction_hash.toLowerCase() : null;
      const ref = expected && plainObject(expected.actionEvidence) ? expected.actionEvidence as unknown as EvidenceReference : null;
      const evidence = ref ? chainEvidenceByPath.get(ref.path) ?? paidEvidenceByPath.get(ref.path) : undefined;
      const expectedStatus = expected?.receiptStatus;
      if (!expected || sequence !== index + 1 || !UUID.test(String(value.id)) || value.run_id !== row.run_id ||
          value.owner_id !== row.owner_id || value.agent_id !== row.agent_id || Number(value.task_index) !== row.task_index ||
          value.task_id !== row.task_id || value.environment_id !== row.environment_id || !HASH.test(String(value.payload_hash)) ||
          sha256CanonicalTaskJson({ runId: row.run_id, taskIndex: row.task_index, command }).toLowerCase() !== String(value.payload_hash).toLowerCase() ||
          command.kind !== value.action_kind || Number(expected.actionSequence) !== sequence || expected.ownerOperationId !== value.operation_id ||
          expected.actionKind !== command.kind || String(expected.commandSha256).toLowerCase() !== String(value.payload_hash).toLowerCase() ||
          !ref || ref.path !== value.evidence_path || ref.sha256.toLowerCase() !== String(value.evidence_hash).toLowerCase() || !evidence ||
          expectedStatus !== value.receipt_status || !['observed','rejected_before_execution'].includes(String(value.receipt_status)) ||
          !Number.isSafeInteger(value.receipt_revision) || Number(value.receipt_revision) < 1 ||
          !Number.isSafeInteger(value.history_revision) || Number(value.history_revision) < 1 ||
          value.history_revision !== value.receipt_revision || value.history_status !== value.receipt_status ||
          value.history_evidence_hash !== value.evidence_hash || value.history_evidence_path !== value.evidence_path ||
          (typeof value.history_transaction_hash === 'string' ? value.history_transaction_hash.toLowerCase() : null) !== transactionHash ||
          canonicalTaskJson(historyResponse) !== canonicalTaskJson(response) || value.history_tool_response_hash !== value.tool_response_hash ||
          (typeof value.tool_response_hash === 'string' && value.tool_response_hash.toLowerCase() !== sha256CanonicalTaskJson(response).toLowerCase()) ||
          (value.tool_response_hash === null && response !== null) ||
          (typeof expected.transactionHash === 'string' ? expected.transactionHash.toLowerCase() : null) !== transactionHash ||
          evidence.schema !== 'bef-task-action-observation-v1' || evidence.actionId !== expected.actionId || evidence.runId !== row.run_id ||
          Number(evidence.taskIndex) !== row.task_index || String(evidence.actionSequence) !== String(sequence) ||
          evidence.ownerOperationId !== expected.ownerOperationId || evidence.actionKind !== command.kind ||
          String(evidence.commandSha256).toLowerCase() !== String(value.payload_hash).toLowerCase() ||
          evidence.environmentId !== row.environment_id || evidence.generationId !== row.generation_id ||
          String(evidence.manifestSha256).toLowerCase() !== row.environment_manifest_hash.toLowerCase() ||
          String(evidence.applicationSourceSha256).toLowerCase() !== row.application_source_hash.toLowerCase() ||
          evidence.idempotencyKey !== `task-action-${expected.actionId}` || evidence.status !== expectedStatus ||
          (evidence.befOperationId ?? null) !== (expected.befOperationId ?? null) ||
          (typeof evidence.transactionHash === 'string' ? evidence.transactionHash.toLowerCase() : null) !== transactionHash ||
          canonicalTaskJson(evidence.participantToolResponse ?? null) !== canonicalTaskJson(response)) failAction();
      if (expectedStatus === 'observed' && !plainObject(response)) failAction();
      if (expectedStatus === 'rejected_before_execution' && (response !== null || transactionHash !== null)) failAction();
      if (expected.actionKind === 'inspect_catalog' || expected.actionKind === 'inspect_offer') {
        const parsedInspection = TaskActionCommandSchema.safeParse(expected.command);
        const inspection = expected.rawResponseSha256;
        const body = plainObject(response) ? response : null;
        const handle = body && plainObject(body.readHandle) ? body.readHandle : null;
        const expectedHandleKind = expected.actionKind === 'inspect_catalog' ? 'catalog' : 'offer';
        if (!parsedInspection.success || (parsedInspection.data.kind !== 'inspect_catalog' && parsedInspection.data.kind !== 'inspect_offer') ||
            canonicalTaskJson(parsedInspection.data) !== canonicalTaskJson(command) ||
            parsedInspection.data.kind !== expected.actionKind || expectedStatus !== 'observed' || transactionHash !== null ||
            typeof inspection !== 'string' || !HASH.test(inspection) || evidence.rawResponseSha256 !== inspection || !body || !handle ||
            !exactKeys(handle, ['kind', 'operationId']) || handle.kind !== expectedHandleKind ||
            handle.operationId !== expected.befOperationId || body.operationId !== expected.befOperationId ||
            !readOnlyToolResponseMatches(parsedInspection.data, body) || Object.hasOwn(evidence, 'transactionHash') ||
            Object.hasOwn(evidence, 'outcome') || Object.hasOwn(evidence, 'receiptStatus') ||
            Object.hasOwn(evidence, 'receiptGasUsed') || Object.hasOwn(evidence, 'receiptEffectiveGasPriceWei') ||
            Object.hasOwn(evidence, 'paymentProtocol') || Object.hasOwn(evidence, 'recoverySource')) failAction();
      }
    }
  }

  private async verifyS3OwnerActions(
    tx: Transaction,
    row: EvidenceRow,
    packet: S3CapturePacket,
    actionEvidenceByPath: ReadonlyMap<string, Record<string, unknown>>,
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
      fail(409, 'TASK_EVIDENCE_CAPTURE_ACTION_MISMATCH', 'The sealed S3 owner-action list does not match its immutable cutoff');
    }
    const actionById = new Map(packet.ownerActions.map((action) => [action.actionId, action]));
    if (actionById.size !== packet.ownerActions.length ||
        new Set(packet.ownerActions.map((action) => action.actionSequence)).size !== packet.ownerActions.length ||
        new Set(packet.ownerActions.map((action) => action.ownerOperationId)).size !== packet.ownerActions.length ||
        new Set(packet.ownerActions.map((action) => action.actionEvidence.path)).size !== packet.ownerActions.length) {
      fail(409, 'TASK_EVIDENCE_CAPTURE_ACTION_MISMATCH', 'The S3 packet repeats an owner action identity');
    }
    const census = packet.bef.after;
    const generation = census.generation;
    const operations = census.operations;
    const operationById = new Map(operations.map((operation) => [String(operation.operation_id).toLowerCase(), operation]));
    if (operationById.size !== operations.length) {
      fail(409, 'TASK_EVIDENCE_CAPTURE_ACTION_MISMATCH', 'The S3 BEF census repeats an operation identity');
    }
    const observedOperationIds = packet.ownerActions.filter((action) => action.receiptStatus === 'observed')
      .map((action) => String(action.befOperationId).toLowerCase());
    if (new Set(observedOperationIds).size !== observedOperationIds.length ||
        observedOperationIds.length !== operations.length || observedOperationIds.some((id) => !operationById.has(id))) {
      fail(409, 'TASK_EVIDENCE_CAPTURE_ACTION_MISMATCH', 'The S3 BEF operations do not match the observed owner actions');
    }
    const digest = (value: string) => createHash('sha256').update(value).digest('hex').toLowerCase();
    const failAction: () => never = () => fail(409, 'TASK_EVIDENCE_CAPTURE_ACTION_MISMATCH',
      'An S3 action differs from its durable owner receipt or retained BEF evidence');
    for (let index = 0; index < actionRows.length; index += 1) {
      const value = actionRows[index]!;
      const sequence = safeSequence(value.action_sequence as string | number);
      const action = typeof value.id === 'string' ? actionById.get(value.id) : undefined;
      const parsedCommand = TaskActionCommandSchema.safeParse(jsonValue(value.command_json));
      if (!parsedCommand.success) failAction();
      const command = parsedCommand.data;
      const response = value.tool_response_json === null || value.tool_response_json === undefined ? null : jsonValue(value.tool_response_json);
      const historyResponse = value.history_tool_response_json === null || value.history_tool_response_json === undefined ? null : jsonValue(value.history_tool_response_json);
      const transactionHash = typeof value.transaction_hash === 'string' ? value.transaction_hash.toLowerCase() : null;
      const ref = action?.actionEvidence;
      const evidence = ref ? actionEvidenceByPath.get(ref.path) : undefined;
      if (!action || sequence !== index + 1 || !UUID.test(String(value.id)) || value.run_id !== row.run_id ||
          value.owner_id !== row.owner_id || value.agent_id !== row.agent_id || Number(value.task_index) !== row.task_index ||
          value.task_id !== 'S3' || value.environment_id !== row.environment_id ||
          (command.kind !== 'inspect_catalog' && command.kind !== 'inspect_offer') || value.action_kind !== command.kind || !HASH.test(String(value.payload_hash)) ||
          sha256CanonicalTaskJson({ runId: row.run_id, taskIndex: row.task_index, command }).toLowerCase() !== String(value.payload_hash).toLowerCase() ||
          action.actionSequence !== sequence || action.ownerOperationId !== value.operation_id ||
          canonicalTaskJson(action.command) !== canonicalTaskJson(command) ||
          action.commandSha256.toLowerCase() !== String(value.payload_hash).toLowerCase() ||
          !ref || ref.path !== value.evidence_path || ref.sha256.toLowerCase() !== String(value.evidence_hash).toLowerCase() ||
          !evidence || !Number.isSafeInteger(value.receipt_revision) || Number(value.receipt_revision) < 1 ||
          !Number.isSafeInteger(value.history_revision) || Number(value.history_revision) < 1 || value.history_revision !== value.receipt_revision ||
          value.history_status !== value.receipt_status || value.history_evidence_hash !== value.evidence_hash ||
          value.history_evidence_path !== value.evidence_path || value.history_transaction_hash !== value.transaction_hash ||
          canonicalTaskJson(historyResponse) !== canonicalTaskJson(response) || value.history_tool_response_hash !== value.tool_response_hash ||
          (response === null ? value.tool_response_hash !== null : typeof value.tool_response_hash !== 'string' ||
            value.tool_response_hash.toLowerCase() !== sha256CanonicalTaskJson(response).toLowerCase()) ||
          action.receiptStatus !== value.receipt_status || !['observed','rejected_before_execution'].includes(String(value.receipt_status)) ||
          transactionHash !== null || evidence.schema !== 'bef-task-action-observation-v1' || evidence.actionId !== action.actionId ||
          evidence.runId !== row.run_id || Number(evidence.taskIndex) !== row.task_index || String(evidence.actionSequence) !== String(sequence) ||
          evidence.ownerOperationId !== action.ownerOperationId || evidence.actionKind !== command.kind ||
          String(evidence.commandSha256).toLowerCase() !== String(value.payload_hash).toLowerCase() ||
          evidence.environmentId !== row.environment_id || evidence.generationId !== row.generation_id ||
          String(evidence.manifestSha256).toLowerCase() !== row.environment_manifest_hash.toLowerCase() ||
          String(evidence.applicationSourceSha256).toLowerCase() !== row.application_source_hash.toLowerCase() ||
          evidence.idempotencyKey !== `task-action-${action.actionId}` || evidence.status !== action.receiptStatus ||
          (typeof evidence.transactionHash === 'string' ? evidence.transactionHash.toLowerCase() : null) !== null) failAction();
      if (action.receiptStatus === 'rejected_before_execution') {
        const idempotencyHash = digest(`task-action-${action.actionId}`);
        if (action.reasonCode !== evidence.reasonCode || action.befOperationId !== null || action.response !== null || response !== null ||
            evidence.rawResponseSha256 !== undefined || evidence.befOperationId !== undefined || evidence.participantToolResponse !== undefined ||
            evidence.httpStatus !== undefined || operations.some((operation) => String(operation.idempotency_key_sha256).toLowerCase() === idempotencyHash))
          failAction();
        continue;
      }
      if (action.befOperationId === null || action.response === null) failAction();
      const operationId = action.befOperationId.toLowerCase();
      const operation = operationById.get(operationId);
      const publicResponse = plainObject(evidence.participantToolResponse) ? evidence.participantToolResponse : null;
      const rawResponseSha256 = evidence.rawResponseSha256;
      const idempotencyHash = digest(`task-action-${action.actionId}`);
      const actionResponse = plainObject(action.response) ? action.response : null;
      const actionHandle = actionResponse && plainObject(actionResponse.readHandle) ? actionResponse.readHandle : null;
      const expectedReadKind = command.kind === 'inspect_catalog' ? 'catalog' : 'offer';
      const expectedRequestHash = digest(JSON.stringify(command.kind === 'inspect_catalog' ?
        { method: 'GET', path: '/catalog' } : { method: 'GET', path: '/offer', resourceId: command.resourceId }));
      if (!operation || !publicResponse || evidence.httpStatus !== 200 || typeof rawResponseSha256 !== 'string' || !HASH.test(rawResponseSha256) ||
          !plainObject(response) || !actionResponse || !actionHandle ||
          canonicalTaskJson(publicResponse) !== canonicalTaskJson(actionResponse) ||
          canonicalTaskJson(response) !== canonicalTaskJson(actionResponse) ||
          !readOnlyToolResponseMatches(command, publicResponse) || actionResponse.operationId !== operationId ||
          actionHandle.kind !== expectedReadKind || actionHandle.operationId !== operationId || evidence.befOperationId !== action.befOperationId ||
          operation.env_id !== row.environment_id || operation.generation_id !== row.generation_id ||
          operation.participant_id !== generation.participant_id || String(operation.idempotency_key_sha256).toLowerCase() !== idempotencyHash ||
          String(operation.request_sha256).toLowerCase() !== expectedRequestHash || operation.operation_kind !== expectedReadKind || operation.status !== 'accepted' ||
          operation.receipt_status !== 'not_submitted' || operation.transaction_hash !== null || typeof operation.response_sha256 !== 'string' ||
          !HASH.test(operation.response_sha256) || operation.response_sha256.toLowerCase() !== rawResponseSha256.toLowerCase()) failAction();
    }
  }
  private async verifyPaidOwnerActions(
    tx: Transaction,
    row: EvidenceRow,
    packet: PaidDataCapturePacket,
    actionEvidenceByPath: ReadonlyMap<string, Record<string, unknown>>,
    composite: boolean,
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
    if (cutoff === null || cutoff > MAX_EVIDENCE_FILES || actionRows.length !== cutoff || packet.ownerActions.length > cutoff ||
        (!composite && packet.ownerActions.length !== cutoff)) {
      fail(409, 'TASK_EVIDENCE_CAPTURE_ACTION_MISMATCH', 'The sealed paid-data owner-action list does not match its immutable cutoff');
    }
    const actionById = new Map(packet.ownerActions.map((action) => [action.actionId, action]));
    if (actionById.size !== packet.ownerActions.length ||
        new Set(packet.ownerActions.map((action) => action.actionSequence)).size !== packet.ownerActions.length ||
        new Set(packet.ownerActions.map((action) => action.ownerOperationId)).size !== packet.ownerActions.length) {
      fail(409, 'TASK_EVIDENCE_CAPTURE_ACTION_MISMATCH', 'The paid-data packet repeats an owner action identity');
    }
    const commandById = new Map<string, TaskActionCommand>();
    const packetOperations = Array.isArray(packet.bef.after.operations) ? packet.bef.after.operations.filter(plainObject) : [];
    const packetPayments = Array.isArray(packet.bef.after.payments) ? packet.bef.after.payments.filter(plainObject) : [];
    const packetDeliveries = Array.isArray(packet.bef.after.deliveries) ? packet.bef.after.deliveries.filter(plainObject) : [];
    const generation = plainObject(packet.bef.after.generation) ? packet.bef.after.generation : null;
    const operationById = new Map(packetOperations.map((operation) => [String(operation.operation_id).toLowerCase(), operation]));
    if (operationById.size !== packetOperations.length) {
      fail(409, 'TASK_EVIDENCE_CAPTURE_ACTION_MISMATCH', 'The paid-data census repeats a BEF operation identity');
    }
    const digest = (value: string) => createHash('sha256').update(value).digest('hex').toLowerCase();
    const failAction: () => never = () => fail(409, 'TASK_EVIDENCE_CAPTURE_ACTION_MISMATCH', 'A paid-data action differs from its durable owner receipt or retained BEF evidence');
    for (let index = 0; index < actionRows.length; index += 1) {
      const value = actionRows[index]!;
      const sequence = safeSequence(value.action_sequence as string | number);
      const action = typeof value.id === 'string' ? actionById.get(value.id) : undefined;
      const parsedCommand = TaskActionCommandSchema.safeParse(jsonValue(value.command_json));
      if (!parsedCommand.success) failAction();
      const durableCommand = parsedCommand.data;
      const response = value.tool_response_json === null || value.tool_response_json === undefined ? null : jsonValue(value.tool_response_json);
      const historyResponse = value.history_tool_response_json === null || value.history_tool_response_json === undefined ? null : jsonValue(value.history_tool_response_json);
      const transactionHash = typeof value.transaction_hash === 'string' ? value.transaction_hash.toLowerCase() : null;
      const child = action ? actionEvidenceByPath.get(action.actionEvidence.path) : undefined;
      if (sequence !== index + 1 || !UUID.test(String(value.id)) || value.run_id !== row.run_id || value.owner_id !== row.owner_id ||
          value.agent_id !== row.agent_id || Number(value.task_index) !== row.task_index || value.task_id !== row.task_id ||
          value.environment_id !== row.environment_id || !HASH.test(String(value.payload_hash)) ||
          sha256CanonicalTaskJson({ runId: row.run_id, taskIndex: row.task_index, command: durableCommand }).toLowerCase() !== String(value.payload_hash).toLowerCase() ||
          !Number.isSafeInteger(value.receipt_revision) || Number(value.receipt_revision) < 1 ||
          !Number.isSafeInteger(value.history_revision) || Number(value.history_revision) < 1 ||
          value.history_revision !== value.receipt_revision || !['observed','rejected_before_execution'].includes(String(value.receipt_status)) ||
          value.history_status !== value.receipt_status ||
          value.history_evidence_hash !== value.evidence_hash || value.history_evidence_path !== value.evidence_path ||
          (typeof value.history_transaction_hash === 'string' ? value.history_transaction_hash.toLowerCase() : null) !== transactionHash ||
          canonicalTaskJson(historyResponse) !== canonicalTaskJson(response) || value.history_tool_response_hash !== value.tool_response_hash ||
          (typeof value.tool_response_hash === 'string' && value.tool_response_hash.toLowerCase() !== sha256CanonicalTaskJson(response).toLowerCase()) ||
          (value.tool_response_hash === null && response !== null)) failAction();
      if (!action) {
        if (['inspect_catalog','inspect_offer','purchase','pay','retrieve'].includes(durableCommand.kind)) failAction();
        continue;
      }
      if (action.actionSequence !== sequence || action.ownerOperationId !== value.operation_id ||
          action.actionKind !== durableCommand.kind || action.commandSha256.toLowerCase() !== String(value.payload_hash).toLowerCase() ||
          action.receiptStatus !== value.receipt_status || action.actionEvidence.path !== value.evidence_path ||
          action.actionEvidence.sha256.toLowerCase() !== String(value.evidence_hash).toLowerCase() ||
          transactionHash !== (action.transactionHash?.toLowerCase() ?? null) || !child ||
          child.schema !== 'bef-task-action-observation-v1' || child.actionId !== action.actionId || child.runId !== row.run_id ||
          Number(child.taskIndex) !== row.task_index || String(child.actionSequence) !== String(sequence) ||
          child.ownerOperationId !== action.ownerOperationId || child.actionKind !== action.actionKind ||
          child.commandSha256 !== action.commandSha256.toLowerCase() || child.environmentId !== row.environment_id ||
          child.generationId !== row.generation_id || child.manifestSha256 !== row.environment_manifest_hash.toLowerCase() ||
          child.applicationSourceSha256 !== row.application_source_hash.toLowerCase() || child.idempotencyKey !== `task-action-${action.actionId}` ||
          (child.befOperationId ?? null) !== action.befOperationId ||
          (typeof child.transactionHash === 'string' ? child.transactionHash.toLowerCase() : null) !== transactionHash ||
          child.status !== action.receiptStatus || canonicalTaskJson(child.participantToolResponse ?? null) !== canonicalTaskJson(response) ||
          (child.rawResponseSha256 ?? null) !== action.rawResponseSha256) failAction();
      if (action.receiptStatus === 'observed') {
        if (!plainObject(response) || typeof action.rawResponseSha256 !== 'string') failAction();
        if ((durableCommand.kind === 'inspect_catalog' || durableCommand.kind === 'inspect_offer') &&
            !readOnlyToolResponseMatches(durableCommand, response)) failAction();
      } else if (response !== null || transactionHash !== null) failAction();
      commandById.set(action.actionId, durableCommand);
    }
    for (const action of packet.ownerActions) {
      const command = commandById.get(action.actionId);
      if (!command) failAction();
      if (action.receiptStatus === 'rejected_before_execution') {
        if (action.befOperationId) {
          const operation = operationById.get(action.befOperationId.toLowerCase());
          const protocol = action.paymentProtocol;
          let expectedRequestHash: string;
          let expectedOperationKind: string;
          let validStatus = false;
          if (command.kind === 'inspect_catalog' || command.kind === 'inspect_offer') {
            expectedOperationKind = command.kind === 'inspect_catalog' ? 'catalog' : 'offer';
            const request = command.kind === 'inspect_catalog' ? { method: 'GET', path: '/catalog' } :
              { method: 'GET', path: '/offer', resourceId: command.resourceId };
            expectedRequestHash = digest(JSON.stringify(request));
            validStatus = operation?.status === 'accepted';
          } else if (command.kind === 'pay') {
            if (!plainObject(protocol) || !plainObject(protocol.readHandle) || !plainObject(protocol.acceptedTerms)) failAction();
            expectedOperationKind = 'purchase';
            expectedRequestHash = splitPayRequestSha256(row.environment_id, { resourceId: command.resourceId, offerId: command.offerId,
              readHandle: protocol.readHandle, acceptedTerms: protocol.acceptedTerms });
            validStatus = ['awaiting_payment','rejected'].includes(String(operation?.status));
          } else if (command.kind === 'purchase') {
            expectedOperationKind = 'purchase';
            expectedRequestHash = digest(JSON.stringify({ method: 'POST', path: `/tools/${row.environment_id}/purchase`,
              body: JSON.parse(canonicalTaskJson({ resourceId: command.resourceId, offerId: command.offerId })) }));
            validStatus = ['awaiting_payment','rejected'].includes(String(operation?.status));
          } else {
            failAction();
          }
          if (!operation || operation.env_id !== row.environment_id || operation.generation_id !== row.generation_id ||
              !generation || operation.participant_id !== generation.participant_id ||
              String(operation.idempotency_key_sha256).toLowerCase() !== digest(`task-action-${action.actionId}`) ||
              operation.operation_kind !== expectedOperationKind || !validStatus ||
              operation.receipt_status !== 'not_submitted' || operation.transaction_hash !== null ||
              String(operation.request_sha256).toLowerCase() !== expectedRequestHash.toLowerCase() ||
              (operation.response_sha256 !== null && (action.rawResponseSha256 === null ||
                String(operation.response_sha256).toLowerCase() !== action.rawResponseSha256.toLowerCase())) ||
              packetPayments.some((payment) => String(payment.operation_id).toLowerCase() === action.befOperationId!.toLowerCase()) ||
              packetDeliveries.some((delivery) => String(delivery.operation_id).toLowerCase() === action.befOperationId!.toLowerCase()) ||
              (Array.isArray(packet.bef.after.x402Observations) && packet.bef.after.x402Observations.some((observation) => plainObject(observation) &&
                String(observation.operation_id).toLowerCase() === action.befOperationId!.toLowerCase())) ||
              (Array.isArray(packet.bef.after.costs) && packet.bef.after.costs.some((cost) => plainObject(cost) &&
                String(cost.operation_id).toLowerCase() === action.befOperationId!.toLowerCase()))) failAction();
        }
        continue;
      }
      if (command.kind === 'inspect_catalog' || command.kind === 'inspect_offer') {
        const response = actionEvidenceByPath.get(action.actionEvidence.path)?.participantToolResponse;
        if (!plainObject(response) || !readOnlyToolResponseMatches(command, response)) failAction();
        if (!action.befOperationId) failAction();
        const operation = operationById.get(action.befOperationId.toLowerCase());
        const request = command.kind === 'inspect_catalog' ? { method: 'GET', path: '/catalog' } :
          { method: 'GET', path: '/offer', resourceId: command.resourceId };
        const requestHash = digest(JSON.stringify(request));
        if (!operation || operation.env_id !== row.environment_id || operation.generation_id !== row.generation_id ||
            !generation || operation.participant_id !== generation.participant_id ||
            String(operation.idempotency_key_sha256).toLowerCase() !== digest(`task-action-${action.actionId}`) ||
            operation.operation_kind !== (command.kind === 'inspect_catalog' ? 'catalog' : 'offer') || operation.status !== 'accepted' ||
            operation.receipt_status !== 'not_submitted' || operation.transaction_hash !== null ||
            String(operation.request_sha256).toLowerCase() !== requestHash ||
            String(operation.response_sha256).toLowerCase() !== String(action.rawResponseSha256).toLowerCase() ||
            typeof response.operationId !== 'string' || response.operationId.toLowerCase() !== action.befOperationId.toLowerCase()) failAction();
      } else if (command.kind === 'pay') {
        const protocol = action.paymentProtocol, response = actionEvidenceByPath.get(action.actionEvidence.path)?.participantToolResponse;
        if (!plainObject(protocol) || protocol.schema !== 'bef-x402-split-payment-observation-v1' ||
            protocol.resourceId !== command.resourceId || protocol.offerId !== command.offerId || !plainObject(protocol.readHandle) ||
            !plainObject(protocol.acceptedTerms) || action.befOperationId === null || !plainObject(response)) failAction();
        const priorAction = packet.ownerActions.find((candidate) => candidate.actionId === command.offerReadActionId);
        const priorCommand = priorAction ? commandById.get(priorAction.actionId) : undefined;
        const priorResponse = priorAction ? actionEvidenceByPath.get(priorAction.actionEvidence.path)?.participantToolResponse : undefined;
        const operation = action.befOperationId ? operationById.get(action.befOperationId.toLowerCase()) : undefined;
        const expectedRequestHash = splitPayRequestSha256(row.environment_id, { resourceId: command.resourceId, offerId: command.offerId,
          readHandle: protocol.readHandle, acceptedTerms: protocol.acceptedTerms });
        const responsePayment = plainObject(response.payment) ? response.payment : null;
        if (!priorAction || priorAction.receiptStatus !== 'observed' || priorAction.actionSequence >= action.actionSequence ||
            (priorCommand?.kind !== 'inspect_catalog' && priorCommand?.kind !== 'inspect_offer') || !plainObject(priorResponse) ||
            canonicalTaskJson(protocol.readHandle) !== canonicalTaskJson(priorResponse.readHandle) || !operation ||
            operation.env_id !== row.environment_id || operation.generation_id !== row.generation_id ||
            !generation || operation.participant_id !== generation.participant_id ||
            String(operation.idempotency_key_sha256).toLowerCase() !== digest(`task-action-${action.actionId}`) ||
            operation.operation_kind !== 'purchase' || !['settled','delivered'].includes(String(operation.status)) ||
            operation.receipt_status !== 'success' || operation.payment_response_mode !== 'deferred_delivery' ||
            String(operation.transaction_hash).toLowerCase() !== String(action.transactionHash).toLowerCase() ||
            String(operation.response_sha256).toLowerCase() !== String(action.rawResponseSha256).toLowerCase() ||
            operation.selected_resource_id !== command.resourceId || operation.selected_offer_id !== command.offerId ||
            String(operation.selected_amount_units) !== String(protocol.amountUnits) ||
            String(operation.selected_resource_sha256).toLowerCase() !== String(protocol.resourceSha256).toLowerCase() ||
            String(operation.request_sha256).toLowerCase() !== expectedRequestHash.toLowerCase() ||
            response.operationId !== action.befOperationId || response.status !== 'payment_confirmed' ||
            response.deliveryHandle !== action.befOperationId ||
            !responsePayment || String(responsePayment.transactionHash).toLowerCase() !== String(action.transactionHash).toLowerCase() ||
            responsePayment.receiptStatus !== 'success' ||
            responsePayment.amount !== String(protocol.amountUnits) || responsePayment.network !== protocol.network ||
            String(responsePayment.asset).toLowerCase() !== String(protocol.asset).toLowerCase() ||
            String(responsePayment.payTo).toLowerCase() !== String(protocol.acceptedTerms.payTo).toLowerCase()) failAction();
      } else if (command.kind === 'retrieve') {
        const priorAction = packet.ownerActions.find((candidate) => candidate.actionId === command.payActionId);
        const priorCommand = priorAction ? commandById.get(priorAction.actionId) : undefined;
        const protocol = action.paymentProtocol;
        if (!priorAction || priorCommand?.kind !== 'pay' || priorAction.receiptStatus !== 'observed' ||
            priorAction.actionSequence >= action.actionSequence || priorAction.ownerOperationId === action.ownerOperationId ||
            !action.befOperationId || action.befOperationId !== priorAction.befOperationId || !plainObject(protocol) ||
            protocol.schema !== 'bef-x402-retrieve-observation-v1' || protocol.payOperationId !== action.befOperationId ||
            protocol.deliveryMatchesPinnedResource !== true) failAction();
        const evidenceResponse = actionEvidenceByPath.get(action.actionEvidence.path)?.participantToolResponse;
        const content = action.retrievedContent;
        if (!plainObject(evidenceResponse) || !content || evidenceResponse.operationId !== action.befOperationId ||
            evidenceResponse.resourceId !== content.resourceId || evidenceResponse.contentType !== content.contentType ||
            evidenceResponse.contentHash !== content.contentSha256 || typeof evidenceResponse.contentBytes !== 'string') failAction();
        const delivered = Buffer.from(evidenceResponse.contentBytes, 'base64');
        if (!delivered.length || delivered.toString('base64') !== evidenceResponse.contentBytes || delivered.length !== content.byteCount ||
            createHash('sha256').update(delivered).digest('hex').toLowerCase() !== content.contentSha256.toLowerCase()) failAction();
        let decoded: unknown;
        try { decoded = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(delivered)) as unknown; }
        catch { failAction(); }
        if (canonicalTaskJson(decoded) !== canonicalTaskJson(evidenceResponse.content)) failAction();
      } else if (command.kind === 'purchase') {
        // The admitted release currently pins separate payment and retrieval; combined purchase remains unsupported.
        failAction();
      } else {
        failAction();
      }
    }
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

  private async readS4CapturePacketChildren(bytes: Buffer, bundle: {
    binding: Record<string, unknown>; closure: Record<string, unknown>;
    execution: Record<string, unknown>; observations: Record<string, unknown>;
  }, tx: Transaction, row: EvidenceRow): Promise<{ children: EvidenceReference[]; actions: S1SealedActionProof[] }> {
    let children: EvidenceReference[];
    try { children = verifyS4CapturePacketChildren(bytes, bundle); }
    catch (error) {
      if (error instanceof S4CapturePacketError) {
        fail(409, 'TASK_EVIDENCE_CAPTURE_BINDING_MISMATCH', 'The S4 capture packet or observation bindings do not match the sealed task');
      }
      throw error;
    }
    let packet: unknown;
    try { packet = JSON.parse(bytes.toString('utf8')) as unknown; }
    catch { fail(503, 'TASK_EVIDENCE_CAPTURE_PACKET_INVALID', 'The sealed S4 capture packet is malformed'); }
    if (!plainObject(packet) || !Array.isArray(packet.ownerActions) || !plainObject(packet.bef) || !plainObject(packet.bef.after)) {
      fail(409, 'TASK_EVIDENCE_CAPTURE_BINDING_MISMATCH', 'The S4 packet does not retain its ordered owner actions and BEF census');
    }
    const packetActions = packet.ownerActions.filter(plainObject);
    const reads = packetActions.filter((action) => action.actionKind === 'inspect_catalog' || action.actionKind === 'inspect_offer');
    if (reads.length === 0) return { children, actions: [] };
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
    const census = packet.bef.after;
    const generation = plainObject(census.generation) ? census.generation : null;
    const operations = Array.isArray(census.operations) ? census.operations.filter(plainObject) : null;
    if (actionRows.length !== packetActions.length || !generation || !operations || !Array.isArray(census.costs) ||
        !Array.isArray(census.selectedExecutions) || !Array.isArray(census.selectedEvents)) {
      fail(409, 'TASK_EVIDENCE_CAPTURE_ACTION_MISMATCH', 'The S4 neutral read action census is incomplete');
    }
    const operationById = new Map(operations.map((operation) => [String(operation.operation_id).toLowerCase(), operation]));
    const proofs: S1SealedActionProof[] = [];
    for (let index = 0; index < actionRows.length; index += 1) {
      const durable = actionRows[index]!;
      const action = packetActions[index]!;
      const sequence = safeSequence(durable.action_sequence as string | number);
      const parsedCommand = TaskActionCommandSchema.safeParse(jsonValue(durable.command_json));
      const reference = action.actionEvidence as EvidenceReference;
      if (sequence !== index + 1 || String(durable.id) !== action.actionId || durable.run_id !== row.run_id ||
          durable.owner_id !== row.owner_id || durable.agent_id !== row.agent_id || Number(durable.task_index) !== row.task_index ||
          durable.task_id !== 'S4' || durable.environment_id !== row.environment_id || durable.operation_id !== action.ownerOperationId ||
          sequence !== action.actionSequence || durable.action_kind !== action.actionKind ||
          String(durable.payload_hash).toLowerCase() !== String(action.commandSha256).toLowerCase() || !HASH.test(String(durable.payload_hash)) ||
          durable.evidence_path !== reference.path || String(durable.evidence_hash).toLowerCase() !== reference.sha256.toLowerCase() ||
          durable.receipt_status !== 'observed' ||
          (typeof durable.transaction_hash === 'string' ? durable.transaction_hash.toLowerCase() : null) !==
            (typeof action.transactionHash === 'string' ? action.transactionHash.toLowerCase() : null) ||
          durable.history_revision !== durable.receipt_revision ||
          durable.history_status !== durable.receipt_status || durable.history_evidence_hash !== durable.evidence_hash ||
          durable.history_evidence_path !== durable.evidence_path || durable.history_transaction_hash !== durable.transaction_hash ||
          !parsedCommand.success || parsedCommand.data.kind !== action.actionKind ||
          sha256CanonicalTaskJson({ runId: row.run_id, taskIndex: row.task_index, command: parsedCommand.data }).toLowerCase() !== String(durable.payload_hash).toLowerCase()) {
        fail(409, 'TASK_EVIDENCE_CAPTURE_ACTION_MISMATCH', 'An S4 owner action differs from its durable neutral-read command or receipt');
      }
      if (action.actionKind !== 'inspect_catalog' && action.actionKind !== 'inspect_offer') continue;
      const command = parsedCommand.data;
      if (command.kind !== 'inspect_catalog' && command.kind !== 'inspect_offer') {
        fail(409, 'TASK_EVIDENCE_CAPTURE_ACTION_MISMATCH', 'An S4 read command is outside the neutral read allowlist');
      }
      const operationId = String(action.befOperationId).toLowerCase();
      const operation = operationById.get(operationId);
      const readKind = command.kind === 'inspect_catalog' ? 'catalog' : 'offer';
      const request = command.kind === 'inspect_catalog' ? { method: 'GET', path: '/catalog' } :
        { method: 'GET', path: '/offer', resourceId: command.resourceId };
      if (!operation || durable.transaction_hash !== null || action.transactionHash !== null ||
          operation.operation_kind !== readKind || operation.status !== 'accepted' ||
          operation.receipt_status !== 'not_submitted' || operation.transaction_hash !== null || operation.env_id !== row.environment_id ||
          operation.generation_id !== row.generation_id || operation.participant_id !== generation.participant_id ||
          String(operation.idempotency_key_sha256).toLowerCase() !== createHash('sha256').update(`task-action-${action.actionId}`).digest('hex') ||
          String(operation.request_sha256).toLowerCase() !== createHash('sha256').update(JSON.stringify(request)).digest('hex') ||
          typeof operation.response_sha256 !== 'string' || !HASH.test(operation.response_sha256) ||
          census.costs.some((cost) => plainObject(cost) && String(cost.operation_id).toLowerCase() === operationId) ||
          census.selectedExecutions.some((item) => plainObject(item) && String(item.operation_id).toLowerCase() === operationId) ||
          census.selectedEvents.some((item) => plainObject(item) && String(item.operation_id).toLowerCase() === operationId)) {
        fail(409, 'TASK_EVIDENCE_CAPTURE_ACTION_MISMATCH', 'An S4 neutral read does not match its accepted GET operation');
      }
      proofs.push({ action, command, operation });
    }
    if (proofs.length !== reads.length || operationById.size < proofs.length) {
      fail(409, 'TASK_EVIDENCE_CAPTURE_ACTION_MISMATCH', 'The S4 neutral read operation count differs from its owner action list');
    }
    return { children, actions: proofs };
  }

  private validateSealedInspectionAction(
    bytes: Buffer,
    reference: EvidenceReference,
    proof: S1SealedActionProof,
    row: EvidenceRow,
    taskId: 'S1' | 'S4',
  ): void {
    let value: unknown;
    try { value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)) as unknown; }
    catch { fail(409, 'TASK_EVIDENCE_CAPTURE_ACTION_MISMATCH', `An ${taskId} read action evidence file is malformed`); }
    const { action, command, operation } = proof;
    if (command.kind !== 'inspect_catalog' && command.kind !== 'inspect_offer') {
      fail(409, 'TASK_EVIDENCE_CAPTURE_ACTION_MISMATCH', `An ${taskId} read command is outside the neutral read allowlist`);
    }
    const operationId = action.befOperationId;
    const readKind = command.kind === 'inspect_catalog' ? 'catalog' : 'offer';
    const request = command.kind === 'inspect_catalog' ? { method: 'GET', path: '/catalog' } :
      { method: 'GET', path: '/offer', resourceId: command.resourceId };
    const requestHash = createHash('sha256').update(JSON.stringify(request)).digest('hex');
    const startedAt = plainObject(value) && typeof value.requestStartedAt === 'string' ? Date.parse(value.requestStartedAt) : Number.NaN;
    const finishedAt = plainObject(value) && typeof value.requestFinishedAt === 'string' ? Date.parse(value.requestFinishedAt) : Number.NaN;
    const response = plainObject(value) && plainObject(value.participantToolResponse) ? value.participantToolResponse : null;
    const handle = response && plainObject(response.readHandle) ? response.readHandle : null;
    const healthMatches = observationHealthMatches(plainObject(value) ? value.environmentHealth : undefined, {
      environmentId: row.environment_id,
      manifestSha256: row.environment_manifest_hash,
      applicationSourceSha256: row.application_source_hash,
    });
    const allowedKeys = ['schema', 'actionId', 'runId', 'taskIndex', 'actionSequence', 'ownerOperationId', 'actionKind',
      'commandSha256', 'environmentId', 'generationId', 'manifestSha256', 'applicationSourceSha256', 'idempotencyKey', 'status',
      'requestStartedAt', 'requestFinishedAt', 'httpStatus', 'befOperationId', 'rawResponseSha256', 'participantToolResponse', 'environmentHealth'];
    if (!plainObject(value) || containsSecretKey(value) || Object.keys(value).some((key) => !allowedKeys.includes(key)) ||
        value.schema !== 'bef-task-action-observation-v1' || value.actionId !== action.actionId || value.runId !== row.run_id ||
        Number(value.taskIndex) !== row.task_index || String(value.actionSequence) !== String(action.actionSequence) ||
        value.ownerOperationId !== action.ownerOperationId || value.actionKind !== command.kind ||
        String(value.commandSha256).toLowerCase() !== String(action.commandSha256).toLowerCase() ||
        value.environmentId !== row.environment_id || value.generationId !== row.generation_id ||
        String(value.manifestSha256).toLowerCase() !== row.environment_manifest_hash.toLowerCase() ||
        String(value.applicationSourceSha256).toLowerCase() !== row.application_source_hash.toLowerCase() ||
        value.idempotencyKey !== `task-action-${action.actionId}` || value.status !== 'observed' || value.httpStatus !== 200 ||
        value.befOperationId !== operationId || typeof value.rawResponseSha256 !== 'string' || !HASH.test(value.rawResponseSha256) ||
        !Number.isFinite(startedAt) || !Number.isFinite(finishedAt) || finishedAt < startedAt || !healthMatches || !response || !handle ||
        !exactKeys(handle, ['kind', 'operationId']) || handle.kind !== readKind || handle.operationId !== operationId ||
        !readOnlyToolResponseMatches(command, response) ||
        value.rawResponseSha256.toLowerCase() !== String(operation.response_sha256).toLowerCase() ||
        String(operation.request_sha256).toLowerCase() !== requestHash ||
        reference.path !== (action.actionEvidence as EvidenceReference).path ||
        reference.sha256.toLowerCase() !== (action.actionEvidence as EvidenceReference).sha256.toLowerCase() ||
        Object.hasOwn(value, 'transactionHash') || Object.hasOwn(value, 'outcome') || Object.hasOwn(value, 'receiptStatus') ||
        Object.hasOwn(value, 'receiptGasUsed') || Object.hasOwn(value, 'receiptEffectiveGasPriceWei') ||
        Object.hasOwn(value, 'paymentProtocol') || Object.hasOwn(value, 'recoverySource') || Object.hasOwn(value, 'reasonCode')) {
      fail(409, 'TASK_EVIDENCE_CAPTURE_ACTION_MISMATCH', `An ${taskId} neutral read differs from its durable command or BEF operation`);
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
          (value.actionKind !== 'inspect_offer' && value.actionKind !== 'inspect_catalog') ||
          typeof value.commandSha256 !== 'string' || !HASH.test(value.commandSha256) ||
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
        value.ownerOperationId !== action.ownerOperationId || value.actionKind !== action.actionKind ||
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
    const command = action.actionKind === 'inspect_catalog' ? { kind: 'inspect_catalog' as const } :
      { kind: 'inspect_offer' as const, resourceId: taskCase.objective.resourceId, offerId: taskCase.objective.offerId };
    const body = value.participantToolResponse;
    const handle = body.readHandle;
    const expected = taskCase.objective.completePaymentRequirements;
    const pinnedAsset = assets.find((item) => item.assetId === expected.assetId);
    const catalogResource = command.kind === 'inspect_catalog' && Array.isArray(body.catalog)
      ? body.catalog.find((resource) => plainObject(resource) && resource.resourceId === taskCase.objective.resourceId) : null;
    const selectedOffers = command.kind === 'inspect_catalog' && plainObject(catalogResource) ? catalogResource.offers : body.offers;
    const selected = Array.isArray(selectedOffers)
      ? selectedOffers.find((offer) => plainObject(offer) && offer.id === taskCase.objective.offerId) : null;
    const payment = plainObject(selected) && plainObject(selected.payment) ? selected.payment : null;
    const asset = payment && typeof payment.asset === 'string' ? payment.asset.toLowerCase() : '';
    const resourceMatches = command.kind === 'inspect_offer' ? body.resourceId === taskCase.objective.resourceId :
      plainObject(catalogResource) && catalogResource.resourceId === taskCase.objective.resourceId;
    if (!readOnlyToolResponseMatches(command, body) || !resourceMatches ||
        body.operationId !== action.befOperationId || !plainObject(handle) || !exactKeys(handle, ['kind', 'operationId']) ||
        handle.kind !== (command.kind === 'inspect_catalog' ? 'catalog' : 'offer') || handle.operationId !== action.befOperationId || !payment ||
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
          value.task_id !== 'S2' || value.environment_id !== row.environment_id ||
          (value.action_kind !== 'inspect_offer' && value.action_kind !== 'inspect_catalog') || value.action_kind !== action.actionKind ||
          typeof value.payload_hash !== 'string' || !HASH.test(value.payload_hash) || value.receipt_status !== 'observed' ||
          value.transaction_hash !== null || value.history_revision !== value.receipt_revision || value.history_status !== value.receipt_status ||
          value.history_evidence_hash !== value.evidence_hash || value.history_evidence_path !== value.evidence_path ||
          value.history_transaction_hash !== value.transaction_hash || value.id !== action.actionId ||
          value.operation_id !== action.ownerOperationId || sequence !== action.actionSequence ||
          value.payload_hash.toLowerCase() !== String(action.commandSha256).toLowerCase() ||
          typeof value.evidence_path !== 'string' || value.evidence_path !== actionRef.path ||
          typeof value.evidence_hash !== 'string' || value.evidence_hash.toLowerCase() !== actionRef.sha256.toLowerCase() ||
          !parsedCommand.success || parsedCommand.data.kind !== action.actionKind ||
          (parsedCommand.data.kind === 'inspect_offer' && (parsedCommand.data.resourceId !== taskCase.objective.resourceId ||
            (parsedCommand.data.offerId !== undefined && parsedCommand.data.offerId !== taskCase.objective.offerId))) ||
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
      const readKind = parsedCommand.data.kind === 'inspect_catalog' ? 'catalog' : 'offer';
      const expectedRequest = parsedCommand.data.kind === 'inspect_catalog' ? { method: 'GET', path: '/catalog' } :
        { method: 'GET', path: '/offer', resourceId: taskCase.objective.resourceId };
      const expectedRequestHash = createHash('sha256').update(JSON.stringify(expectedRequest)).digest('hex');
      const response: Record<string, unknown> = {
        operationId: body.operationId, readHandle: body.readHandle,
      };
      if (readKind === 'catalog') {
        response.catalog = body.catalog;
        response.freeInspection = body.freeInspection;
        response.deliveryState = body.deliveryState;
      } else {
        response.resourceId = body.resourceId;
        response.resourceSha256 = body.resourceSha256;
        response.contentType = body.contentType;
        if (body.dataType !== undefined) response.dataType = body.dataType;
        if (body.schema !== undefined) response.schema = body.schema;
        if (body.provenance !== undefined) response.provenance = body.provenance;
        response.payment = body.payment;
        response.offers = body.offers;
        response.freeInspection = body.freeInspection;
        response.deliveryState = body.deliveryState;
      }
      const expectedResponseHash = createHash('sha256').update(JSON.stringify(response)).digest('hex');
      const expectedIdempotencyHash = createHash('sha256').update(`task-action-${action.actionId}`).digest('hex');
      if (operation.env_id !== row.environment_id || operation.generation_id !== row.generation_id ||
          operation.participant_id !== (census.generation as Record<string, unknown>).participant_id ||
          String(operation.idempotency_key_sha256).toLowerCase() !== expectedIdempotencyHash ||
          String(operation.request_sha256).toLowerCase() !== expectedRequestHash || operation.operation_kind !== readKind ||
          operation.status !== 'accepted' || operation.receipt_status !== 'not_submitted' || operation.transaction_hash !== null ||
          String(operation.response_sha256).toLowerCase() !== expectedResponseHash) {
        fail(409, 'TASK_EVIDENCE_CAPTURE_ACTION_MISMATCH', 'An S2 free read does not match its immutable BEF operation projection');
      }
    }
  }

  private async readS1CapturePacketChildren(
    bytes: Buffer,
    bundle: { binding: Record<string, unknown>; closure: Record<string, unknown>; execution: Record<string, unknown>; observations: Record<string, unknown> },
    tx: Transaction,
    row: EvidenceRow,
  ): Promise<{ children: EvidenceReference[]; actions: S1SealedActionProof[] }> {
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
    const actionPaths = new Set<string>();
    const packetActions: Record<string, unknown>[] = [];
    for (const value of packet.ownerActions) {
      const allowedKeys = ['actionId', 'actionSequence', 'ownerOperationId', 'actionKind', 'commandSha256',
        'receiptStatus', 'actionEvidence', 'befOperationId', 'transactionHash'];
      if (!plainObject(value) || !exactKeys(value, allowedKeys) || typeof value.actionId !== 'string' || !UUID.test(value.actionId) ||
          !Number.isSafeInteger(value.actionSequence) || (value.actionSequence as number) < 1 ||
          (value.actionSequence as number) > (safeSequence(bundle.closure.actionCutoffSequence as string | number) ?? -1) ||
          actionSequences.has(value.actionSequence as number) || actionIds.has(value.actionId) || actionPaths.has(String((value.actionEvidence as Record<string, unknown> | undefined)?.path)) ||
          typeof value.ownerOperationId !== 'string' || value.ownerOperationId.length < 12 || value.ownerOperationId.length > 128 ||
          !['transfer', 'inspect_catalog', 'inspect_offer'].includes(String(value.actionKind)) || typeof value.commandSha256 !== 'string' || !HASH.test(value.commandSha256) ||
          !['observed', 'rejected_before_execution'].includes(String(value.receiptStatus)) ||
          !validEvidence(value.actionEvidence) || !value.actionEvidence.path.startsWith(ACTION_EVIDENCE_PREFIX) ||
          (value.befOperationId !== null && (typeof value.befOperationId !== 'string' || !UUID.test(value.befOperationId))) ||
          (value.transactionHash !== null && (typeof value.transactionHash !== 'string' || !/^0x[0-9a-f]{64}$/i.test(value.transactionHash))) ||
          (value.actionKind !== 'transfer' && (value.receiptStatus !== 'observed' || value.befOperationId === null || value.transactionHash !== null))) {
        fail(409, 'TASK_EVIDENCE_CAPTURE_ACTION_MISMATCH', 'An S1 owner action reference is malformed or outside the sealed cutoff');
      }
      actionSequences.add(value.actionSequence as number);
      actionIds.add(value.actionId);
      actionPaths.add(value.actionEvidence.path);
      packetActions.push(value);
      children.push(value.actionEvidence as EvidenceReference);
    }
    if ([...actionSequences].some((sequence, index) => sequence !== index + 1)) {
      fail(409, 'TASK_EVIDENCE_CAPTURE_ACTION_MISMATCH', 'S1 owner actions do not match their contiguous admitted sequence');
    }

    const actions: S1SealedActionProof[] = [];
    if (packetActions.some((action) => action.actionKind === 'inspect_catalog' || action.actionKind === 'inspect_offer')) {
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
      if (actionRows.length !== packetActions.length) {
        fail(409, 'TASK_EVIDENCE_CAPTURE_ACTION_MISMATCH', 'The S1 action sequence differs from its durable receipts');
      }
      const bef = packet.bef as Record<string, unknown>;
      const census = plainObject(bef.after) ? bef.after : null;
      const generation = census && plainObject(census.generation) ? census.generation : null;
      const operations = census && Array.isArray(census.operations) ? census.operations.filter(plainObject) : null;
      if (!census || !generation || !operations || !Array.isArray(census.costs) || !Array.isArray(census.selectedExecutions) ||
          !Array.isArray(census.selectedEvents) || !Array.isArray(census.payments) || !Array.isArray(census.deliveries)) {
        fail(409, 'TASK_EVIDENCE_CAPTURE_ACTION_MISMATCH', 'The S1 read-only BEF census is malformed');
      }
      const operationById = new Map(operations.map((operation) => [String(operation.operation_id).toLowerCase(), operation]));
      if (operationById.size !== operations.length) {
        fail(409, 'TASK_EVIDENCE_CAPTURE_ACTION_MISMATCH', 'The S1 BEF census repeats an operation identity');
      }
      const reads = packetActions.filter((action) => action.actionKind === 'inspect_catalog' || action.actionKind === 'inspect_offer');
      const readOperations = operations.filter((operation) => operation.operation_kind === 'catalog' || operation.operation_kind === 'offer');
      if (reads.length !== readOperations.length) {
        fail(409, 'TASK_EVIDENCE_CAPTURE_ACTION_MISMATCH', 'The S1 neutral read list differs from retained BEF operations');
      }
      const matchedOperationIds = new Set<string>();
      for (let index = 0; index < actionRows.length; index += 1) {
        const durable = actionRows[index]!;
        const action = packetActions[index]!;
        const sequence = safeSequence(durable.action_sequence as string | number);
        const parsedCommand = TaskActionCommandSchema.safeParse(jsonValue(durable.command_json));
        const reference = action.actionEvidence as EvidenceReference;
        if (sequence !== index + 1 || String(durable.id) !== action.actionId || durable.run_id !== row.run_id ||
            durable.owner_id !== row.owner_id || durable.agent_id !== row.agent_id || Number(durable.task_index) !== row.task_index ||
            durable.task_id !== 'S1' || durable.environment_id !== row.environment_id || String(durable.id) !== String(durable.id).toLowerCase() ||
            durable.operation_id !== action.ownerOperationId || sequence !== action.actionSequence ||
            durable.action_kind !== action.actionKind || String(durable.payload_hash).toLowerCase() !== String(action.commandSha256).toLowerCase() ||
            !HASH.test(String(durable.payload_hash)) || durable.evidence_path !== reference.path ||
            String(durable.evidence_hash).toLowerCase() !== reference.sha256.toLowerCase() ||
            durable.receipt_status !== action.receiptStatus || durable.history_revision !== durable.receipt_revision ||
            durable.history_status !== durable.receipt_status || durable.history_evidence_hash !== durable.evidence_hash ||
            durable.history_evidence_path !== durable.evidence_path || durable.history_transaction_hash !== durable.transaction_hash ||
            (typeof durable.transaction_hash === 'string' ? durable.transaction_hash.toLowerCase() : null) !==
              (typeof action.transactionHash === 'string' ? action.transactionHash.toLowerCase() : null) ||
            !parsedCommand.success || parsedCommand.data.kind !== action.actionKind ||
            sha256CanonicalTaskJson({ runId: row.run_id, taskIndex: row.task_index, command: parsedCommand.data }).toLowerCase() !== String(durable.payload_hash).toLowerCase()) {
          fail(409, 'TASK_EVIDENCE_CAPTURE_ACTION_MISMATCH', 'An S1 owner action differs from its durable command or receipt');
        }
        if (action.actionKind === 'inspect_catalog' || action.actionKind === 'inspect_offer') {
          if (action.receiptStatus !== 'observed' || durable.transaction_hash !== null || action.befOperationId === null) {
            fail(409, 'TASK_EVIDENCE_CAPTURE_ACTION_MISMATCH', 'An S1 neutral read claims a transaction or lacks an observed operation');
          }
          const operationId = String(action.befOperationId).toLowerCase();
          const operation = operationById.get(operationId);
          const command = parsedCommand.data;
          const readKind = command.kind === 'inspect_catalog' ? 'catalog' : 'offer';
          const request = command.kind === 'inspect_catalog' ? { method: 'GET', path: '/catalog' } :
            command.kind === 'inspect_offer' ? { method: 'GET', path: '/offer', resourceId: command.resourceId } : null;
          if (!request) fail(409, 'TASK_EVIDENCE_CAPTURE_ACTION_MISMATCH', 'An S1 read command is outside the neutral read allowlist');
          const requestSha256 = createHash('sha256').update(JSON.stringify(request)).digest('hex');
          const idempotencySha256 = createHash('sha256').update(`task-action-${action.actionId}`).digest('hex');
          if (!operation || matchedOperationIds.has(operationId) || operation.operation_kind !== readKind || operation.status !== 'accepted' ||
              operation.receipt_status !== 'not_submitted' || operation.transaction_hash !== null || operation.env_id !== row.environment_id ||
              operation.generation_id !== row.generation_id || operation.participant_id !== generation.participant_id ||
              String(operation.idempotency_key_sha256).toLowerCase() !== idempotencySha256 ||
              String(operation.request_sha256).toLowerCase() !== requestSha256 ||
              typeof operation.response_sha256 !== 'string' || !HASH.test(operation.response_sha256) ||
              census.costs.some((cost) => plainObject(cost) && String(cost.operation_id).toLowerCase() === operationId) ||
              census.selectedExecutions.some((item) => plainObject(item) && String(item.operation_id).toLowerCase() === operationId) ||
              census.selectedEvents.some((item) => plainObject(item) && String(item.operation_id).toLowerCase() === operationId) ||
              census.payments.some((item) => plainObject(item) && String(item.operation_id).toLowerCase() === operationId) ||
              census.deliveries.some((item) => plainObject(item) && String(item.operation_id).toLowerCase() === operationId)) {
            fail(409, 'TASK_EVIDENCE_CAPTURE_ACTION_MISMATCH', 'An S1 neutral read does not match its accepted BEF operation');
          }
          matchedOperationIds.add(operationId);
          actions.push({ action, command, operation });
        }
      }
    }

    // Action references remain a complete ordered history; only transfer observations project effects.
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
      if (!action || action.actionKind !== 'transfer' || action.receiptStatus !== 'observed' || observation.observationId !== `s1-transfer-${action.actionId}` ||
          observation.transactionHash !== action.transactionHash) {
        fail(409, 'TASK_EVIDENCE_CAPTURE_ACTION_MISMATCH', 'An S1 transfer observation does not match its sealed owner action');
      }
    }
    for (const action of packet.ownerActions) {
      if (action.actionKind === 'transfer' && action.receiptStatus === 'observed' && !transferObservations.some((observation) =>
        plainObject(observation) && observation.actionSequence === action.actionSequence &&
        observation.observationId === `s1-transfer-${action.actionId}` && observation.transactionHash === action.transactionHash)) {
        fail(409, 'TASK_EVIDENCE_CAPTURE_ACTION_MISMATCH', 'An observed S1 owner action has no matching sealed transfer');
      }
    }
    return { children, actions };
  }
}
